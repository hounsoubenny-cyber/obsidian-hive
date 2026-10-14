# Le moteur : capture → flux → ring → Python

Ce document décrit la couche qui relie tout le reste : `engine/` (le chef d'orchestre), `ipset/` (les IP à ignorer),
`mmap_ring/` (le ring partagé) et `python/` (la porte d'entrée Cython).

## 1. En une image

```
                Python (ids_engine.pyx, numpy)
   start / stop / release / read / stats / ignore_*
                         │   (un verrou interne sérialise ces appels)
                         ▼
                      engine.c ── registre : une case par interface (16 maximum)
                         │
      ┌──────────────────┴───────────────────────────────┐
      │  UNE interface = UNE thread = SA capture, SA table de flux, SON ring
      │
      │   socket AF_PACKET + filtre BPF            (capture.c)
      │        │  cap_recv / cap_recv_mmsg
      │        ▼
      │   parse()                                   (parser.c)       octets → fiche
      │        │
      │        ├─ IP source ∈ liste « src » ?  ou  IP destination ∈ liste « dst » ?  → on jette (compté)
      │        ▼                                    (ipset.c, lecture SANS verrou)
      │   ft_process()                              (flow_table.c)   fiche → flux
      │        │   un flux qui part (inactif, durée max, fin TCP, table pleine, arrêt)
      │        ▼
      │   sink : copie à plat (176 octets)          → ring_write()   (mmap_ring.c)
      └────────────────────────────────────────────────────────────────┐
                                                                       ▼
                                    /dev/shm/ids_<interface>   ← Python lit : un flux = 176 octets
```

Les deux listes d'IP à ignorer (source et destination) sont **partagées** par toutes les threads.

## 2. Les fichiers

| Dossier | Rôle | Tests |
|---|---|---|
| `engine/engine.h`, `engine.c` | L'API que Python appelle : captures, rings, listes d'IP, erreurs | `test_engine.c` (16 tests) |
| `ipset/ipset.h`, `ipset.c` | Ensemble d'IP v4/v6 : lecture sans verrou, écriture sous verrou | `test_ipset.c` (7 tests) |
| `mmap_ring/` | Ring d'octets en mémoire partagée, un écrivain, un lecteur | `test_mmap_ring.c` (28 tests) |
| `python/ids_engine.pyx`, `setup.py` | La liaison Cython et le `dtype` numpy d'un flux | `test_ids_engine.py` (7 scénarios) |

Lancer les tests C : `sudo -E ./run_tests.sh engine ipset mmap_ring` (le moteur capture `lo`, donc root).
Compiler et tester la liaison : `cd python && python3 setup.py build_ext --inplace && sudo python3 test_ids_engine.py`.

## 3. Le cycle de vie d'une capture

```
engine_start ──► (engine_read, engine_stats...) ──► engine_stop ──► engine_read jusqu'à 0 ──► engine_release
   │                                                    │                                          │
   crée ring, table, socket, thread                     arrête la thread, envoie les             supprime le ring
   (les erreurs sont renvoyées ICI)                     flux restants au ring (raison « arrêt »)  (/dev/shm)
```

* `engine_start` construit **tout** dans la thread de l'appelant (ring, table, socket) et ne lance la thread de capture
  qu'à la fin. Ainsi « pas root », « interface inconnue » ou « ring trop grand » sont renvoyés à Python tout de suite,
  sous forme d'exception, et pas perdus dans une thread.
* `engine_stop` ne supprime pas le ring : Python peut finir de le vider. `engine_release` le supprime.
* `engine_destroy` (ou `Engine.close()` / sortie du `with`) arrête et libère tout.
* Une capture qui s'arrête toute seule sur une erreur passe à l'état « en erreur » ; on fait `stop` puis `release`.

## 4. L'API C (conventions du projet : action `0 / -1`, question `1 / 0`)

| Fonction | Retour |
|---|---|
| `engine_create()` / `engine_destroy(e)` | pointeur / – |
| `engine_config_default(&cfg)` | – (toujours l'appeler avant de régler `cfg`) |
| `engine_start(e, &cfg)` | 0 / -1 |
| `engine_stop(e, "eth0")` | 0 / -1 |
| `engine_release(e, "eth0")` | 0 / -1 |
| `engine_read(e, "eth0", out, max)` | nombre de flux lus (≥ 0, 0 = rien de neuf), -1 = erreur |
| `engine_stats(e, "eth0", &st)` / `engine_list(e, buf, max)` | 0 / -1 · nombre de captures |
| `engine_ring_name(e, "eth0", buf, size)` | 0 / -1 |
| `engine_ignore_add / remove(e, "10.0.0.1", which)` | 0 / -1 (`remove` d'une IP absente : -1) |
| `engine_ignore_contains(e, ip, which)` | **1 / 0** (question) |
| `engine_last_error()` | une phrase, valable pour la thread qui vient d'échouer |

`which` vaut `IGNORE_SRC`, `IGNORE_DST` ou `IGNORE_BOTH`.

### Les réglages (`struct EngineConfig`)

| Champ | Défaut | Effet |
|---|---|---|
| `ifname` | – | interface à capturer (obligatoire) |
| `ring_prefix` | `"ids"` | le ring s'appelle `/<prefix>_<ifname>` |
| `use_mmsg` | 1 | 1 = lots (`recvmmsg`), 0 = une trame par appel |
| `promisc` | 0 | voir aussi les trames d'autres machines |
| `buffer_mb` | 16 | tampon du noyau |
| `table_size` | 65536 | flux suivis en même temps |
| `idle_ms` | 30 000 | un flux sans paquet depuis ce délai part au ring (0 = jamais) |
| `max_ms` | 300 000 | un flux qui dure depuis ce délai est envoyé puis repart de zéro (0 = jamais) |
| `close_on_tcp_end` | 1 | un RST, ou deux FIN, retire le flux tout de suite |
| `scan_rule` | 1 | la règle « scan de ports » (20 ports distincts) met l'IP en liste noire |
| `ring_size` | 16 Mio | taille du segment (place utile = taille − 256) |
| `batch_size`, `max_turns` | 64, 16 | pour `use_mmsg` |
| `poll_ms` | 200 | attente d'une trame ; c'est aussi la durée maximale d'un `engine_stop` |

## 5. Côté Python

```python
import ids_engine
with ids_engine.Engine() as eng:
    eng.start("eth0", idle_ms=30000)
    eng.ignore_add("10.0.0.1", "both")
    flows = eng.read("eth0")                 # tableau numpy, dtype FLOW_DTYPE : une ligne = un flux
    for f in flows:
        ini, port_i, rec, port_r = ids_engine.flow_addresses(f)
    print(eng.stats("eth0"))
    eng.stop("eth0"); eng.read("eth0"); eng.release("eth0")
```

Les erreurs sont des `ids_engine.EngineError` avec le message du C. `stop`, `release`, `start`, `read`, `stats`
libèrent le GIL pendant qu'elles travaillent : une autre thread Python n'est pas figée.

### Un flux dans le ring (176 octets, `FLOW_DTYPE`)

| Champ | Octet | Taille | Sens |
|---|---|---|---|
| `key` | 0 | 44 | la clé du flux (octets bruts) |
| `v4` | 48 | 1 | 1 = IPv4, 0 = IPv6 |
| `hdr` | 49 | 36 | initiateur / receveur : IP et ports (`flow_addresses` le décode) |
| `start_time`, `end_time` | 88, 96 | 8 + 8 | millisecondes depuis 1970 : `int(time.time()*1000)` |
| `rst syn ack fin urg cwr ece psh` | 104 … 132 | 8 × 4 | nombre de paquets ayant ce drapeau TCP |
| `n_pkt_ltr`, `n_pkt_rtl` | 136, 140 | 4 + 4 | paquets initiateur → receveur, receveur → initiateur |
| `octets_ltr`, `octets_rtl` | 144, 152 | 8 + 8 | somme des tailles de trames |
| `proto` | 160 | 1 | 6 = TCP, 17 = UDP, 1 = ICMP, 58 = ICMPv6 |
| `verdict` | 164 | 4 | 0 inconnu, 1 BLOCK, 2 LIMIT_REACHED |
| `reason` | 168 | 4 | 1 inactif, 2 tcp-fini, 3 chassé, 4 arrêt, 5 durée-max |

Le moteur vérifie au chargement que `sizeof(FlowRecord)` vaut bien la taille du `dtype` : si tu changes une structure
C, il refuse de démarrer au lieu de te donner des nombres faux.

## 6. Les choix, et pourquoi

1. **Une thread par interface, une table et un ring par thread.** La table de flux n'est jamais partagée : aucun verrou
   sur le chemin chaud. Le ring a un seul écrivain (la thread) et un seul lecteur (le verrou du registre garantit qu'un
   seul `engine_read` tourne à la fois), ce que le ring supporte sans verrou.
2. **Pas de fanout dans ce module** (une seule capture par interface). Le fanout répartirait un même scanneur sur plusieurs
   threads et casserait la règle de scan par IP. À reprendre avec un compteur de ports partagé ou une détection en
   deuxième étage.
3. **Les listes d'IP : lecture sans verrou, écriture sous verrou.** Chaque case est UN pointeur atomique vers une fiche
   qu'on ne modifie jamais. Un lecteur voit donc la case vide ou une fiche complète, jamais une IP à moitié écrite.
   Les fiches retirées ne sont pas libérées tout de suite (un lecteur peut encore les lire) : elles le sont à la
   destruction de la liste. C'est le prix de la lecture sans verrou ; il est petit (17 octets par IP retirée).
4. **Deux listes, source et destination.** Un paquet est ignoré si sa source est dans la liste « src » ou si sa
   destination est dans la liste « dst ». Pour ne plus suivre du tout une machine, on l'ajoute des deux côtés
   (`which="both"`, le défaut).
5. **Un ring plein ne bloque jamais la capture.** Le flux est perdu et compté (`flows_lost`, `ring_dropped`).
   Mieux vaut perdre un résumé de flux que des paquets.
6. **L'arrêt envoie les flux restants.** Rien n'est perdu à la fermeture, et Python peut finir de lire.
7. **Les compteurs sont atomiques.** La thread de capture les écrit, Python les lit à n'importe quel moment sans verrou.
8. **Les erreurs sont des phrases.** `engine_last_error()` est propre à chaque thread, donc deux threads Python qui
   échouent en même temps ne se mélangent pas.
9. **Un segment resté d'un arrêt brutal est remplacé** au démarrage (une seule fois). Un ring est « à nous » :
   on ne partage pas un nom de ring entre deux programmes.

## 7. À savoir

* **Droits :** il faut root ou `CAP_NET_RAW`.
* **`/dev/shm` :** sous Docker il fait 64 Mo par défaut. Le ring réserve sa place à l'ouverture (`posix_fallocate`) :
  trop grand pour `/dev/shm`, `start` échoue proprement. Prévoir `--shm-size`.
* **`lo` voit chaque paquet deux fois** (sortant puis entrant) : les compteurs de test sont doublés. Ce n'est pas un bug.
* **Un flux fermé par un RST peut renaître** si un paquet tardif arrive : il apparaît alors avec les rôles inversés et
  un seul paquet. À traiter plus tard (ne pas créer de flux quand le premier paquet est un RST).
* **La règle de scan** compte les ports par IP source dans la table de CETTE interface : pas de fenêtre de temps.
* **Un lecteur Python qui attend** un ring non encore initialisé reçoit une erreur : il suffit de réessayer.
* **Non faits :** durée maximale par flux sur un balayage de la table, détection DDoS (par IP cible), répartition
  multi-threads d'une même interface, lecture directe du ring par Python sans passer par `engine_read`.

## 8. Pour aller plus loin

* Lire le ring sans le moteur (autre processus) : `Engine.ring_name()` donne le nom, puis `mmap` sur
  `/dev/shm/<nom>` ; en-tête de 256 octets (`n_write`@0, `n_read`@64, `r_size`@128, `n_dropped`@192), données dès
  l'octet 256, un flux = 176 octets.
* Changer le nom du projet : le module Python s'appelle `ids_engine` ; le préfixe des rings est réglable
  (`ring_prefix`).
