ShieldAI · modules_c · 11 octobre 2026

# Où vit chaque octet, et qui parle à qui 🧠

Les paquets arrivent en octets, le parser les range dans une fiche, la table de flux retient chaque conversation. Touche les cases colorées : chaque case est **un octet** pour de vrai (tailles mesurées sur ton code).

[🧭 Vue d'ensemble](#vue)[🗄️ struct](#struct)[📦 union](#union)[🏷️ enum](#enum)[📐 Padding](#pad)[🧱 Pile et tas](#tas)[⏳ Cycle de vie](#vie)[📏 Conventions](#conv)[✅ État](#etat)

## 🧭 Le voyage d'un paquet

🧒 **Comme à 5 ans :** un camion de lettres arrive (les octets). Le facteur `parse` lit l'enveloppe et remplit une fiche. Le bureau `ft_process` cherche : « cette conversation existe déjà ? » Si oui, il met la fiche à jour. Sinon, il en crée une et la range à deux endroits : un **annuaire** (dict, pour retrouver vite) et une **file** (pour savoir qui est le plus vieux).

1. `parse(pkt, len)` rend un `ParserResult` (92 o, sur la pile). Si `code ≠ SUCCES` : refusé.
2. `pr_tuple` en tire IP, ports, protocole. Pas d'IP (ARP) : refusé.
3. `build_flow_key` fabrique la clé **canonique** (A→B et B→A donnent la même).
4. `ft_get` : connue ? → `entry_update` (compteurs, flags) puis `move_to_end`.
5. Inconnue ? → `FlowEntry` + `FlowData` créés, `ft_add` (évince le plus ancien si plein), puis compteur d'IP et port visité dans la `PortMap`.

| Module | Rôle en une phrase | État |
| --- | --- | --- |
| `utils` | octets → entiers, hachage | ✅ |
| `parser` | octets → `ParserResult` (Ethernet, VLAN, IPv4/6, TCP, UDP, ICMP, ARP) | ✅ |
| `dict` | table de hachage générique (rehash à 75 %) | ✅ |
| `portmap` | 65 536 bits : « ce port a été visité » | ✅ |
| `flow` | clé de flux, fiche, mise à jour, fonctions du dict | ✅ |
| `dchained_list` | file ancien → récent des `FlowEntry` | ✅ |
| `flow_table` | chef d'orchestre : `ft_process` | ✅ |
| `rules` | règle rapide : un flux et sa `PortMap` → un verdict (scan de ports) | ✅ |
| capture, ring | sockets, partage vers Python | ⏳ prévu |

## 🗄️ struct : une commode à tiroirs

🧒 Une `struct` range ses champs **l'un après l'autre**, comme des tiroirs. Chaque tiroir a une place fixe (`offsetof`). Parfois le compilateur laisse un tiroir vide (hachuré) pour que le suivant commence à une adresse « ronde » : c'est l'**alignement**, et c'est pour ça que `sizeof` est souvent plus grand que la somme des champs.

👆 Touche une case.

🤔 Question : ParserResult fait 92 o, mais ses champs ne font que 86. Où sont les 6 autres ?

Dans les deux blocs hachurés : 3 octets après `code` (pour aligner `n_vlan` sur 4) et 3 après `ip_data` (pour aligner `data` sur 4).

## 📐 La logique du padding

🧒 Le compilateur range chaque tiroir sur une étagère à **trous réguliers**. Un tiroir de 1 octet va n'importe où. Un tiroir de 4 octets ne s'installe qu'aux places 0, 4, 8… Un tiroir de 8 octets, qu'aux places 0, 8, 16… Si la place libre ne convient pas, il saute jusqu'à la prochaine : les cases sautées sont le **padding**.

1. **Chaque champ** commence à un offset multiple de son *alignement*, en général sa taille : `uint8_t` n'importe où · `uint16_t` multiple de 2 · `int` / `uint32_t` multiple de 4 · `uint64_t` / pointeur multiple de 8.
2. **La struct entière** est arrondie à un multiple de son plus grand alignement, pour qu'un tableau de ces structs reste aligné case après case.
3. Le compilateur **ne réordonne jamais** : l'ordre écrit est l'ordre en mémoire.
4. Une **union** a la taille de son plus grand membre, arrondie de la même façon. Un tableau d'`uint8_t` n'exige aucun alignement : c'est pourquoi `IPV4_DATA` (9 o) n'a aucun trou.

Dans ton code : `code` est à 4 et `n_vlan` (4 o) ne peut pas aller à 5, il saute à 8. Dans `FlowData`, `header` finit à 37 et `start_time` (8 o) saute à 40. Dans `FlowKeyIpv4`, les champs finissent à 17 mais la struct fait 20 : arrondie au multiple de 4.

### Essaie : mêmes champs, autre ordre

Le contenu du padding est **indéfini** : c'est pour ça que ton parser fait un `memset` et que `PortPerIpKey` a un `pad[3]` explicite avant le `memcmp`. Déclarer du plus gros au plus petit réduit le padding, mais chez toi le gain serait faible : ça ne compterait qu'avec des millions d'objets.

🤔 Question : un `uint8_t` est à l'offset 0, un `uint64_t` le suit. À quel offset commence le `uint64_t` ?

À 8 : il saute 7 octets de padding pour tomber sur un multiple de 8.

## 📦 union : une boîte, plusieurs étiquettes

🧒 Une `union` est **une seule boîte** avec plusieurs étiquettes. La boîte a la taille du **plus grand** contenu. Dedans, il y a soit des légumes (IPv4), soit des jouets (IPv6), jamais les deux : changer l'étiquette, c'est relire **les mêmes cases** autrement. C'est pour ça qu'on garde à côté un champ qui dit comment lire (`version`, `proto`).

### ip_data : IPv4 ou IPv6 (33 octets)

### data : TCP, UDP, ICMP ou ARP (24 octets)

🤔 Question : j'écris 10 dans `ip_data.ipv4.src_ip[0]`. Que lit-on dans `ip_data.ipv6.src_ip[0]` ?

10 aussi : c'est la même case. Les tests le vérifient (`t_mem_unions_du_parser`).

🤔 Question : pourquoi lire `data.tcp` si le paquet est ICMP serait une erreur ?

Tu lirais les octets d'ICMP en croyant que ce sont des ports. D'où `pr_tuple` : il choisit le bon membre selon `proto` et donne des zéros sinon.

## 🏷️ enum : des noms pour des nombres

🧒 Un `enum` est une liste de **noms** qui valent des **nombres**. `TCP` veut juste dire 6. En mémoire, c'est un entier (4 octets ici). Pour les flags TCP, chaque nom est **un interrupteur** dans un seul octet. Allume-les :

| enum | valeurs |
| --- | --- |
| `PARSER_RETURN_CODE` | SUCCES 0 · ERROR 1 · TOO_LITTLE 2 · INCOHERENCE 3 · NOT_HANDLE 4 · FRAGMENT 5 |
| `PKT_TYPE` | IPV4 0x0800 · IPV6 0x86DD · ARP 0x0806 · VLAN 0x8100 · QINQ 0x88A8 |
| `PROTOCOLS` | ICMP 1 · TCP 6 · UDP 17 · ICMPV6 58 |
| `FlowKeyType` | FlowKeyIpv4Type 0 · FlowKeyIpv6Type 1 (premier champ de chaque clé) |
| `FlowVerdict` | UNKNOW 0 · BLOCK 1 · LIMIT_REACHED 2 |

🤔 Question : l'octet de flags vaut 0x12. Quels interrupteurs sont allumés ?

0x12 = 0001 0010 : ACK (0x10) et SYN (0x02). C'est un SYN-ACK. Essaie en haut.

## 🧱 Pile et tas : où vit un flux

Une conversation = **une** `FlowEntry`, vue par le dict (via `Entry.value`) et par la file (via `lru_prev / lru_next`). Il y a **deux copies de la clé** : une dans la `FlowEntry`, une dans le dict. Le dict est créé avec `key_dup` mais sans `value_dup`. Retrait (éviction, expiration, fin TCP) = copie vers le `sink`, `dict_delitem`, `free(data)`, `free(key)`, puis `delete_entry` libère la `FlowEntry`.

## ⏳ Quand un flux quitte la table

| Condition | Qui la voit | Raison envoyée |
| --- | --- | --- |
| Inactif depuis `idle_ms` | `ft_expire` (tête de file) | `END_IDLE` |
| RST, ou FIN des deux côtés (option `close_on_tcp_end`) | `ft_process`, juste après la mise à jour | `END_TCP_CLOSED` |
| Table pleine | `ft_add` chasse le plus ancien | `END_EVICTED` |
| Arrêt du programme | `ft_destroy` | `END_SHUTDOWN` |
| Durée dépassée (`max_ms`) | `ft_process`, en dernier (après la règle et la fin TCP) | `END_MAX_DURATION` : le flux **reste**, il repart de zéro |
| Verdict `BLOCK` ou `LIMIT_REACHED` | la règle | **le flux reste** avec son verdict, jusqu'à l'une des lignes ci-dessus |

Chaque flux qui part est d'abord copié dans un `FlowRecord` (176 o, sans pointeur) donné au `sink`, puis libéré. Pour Python, `start_time` et `end_time` sont en ms depuis 1970 : `int(time.time() * 1000)`. `end_time` = dernier paquet vu.

### Deux minuteurs, deux jobs

🧒 **Inactivité (`idle_ms`)** : « cette personne s'est endormie, on libère sa chaise » 💤. **Durée max (`max_ms`)** : « tu es là depuis 5 minutes : tu notes ce que tu as fait, et on repart d'une page blanche » 🗣️. Le flux reste, ses compteurs repartent à 0.

- Sans `idle_ms` : les flux morts (client débranché, attaque à moitié ouverte) pèsent en mémoire pour rien.
- Sans `max_ms` : un flux qui parle sans arrêt n'est jamais envoyé à Python.

🤔 Question : `idle_ms` = 30 s, `max_ms` = 5 min. Un flux envoie un paquet toutes les 10 s pendant 1 heure. Est-il exporté ?

Oui, 12 fois (toutes les 5 min), et jamais pour inactivité : il n'est jamais silencieux plus de 10 s. Le test `t_duree_max_flux_bavard` le vérifie.

### L'ordre pour chaque paquet : `ft_process(ft, pr, now_ms)`

1. IP source sur la liste noire ? On l'ignore, **rien n'est stocké**, retour 0.
2. `ft_expire` : le ménage, en regardant la tête de file.
3. Fiche : `entry_update` (compteurs, octets, `end_time`) ou création du flux.
4. Règle `check` : elle donne un verdict, et `BLOCK` ajoute l'IP à la liste noire.
5. Fin TCP ? Le flux est retiré (en dernier : il peut être libéré).
6. Sinon, durée max atteinte ? Instantané envoyé, le flux repart de zéro.

Tu n'as pas à appeler `ft_expire` pour chaque paquet : `ft_process` le fait. Mais si aucun paquet n'arrive, rien ne se déclenche : ta boucle de capture appelle aussi `ft_expire(ft, realtime_ms())` quand `recv` expire, ou toutes les secondes.

```
struct FlowHooks h = {0};
h.idle_ms = 30000;          // 30 s sans paquet : retiré
h.max_ms  = 300000;         // 5 min : instantané, puis il repart de zéro
h.close_on_tcp_end = 1;
h.check = rule_port_scan;
h.sink  = mon_sink;         // void mon_sink(const FlowRecord *r, void *ctx)
h.ctx   = mon_ring;         // le sink copie ce qu'il veut de *r
FlowTable *ft = ft_create_with(65536, &h);   // ou ft_create puis ft_set_hooks
ft_process(ft, &pr, realtime_ms());
```

🤔 Question : une règle renvoie BLOCK pour un flux. Est-il supprimé tout de suite ?

Non. L'IP va sur la liste noire (ses prochains paquets sont ignorés) et le flux reste avec son verdict jusqu'à son expiration. Le supprimer ferait recréer un flux UNKNOW au paquet suivant.

## 📏 Les conventions, une seule fois pour toutes

| Famille | Règle | Exemples |
| --- | --- | --- |
| Action | **0** = succès · **-1** = échec | `ft_add`, `ft_process`, `dict_setitem`, `move_to_end`, `build_flow_key` |
| Question | **1** = oui · **0** = non | `ft_contains`, `ft_can_add`, `portmap_add` (nouveau ?), `portmap_test` |
| Comparaison | **0** = égaux · sinon différents | `flow_key_compare`, `port_key_compare` |
| Pointeur | **NULL** = absent ou échec | `ft_get`, `dict_getitem`, `create_dcl` |
| Drapeau `v4` | **1** = IPv4 · **0** = IPv6 | `FlowData.v4`, `PortPerIpKey.v4`, `PacketTuple.v4` |
| Compteur | **≥ 0** = nombre · **-1** = erreur | `ft_expire` (nombre de flux retirés) |
| Parser | **SUCCES = 0**, erreurs > 0 toutes différentes | `ParserResult.code` |

Avant, `v4 == 0` voulait dire IPv4 (à l'envers de son nom), et `ft_contains` / `ft_can_add` répondaient 0 pour « oui ». C'est ce qui embrouillait.

🤔 Question : `ft_contains(ft, key)` renvoie 0. Le flux est-il présent ?

Non. C'est une question : 0 = non, 1 = oui. Ce n'est jamais -1.

🤔 Question : `delete_from_top` sur une liste vide renvoie 0. Est-ce une erreur ?

Non : rien à supprimer n'est pas un échec. Seul -1 signale un échec.

## ✅ État du code

**Tests : tout est vert** avec ASan et UBSan, 0 avertissement : utils 10 · portmap 11 · dchained_list 28 · flow 44 · flow_table 35 · integration 45 · dict 74 · parser 46 + 37 + 52.\
**Corrigé :** `ft_add` chassait avant de regarder si la clé existait (il pouvait se chasser lui-même) · l'éviction supposait la tête de file · fuites dans `ft_create` en cas d'échec · code dupliqué v4 / v6 regroupé dans `pr_tuple` · code mort retiré.\
**Nouveau :** `octets_data_*` et `end_time` remplis, heure réelle compatible Python, `ft_expire`, `FlowHooks` (sink, règle, inactivité), liste noire, règle de scan, durée max (`max_ms`), `ft_create_with`.\
**Pas encore fait :** fenêtre de temps pour le scan (la `PortMap` vit tant que l'IP a un flux), capture et ring.

Lancer : `./run_tests.sh` (ou `./run_tests.sh integration`)