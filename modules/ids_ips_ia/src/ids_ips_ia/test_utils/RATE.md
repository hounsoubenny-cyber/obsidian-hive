# 🎚️ Choisir le débit du trafic (gen_traffic / profile_run)

## ⚡ Aide-mémoire

| Je veux… | J'écris | Remarque |
|---|---|---|
| Vitesse max | `topspeed` | défaut, limité par le veth / le CPU |
| N paquets par seconde | `pps=20000` ou `pps=20k` | suffixes `k` (×1 000) et `M` (×1 000 000) |
| X mégabits par seconde | `mbps=100` | ⚠️ **méga*bits***, pas méga-octets : 1 Mo/s = `mbps=8` |
| X gigabits par seconde | `gbps=1` | converti en `mbps=1000` |

Le préfixe `--` est toléré : `pps=1000`, `--pps=1000` et `pps 1000` sont équivalents.
`pps` et `mbps` sont liés par la taille moyenne des paquets :
`mbps ≈ pps × taille_moyenne_octets × 8 / 1 000 000`.

---

## 1️⃣ `gen_traffic.py`

### Au lancement : `--rate`

```bash
sudo -E $(which python) gen_traffic.py                       # topspeed (défaut)
sudo -E $(which python) gen_traffic.py --rate pps=20000
sudo -E $(which python) gen_traffic.py --rate=pps=50k
sudo -E $(which python) gen_traffic.py --rate mbps=100
sudo -E $(which python) gen_traffic.py --rate=--topspeed     # ancienne syntaxe, toujours valide
```

Une valeur invalide est refusée **immédiatement** avec un message clair
(ex. `--rate=--pps` sans valeur → « pps sans valeur : écris pps=<nombre> »).

### À chaud : commande `rate` sur stdin

Taper dans le terminal du générateur (ou écrire sur son stdin) :

```
rate pps=20000     → passe à 20 000 paquets/s
rate mbps=50       → passe à 50 Mbit/s
rate topspeed      → repasse à fond
rate               → affiche le débit courant
status             → pcap en cours + débit
attack / normal    → change de pcap (le débit courant est conservé)
quit               → arrête tout
```

Un changement de débit **relance tcpreplay** sur le pcap courant : prévoir une micro-coupure
(quelques ms). Une commande invalide est refusée, le débit en cours n'est pas touché.

### Si ça ne marche pas

- Les erreurs de tcpreplay sont écrites dans **`/tmp/ids_tcpreplay.log`** (avant : jetées).
- Si tcpreplay meurt dans les 2 s suivant son lancement, le script s'arrête avec le message d'erreur
  au lieu de relancer en boucle.

---

## 2️⃣ `profile_run.py`

⚠️ Ne pas confondre : **`--rate`** = fréquence d'échantillonnage de py-spy (Hz).
Le débit du trafic se règle avec **`--traffic-rate`** et **`--rate-switch`**.

| Option | Rôle |
|---|---|
| `--traffic-rate SPEC` | Débit **initial** (défaut `topspeed`). Seul, il donne un débit **fixe**. |
| `--rate-switch "T:SPEC,T:SPEC"` | Débit **dynamique** : à T secondes après le début du profil, bascule sur SPEC. |

```bash
# Débit fixe à 20 000 pps
sudo -E $(which python3) profile_run.py --traffic --traffic-rate pps=20000 --duration 90

# Dynamique : 10k pps → 50k pps à 60 s → topspeed à 120 s
sudo -E $(which python3) profile_run.py --traffic --duration 180 \
    --traffic-rate pps=10000 --rate-switch "60:pps=50000,120:topspeed"

# Combiné avec l'attaque : attaque à 40 s, puis on monte le débit à 80 s
sudo -E $(which python3) profile_run.py --traffic --duration 150 \
    --traffic-rate pps=10000 --attack-after 40 --rate-switch "80:topspeed"
```

- `--rate-switch` exige `--traffic`. Les specs sont validées **avant** de lancer quoi que ce soit.
- Un temps ≥ `--duration` est signalé (il ne sera jamais atteint).
- Le rapport (`report.md`) contient une section **« Phases de trafic »** : une ligne par phase
  (changement de pcap ou de débit) avec le pkt/s moyen/max vu par l'IDS et la perte cumulée.
  Pratique pour trouver le débit à partir duquel l'IDS décroche.

---

## 🛠️ Corrections apportées à `gen_traffic.py`

1. **`--rate`** : `--rate --topspeed` (avec espace) est maintenant accepté ; valeurs validées au démarrage.
2. **Débit invalide / `--pps` sans valeur** : tcpreplay échouait en silence (stderr vers `/dev/null`) et
   le watchdog le relançait à l'infini. Maintenant : erreur affichée + log + arrêt.
3. **Ordre des arguments tcpreplay** : le débit est mis *avant* le fichier pcap.
4. **`quit`** ne quittait pas le programme (`SystemExit` levé dans le thread stdin) ; ça passe
   maintenant par un `Event`, le nettoyage (`veth_down`) est bien exécuté.
5. **`self._stop`** dans `StdinReader` écrasait `Thread._stop()` de la stdlib → renommé `_stop_evt`.
6. Une exception dans une commande stdin ne tue plus le lecteur silencieusement.
7. `--help` affichait l'en-tête Spyder au lieu de la vraie description (docstring en double).
8. Vérification de la présence de `tcpreplay` au démarrage.