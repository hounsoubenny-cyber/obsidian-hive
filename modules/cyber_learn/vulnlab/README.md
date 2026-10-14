# VulnLab 🔐

Lab de pentest perso, 5 niveaux de difficulté croissante, à lancer sur **ta propre machine**.
Chaque niveau cache un `FLAG{...}`. Objectif : le trouver et le valider.

⚠️ **Règle d'or** : ne lis pas le code source des niveaux avant de les avoir attaqués, sinon
tu perds tout l'intérêt de l'exercice. Les flags ne sont volontairement pas stockés en clair
dans `check_flag.py` (juste leur hash) pour éviter la tentation de tricher.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate      # sous Windows: venv\Scripts\activate
pip install flask
```

## Lancer les niveaux

```bash
python3 start.py        # lance les 5 niveaux en même temps
python3 start.py 1 2    # lance seulement les niveaux 1 et 2
```

| Niveau | Protocole / Port         | Type        |
|--------|---------------------------|-------------|
| 1      | HTTP - 127.0.0.1:5001     | Web (facile)|
| 2      | HTTP - 127.0.0.1:5002     | Web (moyen) |
| 3      | HTTP - 127.0.0.1:5003     | Web (difficile) |
| 4      | TCP brut - 127.0.0.1:4444 | Service réseau |
| 5      | HTTP - 127.0.0.1:5005 (+ API interne 6000) | Web + réseau + "privesc" |

## Valider un flag

```bash
python3 check_flag.py "FLAG{...}"
```

## Outils conseillés (déjà sur la plupart des distros Linux, sinon `apt install`)

- `nmap` — scanner les ports ouverts (`nmap -p- -sV 127.0.0.1`)
- `curl` / navigateur — explorer les apps web
- `netcat` (`nc`) — parler directement à un service TCP brut
- Burp Suite (Community) ou juste les devtools du navigateur — intercepter/modifier les requêtes
- `python3` — scripts perso pour automatiser une attaque (brute force, fuzzing...)

## Idée de méthode (comme en vrai pentest)

1. **Recon** : quels ports sont ouverts ? (`nmap`)
2. **Énumération** : quelles pages/endpoints existent ? quels formulaires ?
3. **Exploitation** : teste les classes de vulnérabilités que tu connais (injection, logique
   métier cassée, contrôle d'accès, mauvaise configuration...)
4. **Post-exploitation** : une fois dans la place, qu'est-ce que tu peux atteindre d'autre ?

## Arrêter

`Ctrl+C` dans le terminal où tourne `start.py`.

## Aller plus loin

Une fois les 5 niveaux pliés, demande à Claude de t'ajouter :
- un niveau 6 encore plus tordu,
- des write-ups une fois que tu as trouvé (pas avant !),
- une version avec Docker pour isoler proprement chaque niveau.
