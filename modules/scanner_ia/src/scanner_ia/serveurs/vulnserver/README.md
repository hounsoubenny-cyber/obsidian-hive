# vulnserver — serveur de test volontairement vulnérable

Généré pour produire des données d'entraînement pour un modèle ML
multi-label de détection de vulnérabilités web (10 000+ endpoints).

## ⚠️ Avertissements — À LIRE avant de lancer

Ce serveur contient de **vraies vulnérabilités exploitables** (injections SQL/
commande réelles, path traversal réel, désérialisation pickle réelle, etc.),
volontairement, pour que ton scanner/fuzzer ait quelque chose de réaliste à
détecter. Ce n'est **pas** cosmétique.

- **Ne jamais exposer ce serveur sur Internet ou sur un réseau non isolé.**
- **Lance-le uniquement dans un conteneur/VM jetable**, jamais sur ta machine
  hôte avec des données réelles à côté.
- Le moteur `CMDi` exécute de vraies commandes shell (`subprocess(shell=True)`).
- Le moteur `InsecDeser` appelle réellement `pickle.loads()` sur de l'input
  externe — en dehors de cette démo, ça permet l'exécution de code arbitraire.
- Le moteur `DirTrav` / `InsecUpload` lisent/écrivent réellement des fichiers
  sous `/tmp/vulnserver_*`.
- Le moteur `BufOvr` est isolé dans un sous-process (`multiprocessing`) pour
  qu'un crash mémoire ne puisse jamais faire tomber le serveur principal.
- Le moteur `SSRF` ne fait **pas** de vraie requête réseau sortante : il
  simule la détection de cible interne, par sécurité.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Lancement

```bash
python app.py
```

Démarre sur `http://0.0.0.0:5000` et écrit `manifest.json` à la racine.

## Structure

```
vulnserver/
  app.py            # point d'entrée
  generator.py       # génère les 10000+ routes mono/multi + manifest
  engines/
    base.py          # Unit, UnitCtx, helpers communs
    sqli.py, cmdi.py, xss.py, ... # un fichier par vulnérabilité (30 au total)
  manifest.json       # généré au lancement : route -> vulns -> métadonnées
```

## Le manifest.json

Chaque route générée a une entrée :

```json
{
  "route": "/products/sqli-where_id_concat",
  "method": "GET",
  "page_type": "mono",
  "resource": "products",
  "vulns": ["SQLi"],
  "details": [
    {
      "vuln": "SQLi",
      "variant": "where_id_concat",
      "context": "query",
      "param": "id",
      "description": "id concaténé directement dans une clause WHERE numérique",
      "difficulty": "easy"
    }
  ]
}
```

→ directement utilisable comme labels pour l'entraînement multi-label
(`vulns` = liste des classes positives pour cette route).

## Volumétrie générée

- **10 170 routes** au total
- **7 020 mono-vuln** (30 types de vulns × ~78 variantes techniques × 90
  combinaisons de ressources/préfixes)
- **3 150 multi-vuln** (35 combinaisons curées de 2-3 vulns × 90 ressources)

## Les 30 types de vulnérabilités couverts

SQLi, CMDi, InsecDeser, InsecUpload, BufOvr, CredsExpose, BrokenAuth, XSS,
DirTrav, XXE, NoSQLi, LDAPi, InsecPerm, IDOR, SessFix, SSRF, SSTI,
Prototype_Pollution, HTTP_Request_Smuggling, XPATH_Injection, GraphQLi,
CORS, CSRF, RateLimit, InfoDisc, InsecCrypto, OpenRedirect, JWT,
CRLF_Injection, RaceCondition.

Voir `vulnerabilites-explication.md` (fourni séparément) pour le détail de
chaque vuln, son impact, et un exemple de requête.

## Étendre / ajuster le volume

Dans `generator.py` :
- `NOUNS` / `PREFIXES` contrôlent le nombre de "ressources" (donc le nombre
  de routes mono générées).
- `MULTI_COMBOS` contrôle les combinaisons multi-vuln (ajoute/retire des
  tuples pour ajuster le volume et l'équilibre des classes).
- Pour ajouter des variantes à un vuln existant, ajoute un `Unit` de plus
  dans `make_units()` du fichier correspondant sous `engines/`.
