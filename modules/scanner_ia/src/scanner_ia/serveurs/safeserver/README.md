# safeserver — contre-partie sécurisée du vulnserver

Même structure exacte de routes que `vulnserver` (mêmes ressources, mêmes
noms de variants, mêmes points d'injection) mais chaque page implémente le
comportement **sécurisé** correspondant. Sert de jeu de labels négatifs
(`vulns: []`) pour équilibrer l'entraînement du modèle multi-label, en
complément du dataset produit par `vulnserver`.

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

Démarre sur `http://0.0.0.0:5001` (port différent du vulnserver pour
pouvoir lancer les deux en parallèle) et écrit `manifest.json`.

## Le manifest.json

Contrairement au vulnserver, `vulns` est **toujours vide** (`[]`) — c'est
le label négatif. Le champ `hardened_against` indique, à titre informatif,
contre quelle(s) classe(s) de faille chaque page a été durcie :

```json
{
  "route": "/products/sqli-where_id_concat",
  "vulns": [],
  "hardened_against": ["SQLi"],
  "details": [
    {
      "hardened_against": "SQLi",
      "variant": "where_id_concat",
      "context": "query",
      "param": "id",
      "description": "requête paramétrée (placeholder ?)"
    }
  ]
}
```

## Correspondance avec vulnserver

Les routes portent **les mêmes noms de variants** que dans `vulnserver`
(ex: `sqli-where_id_concat`, `xss-reflected_query_div`), ce qui permet un
mapping direct route-à-route entre les deux serveurs si tu veux comparer
les paires vulnérable/safe pour un même pattern.

## Ce qui a été appliqué comme correction, par vuln

| Vuln | Correction appliquée |
|---|---|
| SQLi | Requêtes 100% paramétrées (`?` placeholders), whitelist pour ORDER BY |
| CMDi | Aucun shell exécuté, validation stricte des entrées |
| InsecDeser | JSON strict uniquement, jamais pickle/yaml.unsafe_load |
| InsecUpload | Whitelist d'extensions + vérification des magic bytes |
| BufOvr | Longueur d'entrée bornée avant toute écriture |
| CredsExpose | Aucun secret en réponse, endpoints debug désactivés |
| BrokenAuth | Throttle réel (5 tentatives/60s), tokens CSPRNG |
| XSS | Échappement systématique (`markupsafe.escape`) |
| DirTrav | Chemin normalisé + vérifié contre le dossier de base |
| XXE | `resolve_entities=False`, `no_network=True` |
| NoSQLi | Champs sensibles limités aux types scalaires |
| LDAPi | Échappement des caractères spéciaux LDAP |
| InsecPerm | Rôle toujours lu depuis la session serveur, jamais du client |
| IDOR | Vérification systématique `owner_id == current_user` |
| SessFix | Session toujours régénérée côté serveur au login |
| SSRF | Liste blanche stricte de hosts autorisés |
| SSTI | Input toujours passé comme variable, jamais compilé comme template |
| Prototype_Pollution | Whitelist stricte de clés modifiables |
| HTTP_Request_Smuggling | Requête rejetée si CL et TE présents simultanément |
| XPATH_Injection | Comparaison en Python après extraction, pas de concat XPath |
| GraphQLi | Introspection désactivée, profondeur de requête limitée |
| CORS | Liste blanche stricte d'origines |
| CSRF | Token anti-CSRF requis et vérifié (HMAC) |
| RateLimit | Limite réelle appliquée (5 appels/60s) |
| InfoDisc | Messages d'erreur génériques, aucune stack trace |
| InsecCrypto | PBKDF2-HMAC-SHA256 salé (200k itérations) |
| OpenRedirect | Liste blanche stricte de chemins internes |
| JWT | Signature toujours vérifiée, `alg=none` jamais autorisé |
| CRLF_Injection | Filtrage systématique de `\r`/`\n` |
| RaceCondition | Verrous atomiques (`threading.Lock`) sur les sections critiques |

## Volumétrie

**10 170 routes** (7 020 mono + 3 150 multi), identique au vulnserver.
