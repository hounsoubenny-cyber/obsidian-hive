# Site statique vulnérable — ShieldAI (test passif)

Site **100% statique** (aucun backend, aucune route dynamique) destiné à tester
la partie **analyse passive + analyse de code** du scanner, **sans fuzzer actif
ni modèle ML**. Complète tes `vuln_server*.py` existants (qui testent surtout
le fuzzing actif).

## Lancer le site

```bash
cd vuln_static_site
python3 serve.py        # http://localhost:8090
```

## Lancer le scan (sans fuzzer, sans ML)

Utilise ton scanner avec `active_scan=False` (ou l'option CLI équivalente) pour
n'exécuter que crawler + analyse passive + analyse de code sur ce site, puis
compare la sortie à `manifest.json`.

## Contenu

| Page | Vuln attendue | Technique |
|---|---|---|
| `index.html` | InfoDisc | commentaire HTML révélant un chemin caché |
| `page_xss_dom.html` | XSS | DOM XSS via `location.hash` → `innerHTML` |
| `page_secrets.html` | CredsExpose | clés API/mots de passe en dur dans le JS |
| `page_outdated_lib.html` | XSS, InsecCrypto | jQuery 1.12.4 / Angular 1.5.8 (CVE connues) |
| `page_form_csrf.html` | CSRF | formulaires sans token, action sensible en GET |
| `page_clickjack.html` | InfoDisc | page sensible sans anti-clickjacking |
| `page_info_disclosure.html` | InfoDisc, CredsExpose | commentaires/stack trace avec secrets |
| `page_safe.html` | SAFE | témoin négatif — mesure les faux positifs |
| `.env` | CredsExpose, InfoDisc | fichier de config exposé publiquement |

`serve.py` sert aussi le site avec des **headers de sécurité volontairement
absents** (pas de CSP, X-Frame-Options, HSTS...) et un **CORS trop permissif**
(`Access-Control-Allow-Origin: *` + `Allow-Credentials: true`), pour tester
la détection au niveau des headers de réponse en plus du contenu des pages.

⚠️ Tous les secrets/clés sont **factices**. Usage local uniquement, ne jamais
déployer ce site publiquement.

## Prochaine étape

Une fois testé sans ML : comparer `manifest.json` aux résultats réels du scan,
calculer précision/rappel par classe, puis on nettoie le zip original.
