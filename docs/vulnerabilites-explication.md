# Les 30 vulnérabilités du dataset — explication, impact, exemples

Doc de référence avant génération du serveur vulnérable. Chaque fiche donne : ce qu'est la vuln, son impact réel, et un exemple de requête d'attaque type (pour comprendre le pattern, pas un exploit prêt à l'emploi).

---

## 1. SQLi — SQL Injection
**Description** : Une entrée utilisateur est concaténée directement dans une requête SQL sans paramétrage ni échappement.
**Impact** : Lecture/modification/suppression de toute la base, contournement d'authentification, parfois exécution de commandes système (via `xp_cmdshell` sur MSSQL par ex.).
**Exemple** :
```
GET /products?id=1' OR '1'='1
POST /login  body: username=admin'--&password=x
```

## 2. CMDi — Command Injection
**Description** : Une entrée utilisateur est passée à un shell système (`os.system`, `subprocess` avec `shell=True`) sans validation.
**Impact** : Exécution de commandes arbitraires sur le serveur → compromission totale de la machine.
**Exemple** :
```
POST /ping  body: host=127.0.0.1; cat /etc/passwd
```

## 3. InsecDeser — Insecure Deserialization
**Description** : L'application désérialise des données non fiables (pickle Python, `yaml.load`, objets Java sérialisés) venant de l'utilisateur.
**Impact** : Exécution de code arbitraire au moment de la désérialisation, avant même l'usage de l'objet.
**Exemple** :
```
POST /import  body: {"data": "<base64 d'un objet pickle malveillant>"}
```

## 4. InsecUpload — Insecure File Upload
**Description** : Absence de contrôle du type/contenu/nom des fichiers uploadés, ou stockage dans un dossier exécutable.
**Impact** : Upload d'un webshell (`.php`, `.py`) exécuté ensuite via HTTP → exécution de code à distance.
**Exemple** :
```
POST /upload  multipart: fichier "shell.php" contenant <?php system($_GET['c']); ?>
```

## 5. BufOvr — Buffer Overflow
**Description** : Écriture au-delà des limites d'un buffer mémoire alloué (surtout code natif C/C++, ou binding Python vers du C non sécurisé).
**Impact** : Crash, corruption mémoire, parfois exécution de code arbitraire (écrasement d'adresse de retour).
**Exemple** :
```
POST /parse-header  body: X-Custom-Field: AAAAAAAAAA...[8000 'A']...
```

## 6. CredsExpose — Credentials Exposure
**Description** : Identifiants (clés API, mots de passe, tokens) laissés en clair dans le code source, les réponses HTTP, les logs ou des fichiers accessibles (`.env`, `.git`).
**Impact** : Vol direct d'accès à des services tiers ou à la base de données.
**Exemple** :
```
GET /.env
GET /api/debug/config   -> renvoie {"db_password": "s3cr3t", "aws_key": "AKIA..."}
```

## 7. BrokenAuth — Broken Authentication
**Description** : Mécanisme d'authentification défaillant : pas de limite de tentatives, mots de passe faibles acceptés, tokens de session prévisibles, "remember me" mal implémenté.
**Impact** : Prise de contrôle de comptes par brute-force ou prédiction de session.
**Exemple** :
```
POST /login  (aucune limite, testable en boucle) body: username=admin&password=<bruteforce>
```

## 8. XSS — Cross-Site Scripting
**Description** : Une entrée utilisateur est renvoyée dans le HTML de la page sans échappement, permettant l'exécution de JS dans le navigateur de la victime.
**Impact** : Vol de session/cookies, actions au nom de la victime, defacement, keylogging.
**Exemple** :
```
GET /search?q=<script>alert(document.cookie)</script>
```

## 9. DirTrav — Directory / Path Traversal
**Description** : Un paramètre de chemin de fichier n'est pas validé, permettant de sortir du dossier prévu avec `../`.
**Impact** : Lecture (ou écriture) de fichiers arbitraires sur le serveur (`/etc/passwd`, fichiers de config, code source).
**Exemple** :
```
GET /files?name=../../../../etc/passwd
```

## 10. XXE — XML External Entity
**Description** : Un parseur XML mal configuré résout les entités externes définies dans le document (`<!ENTITY>`).
**Impact** : Lecture de fichiers locaux, SSRF, parfois déni de service (entity expansion / "billion laughs").
**Exemple** :
```xml
POST /import-xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

## 11. NoSQLi — NoSQL Injection
**Description** : Équivalent du SQLi pour les bases NoSQL (MongoDB...) : injection d'opérateurs dans une requête construite depuis l'input utilisateur.
**Impact** : Contournement d'authentification, extraction de données.
**Exemple** :
```
POST /login  body: {"username": "admin", "password": {"$ne": ""}}
```

## 12. LDAPi — LDAP Injection
**Description** : Une entrée utilisateur est insérée dans un filtre LDAP sans échappement des caractères spéciaux (`*`, `(`, `)`).
**Impact** : Contournement d'authentification, extraction d'informations de l'annuaire.
**Exemple** :
```
POST /login  body: username=*)(uid=*))(|(uid=*&password=x
```

## 13. InsecPerm — Insecure Permissions
**Description** : Contrôle d'accès mal configuré au niveau fichier/ressource/API — droits trop permissifs par défaut.
**Impact** : Accès ou modification de ressources qui devraient être restreintes.
**Exemple** :
```
GET /admin/export-all   -> accessible sans rôle admin vérifié
```

## 14. IDOR — Insecure Direct Object Reference
**Description** : Une ressource est accédée via un identifiant direct (ID en URL) sans vérifier que l'utilisateur a le droit d'y accéder.
**Impact** : Accès aux données d'autres utilisateurs simplement en changeant un ID.
**Exemple** :
```
GET /api/invoices/1042   (l'utilisateur connecté n'est pas propriétaire de la facture 1042)
```

## 15. SessFix — Session Fixation
**Description** : L'application accepte un identifiant de session fourni par l'attaquant au lieu d'en régénérer un nouveau à la connexion.
**Impact** : L'attaquant fixe un ID de session à la victime avant login, puis l'utilise après qu'elle se soit authentifiée.
**Exemple** :
```
GET /login?sessionid=ATTACKER_CHOSEN_ID
(puis après login légitime de la victime, l'ID reste valide pour l'attaquant)
```

## 16. SSRF — Server-Side Request Forgery
**Description** : Le serveur effectue une requête HTTP vers une URL fournie par l'utilisateur sans restriction.
**Impact** : Accès à des services internes non exposés (metadata cloud, réseau interne), pivot réseau.
**Exemple** :
```
POST /fetch-preview  body: {"url": "http://169.254.169.254/latest/meta-data/"}
```

## 17. SSTI — Server-Side Template Injection
**Description** : Une entrée utilisateur est rendue directement par le moteur de template (Jinja2, Twig...) au lieu d'être passée comme simple variable.
**Impact** : Exécution de code arbitraire côté serveur.
**Exemple** :
```
GET /greet?name={{7*7}}     -> si la page affiche "49", le SSTI est confirmé
GET /greet?name={{config.items()}}
```

## 18. Prototype_Pollution
**Description** : (JS/Node) Une fusion d'objets non contrôlée permet de modifier `Object.prototype`, affectant tous les objets de l'application.
**Impact** : Contournement de logique métier, parfois exécution de code selon comment la propriété polluée est utilisée ensuite.
**Exemple** :
```
POST /merge-settings  body: {"__proto__": {"isAdmin": true}}
```

## 19. HTTP_Request_Smuggling
**Description** : Désaccord d'interprétation entre deux serveurs HTTP en chaîne (proxy/back-end) sur où se termine une requête, souvent via `Content-Length` vs `Transfer-Encoding`.
**Impact** : Contournement de contrôles de sécurité du proxy, vol de requêtes d'autres utilisateurs, cache poisoning.
**Exemple** :
```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
...
```

## 20. XPATH_Injection
**Description** : Une entrée utilisateur est insérée dans une requête XPath (utilisée pour interroger du XML) sans échappement.
**Impact** : Contournement d'authentification, extraction de données du document XML.
**Exemple** :
```
POST /login  body: username=' or '1'='1&password=' or '1'='1
```

## 21. GraphQLi — GraphQL Injection / abuse
**Description** : Absence de validation de profondeur/complexité des requêtes, introspection laissée active en prod, ou injection dans les résolveurs.
**Impact** : Déni de service (requêtes imbriquées coûteuses), fuite du schéma complet, extraction de données non prévues.
**Exemple** :
```
POST /graphql
{"query": "{ __schema { types { name fields { name } } } }"}
```

## 22. CORS — Cross-Origin Resource Sharing misconfiguré
**Description** : Le serveur renvoie `Access-Control-Allow-Origin: *` (ou reflète l'origine) combiné à `Access-Control-Allow-Credentials: true`.
**Impact** : Un site malveillant peut lire des données authentifiées de l'utilisateur depuis l'API vulnérable.
**Exemple** :
```
Réponse serveur:
Access-Control-Allow-Origin: https://site-attaquant.com
Access-Control-Allow-Credentials: true
```

## 23. CSRF — Cross-Site Request Forgery
**Description** : Absence de token anti-CSRF sur une action qui modifie un état, permettant à un site tiers de déclencher l'action au nom de la victime connectée.
**Impact** : Actions non voulues exécutées avec les droits de la victime (changement d'email, virement, suppression...).
**Exemple** :
```html
<img src="https://site-cible.com/transfer?to=attacker&amount=1000">
```

## 24. RateLimit — Absence de limitation de débit
**Description** : Aucune limite sur le nombre de requêtes/tentatives (login, reset password, API) par utilisateur ou IP.
**Impact** : Brute-force facilité, abus de ressources, déni de service applicatif.
**Exemple** :
```
POST /login  (répété 100000x sans blocage)
```

## 25. InfoDisc — Information Disclosure
**Description** : Fuite d'informations sensibles via messages d'erreur détaillés, stack traces, commentaires HTML, headers serveur verbeux.
**Impact** : Aide à la reconnaissance pour d'autres attaques (versions, chemins internes, structure de la BDD).
**Exemple** :
```
GET /api/user/999999999
-> 500 Internal Server Error: Traceback (most recent call last)... File "/app/models/user.py" line 42...
```

## 26. InsecCrypto — Insecure Cryptography
**Description** : Usage d'algorithmes faibles (MD5/SHA1 pour mots de passe sans sel, DES, ECB), ou clés hardcodées.
**Impact** : Mots de passe cassables rapidement, données chiffrées récupérables.
**Exemple** :
```
Stockage observé: password_hash = md5(password)   (sans sel)
```

## 27. OpenRedirect — Redirection ouverte
**Description** : Un paramètre contrôlant une redirection HTTP n'est pas validé contre une liste blanche.
**Impact** : Phishing (URL du domaine légitime qui redirige vers un site malveillant), contournement de filtres.
**Exemple** :
```
GET /redirect?url=https://site-phishing-qui-imite-le-vrai.com
```

## 28. JWT — Vulnérabilités JSON Web Token
**Description** : Mauvaise validation du token : acceptation de `alg: none`, clé secrète faible/devinable, absence de vérification de signature.
**Impact** : Forge de tokens arbitraires → usurpation d'identité, élévation de privilèges (`role: admin`).
**Exemple** :
```
Header modifié: {"alg": "none", "typ": "JWT"}
Payload: {"user": "admin", "role": "admin"}
(signature vide, acceptée par un serveur mal validé)
```

## 29. CRLF_Injection
**Description** : Une entrée utilisateur contenant `\r\n` est insérée dans des headers HTTP sans filtrage.
**Impact** : Injection de headers arbitraires, HTTP Response Splitting, parfois XSS via une réponse forgée.
**Exemple** :
```
GET /redirect?url=/home%0d%0aSet-Cookie:%20session=attacker_value
```

## 30. RaceCondition — Condition de course
**Description** : Deux requêtes concurrentes exploitent une fenêtre de temps entre vérification et action (TOCTOU) non protégée par verrou/transaction atomique.
**Impact** : Contournement de limites métier (ex: utiliser un coupon de réduction plusieurs fois, retirer plus d'argent que le solde disponible).
**Exemple** :
```
20 requêtes simultanées: POST /withdraw  body: {"amount": 100}
(sur un solde de 100, si pas de verrou atomique, plusieurs retraits peuvent passer)
```

---

## Notes pour la génération du serveur de test

- Chaque fiche ci-dessus correspond à un "moteur" de vuln implémenté réellement (comportement vulnérable authentique, pas juste un label cosmétique).
- Les exemples de requêtes serviront de base aux payloads de test/fuzzing générés automatiquement pour chaque route.
- Prochaine étape : génération du serveur Flask avec routes mono-vuln, multi-vuln, et manifest.json associé.
