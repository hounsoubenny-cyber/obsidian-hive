# VulnMart 🛒⚠️

Boutique e-commerce **volontairement vulnérable**, construite comme cible de test/entraînement
pour un scanner de sécurité (Obsidian Hive — module Scanner). Ne jamais déployer sur un réseau
non isolé ou public.

## Installation

```bash
cd vulnmart
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py      # crée vulnmart.db avec des données de démo
python app.py           # lance sur http://0.0.0.0:5000
```

Comptes de démo : `admin/admin123`, `alice/alice2020`, `bob/letmein`, `sam/P@ssw0rd!`

## Table des vulnérabilités (pour calibrer la détection/le scoring)

| # | Route | Type (OWASP) | Sévérité | Détail |
|---|-------|--------------|----------|--------|
| 1 | tout le code | Hardcoded secrets (A05/A02) | Haute | `SECRET_KEY`, `JWT_SECRET`, clé Stripe factice en dur dans `app.py` |
| 2 | global | Security Misconfiguration (A05) | Moyenne | `DEBUG=True` en "prod", stacktraces exposées |
| 3 | `/login` | SQL Injection (A03) | Critique | Requête construite par f-string, bypass avec `' OR '1'='1` |
| 4 | `/login` | Information disclosure (A05) | Moyenne | Erreur SQL brute + requête renvoyée dans la réponse |
| 5 | `/login` (cookie `remember_token`) | Broken auth / JWT faible (A07/A02) | Haute | Secret JWT faible et statique, pas de vérif d'algo |
| 6 | `/search?q=` | XSS réfléchi (A03) | Haute | `q` réinjecté avec `\|safe` dans le template |
| 7 | `/product/<id>` | IDOR (A01) | Basse-Moyenne | Tout produit accessible, pas grave en soi mais pattern à détecter |
| 8 | `/product/<id>` (avis) | XSS stocké (A03) | Critique | Avis client rendu avec `\|safe`, persistant en DB |
| 9 | `/profile/<username>` | IDOR (A01) | Critique | Aucun contrôle que le viewer == propriétaire |
| 10 | `/profile/<username>` | Sensitive data exposure (A02) | Critique | SSN, carte bancaire, hash de mot de passe affichés |
| 11 | `/api/user/<id>` | IDOR + fuite API (A01) | Critique | Même faille que #9, en JSON, dump complet de la table `users` |
| 12 | `/admin` | Broken Access Control (A01) | Critique | Contrôle basé sur un cookie client `is_admin=true` |
| 13 | `/upload` | Unrestricted file upload (A04) | Haute | Aucune whitelist d'extension, pas de `secure_filename` |
| 14 | `/file?name=` | Path Traversal / LFI (A01) | Critique | Pas de normalisation de chemin, lit n'importe quel fichier lisible |
| 15 | `/ping` | Command Injection (A03) | Critique | `subprocess` avec `shell=True` + f-string non filtrée |
| 16 | `/fetch-image` | SSRF (A10) | Critique | `requests.get(url)` sans validation de schéma/hôte |
| 17 | `/cart/import` | Insecure Deserialization (A08) | Critique | `pickle.loads()` sur une entrée utilisateur base64 |
| 18 | `/account/change-email` | CSRF (A01) | Haute | Aucun jeton CSRF, POST accepté depuis n'importe quelle origine |
| 19 | `/reset-password` | Broken auth / prévisibilité (A07) | Haute | Token = timestamp, fuite du token dans la réponse, énumération d'emails |
| 20 | `/config` | Security Misconfiguration (A05) | Critique | Endpoint qui expose tous les secrets de config |
| 21 | `/login` (global) | Missing rate limiting (A07) | Moyenne | Aucun verrou anti brute-force |
| 22 | comptes `admin/alice/bob` | Weak crypto (A02) | Moyenne | Hashing MD5 sans sel pour les comptes "legacy" |
| 23 | `/comments` | XSS stocké (A03) | Critique | Identique à #8, sur un mur public sans auth |

## Idées pour la partie ML / scoring du Scanner

- Chaque route ci-dessus peut servir de **cas positif labellisé** (payload connu → vuln connue → sévérité connue) pour entraîner/valider le scoring.
- Le mélange volontaire de vulns "évidentes" (SQLi, XSS) et plus subtiles (IDOR sur `/product/<id>`, faible sévérité) donne de la variance pour tester la calibration du score plutôt qu'un simple classement binaire vuln/pas-vuln.
- Possibilité de dupliquer cette structure avec des variantes patchées (ex: `/login` avec requêtes paramétrées) pour générer des faux-négatifs contrôlés et mesurer le taux de détection réel du modèle.
