---

## 📄 Document 1 : `explain.md` - Explication complète du système anti-phishing

```markdown
# ShieldAI - Système Anti-Phishing

## Architecture générale

Le système combine deux approches complémentaires :

1. **Analyse passive** : 18 critères heuristiques (âge domaine, présence d'IP, mots suspects, TLDs...)
2. **Apprentissage automatique** : Modèle ML entraîné sur 2M+ URLs avec 33 features

```
URL entrante
    │
    ├── Nettoyage + Cache
    │
    ├── Whitelist ? → SAFE immédiat
    │
    ├── Analyse parallèle
    │   ├── IA (33 features → probabilité phishing/safe)
    │   └── Passive (18 critères → score risque 0-100)
    │
    └── Décision finale (cascade 7 cas)
            │
            ├── safe / suspicious / phishing
            └── confidence + source + flags + advice
```

## Composants principaux

### 1. Base de domaines légitimes (`legitimate_domain_creator.py`)
- 5000+ domaines whitelistés
- Sources : Wikipedia Top Sites, Cloudflare Radar, DigitalStakeout
- Catégories : tech, e-commerce, finance, gouvernement, éducation...

### 2. Analyse passive (`passive_analyzer.py`)

**18 critères évalués :**

| Critère | Points max | Explication |
|---------|------------|-------------|
| Âge domaine < 7 jours | 35 | Domaine ultra récent = suspect |
| Punycode (xn--) | 52 | Attaque homoglyphe confirmée |
| Caractère @ | 52 | Technique d'obfuscation |
| IP dans l'URL | 55 | Masquage de l'identité |
| TLD suspect (.tk, .ml) | 30 | TLDs gratuits souvent abusés |
| Typosquatting | 60 | Domaine qui ressemble à un légitime |
| Mots suspects (login, verify) | 10-35 | Termes d'ingénierie sociale |

**Seuils de décision :**
- Score ≥ 55 → 🚨 CRITIQUE (phishing)
- Score ≥ 35 → ⚠️ ÉLEVÉ (phishing)
- Score ≥ 20 → 📊 MOYEN (suspicious)
- Score ≥ 10 → 📊 FAIBLE (safe)
- Score < 10 → ✅ NÉGLIGEABLE (safe)

### 3. Modèle ML (`phishing_ia.py` + `modelstack.py`)

**33 features extraites :**
- Longueur URL, longueur domaine
- Présence d'IP, présence HTTPS
- Âge du domaine (WHOIS)
- Nombre de sous-domaines
- Mots suspects, TLD suspect
- Nombre de redirections
- Entropie du domaine
- Caractères Unicode
- ...

**Architecture :**
```
Pipeline complet
    │
    ├── RobustScaler (normalisation)
    │
    └── StackingClassifier
            ├── XGBoost (n_estimators=1500)
            ├── ExtraTrees (n_estimators=600)
            ├── HistGradientBoosting (max_iter=1500)
            ├── MLP (100,50 neurones)
            │
            └── Méta-classifieur : LogisticRegression
```

### 4. Décision finale (`final_decision` dans `main_phish.py`)

Cascade à 7 cas :

| Cas | Condition | Décision |
|-----|-----------|----------|
| 1 | Domaine dans whitelist | safe (confiance 1.0) |
| 2 | IA safe > 85% | safe |
| 3 | IA phishing > 80% + passive safe | suspicious |
| 4 | IA phishing > 80% + passive phishing | phishing |
| 5 | SPF fail + DKIM absent (email) | phishing |
| 6 | Passive élevé + IA incertain | phishing |
| 7 | Fallback | safe |

### 5. Analyse email (`analyze_mail.py`)

Processus complet pour un email :

```
Email brut (.eml ou texte)
    │
    ├── parse_email()
    │   ├── Headers : From, Reply-To, SPF, DKIM
    │   ├── Body : texte propre (sans HTML)
    │   └── URLs : extraction + déduplication
    │
    ├── build_bert_input()
    │   → chaîne balisée pour BERT
    │   → [FROM] [SUBJECT] [SPF] [URLS] [BODY]
    │
    ├── predict_email_async()
    │   → appelle analyze_mail()
    │
    └── final_decision_mail()
        ├── URL critique (score > 90%) → phishing
        ├── BERT safe > 85% + passive faible → safe
        ├── SPF fail + DKIM absent → phishing
        └── Fallback → suspicious
```

### 6. API REST (`main_phish.py`)

**Endpoints principaux :**

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/analyze` | Analyse une URL |
| POST | `/api/analyze_mail` | Analyse un email (fichier ou texte) |
| GET | `/api/history` | Historique des analyses URL |
| GET | `/api/history_mail` | Historique des analyses email |
| GET | `/api/health` | État de santé |
| POST | `/api/settings` | Modifier configuration |
| GET | `/api/close` | Fermeture propre |

**Rate limiting :** 30 requêtes/minute par IP

### 7. Agent CrewAI (`agent/`)

**Outils disponibles :**
- `analyze_url` : analyse une URL complète (IA + passive)
- `analyze_email` : analyse un email complet
- `extract_urls` : extrait les URLs d'un texte
- `get_phishing_stats` : statistiques des analyses
- `clear_cache` : vide le cache
- `analyze_url_ia_only` : IA uniquement
- `analyze_url_passive_only` : passive uniquement
- `check_url_blacklist` : vérification blacklist externe

## Flux de données complet

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UTILISATEUR                                  │
│                    (CLI / API / Agent CrewAI)                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      AntiPhishing.predict_url()                      │
│                                                                      │
│  1. Nettoyage URL (_clean_url)                                       │
│  2. Vérification cache (diskcache)                                   │
│  3. Vérification whitelist                                           │
│  4. Lancement parallèle IA + Passive                                 │
│  5. Décision finale (cascade)                                        │
│  6. Mise en cache + historique                                       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   PhishingIA      │   │  PassiveAnalyzer  │   │   MailPhishing    │
│                   │   │                   │   │   (BERT email)    │
│ • 33 features     │   │ • 18 critères     │   │ • BERT encoder    │
│ • Stacking ML     │   │ • WHOIS age       │   │ • Contrastive     │
│ • Refit auto      │   │ • Typosquatting   │   │ • Classification  │
└───────────────────┘   └───────────────────┘   └───────────────────┘
```

## Formats de réponse

### Pour URL :
```json
{
    "final_decision": "safe|suspicious|phishing",
    "confidence": 0.95,
    "source": "whitelist|ia_prediction|passive_analyze|cascade",
    "date": "DD/MM/YYYY à HH:MM:SS",
    "elapsed": 0.45,
    "breakdown": {
        "ia_pred_proba": 0.92,
        "passive_analyze_level": "ÉLEVÉ",
        "flags": ["typosquatting", "tld_suspect"]
    }
}
```

### Pour email :
```json
{
    "final_decision": "safe|suspicious|phishing",
    "confidence": 0.92,
    "source": "url_critique|bert_haut_confiance|headers_compromis",
    "sender": "expediteur@example.com",
    "subject": "Sujet de l'email",
    "nb_urls_total": 3,
    "nb_urls_phishing": 2,
    "spf": "fail",
    "dkim": "absent",
    "analysis": "Analyse détaillée..."
}
```

## Installation et utilisation

### CLI
```bash
# Analyser une URL
python run_cli.py -u https://google.com

# Analyser une URL avec blacklist
python run_cli.py -u https://paypal-verify.tk -b

# Analyser un email
python run_cli.py --email "Objet: Vérification..."

# Lancer l'API
python run_cli.py --api --port 8080

# Lancer les tests
python run_cli.py --test -v

# Vider le cache
python run_cli.py --clear-cache
```

### API
```bash
# Démarrer l'API
python run_api.py

# Ou via CLI
python run_cli.py --api --host 0.0.0.0 --port 8000
```

### Agent CrewAI
```python
from crewai import LLM
from anti_phishing_ia.agent.agent import create_anti_phishing_agent

llm = LLM(model="groq/llama-3.3-70b-versatile")
agent = create_anti_phishing_agent(llm)
```

## Fichiers de configuration clés

| Fichier | Rôle |
|---------|------|
| `config.py` | Configuration globale (ports, chemins, seuils) |
| `DATA` dans `config.py` | Paramètres par défaut de l'analyse |
| `legitimate_domains_mega.joblib` | Whitelist 5000+ domaines |
| `history/history.json` | Historique des analyses URL |
| `history/history_mail.json` | Historique des analyses email |

## Équipe

**Auteur :** HOUNSOU Samuel  
**Version :** 2.0.0  
**Projet :** AntiPhishing Based on IA and Static Analysis
```

---

## 📄 Document 2 : Guide pour reconnaître le phishing

### Option A : Fichier Markdown à télécharger

```markdown
# Guide complet : Comment reconnaître une tentative de phishing

## Qu'est-ce que le phishing ?

Le phishing est une technique frauduleuse visant à obtenir des informations personnelles (identifiants, mots de passe, données bancaires) en se faisant passer pour une entité de confiance.

## Les 10 signaux d'alerte à connaître

### 1. L'URL ne correspond pas au site officiel

| Signal suspect | Exemple | Pourquoi c'est dangereux |
|----------------|---------|--------------------------|
| Domaine différent | `paypal-verification.net` au lieu de `paypal.com` | Les pirates achètent des noms proches |
| TLD bizarre | `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz` | TLDs gratuits = aucune vérification d'identité |
| Sous-domaine trompeur | `paypal.com.secure-login.tk` | Le vrai domaine est après le dernier point |
| Typosquatting | `gooogle.com` (3 'o'), `paypa1.com` (1 au lieu de l) | Erreur de frappe courante exploitée |

### 2. La barre d'adresse contient une IP

```
❌ http://192.168.1.100/login
❌ https://45.67.89.123/bank

✅ https://www.mabanque.fr
```

**Pourquoi :** Les sites légitimes utilisent des noms de domaine, pas des adresses IP.

### 3. Présence d'un caractère @ dans l'URL

```
❌ https://www.paypal.com@malicious-site.net/login
```

**Explication :** Le caractère @ trompe le navigateur. Tout ce qui est avant @ est ignoré.

### 4. Le domaine contient des caractères étranges

```
❌ https://xn--pple-43d.com  (аpple avec un 'a' cyrillique)
❌ https://gⓞⓞgle.com
❌ https://рaypal.com  ('р' cyrillique au lieu de 'p')
```

**Ce qu'il faut savoir :** Les pirates utilisent des caractères d'autres alphabets qui ressemblent aux lettres latines.

### 5. L'URL est anormalement longue

```
❌ https://secure.paypal.com.cgi-bin.webscr.cmd.login.dispatch.session-id.789456123.xyz/...
```

**Pourquoi :** La longueur cache la vraie destination.

### 6. Le site utilise HTTP (pas de cadenas)

```
❌ http://www.paypal.com/login
✅ https://www.paypal.com/login
```

**Règle simple :** Pas de cadenas → pas d'informations personnelles.

### 7. Fautes d'orthographe dans l'email ou le site

**Exemples réels :**
- "Votre compte a été **verrouillé**" au lieu de "vérrouillé"
- "**Cliqez** ici" au lieu de "Cliquez"
- "PayPal **Sécurity** Department"

### 8. Urgence ou menace

**Phrases typiques :**
- "Votre compte sera suspendu dans 24h"
- "Action requise immédiatement"
- "Nous avons détecté une activité suspecte"
- "Cliquez ici pour vérifier votre identité"

**Pourquoi :** La pression psychologique empêche la réflexion.

### 9. L'expéditeur ne correspond pas au domaine

**Exemple :**
- Expéditeur : `service@paypal.com`
- Mais le lien pointe vers `https://paypa1.xyz/login`
- Ou l'adresse Reply-To est différente : `noreply@fake-paypal.ru`

### 10. Absence de SPF/DKIM (pour les emails)

Ces signatures prouvent que l'email vient vraiment du domaine affiché.  
Leur absence (ou un statut "fail") est un signal d'alerte fort.

## Vérifications simples à faire

### Avant de cliquer :

1. **Survolez le lien** (sans cliquer) : l'URL réelle apparaît en bas de la fenêtre
2. **Vérifiez le cadenas** : HTTPS n'est pas une garantie absolue, mais son absence est rédhibitoire
3. **Comparez avec le site officiel** : allez sur le site par vous-même (tapez l'URL dans votre navigateur)
4. **Cherchez sur Google** : tapez le nom de l'entreprise + "phishing" ou "arnaque"

### Ce qu'un site légitime ne vous demandera JAMAIS :

- Votre mot de passe par email
- Vos coordonnées bancaires complètes
- De "vérifier votre compte" via un lien
- De télécharger une pièce jointe inattendue
- Vos identifiants sur une page qui n'est pas le site officiel

## Statistiques 2025-2026

| Secteur le plus ciblé | Télécoms : 33% des attaques |
|----------------------|----------------------------|
| 2ème secteur | Banques : 28% |
| 3ème secteur | Services en ligne : 18% |
| Progression globale | +13.8% par rapport à 2024 |
| Domaines malveillants actifs | 378 000 simultanément (pic 2025) |

## Que faire si vous avez cliqué ?

1. **Ne saisissez RIEN** - fermez la page immédiatement
2. **Changez vos mots de passe** - sur le site officiel uniquement
3. **Activez la double authentification** si disponible
4. **Surveillez vos comptes** (banque, email, réseaux sociaux)
5. **Signalez le site** :
   - Google Safe Browsing : https://safebrowsing.google.com
   - Signal Spam (France) : https://www.signal-spam.fr
   - Pharos (arnaques en ligne) : https://www.internet-signalement.gouv.fr

## Ressources externes

### Documentation officielle

| Source | Lien | Contenu |
|--------|------|---------|
| ANSSI | [Recommandations](https://www.ssi.gouv.fr) | Guide officiel français |
| CNIL | [Guide phishing](https://www.cnil.fr) | Conseils aux particuliers |
| APWG | [Rapports trimestriels](https://apwg.org) | Statistiques mondiales |

### Vidéos et tutoriels (recherche Google/YouTube)

- "Comment reconnaître un email de phishing" - Cybermalveillance.gouv.fr
- "Test your phishing knowledge" - Google Phishing Quiz
- "Anatomy of a phishing attack" - IBM Security

### Exercices pratiques (recherche)

- "Phishing Spotter Challenge" (jeu interactif)
- "Can you spot the scam?" (Microsoft)
- "Jigsaw Phishing Quiz" (Google)

---

**Règle d'or :** Dans le doute, ne cliquez pas. Allez directement sur le site en tapant l'URL vous-même.
```

---