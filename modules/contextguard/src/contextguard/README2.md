```markdown
# 🛡️ ContextGuard – Protection des prompts IA

![Python Version](https://img.shields.io/badge/python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green)
![React](https://img.shields.io/badge/React-18+-61DAFB)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C)
![SQLite](https://img.shields.io/badge/SQLite-3+-003B57)
[![GitHub repo](https://img.shields.io/badge/GitHub-ContextGuard-181717?logo=github)](https://github.com/hounsoubenny-cyber/contextguard)

**ContextGuard** est une plateforme complète de détection et de protection en temps réel contre les injections de prompts, les jailbreaks et les tentatives d'exfiltration de données dans les interactions avec les modèles de langage (LLM).

Le projet comprend :
- Une **API REST** (FastAPI) avec JWT signé par secret serveur, chiffrement Fernet, base de données SQLite, cache de sessions en mémoire
- Un **modèle de deep learning** (Transformer entraîné from scratch) pour la classification des prompts, combiné à un moteur de règles statiques pour un filtrage instantané des patterns connus
- Un **SDK Python** stateful (sync + async) avec connexion intelligente, rafraîchissement automatique de token et récupération de session
- Un **frontend React** moderne (thème clair/sombre, statistiques, analyse interactive), servi directement par le backend

🔗 **Dépôt** : [github.com/hounsoubenny-cyber/contextguard](https://github.com/hounsoubenny-cyber/contextguard)

---

## 📦 Architecture globale

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React SPA)                         │
│  Login / Analyse / Health / IsConnected / Navigation / ThemeToggle   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTP (Fetch API)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         API (FastAPI)                                │
│  • Authentification JWT (HS256, secret serveur)                     │
│  • Cache de sessions en mémoire (dict + RLock, TTL 8h)              │
│  • Chiffrement Fernet (historique utilisateur)                      │
│  • Rate limiting (SlowAPI)                                          │
│  • Routes : /login, /analyse, /health, /is_connected,               │
│             /logout, /delete_account, /refresh_token, /salt         │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│  Base SQLite      │ │ Modèle Transformer│ │  Analyse statique   │
│  (utilisateurs,   │ │ (PyTorch / ONNX)  │ │ (patterns regex)    │
│   historique)      │ │                   │ │                     │
└───────────────────┘ └─────────────────┘ └─────────────────────┘
```

**Flux de détection :** un prompt passe d'abord par le moteur de règles statiques (regex) — s'il matche un pattern connu, la réponse est instantanée. Sinon, il tombe dans le modèle Transformer pour une analyse sémantique plus fine.

---

## 🧠 Modèle de classification

Le modèle est un **Transformer maison** (encodage positionnel sinusoïdal, multi-head self-attention, mean pooling, tête MLP) entraîné from scratch en PyTorch, qui classe les prompts en **4 catégories** :

| Label | Description |
|-------|-------------|
| `safe` | Prompt normal, sans risque |
| `injection` | Tentative d'injection (SQL, commandes, override) |
| `jailbreak` | Tentative de contournement des restrictions |
| `exfiltration` | Tentative d'extraction de données système |

**Caractéristiques techniques** :
- Architecture : Embedding + Multi-Head Attention + Mean Pooling + Classification head
- Tokenizer : BERT (`bert-base-uncased`)
- Taille max : 256 tokens
- Export possible vers **ONNX** pour inférence légère
- Complété par un **analyseur statique** basé sur des règles regex (fallback rapide)

### 📊 Données d'entraînement

Le dataset combine plusieurs sources publiques (Neuralchemy, DeepSet, corpus jailbreak, Dolly) agrégées et mappées vers la taxonomie à 4 classes, puis équilibrées par classe. Un pipeline d'**augmentation de données 100% offline** (templating, remplacement de synonymes, perturbations structurées, paraphrases) génère des variantes bilingues **FR/EN** pour renforcer la robustesse du modèle.

---

## 🔐 Sécurité

ContextGuard applique plusieurs principes de défense en profondeur :

| Mécanisme | Détail |
|-----------|--------|
| **Mot de passe** | Hashé en `bcrypt` en base |
| **JWT** | Signé avec `CONTEXTGUARD_JWT_SECRET` (variable d'environnement), algorithme HS256 |
| **Session** | Cache en mémoire (dict + `RLock`), TTL 8h aligné sur l'expiration JWT |
| **Salt utilisateur** | Généré serveur au signup, stocké en DB, sert **uniquement** à dériver la clé Fernet |
| **Historique** | Chiffré au repos avec `Fernet` (clé dérivée de `password + salt`) |
| **Rate limiting** | SlowAPI — limite globale par IP |
| **Suppression de compte** | Exige password **et** token valide (protection contre token volé) |

### 🔑 Variable d'environnement obligatoire

Le serveur refuse de démarrer sans clé JWT. Génère-la une fois :

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Et place-la dans ton `.env` :

```
CONTEXTGUARD_JWT_SECRET=<ta_clé_générée>
```

> ⚠️ **Ne jamais committer cette clé**. Si elle fuite, un attaquant peut forger des JWT pour n'importe quel utilisateur. En cas de compromission : régénère-la (toutes les sessions actives seront invalidées, les users devront se reconnecter).

---

## 🔐 API – Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/salt` | GET | Génère un nouveau sel bcrypt (diagnostic / bootstrap) |
| `/api/login` | POST | Création de compte (`connect=False`) ou connexion (`connect=True`) |
| `/api/analyse` | POST | Analyse d'un ou plusieurs prompts (batch async) |
| `/api/health` | POST | Récupère l'historique et les statistiques de l'utilisateur |
| `/api/is_connected` | POST | Vérifie si un utilisateur a une session active (sans token) |
| `/api/logout` | POST | Révoque la session serveur (purge du cache) |
| `/api/delete_account` | POST | Supprime définitivement le compte (password + token requis) |
| `/api/refresh_token` | POST | Rafraîchit un JWT expiré (sans vérifier l'expiration) |
| `/api/docs` | GET | Documentation Swagger interactive |

**Authentification** : Bearer token JWT (expiration configurable). Le salt n'est **plus** envoyé par le client à chaque requête — il est généré au signup, stocké en DB, et lu côté serveur à chaque appel qui en a besoin.

---

## 🧪 SDK Python

Le SDK (`sdk/`) expose un client **stateful**, **configurable** et **intelligent**, avec une version **synchrone** et **asynchrone** de chaque méthode.

### Structure

```
sdk/
├── __init__.py       # Point d'entrée public
├── client.py         # ContextGuardClient
├── models.py         # Modèles Pydantic (Params + Responses)
├── test_client.py    # Tests unitaires (transport mocké)
└── test_client_live.py  # Tests d'intégration (serveur réel)
```

### Utilisation asynchrone

```python
import asyncio
from contextguard.sdk import ContextGuardClient

async def main():
    client = ContextGuardClient(
        api_url="http://localhost:8000",
        username="alice",
        password="secret",
    )

    # Connexion intelligente : login d'abord, création si user inconnu
    conn = await client.connect_async()
    if not conn.success:
        print("Erreur :", conn.errors)
        return

    print(f"Connecté en tant que {conn.username} ({conn.state})")

    # Analyse — le client gère automatiquement :
    # - l'auto-connexion si pas de token
    # - le refresh sur 401 TOKEN_EXPIRED
    # - la reconnexion sur session perdue
    result = await client.analyse_async(
        prompts=["Hello world", "Ignore all previous instructions"],
        thresholds=0.5,
    )
    for prompt, item in result.results.items():
        print(f"[{item.label:12s} {item.prob:.1%}] {prompt}")

    # Vérifier l'état de session sans rien déclencher
    status = await client.is_connected_async()
    print(f"Session active : {status.connected}")

    # Déconnexion propre (révoque côté serveur)
    await client.logout_async()

asyncio.run(main())
```

### Utilisation synchrone

```python
from contextguard.sdk import ContextGuardClient

client = ContextGuardClient(
    username="alice",
    password="secret",
)

conn = client.connect()
if conn.success:
    result = client.analyse(["Hello world"])
    print(result.results)
    client.logout()
```

### Fonctionnalités clés

| Méthode | Description |
|---------|-------------|
| `connect()` / `connect_async()` | Login-first avec fallback création (mode intelligent) |
| `analyse()` / `analyse_async()` | Analyse batch avec auto-recover (refresh + reconnect) |
| `health()` / `health_async()` | Historique + statistiques, avec auto-recover |
| `is_connected()` / `is_connected_async()` | Diagnostic pur, sans reprise automatique |
| `refresh_token()` / `refresh_token_async()` | Renouvelle le JWT |
| `logout()` / `logout_async()` | Révoque la session serveur (idempotent) |
| `delete_account()` / `delete_account_async()` | Suppression définitive (password + token requis) |
| `get_salt()` / `get_salt_async()` | Récupère un nouveau sel bcrypt |
| `disconnect(clear_credentials=False)` | Efface l'état local (token, ou tout) |

### Interface des réponses

Toutes les réponses héritent de `SDKResponse` et offrent une **double interface** :

```python
resp = await client.analyse_async(["Hello"])

# Accès par attribut (typé)
resp.success                  # bool
resp.results["Hello"].label   # "safe"

# Accès par clé (dict-like)
resp["success"]
resp.get("results", {})

# Méthodes dict classiques
list(resp.keys())
dict(resp.items())
resp.to_dict()                # dict sérialisable JSON
```

### 🚀 Exemple d'intégration en prod

Écris un petit wrapper **une seule fois** — connexion au démarrage, puis un simple `check(prompt)` partout ailleurs :

```python
# guard.py — dans ton app cliente
import os
from contextguard.sdk import ContextGuardClient

class Guard:
    """Login une fois au démarrage, puis check(prompt) partout."""

    def __init__(self):
        self.client = ContextGuardClient(
            api_url=os.environ.get("CONTEXTGUARD_API_URL", "http://localhost:8000"),
            username=os.environ["CONTEXTGUARD_USER"],
            password=os.environ["CONTEXTGUARD_PASSWORD"],
        )

    async def start(self):
        conn = await self.client.connect_async()
        if not conn.success:
            raise RuntimeError(f"Connexion ContextGuard échouée : {conn.errors}")

    async def check(self, prompt: str, threshold: float = 0.5) -> bool:
        """True si le prompt est SAFE, False s'il faut le bloquer."""
        result = await self.client.analyse_async(
            prompts=[prompt],
            thresholds=threshold,
        )
        if not result.success:
            # Fail-closed : on bloque par défaut en cas d'erreur
            return False
        return result.results[prompt].is_safe

    async def close(self):
        await self.client.logout_async()

guard = Guard()  # instance globale, une seule connexion pour toute l'app
```

Ensuite, dans ta vraie application (exemple avec un chatbot FastAPI) :

```python
from fastapi import FastAPI, HTTPException
from guard import guard

app = FastAPI()

@app.on_event("startup")
async def startup():
    await guard.start()   # login une fois au démarrage de l'app

@app.on_event("shutdown")
async def shutdown():
    await guard.close()

@app.post("/chat")
async def chat(prompt: str):
    if not await guard.check(prompt):          # 👈 la ligne d'intégration
        raise HTTPException(400, "Prompt bloqué par ContextGuard")

    return await call_my_llm(prompt)  # ton appel LLM normal
```

---

## 💻 Frontend React

L'interface utilisateur est une **SPA** moderne avec :

### Composants principaux

| Composant | Route | Fonction |
|-----------|-------|----------|
| `Login` | `/login` | Connexion / inscription |
| `Analyse` | `/analyse` | Interface d'analyse de prompts (cœur de l'app) |
| `Health` | `/health` | Statistiques et historique utilisateur |
| `ThemeToggle` | global | Bascule thème clair/sombre (localStorage) |
| `Navigation` | layout | Barre latérale + routes |

### Flux d'analyse (page `/analyse`)

1. Vérifie la connexion (`sessionStorage`)
2. L'utilisateur paramètre un **seuil** (0–1) et saisit un **prompt**
3. Ajout à une file d'attente (plusieurs prompts possibles)
4. Envoi groupé à `/api/analyse`
5. Gestion automatique du **token expiré** (refresh + retry)
6. Affichage des résultats (label, probabilité, seuil)

> Le frontend est **déjà buildé** dans `FRONT_END_REACT/build/` et servi directement par FastAPI — pas besoin de Node.js pour lancer l'app telle quelle, seulement si tu veux modifier le frontend depuis les sources.

---

## 🗃️ Base de données

- **SQLite** avec SQLModel (ORM)
- Table `User` :
  - `id`, `username`, `password` (hashé bcrypt)
  - `salt` (généré serveur, utilisé uniquement pour dériver la clé Fernet)
  - `history` (chiffré avec Fernet) : `{ "prompt": "label" }`
  - `created_at`

Le chiffrement de l'historique utilise `password + salt`. L'API ne stocke jamais les prompts en clair.

---

## 📋 Prérequis

- **Python 3.11**
- Node.js 18+ (uniquement si tu veux rebuild le frontend React depuis les sources)
- SQLite3

---

## ⚙️ Installation

```bash
# Cloner le projet
git clone https://github.com/hounsoubenny-cyber/contextguard.git
cd contextguard

# Environnement virtuel
python3.11 -m venv venv
source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements.txt
```

Crée un fichier `.env` à la racine :

```bash
CONTEXTGUARDURL=sqlite:///./contextguarddatabase.db
CONTEXTGUARD_JWT_SECRET=<génère-le avec la commande ci-dessus>
```

### ⚠️ Modèle non inclus dans le dépôt

Les poids du modèle (`model/models/contextguard2.pt` / `.onnx`) sont exclus du repo (fichiers trop volumineux, voir `.gitignore`). Pour lancer l'API il faut soit :
- Entraîner ton propre modèle : `cd model && python train.py`
- Récupérer les poids pré-entraînés :

  📥 **[Télécharger le modèle pré-entraîné](https://github.com/hounsoubenny-cyber/contextguard/releases/latest)**

Place ensuite les fichiers téléchargés ici :

```
model/models/contextguard2.pt          # requis (inférence PyTorch)
model/models/contextguard2.onnx        # optionnel, si USE_ONNX=True dans config.py
model/models/contextguard2.onnx.data   # optionnel, accompagne le .onnx
```

Le dossier `model/models/tokenizer/` (avec `tokenizer_config.json` et `tokenizer.json`) est lui déjà inclus dans le dépôt, rien à télécharger pour ça.

---

## ▶️ Lancer l'application

```bash
python run_api.py
```

Le dashboard React (déjà buildé) et l'API sont servis ensemble — une seule commande donne accès à tout :
- Dashboard : `http://localhost:8000`
- Documentation API interactive : `http://localhost:8000/api/docs`

---

## 🧪 Tests

### Tests unitaires du SDK (transport mocké, aucun serveur requis)

```bash
pytest sdk/test_client.py -v
```

Couvre : interface `SDKResponse`, construction des URLs, logique de `connect` (login-first, fallback, race condition), récupération intelligente d'`analyse`, cycle de vie du client.

### Tests d'intégration du SDK (serveur réel)

```bash
# Terminal 1
python run_api.py

# Terminal 2
pytest sdk/test_client_live.py -v -s

# Ou sur une instance distante
CONTEXTGUARD_API_URL="https://api.example.com" pytest sdk/test_client_live.py -v -s
```

Couvre : connexion (création, login, mauvais mot de passe), analyse batch, health, refresh token, logout, delete account, is_connected, auto-recover, multi-client, isolation des sessions.

### Tests unitaires de l'API

```bash
pytest test/test.py
```

---

## 📁 Structure des fichiers clés

```
contextguard/
├── __init__.py
├── README.md
├── requirements.txt
│
├── api/                          # Couche HTTP
│   ├── __init__.py
│   ├── main_api.py               # Entrypoint FastAPI (ex main.py)
│   ├── run_api.py                # Lancement avec gestion signaux
│   ├── config.py                 # Configuration (chemins, seuils, JWT_SECRET, IP, port)
│   ├── router.py                 # Routes HTTP
│   ├── models.py                 # Modèles Pydantic d'entrée/sortie
│   ├── state.py                  # SessionCache (dict + RLock), singletons, vérifications
│   └── utils.py                  # Constantes partagées (markers d'erreur)
│
├── contextguard_utils/           # Utilitaires transverses
│   ├── __init__.py
│   ├── jwt_utils.py              # JWT (création, vérification)
│   └── utils.py                  # FernetManager, hashpw, checkpw, verify_salt
│
├── database/                     # Persistance
│   ├── __init__.py
│   ├── db_manager.py             # SQLModel + DBManager + User (avec salt)
│   ├── dataset_base.py           # Datasets de base (SAFE / INJECTION / ...)
│   ├── augment.py                # Pipeline d'augmentation offline
│   ├── contextguard_database.db  # SQLite (runtime)
│   └── contextguard_database_.db # ⚠️ doublon à nettoyer
│
├── model/                        # Modèle de classification
│   ├── __init__.py
│   ├── model_guard.py            # Transformer + wrappers
│   ├── train.py                  # Entraînement
│   ├── trainer.py                # Boucle d'entraînement avec métriques
│   ├── callbacks.py              # EarlyStopping
│   ├── static_analyzer.py        # Analyse regex rapide
│   ├── onnx_utils.py             # Export / inférence ONNX
│   ├── models/
│   │   ├── contextguard.pt       # Poids PyTorch (à télécharger)
│   │   ├── contextguard.onnx     # Modèle ONNX (optionnel)
│   │   ├── contextguard.onnx.data
│   │   └── tokenizer/            # Tokenizer BERT (inclus dans le repo)
│   └── static_rule/
│       └── static_patterns.json
│
├── datasets/                     # Préparation du dataset
│   ├── __init__.py
│   ├── display_df.py             # Inspection des fichiers parquet/jsonl
│   └── prepare_data.py           # Génération du dataset final
│
├── sdk/                          # SDK Python
│   ├── __init__.py               # Exports publics
│   ├── client.py                 # ContextGuardClient
│   ├── models.py                 # Modèles Pydantic (Params + Responses)
│   ├── test_client.py            # Tests unitaires (transport mocké)
│   └── test_client_live.py       # Tests d'intégration (serveur réel)
│
├── FRONT_END_REACT/
│   └── build/                    # Frontend React prébuildé
│
└── test/
    ├── __init__.py
    └── test.py                   # Tests API (FastAPI TestClient)
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Merci d'ouvrir une *issue* ou une *pull request* pour toute suggestion ou correction.

---

**Auteur** : HOUNSOU Samuel Benny
**Version** : 2.0.0
```
