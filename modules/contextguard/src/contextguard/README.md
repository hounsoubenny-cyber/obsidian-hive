# 🛡️ ContextGuard – Protection des prompts IA

![Python Version](https://img.shields.io/badge/python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green)
![React](https://img.shields.io/badge/React-18+-61DAFB)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C)
![SQLite](https://img.shields.io/badge/SQLite-3+-003B57)
[![GitHub repo](https://img.shields.io/badge/GitHub-ContextGuard-181717?logo=github)](https://github.com/hounsoubenny-cyber/contextguard)

**ContextGuard** est une plateforme complète de détection et de protection en temps réel contre les injections de prompts, les jailbreaks et les tentatives d'exfiltration de données dans les interactions avec les modèles de langage (LLM).

Le projet comprend :
- Une **API REST** (FastAPI) avec gestion JWT, chiffrement Fernet, base de données SQLite
- Un **modèle de deep learning** (Transformer entraîné from scratch) pour la classification des prompts, combiné à un moteur de règles statiques pour un filtrage instantané des patterns connus
- Un **SDK Python** asynchrone (+ version synchrone) pour interagir avec l'API, avec rafraîchissement automatique du token
- Un **frontend React** moderne (thème clair/sombre, statistiques, analyse interactive), servi directement par le backend

🔗 **Dépôt** : [github.com/hounsoubenny-cyber/contextguard](https://github.com/hounsoubenny-cyber/contextguard)

---

## 📦 Architecture globale

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React SPA)                         │
│  Login / Analyse / Health / GetSalt / Navigation / ThemeToggle       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTP (Fetch API)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         API (FastAPI)                                │
│  • Authentification JWT                                             │
│  • Chiffrement Fernet (historique utilisateur)                      │
│  • Rate limiting (SlowAPI)                                          │
│  • Routes : /login, /analyse, /health, /salt, /refresh_token        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│  Base SQLite      │ │ Modèle Transformer│ │  Analyse statique   │
│  (utilisateurs,   │ │ (PyTorch / ONNX)  │ │ (patterns regex)    │
│   historique)     │ │                   │ │                     │
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

## 🔐 API – Endpoints principaux

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/salt` | GET | Génère un nouveau sel de chiffrement |
| `/api/login` | POST | Création de compte ou connexion (retourne token JWT + salt) |
| `/api/analyse` | POST | Analyse d'un ou plusieurs prompts avec seuils personnalisés (batch async) |
| `/api/health` | POST | Récupère l'historique et les statistiques de l'utilisateur |
| `/api/refresh_token` | POST | Rafraîchit un token JWT expiré |
| `/api/docs` | GET | Documentation Swagger interactive |

**Authentification** : Bearer token JWT (expiration configurable, rafraîchissement auto). Mots de passe hashés en `bcrypt`, historique utilisateur chiffré au repos avec `Fernet` (clé dérivée du mot de passe + salt).

---

## 🧪 SDK Python

Le SDK (`sdk/contextguard_py_sdk.py`) fournit une interface asynchrone (+ synchrone) simple :

```python
from contextguard.sdk.contextguard_py_sdk import ContextGuardSDK
import aiohttp

sdk = ContextGuardSDK()

async with aiohttp.ClientSession() as session:
    # Connexion
    result = await sdk.connect_async("user", "pass", salt, connect=True, session=session)
    token = result["result"]["token"]

    # Analyse
    result = await sdk.secure_prompt_async(
        username="user", password="pass", salt=salt, token=token,
        prompts=["Hello world"], threasholds=[0.5], session=session
    )
```

Fonctionnalités du SDK :
- Connexion / création de compte
- Analyse de prompts (auto‑refresh du token si expiré)
- Récupération d'un salt
- Vérification d'état de santé (`/health`)

### 🚀 Exemple d'intégration en prod

Dans ton application cliente (celle qui utilise ContextGuard), écris un petit wrapper **une seule fois** — connexion au démarrage, puis un simple `check(prompt)` partout ailleurs :

```python
# guard.py — dans ton app cliente
import os
import aiohttp
from contextguard.sdk.contextguard_py_sdk import ContextGuardSDK

class Guard:
    """Login une fois au démarrage, puis check(prompt) partout."""

    def __init__(self):
        self.sdk = ContextGuardSDK()
        self.username = os.environ["CONTEXTGUARD_USER"]
        self.password = os.environ["CONTEXTGUARD_PASSWORD"]
        self.salt = os.environ["CONTEXTGUARD_SALT"]
        self.token = None
        self.session = None

    async def start(self):
        self.session = aiohttp.ClientSession()
        result = await self.sdk.connect_async(
            self.username, self.password, self.salt,
            connect=True, session=self.session
        )
        self.token = result["result"]["token"]

    async def check(self, prompt: str, threshold: float = 0.5) -> bool:
        """True si le prompt est SAFE, False s'il faut le bloquer."""
        result = await self.sdk.secure_prompt_async(
            username=self.username, password=self.password,
            salt=self.salt, token=self.token,
            prompts=[prompt], threasholds=[threshold],
            session=self.session,
        )
        data = result["result"]["result"][prompt]
        return data["label"] == "safe"

    async def close(self):
        await self.session.close()

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
| `GetSalt` | `/getsalt` | Génération d'un nouveau salt |
| `Analyse` | `/analyse` | Interface d'analyse de prompts (cœur de l'app) |
| `Health` | `/health` | Statistiques et historique utilisateur |
| `ThemeToggle` | global | Bascule thème clair/sombre (localStorage) |
| `Naviguation` | layout | Barre latérale + routes |

### Flux d'analyse (page `/analyse`)

1. Vérifie la connexion (`sessionStorage`)
2. L'utilisateur paramètre un **seuil** (0–1) et saisit un **prompt**
3. Ajout à une file d'attente (plusieurs prompts possibles)
4. Envoi groupé à `/api/analyse`
5. Gestion automatique du **token expiré** (refresh + retry)
6. Affichage des résultats (label, probabilité, seuil)

### Stockage côté client

```javascript
sessionStorage.setItem("token", token);
sessionStorage.setItem("username", username);
sessionStorage.setItem("salt", salt);
```

Le salt est essentiel pour le déchiffrement de l'historique et ne doit jamais être perdu.

> Le frontend est **déjà buildé** dans `FRONT_END_REACT/build/` et servi directement par FastAPI — pas besoin de Node.js pour lancer l'app telle quelle, seulement si tu veux modifier le frontend depuis les sources.

---

## 🗃️ Base de données

- **SQLite** avec SQLModel (ORM)
- Table `User` :
  - `id`, `username`, `password` (hashé bcrypt)
  - `history` (chiffré avec Fernet) : `{ "prompt": "label" }`
  - `created_at`

Le chiffrement de l'historique utilise le salt + mot de passe utilisateur (Fernet).
L'API ne stocke jamais les prompts en clair.

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
```
CONTEXTGUARDURL=sqlite:///./contextguarddatabase.db
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

## ▶️ Lancer l'application

```bash
python run_api.py
```

Le dashboard React (déjà buildé) et l'API sont servis ensemble — une seule commande donne accès à tout :
- Dashboard : `http://localhost:8000`
- Documentation API interactive : `http://localhost:8000/api/docs`

---

## 🧪 Tests

```bash
# Tests unitaires de l'API (avec pytest)
pytest test/test.py

# Tests du SDK
python sdk/test_sdk.py
python sdk/test_sdk1.py
```

---

## 📁 Structure des fichiers clés

```
contextguard/
├── main.py                # Entrypoint FastAPI
├── run_api.py             # Lancement avec gestion signaux
├── config.py              # Configuration (chemins, seuils, IP, port)
├── core/
│   ├── database.py        # SQLModel + DBManager
│   ├── fernet_manager.py  # Chiffrement Fernet
│   ├── jwt_utils.py       # JWT (création, vérification)
│   ├── limiter.py         # Rate limiting (SlowAPI)
│   ├── router.py          # Routes API
│   └── utils.py
├── model/
│   ├── model_guard.py     # Modèle Transformer + wrappers
│   ├── train.py           # Entraînement
│   ├── trainer.py         # Boucle d'entraînement avec métriques
│   ├── static_analyzer.py # Analyse regex rapide
│   ├── onnx_utils.py      # Export/inférence ONNX
│   └── static_rule/static_patterns.json
├── datasets/               # Préparation & augmentation du dataset
├── sdk/                    # SDK Python asynchrone
├── FRONT_END_REACT/build/  # Frontend React (build)
└── test/                   # Tests unitaires
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Merci d'ouvrir une *issue* ou une *pull request* pour toute suggestion ou correction.

---

**Auteur** : HOUNSOU Samuel Benny
**Version** : 1.0.0
