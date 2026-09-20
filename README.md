<div align="center">

```
 ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗
██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║
██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║
██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║
╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                     H I V E
```

# Obsidian Hive — Autonomous AI-Powered Cybersecurity Platform

**La nervure de cybersécurité pour l'ère de l'IA.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=flat-square&logo=pytorch)](https://pytorch.org)
[![Local LLM](https://img.shields.io/badge/LLM-llama.cpp%20%2B%20API-663399?style=flat-square)]()
[![Suricata](https://img.shields.io/badge/IDS-Suricata-F47C20?style=flat-square)](https://suricata.io)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-MVP%20~%2095%25-orange?style=flat-square)]()

> *"Tu ne gères pas Obsidian Hive. Tu lui délègues ton infrastructure."*

</div>

---

## Ce qu'est Obsidian Hive

Obsidian Hive est une plateforme de cybersécurité autonome pilotée par IA. Ce n'est pas un scanner de plus, pas un firewall, pas un dashboard SIEM — c'est une **ruche** : un ensemble de modules de sécurité, chacun assez complet et autonome pour être considéré comme un projet à part entière, unifiés par deux agents centraux qui orchestrent, corrèlent et décident.

Chaque module — scanner web, anti-phishing, IDS/IPS, sandbox comportementale, simulateur d'attaque — a sa propre intelligence embarquée (son propre agent, son propre pipeline ML/DL, parfois sa propre API). La Hive les relie, les fait parler entre eux, et garde un humain dans la boucle pour toute décision qui compte.

**Tu délègues. La Hive protège.**

---

## Philosophie

| Principe | Ce que ça implique |
|---|---|
| **Fail-closed par défaut** | En cas de doute, le système bloque plutôt que de laisser passer |
| **Aucune confiance aveugle dans les LLM** | Chaque affirmation d'un agent est vérifiée mécaniquement, jamais prise pour argent comptant |
| **Humain dans la boucle** | Toute action destructrice (patch, isolation, simulation réelle) passe par confirmation explicite (`human_in_loop.py`) |
| **LLM local pour les modules sensibles** | Inférence 100% locale via `llama.cpp` sur les modules critiques, API externe seulement quand c'est acceptable |
| **Simplicité assumée** | Un seul worker, état en mémoire + SQLite/SQLModel async — pas de cluster, pas d'infra qu'on n'a pas besoin de gérer |
| **Chaque module tient debout seul** | Aucun module ne dépend de l'orchestrateur central pour fonctionner |

---

## Coralie & Alex — le cœur décisionnel

Deux agents, deux rôles stricts, aucun flou entre les deux :

| Agent | Rôle |
|---|---|
| **Coralie** | Décisionnaire. Orchestre les modules, corrèle les événements, répond en conversation libre — appeler zéro outil et répondre directement est un cas normal, pas un échec |
| **Alex** | Analyste. Interprète les données techniques brutes, lit/corrige du code, cherche des patterns, propose des correctifs — doit toujours conclure par un rapport structuré |

Les deux reçoivent leur `LLMManager` par injection de dépendance : un seul pool de clés/modèles est partagé entre agents concurrents, et chacun se teste avec un LLM mocké, sans base de données ni serveur réel à démarrer.

---

## La Hive — les modules

Chaque module ci-dessous a sa propre intelligence embarquée. Certains (ContextGuard en tête) sont des projets complets en eux-mêmes, avec leur propre API et parfois leur propre frontend.

### `anti_phishing_ia` — ✅ 100%
Classification d'URLs (36 features, ~2M URLs d'entraînement) et analyse d'emails, avec un encodeur de mail deep learning en plus du modèle ML classique. Livré avec sa propre extension navigateur (Chrome + Firefox) qui interroge l'API en direct pour bloquer un lien avant le clic.

### `scanner_ia` — 🟡 ~95%
Scanner web offensif : crawler async, fuzzer actif qui compare similarité BERT et TF-IDF pour affiner ses payloads, analyseur de code, classification ML multi-label (One-vs-Rest + MLSMOTE pour gérer le déséquilibre des classes de vulnérabilités).

### `simulateur_attaque_ia` — 🟡 ~95%
L'agent offensif de la Hive. Piloté par un graphe d'état LangGraph qui déroule une vraie kill-chain MITRE ATT&CK — reconnaissance, accès initial, exécution, élévation de privilèges, persistance, exfiltration — avec des branches conditionnelles selon ce qui a été trouvé à chaque étape. Il ne se contente pas de rejouer un script : il décide de la suite en fonction du terrain.

### `sandbox_ia` — 🟡 ~95%
Environnement d'exécution isolé multi-langage, avec tracer de syscalls, monitoring du système de fichiers et autoencodeurs pour repérer les comportements anormaux. Fait tourner en sécurité tout ce que le scanner ou le simulateur doivent exécuter sans risque.

### `ids_ips_ia` — 🟡 ~95%
Détection d'intrusion réseau (LSTM/CNN sur flux Suricata EVE JSON), avec système de ré-entraînement continu et module de réaction automatique.

### `contextguard` — ✅ projet intégré
Classifieur anti prompt-injection / jailbreak / exfiltration qui protège toutes les interfaces LLM de la Hive. C'est un sous-projet complet : Transformer maison entraîné from scratch (export ONNX), API JWT, SDK Python async, frontend React livré avec son propre dashboard.

### `deepfake_detector` (TrustSignal) — 🟡 en développement
Détection de contenu généré par IA — texte (perplexité, burstiness, diversité lexicale) et image — via un encodeur contrastif suivi d'une tête de classification.

### `modules_utils`
Utilitaires partagés par tous les modules ci-dessus.

### `cyber_learn`
Amorce d'un module pentest pédagogique — tout début.

---

## Colonne vertébrale

```
                    ┌───────────────────────────────┐
                    │        API (FastAPI)          │
                    │   api/main_api.py + routers   │
                    └───────────────┬───────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  Coralie & Alex  │◄────►│  ObsidianEngine      │◄────►│  ServerAsset agent   │
│                  │      │  (core/engine.py)    │      │  système distant     │
└─────────────────┘      └──────────┬───────────┘      └─────────────────────┘
                                    │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
     ConversationManager      JobManager (APScheduler   AssetManager /
     (SQLite/SQLModel async)  double jobstore)           ReportManager /
                                                          TaskManager /
                                                          WorkflowManager
```

Le `LLMManager` unifie les appels vers un LLM local (`llama.cpp`) et vers des API compatibles OpenAI/Anthropic, avec un `StreamEventBus` pour le streaming des réponses.

Le **système ServerAsset** est l'agent distant de la Hive sur les machines qu'elle surveille : catalogue d'outils fermé et fail-closed (`allowed_tools`), binaire `tool_engine` compilé via Nuitka, mTLS prévu, dashboard local scopé à un seul asset. Il se gère en entier depuis l'API : enregistrement, révocation, rotation de secret, réactivation, ajout/retrait de capacités et d'outils autorisés.

---

## API

| Router | Ce qu'il expose |
|---|---|
| `core_router` | CRUD complet des assets (web/network/server), cycle de vie ServerAsset, `POST /agent/alex/analyze` |
| `login_router` | Auth, `/health`, refresh de token |
| `manager_router` | Liste/état/catalogue des jobs planifiés |
| `extension_token_manager_router` | Tokens pour l'extension navigateur |
| `anti_phishing_extension_router` | `/check_url`, `/check_urls_batch` — utilisé en direct par l'extension |
| `scanner_report_manager_router` | Rapports du scanner web |
| `utils_router` | `path_exists`, `check_port` |
| `core_ws_router` | WebSocket temps réel |

---

## Stack technique

```
Backend        FastAPI, asyncio, aiohttp
Persistance    SQLite + SQLModel async
Scheduling     APScheduler (double jobstore : mémoire + persistant)
IA / ML        PyTorch, TensorFlow, scikit-learn (MLSMOTE, OVR)
LLM            llama.cpp (local) + API compatibles OpenAI/Anthropic
Orchestration  LangGraph (simulateur), CrewAI (agents par module)
Sandbox        Docker (exécution multi-langage isolée)
IDS            Suricata (EVE JSON) + LSTM/CNN
Extension nav. Manifest V3 — Chrome + Firefox
Matériel dev   CPU-only, i7-1355U, 15 Go RAM
```

---

## Structure du dépôt

```
obsidian_hive/
├── agents/
│   ├── core/            # Coralie
│   ├── analyst/         # Alex
│   └── shared/          # human_in_loop.py, KeyedLock
├── core/
│   ├── engine.py         # ObsidianEngine
│   ├── managers/         # Conversation, Job, Asset, Report, Task, Workflow, LLM
│   └── assets/           # Types d'assets + ServerAsset
├── api/
│   ├── main_api.py
│   └── routers/
├── modules/
│   ├── anti_phishing_ia/
│   ├── scanner_ia/
│   ├── sandbox_ia/
│   ├── simulateur_attaque_ia/
│   ├── ids_ips_ia/
│   ├── contextguard/
│   ├── deepfake_detector/
│   ├── modules_utils/
│   └── cyber_learn/
├── ecosystem/
│   └── extension_anti_phishing/   # Chrome + Firefox
├── obsidian_code_fix/      # Bac à sable pour les corrections d'Alex
├── config/
└── docs/
```

La vision long terme, le marché visé et les modules pas encore construits sont dans [`VISION.md`](./VISION.md).

---

## Auteur

**Samuel « Benny » Hounsou** (`hounsoubenny-cyber`)
Développeur autodidacte — Cotonou, Bénin

- GitHub : [github.com/hounsoubenny-cyber](https://github.com/hounsoubenny-cyber)
- LinkedIn : [linkedin.com/in/benny-hounsou-00a267374](https://linkedin.com/in/benny-hounsou-00a267374)

---

<div align="center">

*Construit avec conviction. Construit depuis l'Afrique.*

**Obsidian Hive — on ne se contente pas de détecter les menaces. On les élimine.**

</div>
