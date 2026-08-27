<div align="center">

```
███████╗██╗  ██╗██╗███████╗██╗     ██████╗      █████╗ ██╗
██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗    ██╔══██╗██║
███████╗███████║██║█████╗  ██║     ██║  ██║    ███████║██║
╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║    ██╔══██║██║
███████║██║  ██║██║███████╗███████╗██████╔╝    ██║  ██║██║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝
```

# ShieldAI — Plateforme de Cybersécurité IA Autonome

**Le système nerveux cybernétique de l'ère IA.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=flat-square&logo=pytorch)](https://pytorch.org)
[![Suricata](https://img.shields.io/badge/IDS-Suricata-F47C20?style=flat-square)](https://suricata.io)
[![Licence](https://img.shields.io/badge/Licence-MIT-green?style=flat-square)](LICENSE)
[![Statut](https://img.shields.io/badge/Statut-MVP%20En%20Cours-orange?style=flat-square)]()

> *"Vous ne gérez pas ShieldAI. Vous lui déléguez votre infrastructure."*

</div>

---

## Qu'est-ce que ShieldAI ?

ShieldAI n'est pas un scanner. Ce n'est pas un pare-feu. Ce n'est pas encore un autre tableau de bord SIEM.

**ShieldAI est un système d'exploitation cybernétique autonome** — une plateforme qui prend en charge totale votre infrastructure numérique, la surveille en continu, détecte les menaces, simule des attaques, isole les comportements suspects, et rend compte de tout à l'administrateur en temps réel.

Il peut être piloté manuellement par un analyste humain, ou fonctionner en mode entièrement autonome, dirigé par un orchestrateur IA qui coordonne des agents spécialisés — chacun expert dans son domaine.

Vous déléguez. ShieldAI protège.

---

## Philosophie Fondamentale

| Principe | Description |
|---|---|
| **Autonome par défaut** | ShieldAI tourne 24h/24, 7j/7 sans attendre l'intervention humaine |
| **Humain dans la boucle** | Chaque action critique nécessite l'autorisation de l'administrateur |
| **Architecture modulaire** | Chaque module fonctionne seul OU comme outil d'un agent IA |
| **Natif IA** | Chaque détection, décision et rapport est propulsé par l'IA |
| **Afrique d'abord** | Conçu pour les infrastructures et organisations ignorées par les géants occidentaux |

---

## Vue d'Ensemble de l'Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SHIELDAI CYBER-OS                                │
│           Orchestrateur IA — Le Cerveau Central                     │
│                  (Llama 3.1 8B via Groq)                           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Agent Scanner   │   │   Agent IDS/IPS  │   │ Agent Simulateur │
│ "L'Explorateur"  │   │  "Le Gardien"    │   │  "L'Attaquant"   │
│  DeepSeek-Coder  │   │  Phi-3 Mini      │   │  CodeLlama 7B    │
└──────────────────┘   └──────────────────┘   └──────────────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ Agent Anti-Phish │   │  Agent Sandbox   │   │ Agent Rapporteur │
│  "Le Détecteur"  │   │  "Le Biologiste" │   │  "Le Greffier"   │
│  Mistral 7B      │   │  CodeLlama 7B    │   │  Mistral 7B      │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

### Double Mode de Fonctionnement

```
┌────────────────────────────────────────────────┐
│                                                │
│   MODE AUTONOME            MODE MANUEL         │
│   ─────────────            ───────────         │
│   L'Orchestrateur IA       L'Analyste humain   │
│   coordonne les agents     utilise les modules │
│   de façon indépendante    directement via UI  │
│                                                │
│   Les deux modes partagent la même couche      │
│   de modules                                   │
│                                                │
└────────────────────────────────────────────────┘
```

---

## Feuille de Route des Modules

### 🔥 Phase 1 — MVP (Sécurité Fondamentale)

| # | Module | Description | Statut |
|---|---|---|---|
| 1 | **Scanner de Vulnérabilités** | Scanner web IA — détecte SQLi, XSS, SSRF, OWASP Top 10 | 🔄 En cours |
| 2 | **Anti-Phishing IA** | Dataset 2M+ URLs, 36 features, API PhishDestroy, TTLCache — 99.3% de précision | ✅ Quasi-complet |
| 3 | **IDS/IPS IA** | Détection d'intrusion LSTM sur Suricata EVE JSON — surveillance réseau temps réel | 🔄 Migration |
| 4 | **Simulateur d'Attaques** | Moteur offensif IA adaptatif — teste votre propre infrastructure en sécurité | 🔄 En cours |
| 5 | **Sandbox IA** | Environnement d'exécution isolé — analyse fichiers, scripts et comportements suspects | 🔄 En cours |

### ⚡ Phase 2 — Avancé (Différenciation)

| # | Module | Description |
|---|---|---|
| 6 | **Orchestrateur IA Principal** | Cerveau central — coordonne tous les agents, multi-modules, multi-utilisateurs |
| 7 | **Chatbot Cybersécurité** | Assistant NLP pour analystes — protégé par ContextGuard contre les injections de prompt |
| 8 | **Gestionnaire de Logs SIEM-like** | Analyse intelligente des logs, audit trail, stockage horodaté sécurisé |
| 9 | **Moteur d'Apprentissage Continu** | Système auto-adaptatif — apprend des retours et des nouveaux patterns d'attaque |
| 10 | **Protection Anti-Ransomware** | IA comportementale — détecte les patterns de chiffrement avant les dégâts |
| 11 | **Détection de Phishing Temps Réel** | Interception et analyse en direct des emails et URLs |
| 12 | **Sandbox Améliorée** | Exécution isolée avancée avec analyse comportementale complète |
| 13 | **Interface de Règles de Sécurité** | Seuils personnalisés, politiques d'actions automatiques, panneau de contrôle admin |
| 14 | **Intégration Outils Tiers** | Connecteurs SIEM, Jira, ServiceNow, Slack |

### 🚀 Phase 3 — Ultra-Innovant (vs. les Géants Mondiaux)

| # | Module | Description |
|---|---|---|
| 15 | **Anticipation des Cyber-Menaces** | IA prédictive — anticipe les vecteurs d'attaque avant qu'ils surviennent |
| 16 | **Cyber Déception / Honeypots** | Honeypots IA dynamiques — attirent et étudient les attaquants en temps réel |
| 17 | **Intelligence Dark Web** | Surveille le dark web pour les credentials et données d'infrastructure fuités |
| 18 | **Couche Sécurité Blockchain** | Logs d'audit immuables et infalsifiables |
| 19 | **Privacy Guardian** | Anonymisation intelligente des données et conformité RGPD |
| 20 | **Moteur Zero-Trust Adaptatif** | Vérification dynamique de confiance par requête/utilisateur |
| 21 | **Swarm AI Defense** | Partage inter-IA des menaces — défense collaborative en temps réel |
| 22 | **Réponse Automatique aux Incidents** | Playbooks IA — isolation auto, patch auto, escalade auto |
| 23 | **Intelligence Vuln Cross-Platform** | Corrélation des vulnérabilités web + mobile + cloud |
| 24 | **Auto-patching Intelligent** | Propose ou applique des correctifs automatiquement (autorisation admin requise) |
| 25 | **Threat Feed et Dashboard Temps Réel** | Alertes en direct, scoring des menaces, priorisation |
| 26 | **Simulateur d'Attaques Sociales** | Campagnes de phishing et simulations d'ingénierie sociale |
| 27 | **Visualisation de la Surface d'Attaque** | Cartographie dynamique et interactive de l'infrastructure |
| 28 | **UEBA** | Analyse comportementale utilisateurs/entités — détecte les menaces internes |

### 🟣 Phase 4 — Red/Blue/Purple Team IA

| # | Module | Description |
|---|---|---|
| 29 | **Red Team IA** | Génère des attaques réalistes avec comportements humains (pauses, adaptation) |
| 30 | **Blue Team IA** | Défend, détecte et bloque les attaques Red Team de façon autonome |
| 31 | **Purple Team IA** | Fusion Red+Blue — analyse les interactions, optimise les défenses, ajuste les playbooks |

---

## Flux Autonomes

### Asset Ajouté par l'Admin

```
Admin ajoute un asset (site web, serveur, PC, réseau)
              ↓
    Orchestrateur notifié
              ↓
    ┌──────────────────────────┐
    │  Scanner lancé           │ → vulnérabilités détectées
    │  Simulateur lancé        │ → défenses testées
    │  IDS/IPS activé          │ → trafic surveillé
    └──────────────────────────┘
              ↓
    Résultats corrélés par l'Orchestrateur
              ↓
    Admin notifié → autorise le patch ?
              ↓
    Patch appliqué automatiquement OU action manuelle
              ↓
    Rapport complet généré
```

### Attaque Détectée en Temps Réel

```
IDS/IPS déclenche une alerte
       ↓
UEBA corrèle → menace interne ou externe ?
       ↓
Dark Web Intel → acteur de menace connu ?
       ↓
Cyber Déception → déploiement honeypot pour piéger l'attaquant
       ↓
Orchestrateur décide → bloquer IP / isoler / surveiller
       ↓
Sandbox → exécution sécurisée du payload suspect
       ↓
Rapporteur → rapport d'incident immédiat à l'Admin
```

### Email / Lien Suspect Intercepté

```
Email / lien reçu
       ↓
Anti-Phishing IA → score de phishing calculé
       ↓
TrustSignal → contenu généré par IA détecté ?
       ↓
ContextGuard → injection de prompt cachée dans le contenu ?
       ↓
Blocage + alerte Admin  OU  Autorisation + journalisation
```

---

## Couche de Défense IA (ContextGuard + TrustSignal)

ShieldAI intègre deux modules uniques qu'aucun concurrent ne combine actuellement :

### ContextGuard
Classificateur multilingue d'injection de prompt — protège le chatbot admin et toutes les interfaces LLM de ShieldAI.

- Architecture : Transformer Encoder personnalisé (3 couches, 4 têtes d'attention)
- Classes : `safe` | `injection` | `jailbreak` | `exfiltration`
- Export : TorchScript → ONNX pour inférence rapide sur CPU

### TrustSignal
Détecteur de contenu généré par IA — identifie les textes synthétiques, deepfakes et images forgées utilisées dans les attaques d'ingénierie sociale.

- Détecte les faux documents d'identité
- Signale les images générées par IA tentant de contourner la reconnaissance faciale
- Score les emails et rapports pour probabilité de contenu synthétique

```
Attaquant envoie une fausse pièce d'identité générée par IA
              → tentative de contournement de la reconnaissance faciale
                          ↓
        TrustSignal intercepte → contenu synthétique détecté
                          ↓
                        BLOQUÉ
```

---

## Stack Technique

### Backend
```
FastAPI          — API modulaire avec architecture include_router
PyTorch 2.0+     — Tous les modèles IA/ML personnalisés
Suricata         — IDS/IPS réseau (format EVE JSON)
ONNX Runtime     — Inférence rapide CPU pour modèles exportés
Redis            — Cache (TTLCache pour Anti-Phishing)
Docker           — Déploiement conteneurisé
Caddy            — Reverse proxy HTTPS
```

### Modèles IA (Construits from scratch)
```
IDS LSTM              — Détection d'intrusion sur NSL-KDD / logs Suricata
Anti-Phishing MLP     — Classificateur URL 36 features (2M+ URLs d'entraînement)
Malware CNN           — Classification malware bytes-to-image
DeepLog LSTM          — Détection d'anomalies dans les logs système
ContextGuard Encoder  — Classificateur injection de prompt (Transformer)
TrustSignal           — Détecteur de contenu généré par IA
```

### Agents LLM (via API Groq)
```
Llama 3.1 8B     — Orchestrateur Principal
DeepSeek-Coder   — Agent Scanner
Phi-3 Mini       — Agent IDS/IPS
CodeLlama 7B     — Agents Simulateur + Sandbox
Mistral 7B       — Agents Anti-Phishing + Rapporteur
```

---

## Structure du Projet

```
shieldai/
├── core/
│   ├── orchestrator/        # Orchestrateur IA — coordination des agents
│   ├── agents/              # Agents IA spécialisés
│   └── memory/              # Contexte partagé et état global
├── modules/
│   ├── scanner/             # Scanner de Vulnérabilités
│   ├── anti_phishing/       # Anti-Phishing IA
│   ├── ids_ips/             # IDS/IPS (Suricata + LSTM)
│   ├── simulator/           # Simulateur d'Attaques
│   ├── sandbox/             # Sandbox IA
│   ├── context_guard/       # Classificateur Injection de Prompt
│   ├── trust_signal/        # Détecteur de Contenu IA
│   └── reporter/            # Générateur de Rapports
├── api/
│   ├── main.py              # Point d'entrée FastAPI
│   └── routers/             # Routeurs API par module
├── models/
│   ├── trained/             # Fichiers modèles .pt et .onnx sauvegardés
│   └── trainers/            # Pipelines d'entraînement personnalisés
├── dashboard/               # Interface Admin (React)
├── docker/                  # Configs Docker Compose
└── docs/                    # Documentation
```

---

## Statut Actuel

```

## Vision

> CrowdStrike sert les entreprises du Fortune 500 à 50 000$/an.
> Darktrace cible les grandes entreprises européennes.
> SentinelOne se concentre sur le marché américain.
>
> **L'Afrique est sans protection. ShieldAI change ça.**

ShieldAI est construit pour le marché africain en premier — conçu pour fonctionner sur des infrastructures modestes, tarifé pour les organisations locales, et bâti par quelqu'un qui comprend l'écosystème de l'intérieur.

La vision long terme :

```
Phase 1 → Dominer les PMEs et startups d'Afrique de l'Ouest
Phase 2 → Banques, télécoms, gouvernements d'Afrique francophone
Phase 3 → Multinationales opérant en Afrique
Phase 4 → Expansion internationale avec track record africain prouvé
```

ShieldAI n'est pas juste un autre outil de cybersécurité.
**C'est le standard de cybersécurité de l'ère IA en Afrique.**

---

## Auteur

**Sam Hounsou** (`hounsoubenny-cyber`)
L1 Systèmes d'Information — IFRI, Cotonou, Bénin

- GitHub : [github.com/hounsoubenny-cyber](https://github.com/hounsoubenny-cyber)
- LinkedIn : [linkedin.com/in/benny-hounsou-00a267374](https://linkedin.com/in/benny-hounsou-00a267374)

---

<div align="center">

*Construit avec conviction. Construit pour l'Afrique. Construit pour l'ère IA.*

**ShieldAI — Nous ne détectons pas seulement les menaces. Nous les éliminons.**

</div>
