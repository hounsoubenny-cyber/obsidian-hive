<div align="center">

```
███████╗██╗  ██╗██╗███████╗██╗     ██████╗      █████╗ ██╗
██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗    ██╔══██╗██║
███████╗███████║██║█████╗  ██║     ██║  ██║    ███████║██║
╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║    ██╔══██║██║
███████║██║  ██║██║███████╗███████╗██████╔╝    ██║  ██║██║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝
```

# ShieldAI — Autonomous AI-Powered Cybersecurity Platform

**The cybersecurity nervous system for the AI era.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=flat-square&logo=pytorch)](https://pytorch.org)
[![Suricata](https://img.shields.io/badge/IDS-Suricata-F47C20?style=flat-square)](https://suricata.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-MVP%20In%20Progress-orange?style=flat-square)]()

> *"You don't manage ShieldAI. You delegate your infrastructure to it."*

</div>

---

## What is ShieldAI ?

ShieldAI is not a scanner. It's not a firewall. It's not another SIEM dashboard.

**ShieldAI is an autonomous cybersecurity operating system** — a platform that takes full custody of your digital infrastructure, continuously monitors it, detects threats, simulates attacks, isolates suspicious behavior, and reports everything to the administrator in real time.

It can be operated manually by a human analyst, or run fully autonomously driven by an AI orchestrator that coordinates specialized agents — each expert in their domain.

You delegate. ShieldAI protects.

---

## Core Philosophy

| Principle | Description |
|---|---|
| **Autonomous by default** | ShieldAI runs 24/7 without waiting for human intervention |
| **Human in the loop** | Every critical action requires admin authorization |
| **Modular architecture** | Each module works standalone OR as an agent tool |
| **AI-native** | Every detection, decision and report is AI-powered |
| **Africa-first** | Built for infrastructures and organizations overlooked by Western giants |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SHIELDAI CYBER-OS                                │
│              AI Orchestrator — The Central Brain                    │
│                     (Llama 3.1 8B via Groq)                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Agent Scanner   │   │   Agent IDS/IPS  │   │  Agent Simulator │
│  "The Explorer"  │   │  "The Guardian"  │   │  "The Attacker"  │
│  DeepSeek-Coder  │   │  Phi-3 Mini      │   │  CodeLlama 7B    │
└──────────────────┘   └──────────────────┘   └──────────────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Agent Anti-Phish│   │  Agent Sandbox   │   │ Agent Reporter   │
│  "The Detector"  │   │  "The Biologist" │   │  "The Scribe"    │
│  Mistral 7B      │   │  CodeLlama 7B    │   │  Mistral 7B      │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

### Dual Operation Mode

```
┌────────────────────────────────────────────────┐
│                                                │
│   AUTONOMOUS MODE          MANUAL MODE         │
│   ───────────────          ───────────         │
│   AI Orchestrator          Human Analyst       │
│   coordinates agents       uses modules        │
│   independently            directly via UI     │
│                                                │
│   Both modes share the same module layer       │
│                                                │
└────────────────────────────────────────────────┘
```

---

## Module Roadmap

### 🔥 Phase 1 — MVP (Core Security)

| # | Module | Description | Status |
|---|---|---|---|
| 1 | **Vulnerability Scanner** | AI-powered web vulnerability scanner — detects SQLi, XSS, SSRF, OWASP Top 10 | 🔄 In Progress |
| 2 | **Anti-Phishing AI** | 2M+ URL dataset, 36 features, PhishDestroy API, TTLCache — 99.3% accuracy | ✅ Near Complete |
| 3 | **IDS/IPS AI** | LSTM-based intrusion detection on Suricata EVE JSON — real-time network monitoring | 🔄 Migration |
| 4 | **Attack Simulator** | Adaptive AI offensive engine — tests your own infrastructure safely | 🔄 In Progress |
| 5 | **AI Sandbox** | Isolated execution environment — analyzes suspicious files, scripts, and behaviors | 🔄 In Progress |

### ⚡ Phase 2 — Advanced (Differentiation)

| # | Module | Description |
|---|---|---|
| 6 | **AI Orchestrator** | Central brain — coordinates all agents, multi-module, multi-user |
| 7 | **Cybersecurity Chatbot** | NLP assistant for analysts — powered by ContextGuard for prompt injection defense |
| 8 | **SIEM-like Log Manager** | Intelligent log analysis, audit trail, secure timestamped storage |
| 9 | **Continuous Learning Engine** | Self-adapting system — learns from feedback and new attack patterns |
| 10 | **Ransomware Protection** | Behavioral AI — detects encryption patterns before damage occurs |
| 11 | **Real-time Phishing Detection** | Live interception and analysis of emails and URLs |
| 12 | **Enhanced Sandbox** | Advanced isolated execution with full behavioral analysis |
| 13 | **Security Rules Interface** | Custom thresholds, automated action policies, admin control panel |
| 14 | **Third-party Integration** | SIEM, Jira, ServiceNow, Slack connectors |

### 🚀 Phase 3 — Ultra-Innovative (vs. Global Giants)

| # | Module | Description |
|---|---|---|
| 15 | **Cyber Threat Anticipation** | Predictive AI — forecasts attack vectors before they happen |
| 16 | **Cyber Deception / Honeypots** | Dynamic AI honeypots — lure and study attackers in real time |
| 17 | **Dark Web Intelligence** | Monitors dark web for leaked credentials and infrastructure data |
| 18 | **Blockchain Security Layer** | Immutable, tamper-proof audit logs |
| 19 | **Privacy Guardian** | Intelligent data anonymization and GDPR-like compliance |
| 20 | **Adaptive Zero-Trust Engine** | Dynamic per-request/per-user trust verification |
| 21 | **Swarm AI Defense** | Inter-AI threat sharing — collaborative real-time defense |
| 22 | **Automated Incident Response** | AI playbooks — auto-isolate, auto-patch, auto-escalate |
| 23 | **Cross-platform Vuln Intelligence** | Web + Mobile + Cloud vulnerability correlation |
| 24 | **Auto-patching** | Proposes or applies fixes automatically (admin-authorized) |
| 25 | **Threat Feed Dashboard** | Real-time alerts, threat scoring, prioritization |
| 26 | **Social Engineering Simulator** | Phishing campaigns and social attack simulations |
| 27 | **Attack Surface Visualization** | Interactive dynamic infrastructure mapping |
| 28 | **UEBA** | User and Entity Behavior Analytics — detects insider threats |

### 🟣 Phase 4 — Red/Blue/Purple Team AI

| # | Module | Description |
|---|---|---|
| 29 | **Red Team AI** | Generates realistic attacks with human-like behavior patterns |
| 30 | **Blue Team AI** | Defends, detects, and blocks Red Team attacks autonomously |
| 31 | **Purple Team AI** | Fusion of Red+Blue — analyzes interactions, optimizes defenses, adjusts playbooks |

---

## Autonomous Workflow

### Asset Added by Admin

```
Admin adds asset (website, server, PC, network)
              ↓
    Orchestrator notified
              ↓
    ┌─────────────────────┐
    │  Scanner launched   │ → vulnerabilities detected
    │  Simulator launched │ → defenses tested
    │  IDS/IPS activated  │ → traffic monitored
    └─────────────────────┘
              ↓
    Results correlated by Orchestrator
              ↓
    Admin notified → authorizes patch?
              ↓
    Auto-patch applied OR manual action
              ↓
    Full report generated
```

### Real-time Attack Detected

```
IDS/IPS fires alert
       ↓
UEBA correlates → insider or external?
       ↓
Dark Web Intel → known threat actor?
       ↓
Cyber Deception → deploy honeypot to trap attacker
       ↓
Orchestrator decides → block IP / isolate / monitor
       ↓
Sandbox → execute suspicious payload safely
       ↓
Reporter → immediate incident report to Admin
```

### Suspicious Email / Link Intercepted

```
Email / link received
       ↓
Anti-Phishing AI → phishing score computed
       ↓
TrustSignal → AI-generated content detected?
       ↓
ContextGuard → prompt injection hidden in content?
       ↓
Block + alert Admin OR allow + log
```

---

## AI Defense Layer (ContextGuard + TrustSignal)

ShieldAI integrates two unique modules that no competitor currently combines:

### ContextGuard
Multilingual prompt injection classifier protecting the admin chatbot and all LLM interfaces inside ShieldAI.

- Architecture: Custom Transformer Encoder (3 layers, 4 heads)
- Classes: `safe` | `injection` | `jailbreak` | `exfiltration`
- Export: TorchScript → ONNX for fast CPU inference

### TrustSignal
AI-generated content detector — identifies synthetic text, deepfakes, and forged images used in social engineering attacks.

- Detects fake identity documents
- Flags AI-generated images attempting to bypass facial recognition
- Scores emails and reports for synthetic content probability

```
Attacker sends AI-generated fake ID → facial recognition bypass attempt
                    ↓
        TrustSignal intercepts → synthetic content detected
                    ↓
                  BLOCKED
```

---

## Tech Stack

### Backend
```
FastAPI          — Modular API with include_router architecture
PyTorch 2.0+     — All custom AI/ML models
Suricata         — Network IDS/IPS (EVE JSON format)
ONNX Runtime     — Fast CPU inference for exported models
Redis            — Caching (TTLCache for Anti-Phishing)
Docker           — Containerized deployment
Caddy            — HTTPS reverse proxy
```

### AI Models (Custom-built)
```
IDS LSTM              — Intrusion detection on NSL-KDD / Suricata logs
Anti-Phishing MLP     — 36-feature URL classifier (2M+ training URLs)
Malware CNN           — Bytes-to-image malware classification
DeepLog LSTM          — Anomaly detection in system logs
ContextGuard Encoder  — Prompt injection classifier (Transformer)
TrustSignal           — AI-generated content detector
```

### LLM Agents (via Groq API)
```
Llama 3.1 8B     — Main Orchestrator
DeepSeek-Coder   — Scanner Agent
Phi-3 Mini       — IDS/IPS Agent
CodeLlama 7B     — Simulator + Sandbox Agents
Mistral 7B       — Anti-Phishing + Reporter Agents
```

---

## Project Structure

```
shieldai/
├── core/
│   ├── orchestrator/        # AI Orchestrator — agent coordination
│   ├── agents/              # Specialized AI agents
│   └── memory/              # Shared context and state
├── modules/
│   ├── scanner/             # Vulnerability Scanner
│   ├── anti_phishing/       # Anti-Phishing AI
│   ├── ids_ips/             # IDS/IPS (Suricata + LSTM)
│   ├── simulator/           # Attack Simulator
│   ├── sandbox/             # AI Sandbox
│   ├── context_guard/       # Prompt Injection Classifier
│   ├── trust_signal/        # AI Content Detector
│   └── reporter/            # Report Generator
├── api/
│   ├── main.py              # FastAPI entrypoint
│   └── routers/             # Per-module API routers
├── models/
│   ├── trained/             # Saved .pt and .onnx model files
│   └── trainers/            # Custom training pipelines
├── dashboard/               # Admin UI (React)
├── docker/                  # Docker Compose configs
└── docs/                    # Documentation
```
---

## Vision

> CrowdStrike serves Fortune 500 companies at $50K/year.
> Darktrace targets European enterprises.
> SentinelOne focuses on the US market.
>
> **Africa is unprotected. ShieldAI changes that.**

ShieldAI is built for the African market first — designed to run on modest infrastructure, priced for local organizations, and built by someone who understands the ecosystem from the inside.

The long-term vision:

```
Phase 1 → Dominate West African SMEs and startups
Phase 2 → Banks, telecoms, governments across francophone Africa
Phase 3 → Multinationals operating in Africa
Phase 4 → International expansion with proven African track record
```

ShieldAI is not another cybersecurity tool.
**It's the cybersecurity standard for the AI era in Africa.**

---

## Author

**Sam Hounsou** (`hounsoubenny-cyber`)
L1 Information Systems — IFRI, Cotonou, Bénin

- GitHub: [github.com/hounsoubenny-cyber](https://github.com/hounsoubenny-cyber)
- LinkedIn: [linkedin.com/in/benny-hounsou-00a267374](https://linkedin.com/in/benny-hounsou-00a267374)

---

<div align="center">

*Built with conviction. Built for Africa. Built for the AI era.*

**ShieldAI — We don't just detect threats. We eliminate them.**

</div>
