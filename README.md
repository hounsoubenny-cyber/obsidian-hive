<div align="center">

```
███████╗██╗  ██╗██╗███████╗██╗     ██████╗      █████╗ ██╗
██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗    ██╔══██╗██║
███████╗███████║██║█████╗  ██║     ██║  ██║    ███████║██║
╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║    ██╔══██║██║
███████║██║  ██║██║███████╗███████╗██████╔╝    ██║  ██║██║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝
```

# ShieldAI — Autonomous AI-Powered Cybersecurity Ecosystem

**The cybersecurity nervous system for the AI era.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=flat-square&logo=pytorch)](https://pytorch.org)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?style=flat-square&logo=redis)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-MVP%20In%20Progress-orange?style=flat-square)]()

> *"You don't manage ShieldAI. You delegate your infrastructure to it."*

</div>

---

## What is ShieldAI?

ShieldAI is not a scanner. It's not a firewall. It's not another SIEM dashboard.

**ShieldAI is an autonomous cybersecurity ecosystem** — a living platform that takes full custody of your digital infrastructure, continuously monitors it, detects threats, simulates attacks, isolates suspicious behavior, proposes and tests remediation, and reports everything to the administrator in real time.

It runs as an organism. Every module is a specialized organ. The AI orchestrator is the brain. The admin is the conscience.

You delegate. ShieldAI protects.

---

## Core Philosophy

| Principle | Description |
|---|---|
| **Autonomous by default** | ShieldAI runs 24/7 without waiting for human intervention |
| **Human in the loop** | Every critical action — patch, simulation, isolation — requires explicit admin authorization |
| **Modular by design** | Each module works standalone OR as a component of the autonomous system |
| **AI-native** | Every detection, decision, and report is AI-powered |
| **Memory-driven** | ShieldAI remembers every asset, every attack, every fix — and learns from them |
| **Ecosystem thinking** | From browser extension to mail proxy to core platform — protection at every layer |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                      SHIELDAI ECOSYSTEM                              │
├──────────────────────┬───────────────────────┬───────────────────────┤
│   🖥️  Admin Dashboard │ 🔌 Browser Extension  │  📧 Mail Proxy        │
│      (React)         │  (Chrome / Firefox)   │  (SMTP / IMAP)        │
└──────────────────────┴───────────────────────┴───────────────────────┘
                                    │
                         HTTP / WebSocket
                                    │
┌───────────────────────────────────▼──────────────────────────────────┐
│                        AEGIS API GATEWAY                             │
│                           (FastAPI)                                  │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │
┌───────────────────────────────────▼──────────────────────────────────┐
│                          AEGIS CORE                                  │
│              The Central Brain — AI Orchestrator                     │
│        Correlates · Decides · Alerts · Learns · Remembers            │
│                                                                      │
│   ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│   │  AegisCore      │  │  AegisAnalyst    │  │  AegisRed        │   │
│   │  Orchestrator   │  │  Interpreter     │  │  Simulator       │   │
│   │  Coordinates    │  │  Explains vulns  │  │  Runs attacks    │   │
│   │  all modules    │  │  Proposes fixes  │  │  (Sandbox only)  │   │
│   └─────────────────┘  └──────────────────┘  └──────────────────┘   │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │
                     Redis Event Bus (Pub/Sub)
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────┐      ┌─────────────────┐       ┌─────────────────┐
│  Scanner Layer  │      │  Defense Layer  │       │  Intel Layer    │
│                 │      │                 │       │                 │
│  Port Scanner   │      │  IDS / IPS AI   │       │  ThreatIntel    │
│  Web Auditor    │      │  Anti-Phishing  │       │  CVE Tracker    │
│  Vuln Scanner   │      │  ContextGuard   │       │  TrustSignal    │
└─────────────────┘      └─────────────────┘       └─────────────────┘
         │                          │                          │
         └──────────────────────────┼──────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────┐      ┌─────────────────┐       ┌─────────────────┐
│  Action Layer   │      │  Memory Layer   │       │  Output Layer   │
│                 │      │                 │       │                 │
│  Sandbox        │      │  Asset Manager  │       │  Report Engine  │
│  Attack Sim     │      │  System Memory  │       │  Alert System   │
│  Playbook Eng.  │      │  Audit Trail    │       │  Risk Scoring   │
└─────────────────┘      └─────────────────┘       └─────────────────┘
                                    │
┌───────────────────────────────────▼──────────────────────────────────┐
│                         DATA LAYER                                   │
│              PostgreSQL · Redis · ONNX Runtime                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Dual Operation Mode

```
┌────────────────────────────────────────────────────┐
│                                                    │
│   AUTONOMOUS MODE           MANUAL MODE            │
│   ───────────────           ───────────            │
│   AegisCore coordinates     Human analyst          │
│   all modules               uses modules           │
│   independently             directly via UI        │
│                                                    │
│   Both modes share the exact same module layer     │
│   Every module works standalone OR orchestrated    │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## Autonomous Workflows

### Asset Added by Admin

```
Admin adds asset (website, server, PC, network, mail domain)
                        ↓
              Asset Manager registers asset
                        ↓
              AegisCore notified via Event Bus
                        ↓
        ┌───────────────────────────────┐
        │    Immediate analysis         │
        │    Port Scanner launched      │
        │    Web Auditor launched       │
        │    IDS/IPS activated          │
        │    ThreatIntel queried        │
        └───────────────────────────────┘
                        ↓
        AegisAnalyst correlates results
                        ↓
        Risk Score computed and assigned
                        ↓
        Vulnerabilities ranked by criticality
                        ↓
        Admin notified — "Authorize patch?"
                        ↓
        Admin validates
                        ↓
        Playbook Engine tests fix in Sandbox (Docker clone)
                        ↓
        Fix validated → Admin applies OR auto-deploys
                        ↓
        Full report generated · Audit trail updated
```

### Real-Time Attack Detected

```
IDS/IPS fires alert
        ↓
AegisCore receives event
        ↓
ThreatIntel → known threat actor? known IP?
        ↓
AegisAnalyst → attack vector identified
        ↓
Risk Score updated in real time
        ↓
AegisCore decides → block / isolate / monitor / deploy honeypot
        ↓
Sandbox → execute suspicious payload safely
        ↓
Smart Alert System → admin notified by criticality level
        ↓
Full incident report generated
```

### Simulation Request

```
AegisCore detects weak asset OR admin requests manual simulation
        ↓
⚠️  ADMIN EXPLICIT VALIDATION REQUIRED — no exception
        ↓
Admin authorizes + selects simulation type
        ↓
Asset cloned in isolated Docker environment
        ↓
AegisRed pilots simulation on CLONE ONLY
        ↓
AegisAnalyst interprets results
        ↓
Vulnerabilities mapped, resistance score computed
        ↓
Report delivered to admin
        ↓
Real asset — untouched
```

### Phishing Intercepted (Mail Proxy)

```
Incoming email → ShieldAI Mail Proxy intercepts
        ↓
Anti-Phishing AI → phishing score computed
        ↓
TrustSignal → AI-generated content detected?
        ↓
ContextGuard → prompt injection hidden in content?
        ↓
Block + alert admin  OR  deliver + log
```

### User Clicks a Link (Browser Extension)

```
User clicks link in browser
        ↓
ShieldAI Extension intercepts
        ↓
URL sent to Anti-Phishing API (< 200ms)
        ↓
✅ Safe → allow   ⚠️ Suspicious → warn   🚫 Malicious → block
        ↓
Event logged and remounted to admin dashboard
```

---

## The Three AI Agents

ShieldAI uses exactly three AI agents — no more. Each has a strict domain.

| Agent | Role | Lives where |
|---|---|---|
| **Coralie, the decision-maker** | Orchestrates all modules, correlates events, decides, alerts | Core platform |
| **Alex, the analyst** | Interprets raw technical data, explains vulnerabilities, proposes fixes | Core platform |
| **Red, the the hacker** | Pilots attack simulations, adapts strategy, analyzes resistance | Sandbox only — never exits |

> Red is sandbox-isolated by design. It has no access to real assets. Ever.

---

## Complete Module List

### Phase 1 — Foundation (Existing + Core Infrastructure)

| # | Module | Description | Status |
|---|---|---|---|
| 1 | **Vulnerability Scanner** | AI-powered web vuln scanner — SQLi, XSS, SSRF, OWASP Top 10 | 🔄 In Progress |
| 2 | **Anti-Phishing AI** | 2M+ URL dataset, 36 features, 99.3% accuracy | ✅ Near Complete |
| 3 | **IDS/IPS AI** | LSTM-based intrusion detection on Suricata EVE JSON | 🔄 Migration |
| 4 | **Attack Simulator** | Adaptive offensive engine on Docker clones only | 🔄 In Progress |
| 5 | **AI Sandbox** | Isolated execution — analyzes files, scripts, behaviors | 🔄 In Progress |
| 6 | **ContextGuard** | Prompt injection classifier protecting all LLM interfaces | ✅ Built |
| 7 | **Port Scanner** | Port scan, service detection, OS fingerprinting, banner grabbing | 🔲 To Build |
| 8 | **Asset Manager** | Add/remove/manage assets. Type, status, risk score per asset | 🔲 To Build |
| 9 | **Risk Scoring Engine** | Continuous live risk score per asset. Updates on every event | 🔲 To Build |
| 10 | **Audit Trail** | Immutable log of all system and admin actions | 🔲 To Build |

### Phase 2 — Intelligence & Automation

| # | Module | Description |
|---|---|---|
| 11 | **AegisCore Orchestrator** | Central AI brain — 3 agents, event bus, full coordination |
| 12 | **Playbook Engine** | Versioned, sandboxed remediation scripts — tested before deployment |
| 13 | **Smart Alert System** | Grouped alerts by criticality. Anti-spam. Info / Warning / Critical |
| 14 | **System Memory** | ShieldAI remembers every asset history — attacks, fixes, patterns |
| 15 | **Scheduled Red Team** | Plan simulations (e.g. every Monday 3AM). Results in dashboard at dawn |
| 16 | **Report Engine** | Auto-generated PDF/HTML reports per scan, incident, simulation |
| 17 | **CVE / VulnTracker** | Matches detected services to known CVEs. Severity scoring |
| 18 | **TrustSignal** | Detects AI-generated content — synthetic text, deepfake images (bypass attempts) |
| 19 | **Cybersecurity Chatbot** | NLP assistant for analysts — protected by ContextGuard |
| 20 | **SIEM-like Log Manager** | Intelligent log analysis, anomaly detection, timestamped storage |

### Phase 2 — Ecosystem Layer

| # | Module | Description |
|---|---|---|
| 21 | **ShieldAI Browser Extension** | Real-time URL analysis in Chrome/Firefox — blocks phishing before the click |
| 22 | **ShieldAI Mail Proxy** | SMTP/IMAP proxy — intercepts and analyzes emails before delivery |
| 23 | **ShieldAI Mail Integration** | API connector for Gmail/Outlook — lighter deployment option |

### Phase 3 — Advanced Differentiation

| # | Module | Description |
|---|---|---|
| 24 | **Dynamic Honeypots** | AI-powered decoys — lure and study attackers in real time |
| 25 | **Dark Web Intelligence** | Monitors for leaked credentials and infrastructure data |
| 26 | **UEBA** | User & Entity Behavior Analytics — detects insider threats |
| 27 | **Threat Feed Dashboard** | Real-time threat scoring, prioritization, global feed |
| 28 | **Attack Surface Visualizer** | Interactive map of infrastructure — assets, links, risk zones |
| 29 | **Continuous Learning Engine** | System adapts from admin feedback and new attack patterns |
| 30 | **Ransomware Protection** | Behavioral AI — detects encryption patterns before damage occurs |
| 31 | **Third-Party Integrations** | Jira, ServiceNow, Slack, PagerDuty connectors |

### Phase 4 — Red / Blue / Purple Team AI

| # | Module | Description |
|---|---|---|
| 32 | **Red Team AI** | Generates realistic attacks with human-like behavior patterns |
| 33 | **Blue Team AI** | Defends, detects, and blocks Red Team attacks autonomously |
| 34 | **Purple Team AI** | Fusion of Red+Blue — analyzes interactions, optimizes defenses, adjusts playbooks |
| 35 | **Adaptive Zero-Trust Engine** | Dynamic per-request/per-user trust verification |
| 36 | **Automated Incident Response** | AI playbooks — auto-isolate, auto-patch, auto-escalate |

---

## AI Defense Layer

### ContextGuard
Multilingual prompt injection classifier protecting every LLM interface inside ShieldAI.

- Architecture: Custom Transformer Encoder (3 layers, 4 heads)
- Classes: `safe` | `injection` | `jailbreak` | `exfiltration`
- Export: TorchScript → ONNX for fast CPU inference
- Scope: Admin chatbot, AegisCore inputs, all external data parsed by LLMs

### TrustSignal
AI-generated content detector — identifies synthetic content used in social engineering and bypass attacks.

- Detects AI-generated text in emails and reports
- Flags synthetic images attempting to bypass facial recognition
- Identifies forged identity documents
- Scores all content with a 0–100 confidence rating

```
Attacker sends AI-generated fake ID → facial recognition bypass attempt
                    ↓
        TrustSignal intercepts → synthetic content detected
                    ↓
                  BLOCKED · Admin alerted
```

---

## Smart Alert System

No alert spam. No ignored notifications.

```
🟢 INFO     → Silent log only
🟡 WARNING  → Dashboard notification
🔴 CRITICAL → Immediate alert (dashboard + email + webhook)
```

- Similar alerts are grouped and deduplicated by AegisCore
- Each alert links directly to the affected asset and event timeline
- Admin can configure thresholds per asset type

---

## Tech Stack

### Backend
```
FastAPI          — Modular API with include_router architecture
PyTorch 2.0+     — All custom AI/ML models
Suricata         — Network IDS/IPS (EVE JSON format)
ONNX Runtime     — Fast CPU inference for exported models
Redis            — Event Bus (Pub/Sub) + caching
PostgreSQL       — Assets, events, reports, audit trail
Docker           — Sandbox isolation for simulations
asyncio          — Async workers and event processing
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

### LLM Layer
```
Single LLM via API    — Powers AegisCore, AegisAnalyst, AegisRed
                        One model, three agents, zero bloat
```

### Frontend & Ecosystem
```
React 18             — Admin dashboard with real-time WebSocket updates
Manifest V3          — Browser extension (Chrome + Firefox)
aiosmtpd             — Mail Proxy (SMTP)
aioimaplib           — Mail Proxy (IMAP)
```

---

## Project Structure

```
shieldai/
├── core/
│   ├── orchestrator/        # AegisCore — event bus, agent coordination
│   ├── agents/              # AegisAnalyst, AegisRed
│   ├── memory/              # System Memory, Asset state
│   └── scoring/             # Risk Scoring Engine
├── modules/
│   ├── scanner/             # Port Scanner + Web Auditor
│   ├── vuln_scanner/        # Vulnerability Scanner (existing)
│   ├── anti_phishing/       # Anti-Phishing AI (existing)
│   ├── ids_ips/             # IDS/IPS — Suricata + LSTM (existing)
│   ├── simulator/           # Attack Simulator — Docker only (existing)
│   ├── sandbox/             # AI Sandbox (existing)
│   ├── context_guard/       # Prompt Injection Classifier (existing)
│   ├── trust_signal/        # AI Content Detector
│   ├── playbook_engine/     # Remediation playbooks
│   ├── alert_system/        # Smart Alert System
│   ├── vuln_tracker/        # CVE matching and scoring
│   └── reporter/            # Report Engine
├── assets/
│   ├── manager/             # Asset Manager — CRUD, types, status
│   └── audit/               # Audit Trail — immutable logs
├── ecosystem/
│   ├── extension/           # Browser Extension (JS / Manifest V3)
│   ├── mail_proxy/          # SMTP/IMAP Proxy (Python)
│   └── mail_integration/    # Gmail / Outlook API connector
├── api/
│   ├── main.py              # FastAPI entrypoint
│   ├── gateway.py           # Unified API Gateway
│   └── routers/             # Per-module API routers
├── models/
│   ├── trained/             # Saved .pt and .onnx model files
│   └── trainers/            # Custom training pipelines
├── dashboard/               # Admin UI (React)
├── docker/                  # Docker Compose — platform + sandbox configs
└── docs/                    # Documentation
```

---

## Security Principles

| Principle | Implementation |
|---|---|
| **Sandbox isolation** | All simulations run on Docker clones — real assets never touched |
| **Admin-gated actions** | Simulations, patches, isolations — all require explicit human validation |
| **LLM protection** | ContextGuard filters all inputs to AI agents |
| **Immutable audit trail** | Every action logged with timestamp, actor, and result |
| **Least privilege** | AegisRed has zero access to production assets by architecture |
| **Fix versioning** | All playbooks are versioned and sandbox-tested before deployment |

---

## Vision

> CrowdStrike serves Fortune 500 companies at $50K/year.
> Darktrace targets European enterprises.
> SentinelOne focuses on the US market.
>
> **ShieldAI is built differently.**

Born from the conviction that serious cybersecurity should be accessible to every organization — not just those with enterprise budgets. Built from a deep understanding of underserved markets and overlooked infrastructures.

The long-term roadmap:

```
Phase 1 → MVP — Core modules + orchestration
Phase 2 → Full ecosystem — Dashboard, browser extension, mail proxy
Phase 3 → Advanced intelligence — Honeypots, Dark Web, UEBA
Phase 4 → Market expansion — Red/Blue/Purple Team, Zero-Trust, global reach
```

ShieldAI is not another cybersecurity tool.
**It's the cybersecurity standard for the AI era.**

---

## Author

**Samuel « Benny » Hounsou** (`hounsoubenny-cyber`)
Information Systems — IFRI, Cotonou, Bénin

- GitHub: [github.com/hounsoubenny-cyber](https://github.com/hounsoubenny-cyber)
- LinkedIn: [linkedin.com/in/benny-hounsou-00a267374](https://linkedin.com/in/benny-hounsou-00a267374)

---

<div align="center">

*Built with conviction. Built from Africa. Built for the world.*

**ShieldAI — We don't just detect threats. We eliminate them.**

</div>
