# 🛡️ ShieldAI V2 — Sandbox Module

## Rôle
Exécution isolée de code suspect dans un container Docker avec surveillance
comportementale en temps réel et honeypot filesystem pour piéger les malwares.

---

## Fichiers et rôles

| Fichier | Rôle | État |
|---|---|---|
| `Dockerfile.sandbox-base` | Image Docker avec 13 langages + honeypot filesystem | ✅ Fait — build en attente (timeout réseau) |
| `container_manager.py` | Gestion complète des containers Docker | ✅ Complet |
| `fs_monitor.py` | Surveillance filesystem via watchdog | ✅ Complet |
| `detect_language.py` | Détection de langage (14 langages) | ✅ Complet |
| `executor.py` | Exécution isolée du code dans le container | ✅ Complet |
| `behavior_scorer.py` | Agrégation des events → threat score | ⏳ À faire |
| `syscall_tracer.py` | Parsing des logs strace en temps réel | ⏳ À faire |
| `orchestrator.py` | Coordinateur principal du sandbox | ⏳ À faire |
| `agent_interface/` | Hooks pour agent IA futur | ⏳ À faire |

---

## Architecture des dépendances

```
orchestrator.py
    ├── container_manager.py   → Docker (create, exec, kill, stats...)
    ├── executor.py            → copy_in + exec_command_async
    │       ├── container_manager.py
    │       └── detect_language.py
    ├── fs_monitor.py          → watchdog sur get_fs_root()
    ├── syscall_tracer.py      → strace sur get_pid()
    └── behavior_scorer.py     → reçoit events de fs_monitor + syscall_tracer
```

---

## Langages supportés (14)
Python, JavaScript, PHP, Ruby, Perl, Java, Go, Rust, Lua, R, PowerShell, C, C++, Bash

---

## Honeypot Filesystem
Le container simule un vrai serveur de production Ubuntu 22.04 avec :
- Utilisateurs crédibles : `devops`, `deploy`, `appservice`, `dbadmin`, `sandbox`
- Fichiers piégés avec canary tokens marqués `CANARY-*-SHIELDAI` :
  - `/home/devops/.env.prod` → AWS, Stripe, DB, JWT fake
  - `/home/devops/.ssh/id_rsa` → clé SSH fake
  - `/root/.ssh/id_rsa` → clé SSH fake
  - `/var/www/app/.env` → credentials app fake
  - `/opt/monitoring/agent/config.yml` → API key fake
- Réseau interne fictif : db-primary, redis, bastion, ci-server

## Sécurité container
- `cap_drop=ALL` + `cap_add=SYS_PTRACE` (pour strace)
- `network_disabled=True`
- `pids_limit=64` (anti fork-bomb)
- `mem_limit=256m`
- User `sandbox` (uid 1500:1500)
- `security_opt=no-new-privileges`

---

## Queue d'événements
`SandBoxQueue` — wrapper unifié `asyncio.Queue` / `queue.Queue`
- `fs_monitor` → events filesystem → `behavior_scorer`
- `syscall_tracer` → events syscalls → `behavior_scorer`

---

## Ce qui reste à faire
1. `behavior_scorer.py` — agrège les events, calcule threat score 0-100
2. `syscall_tracer.py` — parse strace ligne par ligne (async for)
3. `orchestrator.py` — assemble tout, gère le cycle complet
4. `agent_interface/` — tools exposés pour agent IA futur
