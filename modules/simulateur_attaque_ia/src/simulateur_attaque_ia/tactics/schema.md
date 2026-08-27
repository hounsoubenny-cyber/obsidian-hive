# ShieldAI V2 — Logique du Graphe d'Attaque

## Vue d'ensemble

Le simulateur est orchestré via **LangGraph** — un graphe d'état où chaque nœud est une phase d'attaque MITRE ATT&CK. L'état (`SimulatorState`) se propage de nœud en nœud, s'enrichissant à chaque étape. Les **edges conditionnels** décident dynamiquement du prochain nœud selon ce qui a été trouvé.

---

## Schéma du graphe

```
START
  │
  ▼
┌─────────────────────┐
│   RECONNAISSANCE    │  NetworkServiceDiscover
│   scan ports        │  → open_ports, port_function
└─────────┬───────────┘
          │
     ports ouverts ?
     ├── NON → END
     └── OUI ▼
┌─────────────────────┐
│   INITIAL ACCESS    │  SSHBruteForce + FTPBruteForce + HTTPBruteForce
│   brute force       │  → ssh_brute_force_found_credentials
└─────────┬───────────┘
          │
     creds SSH trouvés ?
     ├── NON → PERSISTENCE → REPORT → END
     └── OUI ▼
┌─────────────────────┐
│     EXECUTION       │  CommandExecution + PythonExecution + ReverseShell
│   shell distant     │  → command_execution_results
└─────────┬───────────┘
          │ (toujours)
          ▼
┌─────────────────────┐
│ PRIVILEGE ESCALATION│  SudoExploit + SUIDBinary
│   élévation privs   │  → privilege_escalation_success
└─────────┬───────────┘
          │ (toujours — peu importe si réussie ou non)
          ▼
┌─────────────────────┐
│  CREDENTIAL ACCESS  │  PasswordFileDump + BashHistoryRead + SSHKeyTheft
│  harvest secrets    │  → usable_keys, known_hosts
└─────────┬───────────┘
          │
     clés SSH + known_hosts trouvés ?
     ├── NON → EXFILTRATION
     └── OUI ▼
┌─────────────────────┐
│  LATERAL MOVEMENT   │  SSHLateralMovement (BFS asyncio)
│  propagation réseau │  → sessions, compromised_hosts
└─────────┬───────────┘
          │ (toujours)
          ▼
┌─────────────────────┐
│    EXFILTRATION     │  ExfiltrationHTTP
│  envoi vers C2      │  → sent_payloads
└─────────┬───────────┘
          │ (toujours)
          ▼
┌─────────────────────┐
│  DEFENSE EVASION    │  LogCleaner + Timestomp
│  effacer les traces │  → nettoyage logs, timestamps
└─────────┬───────────┘
          │ (toujours)
          ▼
┌─────────────────────┐
│    PERSISTENCE      │  CronBackdoor + SSHKeyBackdoor
│  maintenir l'accès  │  → backdoors installées
└─────────┬───────────┘
          │ (toujours)
          ▼
┌─────────────────────┐
│      REPORT         │  Génération rapport final
└─────────┬───────────┘
          │
          ▼
         END
```

---

## Logique de chaque edge conditionnel

### Recon → ?
| Condition | Destination |
|---|---|
| Ports ouverts trouvés | `initial_access` |
| Aucun port ouvert | `end` |

### Initial Access → ?
| Condition | Destination |
|---|---|
| Creds SSH trouvés | `execution` |
| Pas de creds SSH | `persistence` (ou `report` si persistence déjà fait) |

> **Pourquoi pas de creds SSH = persistence directe ?**
> Sans shell SSH, on ne peut pas exécuter de commandes. On tente quand même d'installer une backdoor si FTP ou HTTP ont donné accès à quelque chose.

### Execution → Privilege Escalation
Toujours. Le shell est obtenu, on tente systématiquement d'élever les privilèges avant de harvester.

### Privilege Escalation → Credential Access
Toujours — même si la privesc échoue. La différence :
- **PrivEsc réussie (root)** → `/etc/shadow` lisible, toutes les clés SSH accessibles
- **PrivEsc échouée (user)** → seulement les fichiers du user courant

### Credential Access → ?
| Condition | Destination |
|---|---|
| `usable_keys` ET `known_hosts` non vides | `lateral_movement` |
| L'un ou l'autre vide | `exfiltration` (skip lateral) |

> Les `usable_keys` viennent de `SSHKeyTheft`, les `known_hosts` aussi. Sans clés utilisables, pas de propagation possible.

### Lateral Movement → Exfiltration
Toujours. Qu'on ait compromis 0 ou 10 machines, on exfiltre ce qu'on a collecté.

### Exfiltration → Defense Evasion
Toujours. On nettoie les traces **après** avoir exfiltré — pas avant, sinon on efface des données utiles.

### Defense Evasion → Persistence
Toujours. On installe les backdoors après avoir nettoyé — les logs de l'installation de la backdoor seront nettoyés au prochain passage.

### Persistence → Report → End
Toujours.

---

## Pourquoi cet ordre ?

```
PrivEsc avant CredAccess  → plus de secrets accessibles avec root
CredAccess avant Lateral  → les clés volées alimentent la propagation
Exfil avant DefEvasion    → on envoie d'abord, on nettoie ensuite
DefEvasion avant Persist  → les traces de persistence sont nettoyées plus tard
```

C'est l'ordre qu'utilise un vrai attaquant — chaque phase prépare la suivante.

---

## État partagé — clés importantes

| Clé dans `SimulatorState` | Produite par | Consommée par |
|---|---|---|
| `open_ports` | Reconnaissance | Initial Access |
| `port_function` | Reconnaissance | Initial Access |
| `ssh_brute_force_found_credentials` | Initial Access | Execution, CredAccess, DefEvasion, Persistence |
| `privilege_escalation_success` | PrivEsc | (info rapport) |
| `lateral_movement_usable_keys` | CredAccess | Lateral Movement |
| `lateral_movement_known_hosts` | CredAccess | Lateral Movement |
| `credential_access_results` | CredAccess | Exfiltration |
| `lateral_movement_results` | Lateral Movement | Rapport |
| `exfiltration_results` | Exfiltration | Rapport |

---

## Cas limite : pas de creds SSH

```
Recon → Initial Access (FTP/HTTP only)
  └── FTP/HTTP trouvés mais pas SSH
      └── Persistence (via FTP upload ou HTTP)
          └── Report
```

La kill chain est courte mais le simulateur ne s'arrête pas — il documente ce qui était accessible et ce qui ne l'était pas.

---

## Stack technique

| Composant | Technologie |
|---|---|
| Orchestration | LangGraph + AsyncSqliteSaver (checkpointing) |
| Parallélisme | `asyncio.gather` par nœud |
| Connexions SSH | Paramiko (password + pkey) |
| Transport exfil | aiohttp |
| Dashboard | FastAPI WebSocket + React |
| Mode terminal | Rich (interactif step-by-step) |
| Persistance état | LMDB |
