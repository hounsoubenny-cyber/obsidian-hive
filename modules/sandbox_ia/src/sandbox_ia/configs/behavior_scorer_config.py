#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 20:15:10 2026

@author: hounsousamuel
"""

# =============================================================================
# CONSTANTES
# =============================================================================

THREAT_LEVELS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 59),
    "HIGH":     (60, 79),
    "CRITICAL": (80, 100),
}

ALERT_THRESHOLD = 60

# Decay
DECAY_INTERVAL = 10.0
DECAY_AMOUNT = 5

# Pondération temporelle (demi-vie en secondes)
TIME_DECAY_HALF_LIFE = 10.0  # Apres ce temps, il perds 50% de son poids

# Fenêtre pour la détection de séquences
SEQUENCE_WINDOW_SIZE = 20
SEQUENCE_TIMEOUT = 5.0

# Multiplicateur pour patterns de sets
PATTERN_MULTIPLIER = 1.5


# =============================================================================
# PATTERNS CONTEXTUELS (analyse des arguments)
# =============================================================================

CONTEXT_PATTERNS: dict[str, dict] = {
    # ── Credential Access ────────────────────────────────────────────────────
    "shadow_read": {
        "syscall": "openat",
        "args_contains": "/etc/shadow",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 50,
        "mitre": "T1003.008",
        "description": "Lecture de /etc/shadow — vol de hashes",
    },
    "passwd_read": {
        "syscall": "openat",
        "args_contains": "/etc/passwd",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 25,
        "mitre": "T1003.008",
        "description": "Lecture de /etc/passwd — énumération utilisateurs",
    },
    "ssh_key_theft": {
        "syscall": "openat",
        "args_contains": None,
        "args_contains_any": [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa"],
        "flags_contains": None,
        "score": 55,
        "mitre": "T1552.004",
        "description": "Vol de clé SSH privée",
    },
    "known_hosts_read": {
        "syscall": "openat",
        "args_contains": "known_hosts",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 30,
        "mitre": "T1021.004",
        "description": "Lecture known_hosts — préparation lateral movement",
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    "crontab_write": {
        "syscall": "openat",
        "args_contains": None,
        "args_contains_any": ["/etc/cron", "/var/spool/cron"],
        "flags_contains": "O_WRONLY",
        "score": 45,
        "mitre": "T1053.003",
        "description": "Écriture crontab — persistence",
    },
    "bashrc_write": {
        "syscall": "openat",
        "args_contains": ".bashrc",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 35,
        "mitre": "T1546.004",
        "description": "Modification .bashrc — persistence",
    },
    "systemd_persist": {
        "syscall": "openat",
        "args_contains": None,
        "args_contains_any": ["/etc/systemd", "/lib/systemd", "/usr/lib/systemd"],
        "flags_contains": "O_WRONLY",
        "score": 45,
        "mitre": "T1543.002",
        "description": "Modification service systemd — persistence",
    },
    "rc_local_write": {
        "syscall": "openat",
        "args_contains": "/etc/rc.local",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 45,
        "mitre": "T1037.004",
        "description": "Écriture /etc/rc.local — persistence démarrage",
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    "log_tampering": {
        "syscall": "openat",
        "args_contains": "/var/log",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 40,
        "mitre": "T1070.002",
        "description": "Modification logs — effacement de traces",
    },
    "ld_preload_inject": {
        "syscall": "openat",
        "args_contains": "ld.so.preload",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 60,
        "mitre": "T1574.006",
        "description": "Écriture ld.so.preload — injection LD_PRELOAD",
    },

    # ── Process Injection ────────────────────────────────────────────────────
    "proc_mem_write": {
        "syscall": "openat",
        "args_contains": "/proc/self/mem",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 60,
        "mitre": "T1055",
        "description": "Écriture /proc/self/mem — injection directe",
    },
    "proc_maps_read": {
        "syscall": "openat",
        "args_contains": "/proc/self/maps",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 25,
        "mitre": "T1055",
        "description": "Lecture /proc/self/maps — cartographie mémoire",
    },
    "mprotect_exec": {
        "syscall": "mprotect",
        "args_contains": "PROT_EXEC",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 50,
        "mitre": "T1055",
        "description": "mprotect PROT_EXEC — allocation mémoire exécutable",
    },

    # ── Backdoors & Payloads ─────────────────────────────────────────────────
    "backdoor_creation": {
        "syscall": "openat",
        "args_contains": None,
        "args_contains_any": ["backdoor", "rootkit", "reverse", "payload", "implant"],
        "flags_contains": "O_CREAT",
        "score": 60,
        "mitre": "T1587.001",
        "description": "Création fichier backdoor/payload",
    },
    "tmp_exec_write": {
        "syscall": "openat",
        "args_contains": "/tmp/",
        "args_contains_any": None,
        "flags_contains": "O_CREAT",
        "score": 30,
        "mitre": "T1036.005",
        "description": "Création fichier dans /tmp — staging payload",
    },
    "dev_shm_write": {
        "syscall": "openat",
        "args_contains": "/dev/shm/",
        "args_contains_any": None,
        "flags_contains": "O_CREAT",
        "score": 40,
        "mitre": "T1036.005",
        "description": "Écriture dans /dev/shm — fileless staging",
    },
    "elf_write": {
        "syscall": "openat",
        "args_contains": ".elf",
        "args_contains_any": None,
        "flags_contains": "O_CREAT",
        "score": 45,
        "mitre": "T1587.001",
        "description": "Écriture fichier ELF — dépôt d'exécutable",
    },
    "b64_exfil": {
        "syscall": "openat",
        "args_contains": ".b64",
        "args_contains_any": None,
        "flags_contains": "O_CREAT",
        "score": 35,
        "mitre": "T1560.001",
        "description": "Fichier base64 — données encodées pour exfiltration",
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "hosts_tamper": {
        "syscall": "openat",
        "args_contains": "/etc/hosts",
        "args_contains_any": None,
        "flags_contains": "O_WRONLY",
        "score": 45,
        "mitre": "T1565.001",
        "description": "Modification /etc/hosts — DNS hijacking",
    },

    # ── Container Escape ─────────────────────────────────────────────────────
    "docker_socket_access": {
        "syscall": "openat",
        "args_contains": "/var/run/docker.sock",
        "args_contains_any": None,
        "flags_contains": None,
        "score": 70,
        "mitre": "T1611",
        "description": "Accès socket Docker — escape container",
    },
    "kernel_module_load": {
        "syscall": "init_module",
        "args_contains": None,
        "args_contains_any": None,
        "flags_contains": None,
        "score": 70,
        "mitre": "T1215",
        "description": "Chargement module kernel — rootkit",
    },
}

# =============================================================================
# PATTERNS DE SÉQUENCES (ordre temporel important)
# =============================================================================

SEQUENCE_PATTERNS: dict[str, dict] = {
    "exfiltration": {
        "sequence": ["openat", "read", "connect", "sendto"],
        "timeout": 5.0,
        "score": 60,
        "mitre": "T1041",
        "description": "Exfiltration de données via réseau",
    },
    "ptrace_injection": {
        "sequence": ["ptrace", "openat", "write", "execve"],
        "timeout": 3.0,
        "score": 80,
        "mitre": "T1055.008",
        "description": "Injection de processus via ptrace",
    },
    "fileless_exec": {
        "sequence": ["memfd_create", "write", "execve"],
        "timeout": 2.0,
        "score": 85,
        "mitre": "T1620",
        "description": "Exécution fileless (mémoire uniquement)",
    },
    "ransomware_encrypt": {
        "sequence": ["openat", "read", "write", "rename"],
        "timeout": 3.0,
        "score": 70,
        "mitre": "T1486",
        "description": "Pattern ransomware",
    },
    "reverse_shell": {
        "sequence": ["socket", "connect", "dup2", "execve"],
        "timeout": 3.0,
        "score": 90,
        "mitre": "T1059.004",
        "description": "Reverse shell",
    },
    "priv_escalation": {
        "sequence": ["setuid", "execve"],
        "timeout": 2.0,
        "score": 70,
        "mitre": "T1548.001",
        "description": "Élévation de privilèges",
    },
}

# =============================================================================
# PATTERNS DE SETS (ordre non important)
# =============================================================================

SET_PATTERNS: dict[str, dict] = {
    "RANSOMWARE": {
        "syscalls": {"openat", "read", "write", "rename", "unlink"},
        "score": 80,
        "mitre": "T1486",
        "description": "Pattern ransomware (set)",
    },
    "EXFILTRATION": {
        "syscalls": {"openat", "read", "connect", "sendto"},
        "score": 70,
        "mitre": "T1041",
        "description": "Pattern exfiltration (set)",
    },
    "INJECTION": {
        "syscalls": {"mmap", "mprotect", "execve"},
        "score": 75,
        "mitre": "T1055",
        "description": "Pattern injection (set)",
    },
    "PERSISTENCE": {
        "syscalls": {"execve", "write", "chmod"},
        "score": 65,
        "mitre": "T1547",
        "description": "Pattern persistence (set)",
    },
    "FILELESS": {
        "syscalls": {"memfd_create", "execve"},
        "score": 85,
        "mitre": "T1620",
        "description": "Pattern fileless (set)",
    },
}
