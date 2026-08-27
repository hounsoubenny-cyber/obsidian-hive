#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 30 06:26:56 2026

@author: hounsousamuel
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

# Encoding manuel pour les familles de syscalls
# Utilisé directement dans le vecteur de features (pas d'Embedding)
FAMILY_ENCODING: dict[str, int] = {
    "network": 0,
    "file":    1,
    "process": 2,
    "memory":  3,
    "system":  4,
    "unknown": 5,
}

# Encoding pour les types d'events filesystem
# Symétrique de FAMILY_ENCODING pour les FSEvent
FS_EVENT_TYPE_ENCODING: dict[str, int] = {
    "created":  0,
    "modified": 1,
    "deleted":  2,
    "moved":    3,
    "opened":   4,
    "closed":   5,
}

# Syscalls critiques qui reçoivent un flag dédié
# Indépendamment de leur score dans SYSCALL_FAMILIES
TOP_DANGEROUS_SYSCALLS: set[str] = {
    "ptrace",
    "memfd_create",
    "pivot_root",
    "init_module",
    "finit_module",
    "capset",
    "chroot",
}

# Chemins sensibles — croisés avec args_raw (syscall) ou path (fs)
SENSITIVE_PATHS: dict[str, str] = {
    "is_shadow":  "/etc/shadow",
    "is_passwd":  "/etc/passwd",
    "is_ssh":     ".ssh/",
    "is_tmp":     "/tmp/",
    "is_dev_shm": "/dev/shm/",
    "is_proc":    "/proc/",
    "is_etc":     "/etc/",
    "is_root":    "/root/",
    "is_home":    "/home/",
    "is_var":     "/var/",
    "is_sys":     "/sys/",
}

# Extensions de fichiers suspectes
SUSPICIOUS_EXTENSIONS: dict[str, str] = {
    "ext_sh":  ".sh",
    "ext_py":  ".py",
    "ext_elf": ".elf",
    "ext_b64": ".b64",
    "ext_so":  ".so",
    "ext_pl":  ".pl",
    "ext_rb":  ".rb",
    "ext_enc": ".enc",
}

# Mots-clés suspects dans args_raw ou path
SUSPICIOUS_KEYWORDS: dict[str, str] = {
    "has_backdoor": "backdoor",
    "has_payload":  "payload",
    "has_exfil":    "exfil",
    "has_reverse":  "reverse",
    "has_rootkit":  "rootkit",
    "has_implant":  "implant",
    "has_shell":    "shell",
    "has_exploit":  "exploit",
}

# IPs et ports suspects dans args_raw
SUSPICIOUS_IPS: list[str] = [
    "0x7f000001", "127.0.0.1", "192.168", "10.0", "172.",
]
SUSPICIOUS_PORTS: list[str] = [
    ":80", ":443", ":22", ":4444", ":1337", ":8080", ":3333",
]

EXCLUDED = {"syscall", "timestamp"}
