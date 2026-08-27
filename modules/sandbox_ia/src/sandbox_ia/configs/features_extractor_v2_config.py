#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 30 06:26:53 2026

@author: hounsousamuel
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

FAMILY_ENCODING: dict[str, int] = {
    "network": 0,
    "file":    1,
    "process": 2,
    "memory":  3,
    "system":  4,
    "unknown": 5,
}

FS_EVENT_TYPE_ENCODING: dict[str, int] = {
    "created":  0,
    "modified": 1,
    "deleted":  2,
    "moved":    3,
    "opened":   4,
    "closed":   5,
}

TOP_DANGEROUS_SYSCALLS: set[str] = {
    "ptrace", "memfd_create", "pivot_root",
    "init_module", "finit_module", "capset", "chroot",
}

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

SUSPICIOUS_IPS: list[str] = [
    "0x7f000001", "127.0.0.1", "192.168", "10.0", "172.",
]
SUSPICIOUS_PORTS: list[str] = [
    ":80", ":443", ":22", ":4444", ":1337", ":8080", ":3333",
]

# Taille de la fenêtre glissante pour les features de contexte
CONTEXT_WINDOW_SIZE: int = 20

EXCLUDED = {"syscall", "timestamp"}