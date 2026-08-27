#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 20:06:45 2026

@author: hounsousamuel
"""

# =============================================================================
# CONSTANTES — Familles de syscalls et scores associés
# =============================================================================
SYSCALL_FAMILIES: dict[str, dict] = {
    # ── Réseau ──────────────────────────────────────────────
    # Toute tentative réseau depuis un container isolé est suspecte.
    # network_disabled=True dans le container → si strace voit connect(), c'est
    # soit une tentative bloquée (intéressante), soit un bug (à investiguer).
    "socket":        {"family": "network", "score": 10},
    "connect":       {"family": "network", "score": 20},
    "bind":          {"family": "network", "score": 10},
    "listen":        {"family": "network", "score": 10},
    "sendto":        {"family": "network", "score": 15},
    "sendmsg":       {"family": "network", "score": 15},
    "recvfrom":      {"family": "network", "score":  5},
    "recvmsg":       {"family": "network", "score":  5},
    "getsockopt":    {"family": "network", "score":  5},
    "setsockopt":    {"family": "network", "score":  5},

    # ── Fichiers ─────────────────────────────────────────────
    # Les accès fichiers sont croisés avec les CANARY_PATHS de fs_monitor.
    # openat sur /etc/shadow ou /home/devops/.ssh/id_rsa → critique.
    "openat":        {"family": "file",    "score": 10},
    "open":          {"family": "file",    "score": 10},
    "read":          {"family": "file",    "score":  2},
    "write":         {"family": "file",    "score":  5},
    "unlink":        {"family": "file",    "score": 15}, # suppression de fichier
    "unlinkat":      {"family": "file",    "score": 15},
    "rename":        {"family": "file",    "score": 10},
    "renameat":      {"family": "file",    "score": 10},
    "renameat2":     {"family": "file",    "score": 10},
    "chmod":         {"family": "file",    "score": 15}, # modification de permissions
    "fchmod":        {"family": "file",    "score": 15},
    "chown":         {"family": "file",    "score": 15},
    "truncate":      {"family": "file",    "score": 10},
    "ftruncate":     {"family": "file",    "score": 10},

    # ── Processus ────────────────────────────────────────────
    # execve est le syscall le plus important : il indique qu'un programme
    # en lance un autre. fork/clone = création de processus enfant.
    # ptrace = tentative d'attachement à un autre processus (injection).
    "execve":        {"family": "process", "score": 25},
    "execveat":      {"family": "process", "score": 25},
    "fork":          {"family": "process", "score": 15},
    "vfork":         {"family": "process", "score": 15},
    "clone":         {"family": "process", "score": 15},
    "clone3":        {"family": "process", "score": 15},
    "kill":          {"family": "process", "score": 20},  # signal vers un autre processus
    "tkill":         {"family": "process", "score": 20},
    "tgkill":        {"family": "process", "score": 20},
    "ptrace":        {"family": "process", "score": 40}, # injection / debugging → très suspect

    # ── Mémoire ──────────────────────────────────────────────
    # mmap avec PROT_EXEC = allocation de mémoire exécutable → shellcode.
    # mprotect pour rendre une zone exécutable après écriture → red flag.
    "mmap":          {"family": "memory",  "score":  5},
    "mmap2":         {"family": "memory",  "score":  5},
    "mprotect":      {"family": "memory",  "score": 20},  # changement de permissions mémoire
    "munmap":        {"family": "memory",  "score":  2},
    "mremap":        {"family": "memory",  "score":  5},
    "memfd_create":  {"family": "memory",  "score": 30},  # fichier en mémoire → fileless malware

    # ── Système ──────────────────────────────────────────────
    # setuid/setgid = tentative d'escalade de privilèges.
    # mount = tentative de monter un filesystem.
    # sethostname = tentative de modifier l'identité du système.
    "setuid":        {"family": "system",  "score": 30},
    "setgid":        {"family": "system",  "score": 30},
    "setreuid":      {"family": "system",  "score": 30},
    "setregid":      {"family": "system",  "score": 30},
    "capset":        {"family": "system",  "score": 35},  # modification des capabilities Linux
    "mount":         {"family": "system",  "score": 35},
    "umount2":       {"family": "system",  "score": 25},
    "sethostname":   {"family": "system",  "score": 25},
    "pivot_root":    {"family": "system",  "score": 40},  # escape de namespace → très suspect
    "chroot":        {"family": "system",  "score": 35},
    "init_module":   {"family": "system",  "score": 45}, # chargement de module kernel → critique
    "finit_module":  {"family": "system",  "score": 45},
    "delete_module": {"family": "system",  "score": 40},
}

# Bonus supplémentaires pour certains syscalls spécifiques.
# S'ajoutent au score de base de la famille.
# Exemple : ptrace a déjà 40 de base (famille process) → pas de bonus
# mais memfd_create + execve ensemble = fileless execution pattern.
SYSCALL_BONUS: dict[str, int] = {
    "ptrace":         10, # 40 (process) + 10 bonus = 50 total
    "init_module":    10, # 45 (system) + 10 bonus = 55 total
    "finit_module":   10,
    "pivot_root":      5,
    "memfd_create":    5,
    "capset":          5,
}

IGNORE_PATTERNS = [
    "+++",                         # sortie de processus
    "---",                         # signal reçu
    "<unfinished",                 # syscall interrompu
    "resumed>",                    # reprise de syscall interrompu
    "= ?",                         # retval inconnu (exit_group)
    "strace:",                     # message strace (Process X attached)
    "<... ",                       # reprise de syscall avec préfixe
]