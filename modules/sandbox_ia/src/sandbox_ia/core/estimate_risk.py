#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug  6 00:48:04 2026

@author: hounsousamuel
"""


import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from sandbox_ia.executor.detect_language import detect_language

# Patterns suspects par catégorie
PATTERNS = {
    # Credential harvesting
    "/etc/shadow": ("Lecture /etc/shadow", 40),
    "/etc/passwd": ("Lecture /etc/passwd", 20),
    ".ssh/id_rsa": ("Accès clé SSH privée", 45),
    ".ssh/id_ed25519": ("Accès clé SSH privée", 45),

    # Network / C2
    "socket.connect": ("Connexion réseau", 25),
    "requests.get": ("Requête HTTP sortante", 15),
    "urllib.request": ("Requête HTTP sortante", 15),
    "subprocess.Popen": ("Exécution de sous-processus", 30),
    "os.system": ("Exécution commande système", 25),
    "eval(": ("Eval dynamique (obfuscation possible)", 30),
    "exec(": ("Exec dynamique", 30),
    "__import__": ("Import dynamique", 20),

    # Persistence
    "/etc/crontab": ("Modification crontab", 35),
    "/etc/rc.local": ("Persistence rc.local", 35),
    ".bashrc": ("Modification .bashrc", 25),
    "ld.so.preload": ("Injection LD_PRELOAD", 50),

    # Fileless
    "memfd_create": ("Fileless execution", 60),
    "/dev/shm": ("Utilisation /dev/shm", 30),
    "ctypes": ("Ctypes (shellcode possible)", 25),
    "mmap": ("Mmap mémoire", 15),

    # Reverse shell indicators
    "bash -i": ("Pattern reverse shell", 70),
    "/dev/tcp": ("Redirection TCP bash", 70),
    "nc -e": ("Netcat reverse shell", 70),
    "base64.b64decode": ("Décodage base64 (payload possible)", 20),

    # Container escape
    "/var/run/docker.sock": ("Accès socket Docker (escape)", 65),
    "pivot_root": ("Tentative pivot_root", 60),

    # Crypto mining
    "stratum+": ("Pool minage crypto", 55),
    "xmrig": ("Miner XMRig", 65),
}

def estimate_risk(code: str, pattern: dict | None = None) -> dict:
    language = detect_language("", code)
    flags = []
    score = 0
    for pattern, (label, points) in dict(pattern or PATTERNS).items():
        if pattern.lower() in code.lower():
            flags.append(f"{label} (+{points})")
            score += points

    score = min(score, 100)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_level": level,
        "risk_score": score,
        "flags": flags,
        "recommend_sandbox": score >= 20,
        "language_detected": language,
    }

async def estimate_risk_async(code: str, pattern: dict | None = None) -> dict:
    return estimate_risk(code, pattern)