#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 20:04:13 2026

@author: hounsousamuel
"""


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES — Chemins surveillés
# ─────────────────────────────────────────────────────────────────────────────

# Fichiers honeypot — contiennent des canary tokens marqués CANARY+SHIELDAI
# Tout accès à ces fichiers déclenche une alerte CRITIQUE (score +40)
CANARY_PATHS = [
    "/home/devops/.env.prod",
    "/home/devops/.ssh/id_rsa",
    "/home/deploy/.ssh/id_rsa",
    "/root/.ssh/id_rsa",
    "/var/www/app/.env",
    "/opt/monitoring/agent/config.yml",
    "/etc/shadow",
]

# Chemins suspects — typiquement fouillés par du code malveillant
# Tout accès déclenche une alerte MOYENNE (score +15)
SUSPICIOUS_PATHS = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/nginx",
    "/etc/mysql",
    "/etc/redis",
    "/home/devops/.bash_history",
    "/home/devops/scripts/",
    "/var/log/",
    "/var/backups/",
    "/var/www/",
    "/root/",
]

# Extensions suspectes — si le code crée des fichiers avec ces extensions
# Indique une tentative de persistence ou d'exfiltration (score +10)
SUSPICIOUS_EXTENSIONS = [
    ".sh", ".pl", ".rb",     # scripts de persistence
    ".elf", ".so",           # binaires Linux compilés
    ".b64", ".enc",          # données encodées/chiffrées (exfiltration)
]