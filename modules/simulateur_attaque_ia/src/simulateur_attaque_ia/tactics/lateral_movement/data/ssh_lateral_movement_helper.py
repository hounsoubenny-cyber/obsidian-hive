#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel

Helper data pour SSHLateralMovement (T1021.004).
"""

from typing import Dict, Any
# =============================================================================
# USERNAMES — à tester pour la connexion SSH avec clé
# =============================================================================

# Un attaquant essaie ces users courants sur chaque host découvert
DEFAULT_USERNAMES = [
    "root",
    "ubuntu",
    "debian",
    "admin",
    "user",
    "git",
    "deploy",
    "ansible",
    "vagrant",
]

NETWORK_COMMANDS = {
    "cat /etc/hosts 2>/dev/null || echo 'HOSTS_DENIED'": {...},
    "ip addr show 2>/dev/null || ...": {...},
    "ip route 2>/dev/null || ...": {...},
    "ss -tlnp 2>/dev/null || ...": {...},
}
