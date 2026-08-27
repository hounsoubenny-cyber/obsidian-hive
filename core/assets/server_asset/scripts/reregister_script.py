#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 07:34:57 2026

@author: hounsousamuel
"""

REREGISTER_SCRIPT_TEMPLATE = """#!/bin/bash
set -euo pipefail

export LANG=C.UTF-8
export LC_ALL=C.UTF-8

TOKEN="{token}"
CONFIG_PATH="/opt/obsidian-agent/config.toml"
SERVICE_NAME="obsidian-agent"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être exécuté en root (sudo)." >&2
    exit 1
fi

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Configuration introuvable ($CONFIG_PATH) — utilise install.sh pour une première installation." >&2
    exit 1
fi

echo "==> Mise à jour du token d'installation..."
sed -i '/^pending_token/d' "$CONFIG_PATH"
echo "pending_token = \\"$TOKEN\\"" >> "$CONFIG_PATH"

echo "==> Redémarrage de l'agent..."
systemctl restart "$SERVICE_NAME"

echo "==> Agent redémarré, ré-enregistrement en cours (vérifie avec: journalctl -u $SERVICE_NAME -f)"
"""
