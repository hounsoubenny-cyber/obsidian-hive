#!/usr/bin/env bash
set -euo pipefail

# Charge le .env de manière robuste
if [[ -f .env ]]; then
    set -a
    source .env
    set +a
else
    echo "❌ .env introuvable" >&2
    exit 1
fi

sudo -E /home/hounsousamuel/pyglobal0/bin/python3.11 /home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/main/api.py