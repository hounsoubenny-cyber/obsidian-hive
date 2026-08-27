#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scripts CRON pour backdoor - Niveaux SIMPLE, INTERMEDIATE, SILENT
À placer dans tactics/persistence/data/backdoor_helper.py
"""

# ============================================================
# SCRIPT SIMPLE - Collecte basique pour test IDS
# ============================================================

SIMPLE = '''#!/bin/bash
# SIMPLE Persistence Agent - Pour test IDS basique

LOG_DIR="/log"
mkdir -p "$LOG_DIR" 2>/dev/null

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="$LOG_DIR/cron_simple.log"

echo "[$TIMESTAMP] SIMPLE_AGENT_STARTED" >> "$LOG_FILE"
echo "[$TIMESTAMP] HOSTNAME: $(hostname)" >> "$LOG_FILE"
echo "[$TIMESTAMP] USER: $(whoami)" >> "$LOG_FILE"
echo "[$TIMESTAMP] PWD: $(pwd)" >> "$LOG_FILE"
echo "[$TIMESTAMP] SIMPLE_AGENT_COMPLETED" >> "$LOG_FILE"

exit 0
'''

# ============================================================
# SCRIPT INTERMEDIATE - Collecte réseau + processus
# ============================================================

INTER = '''#!/bin/bash
# INTERMEDIATE Persistence Agent - Simulation realistic

LOG_DIR="/log"
mkdir -p "$LOG_DIR" 2>/dev/null

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="$LOG_DIR/agent_advanced.log"

echo "[$TIMESTAMP] INTERMEDIATE_AGENT_STARTED" >> "$LOG_FILE"

# Infos système
echo "=== SYSTEM INFO ===" >> "$LOG_FILE"
echo "HOSTNAME: $(hostname)" >> "$LOG_FILE"
echo "USER: $(whoami)" >> "$LOG_FILE"
echo "OS: $(uname -a | cut -d' ' -f1-3)" >> "$LOG_FILE"
echo "KERNEL: $(uname -r)" >> "$LOG_FILE"

# Réseau (ports ouverts)
echo "=== OPEN PORTS ===" >> "$LOG_FILE"
netstat -tuln 2>/dev/null | grep LISTEN | head -5 >> "$LOG_FILE"
ss -tuln 2>/dev/null | grep LISTEN | head -5 >> "$LOG_FILE"

# Processus top 3 CPU
echo "=== TOP PROCESSES ===" >> "$LOG_FILE"
ps aux --sort=-%cpu | head -4 | tail -3 >> "$LOG_FILE"

# Utilisateurs connectés
echo "=== LOGGED USERS ===" >> "$LOG_FILE"
who >> "$LOG_FILE" 2>/dev/null

echo "[$TIMESTAMP] INTEL_COLLECTED" >> "$LOG_FILE"
echo "[$TIMESTAMP] INTERMEDIATE_AGENT_COMPLETED" >> "$LOG_FILE"

exit 0
'''

# ============================================================
# SCRIPT SILENT - Ultra furtif pour test détection avancée
# ============================================================

SILENT = '''#!/bin/bash
# SILENT Persistence Agent - Ultra-stealth

LOG_DIR="/log"
mkdir -p "$LOG_DIR" 2>/dev/null

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="$LOG_DIR/ghost_activity.log"

# Écriture compacte sur 1 ligne
echo "$TIMESTAMP: GHOST_HEARTBEAT" >> "$LOG_FILE"
echo "$TIMESTAMP: GHOST_AGENT_STARTED" >> "$LOG_FILE"

# Collecte minimale mais critique
echo "$TIMESTAMP: HOST=$(hostname 2>/dev/null | cut -c1-32)" >> "$LOG_FILE"
echo "$TIMESTAMP: USER=$(whoami 2>/dev/null)" >> "$LOG_FILE"

# 1 ligne pour les ports (furtif)
PORTS=$(netstat -tuln 2>/dev/null | grep LISTEN | wc -l)
echo "$TIMESTAMP: PORTS=$PORTS" >> "$LOG_FILE"

# 1 ligne pour les processus
PROCS=$(ps aux 2>/dev/null | wc -l)
echo "$TIMESTAMP: PROCS=$PROCS" >> "$LOG_FILE"

echo "$TIMESTAMP: GHOST_AGENT_COMPLETED" >> "$LOG_FILE"

exit 0
'''

# ============================================================
# MAP pour conversion niveau -> script
# ============================================================

LEVEL_MAP = {
    'simple': SIMPLE,
    'sp': SIMPLE,
    'intermediate': INTER,
    'i': INTER,
    'inter': INTER,
    'silent': SILENT,
    's': SILENT,
    'advanced': SILENT,
    'a': SILENT,
}

def get_backdoor_script(level='simple'):
    """
    Retourne le script correspondant au niveau.
    
    Args:
        level (str): simple / intermediate / silent
    
    Returns:
        str: Le contenu du script bash
    """
    return LEVEL_MAP.get(level.lower(), SILENT)

def get_all_scripts():
    """
    Retourne tous les scripts dans un dictionnaire.
    
    Returns:
        dict: {'simple': script, 'intermediate': script, 'silent': script}
    """
    return {
        'simple': SIMPLE,
        'intermediate': INTER,
        'silent': SILENT,
    }

# ============================================================
# TEST
# ============================================================

if __name__ == '__main__':
    print("=" * 60)
    print("📜 SCRIPTS BACKDOOR PRÊTS À L'EMPLOI")
    print("=" * 60)
    
    for level, script in get_all_scripts().items():
        print(f"\n🔹 {level.upper()} ({len(script)} caractères)")
        print("-" * 40)
        print(script[:200] + "..." if len(script) > 200 else script)
    
    print("\n✅ Import utilisable :")
    print("   from backdoor_helper import SIMPLE, INTER, SILENT, get_backdoor_script")