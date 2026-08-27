#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LIST_CHECKPOINTS — Version officielle LangGraph
"""

import sqlite3
import json
import os
from langgraph.checkpoint.sqlite import SqliteSaver

db_path = "/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/simulateur_attaque_ia/orchestrator/data/checkpoint/test_orchestrator_checkpoints_graphe_checkpoint.db"

print("=" * 70)
print("📋 LIST_CHECKPOINTS — VERSION OFFICIELLE")
print("=" * 70)
print(f"📁 DB: {db_path}")
print()

if not os.path.exists(db_path):
    print("❌ Base de données introuvable !")
    exit(1)

# ── Utiliser SqliteSaver avec context manager ──
with SqliteSaver.from_conn_string(db_path) as checkpointer:
    
    # Config pour lire les checkpoints d'un thread
    # Pour lister tous les checkpoints, on peut itérer sur chaque thread
    # ou lire directement la base
    
    # ── Méthode 1: Lire via la DB pour récupérer les thread_id ──
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Récupérer tous les thread_id uniques
        cursor.execute("SELECT DISTINCT thread_id FROM checkpoints")
        threads = cursor.fetchall()
        
        print(f"📊 {len(threads)} session(s) trouvée(s)\n")
        
        for thread_row in threads:
            thread_id = thread_row['thread_id']
            print(f"🔹 Session: {thread_id}")
            
            # Config pour ce thread
            config = {"configurable": {"thread_id": thread_id}}
            
            # ── Méthode officielle: utiliser list() ──
            try:
                # list() retourne un itérateur de checkpoints [citation:6]
                checkpoints = list(checkpointer.list(config, limit=5))
                
                if checkpoints:
                    # Prendre le plus récent (premier de la liste)
                    latest = checkpoints[0]
                    
                    # Extraire les données du checkpoint
                    checkpoint_data = latest.checkpoint
                    channel_values = checkpoint_data.get('channel_values', {})
                    
                    # ── Extraire l'IP ──
                    ip = channel_values.get('ip', 'N/A')
                    print(f"   🎯 IP cible: {ip}")
                    
                    # ── Extraire les phases ──
                    already_done = channel_values.get('already_done', [])
                    print(already_done, channel_values.get("actual_step"))
                    phases_done = [str(p) for p in already_done]
                    print(f"   📋 Phases: {phases_done}")
                    
                    # ── Credentials SSH ──
                    ssh_creds = channel_values.get('ssh_brute_force_found_credentials', {})
                    if ssh_creds:
                        total = sum(len(c) for c in ssh_creds.values())
                        print(f"   🔑 Credentials SSH: {total}")
                    
                    # ── Ports ouverts ──
                    open_ports = channel_values.get('open_ports', [])
                    if open_ports:
                        print(f"   🌐 Ports ouverts: {open_ports}")
                    
                    # ── Timestamp ──
                    ts = checkpoint_data.get('ts', 'N/A')
                    print(f"   🕐 Timestamp: {ts}")
                    
                    # ── Nombre de checkpoints ──
                    print(f"   📦 Checkpoints: {len(checkpoints)}")
                    
                else:
                    print("   ⚠️ Aucun checkpoint trouvé pour ce thread")
                    
            except Exception as e:
                print(f"   ⚠️ Erreur list(): {e}")
            
            print()
            
    except sqlite3.OperationalError as e:
        print(f"❌ Erreur SQLite: {e}")
    
    finally:
        conn.close()

print("=" * 70)