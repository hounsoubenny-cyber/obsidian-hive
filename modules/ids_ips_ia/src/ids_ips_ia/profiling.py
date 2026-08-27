#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 10:04:34 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import cProfile
import pstats
import time
import threading
import multiprocessing
from ids_ips_ia.detection.detection_module import AnomalyDetector  # Adapter le chemin
from ids_ips_ia.main.orchestrator import IDS_IPS

def run_profiling(duration=600):
    """Exécute l'analyse et génère un rapport."""
    print(f"🔍 Profilage de l'IDS/IPS pendant {duration} secondes...")
    
    # # Initialisation minimale
    # detector = AnomalyDetector(graphs=False, Models_instance=None, interfaces=['lo']) # Exemple avec loopback
    
    # Lancement du profileur
    profiler = cProfile.Profile()
    profiler.enable()
    IDS = IDS_IPS()
    th = threading.Thread(target=IDS.main, args=(True, ), daemon=True)
    th.start()
    try:
        th.join(duration)
    except Exception:
        pass
    
    
    profiler.disable()
    
    # Sauvegarde et analyse des stats
    stats_file = 'ids_profile.stats'
    profiler.dump_stats(stats_file)
    print(f"📊 Statistiques brutes sauvegardées dans {stats_file}")
    
    # Affichage du top 20 des fonctions les plus consommatrices
    print("\n🔥 TOP 20 DES FONCTIONS PAR TEMPS CUMULÉ :")
    p = pstats.Stats(stats_file)
    p.sort_stats('cumulative').print_stats(20)
    
    print("\n🔥 TOP 20 DES FONCTIONS PAR NOMBRE D'APPELS :")
    p.sort_stats('ncalls').print_stats(20)
    
    # Pour une visualisation graphique (optionnel)
    try:
        import gprof2dot
        import subprocess
        subprocess.run(f"gprof2dot -f pstats {stats_file} | dot -Tpng -o profile_graph.png", shell=True)
        print("📈 Graphique d'appel généré : profile_graph.png")
    except Exception:
        print("💡 Pour un graphique, installez : pip install gprof2dot")

if __name__ == "__main__":
    run_profiling()