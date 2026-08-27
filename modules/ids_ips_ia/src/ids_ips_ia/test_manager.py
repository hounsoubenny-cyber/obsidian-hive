#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 20:54:48 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test de partage d'instance de classe via multiprocessing.Manager().dict()
"""

import multiprocessing as mp
import time
import os
import sys
import threading
from dataclasses import dataclass
from typing import Optional

# =============================================================================
# CLASSE COMPLEXE À PARTAGER (similaire à AnomalyDetector)
# =============================================================================

class ComplexDetector:
    """Simule un détecteur complexe avec threads, locks, et état interne."""
    
    def __init__(self, name: str = "Detector"):
        self.name = name
        self.pid = os.getpid()
        self.running = True
        self.counter = 0
        self.data = {}
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        
        # Simuler des modèles ML (non picklable)
        self.model = lambda x: x * 2  # Les lambdas ne sont pas picklables
        
        # Simuler une connexion réseau (non picklable)
        self.socket = object()  # Les objets bruts ne sont pas picklables
        
        print(f"[{self.name}] Initialisé dans PID {self.pid}")
    
    def _worker(self):
        """Thread worker qui modifie l'état interne."""
        while self.running:
            time.sleep(1)
            with self.lock:
                self.counter += 1
    
    def get_status(self):
        """Retourne l'état actuel."""
        with self.lock:
            return {
                'name': self.name,
                'pid': self.pid,
                'counter': self.counter,
                'running': self.running,
                'data_size': len(self.data)
            }
    
    def add_data(self, key, value):
        """Ajoute des données."""
        with self.lock:
            self.data[key] = value
    
    def stop(self):
        """Arrête le détecteur."""
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=2)


# =============================================================================
# TEST 1 : Essayer de partager l'instance directement
# =============================================================================

def worker_process_direct(shared_dict, detector_instance):
    """Processus qui essaie de recevoir une instance directement."""
    print(f"\n[Worker Direct PID {os.getpid()}] Reçu : {detector_instance}")
    
    if detector_instance is not None:
        try:
            status = detector_instance.get_status()
            print(f"[Worker Direct] Status: {status}")
        except Exception as e:
            print(f"[Worker Direct] ERREUR: {e}")
    else:
        print("[Worker Direct] Instance est None")


def test_direct_sharing():
    """Test 1 : Partage direct de l'instance."""
    print("\n" + "=" * 70)
    print("TEST 1 : Partage DIRECT de l'instance via Manager.dict()")
    print("=" * 70)
    
    manager = mp.Manager()
    shared_dict = manager.dict()
    
    # Créer l'instance dans le processus principal
    detector = ComplexDetector("DirectDetector")
    time.sleep(0.5)  # Laisser le thread démarrer
    
    print(f"\n[Main PID {os.getpid()}] Instance créée : {detector}")
    print(f"[Main] Status initial : {detector.get_status()}")
    
    # Essayer de mettre l'instance dans le dict partagé
    try:
        shared_dict['detector'] = detector
        print("[Main] ✅ Instance mise dans shared_dict")
    except Exception as e:
        print(f"[Main] ❌ ERREUR lors de la mise dans shared_dict : {e}")
        return
    
    # Lancer un processus enfant qui va essayer de récupérer l'instance
    print("\n[Main] Lancement du processus enfant...")
    p = mp.Process(
        target=worker_process_direct,
        args=(shared_dict, shared_dict.get('detector', None))
    )
    p.start()
    p.join(timeout=5)
    
    if p.is_alive():
        print("[Main] ⚠️ Processus enfant bloqué, kill...")
        p.kill()
        p.join()
    
    detector.stop()


# =============================================================================
# TEST 2 : Partager uniquement les DONNÉES (Proxy Pattern)
# =============================================================================

def worker_process_proxy(shared_state, command_queue):
    """Processus qui simule un détecteur et met à jour l'état partagé."""
    print(f"\n[Worker Proxy PID {os.getpid()}] Démarrage...")
    
    # Créer SA PROPRE instance du détecteur
    detector = ComplexDetector("ProxyDetector")
    
    # Mettre à jour l'état partagé pour indiquer qu'il est prêt
    shared_state['detector_ready'] = True
    shared_state['detector_pid'] = os.getpid()
    shared_state['detector_name'] = detector.name
    
    # Boucle de travail
    iteration = 0
    while iteration < 5:
        time.sleep(1)
        iteration += 1
        
        # Mettre à jour l'état partagé avec les données
        status = detector.get_status()
        shared_state['counter'] = status['counter']
        shared_state['data_size'] = status['data_size']
        shared_state['last_update'] = time.time()
        
        # Ajouter des données dans le dict partagé
        shared_state[f'data_{iteration}'] = f'Value from PID {os.getpid()}'
        
        print(f"[Worker Proxy] Itération {iteration}, counter={status['counter']}")
        
        # Vérifier les commandes
        if 'commands' in shared_state:
            cmd = shared_state.get('commands', [])
            if 'stop' in cmd:
                print("[Worker Proxy] Commande STOP reçue")
                break
    
    # Nettoyage
    detector.stop()
    shared_state['detector_ready'] = False
    print("[Worker Proxy] Arrêt")


def test_proxy_pattern():
    """Test 2 : Proxy Pattern - Partager les données, pas l'instance."""
    print("\n" + "=" * 70)
    print("TEST 2 : Proxy Pattern - Partage des DONNÉES uniquement")
    print("=" * 70)
    
    manager = mp.Manager()
    shared_state = manager.dict()
    
    # Initialiser l'état partagé
    shared_state['detector_ready'] = False
    shared_state['counter'] = 0
    shared_state['commands'] = manager.list()
    
    print(f"\n[Main PID {os.getpid()}] État partagé initialisé")
    print(f"[Main] shared_state est de type : {type(shared_state)}")
    
    # Lancer le processus worker
    print("\n[Main] Lancement du processus worker...")
    p = mp.Process(
        target=worker_process_proxy,
        args=(shared_state, None)
    )
    p.start()
    
    # Attendre que le détecteur soit prêt
    print("[Main] Attente que le détecteur soit prêt...")
    timeout = 10
    while timeout > 0 and not shared_state.get('detector_ready', False):
        time.sleep(0.5)
        timeout -= 0.5
        print(f"[Main] En attente... (detector_ready={shared_state.get('detector_ready', False)})")
    
    if shared_state.get('detector_ready', False):
        print(f"\n[Main] ✅ Détecteur PRÊT !")
        print(f"[Main] PID du détecteur : {shared_state.get('detector_pid')}")
        print(f"[Main] Nom du détecteur : {shared_state.get('detector_name')}")
        
        # Surveiller l'état partagé
        for i in range(5):
            time.sleep(1)
            print(f"[Main] Counter = {shared_state.get('counter', 0)}, "
                  f"Data size = {shared_state.get('data_size', 0)}")
            
            # Lire les données ajoutées
            for key in list(shared_state.keys()):
                if key.startswith('data_'):
                    print(f"[Main]   {key} = {shared_state[key]}")
                    del shared_state[key]  # Nettoyer après lecture
        
        # Envoyer commande d'arrêt
        print("\n[Main] Envoi commande STOP...")
        shared_state['commands'].append('stop')
    
    p.join(timeout=5)
    if p.is_alive():
        print("[Main] ⚠️ Worker bloqué, kill...")
        p.kill()
        p.join()
    
    print(f"\n[Main] État final : {dict(shared_state)}")


# =============================================================================
# TEST 3 : Vérifier ce qui est picklable ou non
# =============================================================================

def test_picklability():
    """Test 3 : Vérifier ce qui peut être picklé."""
    print("\n" + "=" * 70)
    print("TEST 3 : Vérification de picklability")
    print("=" * 70)
    
    import pickle
    
    detector = ComplexDetector("PickleTest")
    
    # Liste des attributs à tester
    tests = [
        ("Instance complète", detector),
        ("Lambda", detector.model),
        ("Thread", detector.thread),
        ("Lock", detector.lock),
        ("Socket simulé", detector.socket),
        ("Dict simple", detector.data),
        ("String", detector.name),
        ("Int", detector.counter),
    ]
    
    for name, obj in tests:
        try:
            pickle.dumps(obj)
            print(f"✅ {name} : PICKLABLE")
        except Exception as e:
            print(f"❌ {name} : NON PICKLABLE - {type(e).__name__}")
    
    detector.stop()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # S'assurer d'utiliser spawn pour éviter les problèmes d'héritage
    try:
        mp.set_start_method('spawn')
    except RuntimeError:
        pass
    
    print("=" * 70)
    print("TEST DE PARTAGE D'INSTANCE ENTRE PROCESSUS")
    print("=" * 70)
    
    # Test 1 : Partage direct (VA ÉCHOUER)
    test_direct_sharing()
    
    # Test 2 : Proxy Pattern (VA RÉUSSIR)
    test_proxy_pattern()
    
    # Test 3 : Picklability
    test_picklability()
    
    print("\n" + "=" * 70)
    print("✅ TOUS LES TESTS TERMINÉS")
    print("=" * 70)
    print("\nCONCLUSION :")
    print("  - Une instance de classe complexe NE PEUT PAS être partagée directement")
    print("  - Le Proxy Pattern (partage des DONNÉES) FONCTIONNE PARFAITEMENT")
    print("  - Les objets non-picklables (lambdas, threads, locks) bloquent la sérialisation")