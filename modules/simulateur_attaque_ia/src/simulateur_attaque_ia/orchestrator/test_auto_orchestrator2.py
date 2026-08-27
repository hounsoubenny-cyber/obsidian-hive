#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 20 09:31:04 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_auto_orchestrator.py - Lance l'orchestrateur complet avec API dashboard

Usage:
    python test_auto_orchestrator.py
"""

import os
import sys
import asyncio
import json
import threading
import time
from datetime import datetime
from typing import Optional

# Ajouter les chemins
sys.path.insert(0, "/home/hounsousamuel/PROJET/ShieldIA_v2")
sys.path.insert(0, "/home/hounsousamuel/PROJET/ShieldIA_v2/simulateur_attaque_ia")

from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.orchestrator.auto_orchestrator import AutoAttackOrchestrator
from simulateur_attaque_ia.tactics.tests.environment import TestEnvironment
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.simulateur_utils.ids_utils import random_session_id
from simulateur_attaque_ia.api.run_api import run_api, IP, PORT
from simulateur_attaque_ia.orchestrator.ws_manager import WSManager

logger = get_logger()

# =============================================================================
# CONSTANTES
# =============================================================================
IMAGE_NAME = "clone_20260421_073827:latest"
CONTAINER_NAME = "shieldai_test"
API_START_DELAY = 3  # secondes d'attente pour l'API


# =============================================================================
# CALLBACK DASHBOARD
# =============================================================================
def create_dashboard_callback(ws_manager: WSManager):
    """Crée le callback pour envoyer les messages au dashboard."""
    
    async def dashboard_callback(msg: dict, session_id: str, in_dev: bool = True):
        """Callback appelé par l'orchestrateur → envoi via WebSocket."""
        await ws_manager.send_all(msg, session_id, in_dev)
    
    return dashboard_callback


# =============================================================================
# AFFICHAGE
# =============================================================================
def print_header():
    """Affiche l'en-tête du programme."""
    print("\n" + "=" * 70)
    print("🔴 SHIELDIA - AUTO ATTACK ORCHESTRATOR")
    print("=" * 70)
    print(f"📅 Démarrage : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def print_section(title: str):
    """Affiche un titre de section."""
    print(f"\n{title}")
    print("-" * 50)


def print_result_summary(state: dict, duration: float):
    """Affiche un résumé des résultats."""
    print_section("📊 RÉSULTATS DE L'ATTAQUE")
    
    # Infos générales
    print(f"\n🎯 Cible : {state.get('ip', 'inconnue')}")
    print(f"📡 Ports ouverts : {state.get('open_ports', [])}")
    print(f"⏱️  Durée : {duration:.2f} secondes")
    
    # Credentials SSH
    ssh_creds = state.get('ssh_brute_force_found_credentials', {})
    if ssh_creds:
        print(f"\n🔑 Credentials SSH trouvés :")
        for port, creds in ssh_creds.items():
            for cred in creds:
                print(f"   ✅ port {port} : {cred.get('username')}:{cred.get('password')}")
    else:
        print(f"\n🔑 Aucun credential SSH trouvé")
    
    # FTP Credentials
    ftp_creds = state.get('ftp_brute_force_found_credentials', {})
    if ftp_creds:
        print(f"\n📁 Credentials FTP trouvés :")
        for port, creds in ftp_creds.items():
            for cred in creds:
                print(f"   ✅ port {port} : {cred.get('username')}:{cred.get('password')}")
    
    # HTTP découvertes
    http_creds = state.get('http_brute_force_found_credentials', {})
    if http_creds:
        total_paths = sum(len(v) for v in http_creds.values())
        print(f"\n🌐 Chemins HTTP accessibles : {total_paths}")
    
    # Succès par étape
    print(f"\n✅ Succès par étape :")
    success_dict = state.get('success_dict', {})
    for step, success in success_dict.items():
        status = "✅" if success else "❌"
        print(f"   {status} {step}")
    
    # Erreurs éventuelles
    error_dict = state.get('error_dict', {})
    if error_dict:
        print(f"\n⚠️ Erreurs :")
        for step, errors in error_dict.items():
            for err in errors[:3]:  # Limiter à 3 erreurs par étape
                print(f"   ❌ {step} : {err[:100]}...")


def print_footer(success: bool, checkpoint_path: str, report_filename: str):
    """Affiche le pied de page du programme."""
    print("\n" + "=" * 70)
    print("🏁 BILAN FINAL")
    print("=" * 70)
    
    if success:
        print("🎉 L'ORCHESTRATEUR A FONCTIONNÉ !")
    else:
        print("⚠️ L'ORCHESTRATEUR A ÉCHOUÉ !")
    
    print(f"\n📁 Checkpoints : {checkpoint_path}")
    print(f"📄 Rapport JSON : {report_filename}")


# =============================================================================
# SAUVEGARDE RAPPORT
# =============================================================================
def save_report(state: dict, report: dict) -> str:
    """Sauvegarde le rapport au format JSON."""
    report_filename = f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "state": state,
            "report": report
        }, f, indent=2, default=str)
    
    print(f"   ✅ Rapport sauvegardé : {report_filename}")
    return report_filename


# =============================================================================
# LANCEMENT API
# =============================================================================
def start_api_in_thread() -> threading.Thread:
    """Démarre l'API dans un thread séparé."""
    print("🌐 Démarrage de l'API dashboard...")
    
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()
    
    # Attendre que l'API soit prête
    time.sleep(API_START_DELAY)
    print("   ✅ API démarrée sur http://{}:{}".format(IP, PORT))
    
    return api_thread


# =============================================================================
# ORCHESTRATEUR
# =============================================================================
async def run_orchestrator(session_id: str, dashboard_callback=None) -> dict:
    """
    Exécute l'orchestrateur avec environnement de test.
    
    Args:
        session_id: Identifiant de session pour le checkpoint
        dashboard_callback: Callback pour le dashboard (optionnel)
    
    Returns:
        dict: Résultat de l'orchestrateur
    """
    env = TestEnvironment(
        image_name=IMAGE_NAME,
        container_name=CONTAINER_NAME,
    )
    
    try:
        # 1. Créer l'environnement
        print_section("📦 1. Création de l'environnement de test")
        ip = env.setup()
        print(f"   ✅ Container démarré : IP = {ip}")
        
        # 2. Créer l'orchestrateur
        print_section("🎮 2. Initialisation de l'orchestrateur")
        
        dock = DockerManager()
        dock.container = env.container
        
        orchestrator = AutoAttackOrchestrator(
            docker_manager=dock,
            checkpoint_path="test_orchestrator_checkpoints",
            debug=True,
            dashboard_callback=dashboard_callback,
        )
        print("   ✅ Orchestrateur prêt")
        
        # 3. Lancer l'attaque
        print_section("🚀 3. Lancement de l'attaque")
        
        start_time = datetime.now()
        result = await orchestrator.run_async(session_id=session_id)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"   ✅ Attaque terminée en {duration:.2f}s")
        
        return {
            "success": True,
            "result": result,
            "duration": duration,
            "orchestrator": orchestrator,
        }
        
    except Exception as e:
        print(f"\n❌ ERREUR : {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "error": str(e),
        }
        
    finally:
        # 4. Nettoyer l'environnement
        print_section("🧹 4. Nettoyage de l'environnement")
        env.teardown()
        print("   ✅ Environnement nettoyé")


# =============================================================================
# MAIN
# =============================================================================
async def main_async(enable_api: bool = True, session_id: str = None):
    """
    Fonction principale asynchrone.
    
    Args:
        enable_api: Démarrer l'API ou non
        session_id: ID de session (généré automatiquement si None)
    """
    print_header()
    
    # Générer l'ID de session
    if session_id is None:
        session_id = random_session_id()
    print(f"🆔 Session ID : {session_id}")
    
    # Démarrer l'API si demandé
    # api_thread = None
    ws_manager = None
    
    if enable_api:
        from simulateur_attaque_ia.api.dashbord_orchestrator_router import get_ws_manager
        ws_manager = get_ws_manager()
        api_thread = start_api_in_thread()
        await asyncio.sleep(10)
        # # Enregistrer un utilisateur de test pour le dashboard
        # test_user_id = "test_user_dashboard"
        # ws_manager.register(test_user_id)
        # print(f"   👤 Utilisateur test enregistré : {test_user_id}")
    
    # Créer le callback dashboard
    print(ws_manager._users_id)
    dashboard_callback = create_dashboard_callback(ws_manager) if ws_manager else None
    
    # Exécuter l'orchestrateur
    run_result = await run_orchestrator(session_id, dashboard_callback)
    
    if not run_result["success"]:
        print_footer(False, "", "")
        return False
    
    # Récupérer les résultats
    result = run_result["result"]
    orchestrator = run_result["orchestrator"]
    state = result.get("state", {})
    report = result.get("report", {})
    duration = run_result["duration"]
    
    # Afficher les résultats
    print_result_summary(state, duration)
    
    # Sauvegarder le rapport
    report_filename = save_report(state, report)
    
    # Afficher le bilan
    has_creds = bool(state.get('ssh_brute_force_found_credentials', {}))
    has_persistence = bool(
        state.get('cron_results', {}).get('success') or
        state.get('ssh_key_results', {}).get('success')
    )
    success = has_creds or has_persistence
    
    print_footer(success, orchestrator.checkpoint_path, report_filename)
    
    return success


def main(enable_api: bool = True, session_id: str = None):
    """
    Point d'entrée principal.
    
    Args:
        enable_api: Démarrer l'API ou non (défaut: True)
        session_id: ID de session personnalisé (optionnel)
    """
    success = asyncio.run(main_async(enable_api, session_id))
    
    print("\n" + "=" * 70)
    if success:
        print("✅ TEST TERMINÉ AVEC SUCCÈS")
    else:
        print("❌ TEST ÉCHOUÉ")
    print("=" * 70 + "\n")
    
    return 0 if success else 1


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
if __name__ == "__main__":
    # Changer ces valeurs pour modifier le comportement
    ENABLE_API = True  # Mettre à False pour désactiver l'API
    CUSTOM_SESSION_ID = None  # Exemple: "ma_session_001"
    
    sys.exit(main(enable_api=ENABLE_API, session_id=CUSTOM_SESSION_ID))