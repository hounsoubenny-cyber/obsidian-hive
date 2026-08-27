#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_auto_orchestrator.py - Lance l'orchestrateur complet

Usage:
    python test_auto_orchestrator.py
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import asyncio
import json
from datetime import datetime
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.orchestrator.auto_orchestrator import AutoAttackOrchestrator
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager
from simulateur_attaque_ia.tactics.tests.environment import TestEnvironment
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from dotenv import load_dotenv
load_dotenv()
logger = get_logger()
logger.remove()
# ─── CONFIGURATION LLM ───
# 🔑 Mets tes clés dans l'env (export GROQ_API_KEY=...) plutôt qu'en dur ici,
# surtout que celles ci-dessus ont déjà été partagées dans une conversation.
LLAMA_SERVER_PATH = os.environ.get(
    "LLAMA_SERVER_PATH",
    "/home/hounsousamuel/llama-bin/llama-b9833/llama-server",
)
MODEL_NAME = "qwen2.5-3b"  # section [qwen2.5-3b] de models.ini -> Qwen2.5-3B-Instruct-Q5_K_S.gguf
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")  
result = None
orchestrator = None
async def run_orchestrator():
    global result, orchestrator
    """Lance l'orchestrateur avec environnement de test"""
    
    print("=" * 70)
    print("🔴 SHIELDIA - AUTO ATTACK ORCHESTRATOR")
    print("=" * 70)
    print(f"📅 Démarrage : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # ============================================================
    # 1. INITIALISER LE LLM
    # ============================================================
    print("🧠 0. Initialisation du LLM...")
    
    # 🔁 Ordre important : la 1ère paire de api_keys est celle utilisée par
    # défaut par run_agent()/chat() tant qu'on ne précise pas model_name.
    # Ici on met le modèle local en premier ; ajoute une 2e paire si tu veux
    # que Groq soit dispo aussi (mais il ne sera PAS pris par défaut).
    api_keys = [(MODEL_NAME, "local-fake-key")]
    if GROQ_API_KEY:
        api_keys.append(("llama-3.3-70b-versatile", GROQ_API_KEY))
    
    api_keys.reverse()
    try:
        llm = LLMManager(
            llama_server_path=LLAMA_SERVER_PATH,
            host="127.0.0.1",
            port=9001,
            api_keys=api_keys,
            sync=False,
        )
        print("   ✅ LLM initialisé")
    except Exception as e:
        print(f"   ⚠️ Erreur LLM : {e}")
        print("   ⚠️ Mode sans LLM (fallback sur logique classique)")
        llm = None
    
    # ============================================================
    # 2. CRÉER L'ENVIRONNEMENT DE TEST
    # ============================================================
    print("\n📦 1. Création de l'environnement de test...")
    
    IMAGE_NAME = "shieldai_sim_atk:v2"
    CONTAINER_NAME = "shieldai_test"
    
    env = TestEnvironment(
        image_name=IMAGE_NAME,
        container_name=CONTAINER_NAME,
    )
    
    try:
        ip = env.setup()
        print(f"   ✅ Container démarré : IP = {ip}")
        print()
        
        # ============================================================
        # 3. CRÉER L'ORCHESTRATEUR
        # ============================================================
        print("🎮 2. Initialisation de l'orchestrateur...")
        
        dock = DockerManager()
        dock.container = env.container
        
        orchestrator = AutoAttackOrchestrator(
            llm=llm,
            docker_manager=dock,
            checkpoint_path="test_orchestrator_checkpoints",
            debug=True,
            use_llm=llm is not None
        )
        
        print("   ✅ Orchestrateur prêt")
        print()
        
        # ============================================================
        # 4. LANCER L'ATTAQUE
        # ============================================================
        print("🚀 3. Lancement de l'attaque...")
        print("-" * 70)
        
        start_time = datetime.now()
        result = await orchestrator.run_async()
        end_time = datetime.now()
        
        print("-" * 70)
        print(f"   ✅ Attaque terminée en {(end_time - start_time).total_seconds():.2f}s")
        print()
        
        # ============================================================
        # 5. AFFICHER LES RÉSULTATS
        # ============================================================
        print("📊 4. RÉSULTATS DE L'ATTAQUE")
        print("=" * 70)
        
        state = result.get("state", {})
        report = result.get("report", {})
        # Infos générales
        print(f"\n🎯 Cible : {state.get('ip', 'inconnue')}")
        print(f"📡 Ports ouverts : {state.get('open_ports', [])}")
        
        # Credentials trouvés
        ssh_creds = state.get('ssh_brute_force_found_credentials', {})
        if ssh_creds:
            print(f"\n🔑 Credentials SSH trouvés :")
            for port, creds in ssh_creds.items():
                for cred in creds:
                    print(f"   - port {port} : {cred.get('username')}:{cred.get('password')}")
        else:
            print(f"\n🔑 Aucun credential SSH trouvé")
        
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
                for err in errors:
                    print(f"   - {step} : {err[:100]}...")
        
        # ============================================================
        # 6. SAUVEGARDER LE RAPPORT
        # ============================================================
        print("\n💾 5. Sauvegarde du rapport...")
        
        report_filename = f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "state": state,
                "report": report
            }, f, indent=2, default=str)
        
        print(f"   ✅ Rapport sauvegardé : {report_filename}")
        
        # ============================================================
        # 7. BILAN FINAL
        # ============================================================
        print("\n" + "=" * 70)
        print("🏁 BILAN FINAL")
        print("=" * 70)
        
        # Vérifier si l'attaque a réussi
        has_creds = len(ssh_creds) > 0
        has_persistence = bool(state.get('cron_results', {}).get('success')) or bool(state.get('ssh_key_results', {}).get('success'))
        
        if has_creds or has_persistence:
            print("🎉 L'ORCHESTRATEUR A FONCTIONNÉ !")
            if has_creds:
                print("   ✅ Des credentials ont été trouvés")
            if has_persistence:
                print("   ✅ Une persistence a été installée")
        else:
            print("⚠️ L'orchestrateur a tourné mais n'a rien trouvé")
            print("   (peut être normal selon la cible)")
        
        print(f"\n📁 Checkpoints sauvegardés dans : {orchestrator.checkpoint_path}")
        print(f"📄 Rapport JSON : {report_filename}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERREUR : {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Nettoyage
        print("\n🧹 6. Nettoyage...")
        if llm:
            llm.stop_server()
        env.teardown()
        print("   ✅ Environnement nettoyé")


def main():
    """Point d'entrée principal"""
    success = asyncio.run(run_orchestrator())
    
    print("\n" + "=" * 70)
    if success:
        print("✅ TEST TERMINÉ AVEC SUCCÈS")
    else:
        print("❌ TEST ÉCHOUÉ")
    print("=" * 70)
    
    return 0 if success else 1


if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    sys.exit(main())