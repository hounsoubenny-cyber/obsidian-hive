#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jul  8 23:59:04 2026

@author: hounsousamuel
"""

"""
Test de validation d'Alex (Analyst) — scénario SQLi complet.

Ce script :
1. Copie le faux projet vulnérable dans le sandbox configuré (OBSIDIAN_SANDBOX_ROOTS)
2. Construit Alex avec un LLMManager pointant sur ton modèle local
3. Lui donne le faux résultat de scan + le chemin où chercher le code
4. Affiche le rapport produit, en particulier le fix proposé

⚠️ AVANT DE LANCER, adapte les 3 endroits marqués TODO ci-dessous à ta config réelle.
"""

import os
import json
import shutil
import asyncio

from obsidian_hive.agents.config import OBSIDIAN_SANDBOX_ROOTS
from obsidian_hive.agents.analyst.agent import Analyst, NoReportProducedError
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager

# =============================================================================
# CONFIG — adapte ces 3 lignes à ton setup réel
# =============================================================================
MODEL_NAME = "qwen3.5-4b"          # TODO: ton vrai nom de modèle chez toi
LOCAL_MODEL_API_KEY = "local-fake-key"  # TODO: cohérent avec ton api_key_client_mapper
FIXTURE_SOURCE_DIR = os.path.join(os.path.dirname(__file__), "test_alex_fixture")


async def main():
    # -------------------------------------------------------------------
    # 1. Copier le faux projet dans le sandbox réel (comme le ferait
    #    handle_web_asset_creating en vrai, mais en manuel pour ce test)
    # -------------------------------------------------------------------
    test_asset_id = "test-alex-sqli-001"
    dest_dir = os.path.join(OBSIDIAN_SANDBOX_ROOTS[0], test_asset_id)

    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    shutil.copytree(FIXTURE_SOURCE_DIR, dest_dir)
    print(f"📁 Code de test copié dans : {dest_dir}\n")

    # -------------------------------------------------------------------
    # 2. Construire Alex
    # -------------------------------------------------------------------
    # TODO: adapte l'instanciation de LLMManager à ta vraie signature
    LLAMA_SERVER  = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
    llama_server_path = os.environ.get("LLAMA_SERVER_PATH", LLAMA_SERVER) 
    llm_manager = LLMManager(api_keys=[(MODEL_NAME, LOCAL_MODEL_API_KEY)], llama_server_path=llama_server_path, port=8000, sync=False)

    alex = Analyst(llm_manager=llm_manager, model_name=MODEL_NAME)

    # -------------------------------------------------------------------
    # 3. Charger le faux résultat de scan + indiquer où chercher le code
    # -------------------------------------------------------------------
    with open(os.path.join(FIXTURE_SOURCE_DIR, "mock_scan_result.json")) as f:
        scan_result = json.load(f)

    content = (
        f"Résultat brut du Scanner :\n{json.dumps(scan_result, indent=2)}\n\n"
        f"Le code source complet de cet asset est disponible dans le dossier : "
        f"{dest_dir}\n"
        f"Utilise search_pattern/read_file pour localiser et examiner le code "
        f"concerné avant de conclure."
    )

    # -------------------------------------------------------------------
    # 4. Lancer l'analyse
    # -------------------------------------------------------------------
    print("🤖 Alex analyse...\n")
    try:
        result = await alex.analyze(content=content, source="scanner")
    except NoReportProducedError as e:
        print(f"❌ Alex n'a produit aucun rapport : {e}")
        return

    report = result.report

    print("=" * 60)
    print("📋 RAPPORT D'ALEX")
    print("=" * 60)
    print(f"Sévérité      : {report.get('severity')}")
    print(f"Résumé        : {report.get('summary')}")
    print(f"\nExplication technique :\n{report.get('technical_explanation')}")
    print(f"\nExplication simple :\n{report.get('natural_explanation')}")
    print(f"\nFix proposé ? : {report.get('have_proposed_fix')}")

    fix = report.get("fix_output")
    if fix:
        print("\n" + "-" * 60)
        print("🔧 DÉTAILS DU FIX")
        print("-" * 60)
        for f in fix.get("files", []):
            print(f"\n📄 Fichier : {f.get('path')} ({f.get('language')})")
            print(f"   Méthode : {f.get('method')}")
            print(f"   Justification : {f.get('justification')}")
            if f.get("diff"):
                print(f"\n   Diff :\n{f.get('diff')}")
        print(f"\nAppliqué automatiquement ? {fix.get('applied')}")
        print(f"Risques notés : {fix.get('risk_notes')}")
        print(f"Tests recommandés : {fix.get('tests_recommended')}")

    print("\n" + "=" * 60)
    print(f"✅ Itérations utilisées : {result.raw.get('iterations')}")
    print(f"⏱️  Temps total : {result.raw.get('total_time'):.2f}s")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
    # pass