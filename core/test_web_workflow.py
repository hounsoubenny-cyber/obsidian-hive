#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 21 10:07:57 2026

@author: hounsousamuel
"""

"""
Test de WebWorkflow avec Alex dans la loop (analyze_with_alex).

⚠️ CE TEST HACKE LE SCAN : on ne lance pas un vrai scan (trop long, et ce
n'est pas ce qu'on veut valider ici). À la place, on construit un faux
ScannerResult dont phases_result["report_generation"] contient un finding
bidon, sur un dossier de code de test (agents/analyst/test_alex_fixture).

Tout le reste est réel : c'est le vrai WebWorkflow.build_prompt() qui
construit le prompt à partir de ce faux résultat, le vrai
analyze_with_alex() qui appelle Alex et persiste le rapport via
ReportManager. Seule l'étape scan() elle-même est court-circuitée.

Idéalement, à terme, ce sera le vrai rapport du scanner ici plutôt qu'un
faux — mais ça valide déjà qu'Alex est bien câblé dans la loop de
WebWorkflow depuis son ajout récent.

⚠️ AVANT DE LANCER, adapte les 3 TODO ci-dessous à ta config réelle
(mêmes valeurs que dans agents/analyst/test_alex.py).
"""

import os
import json
import shutil
import asyncio
import tempfile

from obsidian_hive.agents.config import OBSIDIAN_SANDBOX_ROOTS
from obsidian_hive.core.assets.asset_types import WebAsset, Priority, Source
from obsidian_hive.core.assets.workflows.web_workflow import WebWorkflow
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.managers.report_manager import ReportManager
from scanner_ia.base_class.main_scanner_base_class import ScannerResult

# =============================================================================
# CONFIG — adapte ces 3 lignes à ton setup réel (identique à test_alex.py)
# =============================================================================
MODEL_NAME = "qwen3.5-4b"                 # TODO: ton vrai nom de modèle chez toi
LOCAL_MODEL_API_KEY = "local-fake-key"    # TODO: cohérent avec ton api_key_client_mapper
LLAMA_SERVER = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"  # TODO
FIXTURE_SOURCE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "agents", "analyst", "test_alex_fixture"
)


async def main():
    # -------------------------------------------------------------------
    # 1. Copier le faux projet vulnérable dans le sandbox réel (comme le
    #    ferait le vrai flux de création d'un WebAsset avec fix_allowed=True)
    # -------------------------------------------------------------------
    test_asset_id = "test-web-workflow-alex-001"
    dest_dir = os.path.join(OBSIDIAN_SANDBOX_ROOTS[0], test_asset_id)

    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    shutil.copytree(FIXTURE_SOURCE_DIR, dest_dir)
    print(f"📁 Code de test copié dans : {dest_dir}\n")

    # -------------------------------------------------------------------
    # 2. Construire LLMManager + ReportManager (DB temporaire, comme
    #    test_engine.py) — on veut vérifier que la persistance marche
    #    aussi, pas juste l'appel à Alex.
    # -------------------------------------------------------------------
    llama_server_path = os.environ.get("LLAMA_SERVER_PATH", LLAMA_SERVER)
    llm_manager = LLMManager(
        api_keys=[(MODEL_NAME, LOCAL_MODEL_API_KEY)],
        llama_server_path=llama_server_path,
        port=8000,
        sync=False,
    )

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    report_manager = ReportManager(db_url=f"sqlite+aiosqlite:///{db_path}")
    await report_manager.init_db()

    # -------------------------------------------------------------------
    # 3. Construire l'asset — fix_allowed=True + source_code_dir pointés
    #    sur le code copié à l'étape 1, pour que build_prompt() dise à
    #    Alex où chercher le code (branche "code source disponible").
    # -------------------------------------------------------------------
    asset = WebAsset(
        id=test_asset_id,
        name="Test WebWorkflow + Alex",
        url="http://localhost:5000/login",
        conf_content="{}",  # cf. fix précédent — garde les défauts de shieldai_scanner.config.json5
        fix_allowed=True,
        source_code_dir=dest_dir,
        priority=Priority.HIGH,
    )

    workflow = WebWorkflow(
        asset=asset,
        llm_manager=llm_manager,
        report_manager=report_manager,
    )

    # -------------------------------------------------------------------
    # 4. LE HACK : on fabrique un faux ScannerResult au lieu de lancer un
    #    vrai scan(). Le contenu du finding reprend le mock déjà utilisé
    #    pour tester Alex seul (agents/analyst/test_alex_fixture).
    # -------------------------------------------------------------------
    with open(os.path.join(FIXTURE_SOURCE_DIR, "mock_scan_result.json")) as f:
        fake_finding = json.load(f)

    fake_scan_result = ScannerResult()
    fake_scan_result.phases_result = {"report_generation": fake_finding}
    fake_scan_result.scan_id = "fake-scan-for-webworkflow-test"

    # -------------------------------------------------------------------
    # 5. Appeler le vrai analyze_with_alex() de WebWorkflow avec ce faux
    #    résultat — c'est exactement l'étape ajoutée récemment dans la loop.
    # -------------------------------------------------------------------
    print("🤖 WebWorkflow.analyze_with_alex() en cours...\n")
    alex_report = await workflow.analyze_with_alex(scan_result=fake_scan_result)

    if not alex_report:
        print("❌ analyze_with_alex a renvoyé None/vide — voir les logs 'web_workflow' ci-dessus.")
        return

    print("=" * 60)
    print("📋 RAPPORT D'ALEX (via WebWorkflow)")
    print("=" * 60)
    print(f"Sévérité      : {alex_report.get('severity')}")
    print(f"Résumé        : {alex_report.get('summary')}")
    print(f"Fix proposé ? : {alex_report.get('have_proposed_fix')}")

    fix = alex_report.get("fix_output")
    if fix:
        print("\n" + "-" * 60)
        print("🔧 DÉTAILS DU FIX")
        print("-" * 60)
        for fixed_file in fix.get("files", []):
            print(f"\n📄 Fichier : {fixed_file.get('path')} ({fixed_file.get('language')})")
            print(f"   Appliqué : {fixed_file.get('fix_applied_tofile')}")
            if fixed_file.get("diff"):
                print(f"\n   Diff :\n{fixed_file.get('diff')}")

    # -------------------------------------------------------------------
    # 6. Vérifier que le rapport a bien été persisté via ReportManager
    #    (is_alert / read_at inclus — voir les changements récents).
    # -------------------------------------------------------------------
    reports = await report_manager.list_by_filter(asset_id=asset.id, limit=10)
    print("\n" + "=" * 60)
    print(f"💾 Rapports en DB pour cet asset : {len(reports)}")
    if reports:
        last = reports[-1]
        print(f"   is_alert={last.is_alert}  read_at={last.read_at}  severity={last.severity}")
    print("=" * 60)

    os.unlink(db_path)


if __name__ == "__main__":
    asyncio.run(main())