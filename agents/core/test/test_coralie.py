#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 16:20:00 2026

@author: hounsousamuel
"""


"""
test_coralie_chat.py — Chat interactif en streaming avec Coralie, sur une DB
SQLite jetable pré-remplie avec des assets/rapports factices.

⚠️ Note sur "en mémoire" : on utilise un fichier SQLite temporaire plutôt
qu'un vrai `sqlite+aiosqlite:///:memory:`. En cause : AssetManager/ReportManager
appellent `create_async_engine(db_url)` sans `poolclass=StaticPool` — avec un
`:memory:` littéral, chaque connexion piochée dans le pool peut ouvrir une
base VIDE différente, donc les données insérées à la seed pourraient
disparaître avant même le premier message. Un fichier temporaire supprimé en
fin de script donne le même résultat pratique (rien ne persiste après coup)
sans ce risque. Si tu préfères un vrai :memory: partagé, il faudrait patcher
temporairement create_async_engine avec poolclass=StaticPool — dis-le-moi.

Usage:
    python test_coralie_chat.py
"""

import os
import asyncio
import tempfile
import shutil

# --- Guard nest_asyncio, même pattern que core/engine.py::_test() ---
try:
    asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
import nest_asyncio
nest_asyncio.apply()

from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.assets.asset_types import WebAsset, Priority
from obsidian_hive.agents.core.agent import Coralie


# =============================================================================
# ⚠️ À ADAPTER — config de ton LLMManager local. Contrairement aux managers
# DB ci-dessous, ça ne se fake pas : un vrai serveur llama-server est démarré.
# =============================================================================
LLAMA_SERVER  = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
DEFAULT_MODEL_NAME = "ornith1.0-9b"
LLAMA_SERVER_PATH = os.environ.get("LLAMA_SERVER_PATH", LLAMA_SERVER)
MODELS_PRESET = os.environ.get("MODELS_PRESET")
MODEL_NAME = os.environ.get("CORALIE_MODEL", DEFAULT_MODEL_NAME)
API_KEYS = [(MODEL_NAME, os.environ.get("LLAMA_API_KEY", "local-dummy-key"))]
CORALIE_PORT = int(os.environ.get("CORALIE_LLAMA_PORT", "8090"))
SHOW_REASONING = False
PROVIDER = "mistral"
MODEL_NAME = "mistral-small-latest"
LOCAL_API_KEY = "8HrfCnSQtoG9mLTcPiH6wBqClmlSotXh"
API_KEYS = [(MODEL_NAME, PROVIDER, LOCAL_API_KEY)]
# =============================================================================
# Les callbacks
# =============================================================================
async def on_step(iteration: int, messages: list, response) -> None:
    print(f"\n--- [step {iteration}] --------------------------------------------")


async def on_tool_call(tool_calls: list) -> None:
    for tc in tool_calls:
        func = tc.get("function", {})
        name = func.get("name", "?")
        args_preview = func.get("arguments", "")
        if name == "create_report":
            print(f"  🔧 tool_call COMPLET: {args_preview}")  # 🎯 pas de troncature ici
        else:
            if len(args_preview) > 200:
                args_preview = args_preview[:200] + "…"
            print(f"  🔧 tool_call: {name}({args_preview})")


async def on_tool_exec_after(name: str, args: dict, result, call_id) -> None:
    if isinstance(result, dict) and "diff" in result and result["diff"]:
        print(f"  ✅ {name} -> diff calculé ({len(result['diff'].splitlines())} lignes)")
    else:
        preview = str(result)
        if len(preview) > 200:
            preview = preview[:200] + "…"
        print(f"  ✅ {name} -> {preview}")


async def on_tool_exec_error(name: str, args: dict, error: Exception, call_id) -> None:
    print(f"  ❌ {name} a échoué : {error!r}")

_reasoning_shown = {"done": False}
first = True

async def on_stream_start(iteration, model_name):
    global first
    _reasoning_shown["done"] = False
    first = True
    print(f"\n🤖 Bot (itération {iteration}, modèle {model_name}): ", end="", flush=True)

async def on_stream_token(text, iteration):
    global first
    # Affiché caractère par caractère au fur et à mesure -> c'est ÇA le streaming
    if first and  _reasoning_shown["done"]:
        print("\n\n  🧠 Fin raisoennement\n")
        first = False
    print(text, end="", flush=True)


async def on_stream_reasoning_token(text, iteration):
    # if SHOW_REASONING:
    if not _reasoning_shown["done"]:
        print("\n   🧠 [raisonnement] ", end="", flush=True)
        _reasoning_shown["done"] = True
    print(text, end="", flush=True)


async def on_stream_tool_call_delta(delta, iteration):
    # On ne spam pas la console à chaque fragment de JSON, juste un point
    # de progression discret, pour voir que ça arrive petit bout par petit bout.
    if delta.get("name"):
        print("A appelé: ", f"{delta.get('name')}", end="", flush=True)
    print(".", end="", flush=True)


async def on_stream_message(message_dict, iteration):
    # Le message complet reconstitué, juste avant que run_agent ne décide
    # quoi en faire (réponse finale ou exécution de tool).
    if message_dict.get("tool_calls"):
        print("\n\n")  # saut de ligne propre avant les logs de tool calling



async def seed_fake_data(engine: ObsidianEngine, report_manager: ReportManager):
    """
    Insère 2 assets et 3 rapports factices directement en DB (sans passer
    par engine.add_asset/workflow, pour éviter un vrai tentative de scan sur
    des URLs qui n'existent pas). Retourne les 2 AssetItem créés (pour avoir
    leurs .id sous la main).
    """
    asset1 = WebAsset(
        name="Site Vitrine",
        url="https://vitrine.example.com",
        priority=Priority.HIGH,
        tags=["prod", "vitrine"],
        conf_content=""
    )
    asset2 = WebAsset(
        name="API Interne",
        url="https://api-interne.example.local",
        priority=Priority.CRITICAL,
        tags=["prod", "api", "critique"],
        conf_content=""
    )

    await engine.asset_manager.add(asset1)
    await engine.asset_manager.add(asset2)

    await report_manager.add_report(
        asset_id=asset1.id,
        source="scanner_web",
        content="Résultat brut du scan XSS sur /contact.php",
        report={
            "severity": "medium",
            "summary": "XSS réfléchi sur le formulaire de contact",
            "technical_explanation": (
                "Le paramètre 'message' n'est pas échappé avant réinjection "
                "dans le HTML de la page de confirmation."
            ),
            "natural_explanation": (
                "Un attaquant pourrait injecter du code malveillant via le "
                "formulaire de contact du site."
            ),
            "have_proposed_fix": False,
        },
    )
    await report_manager.add_report(
        asset_id=asset2.id,
        source="ids_ips",
        content="Pic de requêtes anormal détecté sur /api/login",
        report={
            "severity": "critical",
            "summary": "Tentative de brute-force sur /api/login",
            "technical_explanation": (
                "230 tentatives de connexion en 40 secondes depuis 3 IPs "
                "différentes, toutes ciblant le même compte admin."
            ),
            "natural_explanation": (
                "Quelqu'un essaie de deviner un mot de passe en boucle sur "
                "l'API interne."
            ),
            "have_proposed_fix": False,
        },
    )
    await report_manager.add_report(
        asset_id=asset2.id,
        source="ids_ips",
        content="Nouvelle vague de tentatives 10 minutes après la première",
        report={
            "severity": "high",
            "summary": "Deuxième vague de brute-force sur /api/login",
            "technical_explanation": (
                "Nouvelle vague depuis 5 IPs différentes, pattern cohérent "
                "avec la première vague détectée 10 minutes plus tôt."
            ),
            "natural_explanation": (
                "Ça ressemble à une attaque coordonnée plutôt qu'à un pic "
                "isolé — même cible, pattern répété."
            ),
            "have_proposed_fix": False,
        },
    )

    print("✅ Données factices : 2 assets, 3 rapports")
    print(f"   - {asset1.name} ({asset1.id})")
    print(f"   - {asset2.name} ({asset2.id})")
    return asset1, asset2


# def on_token(token: str, iteration: int):
#     """Callback de streaming : affiche chaque token au fur et à mesure."""
#     print(token, end="", flush=True)


async def main():
    tmp_dir = tempfile.mkdtemp(prefix="coralie_test_")
    db_path = os.path.join(tmp_dir, "test.db")
    db_url = f"sqlite+aiosqlite:///{db_path}"
    print(f"📁 DB de test (jetable) : {db_url}")
    from obsidian_hive.agents.shared.human_in_loop import InputConfirmer
    confirmer = InputConfirmer()
    job_manager = JobManager(db_url=db_url)
    report_manager = ReportManager(db_url=db_url)

    try:
        async with ObsidianEngine(db_url=db_url, debug=False, do_silence=True) as engine:
            asset1, asset2 = await seed_fake_data(engine, report_manager)

            llm_manager = LLMManager(
                llama_server_path=LLAMA_SERVER_PATH,
                port=CORALIE_PORT,
                models_preset=MODELS_PRESET,
                api_keys=API_KEYS,
            )

            coralie = Coralie(
                llm_manager=llm_manager,
                job_manager=job_manager,
                engine=engine,
                report_manager=report_manager,
                model_name=MODEL_NAME,
                confirmer=confirmer
            )

            print("\n" + "=" * 60)
            print("💬 Chat avec Coralie (stream=True) — 'exit' pour quitter")
            print("=" * 60 + "\n")

            history: list[dict] = []

            while True:
                try:
                    user_input = input("\n🧑 Toi : ").strip()
                except (EOFError, KeyboardInterrupt):
                    break

                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit", "q"):
                    break

                # print("🤖 Coralie : ", end="", flush=True)
                result = await coralie.chat(
                    user_input,
                    history=history,
                    stream=True,
                    show_reasoning=SHOW_REASONING,
                    on_step=on_step,
                    on_tool_call=on_tool_call,
                    on_tool_exec_after=on_tool_exec_after,
                    on_tool_exec_error=on_tool_exec_error,
                    timeout=3600,
                    temperature=0.6,
                    on_stream_start=on_stream_start,
                    on_stream_token=on_stream_token,
                    on_stream_reasoning_token=on_stream_reasoning_token,
                    on_stream_tool_call_delta=on_stream_tool_call_delta,
                    on_stream_message=on_stream_message,
                    
                )
                print()  # nouvelle ligne après le stream

                if result.all_tools:
                    print(f"   🔧 tools utilisés : {', '.join(result.all_tools)}")

                if result.response_text:
                    history.append({"role": "user", "content": user_input})
                    history.append({"role": "assistant", "content": result.response_text})
                else:
                    print("   ⚠️ Coralie n'a renvoyé aucun texte pour ce tour "
                          "(voir logs) — tour non ajouté à l'historique.")

            print("\n👋 Fin de la session.")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"🧹 DB de test supprimée ({tmp_dir})")


if __name__ == "__main__":
    asyncio.run(main())