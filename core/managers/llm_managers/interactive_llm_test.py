#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🧪 TEST INTERACTIF — LLMManager (ShieldAI)
============================================
Pas un pytest, un vrai bac à sable pour jouer avec la classe à la main.

Lancement:
    python interactive_test.py

Prérequis .env:
    GROQ_API_KEY_1=gsk_...
    GROQ_API_KEY_2=gsk_...
    GROQ_API_KEY_3=gsk_...
"""
import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))

import json
import asyncio
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Adapte à ton arborescence réelle
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager  # noqa

GROQ_MODEL = "llama-3.3-70b-versatile"


def build_manager(llama_server_path: str) -> LLMManager:
    keys = [os.environ.get(f"GROQ_API_KEY_{i}") for i in (1, 2, 3)]
    if not all(keys):
        raise RuntimeError("❌ GROQ_API_KEY_1/2/3 manquantes dans .env")

    print("🔧 Construction du LLMManager (validation fail-fast des clés)...")
    mgr = LLMManager(
        llama_server_path=llama_server_path,
        port=9999,
        api_keys=[(GROQ_MODEL, k) for k in keys] + [("qwen3.5-4b", "local-fake-key")],
        sync=False,
    )
    print("✅ Manager prêt, 3 clés validées, modèle:", GROQ_MODEL)
    return mgr


# ─────────────────────────────────────────────────────────────
# 🛠️ FAUX OUTILS — thème cybersécurité pour rester dans l'esprit ShieldAI
# ─────────────────────────────────────────────────────────────

def tool_calculer(expression: str) -> str:
    """Calcule le résultat d'une expression arithmétique simple.

    Args:
        expression: Expression mathématique à évaluer, ex: (12+8)*3
    """
    try:
        # eval restreint, juste pour la démo — jamais faire ça sur de l'input non fiable en prod
        allowed = "0123456789+-*/(). "
        if not all(c in allowed for c in expression):
            return "❌ Expression invalide (caractères non autorisés)"
        return str(eval(expression, {"__builtins__": {}}, {}))
    except Exception as e:
        return f"❌ Erreur de calcul: {e}"


def tool_scan_ports_fake(host: str) -> str:
    """Simule un scan de ports ouverts sur un host (démo, aucun vrai scan réseau).

    Args:
        host: Adresse IP ou nom d'hôte à scanner, ex: 192.168.1.1
    """
    fake_ports = random.sample([21, 22, 23, 25, 80, 443, 3306, 8080], k=random.randint(2, 4))
    return json.dumps({"host": host, "open_ports": sorted(fake_ports), "note": "SIMULATION — pas un vrai scan"})


def tool_heure_actuelle() -> str:
    """Retourne l'heure actuelle."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Nouveau format attendu par run_agent: liste de callables, pas de dicts.
# build_tools() (tool_builder.py) génère le schéma provider-specific via
# introspection de signature + parsing du docstring (Args:).
TOOLS_LIST = [tool_calculer, tool_scan_ports_fake, tool_heure_actuelle]

# tool_mapping doit être clé sur func.__name__ (c'est ce que run_agent vérifie
# et ce que le nom généré dans le schéma par build_tools contient).
TOOL_MAPPING = {
    "tool_calculer": tool_calculer,
    "tool_scan_ports_fake": tool_scan_ports_fake,
    "tool_heure_actuelle": tool_heure_actuelle,
}


# ─────────────────────────────────────────────────────────────
# 🎧 CALLBACKS — pour voir en direct ce qui se passe dans run_agent
# ─────────────────────────────────────────────────────────────

async def on_step(iteration, msgs, response):
    print(f"   🔄 itération {iteration}")


async def on_tool_call(tool_calls):
    for tc in tool_calls:
        name = tc.get("function", {}).get("name", "?")
        args = tc.get("function", {}).get("arguments", "{}")
        print(f"   🛠️  appel outil: {name}({args})")


async def on_tool_exec_after(name, args, result):
    print(f"   ✅ résultat {name}: {result}")


async def on_tool_exec_error(name, args, error):
    print(f"   💥 erreur outil {name}: {error}")


async def on_retry(attempt, max_retries, error):
    print(f"   ⏳ retry {attempt}/{max_retries} — {error}")


async def on_finish(final, total_time, iterations, tool_calls_count):
    print(f"   🏁 fini en {total_time:.2f}s, {iterations} itération(s), {tool_calls_count} outil(s) appelé(s)")


# ─────────────────────────────────────────────────────────────
# 1️⃣ TEST — appel simple
# ─────────────────────────────────────────────────────────────

async def test_simple_call(mgr: LLMManager):
    print("\n" + "=" * 60)
    print("1️⃣  TEST APPEL SIMPLE")
    print("=" * 60)
    result = await mgr.call(
        prompt="Explique en une phrase ce qu'est un reverse shell.",
        system="Tu es un expert cybersécurité, réponds en une phrase.",
        max_tokens=100,
        temperature=0.3,
    )
    print(f"📤 Succès: {result['success']}")
    print(f"📥 Réponse: {result['response']}")
    print(f"⏱️  Temps: {result['total_time']:.2f}s")


# ─────────────────────────────────────────────────────────────
# 2️⃣ TEST — tool calling
# ─────────────────────────────────────────────────────────────

async def test_tool_calling(mgr: LLMManager):
    print("\n" + "=" * 60)
    print("2️⃣  TEST TOOL CALLING 🛠️")
    print("=" * 60)
    result = await mgr.run_agent(
        model_name=GROQ_MODEL,
        system=(
            "Tu es un assistant qui utilise les outils disponibles quand c'est pertinent. "
            "Réponds en français, de façon concise."
        ),
        user=(
            "Combien font (128 + 47) * 2 ? Ensuite, scanne les ports de 10.0.0.5, "
            "et donne-moi l'heure actuelle."
        ),
        tools=TOOLS_LIST,
        tool_mapping=TOOL_MAPPING,
        max_iter=6,
        temperature=0.0,
        on_step=on_step,
        on_tool_call=on_tool_call,
        on_tool_exec_after=on_tool_exec_after,
        on_tool_exec_error=on_tool_exec_error,
        on_retry=on_retry,
        on_finish=on_finish,
    )
    print(f"\n📤 Succès: {result['success']}")
    print(f"📥 Réponse finale: {result['response']}")
    print(f"🔢 Outils appelés: {result['tool_calls']}")


# ─────────────────────────────────────────────────────────────
# 3️⃣ TEST — casse-le exprès (edge cases)
# ─────────────────────────────────────────────────────────────

async def test_essaie_de_casser(mgr: LLMManager):
    print("\n" + "=" * 60)
    print("3️⃣  ON ESSAIE DE CASSER LE TRUC 😈")
    print("=" * 60)

    cases = [
        ("Prompt vide", dict(prompt="", max_tokens=10)),
        ("max_tokens négatif", dict(prompt="salut", max_tokens=-5)),
        ("temperature hors range", dict(prompt="salut", temperature=5.0, max_tokens=10)),
        ("prompt énorme (10k caractères)", dict(prompt="A" * 10_000, max_tokens=10)),
        ("clé API bidon en argument", dict(prompt="salut", api_key="gsk_totalement_fausse", max_tokens=10)),
    ]

    for label, kwargs in cases:
        print(f"\n🧨 Cas: {label}")
        try:
            result = await mgr.call(**kwargs)
            status = "✅ succès" if result.get("success") else f"⚠️ échec propre: {result.get('error')}"
            print(f"   → {status}")
        except Exception as e:
            print(f"   → 💥 exception non catchée: {type(e).__name__}: {e}")
            print("      (si ça arrive ici, c'est un bug — l'appelant ne devrait jamais voir une exception brute)")


# ─────────────────────────────────────────────────────────────
# 4️⃣ MODE INTERACTIF — toi vs le manager
# ─────────────────────────────────────────────────────────────

async def mode_interactif(mgr: LLMManager):
    print("\n" + "=" * 60)
    print("4️⃣  MODE INTERACTIF 😎 — essaie de le faire buguer")
    print("=" * 60)
    print("Commandes spéciales:")
    print("  /reset          → vide l'historique")
    print("  /history        → affiche l'historique brut")
    print("  /models         → liste les modèles dispo (pool système)")
    print("  /tools <msg>    → envoie <msg> avec les outils activés")
    print("  /key <clé> <msg>→ envoie <msg> avec une clé API explicite")
    print("  /quit           → quitter")
    print("-" * 60)

    while True:
        try:
            user_input = input("\n👤 Toi: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n👋 Bye")
            break

        if not user_input:
            continue

        if user_input == "/quit":
            print("👋 Bye")
            break

        if user_input == "/reset":
            mgr.clear_history()
            print("🧹 Historique vidé")
            continue

        if user_input == "/history":
            print(json.dumps(mgr.get_history(), indent=2, ensure_ascii=False))
            continue

        if user_input == "/models":
            models = await mgr.list_available_models()
            print(f"📋 {len(models)} modèles: {models}")
            continue

        if user_input.startswith("/tools "):
            msg = user_input[len("/tools "):]
            result = await mgr.run_agent(
                model_name=GROQ_MODEL,
                user=msg,
                tools=TOOLS_LIST,
                tool_mapping=TOOL_MAPPING,
                on_tool_call=on_tool_call,
                on_tool_exec_after=on_tool_exec_after,
                max_iter=5,
            )
            print(f"🤖 Bot: {result['response']}")
            continue

        if user_input.startswith("/key "):
            _, rest = user_input.split(" ", 1)
            key, msg = rest.split(" ", 1)
            result = await mgr.run_agent(model_name=GROQ_MODEL, api_key=key, user=msg, max_tokens=200)
            status = "✅" if result["success"] else f"❌ {result.get('error')}"
            print(f"🤖 Bot [{status}]: {result.get('response')}")
            continue

        # chat normal, avec historique
        result = await mgr.chat(prompt=user_input, model_name=GROQ_MODEL, max_tokens=500)
        if result.get("success"):
            print(f"🤖 Bot: {result['response']}")
        else:
            print(f"💥 Erreur: {result.get('error')}")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

async def main():
    LLAMA_SERVER  = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
    llama_server_path = os.environ.get("LLAMA_SERVER_PATH", LLAMA_SERVER)  # placeholder si pas de local
    mgr = build_manager(llama_server_path)

    try:
        await test_simple_call(mgr)
        await test_tool_calling(mgr)
        await test_essaie_de_casser(mgr)
        await mode_interactif(mgr)
    finally:
        if mgr._server_process is not None:
            mgr.stop_server()


if __name__ == "__main__":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(
            asyncio.new_event_loop()
        )
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(main())