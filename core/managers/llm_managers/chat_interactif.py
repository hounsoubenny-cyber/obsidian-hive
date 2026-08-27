#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 10 01:05:47 2026

@author: hounsousamuel
"""

"""
🧪 CHAT INTERACTIF — LLMManager (Obsidian Hive)
=================================================
Bac à sable pour discuter avec un modèle (local ou cloud), avec tools
et suivi complet de ce qui se passe à chaque étape via les callbacks.

Lancement:
    python chat_interactif.py

Modifie juste la section CONFIG juste en dessous pour changer de modèle.
"""

import os
import sys
import json
import time
import base64
import random
import hashlib
import asyncio
from datetime import datetime

from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager

# =============================================================================
# 🎛️  CONFIG — modifie juste ça pour changer de modèle/clé
# =============================================================================
LLAMA_SERVER_PATH = os.environ.get(
    "LLAMA_SERVER_PATH",
    "/home/hounsousamuel/llama-bin/llama-b9833/llama-server",
)
MODELS_PRESET_PATH = os.environ.get(
    "MODELS_PRESET_PATH",
    os.path.join(os.path.dirname(__file__), "models.ini"),
)
HOST = "127.0.0.1"
PORT = 9999

MODEL_NAME = "ornith1.0-9b"
MODEL_NAME = "qwen3.5-4b"       # 🎯 change ici pour tester un autre preset (ex: "ornith-1.0-9b")
API_KEY = "local-fake-key"      # 🎯 clé associée à ce modèle (locale ou vraie clé cloud)
TEMPERATURE = 0.6               # 🎯 0.6 recommandé pour les modèles "reasoning" (Ornith...)
MAX_TOKENS = 2048
SHOW_REASONING = True           # affiche le <think>/reasoning_content si le modèle en produit
# =============================================================================


# =============================================================================
# 🛠️ TOOLS — thème cybersécurité, pour rester dans l'esprit du projet
# =============================================================================

def tool_calculer(expression: str) -> str:
    """Calcule le résultat d'une expression arithmétique simple.

    Args:
        expression: Expression mathématique à évaluer, ex: (12+8)*3
    """
    try:
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


def tool_verifier_force_mdp(password: str) -> str:
    """Évalue la force d'un mot de passe (règles simples, pas un vrai audit).

    Args:
        password: Le mot de passe à évaluer
    """
    score = 0
    reasons = []
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        reasons.append("trop court (< 8 caractères)")

    if any(c.isupper() for c in password):
        score += 1
    else:
        reasons.append("pas de majuscule")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        reasons.append("pas de chiffre")
    if any(not c.isalnum() for c in password):
        score += 1
    else:
        reasons.append("pas de caractère spécial")

    level = ["très faible", "faible", "moyen", "correct", "fort", "très fort"][min(score, 5)]
    return json.dumps({"score": f"{score}/5", "niveau": level, "points_faibles": reasons})


def tool_hash_texte(texte: str, algorithme: str = "sha256") -> str:
    """Calcule le hash d'un texte avec l'algorithme demandé.

    Args:
        texte: Le texte à hasher
        algorithme: 'md5', 'sha1', 'sha256' ou 'sha512' (défaut: sha256)
    """
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    fn = algos.get(algorithme.lower())
    if fn is None:
        return f"❌ Algorithme non supporté. Choix possibles: {list(algos)}"
    return fn(texte.encode()).hexdigest()


def tool_decoder_base64(contenu: str) -> str:
    """Décode une chaîne base64.

    Args:
        contenu: La chaîne encodée en base64 à décoder
    """
    try:
        return base64.b64decode(contenu).decode("utf-8", errors="replace")
    except Exception as e:
        return f"❌ Décodage impossible: {e}"


def tool_lookup_cve_fake(cve_id: str) -> str:
    """Simule une recherche d'information sur un CVE (démo, données inventées).

    Args:
        cve_id: Identifiant CVE, ex: CVE-2024-12345
    """
    fake_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return json.dumps({
        "cve_id": cve_id,
        "severity": random.choice(fake_severities),
        "description": "SIMULATION — pas une vraie base CVE, juste pour tester le tool calling",
        "cvss_score": round(random.uniform(3.0, 9.8), 1),
    })


TOOLS_LIST = [
    tool_calculer,
    tool_scan_ports_fake,
    tool_heure_actuelle,
    tool_verifier_force_mdp,
    tool_hash_texte,
    tool_decoder_base64,
    tool_lookup_cve_fake,
]

TOOL_MAPPING = {f.__name__: f for f in TOOLS_LIST}


# =============================================================================
# 🎧 CALLBACKS — suivi complet de ce qui se passe dans run_agent
# =============================================================================

async def on_step(iteration, msgs, response):
    print(f"   🔄 itération {iteration}")


async def on_tool_call(tool_calls):
    for tc in tool_calls:
        name = tc.get("function", {}).get("name", "?")
        args = tc.get("function", {}).get("arguments", "{}")
        print(f"   🛠️  décision d'appeler: {name}({args})")


async def on_tool_exec_before(name, args):
    print(f"   ⏳ exécution de {name} en cours...")


async def on_tool_exec_after(name, args, result):
    preview = str(result)[:150]
    print(f"   ✅ {name} → {preview}{'...' if len(str(result)) > 150 else ''}")


async def on_tool_exec_error(name, args, error):
    print(f"   💥 erreur dans {name}: {error}")


async def on_retry(attempt, max_retries, error):
    print(f"   ⏳ retry {attempt}/{max_retries} — {error}")


async def on_error(error, iteration, msgs):
    print(f"   ❌ erreur agent (itération {iteration}): {error}")


async def on_finish(final, total_time, iterations, tool_calls_count):
    print(f"   🏁 terminé en {total_time:.2f}s — {iterations} itération(s), {tool_calls_count} outil(s) appelé(s)")


CALLBACKS = dict(
    on_step=on_step,
    on_tool_call=on_tool_call,
    on_tool_exec_before=on_tool_exec_before,
    on_tool_exec_after=on_tool_exec_after,
    on_tool_exec_error=on_tool_exec_error,
    on_retry=on_retry,
    on_error=on_error,
    on_finish=on_finish,
    show_reasoning=SHOW_REASONING,
)


# =============================================================================
# 💬 BOUCLE INTERACTIVE
# =============================================================================

def build_manager() -> LLMManager:
    print(f"🔧 Démarrage de llama-server avec le modèle '{MODEL_NAME}'...")
    mgr = LLMManager(
        llama_server_path=LLAMA_SERVER_PATH,
        host=HOST,
        port=PORT,
        models_preset=MODELS_PRESET_PATH,
        api_keys=[(MODEL_NAME, API_KEY)],
        sync=False,
    )
    # ⚠️ Le constructeur lance le process et valide les clés, mais sans
    # attendre explicitement que le serveur soit prêt à répondre avant de
    # continuer — on le fait nous-mêmes ici pour éviter une course entre
    # démarrage du process et première vraie requête.
    if not mgr.wait_for_server(timeout=120):
        raise RuntimeError("❌ Le serveur local n'a jamais répondu — vérifie le log llama-server")
    return mgr


async def main():
    mgr = build_manager()
    print(f"✅ Prêt à discuter avec '{MODEL_NAME}' (température={TEMPERATURE})\n")
    print("Commandes spéciales:")
    print("  /reset            → vide l'historique de conversation")
    print("  /history          → affiche l'historique brut (JSON)")
    print("  /notools <msg>    → envoie <msg> SANS activer les tools")
    print("  /save <chemin>    → sauvegarde l'historique dans un fichier")
    print("  /load <chemin>    → recharge un historique sauvegardé")
    print("  /quit             → quitter")
    print("-" * 60)

    try:
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

            if user_input.startswith("/save "):
                path = user_input[len("/save "):].strip()
                mgr.save_history(path)
                continue

            if user_input.startswith("/load "):
                path = user_input[len("/load "):].strip()
                mgr.load_history(path)
                continue

            use_tools = True
            if user_input.startswith("/notools "):
                user_input = user_input[len("/notools "):]
                use_tools = False

            t0 = time.time()
            result = await mgr.chat(
                prompt=user_input,
                model_name=MODEL_NAME,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                tools=TOOLS_LIST if use_tools else None,
                tool_mapping=TOOL_MAPPING if use_tools else None,
                **CALLBACKS,
            )

            if result.get("success"):
                print(f"\n🤖 Bot: {result['response']}")
            else:
                print(f"\n💥 Échec: {result.get('error')}")

    finally:
        print("\n🛑 Arrêt du serveur local...")
        mgr.stop_server()


if __name__ == "__main__":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(main())