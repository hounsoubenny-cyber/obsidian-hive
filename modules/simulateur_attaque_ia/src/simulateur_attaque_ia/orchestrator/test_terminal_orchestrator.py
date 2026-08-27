#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  2 14:07:10 2026

@author: hounsousamuel
"""

"""
test_interactive_terminal_orchestrator.py

Lance l'orchestrateur interactif terminal avec un environnement Docker de test.

Usage:
    python test_interactive_terminal_orchestrator.py
    python test_interactive_terminal_orchestrator.py --no-docker  # sans container (IP manuelle)
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import asyncio
import argparse
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.orchestrator.interactive_terminal_orchestrator import (
    InteractiveTerminalOrchestrator, console, _ok, _err, _warn, _section
)
from simulateur_attaque_ia.tactics.tests.environment import TestEnvironment
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from rich.panel import Panel
from rich.text import Text
from dotenv import load_dotenv
load_dotenv()
logger = get_logger()
logger.remove()
IMAGE_NAME     = "shieldai_sim_atk:v2"
CONTAINER_NAME = "shieldai_test_interactive"
# 🔑 Idem, à sortir en variable d'env — cette clé a déjà été partagée ici.
LLAMA_SERVER_PATH = os.environ.get(
    "LLAMA_SERVER_PATH",
    "/home/hounsousamuel/llama-bin/llama-b9833/llama-server",
)
MODEL_NAME = "qwen2.5-3b"  # section [qwen2.5-3b] de models.ini -> Qwen2.5-3B-Instruct-Q5_K_S.gguf
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager

orchestrator = None
result = None

def _build_api_keys():
    # 1ère paire = modèle par défaut (celui utilisé si model_name n'est pas
    # précisé dans self.llm.call(...) côté orchestrateur/graph_nodes).
    keys = [(MODEL_NAME, "local-fake-key")]
    if GROQ_API_KEY:
        keys.append(("llama-3.3-70b-versatile", GROQ_API_KEY))
    return keys  # keys[::-1]

async def run_with_docker():
    global orchestrator, result
    """Lance l'orchestrateur interactif avec un container Docker de test."""

    console.print(Panel.fit(
        Text("🛡  ShieldAI — Test Mode Interactif Terminal", justify="center", style="bold cyan"),
        border_style="cyan", padding=(1, 4),
    ))

    # ── 1. Environnement Docker ───────────────────────────────────────────────
    _section("Démarrage de l'environnement de test")

    env = TestEnvironment(
        image_name=IMAGE_NAME,
        container_name=CONTAINER_NAME,
    )

    dock = None
    ip   = None

    llm = None
    try:
        llm = LLMManager(
            llama_server_path=LLAMA_SERVER_PATH,
            host="127.0.0.1",
            port=9000,
            api_keys=_build_api_keys(),
            sync=False,
        )
        _ok("LLM initialisé (mode assistant disponible)")
    except Exception as e:
        _warn(f"LLM non disponible : {e}")
        raise e

    try:
        ip = env.setup()
        _ok(f"Container démarré — IP cible : {ip}")

        dock = DockerManager()
        dock.container = env.container

        # ── 2. Orchestrateur ─────────────────────────────────────────────────
        _section("Initialisation de l'orchestrateur")

        orchestrator = InteractiveTerminalOrchestrator(
            docker_manager=dock,
            debug=False,
            llm=llm,
        )

        # Pré-remplir la conf avec l'IP du container
        orchestrator.conf["ip"] = ip

        # Pré-remplir port_range pour le scan (ports connus du TestEnvironment)
        orchestrator.conf["network_discover_port_range"] = [22, 21, 8080, 8081, 9090]

        _ok("Orchestrateur prêt")

        # ── 3. Lancer le mode interactif ──────────────────────────────────────
        result = await orchestrator.run_interactive()

        # ── 4. Résumé final ───────────────────────────────────────────────────
        _section("Résumé de la session")
        steps = result.get("steps_results", {})
        _ok(f"Étapes exécutées : {list(steps.keys()) or 'aucune'}")

    except KeyboardInterrupt:
        _warn("Interruption manuelle")

    except Exception as e:
        _err(f"Erreur : {e}")
        import traceback
        console.print_exception()

    finally:
        if llm:
            llm.stop_server()
        if env:
            _section("Nettoyage")
            try:
                env.teardown()
                _ok("Container supprimé")
            except Exception as e:
                _warn(f"Erreur teardown : {e}")


async def run_without_docker(ip: str = None):
    """Lance l'orchestrateur interactif sans Docker — l'user entre l'IP manuellement."""

    console.print(Panel.fit(
        Text("🛡  ShieldAI — Test Mode Interactif (sans Docker)", justify="center", style="bold cyan"),
        border_style="yellow", padding=(1, 4),
    ))

    _warn("Mode sans Docker — vous devrez entrer l'IP cible manuellement")
    llm = None
    try:
        llm = LLMManager(
            llama_server_path=LLAMA_SERVER_PATH,
            host="127.0.0.1",
            port=9000,
            api_keys=_build_api_keys(),
            sync=False,
        )
        _ok("LLM initialisé (mode assistant disponible)")
    except Exception as e:
        _warn(f"LLM non disponible : {e}")
        raise e
        
    orchestrator = InteractiveTerminalOrchestrator(
        docker_manager=None,
        debug=False,
        llm=llm,
    )

    if ip:
        orchestrator.conf["ip"] = ip
        _ok(f"IP pré-configurée : {ip}")

    try:
        result = await orchestrator.run_interactive()

        _section("Résumé de la session")
        steps = result.get("steps_results", {})
        _ok(f"Étapes exécutées : {list(steps.keys()) or 'aucune'}")

    except KeyboardInterrupt:
        _warn("Interruption manuelle")

    except Exception as e:
        _err(f"Erreur : {e}")
        import traceback
        console.print_exception()
    
    if llm:
        llm.stop()


def main():
    parser = argparse.ArgumentParser(description="Test InteractiveTerminalOrchestrator")
    parser.add_argument(
        "--no-docker", action="store_true",
        help="Lancer sans container Docker (IP manuelle)"
    )
    parser.add_argument(
        "--ip", type=str, default=None,
        help="IP cible (utilisé avec --no-docker)"
    )
    args = parser.parse_args()

    if args.no_docker:
        asyncio.run(run_without_docker(ip=args.ip))
    else:
        asyncio.run(run_with_docker())


if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    main()