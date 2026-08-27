#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark multi-modèles — Tool Calling
Compare plusieurs GGUF sur les mêmes tâches
"""

import time
import threading
import requests
import json
import os
import subprocess
import signal
from openai import OpenAI

# ============================================================================
# CONFIG
# ============================================================================

LLAMA_SERVER = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
PORT = 8000

MODELS = [
    # {
    #     "name": "Qwen2.5-7B Q4",
    #     "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    # },
    # {
    #     "name": "Llama-3.1-8B Q4",
    #     "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
    # },
    # {
    #     "name": "Mistral-7B Q4",
    #     "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/mistral-7b-instruct-v0.2.Q4_K_M.gguf",
    # },
    # {
    #     "name": "Gemma-2-2B Q6",
    #     "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/MODELS/MODEL/gemma/gemma-2-2b-it-Q6_K.gguf",
    # },
    # {
    #     "name": "Phi-3.5-mini Q4",
    #     "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/MODELS/MODEL/phi/Phi-3.5-mini-instruct-Q4_K_M.gguf",
    # },
    {
        "name": "Qwen2.5-3B Q5",
        "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/MODELS/MODEL/qwen/Qwen2.5-3B-Instruct-Q5_K_S.gguf",
    },
    
    {
        "name": "Qwen3.5-4B Q5",
        "path": "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/Qwen3.5-4B-Q5_K_M.gguf",
    },
]

TESTS = [
    "Donne-moi des infos sur le système",
    "Liste le contenu du répertoire /home/hounsousamuel et dis-moi combien d'éléments il y a",
    "Lis le fichier /home/hounsousamuel/.bashrc et résume ce qu'il contient",
]

# ============================================================================
# SERVEUR
# ============================================================================

server_process = None

def start_server(model_path: str) -> subprocess.Popen:
    cmd = [
        LLAMA_SERVER,
        "-m", model_path,
        "--host", "127.0.0.1",
        "--port", str(PORT),
        "-t", "10",
        "-c", "16000",
        "--api-key", "ma_super_cle_secrete",
        "--jinja",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_server(proc: subprocess.Popen):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        time.sleep(2)  # Laisse le port se libérer

def wait_for_server(timeout=120) -> bool:
    url = f"http://127.0.0.1:{PORT}/v1/models"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False

# ============================================================================
# TOOLS
# ============================================================================

def list_directory(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Répertoire introuvable : {path}"
        items = os.listdir(path)
        result = f"📁 Contenu de {path} ({len(items)} éléments):\n"
        for item in sorted(items)[:30]:  # max 30 pour pas saturer le contexte
            full = os.path.join(path, item)
            icon = "📁" if os.path.isdir(full) else "📄"
            result += f"  {icon} {item}\n"
        if len(items) > 30:
            result += f"  ... et {len(items) - 30} autres\n"
        return result
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def read_file(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        with open(path, "r", encoding="utf-8") as f:
            content = f.read(2000)
        return f"📄 Contenu de {path}:\n{content}"
    except PermissionError:
        return f"❌ Permission refusée : {path}"
    except UnicodeDecodeError:
        return f"❌ Fichier binaire : {path}"

def get_system_info() -> str:
    import platform
    return (
        f"OS: {platform.system()} {platform.release()}\n"
        f"Machine: {platform.machine()}\n"
        f"CPU cores: {os.cpu_count()}\n"
        f"CWD: {os.getcwd()}"
    )

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "Liste le contenu d'un répertoire",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du répertoire"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Lit le contenu d'un fichier texte",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_info",
            "description": "Retourne des informations sur le système",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

TOOL_MAP = {
    "list_directory": list_directory,
    "read_file": read_file,
    "get_system_info": get_system_info,
}

# ============================================================================
# AGENT
# ============================================================================

def execute_tool(name: str, args: dict) -> str:
    if name not in TOOL_MAP:
        return f"❌ Outil inconnu : {name}"
    return TOOL_MAP[name](**args)

def run_agent(client: OpenAI, user_message: str) -> dict:
    """
    Retourne un dict avec :
    - response    : réponse finale
    - total_time  : temps total
    - iterations  : nombre d'itérations
    - tool_calls  : nombre d'appels outils
    - success     : bool
    """
    messages = [
        {
            "role": "system",
            "content": (
                "Tu es un agent assistant expert en système de fichiers. "
                "Utilise les outils disponibles pour répondre aux demandes. "
                "Réponds toujours en français après avoir utilisé les outils."
                # " Répond UNIQUEMENT EN JSON VALIDE FORMAT {'name': 'nom_du_tool', 'reponse': 'ta réponse ici'}."
            )
        },
        {"role": "user", "content": user_message}
    ]

    t_total_start = time.time()
    iteration = 0
    tool_calls_count = 0

    while iteration < 5:
        iteration += 1

        try:
            response = client.chat.completions.create(
                model="local-model",
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.1,
                max_tokens=2048,
            )
        except Exception as e:
            return {
                "response": f"ERREUR API: {e}",
                "total_time": time.time() - t_total_start,
                "iterations": iteration,
                "tool_calls": tool_calls_count,
                "success": False,
            }

        choice = response.choices[0]

        if choice.finish_reason == "stop" or choice.message.tool_calls is None:
            final = choice.message.content
            if final and final.strip():
                return {
                    "response": final.strip(),
                    "total_time": time.time() - t_total_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "success": True,
                }
            else:
                # Réponse vide — force une synthèse
                messages.append({
                    "role": "user",
                    "content": "Donne ta réponse finale en français."
                })
                continue

        elif choice.message.tool_calls:
            try:
                message_dict = choice.message.model_dump()
            except AttributeError:
                message_dict = choice.message.dict()
            if message_dict.get("content") is None:
                message_dict["content"] = ""
            messages.append(message_dict)

            for tool_call in choice.message.tool_calls:
                tool_calls_count += 1
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                tool_result = execute_tool(tool_name, tool_args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": tool_name,
                    "content": tool_result,
                })

    return {
        "response": "MAX ITERATIONS ATTEINT",
        "total_time": time.time() - t_total_start,
        "iterations": iteration,
        "tool_calls": tool_calls_count,
        "success": False,
    }

# ============================================================================
# BENCHMARK
# ============================================================================

def benchmark_model(model: dict) -> dict:
    """Teste un modèle sur tous les tests et retourne ses résultats."""
    print(f"\n{'='*70}")
    print(f"🧪 MODÈLE : {model['name']}")
    print(f"{'='*70}")

    # Démarre le serveur
    print(f"🚀 Démarrage du serveur...")
    proc = start_server(model["path"])

    if not wait_for_server():
        print(f"❌ Serveur non démarré pour {model['name']}")
        stop_server(proc)
        return {"model": model["name"], "error": "Serveur non démarré", "results": []}

    print(f"✅ Serveur prêt !")

    client = OpenAI(base_url=f"http://127.0.0.1:{PORT}/v1", api_key="ma_super_cle_secrete")

    results = []
    for i, test in enumerate(TESTS):
        print(f"\n📝 Test {i+1}/{len(TESTS)} : {test[:50]}...")
        result = run_agent(client, test)

        status = "✅" if result["success"] else "❌"
        print(f"  {status} | {result['total_time']:.1f}s | {result['tool_calls']} tool calls | {result['iterations']} itérations")
        if result["success"]:
            print(f"  💬 {result['response'][:250]}...")

        results.append({
            "test": test,
            **result
        })

    # Arrête le serveur
    print(f"\n🛑 Arrêt du serveur {model['name']}...")
    stop_server(proc)

    return {"model": model["name"], "results": results}

def print_summary(all_results: list):
    print(f"\n\n{'='*70}")
    print("📊 RÉSUMÉ BENCHMARK")
    print(f"{'='*70}")
    print(f"{'Modèle':<25} {'Succès':<10} {'Temps moy':<12} {'Tool calls moy'}")
    print("-" * 70)

    for model_result in all_results:
        if "error" in model_result:
            print(f"{model_result['model']:<25} ERREUR")
            continue

        results = model_result["results"]
        successes = sum(1 for r in results if r["success"])
        avg_time = sum(r["total_time"] for r in results) / len(results) if results else 0
        avg_tools = sum(r["tool_calls"] for r in results) / len(results) if results else 0

        print(f"{model_result['model']:<25} {successes}/{len(results):<8} {avg_time:<12.1f} {avg_tools:.1f}")

    print(f"{'='*70}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("🏁 BENCHMARK TOOL CALLING — MULTI-MODÈLES")
    print(f"📋 {len(MODELS)} modèles × {len(TESTS)} tests\n")

    all_results = []

    for model in MODELS:
        if not os.path.exists(model["path"]):
            print(f"⚠️  Modèle introuvable, skip : {model['name']} ({model['path']})")
            continue
        result = benchmark_model(model)
        all_results.append(result)
        time.sleep(3)  # Pause entre modèles pour libérer la RAM

    print_summary(all_results)
    print("\n✅ Benchmark terminé !")