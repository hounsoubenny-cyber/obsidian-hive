#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark multi-modèles — Tool Calling
Utilise le router mode de llama-server (un seul serveur pour tous les modèles)
"""

import time
import requests
import json
import os
import subprocess
from openai import OpenAI
from datetime import datetime

# ============================================================================
# CONFIG
# ============================================================================

LLAMA_SERVER  = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
MODELS_PRESET = "./models.ini"
PORT          = 8000
LOG_FILE      = f"./llama_server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Noms des modèles — doivent correspondre aux sections du .ini
MODELS = [
    # "qwen2.5-7b",
    # "llama-3.1-8b",
    # "mistral-7b",
    # "gemma-2-2b",
    # "phi-3.5-mini",
    "qwen3.5-4b",
    "ornith1.0-9b"
    # "qwen2.5-3b",
]

TESTS = [
    "Donne-moi des infos sur le système",
    "Liste le contenu du répertoire /home/hounsousamuel et dis-moi combien d'éléments il y a",
    "Lis le fichier /home/hounsousamuel/.bashrc et résume ce qu'il contient",
]

# ============================================================================
# SERVEUR
# ============================================================================

def start_server() -> subprocess.Popen:
    """Lance llama-server en router mode — logs redirigés dans un fichier."""
    log_fd = open(LOG_FILE, "w")
    print(f"📄 Logs serveur → {LOG_FILE}")

    cmd = [
        LLAMA_SERVER,
        "--models-preset", MODELS_PRESET,
        "--host", "127.0.0.1",
        "--api-key", "ma_super_cle_secrete",
        "--port", str(PORT),
        "--jinja",
        "--models-max", "1",   # ← max 1 modèle en RAM à la fois (swap automatique)
    ]
    return subprocess.Popen(cmd, stdout=log_fd, stderr=log_fd)

def wait_for_server(timeout=120) -> bool:
    url = f"http://127.0.0.1:{PORT}/v1/models"
    print("⏳ Attente du serveur", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                print(" ✅")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print(" ❌")
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
        for item in sorted(items)[:30]:
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

def run_agent(client: OpenAI, model_name: str, user_message: str) -> dict:
    messages = [
        {
            "role": "system",
            "content": (
                "Tu es un agent assistant expert en système de fichiers. "
                "Utilise les outils disponibles pour répondre aux demandes. "
                "Réponds toujours en français après avoir utilisé les outils."
            )
        },
        {"role": "user", "content": user_message}
    ]

    t_start = time.time()
    iteration = 0
    tool_calls_count = 0

    while iteration < 5:
        iteration += 1

        try:
            response = client.chat.completions.create(
                model=model_name,   # ← le router charge le bon modèle automatiquement
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.1,
                max_tokens=2048,
                timeout=300,        # 5 min max par requête
            )
        except Exception as e:
            return {
                "response": f"ERREUR : {e}",
                "total_time": time.time() - t_start,
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
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "success": True,
                }
            else:
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
        "total_time": time.time() - t_start,
        "iterations": iteration,
        "tool_calls": tool_calls_count,
        "success": False,
    }

# ============================================================================
# BENCHMARK
# ============================================================================

def benchmark_all(client: OpenAI) -> list:
    all_results = []

    for model_name in MODELS:
        print(f"\n{'='*70}")
        print(f"🧪 MODÈLE : {model_name}")
        print(f"{'='*70}")

        # Petite pause pour laisser le swap se faire
        time.sleep(2)

        model_results = []
        for i, test in enumerate(TESTS):
            print(f"\n  📝 Test {i+1}/{len(TESTS)} : {test[:55]}...")
            result = run_agent(client, model_name, test)

            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['total_time']:.1f}s | {result['tool_calls']} tools | {result['iterations']} iter")
            if result["success"]:
                print(f"  💬 {result['response'][:100]}...")
            else:
                print(f"  ⚠️  {result['response'][:100]}")

            model_results.append({"test": test, **result})

        all_results.append({
            "model": model_name,
            "results": model_results,
        })

    return all_results

def print_summary(all_results: list):
    print(f"\n\n{'='*70}")
    print("📊 RÉSUMÉ FINAL — TOURNOI TOOL CALLING")
    print(f"{'='*70}")
    print(f"{'Modèle':<20} {'✅/total':<10} {'Temps moy':<12} {'Tools moy':<12} {'Score'}")
    print("-" * 70)

    scored = []
    for model_result in all_results:
        results = model_result["results"]
        successes = sum(1 for r in results if r["success"])
        total = len(results)
        avg_time = sum(r["total_time"] for r in results) / total if total else 0
        avg_tools = sum(r["tool_calls"] for r in results) / total if total else 0

        # Score = taux succès (70%) + bonus vitesse (30%)
        success_score = (successes / total) * 70
        speed_score = max(0, 30 - (avg_time / 10))  # -1pt par 10s
        score = success_score + speed_score

        scored.append({
            "model": model_result["model"],
            "successes": successes,
            "total": total,
            "avg_time": avg_time,
            "avg_tools": avg_tools,
            "score": score,
        })

    # Tri par score
    scored.sort(key=lambda x: x["score"], reverse=True)

    medals = ["🥇", "🥈", "🥉", "4️⃣ ", "5️⃣ ", "6️⃣ "]
    for i, s in enumerate(scored):
        medal = medals[i] if i < len(medals) else "  "
        print(f"{medal} {s['model']:<18} {s['successes']}/{s['total']:<8} {s['avg_time']:<12.1f} {s['avg_tools']:<12.1f} {s['score']:.1f}/100")

    print(f"{'='*70}")
    print(f"\n🏆 Gagnant : {scored[0]['model']} ({scored[0]['score']:.1f}/100)")
    print(f"📄 Logs serveur : {LOG_FILE}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("🏁 TOURNOI TOOL CALLING — ROUTER MODE")
    print(f"📋 {len(MODELS)} modèles × {len(TESTS)} tests")
    print(f"⚙️  --models-max 1 → swap automatique en RAM\n")

    proc = start_server()

    if not wait_for_server():
        print("❌ Serveur non démarré. Consulte les logs :", LOG_FILE)
        proc.terminate()
        exit(1)

    client = OpenAI(
        base_url=f"http://127.0.0.1:{PORT}/v1",
        api_key="ma_super_cle_secrete"
    )

    try:
        all_results = benchmark_all(client)
        print_summary(all_results)
    except KeyboardInterrupt:
        print("\n⚠️  Benchmark interrompu par l'utilisateur")
    finally:
        print("\n🛑 Arrêt du serveur...")
        proc.terminate()
        proc.wait()
        print("✅ Serveur arrêté.")