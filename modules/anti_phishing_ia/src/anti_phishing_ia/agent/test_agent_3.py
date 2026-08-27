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
    # "llama-3.1-8b",
    # "mistral-7b",
    # "gemma-2-2b",
    # "phi-3.5-mini",
    "qwen3.5-4b",
    "qwen2.5-7b",
    "qwen2.5-3b",
]

TESTS = [
    # --- Simple (1 tool call) ---
    "Donne-moi des infos sur le système",
    "Liste le contenu du répertoire /home/hounsousamuel et dis-moi combien d'éléments il y a",
    "Lis le fichier /home/hounsousamuel/.bashrc et résume ce qu'il contient",

    # --- Chaînage (2+ tool calls nécessaires, agrégation) ---
    "Cherche tous les fichiers .py dans /home/hounsousamuel/PROJET (recherche récursive), "
    "puis pour les 3 premiers trouvés, dis-moi combien de lignes fait chacun.",

    "Trouve les fichiers .log dans /home/hounsousamuel (recherche récursive), et si tu en trouves au moins un, "
    "donne-moi la taille et la date de modification du premier.",

    # --- Raisonnement conditionnel (le modèle doit interpréter un résultat, pas juste le restituer) ---
    "Vérifie l'espace disque disponible sur /home/hounsousamuel. Si moins de 20% est libre, préviens-moi "
    "clairement, sinon dis-moi juste que tout va bien.",

    "Dans le fichier /home/hounsousamuel/.bashrc, cherche s'il y a des lignes contenant le mot 'export'. "
    "S'il y en a, montre-les moi et dis combien il y en a. Sinon dis-moi qu'il n'y en a pas.",

    # --- Chaînage + décision (recherche puis choix du bon outil selon ce qui est trouvé) ---
    "Cherche un fichier nommé '.bashrc' ou similaire dans /home/hounsousamuel (pas en profondeur), "
    "puis compte son nombre de lignes.",
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

def search_files(path: str, pattern: str) -> str:
    """Recherche récursive de fichiers par pattern glob (ex: *.py). Limité en profondeur/résultats pour rester safe."""
    import fnmatch
    try:
        if not os.path.exists(path):
            return f"❌ Répertoire introuvable : {path}"
        matches = []
        max_depth = 6
        base_depth = path.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(path):
            depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
                continue
            for f in files:
                if fnmatch.fnmatch(f, pattern):
                    matches.append(os.path.join(root, f))
            if len(matches) >= 200:
                break
        if not matches:
            return f"📭 Aucun fichier correspondant à '{pattern}' trouvé dans {path}"
        result = f"🔎 {len(matches)} fichier(s) trouvé(s) pour '{pattern}' dans {path}:\n"
        for m in matches[:50]:
            result += f"  📄 {m}\n"
        if len(matches) > 50:
            result += f"  ... et {len(matches) - 50} autres\n"
        return result
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def get_file_info(path: str) -> str:
    """Retourne des métadonnées sur un fichier: taille, date de modification, nombre de lignes si texte."""
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        st = os.stat(path)
        size_kb = st.st_size / 1024
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return f"📄 {path}\n  Taille: {size_kb:.1f} Ko\n  Modifié: {mtime}"
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def count_lines(path: str) -> str:
    """Compte le nombre de lignes d'un fichier texte."""
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            n = sum(1 for _ in f)
        return f"📏 {path} contient {n} lignes"
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def disk_usage(path: str) -> str:
    """Retourne l'espace disque (total/utilisé/libre) pour le point de montage contenant ce chemin."""
    import shutil
    try:
        if not os.path.exists(path):
            return f"❌ Chemin introuvable : {path}"
        total, used, free = shutil.disk_usage(path)
        to_gb = lambda b: b / (1024 ** 3)
        pct_free = (free / total) * 100 if total else 0
        return (
            f"💾 Espace disque pour {path}:\n"
            f"  Total: {to_gb(total):.1f} Go\n"
            f"  Utilisé: {to_gb(used):.1f} Go\n"
            f"  Libre: {to_gb(free):.1f} Go ({pct_free:.1f}%)"
        )
    except Exception as e:
        return f"❌ Erreur : {e}"

def grep_in_file(path: str, keyword: str) -> str:
    """Cherche un mot-clé dans un fichier texte et retourne les lignes correspondantes (numérotées)."""
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        matches = [(i + 1, l.rstrip()) for i, l in enumerate(lines) if keyword in l]
        if not matches:
            return f"📭 Aucune ligne contenant '{keyword}' dans {path}"
        result = f"🔍 {len(matches)} ligne(s) contenant '{keyword}' dans {path}:\n"
        for num, line in matches[:20]:
            result += f"  L{num}: {line}\n"
        if len(matches) > 20:
            result += f"  ... et {len(matches) - 20} autres\n"
        return result
    except PermissionError:
        return f"❌ Permission refusée : {path}"
    except UnicodeDecodeError:
        return f"❌ Fichier binaire : {path}"

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
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Recherche récursive de fichiers par pattern glob (ex: *.py, *.log) dans un répertoire",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Répertoire de départ pour la recherche"},
                    "pattern": {"type": "string", "description": "Pattern glob à matcher, ex: *.py"}
                },
                "required": ["path", "pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_info",
            "description": "Retourne la taille et la date de modification d'un fichier",
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
            "name": "count_lines",
            "description": "Compte le nombre de lignes d'un fichier texte",
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
            "name": "disk_usage",
            "description": "Retourne l'espace disque total/utilisé/libre pour le point de montage d'un chemin",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin dont on veut connaître le point de montage"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "grep_in_file",
            "description": "Cherche un mot-clé dans un fichier texte et retourne les lignes correspondantes",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier"},
                    "keyword": {"type": "string", "description": "Mot-clé à rechercher"}
                },
                "required": ["path", "keyword"]
            }
        }
    }
]

TOOL_MAP = {
    "list_directory": list_directory,
    "read_file": read_file,
    "get_system_info": get_system_info,
    "search_files": search_files,
    "get_file_info": get_file_info,
    "count_lines": count_lines,
    "disk_usage": disk_usage,
    "grep_in_file": grep_in_file,
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

    while iteration < 8:
        iteration += 1
        print(f"    🔄 itération {iteration}/8 — envoi requête à {model_name}...")

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
            print(f"    💥 erreur requête: {e}")
            return {
                "response": f"ERREUR : {e}",
                "total_time": time.time() - t_start,
                "iterations": iteration,
                "tool_calls": tool_calls_count,
                "success": False,
            }

        choice = response.choices[0]

        # Certains providers (Groq, vLLM en mode reasoning, etc.) exposent un
        # champ 'reasoning' séparé du content — on l'affiche s'il est présent.
        reasoning = getattr(choice.message, "reasoning", None)
        choice.message.content
        if reasoning:
            print(f"    🧠 reasoning (itération {iteration}):\n{reasoning}")

        print(f"    📬 finish_reason={choice.finish_reason!r}, tool_calls={'oui' if choice.message.tool_calls else 'non'}")

        if choice.finish_reason == "stop" or choice.message.tool_calls is None:
            final = choice.message.content
            if final and final.strip():
                print(f"    🏁 réponse finale obtenue en {time.time() - t_start:.1f}s")
                return {
                    "response": final.strip(),
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "success": True,
                }
            else:
                print("    ⚠️  content vide malgré finish_reason=stop — on relance avec un rappel")
                messages.append({
                    "role": "user",
                    "content": "Donne ta réponse finale en français."
                })
                continue

        elif choice.message.tool_calls:
            try:
                try:
                    message_dict = choice.message.model_dump()
                except AttributeError:
                    message_dict = choice.message.dict()
                if message_dict.get("content") is None:
                    message_dict["content"] = ""
                messages.append(message_dict)
    
                print(f"    🛠️  {len(choice.message.tool_calls)} tool call(s) demandé(s):")
                for tool_call in choice.message.tool_calls:
                    tool_calls_count += 1
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    print(f"       → {tool_name}({tool_args})")
                    tool_result = execute_tool(tool_name, tool_args)
                    print(f"       ← résultat complet:\n{tool_result}")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_name,
                        "content": tool_result,
                    })
            except KeyboardInterrupt:
                return {
                    "response": "",
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "success": False,
                }
            
            except Exception as e:
                return {
                    "response": str(e),
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "success": False,
                }

    print(f"    ⛔ max itérations atteint ({time.time() - t_start:.1f}s écoulées)")
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
            print(f"\n  📝 Test {i+1}/{len(TESTS)} : {test}")
            result = run_agent(client, model_name, test)

            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['total_time']:.1f}s | {result['tool_calls']} tools | {result['iterations']} iter")
            if result["success"]:
                print(f"  💬 {result['response']}")
            else:
                print(f"  ⚠️  {result['response']}")

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