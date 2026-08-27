#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 29 00:16:39 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark multi-modèles + Chat interactif — Tool Calling
Tous les tools : filesystem, système, dev, network
"""

import time
import requests
import json
import os
import subprocess
import shutil
import glob
import psutil
import platform
import socket
from openai import OpenAI
from datetime import datetime

# ============================================================================
# CONFIG
# ============================================================================

LLAMA_SERVER  = "/home/hounsousamuel/llama-bin/llama-b9833/llama-server"
MODELS_PRESET = "./models.ini"
PORT          = 8000
API_KEY       = "ma_super_cle_secrete"
LOG_FILE      = f"./llama_server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

MODELS = [
    "qwen2.5-7b",
    "llama-3.1-8b",
    "qwen2.5-3b",
]

# Tests corsés — multi-tools, raisonnement, erreurs
TESTS = [
    # Niveau 1 — multi-tools enchaînés
    "Liste mon dossier /home/hounsousamuel/PROJETS, puis lis le contenu du premier fichier .md que tu trouves et résume-le",
    # Niveau 2 — raisonnement + tools
    "Donne-moi les infos système, vérifie l'espace disque sur / et dis-moi si j'ai assez de place pour un fichier de 10GB",
    # Niveau 3 — gestion d'erreur
    "Essaie de lire le fichier /home/hounsousamuel/fichier_inexistant.txt, explique ce qui se passe et propose une alternative",
    # Niveau 4 — recherche + lecture
    "Cherche tous les fichiers .py dans /home/hounsousamuel/PROJETS et dis-moi combien il y en a",
    # Niveau 5 — tâche complexe réaliste
    "Analyse l'utilisation mémoire actuelle du système, liste les 5 processus qui consomment le plus de RAM et dis-moi si le système est sous pression",
]

# ============================================================================
# SERVEUR
# ============================================================================

def start_server() -> subprocess.Popen:
    log_fd = open(LOG_FILE, "w")
    print(f"📄 Logs serveur → {LOG_FILE}")
    cmd = [
        LLAMA_SERVER,
        "--models-preset", MODELS_PRESET,
        "--host", "127.0.0.1",
        "--port", str(PORT),
        "--api-key", API_KEY,
        "--jinja",
        "--models-max", "1",
    ]
    return subprocess.Popen(cmd, stdout=log_fd, stderr=log_fd)

def wait_for_server(timeout=120) -> bool:
    url = f"http://127.0.0.1:{PORT}/v1/models"
    print("⏳ Attente du serveur", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2, headers={"Authorization": f"Bearer {API_KEY}"})
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
# TOOLS — FILESYSTEM
# ============================================================================

def list_directory(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Répertoire introuvable : {path}"
        items = os.listdir(path)
        result = f"📁 Contenu de {path} ({len(items)} éléments):\n"
        for item in sorted(items)[:40]:
            full = os.path.join(path, item)
            size = ""
            if os.path.isfile(full):
                s = os.path.getsize(full)
                size = f" ({_human_size(s)})"
            icon = "📁" if os.path.isdir(full) else "📄"
            result += f"  {icon} {item}{size}\n"
        if len(items) > 40:
            result += f"  ... et {len(items) - 40} autres\n"
        return result
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def read_file(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        with open(path, "r", encoding="utf-8") as f:
            content = f.read(3000)
        total = os.path.getsize(path)
        truncated = " (tronqué)" if total > 3000 else ""
        return f"📄 {path} ({_human_size(total)}{truncated}):\n{content}"
    except PermissionError:
        return f"❌ Permission refusée : {path}"
    except UnicodeDecodeError:
        return f"❌ Fichier binaire, impossible de lire : {path}"

def write_file(path: str, content: str) -> str:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"✅ Fichier écrit : {path} ({_human_size(len(content.encode()))})"
    except PermissionError:
        return f"❌ Permission refusée : {path}"
    except Exception as e:
        return f"❌ Erreur écriture : {e}"

def delete_file(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        if os.path.isdir(path):
            return f"❌ C'est un dossier, pas un fichier : {path}"
        os.remove(path)
        return f"✅ Fichier supprimé : {path}"
    except PermissionError:
        return f"❌ Permission refusée : {path}"

def copy_file(source: str, destination: str) -> str:
    try:
        if not os.path.exists(source):
            return f"❌ Source introuvable : {source}"
        shutil.copy2(source, destination)
        return f"✅ Copié : {source} → {destination}"
    except Exception as e:
        return f"❌ Erreur copie : {e}"

def move_file(source: str, destination: str) -> str:
    try:
        if not os.path.exists(source):
            return f"❌ Source introuvable : {source}"
        shutil.move(source, destination)
        return f"✅ Déplacé : {source} → {destination}"
    except Exception as e:
        return f"❌ Erreur déplacement : {e}"

def search_files(directory: str, pattern: str) -> str:
    try:
        if not os.path.exists(directory):
            return f"❌ Répertoire introuvable : {directory}"
        matches = []
        for root, dirs, files in os.walk(directory):
            # Ignore les dossiers cachés
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                if glob.fnmatch.fnmatch(fname, pattern):
                    full = os.path.join(root, fname)
                    matches.append(full)
            if len(matches) > 50:
                break
        if not matches:
            return f"🔍 Aucun fichier trouvé pour '{pattern}' dans {directory}"
        result = f"🔍 {len(matches)} fichier(s) trouvé(s) pour '{pattern}':\n"
        for m in matches[:50]:
            result += f"  📄 {m}\n"
        return result
    except Exception as e:
        return f"❌ Erreur recherche : {e}"

def find_in_file(path: str, search_term: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        results = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                if search_term.lower() in line.lower():
                    results.append(f"  Ligne {i}: {line.rstrip()}")
                if len(results) >= 20:
                    break
        if not results:
            return f"🔍 '{search_term}' non trouvé dans {path}"
        return f"🔍 '{search_term}' trouvé {len(results)} fois dans {path}:\n" + "\n".join(results)
    except Exception as e:
        return f"❌ Erreur : {e}"

def file_info(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Fichier introuvable : {path}"
        stat = os.stat(path)
        ftype = "📁 Dossier" if os.path.isdir(path) else "📄 Fichier"
        return (
            f"{ftype} : {path}\n"
            f"Taille      : {_human_size(stat.st_size)}\n"
            f"Modifié     : {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Créé        : {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Permissions : {oct(stat.st_mode)[-3:]}"
        )
    except Exception as e:
        return f"❌ Erreur : {e}"

# ============================================================================
# TOOLS — SYSTÈME
# ============================================================================

def get_system_info() -> str:
    return (
        f"OS          : {platform.system()} {platform.release()}\n"
        f"Distribution: {platform.version()[:60]}\n"
        f"Machine     : {platform.machine()}\n"
        f"CPU cores   : {os.cpu_count()}\n"
        f"Python      : {platform.python_version()}\n"
        f"CWD         : {os.getcwd()}"
    )

def get_memory_usage() -> str:
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return (
        f"RAM totale  : {_human_size(mem.total)}\n"
        f"RAM utilisée: {_human_size(mem.used)} ({mem.percent}%)\n"
        f"RAM libre   : {_human_size(mem.available)}\n"
        f"Swap total  : {_human_size(swap.total)}\n"
        f"Swap utilisé: {_human_size(swap.used)} ({swap.percent}%)"
    )

def get_disk_usage(path: str = "/") -> str:
    try:
        usage = psutil.disk_usage(path)
        return (
            f"Disque      : {path}\n"
            f"Total       : {_human_size(usage.total)}\n"
            f"Utilisé     : {_human_size(usage.used)} ({usage.percent}%)\n"
            f"Libre       : {_human_size(usage.free)}"
        )
    except Exception as e:
        return f"❌ Erreur : {e}"

def get_processes(limit: int = 10) -> str:
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
        try:
            procs.append({
                'pid': p.info['pid'],
                'name': p.info['name'],
                'ram': p.info['memory_info'].rss if p.info['memory_info'] else 0,
                'cpu': p.info['cpu_percent'] or 0,
            })
        except Exception:
            pass
    procs.sort(key=lambda x: x['ram'], reverse=True)
    result = f"🖥️  Top {limit} processus par RAM:\n"
    for p in procs[:limit]:
        result += f"  PID {p['pid']:<6} {p['name']:<25} RAM: {_human_size(p['ram']):<10} CPU: {p['cpu']}%\n"
    return result

def get_env_var(name: str) -> str:
    val = os.environ.get(name)
    if val is None:
        return f"❌ Variable d'environnement '{name}' non trouvée"
    return f"✅ {name} = {val}"

def execute_command(command: str) -> str:
    # Whitelist de commandes autorisées
    ALLOWED = ["ls", "pwd", "echo", "cat", "head", "tail", "wc", "grep",
               "find", "du", "df", "uname", "whoami", "date", "uptime",
               "free", "top", "ps", "env", "which", "python3", "pip"]
    cmd_name = command.strip().split()[0] if command.strip() else ""
    if cmd_name not in ALLOWED:
        return f"❌ Commande non autorisée : '{cmd_name}'. Autorisées : {', '.join(ALLOWED)}"
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True,
            text=True, timeout=10
        )
        output = result.stdout[:2000] if result.stdout else ""
        error  = result.stderr[:500]  if result.stderr else ""
        if result.returncode != 0:
            return f"⚠️  Code retour {result.returncode}\n{error or output}"
        return output or "✅ Commande exécutée (pas de sortie)"
    except subprocess.TimeoutExpired:
        return "❌ Timeout — commande trop longue (max 10s)"
    except Exception as e:
        return f"❌ Erreur : {e}"

def count_lines(path: str) -> str:
    try:
        if not os.path.exists(path):
            return f"❌ Introuvable : {path}"
        if os.path.isdir(path):
            total = 0
            files = 0
            for root, _, fs in os.walk(path):
                for f in fs:
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            total += sum(1 for _ in fh)
                            files += 1
                    except Exception:
                        pass
            return f"📊 {path}: {total} lignes dans {files} fichiers"
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = sum(1 for _ in f)
        return f"📊 {path}: {lines} lignes"
    except Exception as e:
        return f"❌ Erreur : {e}"

def run_python(code: str) -> str:
    try:
        result = subprocess.run(
            ["python3", "-c", code],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout[:2000] if result.stdout else ""
        error  = result.stderr[:500]  if result.stderr else ""
        if result.returncode != 0:
            return f"❌ Erreur Python:\n{error}"
        return f"✅ Résultat:\n{output}" if output else "✅ Exécuté (pas de sortie)"
    except subprocess.TimeoutExpired:
        return "❌ Timeout (max 10s)"
    except Exception as e:
        return f"❌ Erreur : {e}"

# ============================================================================
# TOOLS — NETWORK
# ============================================================================

def ping_host(host: str) -> str:
    try:
        result = subprocess.run(
            ["ping", "-c", "3", "-W", "2", host],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            return f"✅ {host} répond :\n" + "\n".join(lines[-2:])
        return f"❌ {host} injoignable"
    except subprocess.TimeoutExpired:
        return f"❌ Timeout ping {host}"
    except Exception as e:
        return f"❌ Erreur : {e}"

def http_get(url: str) -> str:
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        content = r.text[:1000] if r.text else ""
        return (
            f"✅ {url}\n"
            f"Status : {r.status_code}\n"
            f"Content-Type: {r.headers.get('content-type', 'N/A')}\n"
            f"Aperçu :\n{content}"
        )
    except requests.Timeout:
        return f"❌ Timeout : {url}"
    except Exception as e:
        return f"❌ Erreur : {e}"

# ============================================================================
# HELPERS
# ============================================================================

def _human_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"

# ============================================================================
# DÉFINITION DES TOOLS (format OpenAI)
# ============================================================================

TOOLS = [
    # --- FILESYSTEM ---
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "Liste le contenu d'un répertoire avec tailles",
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
            "description": "Lit le contenu d'un fichier texte (max 3000 chars)",
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
            "name": "write_file",
            "description": "Écrit du contenu dans un fichier (crée ou écrase)",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier"},
                    "content": {"type": "string", "description": "Contenu à écrire"}
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": "Supprime un fichier",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier à supprimer"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "copy_file",
            "description": "Copie un fichier vers une destination",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Chemin source"},
                    "destination": {"type": "string", "description": "Chemin destination"}
                },
                "required": ["source", "destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "move_file",
            "description": "Déplace ou renomme un fichier",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Chemin source"},
                    "destination": {"type": "string", "description": "Chemin destination"}
                },
                "required": ["source", "destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Cherche des fichiers par pattern (ex: *.py, *.md)",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Dossier de recherche"},
                    "pattern": {"type": "string", "description": "Pattern ex: *.py"}
                },
                "required": ["directory", "pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_in_file",
            "description": "Cherche un terme dans un fichier (comme grep)",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier"},
                    "search_term": {"type": "string", "description": "Terme à chercher"}
                },
                "required": ["path", "search_term"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "file_info",
            "description": "Retourne les métadonnées d'un fichier (taille, dates, permissions)",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin du fichier"}
                },
                "required": ["path"]
            }
        }
    },
    # --- SYSTÈME ---
    {
        "type": "function",
        "function": {
            "name": "get_system_info",
            "description": "Retourne les infos système (OS, CPU, Python)",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_memory_usage",
            "description": "Retourne l'utilisation RAM et swap actuelle",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_disk_usage",
            "description": "Retourne l'espace disque utilisé/libre",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Point de montage (défaut: /)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_processes",
            "description": "Liste les processus actifs triés par consommation RAM",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Nombre de processus à afficher (défaut: 10)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_env_var",
            "description": "Lit la valeur d'une variable d'environnement",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nom de la variable"}
                },
                "required": ["name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_command",
            "description": "Exécute une commande shell (whitelist: ls, pwd, echo, cat, head, tail, wc, grep, find, du, df, uname, whoami, date, uptime, free, top, ps, env, which, python3, pip)",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Commande à exécuter"}
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "count_lines",
            "description": "Compte les lignes d'un fichier ou de tous les fichiers d'un dossier",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Chemin fichier ou dossier"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_python",
            "description": "Exécute un snippet Python et retourne la sortie",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Code Python à exécuter"}
                },
                "required": ["code"]
            }
        }
    },
    # --- NETWORK ---
    {
        "type": "function",
        "function": {
            "name": "ping_host",
            "description": "Ping une adresse IP ou un nom de domaine",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "IP ou domaine à pinger"}
                },
                "required": ["host"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "http_get",
            "description": "Fait une requête HTTP GET et retourne le statut + aperçu du contenu",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL à appeler"}
                },
                "required": ["url"]
            }
        }
    },
]

TOOL_MAP = {
    "list_directory": list_directory,
    "read_file": read_file,
    "write_file": write_file,
    "delete_file": delete_file,
    "copy_file": copy_file,
    "move_file": move_file,
    "search_files": search_files,
    "find_in_file": find_in_file,
    "file_info": file_info,
    "get_system_info": get_system_info,
    "get_memory_usage": get_memory_usage,
    "get_disk_usage": get_disk_usage,
    "get_processes": get_processes,
    "get_env_var": get_env_var,
    "execute_command": execute_command,
    "count_lines": count_lines,
    "run_python": run_python,
    "ping_host": ping_host,
    "http_get": http_get,
}

# ============================================================================
# AGENT CORE
# ============================================================================

SYSTEM_PROMPT = (
    "Tu es un agent assistant expert en système Linux, fichiers et réseau. "
    "Tu as accès à de nombreux outils : filesystem, système, exécution Python, réseau. "
    "Utilise TOUJOURS les outils pour répondre — ne devine jamais les informations. "
    "Enchaîne plusieurs outils si nécessaire pour compléter la tâche. "
    "Réponds toujours en français avec une réponse claire et structurée."
)

def execute_tool(name: str, args: dict) -> str:
    if name not in TOOL_MAP:
        return f"❌ Outil inconnu : {name}"
    return TOOL_MAP[name](**args)

def run_agent(client: OpenAI, model_name: str, user_message: str,
              verbose: bool = False) -> dict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_message}
    ]

    t_start = time.time()
    iteration = 0
    tool_calls_count = 0
    tools_used = []

    while iteration < 8:
        iteration += 1

        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.1,
                max_tokens=2048,
                timeout=300,
            )
        except Exception as e:
            return {
                "response": f"ERREUR API : {e}",
                "total_time": time.time() - t_start,
                "iterations": iteration,
                "tool_calls": tool_calls_count,
                "tools_used": tools_used,
                "success": False,
            }

        choice = response.choices[0]

        if verbose:
            print(f"    [iter {iteration}] finish_reason={choice.finish_reason} | tools={bool(choice.message.tool_calls)}")

        if choice.finish_reason == "stop" or choice.message.tool_calls is None:
            final = choice.message.content
            if final and final.strip():
                return {
                    "response": final.strip(),
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "tools_used": tools_used,
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
                tools_used.append(tool_name)

                if verbose:
                    print(f"    🔧 {tool_name}({json.dumps(tool_args, ensure_ascii=False)[:80]})")

                tool_result = execute_tool(tool_name, tool_args)

                if verbose:
                    print(f"    ✅ {tool_result[:100]}...")

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
        "tools_used": tools_used,
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
        time.sleep(2)

        model_results = []
        for i, test in enumerate(TESTS):
            print(f"\n  📝 Test {i+1}/{len(TESTS)}")
            print(f"  ❓ {test[:70]}...")
            result = run_agent(client, model_name, test, verbose=True)

            status = "✅" if result["success"] else "❌"
            tools_str = " → ".join(result["tools_used"]) if result["tools_used"] else "aucun"
            print(f"  {status} {result['total_time']:.1f}s | {result['tool_calls']} tools | {result['iterations']} iter")
            print(f"  🔗 Tools utilisés : {tools_str}")
            if result["success"]:
                print(f"  💬 {result['response'][:150]}...")
            else:
                print(f"  ⚠️  {result['response'][:100]}")

            model_results.append({"test": test, **result})

        all_results.append({"model": model_name, "results": model_results})

    return all_results

def print_summary(all_results: list):
    print(f"\n\n{'='*70}")
    print("📊 RÉSUMÉ FINAL — TOURNOI CORSÉ")
    print(f"{'='*70}")
    print(f"{'Modèle':<20} {'✅/total':<10} {'Temps moy':<12} {'Tools moy':<12} {'Score'}")
    print("-" * 70)

    scored = []
    for model_result in all_results:
        results = model_result["results"]
        successes     = sum(1 for r in results if r["success"])
        real_successes = sum(1 for r in results if r["success"] and r["tool_calls"] > 0)
        total         = len(results)
        avg_time      = sum(r["total_time"] for r in results) / total if total else 0
        avg_tools     = sum(r["tool_calls"] for r in results) / total if total else 0

        # Score : succès réels (avec tools) comptent double
        success_score = (real_successes / total) * 70
        speed_score   = max(0, 30 - (avg_time / 15))
        score         = success_score + speed_score

        scored.append({
            "model": model_result["model"],
            "successes": successes,
            "real_successes": real_successes,
            "total": total,
            "avg_time": avg_time,
            "avg_tools": avg_tools,
            "score": score,
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    medals = ["🥇", "🥈", "🥉", "4️⃣ ", "5️⃣ ", "6️⃣ "]

    for i, s in enumerate(scored):
        medal = medals[i] if i < len(medals) else "  "
        real = f"({s['real_successes']} avec tools)"
        print(f"{medal} {s['model']:<18} {s['successes']}/{s['total']:<4} {real:<20} {s['avg_time']:<10.1f} {s['avg_tools']:<10.1f} {s['score']:.1f}/100")

    print(f"{'='*70}")
    if scored:
        print(f"\n🏆 Gagnant : {scored[0]['model']} ({scored[0]['score']:.1f}/100)")
    print(f"📄 Logs : {LOG_FILE}")

# ============================================================================
# CHAT INTERACTIF
# ============================================================================

def interactive_chat(client: OpenAI):
    print(f"\n{'='*70}")
    print("💬 MODE CHAT INTERACTIF")
    print(f"{'='*70}")
    print(f"Modèles disponibles : {', '.join(MODELS)}")
    print("Commandes : /model <nom> | /tools | /clear | /quit")
    print(f"{'='*70}\n")

    current_model = MODELS[0]
    history = []
    print(f"🤖 Modèle actif : {current_model}")

    while True:
        try:
            user_input = input("\n👤 Toi : ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 À bientôt !")
            break

        if not user_input:
            continue

        # Commandes spéciales
        if user_input.startswith("/model "):
            new_model = user_input[7:].strip()
            if new_model in MODELS:
                current_model = new_model
                history = []  # Reset historique au changement de modèle
                print(f"✅ Modèle changé → {current_model} (historique réinitialisé)")
            else:
                print(f"❌ Modèle inconnu. Disponibles : {', '.join(MODELS)}")
            continue

        if user_input == "/tools":
            print(f"\n🛠️  {len(TOOLS)} tools disponibles :")
            for t in TOOLS:
                print(f"  • {t['function']['name']:<20} — {t['function']['description'][:50]}")
            continue

        if user_input == "/clear":
            history = []
            print("🗑️  Historique effacé")
            continue

        if user_input in ("/quit", "/exit", "exit", "quit"):
            print("👋 À bientôt !")
            break

        # Construction des messages avec historique
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(history)
        messages.append({"role": "user", "content": user_input})

        print(f"\n🤖 {current_model} réfléchit", end="", flush=True)
        t_start = time.time()
        iteration = 0
        tool_calls_count = 0

        while iteration < 8:
            iteration += 1
            print(".", end="", flush=True)

            try:
                response = client.chat.completions.create(
                    model=current_model,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=0.2,
                    max_tokens=2048,
                    timeout=300,
                )
            except Exception as e:
                print(f"\n❌ Erreur API : {e}")
                break

            choice = response.choices[0]

            if choice.finish_reason == "stop" or choice.message.tool_calls is None:
                final = choice.message.content
                elapsed = time.time() - t_start
                print(f"\n\n🤖 {current_model} ({elapsed:.1f}s | {tool_calls_count} tools) :\n")
                print(final or "(réponse vide)")

                # Sauvegarde dans l'historique
                history.append({"role": "user", "content": user_input})
                history.append({"role": "assistant", "content": final or ""})

                # Limite l'historique à 10 échanges
                if len(history) > 20:
                    history = history[-20:]
                break

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
                    print(f"\n  🔧 {tool_name}...", end="", flush=True)
                    tool_result = execute_tool(tool_name, tool_args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_name,
                        "content": tool_result,
                    })

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import sys

    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║         🤖 LOCAL AGENT — BENCHMARK + CHAT INTERACTIF               ║")
    print("║         19 tools : filesystem, système, Python, réseau              ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    # Mode chat direct sans benchmark
    # chat_only = "--chat" in sys.argv
    chat_only = True

    proc = start_server()
    if not wait_for_server():
        print("❌ Serveur non démarré. Consulte :", LOG_FILE)
        proc.terminate()
        exit(1)

    client = OpenAI(
        base_url=f"http://127.0.0.1:{PORT}/v1",
        api_key=API_KEY
    )

    try:
        if not chat_only:
            print(f"\n🏁 BENCHMARK — {len(MODELS)} modèles × {len(TESTS)} tests corsés\n")
            all_results = benchmark_all(client)
            print_summary(all_results)

            print("\n" + "="*70)
            answer = input("🎮 Lancer le chat interactif ? (o/n) : ").strip().lower()
            if answer in ("o", "oui", "y", "yes"):
                interactive_chat(client)
        else:
            interactive_chat(client)

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrompu")
    finally:
        print("\n🛑 Arrêt du serveur...")
        proc.terminate()
        proc.wait()
        print("✅ Serveur arrêté.")