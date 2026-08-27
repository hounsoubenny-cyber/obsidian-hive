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
# 2. IMPORT DES OUTILS DU SCANNER
# ============================================================================

from scanner_ia.agent.tools import ALL_TOOLS
from scanner_ia.agent.agent import create_scanner_agent
from scanner_ia.agent.config import AGENT_PERSONAS

print(f"📦 {len(ALL_TOOLS)} outils chargés:")
for t in ALL_TOOLS:
    print(f"   - {t.name}")

# ============================================================================
# 3. LLM CONFIGURATION
# ============================================================================

# Choix 1 : Serveur local OpenAI-compatible (llama.cpp)
llm_local = LLM(
    model="openai/local",
    base_url="http://127.0.0.1:8000/v1",
    api_key="fake-key",
    temperature=0.2,
)

# Choix 2 : Groq (rapide, gratuit)
llm_groq = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key="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",
    temperature=0.2,
)

# Choix 3 : OpenRouter (multi-modèles)
llm_openrouter = LLM(
    model="openrouter/openrouter/free",
    api_key="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",
    temperature=0.2,
)

# Sélection du LLM (change ici)
llm = llm_openrouter

# ============================================================================
# 4. AGENT SCANNER
# ============================================================================

agent = create_scanner_agent(
    persona="pentester",
    llm=llm,
    tools=ALL_TOOLS[:],  # Limite pour le test
)
print(f"\n📋 Backstory de l'agent:\n{agent.backstory[:500]}...")

# ============================================================================
# 5. TÂCHES PRÉDÉFINIES
# ============================================================================

def task_full_scan(url: str) -> Task:
    """Crée une tâche de scan complet."""
    return Task(
        description=f"Lance un scan de sécurité complet sur l'URL suivante : {url}",
        expected_output="""Un rapport JSON structuré avec :
        - status: success/partial/error
        - scan_id: identifiant du scan
        - elapsed: temps en secondes
        - total_vulns: nombre de vulnérabilités
        - vuln_count: détails par type de vulnérabilité
        - pages_crawled: nombre de pages explorées
        - recommendations: actions prioritaires""",
        agent=agent,
    )

def task_quick_scan(url: str) -> Task:
    """Crée une tâche de scan rapide (passif uniquement)."""
    return Task(
        description=f"Lance un scan rapide (passif uniquement) sur {url}. "
                    f"Utilise crawl_only puis passive_analyze_only.",
        expected_output="""JSON avec :
        - pages_crawled
        - total_vulns_passives
        - vuln_breakdown (headers, cookies, forms, etc.)
        - critical_count, high_count""",
        agent=agent,
    )

def task_adaptive_scan(url: str) -> Task:
    """Crée une tâche de scan adaptatif (l'agent décide des phases)."""
    return Task(
        description=f"""Scanne l'URL {url} de manière adaptative :
        1. Commence par un crawl limité (profondeur 2, 30 pages max).
        2. Analyse les résultats (passive_analyze_only).
        3. Si des formulaires ou paramètres sont détectés, lance un fuzzer ciblé.
        4. Si le site semble être une SPA (peu de URLs), relance le crawl avec is_spa=True.
        5. À chaque étape, justifie ta décision.""",
        expected_output="Rapport d'exécution pas à pas avec justifications.",
        agent=agent,
    )

def task_analyze_vulnerabilities(scan_id: str = None) -> Task:
    """Crée une tâche d'analyse des vulnérabilités trouvées."""
    return Task(
        description=f"Analyse les vulnérabilités du scan {scan_id if scan_id else 'le plus récent'}.",
        expected_output="""JSON avec :
        - total: nombre de vulnérabilités
        - vulnerabilities: [{name, count, severity, examples}]
        - top_priority: vuln la plus critique
        - recommendations: actions correctives""",
        agent=agent,
    )

def task_get_report(scan_id: str = None) -> Task:
    """Crée une tâche pour récupérer les chemins des rapports."""
    return Task(
        description=f"Récupère les chemins des rapports du scan {scan_id if scan_id else 'le plus récent'}.",
        expected_output="JSON avec json_path, html_path, pdf_path",
        agent=agent,
    )

# ============================================================================
# 6. CREW
# ============================================================================

def run_crew(tasks: List[Task], verbose: bool = True) -> dict:
    """Exécute un crew avec les tâches données."""
    crew = Crew(
        agents=[agent],
        tasks=tasks,
        process=Process.sequential,
        verbose=verbose,
        memory=True,
        cache=True,
    )
    
    print("\n" + "=" * 60)
    print("🚀 EXÉCUTION DU CREW")
    print("=" * 60)
    
    result = crew.kickoff()
    return {"result": str(result), "tasks_count": len(tasks)}

# ============================================================================
# 7. FONCTIONS RAPIDES (ASYNC)
# ============================================================================

async def quick_crawl(url: str) -> dict:
    """Crawl rapide d'une URL."""
    from scanner_ia.agent.tools import CrawlOnly
    tool = CrawlOnly()
    result = tool._run(url=url, max_depth=2, max_pages=20)
    return json.loads(result)

async def quick_passive_scan(url: str) -> dict:
    """Analyse passive rapide."""
    from scanner_ia.agent.tools import PassiveAnalyzeOnly
    tool = PassiveAnalyzeOnly()
    # Assure que le crawl est fait
    await tool._arun(url=url)
    result = tool._run(url=url)
    return json.loads(result)

async def quick_vulns() -> dict:
    """Récupère les vulnérabilités du dernier scan."""
    from scanner_ia.agent.tools import GetVulnerabilities
    tool = GetVulnerabilities()
    result = tool._run()
    return json.loads(result)

async def quick_full_scan(url: str) -> dict:
    """Scan complet rapide."""
    from scanner_ia.agent.tools import StartScan
    tool = StartScan()
    result = tool._run(url=url, active_scan=True, limit_payloads=10)
    return json.loads(result)

# ============================================================================
# 8. INTERFACE INTERACTIVE (REPL)
# ============================================================================

def interactive_mode():
    """Mode interactif pour dialoguer avec l'agent."""
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Assistant Scanner")
    print("=" * 60)
    print("Commandes disponibles:")
    print("  /scan <url>              - Scan complet")
    print("  /quick <url>             - Scan rapide (passif)")
    print("  /adaptive <url>          - Scan adaptatif")
    print("  /crawl <url>             - Crawl uniquement")
    print("  /passive <url>           - Analyse passive")
    print("  /vulns                   - Voir les vulnérabilités du dernier scan")
    print("  /report                  - Voir les chemins des rapports")
    print("  /status                  - État du scanner")
    print("  /help                    - Afficher l'aide")
    print("  /exit                    - Quitter")
    print("=" * 60)
    
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
                print("  /scan <url>              - Scan complet")
                print("  /quick <url>             - Scan rapide (passif)")
                print("  /adaptive <url>          - Scan adaptatif")
                print("  /crawl <url>             - Crawl uniquement")
                print("  /passive <url>           - Analyse passive")
                print("  /vulns                   - Voir les vulnérabilités du dernier scan")
                print("  /report                  - Voir les chemins des rapports")
                print("  /status                  - État du scanner")
                print("  /exit                    - Quitter")
            
            elif cmd.startswith("/scan "):
                url = cmd[6:].strip()
                print(f"🔍 Scan complet de {url}...")
                result = asyncio.run(quick_full_scan(url))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd.startswith("/quick "):
                url = cmd[7:].strip()
                print(f"⚡ Scan rapide de {url}...")
                # Utilise le Crew pour un scan rapide
                task = task_quick_scan(url)
                crew = Crew(agents=[agent], tasks=[task], verbose=True)
                result = crew.kickoff()
                print(f"\n📝 Résultat:\n{result}")
            
            elif cmd.startswith("/adaptive "):
                url = cmd[10:].strip()
                print(f"🧠 Scan adaptatif de {url}...")
                task = task_adaptive_scan(url)
                crew = Crew(agents=[agent], tasks=[task], verbose=True)
                result = crew.kickoff()
                print(f"\n📝 Résultat:\n{result}")
            
            elif cmd.startswith("/crawl "):
                url = cmd[7:].strip()
                print(f"🕷️ Crawl de {url}...")
                result = asyncio.run(quick_crawl(url))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd.startswith("/passive "):
                url = cmd[9:].strip()
                print(f"🔍 Analyse passive de {url}...")
                result = asyncio.run(quick_passive_scan(url))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd == "/vulns":
                print("📊 Récupération des vulnérabilités...")
                result = asyncio.run(quick_vulns())
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd == "/report":
                print("📄 Récupération des chemins de rapports...")
                task = task_get_report()
                crew = Crew(agents=[agent], tasks=[task], verbose=True)
                result = crew.kickoff()
                print(f"\n📝 Résultat:\n{result}")
            
            elif cmd == "/status":
                print("📊 État du scanner...")
                from scanner_ia.agent.tools import GetScanStatus, ScannerStateManager
                scan_id = ScannerStateManager.get_last_scan_id()
                if scan_id:
                    tool = GetScanStatus()
                    result = tool._run(scan_id=scan_id)
                    print(json.dumps(json.loads(result), indent=2, ensure_ascii=False))
                else:
                    print("⚠️ Aucun scan effectué")
            
            else:
                # Passer la commande à l'agent Crew
                print(f"🤔 Traitement de la demande: {cmd}")
                crew = Crew(
                    agents=[agent],
                    tasks=[Task(description=cmd, expected_output="Réponse pertinente à la demande", agent=agent)],
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
# 9. MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Scanner Agent")
    print("=" * 60)
    print(f"   LLM: {llm.model if hasattr(llm, 'model') else 'Groq'}")
    print(f"   Outils: {len(ALL_TOOLS)}")
    print("=" * 60)
    
    # Test rapide avant mode interactif
    print("\n🧪 Test rapide de l'agent...")
    try:
        test_task = Task(
            description="Quels sont les outils disponibles pour scanner une URL ?",
            expected_output="Une liste des outils disponibles avec une brève description.",
            agent=agent,
        )
        test_crew = Crew(agents=[agent], tasks=[test_task], verbose=False)
        response = test_crew.kickoff()
        print(f"✅ Agent prêt: {str(response)}...")
    except Exception as e:
        print(f"⚠️ Erreur test agent: {e}")
    
    # Lancer mode interactif
    interactive_mode()