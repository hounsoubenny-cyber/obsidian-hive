#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import uvicorn
from llama_cpp.server.app import create_app
from llama_cpp.server.settings import Settings
from crewai import Agent, Task, Crew, LLM
from crewai.tools import tool, BaseTool
import requests

path = "/home/hounsousamuel/PROJETS/DEJA_SUR_GIT/Nexus_projet_hackaton/conversation_app/chat_nexus/MODEL_DEMO/tiny/gemma-3-1b-it-Q4_K_M.gguf"
# path = "/home/hounsousamuel/PROJETS/DEJA_SUR_GIT/Nexus_projet_hackaton/conversation_app/chat_nexus/MODEL/qwen/Qwen2.5-3B-Instruct-Q5_K_S.gguf"

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
        n_ctx=4096,
        n_threads=4,
        n_gpu_layers=0,
        chat_format="qwen",
    )
    app = create_app(settings=settings)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

# Lancer le serveur
server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

print("🚀 Démarrage du serveur...")
wait_for_server()
print("🔗 Connexion à l'API locale...")

# ============================================================
# 1. DÉFINIR LES OUTILS
# ============================================================

@tool
def scan_web(url: str) -> str:
    """Scanne un site web pour détecter des vulnérabilités.
    
    Args:
        url: L'URL du site à scanner (ex: https://example.com)
    """
    print(f"🔧 [TOOL] scan_web appelé avec url={url}")
    # Simulation d'un scan (à remplacer par ton vrai scanner)
    return f"Vulnérabilités sur {url}: XSS (Cross-Site Scripting), SQLI (Injection SQL), CSP manquant"

@tool
def scan_network(ip: str) -> str:
    """Scanne une adresse IP pour détecter des ports ouverts.
    
    Args:
        ip: L'adresse IP à scanner (ex: 192.168.1.1)
    """
    print(f"🔧 [TOOL] scan_network appelé avec ip={ip}")
    return f"Ports ouverts sur {ip}: 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL)"

@tool
def get_headers(url: str) -> str:
    """Analyse les en-têtes HTTP de sécurité d'un site.
    
    Args:
        url: L'URL du site à analyser
    """
    print(f"🔧 [TOOL] get_headers appelé avec url={url}")
    return f"Headers manquants sur {url}: CSP, HSTS, X-Frame-Options, X-Content-Type-Options"

@tool
def calculate_cvss(score: float) -> str:
    """Interprète un score CVSS (Common Vulnerability Scoring System).
    
    Args:
        score: Le score CVSS entre 0.0 et 10.0
    """
    print(f"🔧 [TOOL] calculate_cvss appelé avec score={score}")
    if score >= 9.0:
        return "CRITICAL - Vulnérabilité critique, à corriger immédiatement"
    elif score >= 7.0:
        return "HIGH - Vulnérabilité haute priorité"
    elif score >= 4.0:
        return "MEDIUM - Vulnérabilité à planifier"
    elif score > 0.0:
        return "LOW - Vulnérabilité à surveiller"
    else:
        return "INFORMATIONAL - Pas de vulnérabilité critique"

# Test direct de l'outil (sans agent, pour vérifier)
print("\n🧪 TEST DIRECT DES OUTILS")
print("-" * 40)

test_url = "https://example.com"
result_web = scan_web.func(test_url)
print(f"scan_web: {result_web}")

result_headers = get_headers.func(test_url)
print(f"get_headers: {result_headers}")

print("\n✅ Les outils fonctionnent !")

# ============================================================
# 2. CRÉER L'AGENT AVEC LES OUTILS
# ============================================================

llm = LLM(
    model="openai/local",
    base_url="http://127.0.0.1:8000/v1",
    api_key="fake-key",
    temperature=0.2,
)

agent = Agent(
    role="Security Analyst",
    goal="Analyser les vulnérabilités et fournir des recommandations",
    backstory="""Expert en cybersécurité offensive et défensive.
    Tu utilises des outils pour scanner les sites web, les réseaux,
    et analyser les en-têtes de sécurité.""",
    tools=[scan_web, scan_network, get_headers, calculate_cvss],
    llm=llm,
    verbose=True,
    allow_delegation=False,
)

# ============================================================
# 3. TÂCHES
# ============================================================

task1 = Task(
    description="Analyse le site https://example.com et donne ses vulnérabilités",
    expected_output="Liste des vulnérabilités trouvées avec leur sévérité",
    agent=agent,
)

task2 = Task(
    description="""Analyse l'API https://api.example.com/v1/users et identifie:
    1. Les vulnérabilités potentielles
    2. Les en-têtes de sécurité manquants
    3. Les recommandations de correction""",
    expected_output="Rapport d'analyse API complet",
    agent=agent,
)

# ============================================================
# 4. EXÉCUTER
# ============================================================

print("\n" + "="*60)
print("🚀 DÉMARRAGE DE L'AGENT AVEC OUTILS")
print("="*60 + "\n")

crew = Crew(
    agents=[agent],
    tasks=[task1, task2],
    verbose=True,
)

result = crew.kickoff()

print("\n" + "="*60)
print("📊 RÉSULTAT FINAL")
print("="*60)
# print(result)