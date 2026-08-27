#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import uvicorn
from llama_cpp.server.app import create_app
from llama_cpp.server.settings import Settings
from crewai import Agent, Task, Crew, LLM, Process
from crewai.tools import tool, BaseTool
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
path = "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/Qwen2.5-7B-Instruct-Q4_K_M.gguf"
# path = "/run/media/hounsousamuel/Windows/Utilitaire_windows/GGFU_AGENTS/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
# path = "/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED/GGFU/Phi-3.5-mini-instruct-Q4_K_M.gguf"
# path = "/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED/GGFU/Qwen2.5-3B-Instruct-Q5_K_S.gguf"
# ============================================================================
# FONCTIONS SERVEUR
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

# Lancer le serveur
server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

print("🚀 Démarrage du serveur...")
wait_for_server()
print("🔗 Connexion à l'API locale...")

# ============================================================================
# 2. IMPORT DES OUTILS (depuis ton module existant)
# ============================================================================

from anti_phishing_ia.agent.tools import ALL_TOOLS
from anti_phishing_ia.agent.agent import create_anti_phishing_agent
from anti_phishing_ia.main_phish import get_ap_instance, HISTORY_FILE
from anti_phishing_ia.analyze_mail import analyze_mail as _analyze_mail

print(f"📦 {len(ALL_TOOLS)} outils chargés:")
for t in ALL_TOOLS:
    print(f"   - {t.name}")

# ============================================================================
# 3. LLM CONFIGURATION
# ============================================================================

llm = LLM(
    model="openai/local",
    base_url="http://127.0.0.1:8000/v1",
    api_key="fake-key",
    temperature=0.2,
    # max_tokens=2048,
)

# llm = LLM(
#     model="groq/llama-3.1-8b-instant",
#     api_key="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",
#     temperature=0.2,
#     # max_tokens=2048,
# )

# llm = LLM(
#     model="openrouter/openrouter/free",
#     api_key="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",
#     temperature=0.2,
#     # max_tokens=2048,
# )


# ============================================================================
# 4. AGENT ANTI-PHISHING
# ============================================================================
agent = create_anti_phishing_agent("hunter", llm=llm, tools=ALL_TOOLS[:2])
print(agent.backstory)
# agent = Agent(
#     role="Anti-Phishing Specialist",
#     goal="Détecter et analyser les URLs et emails de phishing avec précision maximale",
#     backstory="""Tu es un expert en cybersécurité spécialisé dans la détection de phishing.
#     Tu analyses les URLs avec un modèle ML entraîné sur 2M+ URLs et 33 features.
#     Tu travailles au sein de ShieldAI, une plateforme de cybersécurité autonome.
#     Tu disposes d'outils spécialisés pour analyser URLs, emails, extraire des liens,
#     obtenir des statistiques, et gérer le cache.
#     Tu dois toujours justifier ton verdict avec les preuves détectées.""",
#     tools=ALL_TOOLS,
#     llm=llm,
#     verbose=True,
#     allow_delegation=False,
#     memory=True,
# )

# ============================================================================
# 5. TÂCHES PRÉDÉFINIES
# ============================================================================

def task_analyze_url(url: str) -> Task:
    """Crée une tâche d'analyse d'URL."""
    return Task(
        description=f"Analyse l'URL suivante: {url}",
        expected_output="""Un rapport structuré avec:
        - final_decision: safe/phishing/suspicious
        - confidence: score de confiance (0-1)
        - source: whitelist/ia_prediction/passive_analyse
        - breakdown: détails de l'analyse (si disponible)
        - recommendation: blocage/surveillance/autorisation""",
        agent=agent,
    )

def task_analyze_email(email_file: str = None, email_text: str = None) -> Task:
    """Crée une tâche d'analyse d'email."""
    if email_file:
        desc = f"Analyse l'email contenu dans le fichier: {email_file}"
    elif email_text:
        desc = f"Analyse l'email: {email_text[:200]}..."
    else:
        raise ValueError("Fournir email_file ou email_text")
    
    return Task(
        description=desc,
        expected_output="""Un rapport structuré avec:
        - final_decision: safe/suspicious/phishing
        - confidence: score de confiance
        - sender: expéditeur
        - subject: sujet
        - nb_urls_total, nb_urls_phishing
        - spf, dkim
        - recommendation: bloquer/surveiller/autoriser""",
        agent=agent,
    )

def task_monitor_report(limit: int = 10) -> Task:
    """Crée une tâche de monitoring."""
    return Task(
        description=f"Génère un rapport des {limit} dernières analyses anti-phishing",
        expected_output="""Un rapport JSON avec:
        - urls: {total, safe, suspicious, phishing, recent: [...]}
        - emails: {total, safe, suspicious, phishing, recent: [...]}
        - tendances observées
        - recommandations""",
        agent=agent,
    )

def task_clear_cache() -> Task:
    """Crée une tâche de nettoyage du cache."""
    return Task(
        description="Vide le cache des analyses",
        expected_output="Confirmation que le cache a été vidé",
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

async def quick_analyze_url(url: str) -> dict:
    """Analyse rapide d'une URL sans passer par Crew."""
    ap = get_ap_instance()
    return await ap.predict_url_async(url)

async def quick_analyze_email(email_content: str, check_blacklist: bool = False) -> dict:
    """Analyse rapide d'un email sans passer par Crew."""
    ap = get_ap_instance()
    return await ap.predict_email_async(email_content, check_blacklist)

async def quick_get_stats(limit: int = 10) -> dict:
    """Récupère rapidement les statistiques."""
    from anti_phishing_ia.agent.tools import GetPhishingStats
    stats_tool = GetPhishingStats()
    return stats_tool._run(limit)

# ============================================================================
# 8. INTERFACE INTERACTIVE (REPL)
# ============================================================================

def interactive_mode():
    """Mode interactif pour dialoguer avec l'agent."""
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Assistant Anti-Phishing")
    print("=" * 60)
    print("Commandes disponibles:")
    print("  /analyze_url <url>     - Analyser une URL")
    print("  /analyze_email <fichier> - Analyser un fichier .eml")
    print("  /stats                 - Voir les statistiques")
    print("  /clear_cache           - Vider le cache")
    print("  /help                  - Afficher l'aide")
    print("  /exit                  - Quitter")
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
                print("  /analyze_url <url>")
                print("  /analyze_email <fichier.eml>")
                print("  /stats")
                print("  /clear_cache")
                print("  /exit")
            
            elif cmd.startswith("/analyze_url "):
                url = cmd[13:].strip()
                print(f"🔍 Analyse de {url}...")
                result = asyncio.run(quick_analyze_url(url))
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            elif cmd.startswith("/analyze_email "):
                filepath = cmd[15:].strip()
                if not os.path.exists(filepath):
                    print(f"❌ Fichier non trouvé: {filepath}")
                    continue
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                print(f"📧 Analyse de {filepath}...")
                result = asyncio.run(quick_analyze_email(content))
                # Afficher un résumé
                print(f"📊 Décision: {result.get('final_decision', 'N/A')}")
                print(f"   Confiance: {result.get('confidence', 0):.2%}")
                print(f"   Expéditeur: {result.get('sender', 'N/A')}")
                print(f"   URLs: {result.get('nb_urls_total', 0)} total, {result.get('nb_urls_phishing', 0)} phishing")
            
            elif cmd == "/stats":
                print("📊 Récupération des statistiques...")
                stats = asyncio.run(quick_get_stats(10))
                print(json.dumps(stats, indent=2, ensure_ascii=False))
            
            elif cmd == "/clear_cache":
                print("🗑️ Vidage du cache...")
                from anti_phishing_ia.main_phish import clear
                clear()
                print("✅ Cache vidé")
            
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

# ============================================================================
# 9. MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🛡️ SHIELD AI - Système Anti-Phishing")
    print("=" * 60)
    print(f"   Modèle: {path.split('/')[-1]}")
    print(f"   Outils: {len(ALL_TOOLS)}")
    print("=" * 60)
    
    # Test rapide avant mode interactif
    print("\n🧪 Test rapide de l'agent...")
    # try:
    #     test_task = Task(
    #         description="Quels outils as-tu à ta disposition pour détecter du phishing ?",
    #         expected_output="Une liste des outils disponibles avec une brève description de chacun, formatée en JSON ou en texte clair.",
    #         agent=agent,
    #     )
    #     test_crew = Crew(agents=[agent], tasks=[test_task], verbose=False)
    #     response = test_crew.kickoff()
    #     print(f"✅ Agent prêt: {str(response)[:200]}...")
    # except Exception as e:
    #     print(f"⚠️ Erreur test agent: {e}")
    
    # Lancer mode interactif
    interactive_mode()