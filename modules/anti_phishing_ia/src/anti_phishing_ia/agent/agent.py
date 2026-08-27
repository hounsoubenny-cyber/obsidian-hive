#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent CrewAI pour la détection de phishing.

Création et configuration de l'agent Anti-Phishing ShieldAI.
Tasks disponibles :
- analyse_url : analyse une URL spécifique
- analyse_email : analyse un email complet
- analyse_batch : analyse multiple (URLs ou emails)
- monitoring : rapport des dernières analyses

Auteur: HOUNSOU Samuel
Date: Juin 2026
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from crewai import Agent, Crew, Task, LLM, Process, Memory
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
from crewai.knowledge.source.pdf_knowledge_source import PDFKnowledgeSource
from anti_phishing_ia.agent.tools import ALL_TOOLS
from anti_phishing_ia.agent.config import (
    OUTPUT_LOG_FILE, AGENT_PERSONAS, 
    EXPLAIN_MD_PATH, PDF_PATHS
)


# ============================================================================
# AGENT PRINCIPAL
# ============================================================================

def create_anti_phishing_agent(
    personna: str,
    llm: LLM | str, 
    tools: list = None,
    verbose: bool = True,
    memory: Memory = None,
    embedder: dict = None,
    max_iter: int = 3,
) -> Agent:
    """
    Crée et retourne l'agent Anti-Phishing ShieldAI.
    
    Args:
        llm (LLM): Instance du modèle de langage (OpenAI, Groq, etc.)
        tools (list): Liste des outils disponibles (défaut: ALL_TOOLS)
        verbose (bool): Mode verbeux pour les logs
    
    Returns:
        Agent: Agent CrewAI configuré pour la détection de phishing
    
    Example:
        >>> from crewai import LLM
        >>> llm = LLM(model="gpt-4o-mini")
        >>> agent = create_anti_phishing_agent(llm)
    """
    agent_personna = AGENT_PERSONAS.get(personna, AGENT_PERSONAS['hunter'])
    return Agent(
        role="Anti-Phishing Specialist",
        goal=agent_personna["goal"],
        backstory=agent_personna["backstory"],
        tools=tools or ALL_TOOLS,
        llm=llm,
        verbose=verbose,
        allow_delegation=False,
        memory=memory,
        max_iter=max_iter,
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# TASKS
# ============================================================================

def task_analyze_url(agent: Agent, url: str) -> Task:
    """
    Task pour analyser une URL unique.
    
    Args:
        agent (Agent): Agent CrewAI
        url (str): URL à analyser
    
    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Analyse l'URL suivante et détermine si elle est du phishing: {url}",
        expected_output=(
            "Un rapport JSON avec: label (safe/phishing), score de confiance, source de la décision, "
            "et une recommandation (bloquer / surveiller / autoriser). "
            "Si l'URL contient des signaux suspects (IP, caractères spéciaux, TLD bizarre, etc.), "
            "mentionne-les dans le rapport."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name == "analyze_url"],
    )


def task_analyze_email(agent: Agent, email_content: str = None, email_file: str = None) -> Task:
    """
    Task pour analyser un email complet.
    
    Args:
        agent (Agent): Agent CrewAI
        email_content (str): Contenu brut de l'email (optionnel)
        email_file (str): Chemin vers un fichier .eml (optionnel)
    
    Returns:
        Task: Configuration de la tâche
    
    Note:
        Fournir soit email_content soit email_file
    """
    if email_content and email_file:
        raise ValueError("Fournir soit email_content soit email_file, pas les deux")
    
    if email_file:
        description = f"Analyse l'email contenu dans le fichier: {email_file}"
    else:
        description = "Analyse l'email suivant: " + (email_content[:200] + "..." if len(email_content) > 200 else email_content)
    
    return Task(
        description=description,
        expected_output=(
            "Un rapport JSON avec: label (safe/suspicious/phishing), score de confiance, "
            "expéditeur, sujet, nombre d'URLs détectées, SPF/DKIM status, "
            "et une recommandation (bloquer / surveiller / autoriser). "
            "Signale également les points critiques: URLs malveillantes, SPF fail, DKIM absent, "
            "Reply-To différent de From."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name == "analyze_email"],
    )


def task_analyze_batch(agent: Agent, urls: list[str] = None, emails: list[str] = None) -> Task:
    """
    Task pour analyser un lot d'URLs ou d'emails.
    
    Args:
        agent (Agent): Agent CrewAI
        urls (list[str]): Liste d'URLs à analyser
        emails (list[str]): Liste d'emails (contenu brut) à analyser
    
    Returns:
        Task: Configuration de la tâche
    """
    if urls and emails:
        description = f"Analyse le lot: {len(urls)} URLs et {len(emails)} emails"
    elif urls:
        description = f"Analyse le lot de {len(urls)} URLs: {', '.join(urls[:3])}{'...' if len(urls) > 3 else ''}"
    elif emails:
        description = f"Analyse le lot de {len(emails)} emails"
    else:
        raise ValueError("Fournir au moins urls ou emails")
    
    return Task(
        description=description,
        expected_output=(
            "Un rapport JSON avec: "
            "- total: nombre total d'analyses "
            "- phishing: nombre d'éléments classés phishing "
            "- suspicious: nombre d'éléments suspects "
            "- safe: nombre d'éléments sûrs "
            "- details: liste détaillée des résultats par URL/email"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in ["analyze_url", "analyze_email"]],
    )


def task_monitor_report(agent: Agent, limit: int = 10) -> Task:
    """
    Task pour générer un rapport de monitoring.
    
    Args:
        agent (Agent): Agent CrewAI
        limit (int): Nombre d'entrées récentes à inclure (défaut: 10)
    
    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Génère un rapport de monitoring sur les dernières analyses anti-phishing effectuées (limite: {limit}).",
        expected_output=(
            "Rapport incluant: "
            "- nombre total d'analyses d'URLs "
            "- nombre total d'analyses d'emails "
            "- taux de phishing détecté (URLs et emails séparés) "
            "- patterns récurrents observés (mots suspects, TLDs, spoofing) "
            "- recommandation de refit du modèle si nécessaire "
            "- dernières alertes significatives"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name == "get_phishing_stats"],
    )


def task_clear_cache(agent: Agent) -> Task:
    """
    Task pour vider le cache des analyses.
    
    Args:
        agent (Agent): Agent CrewAI
    
    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description="Vide le cache des analyses anti-phishing pour forcer une réanalyse.",
        expected_output=(
            "Confirmation que le cache a été vidé avec succès."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name == "clear_cache"],
    )

def create_anti_phishing_crew(
    agent: Agent,
    tasks: list[Task], 
    verbose: bool = True,
    planning: bool = True,
    checkpoint: bool = True,
    tracing: bool = True,
    memory: bool | Memory = True,
    embedder: dict = None,
) -> Crew:
    """
    Crée un Crew avec l'agent et les tâches définies.
    
    Args:
        agent (Agent): Agent CrewAI
        tasks (list[Task]): Liste des tâches à exécuter
        verbose (bool): Mode verbeux
    
    Returns:
        Crew: Crew CrewAI configuré
    """
    return Crew(
        name="anti_phishing_crew",
        agents=[agent],
        tasks=tasks,
        process=Process.sequential, 
        verbose=verbose,
        planning=planning,
        output_log_file=OUTPUT_LOG_FILE,
        checkpoint=checkpoint,
        tracing=tracing,
        memory=memory,
        knowledge_sources=[
            StringKnowledgeSource(
                content=open(EXPLAIN_MD_PATH).read()
            ),
            PDFKnowledgeSource(
                file_paths=PDF_PATHS
            )
        ],
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# FONCTION DE RÉPONSE RAPIDE (POUR INTÉGRATION SIMPLE)
# ============================================================================

async def quick_analyze_url(url: str, llm: LLM) -> dict:
    """
    Analyse rapide d'une URL via l'agent CrewAI.
    
    Args:
        url (str): URL à analyser
        llm (LLM): Instance LLM
    
    Returns:
        dict: Résultat de l'analyse
    """
    agent = create_anti_phishing_agent(llm)
    task = task_analyze_url(agent, url)
    crew = create_anti_phishing_crew(agent, [task])
    result = await crew.kickoff_async()
    return result


async def quick_analyze_email(email_content: str, llm: LLM) -> dict:
    """
    Analyse rapide d'un email via l'agent CrewAI.
    
    Args:
        email_content (str): Contenu de l'email
        llm (LLM): Instance LLM
    
    Returns:
        dict: Résultat de l'analyse
    """
    agent = create_anti_phishing_agent(llm)
    task = task_analyze_email(agent, email_content=email_content)
    crew = create_anti_phishing_crew(agent, [task])
    result = await crew.kickoff_async()
    return result


# ============================================================================
# MAIN DE TEST
# ============================================================================

if __name__ == "__main__":
    print("🔧 Test de l'agent Anti-Phishing")
    print("=" * 60)
    m = Memory(
        storage="./memory"
    )
    # Configuration LLM (exemple avec Groq)
    try:
        llm = LLM(
            model="groq/llama-3.3-70b-versatile",
            temperature=0.1,
        )
    except Exception as e:
        print(f"Erreur chargement LLM: {e}")
        print("Utilisation d'un mock pour le test...")
        
        # Mock LLM pour test (si pas de clé API)
        class MockLLM:
            def invoke(self, prompt):
                return "Test mode: Agent would analyze here"
        
        llm = MockLLM()
    
    # Créer l'agent
    agent = create_anti_phishing_agent(llm, verbose=True)
    
    # Afficher les outils disponibles
    print(f"\n📦 Outils disponibles ({len(agent.tools)}):")
    for tool in agent.tools:
        print(f"   - {tool.name}: {tool.description[:60]}...")
    
    # Exemple de tâche simple
    print("\n" + "=" * 60)
    print("📋 Tâches disponibles:")
    print("   - task_analyze_url(agent, url)")
    print("   - task_analyze_email(agent, email_content)")
    print("   - task_analyze_batch(agent, urls=[...])")
    print("   - task_monitor_report(agent)")
    print("   - task_clear_cache(agent)")
    print("\n✅ Agent prêt à l'emploi!")