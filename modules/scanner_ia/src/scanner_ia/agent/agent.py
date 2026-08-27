#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — Agent CrewAI pour le Scanner.
Création de l'agent, des tâches prédéfinies, et du Crew.
Auteur: HOUNSOU Samuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from crewai import Agent, Crew, Task, LLM, Process, Memory
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from scanner_ia.agent.tools import ALL_TOOLS
from scanner_ia.agent.config import (
    OUTPUT_LOG_FILE, AGENT_PERSONAS, DEFAULT_PERSONA,
)


# ============================================================================
# FONCTION DE CRÉATION DE L'AGENT
# ============================================================================

def create_scanner_agent(
    persona: str = DEFAULT_PERSONA,
    llm: LLM = None,
    tools: list = None,
    verbose: bool = True,
    memory: Memory = None,
    embedder: dict = None,
    max_iter: int = 3,
) -> Agent:
    """
    Crée et retourne l'agent Scanner ShieldAI.

    Args:
        persona: Nom du persona ('pentester', 'guardian', 'analyst')
        llm: Instance LLM CrewAI (obligatoire)
        tools: Liste des outils (défaut: ALL_TOOLS)
        verbose: Mode verbeux

    Returns:
        Agent CrewAI
    """
    if llm is None:
        raise ValueError("Un LLM doit être fourni pour l'agent Scanner.")
    if tools is None:
        tools = ALL_TOOLS

    persona_config = AGENT_PERSONAS.get(persona, AGENT_PERSONAS[DEFAULT_PERSONA])
    return Agent(
        role="Web Security Scanner Specialist",
        goal=persona_config["goal"],
        backstory=persona_config["backstory"],
        tools=tools,
        llm=llm,
        verbose=verbose,
        allow_delegation=False,
        memory=memory,
        max_iter=max_iter,
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# TÂCHES PRÉDÉFINIES
# ============================================================================

def task_full_scan(agent: Agent, url: str, **kwargs) -> Task:
    """
    Tâche de scan complet (crawl + fuzzer + rapport).
    """
    params = {**kwargs}
    description = f"""
    Lance un scan de sécurité complet sur l'URL suivante : {url}.
    Utilise les paramètres : active_scan={params['active_scan']}, 
    profondeur max={params['max_depth']}, pages max={params['max_pages']}.
    Après le scan, analyse les vulnérabilités détectées et produit un résumé structuré.
    """
    expected_output = """
    Un rapport JSON structuré contenant :
    - scan_id
    - url
    - elapsed (temps de scan)
    - total_vulns
    - vuln_count par type
    - pages_crawled
    - recommandations prioritaires (top 3 vulnérabilités critiques)
    """
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )


def task_quick_scan(agent: Agent, url: str, **kwargs) -> Task:
    """
    Tâche de scan rapide (passif uniquement ou fuzzer limité).
    """
    params = {**kwargs}
    params["active_scan"] = False  # rapide = passif
    params["limit_payloads"] = 0   # pas de fuzzer
    description = f"""
    Lance un scan rapide (mode passif) sur {url}. Pas d'envoi de payloads actifs.
    Récupère uniquement les vulnérabilités détectables par analyse statique (headers, cookies, code, etc.).
    """
    expected_output = """
    JSON avec : url, total_vulns_passives, liste des vulns par catégorie (headers, cookies, forms, etc.)
    """
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )


def task_analyze_report(agent: Agent, scan_id: str = None) -> Task:
    """
    Tâche d'analyse d'un rapport existant (ne relance pas de scan).
    """
    description = f"""
    Analyse le rapport du scan {scan_id if scan_id else 'le plus récent'}.
    Extrais les tendances, les vulnérabilités les plus critiques,
    et formule des recommandations stratégiques pour l'équipe de développement.
    """
    expected_output = """
    JSON avec : scan_id, date, top_5_vulns, trends (récurrences), 
    recommandations (court terme, long terme).
    """
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )


def task_compare_scans(agent: Agent, scan_id_1: str, scan_id_2: str) -> Task:
    """
    Tâche de comparaison entre deux scans (régressions / améliorations).
    """
    description = f"""
    Compare les résultats des scans {scan_id_1} et {scan_id_2}.
    Identifie les nouvelles vulnérabilités apparues, celles qui ont été corrigées,
    et calcule l'évolution du score de risque global.
    """
    expected_output = """
    JSON avec : new_vulns, fixed_vulns, risk_evolution (en pourcentage),
    summary_diff (texte explicatif).
    """
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )


def task_export_features(agent: Agent, output_format: str = "csv") -> Task:
    """
    Tâche d'export des features extraites du dernier scan.
    """
    description = f"""
    Extrait les features du dernier scan et les exporte au format {output_format}.
    Les features sont les données utilisées par le modèle ML (longueur du body, entropie, etc.).
    """
    expected_output = """
    JSON contenant : format, columns, sample_data (5 premières lignes), 
    et le chemin du fichier exporté (si sauvegardé localement).
    """
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )


# ============================================================================
# CRÉATION DU CREW
# ============================================================================

def create_scanner_crew(
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
    Crée un Crew avec l'agent Scanner et les tâches définies.
    """
    knowledge_sources = []
    # Optionnel : ajouter une base de connaissances sur les vulnérabilités
    # knowledge_sources.append(StringKnowledgeSource(content="..."))

    return Crew(
        name="scanner_crew",
        agents=[agent],
        tasks=tasks,
        process=Process.sequential,
        verbose=verbose,
        planning=planning,
        output_log_file=OUTPUT_LOG_FILE,
        checkpoint=checkpoint,
        tracing=tracing,
        memory=memory,
        knowledge_sources=knowledge_sources,
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# FONCTIONS RAPIDES (ASYNC)
# ============================================================================

async def quick_scan(url: str, llm: LLM, **kwargs) -> dict:
    """Lance un scan rapide et retourne le résultat."""
    agent = create_scanner_agent("pentester", llm=llm)
    task = task_quick_scan(agent, url, **kwargs)
    crew = create_scanner_crew(agent, [task])
    result = await crew.kickoff_async()
    return {"result": str(result), "url": url}


async def full_scan_analysis(url: str, llm: LLM) -> dict:
    """Lance un scan complet + analyse des vulns."""
    agent = create_scanner_agent("pentester", llm=llm)
    task = task_full_scan(agent, url)
    crew = create_scanner_crew(agent, [task])
    result = await crew.kickoff_async()
    return {"result": str(result), "url": url}

if __name__ == "__main__":
    print("🧪 Test de l'agent Scanner")
    print("=" * 60)
    print("Outils disponibles :")
    for tool in ALL_TOOLS:
        print(f"  - {tool.name}")
    print("\nPour utiliser l'agent, fournissez un LLM (ex: Groq, OpenAI).")
    print("Exemple :")
    print("  from crewai import LLM")
    print("  llm = LLM(model='groq/llama-3.3-70b-versatile')")
    print("  agent = create_scanner_agent(llm=llm)")