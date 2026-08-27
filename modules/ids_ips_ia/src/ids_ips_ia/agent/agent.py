#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent CrewAI pour l'IDS/IPS ShieldAI.

Création et configuration de l'agent IDS/IPS ShieldAI.
Tasks disponibles :
- task_investigate_ip       : investigation complète d'une IP
- task_threat_report        : rapport des menaces actives
- task_block_ip             : blocage d'une IP avec justification
- task_manage_whitelist     : gestion de la whitelist
- task_change_mode          : changement de mode IDS/IPS
- task_full_audit           : audit complet du système

Auteur: HOUNSOU Samuel
Date: Juin 2026
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from crewai import Agent, Crew, Task, LLM, Process, Memory
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
from ids_ips_ia.agent.tools import ALL_IDS_TOOLS
from ids_ips_ia.agent.config import (
    OUTPUT_LOG_FILE, AGENT_PERSONAS,
    EXPLAIN_MD_PATH
)


# ============================================================================
# AGENT PRINCIPAL
# ============================================================================

def create_ids_agent(
    persona: str,
    llm: LLM | str,
    tools: list = ALL_IDS_TOOLS,
    verbose: bool = True,
    memory: Memory = None,
    embedder: dict = None,
) -> Agent:
    """
    Crée et retourne l'agent IDS/IPS ShieldAI.

    Args:
        persona (str): Persona de l'agent ('guardian' | 'analyst' | 'responder')
        llm (LLM): Instance du modèle de langage
        tools (list): Liste des outils disponibles (défaut: ALL_IDS_TOOLS)
        verbose (bool): Mode verbeux

    Returns:
        Agent: Agent CrewAI configuré pour la détection d'intrusions

    Example:
        >>> from crewai import LLM
        >>> llm = LLM(model="groq/llama-3.3-70b-versatile")
        >>> agent = create_ids_agent("guardian", llm)
    """
    agent_persona = AGENT_PERSONAS.get(persona, AGENT_PERSONAS["guardian"])
    return Agent(
        role="IDS/IPS Specialist",
        goal=agent_persona["goal"],
        backstory=agent_persona["backstory"],
        tools= tools,
        llm=llm,
        verbose=verbose,
        allow_delegation=False,
        memory=memory,
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# TASKS
# ============================================================================

def task_investigate_ip(agent: Agent, ip: str) -> Task:
    """
    Task pour investiguer une IP suspecte.

    Args:
        agent (Agent): Agent CrewAI
        ip (str): Adresse IP à investiguer

    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Investigue l'IP suivante et fournis une analyse complète: {ip}",
        expected_output=(
            "Un rapport JSON avec: "
            "- ip: adresse analysée "
            "- score: score de dangerosité (0-300) "
            "- country_code: pays d'origine "
            "- is_suspicious_country: bool "
            "- anomaly_count: nombre d'anomalies détectées "
            "- blocked_count: nombre de fois bloquée "
            "- current_decision: décision actuelle (level + action) "
            "- is_blocked: bool — IP actuellement bloquée "
            "- is_whitelisted: bool "
            "- recommendation: 'block' | 'monitor' | 'whitelist' | 'ignore' "
            "- justification: explication de la recommandation"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_ip_info", "get_blocked_ips", "get_whitelist", "geolocate_ip"
        ]],
    )


def task_threat_report(agent: Agent, limit: int = 20) -> Task:
    """
    Task pour générer un rapport des menaces actives.

    Args:
        agent (Agent): Agent CrewAI
        limit (int): Nombre d'IPs à inclure dans le rapport

    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Génère un rapport complet des menaces actives détectées par l'IDS/IPS (limite: {limit} IPs).",
        expected_output=(
            "Un rapport JSON avec: "
            "- mode: mode actuel (ids/ips) "
            "- total_ips_monitored: nombre total d'IPs surveillées "
            "- total_blocked: nombre d'IPs bloquées "
            "- top_threats: liste des IPs avec les scores les plus élevés "
            "- blocked_ips: liste des IPs actuellement bloquées "
            "- geographic_summary: répartition géographique des menaces "
            "- recommendations: actions suggérées à l'orchestrateur"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_all_ips_scores", "get_blocked_ips", "get_mode"
        ]],
    )


def task_block_ip(agent: Agent, ip: str, reason: str = None) -> Task:
    """
    Task pour bloquer une IP avec justification.

    Args:
        agent (Agent): Agent CrewAI
        ip (str): IP à bloquer
        reason (str): Raison du blocage (optionnel)

    Returns:
        Task: Configuration de la tâche
    """
    desc = f"Analyse et bloque l'IP {ip} si nécessaire."
    if reason:
        desc += f" Raison fournie: {reason}"

    return Task(
        description=desc,
        expected_output=(
            "Un rapport JSON avec: "
            "- ip: adresse ciblée "
            "- action_taken: action effectuée ('blocked' | 'already_blocked' | 'whitelisted' | 'insufficient_score') "
            "- rule_applied: règle NFTables utilisée (drop/rate_limit/rate_limit_data) "
            "- score: score de dangerosité "
            "- justification: pourquoi cette action "
            "- status: 'success' | 'error'"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_ip_info", "get_whitelist", "geolocate_ip", "block_ip"
        ]],
    )


def task_unlock_ip(agent: Agent, ip: str) -> Task:
    """
    Task pour débloquer une IP.

    Args:
        agent (Agent): Agent CrewAI
        ip (str): IP à débloquer

    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Débloque l'IP {ip} et réinitialise son score d'anomalie.",
        expected_output=(
            "Un rapport JSON avec: "
            "- ip: adresse débloquée "
            "- status: 'success' | 'error' | 'not_blocked' "
            "- score_reset: bool "
            "- message: confirmation ou erreur"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_ip_info", "get_blocked_ips", "unlock_ip"
        ]],
    )


def task_manage_whitelist(agent: Agent, ip: str, add: bool = True) -> Task:
    """
    Task pour gérer la whitelist.

    Args:
        agent (Agent): Agent CrewAI
        ip (str): IP à ajouter ou retirer
        add (bool): True = ajouter, False = retirer

    Returns:
        Task: Configuration de la tâche
    """
    action = "ajouter à" if add else "retirer de"
    return Task(
        description=f"{'Ajouter' if add else 'Retirer'} l'IP {ip} {'à' if add else 'de'} la whitelist IDS/IPS.",
        expected_output=(
            "Un rapport JSON avec: "
            f"- ip: adresse ciblée "
            f"- action: 'added' | 'removed' "
            f"- status: 'success' | 'error' "
            f"- whitelist_total: nombre d'IPs en whitelist après l'opération "
            f"- message: confirmation"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_whitelist", "manage_whitelist"
        ]],
    )


def task_change_mode(agent: Agent, mode: str) -> Task:
    """
    Task pour changer le mode IDS/IPS.

    Args:
        agent (Agent): Agent CrewAI
        mode (str): 'ids' ou 'ips'

    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description=f"Change le mode de fonctionnement de l'IDS/IPS vers: {mode}",
        expected_output=(
            "Un rapport JSON avec: "
            "- previous_mode: mode avant changement "
            "- new_mode: mode après changement "
            "- status: 'success' | 'error' "
            "- impact: description des implications du changement de mode"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_mode", "change_mode"
        ]],
    )


def task_full_audit(agent: Agent) -> Task:
    """
    Task pour un audit complet du système IDS/IPS.

    Returns:
        Task: Configuration de la tâche
    """
    return Task(
        description="Effectue un audit complet de l'état du système IDS/IPS.",
        expected_output=(
            "Un rapport JSON complet avec: "
            "- mode: mode actuel "
            "- total_ips_monitored: IPs surveillées "
            "- total_blocked: IPs bloquées "
            "- whitelist_size: taille de la whitelist "
            "- top_5_threats: 5 IPs les plus dangereuses avec scores "
            "- geographic_distribution: pays d'origine des menaces "
            "- insider_threats: IPs suspectes en trafic sortant "
            "- recommendations: liste d'actions prioritaires pour l'orchestrateur"
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_all_ips_scores", "get_blocked_ips",
            "get_whitelist", "get_mode"
        ]],
    )


# ============================================================================
# CREW
# ============================================================================

def create_ids_crew(
    agent: Agent,
    tasks: list[Task],
    verbose: bool = True,
    planning: bool = True,
    memory: bool | Memory = False,
    embedder: dict = None,
) -> Crew:
    """
    Crée un Crew IDS avec l'agent et les tâches définies.

    Args:
        agent (Agent): Agent CrewAI IDS
        tasks (list[Task]): Liste des tâches à exécuter
        verbose (bool): Mode verbeux
        planning (bool): Active la planification automatique
        memory (bool|Memory): Active la mémoire

    Returns:
        Crew: Crew CrewAI configuré
    """
    knowledge_sources = []
    if os.path.exists(EXPLAIN_MD_PATH):
        knowledge_sources.append(
            StringKnowledgeSource(content=open(EXPLAIN_MD_PATH).read())
        )

    return Crew(
        name="ids_ips_crew",
        agents=[agent],
        tasks=tasks,
        process=Process.sequential,
        verbose=verbose,
        planning=planning,
        output_log_file=OUTPUT_LOG_FILE,
        memory=memory,
        **({"knowledge_sources": knowledge_sources} if knowledge_sources else {}),
        **({"embedder": embedder} if embedder else {})
    )


# ============================================================================
# FONCTIONS RAPIDES
# ============================================================================

async def quick_investigate(ip: str, llm: LLM) -> dict:
    """Investigation rapide d'une IP."""
    agent = create_ids_agent("analyst", llm)
    task = task_investigate_ip(agent, ip)
    crew = create_ids_crew(agent, [task])
    return await crew.kickoff_async()


async def quick_threat_report(llm: LLM) -> dict:
    """Rapport rapide des menaces actives."""
    agent = create_ids_agent("guardian", llm)
    task = task_threat_report(agent)
    crew = create_ids_crew(agent, [task])
    return await crew.kickoff_async()


async def quick_block(ip: str, llm: LLM, reason: str = None) -> dict:
    """Blocage rapide d'une IP."""
    agent = create_ids_agent("responder", llm)
    task = task_block_ip(agent, ip, reason)
    crew = create_ids_crew(agent, [task])
    return await crew.kickoff_async()


# ============================================================================
# MAIN DE TEST
# ============================================================================

if __name__ == "__main__":
    print("🔧 Test de l'agent IDS/IPS")
    print("=" * 60)

    try:
        llm = LLM(
            model="groq/llama-3.3-70b-versatile",
            temperature=0.1,
        )
    except Exception as e:
        print(f"Erreur chargement LLM: {e}")
        llm = None

    if llm:
        agent = create_ids_agent("guardian", llm, verbose=True)

        print(f"\n📦 Outils disponibles ({len(agent.tools)}):")
        for tool in agent.tools:
            print(f"   - {tool.name}: {tool.description[:60]}...")

        print("\n📋 Tasks disponibles:")
        print("   - task_investigate_ip(agent, ip)")
        print("   - task_threat_report(agent)")
        print("   - task_block_ip(agent, ip)")
        print("   - task_unlock_ip(agent, ip)")
        print("   - task_manage_whitelist(agent, ip, add)")
        print("   - task_change_mode(agent, mode)")
        print("   - task_full_audit(agent)")
        print("\n✅ Agent IDS prêt !")