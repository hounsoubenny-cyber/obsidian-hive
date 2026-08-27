#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent CrewAI pour le Simulateur d'Attaque ShieldAI.

Création et configuration de l'agent.
Tasks disponibles :
- task_full_attack      : Attaque complète (kill chain)
- task_single_phase     : Exécute une phase spécifique
- task_get_status       : État courant
- task_get_report       : Rapport final
- task_list_checkpoints : Lister les sessions
- task_stop_attack      : Arrêter l'attaque
- task_cleanup          : Nettoyer l'environnement

Created on Tue Jun 16 15:08:24 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import json
import asyncio
from typing import Optional, List, Dict, Any

from crewai import Agent, Crew, Task, LLM, Process, Memory
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from simulateur_attaque_ia.agent.tools import ALL_SIMULATOR_TOOLS
from simulateur_attaque_ia.agent.config import OUTPUT_LOG_FILE, AGENT_PERSONAS, DEFAULT_PERSONA
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

def create_simulator_agent(
    persona: str = DEFAULT_PERSONA,
    llm: LLM | str = None,
    tools: list = None,
    verbose: bool = True,
    memory: Memory = None,
    embedder: dict = None,
) -> Agent:
    """
    🎯 Crée et retourne l'agent Simulateur d'Attaque ShieldAI.

    Args:
        persona (str): Persona de l'agent.
            'red_team'   → Attaque complète, agressive
            'blue_team'  → Évaluation prudente
            'trainee'    → Mode pédagogique
            'forensic'   → Analyse post-attaque
            'hunter'     → Traqueur de vulnérabilités
        llm (LLM): Instance du modèle de langage (OBLIGATOIRE).
        tools (list): Outils disponibles. Défaut: ALL_SIMULATOR_TOOLS.
        verbose (bool): Mode verbeux.
        memory (Memory): Mémoire de l'agent.
        embedder (dict): Configuration de l'embedder.

    Returns:
        Agent: Agent CrewAI configuré pour le simulateur d'attaque.

    Example:
        >>> from crewai import LLM
        >>> llm = LLM(model="groq/llama-3.3-70b-versatile", temperature=0.1)
        >>> agent = create_simulator_agent("red_team", llm)
    """
    if llm is None:
        raise ValueError("❌ Un LLM est OBLIGATOIRE pour l'agent Simulateur.")

    agent_persona = AGENT_PERSONAS.get(persona, AGENT_PERSONAS[DEFAULT_PERSONA])
    tools = tools or ALL_SIMULATOR_TOOLS

    return Agent(
        role="ShieldAI Attack Simulator Specialist",
        goal=agent_persona["goal"],
        backstory=agent_persona["backstory"],
        tools=tools,
        llm=llm,
        verbose=verbose,
        allow_delegation=False,
        memory=memory,
        **({"embedder": embedder} if embedder else {})
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TASKS — LES MISSIONS DE L'AGENT
# ═══════════════════════════════════════════════════════════════════════════════

def task_full_attack(
    agent: Agent,
    image_name: str = "shieldai_sim_atk:v2",
    container_name: str = "shieldai_test",
    use_llm: bool = False,
    session_id: Optional[str] = None,
    target_ip: Optional[str] = None,
) -> Task:
    """
    🎯 Tâche : Attaque complète (kill chain MITRE ATT&CK).

    Args:
        agent: Agent CrewAI.
        image_name: Image Docker.
        container_name: Nom du container.
        use_llm: Utiliser le LLM pour les décisions.
        session_id: ID de session (reprise).
        target_ip: IP cible.

    Returns:
        Task configurée pour l'attaque complète.
    """
    description = (
        "🎯 Exécute une attaque cyber complète suivant la kill chain MITRE ATT&CK.\n\n"
        "Étapes :\n"
        "1. 🔍 Reconnaissance — scan des ports et bannières\n"
        "2. 🔑 Initial Access — bruteforce SSH, FTP, HTTP\n"
        "3. ⚡ Execution — commandes, Python, reverse shell\n"
        "4. 🔺 Privilege Escalation — sudo exploit, SUID binaries\n"
        "5. 🕵️ Credential Access — shadow dump, bash history, clés SSH\n"
        "6. 🕸️ Lateral Movement — propagation réseau via SSH\n"
        "7. 📤 Exfiltration — envoi des données vers C2\n"
        "8. 🧹 Defense Evasion — nettoyage des traces\n"
        "9. 💾 Persistence — backdoors cron et clés SSH\n\n"
        f"Configuration :\n"
        f"- Image : {image_name}\n"
        f"- Container : {container_name}\n"
        f"- LLM : {'✅ activé' if use_llm else '❌ désactivé'}\n"
        f"- Session : {session_id or 'nouvelle'}\n"
        f"- IP cible : {target_ip or 'auto-détection'}"
    )

    return Task(
        description=description,
        expected_output=(
            "Un rapport JSON complet avec :\n"
            "- session_id : ID de la session\n"
            "- elapsed : temps total\n"
            "- phases_done : liste des phases terminées\n"
            "- credentials_found : credentials SSH/FTP/HTTP trouvés\n"
            "- success_by_phase : succès/échec par phase\n"
            "- report : rapport détaillé de l'attaque\n"
            "- recommendations : recommandations de remédiation"
        ),
        agent=agent,
    )


def task_single_phase(
    agent: Agent,
    phase: str,
    ip: str,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Task:
    """
    🎯 Tâche : Exécuter une phase spécifique.

    Args:
        agent: Agent CrewAI.
        phase: Phase à exécuter.
        ip: IP cible.
        port: Port spécifique (optionnel).
        username: Username (optionnel).
        password: Password (optionnel).

    Returns:
        Task configurée pour une phase unique.
    """
    description = (
        f"🎯 Exécute la phase '{phase}' de la kill chain.\n\n"
        f"IP cible : {ip}\n"
        f"Port : {port or 'auto'}\n"
        f"Username : {username or 'auto'}\n"
        f"Password : {password or 'auto'}\n\n"
        "Utilise execute_phase pour lancer la phase."
    )

    return Task(
        description=description,
        expected_output=(
            f"Résultat de la phase '{phase}' au format JSON avec :\n"
            "- status : success | error\n"
            "- phase : nom de la phase\n"
            "- result : résultats détaillés\n"
            "- message : message descriptif"
        ),
        agent=agent,
    )


def task_get_status(agent: Agent, include_details: bool = False) -> Task:
    """
    📊 Tâche : Obtenir l'état courant de l'attaque.

    Args:
        agent: Agent CrewAI.
        include_details: Inclure les détails complets.

    Returns:
        Task configurée pour le status.
    """
    description = (
        "📊 Récupère l'état actuel de l'attaque.\n\n"
        f"Inclure les détails : {include_details}\n\n"
        "Utilise get_attack_status."
    )

    return Task(
        description=description,
        expected_output=(
            "JSON avec :\n"
            "- status : running | idle | finished\n"
            "- session_id : ID de session\n"
            "- phases_done : phases terminées\n"
            "- success_by_phase : succès/échec\n"
            "- open_ports : ports ouverts\n"
            "- credentials_found : credentials trouvés\n"
            "- hosts_compromised : hôtes compromis"
        ),
        agent=agent,
    )


def task_get_report(agent: Agent, format: str = "json") -> Task:
    """
    📄 Tâche : Générer le rapport final.

    Args:
        agent: Agent CrewAI.
        format: Format du rapport (json | markdown).

    Returns:
        Task configurée pour le rapport.
    """
    description = (
        f"📄 Génère le rapport final de l'attaque au format {format}.\n\n"
        "Utilise get_attack_report."
    )

    return Task(
        description=description,
        expected_output=(
            f"Rapport complet au format {format} avec :\n"
            "- Résumé de l'attaque\n"
            "- Kill chain détaillée\n"
            "- Vulnérabilités identifiées\n"
            "- Recommandations de remédiation"
        ),
        agent=agent,
    )


def task_list_checkpoints(agent: Agent, limit: int = 20) -> Task:
    """
    📋 Tâche : Lister les checkpoints disponibles.

    Args:
        agent: Agent CrewAI.
        limit: Nombre max de checkpoints.

    Returns:
        Task configurée pour lister les checkpoints.
    """
    description = (
        f"📋 Liste les {limit} dernières sessions d'attaque sauvegardées.\n\n"
        "Utilise list_checkpoints."
    )

    return Task(
        description=description,
        expected_output=(
            "JSON avec :\n"
            "- total : nombre total de checkpoints\n"
            "- checkpoints : liste des sessions avec ID, timestamp, phases_done"
        ),
        agent=agent,
    )


def task_stop_attack(agent: Agent) -> Task:
    """
    🛑 Tâche : Arrêter l'attaque (KILL mode).

    Args:
        agent: Agent CrewAI.

    Returns:
        Task configurée pour l'arrêt.
    """
    description = (
        "🛑 Arrête immédiatement l'attaque en cours.\n\n"
        "Actions :\n"
        "1. Tue le container Docker\n"
        "2. Annule la tâche asyncio\n"
        "3. Réinitialise l'état\n\n"
        "⚠️ Action IRRÉVERSIBLE.\n\n"
        "Utilise stop_attack."
    )

    return Task(
        description=description,
        expected_output=(
            "JSON avec :\n"
            "- status : killed\n"
            "- message : confirmation\n"
            "- container_name : nom du container\n"
            "- session_id : ID de session"
        ),
        agent=agent,
    )


def task_cleanup(
    agent: Agent,
    remove_container: bool = True,
    remove_checkpoints: bool = False
) -> Task:
    """
    🧹 Tâche : Nettoyer l'environnement.

    Args:
        agent: Agent CrewAI.
        remove_container: Supprimer le container.
        remove_checkpoints: Supprimer les checkpoints.

    Returns:
        Task configurée pour le nettoyage.
    """
    description = (
        f"🧹 Nettoie l'environnement de test.\n\n"
        f"Supprimer le container : {remove_container}\n"
        f"Supprimer les checkpoints : {remove_checkpoints}\n\n"
        "Utilise cleanup."
    )

    return Task(
        description=description,
        expected_output=(
            "JSON avec :\n"
            "- status : success | error\n"
            "- container_removed : bool\n"
            "- checkpoints_removed : bool\n"
            "- message : descriptif"
        ),
        agent=agent,
    )


def task_clone_system(
    agent: Agent,
    src: Optional[str] = None,
    dest: Optional[str] = None,
    container_name: Optional[str] = None,
    network_caps: bool = False,
) -> Task:
    """
    🖥️ Tâche : Cloner un système hôte dans un container Docker.

    Args:
        agent: Agent CrewAI.
        src: Source à cloner (auto-détecté si None).
        dest: Destination du backup (auto si None).
        container_name: Nom du container (auto-généré si None).
        network_caps: Ajouter les capacités réseau.

    Returns:
        Task configurée pour le clonage.
    """
    description = (
        f"🖥️ Clone un système hôte dans un container Docker.\n\n"
        f"Source : {src or 'auto-détection'}\n"
        f"Destination : {dest or 'auto'}\n"
        f"Container : {container_name or 'auto-généré'}\n"
        f"Capacités réseau : {network_caps}\n\n"
        "Utilise clone_system."
    )

    return Task(
        description=description,
        expected_output=(
            "JSON avec :\n"
            "- status : success | error\n"
            "- container_name : nom du container\n"
            "- image_name : nom de l'image\n"
            "- explore_cmd : commande pour explorer\n"
            "- message : descriptif"
        ),
        agent=agent,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CREW — L'ÉQUIPE DE LÉGENDE
# ═══════════════════════════════════════════════════════════════════════════════

def create_simulator_crew(
    agent: Agent,
    tasks: list[Task],
    verbose: bool = True,
    planning: bool = False,
    memory: bool | Memory = False,
    embedder: dict = None,
) -> Crew:
    """
    🚀 Crée un Crew avec l'agent Simulateur et les tâches définies.

    Args:
        agent: Agent CrewAI.
        tasks: Liste des tâches à exécuter.
        verbose: Mode verbeux.
        planning: Active la planification automatique.
        memory: Active la mémoire (False par défaut pour le simulateur).
        embedder: Configuration de l'embedder.

    Returns:
        Crew CrewAI configuré.
    """
    # Knowledge source (optionnel)
    knowledge_sources = []

    return Crew(
        name="simulator_crew",
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


# ═══════════════════════════════════════════════════════════════════════════════
# FONCTIONS RAPIDES — POUR L'ACTION IMMÉDIATE
# ═══════════════════════════════════════════════════════════════════════════════

async def quick_attack(
    llm: LLM,
    image_name: str = "shieldai_sim_atk:v2",
    container_name: str = "shieldai_test",
    use_llm: bool = False,
    session_id: Optional[str] = None,
    target_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    🚀 Lance une attaque complète rapidement.

    Args:
        llm: Instance LLM.
        image_name: Image Docker.
        container_name: Nom du container.
        use_llm: Utiliser le LLM.
        session_id: ID de session (reprise).
        target_ip: IP cible.

    Returns:
        Dict: Résultat de l'attaque.
    """
    agent = create_simulator_agent("red_team", llm)
    task = task_full_attack(agent, image_name, container_name, use_llm, session_id, target_ip)
    crew = create_simulator_crew(agent, [task])
    result = await crew.kickoff_async()
    return {"result": result}


async def quick_status(llm: LLM, include_details: bool = False) -> Dict[str, Any]:
    """
    📊 Récupère l'état courant rapidement.

    Args:
        llm: Instance LLM.
        include_details: Inclure les détails.

    Returns:
        Dict: État de l'attaque.
    """
    agent = create_simulator_agent("red_team", llm)
    task = task_get_status(agent, include_details)
    crew = create_simulator_crew(agent, [task])
    result = await crew.kickoff_async()
    return {"result": result}


async def quick_cleanup(llm: LLM, remove_container: bool = True, remove_checkpoints: bool = False) -> Dict[str, Any]:
    """
    🧹 Nettoie l'environnement rapidement.

    Args:
        llm: Instance LLM.
        remove_container: Supprimer le container.
        remove_checkpoints: Supprimer les checkpoints.

    Returns:
        Dict: Résultat du nettoyage.
    """
    agent = create_simulator_agent("red_team", llm)
    task = task_cleanup(agent, remove_container, remove_checkpoints)
    crew = create_simulator_crew(agent, [task])
    result = await crew.kickoff_async()
    return {"result": result}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DE TEST — POUR VOIR LA LÉGENDE EN ACTION
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("🔥 SHIELDIA — SIMULATEUR D'ATTAQUE AGENT CREWAI")
    print("=" * 70)
    print("LA LÉGENDE S'ÉCRIT AUJOURD'HUI 🚀")
    print("=" * 70)

    try:
        from crewai import LLM

        llm = LLM(
            model="groq/llama-3.3-70b-versatile",
            temperature=0.1,
        )

        agent = create_simulator_agent("red_team", llm, verbose=True)

        print(f"\n📦 Outils disponibles ({len(agent.tools)}):")
        for tool in agent.tools:
            print(f"   🔧 {tool.name}")

        print("\n📋 Tasks disponibles:")
        print("   - task_full_attack(agent, ...)")
        print("   - task_single_phase(agent, phase, ip, ...)")
        print("   - task_get_status(agent, include_details)")
        print("   - task_get_report(agent, format)")
        print("   - task_list_checkpoints(agent, limit)")
        print("   - task_stop_attack(agent)")
        print("   - task_cleanup(agent, ...)")
        print("   - task_clone_system(agent, ...)")

        print("\n✅ Agent Simulateur prêt !")
        print("\n🔥 ALORS, ON ATTAQUE ?")

    except Exception as e:
        print(f"❌ Erreur: {e}")
        print("Vérifie ta configuration LLM (clé API Groq ou modèle local).")