#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent CrewAI pour le Sandbox ShieldAI.

Création et configuration de l'agent Sandbox.
Tasks disponibles :
- task_analyze_code         : analyse comportementale complète
- task_triage_code          : triage rapide (statique + sandbox si nécessaire)
- task_forensic_report      : rapport forensique complet
- task_analyze_file         : analyse depuis un chemin de fichier
- task_monitor_container    : monitoring de l'état du container

Auteur: HOUNSOU Samuel
Date: Juin 2026
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from crewai import Agent, Crew, Task, LLM, Process, Memory
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

from sandbox_ia.agent.tools import ALL_SANDBOX_TOOLS, set_orchestrator_instance
from sandbox_ia.agent.config import OUTPUT_LOG_FILE, AGENT_PERSONAS, EXPLAIN_MD_PATH
from sandbox_ia.core.orchestrator import SandboxOrchestrator


# ─────────────────────────────────────────────────────────────────────────────
# AGENT PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def create_sandbox_agent(
    persona: str,
    llm: LLM | str,
    tools: list = ALL_SANDBOX_TOOLS,
    orchestrator: SandboxOrchestrator | None = None,
    verbose: bool = True,
    memory: Memory | None = None,
    embedder: dict | None = None,
) -> Agent:
    """
    Crée et retourne l'agent Sandbox ShieldAI.

    Args:
        persona (str): Persona de l'agent.
            'analyst'  → analyse comportementale + MITRE ATT&CK
            'hunter'   → détection agressive, triage + sandbox
            'forensic' → rapport forensique complet
            'triage'   → filtrage rapide, sandbox si nécessaire
        llm (LLM): Instance du modèle de langage.
        tools (list): Outils disponibles. Défaut: ALL_SANDBOX_TOOLS.
        orchestrator (SandboxOrchestrator | None): Instance existante à réutiliser.
            Si None, une nouvelle instance est créée automatiquement.
        verbose (bool): Mode verbeux.
        memory (Memory | None): Mémoire de l'agent.
        embedder (dict | None): Configuration de l'embedder.

    Returns:
        Agent: Agent CrewAI configuré pour l'analyse sandbox.

    Example:
        >>> from crewai import LLM
        >>> llm = LLM(model="groq/llama-3.3-70b-versatile", temperature=0.1)
        >>> agent = create_sandbox_agent("analyst", llm)
    """
    if orchestrator is not None:
        set_orchestrator_instance(orchestrator)

    agent_persona = AGENT_PERSONAS.get(persona, AGENT_PERSONAS["analyst"])
    return Agent(
        role="Sandbox Security Analyst",
        goal=agent_persona["goal"],
        backstory=agent_persona["backstory"],
        tools=tools,
        llm=llm,
        verbose=verbose,
        allow_delegation=False,
        memory=memory,
        **({"embedder": embedder} if embedder else {})
    )


# ─────────────────────────────────────────────────────────────────────────────
# TASKS
# ─────────────────────────────────────────────────────────────────────────────

def task_analyze_code(
    agent: Agent,
    code: str,
    language: str | None = None,
    context: str | None = None,
) -> Task:
    """
    Task pour l'analyse comportementale complète d'un code.

    Args:
        agent: Agent CrewAI sandbox.
        code: Code source à analyser.
        language: Langage (None = détection auto).
        context: Contexte supplémentaire (ex: "extrait d'un email phishing").

    Returns:
        Task configurée pour l'analyse sandbox.
    """
    desc = "Analyse comportementale du code suivant dans le sandbox ShieldAI"
    if language:
        desc += f" (langage: {language})"
    if context:
        desc += f". Contexte: {context}"
    desc += f":\n\n```\n{code[:300]}{'...' if len(code) > 300 else ''}\n```"

    return Task(
        description=desc,
        expected_output=(
            "Un rapport JSON avec: "
            "final_score (0-100), final_level (LOW/MEDIUM/HIGH/CRITICAL), "
            "alerts_count, liste des alertes avec patterns MITRE ATT&CK détectés, "
            "exec_result (sortie du code, exit_code), "
            "et une recommandation (bloquer / surveiller / autoriser)."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in ["analyze_code", "get_last_report"]],
    )


def task_triage_code(
    agent: Agent,
    code: str,
    language: str | None = None,
) -> Task:
    """
    Task de triage rapide : analyse statique d'abord, sandbox si nécessaire.

    Args:
        agent: Agent CrewAI sandbox.
        code: Code source à trier.
        language: Langage (None = détection auto).

    Returns:
        Task de triage avec décision sandbox ou non.
    """
    desc = (
        f"Triage rapide du code suivant. "
        f"Commence par estimate_risk pour l'analyse statique. "
        f"Si le score statique >= 20 ou si des patterns critiques sont détectés, "
        f"lance quick_analyze pour confirmer dans le sandbox.\n\n"
        f"```\n{code[:300]}{'...' if len(code) > 300 else ''}\n```"
    )
    if language:
        desc += f"\nLangage: {language}"

    return Task(
        description=desc,
        expected_output=(
            "Un rapport JSON avec: "
            "risk_level depuis l'analyse statique, "
            "sandbox_triggered (bool), "
            "final_score si sandbox lancé, "
            "flags suspects détectés, "
            "verdict final (bénin / suspect / malveillant), "
            "et recommandation."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "estimate_risk", "quick_analyze", "get_last_report"
        ]],
    )


def task_forensic_report(
    agent: Agent,
    code: str,
    language: str | None = None,
    incident_context: str | None = None,
) -> Task:
    """
    Task pour produire un rapport forensique complet.

    Args:
        agent: Agent CrewAI sandbox.
        code: Code source à analyser.
        language: Langage (None = détection auto).
        incident_context: Contexte de l'incident (ex: "trouvé sur serveur compromis").

    Returns:
        Task de rapport forensique.
    """
    desc = (
        f"Produis un rapport forensique complet pour le code suivant. "
        f"Lance analyze_code avec strace et fs_monitor activés. "
        f"Documente chaque TTP MITRE ATT&CK détecté, la séquence kill chain "
        f"et les artifacts laissés sur le système.\n\n"
        f"```\n{code[:300]}{'...' if len(code) > 300 else ''}\n```"
    )
    if language:
        desc += f"\nLangage: {language}"
    if incident_context:
        desc += f"\nContexte incident: {incident_context}"

    return Task(
        description=desc,
        expected_output=(
            "Un rapport forensique JSON complet avec: "
            "final_score, final_level, "
            "liste détaillée de chaque alerte avec MITRE TTP, "
            "kill chain reconstruite (étapes de l'attaque dans l'ordre), "
            "artifacts détectés (fichiers créés, connexions tentées, processus), "
            "exec_result (output du code), "
            "et recommandations de remédiation."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "analyze_code", "get_last_report", "estimate_risk"
        ]],
    )


def task_analyze_file(
    agent: Agent,
    file_path: str,
    context: str | None = None,
) -> Task:
    """
    Task pour analyser un fichier de code depuis son chemin.

    Args:
        agent: Agent CrewAI sandbox.
        file_path: Chemin absolu vers le fichier à analyser.
        context: Contexte de découverte du fichier.

    Returns:
        Task d'analyse de fichier.
    """
    desc = (
        f"Lis et analyse le fichier suspect: {file_path}. "
        f"Détecte d'abord le langage depuis l'extension, "
        f"puis lance analyze_code avec le contenu du fichier."
    )
    if context:
        desc += f"\nContexte: {context}"

    return Task(
        description=desc,
        expected_output=(
            "Un rapport JSON avec: "
            "file_path analysé, language_detected, "
            "final_score, final_level, alerts_count, "
            "patterns suspects détectés, "
            "et verdict final avec recommandation."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name in [
            "get_supported_languages", "analyze_code",
            "estimate_risk", "get_last_report"
        ]],
    )


def task_monitor_container(agent: Agent) -> Task:
    """
    Task pour monitorer l'état du container sandbox.

    Returns:
        Task de monitoring.
    """
    return Task(
        description=(
            "Vérifie l'état du container sandbox ShieldAI. "
            "Retourne le status, le PID, et si le container est en bonne santé."
        ),
        expected_output=(
            "Un rapport JSON avec: "
            "status (running/exited/not_start), pid, healthy (bool), "
            "container_name, image_name, et timestamp."
        ),
        agent=agent,
        tools=[t for t in agent.tools if t.name == "get_container_status"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# CREW
# ─────────────────────────────────────────────────────────────────────────────

def create_sandbox_crew(
    agent: Agent,
    tasks: list[Task],
    verbose: bool = True,
    planning: bool = False,
    memory: bool | Memory = False,
    embedder: dict | None = None,
) -> Crew:
    """
    Crée un Crew Sandbox avec l'agent et les tâches définies.

    Args:
        agent: Agent CrewAI sandbox.
        tasks: Liste des tâches à exécuter.
        verbose: Mode verbeux.
        planning: Active la planification automatique.
            Note: désactivé par défaut car le sandbox a des timeouts longs.
        memory: Active la mémoire (False par défaut pour le sandbox).
        embedder: Configuration de l'embedder.

    Returns:
        Crew CrewAI configuré.
    """
    knowledge_sources = []
    if os.path.exists(EXPLAIN_MD_PATH):
        knowledge_sources.append(
            StringKnowledgeSource(content=open(EXPLAIN_MD_PATH).read())
        )

    return Crew(
        name="sandbox_crew",
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


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS RAPIDES
# ─────────────────────────────────────────────────────────────────────────────

async def quick_sandbox_analyze(code: str, llm: LLM, language: str | None = None) -> dict:
    """
    Analyse rapide via l'agent sandbox.

    Args:
        code: Code à analyser.
        llm: Instance LLM.
        language: Langage (None = détection auto).

    Returns:
        Résultat de l'analyse.
    """
    agent = create_sandbox_agent("analyst", llm)
    task = task_analyze_code(agent, code, language)
    crew = create_sandbox_crew(agent, [task])
    return await crew.kickoff_async()


async def quick_triage(code: str, llm: LLM) -> dict:
    """
    Triage rapide : statique d'abord, sandbox si nécessaire.

    Args:
        code: Code à trier.
        llm: Instance LLM.

    Returns:
        Résultat du triage.
    """
    agent = create_sandbox_agent("triage", llm)
    task = task_triage_code(agent, code)
    crew = create_sandbox_crew(agent, [task])
    return await crew.kickoff_async()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DE TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🔧 Test de l'agent Sandbox ShieldAI")
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
        agent = create_sandbox_agent("analyst", llm, verbose=True)

        print(f"\n📦 Outils disponibles ({len(agent.tools)}):")
        for tool in agent.tools:
            print(f"   - {tool.name}: {tool.description[:60]}...")

        print("\n📋 Tasks disponibles:")
        print("   - task_analyze_code(agent, code, language, context)")
        print("   - task_triage_code(agent, code, language)")
        print("   - task_forensic_report(agent, code, language, incident_context)")
        print("   - task_analyze_file(agent, file_path, context)")
        print("   - task_monitor_container(agent)")
        print("\n✅ Agent Sandbox prêt !")