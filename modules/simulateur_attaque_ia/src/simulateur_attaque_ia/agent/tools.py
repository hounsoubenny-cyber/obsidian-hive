#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tools CrewAI pour l'agent Simulateur d'Attaque ShieldAI.
Contrôle TOTAL du système d'attaque.

Created on Tue Jun 16 15:08:15 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import json
import asyncio
import time
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from langgraph.checkpoint.sqlite import SqliteSaver
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.core.cloner import CopyManager
from simulateur_attaque_ia.orchestrator.auto_orchestrator import (
    AutoAttackOrchestrator, DEFAULT_INPUT_DICT, CHECKPOINT_DIR
)
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager
from simulateur_attaque_ia.tactics.tests.environment import TestEnvironment
from simulateur_attaque_ia.simulateur_utils.ids_utils import random_session_id
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from modules_utils.loop_utils import _run_async

logger = get_logger()

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAT PARTAGÉ — LE CŒUR DU SYSTÈME
# ═══════════════════════════════════════════════════════════════════════════════

_orchestrator: AutoAttackOrchestrator | None = None
_llm: LLMManager | None = None
_environment: TestEnvironment | None = None
_last_result: Dict[str, Any] = {}
_current_session_id: str | None = None
_running: bool = False
_model_path = None
_groq_api_key = None

def get_orchestrator() -> AutoAttackOrchestrator:
    """Récupère l'orchestrateur. Lève une erreur si non initialisé."""
    if _orchestrator is None:
        raise ValueError(
            "❌ Orchestrateur non initialisé. Lance d'abord init_orchestrator."
        )
    return _orchestrator

def get_llm() -> LLMManager | None:
    return _llm

def set_orchestrator(instance: AutoAttackOrchestrator):
    global _orchestrator
    _orchestrator = instance

def set_llm(instance: LLMManager | None):
    global _llm
    _llm = instance

def get_environment() -> TestEnvironment:
    if _environment is None:
        raise ValueError("❌ Environnement non initialisé.")
    return _environment

# ═══════════════════════════════════════════════════════════════════════════════
# INPUT SCHEMAS — LA GOUVERNE DE L'AGENT
# ═══════════════════════════════════════════════════════════════════════════════

class InitOrchestratorInput(BaseModel):
    """Initialisation complète du système."""
    image_name: str = Field(
        default="shieldai_sim_atk:v2",
        description="Image Docker à utiliser."
    )
    container_name: str = Field(
        default="shieldai_test",
        description="Nom du container."
    )
    checkpoint_path: str = Field(
        default="test_orchestrator_checkpoints",
        description="Chemin des checkpoints."
    )
    use_llm: bool = Field(
        default=False,
        description="Activer le LLM pour les décisions."
    )
    debug: bool = Field(
        default=True,
        description="Mode debug."
    )
    target_ip: Optional[str] = Field(
        default=None,
        description="IP cible si déjà connue."
    )
    network_mode: bool = Field(
        default=False,
        description="Mode réseau multi-containers."
    )
    n_nodes: int = Field(
        default=3,
        description="Nombre de nodes en mode réseau."
    )


class CloneSystemInput(BaseModel):
    """Clone un système hôte dans un container Docker."""
    src: Optional[str] = Field(
        default=None,
        description="Source à cloner (ex: /, C:\\). None = détection auto."
    )
    dest: Optional[str] = Field(
        default=None,
        description="Destination du backup. None = auto."
    )
    archive_path: Optional[str] = Field(
        default=None,
        description="Chemin d'une archive existante à importer."
    )
    container_name: Optional[str] = Field(
        default=None,
        description="Nom du container. Généré auto si None."
    )
    remove_backup: bool = Field(
        default=True,
        description="Supprimer le backup après import."
    )
    network_caps: bool = Field(
        default=False,
        description="Ajouter les capacités réseau NET_RAW, NET_ADMIN."
    )
    authorize_network: bool = Field(
        default=False,
        description="Autoriser le réseau (sinon --network=isolated)."
    )


class RunAttackInput(BaseModel):
    """Lancer l'attaque complète."""
    session_id: Optional[str] = Field(
        default=None,
        description="ID de session. None = nouvelle session."
    )
    use_llm: bool = Field(
        default=False,
        description="Utiliser le LLM pour les décisions."
    )


class ExecutePhaseInput(BaseModel):
    """Exécuter une phase spécifique."""
    phase: str = Field(
        description="Phase: reconnaissance, initial_access, execution, persistence, privilege_escalation, credential_access, lateral_movement, exfiltration, defense_evasion."
    )
    ip: str = Field(description="IP cible.")
    port: Optional[int] = Field(default=None, description="Port spécifique.")
    username: Optional[str] = Field(default=None, description="Username.")
    password: Optional[str] = Field(default=None, description="Password.")


class GetStatusInput(BaseModel):
    """Obtenir l'état courant."""
    include_details: bool = Field(default=False, description="Inclure les détails.")


class GetReportInput(BaseModel):
    """Obtenir le rapport."""
    format: str = Field(default="json", description="json | markdown")


class ListCheckpointsInput(BaseModel):
    """Lister les checkpoints disponibles."""
    limit: int = Field(default=20, description="Nombre max de checkpoints.")


class SetConfigInput(BaseModel):
    """Modifier la configuration."""
    key: str = Field(description="Clé de configuration.")
    value: Any = Field(description="Nouvelle valeur.")


class GetConfigInput(BaseModel):
    """Voir la configuration."""
    key: Optional[str] = Field(default=None, description="Clé spécifique (None = tout).")


class StopAttackInput(BaseModel):
    """Arrêter l'attaque — KILL MODE."""
    placeholder: str = Field(
        default="",
        description="Paramètre factice (le tool n'a pas de paramètres)"
    )


class CleanupInput(BaseModel):
    """Nettoyer l'environnement."""
    remove_container: bool = Field(default=True, description="Supprimer le container.")
    remove_checkpoints: bool = Field(default=False, description="Supprimer les checkpoints.")


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — INIT ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class InitOrchestrator(BaseTool):
    name: str = "init_orchestrator"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    🚀 INIT_ORCHESTRATOR — DÉMARRAGE DU SYSTÈME D'ATTAQUE
    ═══════════════════════════════════════════════════════════════════════════

    📌 ÉTAPE OBLIGATOIRE AVANT TOUTE ACTION.

    Ce que ça fait :
    ✅ Crée l'environnement Docker (container cible)
    ✅ Initialise le LLM (local ou Groq) si demandé
    ✅ Prépare l'orchestrateur LangGraph avec checkpoints
    ✅ Génère un session_id pour le suivi

    📥 PARAMÈTRES (JSON) :
    {
        "image_name": "shieldai_sim_atk:v2",
        "container_name": "shieldai_test",
        "checkpoint_path": "test_orchestrator_checkpoints",
        "use_llm": false,                      // true pour activer le LLM
        "debug": true,
        "target_ip": null,                     // IP connue (optionnel)
        "network_mode": false,                 // mode multi-containers
        "n_nodes": 3
    }

    📤 RETOUR (JSON) :
    {
        "status": "success" | "error",
        "container_ip": "172.17.0.2",
        "container_name": "shieldai_test",
        "session_id": "simatk-xxxxx",
        "checkpoint_path": "path/to/checkpoints",
        "llm_available": true | false,
        "network_mode": false,
        "n_nodes": 1,
        "message": "message descriptif"
    }

    ⚡ EXEMPLE :
    init_orchestrator(
        image_name="shieldai_sim_atk:v2",
        container_name="test_attack",
        use_llm=True,
    )

    ⚠️ Cette opération peut prendre 5-10 secondes.
    """
    args_schema: type[BaseModel] = InitOrchestratorInput
    description_updated: bool = True

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        global _orchestrator, _llm, _environment, _current_session_id, _running

        try:
            inp = InitOrchestratorInput(**kwargs)

            # ── 1. INITIALISER LE LLM ──
            llm = None
            if inp.model_path and os.path.exists(inp.model_path):
                try:
                    llm = LLMManager(
                        model_path=_model_path,
                        api_key=_groq_api_key or "",
                        port=9000,
                        n_threads=10,
                        n_ctx=4096,
                        timeout=30
                    )
                    _llm = llm
                    logger.print("✅ LLM initialisé avec succès")
                except Exception as e:
                    logger.print(f"⚠️ LLM non disponible: {e}")
                    if inp.use_llm:
                        return json.dumps({
                            "status": "error",
                            "message": f"LLM requis mais échec: {e}",
                            "llm_available": False
                        })

            # ── 2. CRÉER L'ENVIRONNEMENT DOCKER ──
            try:
                env = TestEnvironment(
                    image_name=inp.image_name,
                    container_name=inp.container_name,
                    network=inp.network_mode,
                    n_nodes=inp.n_nodes if inp.network_mode else 1,
                )
                ip = env.setup()
                _environment = env
                logger.print(f"✅ Environnement prêt — IP: {ip}")
            except Exception as e:
                return json.dumps({
                    "status": "error",
                    "message": f"Échec création environnement: {e}",
                    "llm_available": llm is not None
                })

            # ── 3. CRÉER L'ORCHESTRATEUR ──
            dock = DockerManager()
            dock.container = env.container

            orchestrator = AutoAttackOrchestrator(
                docker_manager=dock,
                checkpoint_path=inp.checkpoint_path,
                debug=inp.debug,
                llm=llm,
                use_llm=inp.use_llm,
            )
            _orchestrator = orchestrator
            _running = False

            # ── 4. GÉNÉRER L'ID DE SESSION ──
            session_id = random_session_id()
            _current_session_id = session_id

            # ── 5. CONFIGURER L'IP ──
            if inp.target_ip:
                orchestrator.conf["ip"] = inp.target_ip
            else:
                orchestrator.conf["ip"] = ip

            logger.print(f"🎯 IP cible configurée: {orchestrator.conf['ip']}")

            return json.dumps({
                "status": "success",
                "container_ip": ip,
                "container_name": inp.container_name,
                "session_id": session_id,
                "checkpoint_path": orchestrator.checkpoint_path,
                "llm_available": llm is not None,
                "use_llm": inp.use_llm,
                "network_mode": inp.network_mode,
                "n_nodes": inp.n_nodes if inp.network_mode else 1,
                "message": "🎯 Orchestrateur prêt à l'attaque !"
            }, ensure_ascii=False)

        except Exception as e:
            logger.print(f"❌ Erreur init_orchestrator: {e}")
            # import traceback
            # traceback.print_exc()
            return json.dumps({
                "status": "error",
                "message": str(e),
                "llm_available": False
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — CLONE SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class CloneSystem(BaseTool):
    name: str = "clone_system"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    🖥️  CLONE_SYSTEM — CLONER UN SYSTÈME HÔTE DANS UN CONTAINER DOCKER
    ═══════════════════════════════════════════════════════════════════════════

    📌 Clone un système entier (Linux, Windows, Mac) dans un container Docker.
    Utilise rsync (Linux/Mac) ou robocopy (Windows) pour la copie,
    puis importe l'archive dans Docker.

    📥 PARAMÈTRES (JSON) :
    {
        "src": "/",                          // Source (auto-détecté si None)
        "dest": "/backup",                   // Backup temporaire
        "archive_path": "/path/to/archive.tar",  // Importer une archive existante
        "container_name": "clone_20260618",  // Nom du container (auto-généré)
        "remove_backup": true,               // Supprimer le backup après import
        "network_caps": false,               // Capacités réseau
        "authorize_network": false           // Autoriser le réseau
    }

    📤 RETOUR (JSON) :
    {
        "status": "success" | "error",
        "container_name": "clone_20260618",
        "image_name": "clone_20260618:latest",
        "explore_cmd": "docker run -it --rm clone_20260618:latest /bin/bash",
        "message": "...",
        "services_path": chemin de sauvegarde des services capturer,
        "services": Services capturer lors du clonage
    }

    ⚡ UTILISATION TYPIQUE :
    clone_system(
        src="/home/hounsousamuel/PROJET",
        container_name="clone_projet"
    )

    ⚠️ Nécessite Docker installé et des droits suffisants.
    """
    args_schema: type[BaseModel] = CloneSystemInput
    description_updated: bool = True

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        try:
            inp = CloneSystemInput(**kwargs)

            manager = CopyManager()
            result = manager.clone(
                src=inp.src,
                dest=inp.dest,
                archive_path=inp.archive_path,
                remove_back_up=inp.remove_backup,
                container_name=inp.container_name,
                network_caps=inp.network_caps,
                authorize_network=inp.authorize_network,
            )

            if result.get("success"):
                return json.dumps({
                    "status": "success",
                    "container_name": result.get("container_name"),
                    "image_name": f"{result.get('container_name')}:latest",
                    "explore_cmd": result.get("explore_cmd"),
                    "services_path": result.get("services_path"),
                    "services": result.get("services"),
                    "message": "✅ Système cloné avec succès !"
                }, ensure_ascii=False)
            else:
                return json.dumps({
                    "status": "error",
                    "message": "❌ Échec du clonage",
                    "details": result
                }, ensure_ascii=False)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — RUN ATTACK
# ═══════════════════════════════════════════════════════════════════════════════

class RunAttack(BaseTool):
    name: str = "run_attack"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    💀 RUN_ATTACK — LANCER L'ATTAQUE COMPLÈTE (KILL CHAIN)
    ═══════════════════════════════════════════════════════════════════════════

    📌 Exécute la kill chain MITRE ATT&CK complète :
    reconnaissance → initial_access → execution → privilege_escalation →
    credential_access → lateral_movement → exfiltration → defense_evasion → persistence

    ✅ Si un session_id est fourni, LANGGRAPH REPREND AUTOMATIQUEMENT.
    ✅ Utilise le LLM si configuré.

    📥 PARAMÈTRES (JSON) :
    {
        "session_id": "simatk-xxxxx",    // Optionnel : reprend une session
        "use_llm": false                  // Utiliser le LLM pour les décisions
    }

    📤 RETOUR (JSON) :
    {
        "status": "success" | "partial" | "error",
        "session_id": "simatk-xxxxx",
        "elapsed": 45.2,
        "phases_done": ["reconnaissance", "initial_access", "execution"],
        "credentials_found": {"ssh": [{"port":22, "username":"root", "password":"toor"}]},
        "report": { ... },
        "message": "..."
    }

    ⚡ EXEMPLE :
    run_attack(session_id="simatk-abc123")  # Reprend une attaque

    ⚠️ Cette opération peut durer de quelques secondes à plusieurs minutes.
    """
    args_schema: type[BaseModel] = RunAttackInput
    description_updated: bool = True

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        global _running, _current_session_id

        try:
            inp = RunAttackInput(**kwargs)
            orchestrator = get_orchestrator()

            session_id = inp.session_id or random_session_id()
            _current_session_id = session_id
            _use_llm_backup = orchestrator._use_llm
            if inp.use_llm:
                orchestrator._use_llm = True
                if not orchestrator.llm:
                    raise ValueError("❌ LLM non disponible. Vérifie init_orchestrator.")

            _running = True
            logger.print(f"💀 Lancement de l'attaque — session: {session_id}")

            start_time = time.time()
            result = await orchestrator.run_async(session_id=session_id)
            elapsed = time.time() - start_time

            _running = False

            # ── EXTRAIRE LES INFOS CLÉS ──
            state = result.get("state", {})
            report = result.get("report", {})

            # Credentials SSH
            ssh_creds = state.get("ssh_brute_force_found_credentials", {})
            creds_list = []
            for port, creds in ssh_creds.items():
                for c in creds:
                    creds_list.append({
                        "port": port,
                        "username": c.get("username"),
                        "password": c.get("password")
                    })

            already_done = state.get("already_done", [])
            phases_done = [str(p) for p in already_done]

            success_dict = state.get("success_dict", {})

            return json.dumps({
                "status": "success" if result.get("report") else "partial",
                "session_id": session_id,
                "elapsed": round(elapsed, 2),
                "phases_done": phases_done,
                "credentials_found": {
                    "ssh": creds_list
                },
                "success_by_phase": success_dict,
                "report": report,
                "message": "🎯 Attaque terminée ! Consulte get_attack_report pour les détails."
            }, ensure_ascii=False, default=str)

        except Exception as e:
            _running = False
            logger.print(f"❌ Erreur run_attack: {e}")
            # import traceback
            # traceback.print_exc()
            return json.dumps({
                "status": "error",
                "message": str(e),
                "session_id": _current_session_id
            })
        finally:
            try:
                orchestrator._use_llm = _use_llm_backup
            except Exception:
                pass
        

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — EXECUTE PHASE
# ═══════════════════════════════════════════════════════════════════════════════

class ExecutePhase(BaseTool):
    name: str = "execute_phase"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    🎯 EXECUTE_PHASE — EXÉCUTER UNE PHASE SPÉCIFIQUE
    ═══════════════════════════════════════════════════════════════════════════

    📌 Exécute UNE SEULE phase de la kill chain.
    Utile pour les tests ciblés ou le mode pas-à-pas.

    📥 PARAMÈTRES (JSON) :
    {
        "phase": "reconnaissance",           // ou initial_access, execution, etc.
        "ip": "172.17.0.2",                  // IP cible
        "port": 22,                          // Port spécifique (optionnel)
        "username": "root",                  // Username (optionnel)
        "password": "toor"                   // Password (optionnel)
    }

    📤 RETOUR (JSON) :
    {
        "status": "success" | "error",
        "phase": "reconnaissance",
        "result": { ... },
        "message": "..."
    }

    ⚡ EXEMPLE :
    execute_phase(phase="reconnaissance", ip="172.17.0.2")
    """
    args_schema: type[BaseModel] = ExecutePhaseInput
    description_updated: bool = True

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        try:
            inp = ExecutePhaseInput(**kwargs)
            orchestrator = get_orchestrator()

            # Mettre à jour l'IP dans la config
            orchestrator.conf["ip"] = inp.ip

            # ── MAP PHASE → NOM DU NŒUD LANGGRAPH ──
            phase_map = {
                "reconnaissance": "reconnaissance",
                "initial_access": "initial_access",
                "execution": "execution",
                "privilege_escalation": "privilege_escalation",
                "credential_access": "credential_access",
                "lateral_movement": "lateral_movement",
                "exfiltration": "exfiltration",
                "defense_evasion": "defense_evasion",
                "persistence": "persistence",
            }

            node_name = phase_map.get(inp.phase.lower())
            if not node_name:
                return json.dumps({
                    "status": "error",
                    "message": f"Phase inconnue: {inp.phase}. Choisis parmi: {list(phase_map.keys())}"
                })

            # ── PRÉPARER L'ÉTAT INITIAL ──
            state = orchestrator.final_result.get("state", {})
            if inp.ip:
                state["ip"] = inp.ip

            # ── EXÉCUTER LE NŒUD ──
            # On utilise directement la fonction du nœud
            nodes = orchestrator.get_nodes()
            nodes = list(filter(
                lambda node: str(node[0]).lower() in node_name,
                nodes
            ))
            if not nodes:
                return json.dumps({
                    "status": "error",
                    "message": f"Phase inconnue: {inp.phase}. Choisis parmi: {list(phase_map.keys())}"
                })
            node_func = nodes[0][1]

            # Appeler le nœud
            result = await node_func(state)

            return json.dumps({
                "status": "success",
                "phase": inp.phase,
                "result": result,
                "message": f"✅ Phase {inp.phase} exécutée."
            }, ensure_ascii=False, default=str)

        except Exception as e:
            logger.print(f"❌ Erreur execute_phase: {e}")
            return json.dumps({
                "status": "error",
                "message": str(e)
            })

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — GET ATTACK STATUS
# ═══════════════════════════════════════════════════════════════════════════════

class GetAttackStatus(BaseTool):
    name: str = "get_attack_status"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    📊 GET_ATTACK_STATUS — ÉTAT COURANT DE L'ATTAQUE
    ═══════════════════════════════════════════════════════════════════════════

    📌 Retourne l'état actuel de l'attaque :
    - Phases terminées
    - Succès/échec par phase
    - Credentials trouvés
    - Ports ouverts
    - Hôtes compromis (lateral movement)

    📥 PARAMÈTRES (JSON) :
    {
        "include_details": false    // true pour plus de détails
    }

    📤 RETOUR (JSON) :
    {
        "status": "running" | "idle" | "finished",
        "session_id": "simatk-xxxxx",
        "phases_done": ["reconnaissance"],
        "success_by_phase": {"NetworkServiceDiscover|Reconnaissance": true},
        "open_ports": [22, 80, 443],
        "credentials_found": {"ssh": [...]},
        "hosts_compromised": 3,
        "elapsed": 12.5
    }

    ⚡ EXEMPLE :
    get_attack_status(include_details=True)
    """
    args_schema: type[BaseModel] = GetStatusInput
    description_updated: bool = True

    def _run(self, include_details: bool = False) -> str:
        try:
            orchestrator = get_orchestrator()

            state = orchestrator.final_result.get("state", {})
            steps_results = orchestrator.final_result.get("steps_results", {})

            # ── PHASES TERMINÉES ──
            already_done = state.get("already_done", [])
            phases_done = [str(p) for p in already_done]

            # ── SUCCÈS PAR PHASE ──
            success_dict = state.get("success_dict", {})

            # ── PORTS OUVERTS ──
            open_ports = state.get("open_ports", [])

            # ── CREDENTIALS SSH ──
            ssh_creds = state.get("ssh_brute_force_found_credentials", {})
            creds_list = []
            for port, creds in ssh_creds.items():
                for c in creds:
                    creds_list.append({
                        "port": port,
                        "username": c.get("username"),
                        "password": c.get("password")
                    })

            # ── HÔTES COMPROMIS (lateral movement) ──
            lm_results = state.get("lateral_movement_results", {})
            hosts_compromised = lm_results.get("results", {}).get("sessions_count", 0)

            result = {
                "status": "running" if _running else "idle",
                "session_id": _current_session_id,
                "phases_done": phases_done,
                "success_by_phase": success_dict,
                "open_ports": open_ports,
                "credentials_found": {"ssh": creds_list},
                "hosts_compromised": hosts_compromised,
                "elapsed": state.get("elapsed", 0)
            }

            if include_details:
                result["details"] = {
                    "steps_results": steps_results,
                    "state": {k: v for k, v in state.items() if not k.startswith("_")}
                }

            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — GET ATTACK REPORT
# ═══════════════════════════════════════════════════════════════════════════════

class GetAttackReport(BaseTool):
    name: str = "get_attack_report"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    📄 GET_ATTACK_REPORT — RAPPORT FINAL DE L'ATTAQUE
    ═══════════════════════════════════════════════════════════════════════════

    📌 Génère le rapport complet de l'attaque.
    Format : JSON (structuré) ou Markdown (lisible).

    📥 PARAMÈTRES (JSON) :
    {
        "format": "json"    // "json" ou "markdown"
    }

    📤 RETOUR (JSON) :
    {
        "format": "json",
        "session_id": "simatk-xxxxx",
        "summary": {
            "total_phases": 9,
            "successful_phases": 7,
            "credentials_found": 3,
            "hosts_compromised": 2,
            "total_elapsed": 45.2
        },
        "kill_chain": [
            {"phase": "reconnaissance", "status": "success", "mitre_techniques": ["T1046"]},
            ...
        ],
        "vulnerabilities": [
            {"technique": "T1046", "name": "Network Service Discovery", "severity": "LOW"},
            ...
        ],
        "recommendations": [
            "Désactiver les services inutiles",
            "Mettre à jour les mots de passe par défaut"
        ]
    }

    ⚡ EXEMPLE :
    get_attack_report(format="markdown")
    """
    args_schema: type[BaseModel] = GetReportInput
    description_updated: bool = True

    def _run(self, format: str = "json") -> str:
        try:
            orchestrator = get_orchestrator()
            report = orchestrator.final_result.get("report", {})
            state = orchestrator.final_result.get("state", {})

            if format == "markdown":
                # Générer du Markdown
                lines = []
                lines.append("# 🎯 ShieldAI — Rapport d'Attaque\n")
                lines.append(f"**Session ID** : `{_current_session_id}`")
                lines.append(f"**Date** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

                lines.append("## 📊 Résumé\n")
                lines.append(f"- **Phases terminées** : {len(state.get('already_done', []))}")
                lines.append(f"- **Credentials trouvés** : {len(state.get('ssh_brute_force_found_credentials', {}))}")
                lines.append(f"- **Hôtes compromis** : {state.get('lateral_movement_results', {}).get('results', {}).get('sessions_count', 0)}")

                lines.append("\n## 🔗 Kill Chain\n")
                success_dict = state.get("success_dict", {})
                for phase, success in success_dict.items():
                    emoji = "✅" if success else "❌"
                    lines.append(f"- {emoji} **{phase}**")

                lines.append("\n## 🛡️ Recommandations\n")
                lines.append("- Vérifier les mots de passe par défaut")
                lines.append("- Désactiver les services inutiles")
                lines.append("- Mettre en place un système de détection")

                return "\n".join(lines)

            # Format JSON
            summary = {
                "total_phases": len(state.get("already_done", [])),
                "successful_phases": sum(1 for v in state.get("success_dict", {}).values() if v),
                "credentials_found": sum(len(c) for c in state.get("ssh_brute_force_found_credentials", {}).values()),
                "hosts_compromised": state.get("lateral_movement_results", {}).get("results", {}).get("sessions_count", 0),
                "total_elapsed": state.get("elapsed", 0)
            }

            return json.dumps({
                "format": "json",
                "session_id": _current_session_id,
                "summary": summary,
                "report": report,
                "state": state,
                "timestamp": datetime.now().isoformat()
            }, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — LIST CHECKPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

class ListCheckpoints(BaseTool):
    name: str = "list_checkpoints"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    📋 LIST_CHECKPOINTS — LISTER LES SESSIONS SAUVEGARDÉES
    ═══════════════════════════════════════════════════════════════════════════

    📌 Liste toutes les sessions d'attaque sauvegardées dans les checkpoints.
    Utile pour savoir quelles sessions sont disponibles pour reprise.

    📥 PARAMÈTRES (JSON) :
    {
        "limit": 20
    }

    📤 RETOUR (JSON) :
    {
        "total": 2,
        "checkpoints": [
            {
                "session_id": "simatk-abc123",
                "target_ip": "172.17.0.2",
                "timestamp": "2026-06-18 10:30:00",
                "phases_done": ["Reconnaissance", "InitialAccess", "Execution"],
                "actuel_step": "DefenseEvasion", #derniere étape ou étae actuelle
                "credentials_ssh_count": 3,
                "open_ports": [22, 80, 443],
                "checkpoints_count": 5,
                "size_kb": 42.5
            }
        ]
    }

    ⚡ EXEMPLE :
    list_checkpoints(limit=10)
    """
    args_schema: type[BaseModel] = ListCheckpointsInput
    description_updated: bool = True

    def _run(self, limit: int = 20) -> str:
        try:
            orchestrator = get_orchestrator()
            db_path = orchestrator.checkpoint_path + "_graphe_checkpoint.db"

            if not os.path.exists(db_path):
                return json.dumps({
                    "total": 0,
                    "checkpoints": [],
                    "message": "Aucun checkpoint trouvé."
                }, ensure_ascii=False)
            
            checkpoints_list = []
            
            with SqliteSaver.from_conn_string(db_path) as checkpointer:
                
                # ── Lire les thread_id depuis la DB ──
                conn = sqlite3.connect(db_path)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA read_uncommitted=ON")
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                try:
                    cursor.execute("SELECT DISTINCT thread_id FROM checkpoints LIMIT ?", (limit,))
                    threads = cursor.fetchall()
                    
                    for thread_row in threads:
                        thread_id = thread_row['thread_id']
                        config = {"configurable": {"thread_id": thread_id}}
                        
                        try:
                            # ── Récupérer les checkpoints de ce thread ──
                            checkpoints = list(checkpointer.list(config, limit=5))
                            
                            if checkpoints:
                                latest = checkpoints[0]
                                checkpoint_data = latest.checkpoint
                                channel_values = checkpoint_data.get('channel_values', {})
                                
                                # ── Extraire les données ──
                                target_ip = channel_values.get('ip', 'N/A')
                                
                                # Phases (déjà en str grâce à ta correction)
                                phases_done = channel_values.get('already_done', [])
                                phases_done = [str(p) for p in phases_done]
                                
                                # Credentials SSH
                                ssh_creds = channel_values.get('ssh_brute_force_found_credentials', {})
                                creds_count = sum(len(c) for c in ssh_creds.values())
                                
                                # Ports ouverts
                                open_ports = channel_values.get('open_ports', [])
                                
                                # Timestamp
                                ts = checkpoint_data.get('ts', 'N/A')
                                
                                # Taille
                                size_kb = round(len(str(checkpoint_data)) / 1024, 2)
                                
                                checkpoints_list.append({
                                    "session_id": thread_id,
                                    "target_ip": target_ip,
                                    "timestamp": ts,
                                    "phases_done": phases_done,
                                    "actuel_step": channel_values.get("actuel_step", "N/A"),
                                    "credentials_ssh_count": creds_count,
                                    "open_ports": open_ports,
                                    "checkpoints_count": len(checkpoints),
                                    "size_kb": size_kb
                                })
                                
                        except Exception as e:
                            # Skip ce thread en cas d'erreur
                            continue
                            
                except sqlite3.OperationalError as e:
                    return json.dumps({
                        "total": 0,
                        "checkpoints": [],
                        "error": f"Base de données verrouillée: {str(e)}",
                        "solution": "Arrêtez l'attaque en cours ou utilisez un autre checkpoint_path."
                    }, ensure_ascii=False)
                
                finally:
                    conn.close()
            
            return json.dumps({
                "total": len(checkpoints_list),
                "checkpoints": checkpoints_list
            }, ensure_ascii=False, indent=2)

        except ImportError:
            return json.dumps({
                "total": 0,
                "checkpoints": [],
                "error": "LangGraph non installé. Installe: pip install langgraph"
            }, ensure_ascii=False)
            
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            }, ensure_ascii=False)
# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 8 — SET CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

class SetConfig(BaseTool):
    name: str = "set_config"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    ⚙️ SET_CONFIG — MODIFIER LA CONFIGURATION
    ═══════════════════════════════════════════════════════════════════════════

    📌 Modifie un paramètre de configuration de l'orchestrateur.

    📥 PARAMÈTRES (JSON) :
    {
        "key": "ip",                // Clé à modifier
        "value": "192.168.1.10"     // Nouvelle valeur
    }

    📤 RETOUR (JSON) :
    {
        "status": "success",
        "key": "ip",
        "old_value": "172.17.0.2",
        "new_value": "192.168.1.10"
    }

    🔑 CLÉS DISPONIBLES :
    - ip : IP cible
    - network_discover_port_range : [22, 80, 443, 8080]
    - ssh_brute_force_usernames : ["root", "admin"]
    - ssh_brute_force_passwords : ["toor", "password"]
    - reverse_shell_attaquant_ip : "172.17.0.1"
    - lateral_movement_max_depth : 3
    - exfiltration_c2_url : "http://127.0.0.1:8888/exfil"

    ⚡ EXEMPLE :
    set_config(key="ip", value="192.168.1.100")
    """
    args_schema: type[BaseModel] = SetConfigInput
    description_updated: bool = True

    def _run(self, key: str, value: Any) -> str:
        try:
            orchestrator = get_orchestrator()
            old_value = orchestrator.conf.get(key)

            orchestrator.conf[key] = value

            # Si la clé est "ip", mettre à jour dans l'état
            if key == "ip" and hasattr(orchestrator, "final_result"):
                if "state" in orchestrator.final_result:
                    orchestrator.final_result["state"]["ip"] = value

            return json.dumps({
                "status": "success",
                "key": key,
                "old_value": old_value,
                "new_value": value,
                "message": f"✅ {key} = {value}"
            }, ensure_ascii=False)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 9 — GET CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

class GetConfig(BaseTool):
    name: str = "get_config"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    👁️ GET_CONFIG — VOIR LA CONFIGURATION
    ═══════════════════════════════════════════════════════════════════════════

    📌 Affiche la configuration actuelle de l'orchestrateur.

    📥 PARAMÈTRES (JSON) :
    {
        "key": "ip"    // Optionnel : clé spécifique
    }

    📤 RETOUR (JSON) :
    {
        "config": {
            "ip": "172.17.0.2",
            "network_discover_port_range": [22, 80, 443],
            ...
        }
    }

    ⚡ EXEMPLE :
    get_config(key="ip")
    """
    args_schema: type[BaseModel] = GetConfigInput
    description_updated: bool = True

    def _run(self, key: Optional[str] = None) -> str:
        try:
            orchestrator = get_orchestrator()

            if key:
                return json.dumps({
                    "key": key,
                    "value": orchestrator.conf.get(key)
                }, ensure_ascii=False)

            return json.dumps({
                "config": orchestrator.conf
            }, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 10 — STOP ATTACK
# ═══════════════════════════════════════════════════════════════════════════════

class StopAttack(BaseTool):
    name: str = "stop_attack"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    🛑 STOP_ATTACK — ARRÊTER L'ATTAQUE (KILL MODE)
    ═══════════════════════════════════════════════════════════════════════════

    📌 Arrête immédiatement l'attaque :
    1. Tue le container Docker (kill + remove)
    2. Annule la tâche asyncio en cours
    3. Réinitialise l'état

    🚨 ACTION IRRÉVERSIBLE.

    📤 RETOUR (JSON) :
    {
        "status": "killed",
        "message": "Container tué et attaque arrêtée",
        "container_name": "shieldai_test",
        "session_id": "simatk-xxxxx"
    }

    ⚡ EXEMPLE :
    stop_attack()

    ⚠️ À utiliser en dernier recours ! Les checkpoints permettent de reprendre.
    """
    args_schema: type[BaseModel] = StopAttackInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> str:
        global _running

        try:
            orchestrator = get_orchestrator()
            container_name = "unknown"

            # ── 1. TUER LE CONTAINER ──
            if orchestrator.dock_manager:
                container_name = orchestrator.dock_manager.container.name if orchestrator.dock_manager.container else "unknown"
                orchestrator.dock_manager.stop()  # kill + remove
                logger.print(f"💀 Container tué: {container_name}")

            # ── 3. RÉINITIALISER L'ÉTAT ──
            _running = False

            return json.dumps({
                "status": "killed",
                "message": "Container tué et attaque arrêtée",
                "container_name": container_name,
                "session_id": _current_session_id
            }, ensure_ascii=False)

        except Exception as e:
            logger.print(f"❌ Erreur stop_attack: {e}")
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 11 — CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

class Cleanup(BaseTool):
    name: str = "cleanup"
    description: str = """
    ═══════════════════════════════════════════════════════════════════════════
    🧹 CLEANUP — NETTOYER L'ENVIRONNEMENT
    ═══════════════════════════════════════════════════════════════════════════

    📌 Nettoie l'environnement de test :
    - Supprime le container Docker
    - Supprime les checkpoints (optionnel)
    - Libère les ressources

    📥 PARAMÈTRES (JSON) :
    {
        "remove_container": true,
        "remove_checkpoints": false
    }

    📤 RETOUR (JSON) :
    {
        "status": "success",
        "container_removed": true,
        "checkpoints_removed": false,
        "message": "🧹 Environnement nettoyé."
    }

    ⚡ EXEMPLE :
    cleanup(remove_container=True, remove_checkpoints=True)
    """
    args_schema: type[BaseModel] = CleanupInput
    description_updated: bool = True

    def _run(self, remove_container: bool = True, remove_checkpoints: bool = False) -> str:
        global _environment, _orchestrator, _llm

        try:
            container_removed = False
            checkpoints_removed = False

            # ── 1. SUPPRIMER LE CONTAINER ──
            if remove_container and _environment:
                try:
                    _environment.teardown()
                    container_removed = True
                    logger.print("🧹 Container supprimé")
                except Exception as e:
                    logger.print(f"⚠️ Erreur suppression container: {e}")

            # ── 2. SUPPRIMER LES CHECKPOINTS ──
            if remove_checkpoints and _orchestrator:
                checkpoint_path = _orchestrator.checkpoint_path + "_graphe_checkpoint.db"
                if os.path.exists(checkpoint_path):
                    try:
                        os.remove(checkpoint_path)
                        checkpoints_removed = True
                        logger.print("🧹 Checkpoints supprimés")
                    except Exception as e:
                        logger.print(f"⚠️ Erreur suppression checkpoints: {e}")

            # ── 3. NETTOYER LE LLM ──
            if _llm:
                try:
                    _llm.stop()
                    logger.print("🧹 LLM arrêté")
                except Exception as e:
                    logger.print(f"⚠️ Erreur arrêt LLM: {e}")

            # ── 4. RÉINITIALISER L'ÉTAT ──
            _environment = None
            _orchestrator = None
            _llm = None
            _running = False

            return json.dumps({
                "status": "success",
                "container_removed": container_removed,
                "checkpoints_removed": checkpoints_removed,
                "message": "🧹 Environnement nettoyé avec succès."
            }, ensure_ascii=False)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })


# ═══════════════════════════════════════════════════════════════════════════════
# LISTE DE TOUS LES OUTILS — 11 OUTILS DE LÉGENDE
# ═══════════════════════════════════════════════════════════════════════════════

ALL_SIMULATOR_TOOLS = [
    InitOrchestrator(),
    CloneSystem(),
    RunAttack(),
    ExecutePhase(),
    GetAttackStatus(),
    GetAttackReport(),
    ListCheckpoints(),
    SetConfig(),
    GetConfig(),
    StopAttack(),
    Cleanup(),
]