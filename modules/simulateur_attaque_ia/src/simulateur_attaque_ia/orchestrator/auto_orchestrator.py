#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 22:04:00 2026
@author: hounsousamuel

AutoAttackOrchestrator - Orchestre l'exécution des payloads MITRE ATT&CK

Version refactorée : délègue toute la logique métier à graph_nodes.
Les méthodes d'instance sont de simples wrappers qui appellent les fonctions pures.
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import json5
import asyncio
from datetime import datetime, timezone
from typing import TypedDict, List, Dict, Tuple, Any, Callable, Awaitable, Optional
from dataclasses import dataclass, field
from typing import List, Optional
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from uuid import uuid4
from simulateur_attaque_ia.simulateur_utils.ids_utils import random_session_id
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.orchestrator.graph_nodes import (
    SimulatorStep,
    graph_entry_point,
    graph_initial_access,
    graph_execution,
    graph_persistence,
    graph_exfiltration,
    graph_credential_access,
    graph_lateral_movement,
    graph_defense_evasion,
    graph_privilege_escalation,
    graph_report,
    graph_conditional_edge,
    graph_conditional_edge_with_llm,
)
from simulateur_attaque_ia.tactics.base import Base
from simulateur_attaque_ia.tactics.mittres import MITRE
from simulateur_attaque_ia.simulateur_utils.signal_manager import signal_manager
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager
from simulateur_attaque_ia.simulateur_utils.utils import silence_output

logger = get_logger()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_DIR = os.path.join(BASE_DIR, "data", "checkpoint")
CONFIG_DIR     = os.path.join(BASE_DIR, "data", "config")
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

# Type du callback dashboard
DashboardCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]

class SimulatorError(Exception):
    """Exception spécifique du simulateur."""
    def __init__(self, *args):
        self.message = None


class SimulatorState(TypedDict):
    """État du simulateur pour LangGraph - Complètement sérialisable."""
    ip: str
    steps_results: Dict[str, List[Dict[str, Any]]]
    actual_step: str
    actual_action: List[str]
    success_dict: Dict[str, bool]
    error_dict: Dict[str, List[str]]
    finish: bool
    pivot_errors: List[str]
    already_done: List[str]
    created_files: List[str]

    # NetworkServiceDiscover
    network_discover_timeout_socket: float
    network_discover_port_range: List | range | Tuple
    open_ports: List[int]
    port_function: Dict[str, List[int]]

    # SSHBruteForce
    ssh_brute_force_timeout: float
    ssh_brute_force_total_timeout: float | None
    ssh_brute_force_delay: float
    ssh_brute_force_max_attempts: int
    ssh_brute_force_add_common: bool
    ssh_brute_force_usernames: List[str]
    ssh_brute_force_passwords: List[str]
    ssh_brute_force_found_credentials: Dict[int, List[Dict[str, str]]]

    # FTPBruteForce
    ftp_brute_force_timeout: float
    ftp_brute_force_total_timeout: float | None
    ftp_brute_force_max_attempts: int
    ftp_brute_force_add_common: bool
    ftp_brute_force_usernames: List[str]
    ftp_brute_force_passwords: List[str]
    ftp_brute_force_found_credentials: Dict[int, List[Dict[str, str]]]

    # HTTPBruteForce
    http_brute_force_timeout: float
    http_brute_force_preference: str
    http_brute_force_add_common: bool
    http_brute_force_paths: List[str]
    http_brute_force_found_credentials: Dict[int, List[Dict[str, str]]]

    # Execution
    command_execution_timeout: float
    command_execution_exec_timeout: float
    command_execution_commands: List[str]
    command_execution_add_common: bool
    command_execution_quick: bool
    command_execution_results: Dict[str, Any]

    python_execution_timeout: float
    python_execution_exec_timeout: float
    python_execution_commands: List[str]
    python_execution_add_common: bool
    python_execution_quick: bool
    python_execution_results: Dict[str, Any]

    # Persistence
    ssh_key_timeout: float
    ssh_key_exec_timeout: float
    ssh_key_algo: str
    ssh_key_results: Dict[str, Any]

    cron_script_path: str
    cron_expression: str
    cron_level: str
    cron_results: Dict[str, Any]

    # ReverseShell
    reverse_shell_attaquant_ip: str
    reverse_shell_attaquant_port: int
    reverse_shell_timeout: float
    reverse_shell_exec_timeout: float
    reverse_shell_listener_timeout: float
    reverse_shell_total_timeout: float
    reverse_shell_commands: List[str]
    
    # Privilege Escalation
    privilege_escalation_timeout: float
    privilege_escalation_exec_timeout: float
    privilege_escalation_results: Dict[str, Any]
    privilege_escalation_success: bool
 
    # Credential Access
    credential_access_timeout: float
    credential_access_exec_timeout: float
    credential_access_results: Dict[str, Any]
 
    # Lateral Movement
    lateral_movement_max_depth: int
    lateral_movement_max_workers: int
    lateral_movement_join_timeout: float | None
    lateral_movement_usable_keys: List[Dict]
    lateral_movement_known_hosts: List[Dict]
    lateral_movement_results: Dict[str, Any]
 
    # Exfiltration
    exfiltration_c2_url: str
    exfiltration_timeout: int
    exfiltration_results: Dict[str, Any]
 
    # Defense Evasion
    defense_evasion_timeout: float
    defense_evasion_exec_timeout: float
    defense_evasion_results: Dict[str, Any]


SIMULATOR_STATE_KEYS = list(SimulatorState.__annotations__.keys())

@dataclass
class ReconConfig:
    port_range: List[int] = field(default_factory=lambda: list(range(8080, 8100)) + [22, 21])
    timeout_socket: float = 0.2
    
    def __post_init__(self):
       self.port_range = [p for p in self.port_range if 0 <= p <= 65535]

@dataclass
class SSHBruteConfig:
    timeout: float = 5.0
    total_timeout: Optional[float] = None
    delay: float = 0.2
    max_attempts: int = 50
    add_common: bool = True
    usernames: List[str] = field(default_factory=lambda: ["root", "admin", "testuser", "ubuntu", "user"])
    passwords: List[str] = field(default_factory=lambda: ["toor", "password", "admin123", "root", "123456"])


@dataclass
class FTPBruteConfig:
    timeout: float = 5.0
    total_timeout: Optional[float] = None
    max_attempts: int = 50
    add_common: bool = True
    usernames: List[str] = field(default_factory=lambda: ["root", "admin", "testuser", "anonymous"])
    passwords: List[str] = field(default_factory=lambda: ["toor", "password", "admin123", "anonymous"])


@dataclass
class HTTPBruteConfig:
    timeout: float = 3.0
    preference: str = "http://"
    add_common: bool = True
    paths: List[str] = field(default_factory=lambda: [
        "/admin", "/login", "/backup", "/config", "/api",
        "/phpmyadmin", "/wp-admin", "/console", "/panel", "/portal"
    ])


@dataclass
class ExecutionConfig:
    timeout: float = 2.0
    exec_timeout: float = 10.0
    commands: List[str] = field(default_factory=list)
    add_common: bool = True
    quick: bool = True


@dataclass
class ReverseShellConfig:
    attaquant_ip: str = "172.17.0.1"
    attaquant_port: int = 4444
    timeout: float = 2.0
    exec_timeout: float = 30.0
    listener_timeout: float = 15.0
    total_timeout: float = 60.0
    commands: List[str] = field(default_factory=lambda: ["whoami", "id", "hostname", "pwd", "ls -la"])


@dataclass
class PersistenceConfig:
    ssh_key_timeout: float = 2.0
    ssh_key_exec_timeout: float = 5.0
    ssh_key_algo: str = "RSA"
    cron_script_path: str = "/opt/backdoor.sh"
    cron_expression: str = "*/1 * * * *"
    cron_level: str = "simple"


@dataclass
class PrivescConfig:
    timeout: float = 2.0
    exec_timeout: float = 10.0


@dataclass
class CredentialAccessConfig:
    timeout: float = 2.0
    exec_timeout: float = 10.0


@dataclass
class LateralMovementConfig:
    max_depth: int = 3
    max_workers: int = 5
    join_timeout: float = 60.0


@dataclass
class ExfiltrationConfig:
    c2_url: str = "http://127.0.0.1:8888/exfil"
    timeout: int = 10


@dataclass
class DefenseEvasionConfig:
    timeout: float = 2.0
    exec_timeout: float = 10.0


# ── Config principale ─────────────────────────────────────────────────────────

@dataclass
class SimulatorConfig:
    ip: str = "172.17.0.2"
    recon: ReconConfig = field(default_factory=ReconConfig)
    ssh: SSHBruteConfig = field(default_factory=SSHBruteConfig)
    ftp: FTPBruteConfig = field(default_factory=FTPBruteConfig)
    http: HTTPBruteConfig = field(default_factory=HTTPBruteConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    python_execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    reverse_shell: ReverseShellConfig = field(default_factory=ReverseShellConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)
    privesc: PrivescConfig = field(default_factory=PrivescConfig)
    credential_access: CredentialAccessConfig = field(default_factory=CredentialAccessConfig)
    lateral_movement: LateralMovementConfig = field(default_factory=LateralMovementConfig)
    exfiltration: ExfiltrationConfig = field(default_factory=ExfiltrationConfig)
    defense_evasion: DefenseEvasionConfig = field(default_factory=DefenseEvasionConfig)

    def to_state_dict(self) -> dict:
        """
        Conversion vers le format plat attendu par SimulatorState / LangGraph.
        """
        return {
            "ip": self.ip,
            "created_files": [],

            # Recon
            "network_discover_port_range":    self.recon.port_range,
            "network_discover_timeout_socket": self.recon.timeout_socket,

            # SSH
            "ssh_brute_force_timeout":          self.ssh.timeout,
            "ssh_brute_force_total_timeout":    self.ssh.total_timeout,
            "ssh_brute_force_delay":            self.ssh.delay,
            "ssh_brute_force_max_attempts":     self.ssh.max_attempts,
            "ssh_brute_force_add_common":       self.ssh.add_common,
            "ssh_brute_force_usernames":        self.ssh.usernames,
            "ssh_brute_force_passwords":        self.ssh.passwords,

            # FTP
            "ftp_brute_force_timeout":          self.ftp.timeout,
            "ftp_brute_force_total_timeout":    self.ftp.total_timeout,
            "ftp_brute_force_max_attempts":     self.ftp.max_attempts,
            "ftp_brute_force_add_common":       self.ftp.add_common,
            "ftp_brute_force_usernames":        self.ftp.usernames,
            "ftp_brute_force_passwords":        self.ftp.passwords,

            # HTTP
            "http_brute_force_timeout":         self.http.timeout,
            "http_brute_force_preference":      self.http.preference,
            "http_brute_force_add_common":      self.http.add_common,
            "http_brute_force_paths":           self.http.paths,

            # Execution
            "command_execution_timeout":        self.execution.timeout,
            "command_execution_exec_timeout":   self.execution.exec_timeout,
            "command_execution_commands":       self.execution.commands,
            "command_execution_add_common":     self.execution.add_common,
            "command_execution_quick":          self.execution.quick,

            # Python Execution
            "python_execution_timeout":         self.python_execution.timeout,
            "python_execution_exec_timeout":    self.python_execution.exec_timeout,
            "python_execution_commands":        self.python_execution.commands,
            "python_execution_add_common":      self.python_execution.add_common,
            "python_execution_quick":           self.python_execution.quick,

            # Reverse Shell
            "reverse_shell_attaquant_ip":       self.reverse_shell.attaquant_ip,
            "reverse_shell_attaquant_port":     self.reverse_shell.attaquant_port,
            "reverse_shell_timeout":            self.reverse_shell.timeout,
            "reverse_shell_exec_timeout":       self.reverse_shell.exec_timeout,
            "reverse_shell_listener_timeout":   self.reverse_shell.listener_timeout,
            "reverse_shell_total_timeout":      self.reverse_shell.total_timeout,
            "reverse_shell_commands":           self.reverse_shell.commands,

            # Persistence
            "ssh_key_timeout":                  self.persistence.ssh_key_timeout,
            "ssh_key_exec_timeout":             self.persistence.ssh_key_exec_timeout,
            "ssh_key_algo":                     self.persistence.ssh_key_algo,
            "cron_script_path":                 self.persistence.cron_script_path,
            "cron_expression":                  self.persistence.cron_expression,
            "cron_level":                       self.persistence.cron_level,

            # Privesc
            "privilege_escalation_timeout":     self.privesc.timeout,
            "privilege_escalation_exec_timeout": self.privesc.exec_timeout,

            # Credential Access
            "credential_access_timeout":        self.credential_access.timeout,
            "credential_access_exec_timeout":   self.credential_access.exec_timeout,

            # Lateral Movement
            "lateral_movement_max_depth":       self.lateral_movement.max_depth,
            "lateral_movement_max_workers":     self.lateral_movement.max_workers,
            "lateral_movement_join_timeout":    self.lateral_movement.join_timeout,

            # Exfiltration
            "exfiltration_c2_url":              self.exfiltration.c2_url,
            "exfiltration_timeout":             self.exfiltration.timeout,

            # Defense Evasion
            "defense_evasion_timeout":          self.defense_evasion.timeout,
            "defense_evasion_exec_timeout":     self.defense_evasion.exec_timeout,
        }

DEFAULT_INPUT_DICT = SimulatorConfig().to_state_dict()

# Progress par étape — extensible facilement quand tu ajoutes des étapes
STEP_PROGRESS = {
    SimulatorStep.RECONNAISSANCE:       0.10,
    SimulatorStep.INITIAL_ACCESS:       0.20,
    SimulatorStep.EXECUTION:            0.35,
    SimulatorStep.PRIVILEGE_ESCALATION: 0.45,
    SimulatorStep.CREDENTIAL_ACCESS:    0.55,
    SimulatorStep.LATERAL_MOVEMENT:     0.65,
    SimulatorStep.EXFILTRATION:         0.75,
    SimulatorStep.DEFENSE_EVASION:      0.85,
    SimulatorStep.PERSISTENCE:          0.93,
    SimulatorStep.REPORT:               1.0,
}


def _now() -> str:
    """Retourne l'horodatage courant au format ISO avec millisecondes."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


class AutoAttackOrchestrator(Base):
    """
    Orchestre l'exécution des payloads MITRE ATT&CK.

    La logique métier est déléguée aux fonctions pures de graph_nodes.
    Les wrappers d'instance gèrent le callback dashboard.
    """

    __slots__ = (
        "name", "dock_manager", "current_session_id",
        "checkpoint_path", "graph", "_nodes",
        "config_path", "final_result", "debug",
        "dashboard_callback", "llm", "_use_llm", 
        "out", "err"
    )

    def __init__(
        self,
        docker_manager: DockerManager,
        checkpoint_path: str | None = None,
        config_path: str | None = None,
        debug: bool = False,
        llm: LLMManager | None = None,
        use_llm: bool = False,
        dashboard_callback: DashboardCallback = None,
        **kwargs
    ):
        """
        Initialise l'orchestrateur d'attaque.

        Args:
            docker_manager: Gestionnaire Docker pour les interactions conteneurs.
            checkpoint_path: Chemin pour les checkpoints SQLite.
            config_path: Chemin vers le fichier de configuration JSON5.
            debug: Mode debug - affiche les logs dans le terminal.
            dashboard_callback: Coroutine appelée à chaque événement dashboard.
            **kwargs: Arguments supplémentaires.
        """
        self.name = AutoAttackOrchestrator.__name__
        super().__init__(self.name, **kwargs)
        self.dock_manager = docker_manager
        self.checkpoint_path = checkpoint_path or "auto_orchestrator_checkpoint"
        self.checkpoint_path = os.path.join(CHECKPOINT_DIR, self.checkpoint_path)
        self._nodes = self.get_nodes()
        self.graph = None
        self.config_path = config_path or "default_config.json5"
        self.config_path = os.path.join(CONFIG_DIR, self.config_path)
        self.final_result = {"state": {}, "report": {}, "logs": [], "out": None, "err": None}
        self.debug = debug
        self.dashboard_callback = dashboard_callback
        self.current_session_id = None
        self.llm = llm
        self._use_llm = use_llm
        if self._use_llm and not self.llm:
            raise RuntimeError("Bad config, llm is None but user wan't use llm !")
        self.log(f"AutoAttackOrchestrator initialisé (debug={self.debug})", log=self.debug)

    # =========================================================================
    # CALLBACK DASHBOARD
    # =========================================================================
    
    async def _exec_func(self, func, *args, **kwargs):
        r = func(*args, **kwargs)
        if asyncio.iscoroutine(r):
            r = await r
        
        return r
    
    async def _emit(self, msg: Dict[str, Any]) -> None:
        """
        Envoie un message au dashboard si le callback est défini.

        Args:
            msg: Message à envoyer au dashboard.
        """
        if self.dashboard_callback:
            try:
                await self._exec_func(
                    self.dashboard_callback,
                    msg, self.current_session_id, in_dev=True
                )
                # if self.debug:
                self.log(f"Emit : {json5.dumps(msg, default=str)}", log=self.debug)
                self.final_result.setdefault("logs", []).append(msg)
            except Exception as e:
                self.log(f"⚠️ Erreur dashboard_callback: {e}", log=self.debug)

    def _msg(
        self,
        type_: str,
        step: SimulatorStep | None,
        message: str,
        data: Dict[str, Any] = None,
        progress: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Fabrique un message dashboard standardisé.

        Args:
            type_: Type de message (step_start, step_end, finish, error).
            step: Étape concernée (SimulatorStep ou None).
            message: Message textuel.
            data: Données supplémentaires.
            progress: Progression (0.0 à 1.0).

        Returns:
            Dictionnaire formaté pour le dashboard.
        """
        return {
            "type":      type_,
            "step":      step.value if step else None,
            "timestamp": _now(),
            "progress":  progress,
            "message":   message,
            "data":      data or {},
        }

    # =========================================================================
    # GRAPH SETUP
    # =========================================================================

    def get_nodes(self) -> List[Tuple[str, callable, Dict[str, Any]]]:
        """
        Définit les nœuds du graphe LangGraph.

        Returns:
            Liste des nœuds avec leur nom, fonction associée et métadonnées.
        """
        return [
            (
                "reconnaissance",
                self.graph_entry_point,
                {
                    "description": "Port scan et banner grab pour découvrir les services ouverts",
                    "tactic": "Discovery",
                    "techniques": [MITRE["PortScan"], MITRE["BannerGrab"]],
                }
            ),
            (
                "initial_access",
                self.graph_initial_access,
                {
                    "description": "Bruteforce SSH, FTP et HTTP sur les ports découverts",
                    "tactic": "Initial Access",
                    "techniques": [
                        MITRE["SSHBruteForce"],
                        MITRE["FTPBruteForce"],
                        MITRE["HTTPBruteForce"]
                    ],
                }
            ),
            (
                "execution",
                self.graph_execution,
                {
                    "description": "Exécution de commandes, scripts Python et reverse shell",
                    "tactic": "Execution",
                    "techniques": [
                        MITRE["CommandLineExecution"],
                        MITRE["PythonExecution"],
                        MITRE["ReverseShell"],
                    ]
                }
            ),
            (
                "privilege_escalation",
                self.graph_privilege_escalation,
                {
                    "description": "Élévation de privilèges via sudo et SUID",
                    "tactic": "Privilege Escalation",
                    "techniques": [
                        MITRE["SudoExploit"],
                        MITRE["SUIDBinary"],
                    ]
                }
            ),
            (
                "credential_access",
                self.graph_credential_access,
                {
                    "description": "Vol de credentials, clés SSH et historique bash",
                    "tactic": "Credential Access",
                    "techniques": [
                        MITRE["PasswordFileDump"],
                        MITRE["BashHistoryRead"],
                        MITRE["SSHKeyTheft"],
                    ]
                }
            ),
            (
                "lateral_movement",
                self.graph_lateral_movement,
                {
                    "description": "Propagation latérale SSH dans le réseau",
                    "tactic": "Lateral Movement",
                    "techniques": [
                        MITRE["SSHLateralMovement"],
                    ]
                }
            ),
            (
                "exfiltration",
                self.graph_exfiltration,
                {
                    "description": "Exfiltration des données collectées vers un serveur C2",
                    "tactic": "Exfiltration",
                    "techniques": [
                        MITRE["DataExfiltrationHTTP"],
                    ]
                }
            ),
            (
                "defense_evasion",
                self.graph_defense_evasion,
                {
                    "description": "Nettoyage des traces et modification des timestamps",
                    "tactic": "Defense Evasion",
                    "techniques": [
                        MITRE["LogCleaning"],
                        MITRE["TimestampForgery"],
                    ]
                }
            ),
            (
                "persistence",
                self.graph_persistence,
                {
                    "description": "Installation de backdoors cron et injection de clés SSH",
                    "tactic": "Persistence",
                    "techniques": [
                        MITRE["CronBackdoor"],
                        MITRE["SSHKeyBackdoor"]
                    ]
                }
            ),
            (
                "finish_node",
                self.graph_finish_node,
                {
                    "description": "Terminaison de la campagne d'attaque",
                    "tactic": "None",
                }
            ),
            (
                "pivot_node",
                lambda state: state,
                {"description": "Orchestrateur central avec ou sans llm"}
            ),
            (
                "report",
                self.graph_report,
                {"description": "Noeud de rapport"}
            )
        ]

    def build_state_graph(self) -> SimulatorState:
        """
        Construit l'état initial du simulateur à partir de la configuration.

        Returns:
            État initial typé.
        """
        default_input_dict = {k: v for k, v in DEFAULT_INPUT_DICT.items()}
        try:
            with open(self.config_path, "r") as f:
                data = json5.load(f)
                default_input_dict.update({
                    k: v
                    for k, v in data.items()
                    if k in SIMULATOR_STATE_KEYS
                })
                if "network_discover_port_range" in default_input_dict:
                    raw_ports = default_input_dict["network_discover_port_range"]
                    default_input_dict["network_discover_port_range"] = [
                        p for p in raw_ports if isinstance(p, (int, float)) and 0 <= int(p) <= 65535
                    ]

        except Exception:
            pass
        self.log("État initial construit", log=self.debug)
        return SimulatorState(**default_input_dict)

    def override_signal_manager(self, *args, **kwargs):
        """Surcharge le gestionnaire de signaux."""
        def sig_manager(*args, **kwargs):
            pass
        signal_manager(sig_manager, *args, **kwargs)

    def build_graph(self, checkpointer=None) -> StateGraph:
        """
        Construit et compile le graphe LangGraph.

        Args:
            checkpointer: Checkpointer pour la persistance (AsyncSqliteSaver).

        Returns:
            Graphe compilé prêt pour l'exécution.
        """
        self.log("Construction du graphe LangGraph...", log=self.debug)
        builder = StateGraph(SimulatorState)
        conditionnal_func = (
            self.graph_conditional_edge_with_llm if self._use_llm
            else self.graph_conditional_edge
        )
        mapping = {
            "end": END,
            'reconnaissance': 'reconnaissance',
            'initial_access': 'initial_access',
            'execution': 'execution',
            'privilege_escalation': 'privilege_escalation',
            'credential_access': 'credential_access',
            'lateral_movement': 'lateral_movement',
            'exfiltration': 'exfiltration',
            'defense_evasion': 'defense_evasion',
            'persistence': 'persistence',
            'report': 'report',
            'Reconnaissance': "reconnaissance",
            'InitialAccess': "initial_access",
            'Execution': "execution",
            'PrivilegeEscalation': "privilege_escalation",
            'CredentialAccess': "credential_access",
            'LateralMovement': "lateral_movement",
            'Exfiltration': "exfiltration",
            'DefenseEvasion': "defense_evasion",
            'Persistence': "persistence",
            'Report': "report",
            "End": END,
        }
        for name, func, metadata in self._nodes:
            builder.add_node(name, func, metadata=metadata)
            if name not in ("finish_node", "pivot_node"):
                builder.add_edge(name, "pivot_node")
                mapping[name] = name
                

        builder.set_entry_point("reconnaissance")
        builder.set_finish_point("finish_node")
        builder.add_conditional_edges(
            "pivot_node",
            conditionnal_func,
            mapping
            
        )
        self.graph = builder.compile(checkpointer=checkpointer)
        self.log("Graphe compilé avec succès", log=self.debug)
        return self.graph

    # =========================================================================
    # WRAPPERS avec callback dashboard
    # =========================================================================

    async def graph_entry_point(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud de reconnaissance.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.RECONNAISSANCE
        await self._emit(self._msg(
            "step_start", step,
            "🔍 Reconnaissance — scan réseau en cours...",
            data={"ip": state.get("ip"), "port_range": str(state.get("network_discover_port_range"))},
            progress=0.0,
        ))

        result = await graph_entry_point(state)

        open_ports    = result.get("open_ports", [])
        port_function = result.get("port_function", {})
        success       = result.get("success_dict", {}).get("NetworkServiceDiscover|Reconnaissance", False)

        nsd_results = result.get("steps_results", {}).get("NetworkServiceDiscover|Reconnaissance", [])
        scan_result = nsd_results[0]["results"]["scan_result"] if nsd_results else {}

        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if success else '❌'} Reconnaissance terminée — {len(open_ports)} port(s) ouvert(s)",
            data={
                "open_ports":    open_ports,
                "port_function": port_function,
                "success":       success,
                "discoveries": [
                    {
                        "port":    port,
                        "service": scan_result.get(port, {}).get("service", "unknown"),
                        "banner":  scan_result.get(port, {}).get("banner", ""),
                    }
                    for port in open_ports
                ],
            },
            progress=STEP_PROGRESS[step],
        ))

        self.log(f"🏁 Reconnaissance — succès: {success}, ports: {len(open_ports)}", log=self.debug)
        return result

    async def graph_initial_access(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'accès initial.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.INITIAL_ACCESS
        await self._emit(self._msg(
            "step_start", step,
            "🔑 Initial Access — bruteforce SSH / FTP / HTTP...",
            data={"ports_cibles": state.get("port_function", {})},
            progress=STEP_PROGRESS[SimulatorStep.RECONNAISSANCE],
        ))

        result = await graph_initial_access(state)

        all_credentials = []
        steps_results = result.get("steps_results", {})
        for key, entries in steps_results.items():
            if "InitialAccess" not in key:
                continue
            service = key.split("|")[0].replace("BruteForce", "").lower()
            for entry in entries:
                port = entry.get("port", "?")
                founds = entry.get("result", {}).get("results", {}).get("founds", [])
                for cred in founds:
                    all_credentials.append({
                        "service":  service,
                        "port":     port,
                        "username": cred.get("username", ""),
                        "password": cred.get("password", ""),
                    })

        success_dict = result.get("success_dict", {})
        any_success  = any(v for k, v in success_dict.items() if "InitialAccess" in k)

        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if any_success else '❌'} Initial Access — {len(all_credentials)} credential(s) trouvé(s)",
            data={
                "credentials": all_credentials,
                "success":     any_success,
                "success_dict": {k: v for k, v in success_dict.items() if "InitialAccess" in k},
            },
            progress=STEP_PROGRESS[step],
        ))

        self.log(f"🏁 Initial Access — credentials: {len(all_credentials)}", log=self.debug)
        return result

    async def graph_execution(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'exécution.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.EXECUTION
        await self._emit(self._msg(
            "step_start", step,
            "⚡ Execution — commandes, Python, reverse shell...",
            progress=STEP_PROGRESS[SimulatorStep.INITIAL_ACCESS],
        ))

        result = await graph_execution(state)

        steps_results  = result.get("steps_results", {})
        success_dict   = result.get("success_dict", {})
        any_success    = any(v for k, v in success_dict.items() if "Execution" in k)

        commands_executed = []
        reverse_shell_data = {}

        for key, entries in steps_results.items():
            if "Execution" not in key:
                continue
            action = key.split("|")[0]

            for entry in entries:
                res = entry.get("result", {}).get("results", {})
                port = entry.get("port", "?")

                if action in ("CommandExecution", "PythonExecution"):
                    cmd_type = "command" if action == "CommandExecution" else "python"
                    for cmd_str, cmd_res in res.get("commands", {}).items():
                        commands_executed.append({
                            "type":       cmd_type,
                            "port":       port,
                            "cmd":        cmd_str,
                            "stdout":     cmd_res.get("stdout", ""),
                            "stderr":     cmd_res.get("stderr", ""),
                            "returncode": cmd_res.get("returncode", -1),
                        })

                elif action == "ReverseShell":
                    att = res.get("attaquant_result", {})
                    reverse_shell_data = {
                        "success":        att.get("success_count", 0) > 0,
                        "success_count":  att.get("success_count", 0),
                        "total_commands": att.get("total_commands", 0),
                        "elapsed":        att.get("elapsed", 0),
                        "commands":       att.get("success_commands", []),
                    }

        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if any_success else '❌'} Execution — {len(commands_executed)} commande(s) exécutée(s)",
            data={
                "commands_executed": commands_executed,
                "reverse_shell":     reverse_shell_data,
                "success":           any_success,
                "success_dict":      {k: v for k, v in success_dict.items() if "Execution" in k},
            },
            progress=STEP_PROGRESS[step],
        ))

        self.log(f"🏁 Execution — succès global: {any_success}", log=self.debug)
        return result

    async def graph_persistence(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud de persistance.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.PERSISTENCE
        await self._emit(self._msg(
            "step_start", step,
            "💾 Persistence — installation backdoors...",
            progress=STEP_PROGRESS[SimulatorStep.EXECUTION],
        ))

        state["dock_manager"] = self.dock_manager
        result = await graph_persistence(state)
        state.pop("dock_manager", None)

        steps_results = result.get("steps_results", {})
        success_dict  = result.get("success_dict", {})
        any_success   = any(v for k, v in success_dict.items() if "Persistence" in k)

        backdoors = []
        for key, entries in steps_results.items():
            if "Persistence" not in key:
                continue
            action = key.split("|")[0]

            for entry in entries:
                res = entry.get("result", {}).get("results", {})

                if action == "SshKeyBackdoor":
                    if res.get("success"):
                        backdoors.append({
                            "type":   "ssh_key",
                            "detail": f"public_key={str(res.get('public_key', ''))[:40]}...",
                            "port":   entry.get("port", "?"),
                        })

                elif action == "CronBackdoor":
                    if res.get("inject", {}).get("success"):
                        backdoors.append({
                            "type":   "cron",
                            "detail": state.get("cron_expression", ""),
                            "path":   state.get("cron_script_path", ""),
                            "method": res.get("method", "cron"),
                        })

        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if any_success else '❌'} Persistence — {len(backdoors)} backdoor(s) installée(s)",
            data={
                "backdoors":    backdoors,
                "success":      any_success,
                "success_dict": {k: v for k, v in success_dict.items() if "Persistence" in k},
            },
            progress=STEP_PROGRESS[step],
        ))

        self.log(f"🏁 Persistence — succès global: {any_success}", log=self.debug)
        return result
    
    async def graph_privilege_escalation(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'élévation de privilèges.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.PRIVILEGE_ESCALATION
        await self._emit(self._msg(
            "step_start", step,
            "⚡ Privilege Escalation — sudo exploit + SUID binaries...",
            progress=STEP_PROGRESS[SimulatorStep.EXECUTION],
        ))
        result = await graph_privilege_escalation(state)
        success = result.get("privilege_escalation_success", False)
        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if success else '⚠️'} Privilege Escalation — {'root obtenu' if success else 'pas de privesc'}",
            data={"privilege_escalation": result.get("privilege_escalation_results", {})},
            progress=STEP_PROGRESS[step],
        ))
        return result
 
    async def graph_credential_access(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'accès aux identifiants.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.CREDENTIAL_ACCESS
        await self._emit(self._msg(
            "step_start", step,
            "🔑 Credential Access — shadow dump, historique bash, clés SSH...",
            progress=STEP_PROGRESS[SimulatorStep.PRIVILEGE_ESCALATION],
        ))
        result = await graph_credential_access(state)
        keys_count = len(result.get("lateral_movement_usable_keys", []))
        await self._emit(self._msg(
            "step_end", step,
            f"✅ Credential Access — {keys_count} clé(s) SSH utilisable(s)",
            data={"credential_access": result.get("credential_access_results", {})},
            progress=STEP_PROGRESS[step],
        ))
        return result
 
    async def graph_lateral_movement(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud de mouvement latéral.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.LATERAL_MOVEMENT
        await self._emit(self._msg(
            "step_start", step,
            "🕸️  Lateral Movement — propagation réseau...",
            progress=STEP_PROGRESS[SimulatorStep.CREDENTIAL_ACCESS],
        ))
        result = await graph_lateral_movement(state)
        compromised = result.get("lateral_movement_results", {}).get("results", {}).get("sessions_count", 0)
        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if compromised else '❌'} Lateral Movement — {compromised} host(s) compromis",
            data={"lateral_movement": result.get("lateral_movement_results", {})},
            progress=STEP_PROGRESS[step],
        ))
        return result
 
    async def graph_exfiltration(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'exfiltration.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.EXFILTRATION
        await self._emit(self._msg(
            "step_start", step,
            "📤 Exfiltration — envoi données vers C2...",
            progress=STEP_PROGRESS[SimulatorStep.LATERAL_MOVEMENT],
        ))
        result = await graph_exfiltration(state)
        sent = result.get("exfiltration_results", {}).get("results", {}).get("sent_count", 0)
        await self._emit(self._msg(
            "step_end", step,
            f"{'✅' if sent else '❌'} Exfiltration — {sent} payload(s) envoyé(s)",
            data={"exfiltration": result.get("exfiltration_results", {})},
            progress=STEP_PROGRESS[step],
        ))
        return result
 
    async def graph_defense_evasion(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud d'évasion de défense.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.DEFENSE_EVASION
        await self._emit(self._msg(
            "step_start", step,
            "🧹 Defense Evasion — nettoyage des traces...",
            progress=STEP_PROGRESS[SimulatorStep.EXFILTRATION],
        ))
        result = await graph_defense_evasion(state)
        await self._emit(self._msg(
            "step_end", step,
            "✅ Defense Evasion — traces effacées",
            data={"defense_evasion": result.get("defense_evasion_results", {})},
            progress=STEP_PROGRESS[step],
        ))
        return result

    async def graph_report(self, state: SimulatorState) -> SimulatorState:
        """
        Wrapper pour le nœud de rapport.

        Args:
            state: État courant.

        Returns:
            État mis à jour.
        """
        step = SimulatorStep.REPORT
        await self._emit(self._msg(
            "step_start", step,
            "📊 Génération du rapport...",
            progress=STEP_PROGRESS[SimulatorStep.PERSISTENCE],
        ))

        result = await graph_report(state)
        self.final_result["report"] = result.get("report", {})

        await self._emit(self._msg(
            "step_end", step,
            "📋 Rapport généré",
            data={"report": self.final_result["report"]},
            progress=STEP_PROGRESS[step],
        ))

        self.log("🏁 Report généré", log=self.debug)
        return result

    async def graph_conditional_edge(self, state: SimulatorState) -> str:
        """
        Wrapper pour l'edge conditionnel.

        Args:
            state: État courant.

        Returns:
            Prochain nœud.
        """
        next_node = graph_conditional_edge(state)
        self.final_result["state"] = state
        self.log(f"🔄 Edge: {state.get('actual_step', '?')} → {next_node}", log=self.debug)
        return next_node

    async def graph_conditional_edge_with_llm(self, state: SimulatorState) -> str:
        """
        Wrapper pour l'edge conditionnel avec LLM.

        Args:
            state: État courant.

        Returns:
            Prochain nœud.
        """
        state["llm"] = self.llm
        next_node = await graph_conditional_edge_with_llm(state)
        state.pop("llm")
        self.final_result["state"] = state
        self.log(f"🔄 Edge (LLM): {state.get('actual_step', '?')} → {next_node}", log=self.debug)
        return next_node

    def graph_finish_node(self, state: SimulatorState) -> SimulatorState:
        """
        Nœud de fin - retourne l'état inchangé.

        Args:
            state: État courant.

        Returns:
            État inchangé.
        """
        self.log("🏁 Nœud de fin atteint", log=self.debug)
        return state

    # =========================================================================
    # EXÉCUTION
    # =========================================================================

    async def run_async(self, session_id: str | None = None) -> Dict[str, Any]:
        """
        Exécute la campagne d'attaque de manière asynchrone.

        Args:
            session_id: Identifiant unique pour la session.

        Returns:
            Résultat final contenant l'état et le rapport.
        """
        session_id = session_id or random_session_id()
        self.log("🚀 Démarrage de la simulation asynchrone", log=True)
        self.start_time = time.time()
        logger.remove(all_handlers=False)
        with silence_output() as (out, err):
            try:
                initial_state = self.build_state_graph()
                if not initial_state["ip"]:
                    error = SimulatorError("IP indisponible")
                    error.message = "IP indisponible"
                    raise error
    
                self.log(f"IP cible: {initial_state['ip']}", log=self.debug)
    
                async with AsyncSqliteSaver.from_conn_string(
                    self.checkpoint_path + "_graphe_checkpoint.db",
                ) as acheckpointer:
                    self.build_graph(checkpointer=acheckpointer)
                    self.current_session_id = session_id
                    
                    final_state = await self.graph.ainvoke(
                        initial_state,
                        config={"configurable": {"thread_id": session_id}}, 
                    )
    
                self.final_result["state"] = final_state
                self.final_result.setdefault("logs", [])
                if not self.final_result["report"]:
                    self.final_result["report"] = await self.graph_report(final_state)
    
                self.end_time = time.time()
                duration = self.end_time - self.start_time
    
                await self._emit(self._msg(
                    "finish", None,
                    f"🏁 Simulation terminée en {duration:.2f}s",
                    data={
                        "elapsed": duration,
                        "report":  self.final_result["report"],
                    },
                    progress=1.0,
                ))
    
                self.log(f"✅ Simulation terminée en {duration:.2f}s", log=True)
                self.out = out
                self.err = err
                self.final_result["out"] = out.getvalue()
                self.final_result["err"] = err.getvalue()
                
    
            except Exception as e:
                self.end_time = time.time()
                self.log(f"❌ Erreur lors de la simulation: {str(e)}", log=True)
                import traceback
                self.log(f"Traceback: {traceback.format_exc()}")
                await self._emit(self._msg(
                    "error", None,
                    f"❌ Erreur simulation: {str(e)}",
                    data={"traceback": str(e)},
                    progress=0.0,
                ))
                raise
            
            finally:
                logger.setup(logger.logger.getEffectiveLevel(), logger.structured)
    
            return self.final_result
        
    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Exécute la campagne d'attaque de manière synchrone.

        Returns:
            Résultat final contenant l'état et le rapport.
        """
        self.log("🏁 Démarrage de la simulation synchrone", log=self.debug)
        return asyncio.run(self.run_async(*args, **kwargs))


if __name__ == "__main__":
    orchestrator = AutoAttackOrchestrator(None, None)
    print(list(SimulatorState.__annotations__.keys()))