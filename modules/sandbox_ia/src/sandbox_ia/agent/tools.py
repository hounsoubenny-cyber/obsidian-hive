#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tools CrewAI pour l'agent Sandbox ShieldAI.
Basé sur le vrai code : SandboxOrchestrator, ContainerManager, SandboxConfig
Auteur: HOUNSOU Samuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import json
import asyncio
import time
from datetime import datetime
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from sandbox_ia.core.orchestrator import SandboxOrchestrator, SandboxConfig, SandboxReport
from sandbox_ia.core.container_manager import ContainerManager
from sandbox_ia.executor.detect_language import get_supported_languages, detect_language
from sandbox_ia.configs.orchestrator_config import (
    DEFAULT_SANDBOX_IMAGE, DEFAULT_EXECUTION_TIMEOUT, DOCKER_DEFAULTS
)
from sandbox_ia.core.estimate_risk import estimate_risk, estimate_risk_async
from sandbox_ia.configs.behavior_scorer_config import ALERT_THRESHOLD
from modules_utils.loop_utils import _run_async

_orchestrator: SandboxOrchestrator | None = None
_last_report: SandboxReport | None = None


def get_orchestrator() -> SandboxOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SandboxOrchestrator()
    return _orchestrator


def set_orchestrator_instance(instance: SandboxOrchestrator):
    global _orchestrator
    _orchestrator = instance


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS INTERNES
# ─────────────────────────────────────────────────────────────────────────────

def _report_to_dict(report: SandboxReport) -> dict:
    """Convertit un SandboxReport en dict JSON-serialisable."""
    alerts = []
    for a in report.alerts:
        alerts.append({
            "timestamp": a.timestamp.isoformat(),
            "threat_score": a.threat_score,
            "threat_level": a.threat_level,
            "pattern_detected": a.pattern_detected,
            "canary_triggered": a.canary_triggered,
            "session_duration": round(a.session_duration, 3),
            "mitre": a.mitre,
            "description": a.description,
        })

    exec_result = None
    if report.exec_result:
        exec_result = {
            "success": report.exec_result.success,
            "exit_code": report.exec_result.exit_code,
            "language": report.exec_result.language,
            "command": report.exec_result.command,
            "duration": round(report.exec_result.duration, 3),
            "timeout_passed": report.exec_result.timeout_passed,
            "stdout": (report.exec_result.stdout or "")[:500],
            "stderr": (report.exec_result.stderr or "")[:500],
        }

    return {
        "session_id": report.session_id,
        "final_score": report.final_score,
        "final_level": report.final_level,
        "alerts_count": len(report.alerts),
        "alerts": alerts[:10],
        "session_duration": round(report.session_duration, 3),
        "killed": report.killed,
        "timestamp": report.timestamp.isoformat(),
        "exec_result": exec_result,
        "stats": report.stats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# INPUT SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeCodeInput(BaseModel):
    code: str = Field(
        description=(
            "Le code source à analyser dans le sandbox. "
            "Peut être dans n'importe quel langage supporté : "
            "python, bash, javascript, php, ruby, go, rust, java, c, cpp, perl, lua, r, powershell."
        )
    )
    language: str | None = Field(
        default=None,
        description=(
            "Langage du code. Si None, détection automatique. "
            "Valeurs : 'python', 'bash', 'javascript', 'php', 'ruby', 'go', "
            "'rust', 'java', 'c', 'cpp', 'perl', 'lua', 'r', 'powershell'."
        )
    )
    exec_timeout: float = Field(
        default=30.0,
        description="Timeout d'exécution en secondes. Défaut: 30.0"
    )
    mem_limit: str = Field(
        default="256m",
        description="Limite mémoire Docker. Format: '256m', '512m', '1g'. Défaut: '256m'"
    )
    alert_threshold: int = Field(
        default=60,
        description=(
            "Score de menace déclenchant une alerte (0-100). "
            "Si atteint → container tué automatiquement. Défaut: 60"
        )
    )
    enable_strace: bool = Field(
        default=True,
        description="Active le traceur syscall strace. Défaut: True"
    )
    enable_fs_monitor: bool = Field(
        default=True,
        description="Active la surveillance filesystem via inotify. Défaut: True"
    )
    network_disabled: bool = Field(
        default=True,
        description="Désactive le réseau dans le container. Défaut: True"
    )
    image_name: str = Field(
        default="shieldai-sandbox:v2-ligth",
        description="Image Docker à utiliser. Défaut: 'shieldai-sandbox:v2-ligth'"
    )
    use_cache: bool = Field(
        default=True,
        description="Definie l'usage du cache pour accélerer l'exécution"
    )


class GetContainerStatusInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class KillContainerInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class GetLastReportInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class GetSandboxConfigInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class QuickAnalyzeInput(BaseModel):
    code: str = Field(
        description="Code à analyser rapidement avec la config par défaut."
    )
    language: str | None = Field(
        default=None,
        description="Langage du code. None = détection auto."
    )

class GetSupportedLanguagesInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")

class EstimateRiskInput(BaseModel):
    code: str = Field(
        description="Code source à analyser statiquement (sans exécution)."
    )

# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1 — ANALYZE CODE (principal)
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeCode(BaseTool):
    name: str = "analyze_code"
    description: str = """
Analyse comportementale complète d'un code source dans un container Docker isolé.
Lance le code dans un sandbox ShieldAI et surveille son comportement en temps réel :
syscalls strace, accès filesystem, patterns d'attaque MITRE ATT&CK.

RETOUR (dict JSON) :
{
    "session_id": str,              // Identifiant de session
    "final_score": int,             // Score de menace final (0-100)
    "final_level": str,             // Niveau: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    "alerts_count": int,            // Nombre d'alertes déclenchées
    "alerts": [                     // Détails des alertes (max 10)
        {
            "threat_score": int,
            "threat_level": str,
            "pattern_detected": str,    // Pattern MITRE ATT&CK détecté
            "canary_triggered": bool,   // Honeypot déclenché
            "mitre": str,               // Code MITRE (ex: "T1055")
            "description": str          // Description de l'attaque
        }
    ],
    "session_duration": float,      // Durée en secondes
    "killed": bool,                 // True si container tué (score CRITICAL)
    "exec_result": {
        "success": bool,
        "exit_code": int,
        "language": str,
        "command": str,
        "duration": float,
        "timeout_passed": bool,
        "stdout": str,              // Sortie tronquée à 500 chars
        "stderr": str
    }
}

Utilise cet outil quand l'orchestrateur doit analyser un fichier ou script suspect.
"""
    args_schema: type[BaseModel] = AnalyzeCodeInput
    description_updated: bool = True

    def _run(
        self,
        code: str,
        language: str | None = None,
        exec_timeout: float = 30.0,
        mem_limit: str = "256m",
        alert_threshold: int = 60,
        enable_strace: bool = True,
        enable_fs_monitor: bool = True,
        network_disabled: bool = True,
        image_name: str = "shieldai-sandbox:v2-ligth",
        use_cache: bool = True,
    ) -> dict:
        return _run_async(
            self._arun,
            **dict(
                code=code,
                language=language,
                exec_timeout=exec_timeout,
                mem_limit=mem_limit,
                alert_threshold=alert_threshold,
                enable_strace=enable_strace,
                enable_fs_monitor=enable_fs_monitor,
                network_disabled=network_disabled,
                image_name=image_name
            )
        )

    async def _arun(
        self,
        code: str,
        language: str | None = None,
        exec_timeout: float = 30.0,
        mem_limit: str = "256m",
        alert_threshold: int = 60,
        enable_strace: bool = True,
        enable_fs_monitor: bool = True,
        network_disabled: bool = True,
        image_name: str = "shieldai-sandbox:v2-ligth",
        use_cache: bool = True,
    ) -> dict:
        global _last_report
        config = SandboxConfig(
            image_name=image_name,
            network_disabled=network_disabled,
            mem_limit=mem_limit,
            exec_timeout=exec_timeout,
            alert_threshold=alert_threshold,
            enable_strace=enable_strace,
            enable_fs_monitor=enable_fs_monitor,
            user="sandbox",
            exec_user="sandbox",
        )
        orchestrator = get_orchestrator()
        report = await orchestrator.analyze(code=code, language=language, config=config, use_cache=use_cache)
        _last_report = report
        return _report_to_dict(report)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2 — QUICK ANALYZE (config minimale, rapide)
# ─────────────────────────────────────────────────────────────────────────────

class QuickAnalyze(BaseTool):
    name: str = "quick_analyze"
    description: str = """
Analyse rapide d'un code avec la configuration par défaut ShieldAI.
Plus rapide que analyze_code — timeout 30s, mémoire 256m, seuil d'alerte 60.
Idéal pour une première analyse avant une analyse approfondie.

RETOUR : même structure que analyze_code.

Utilise cet outil pour un triage rapide avant de décider si une analyse
approfondie est nécessaire.
"""
    args_schema: type[BaseModel] = QuickAnalyzeInput
    description_updated: bool = True

    def _run(self, code: str, language: str | None = None) -> dict:
        return _run_async(
            self._arun,
            **dict(
                code=code,
                language=language,
            )
        )

    async def _arun(self, code: str, language: str | None = None) -> dict:
        global _last_report
        config = SandboxConfig(
            exec_timeout=30.0,
            mem_limit="256m",
            alert_threshold=60,
            enable_strace=True,
            enable_fs_monitor=True,
            user="sandbox",
            exec_user="sandbox",
        )
        orchestrator = get_orchestrator()
        report = await orchestrator.analyze(code=code, language=language, config=config)
        _last_report = report
        return _report_to_dict(report)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — GET CONTAINER STATUS
# ─────────────────────────────────────────────────────────────────────────────

class GetContainerStatus(BaseTool):
    name: str = "get_container_status"
    description: str = """
Retourne l'état courant du container Docker sandbox.

RETOUR (dict JSON) :
{
    "status": str,          // "running" | "exited" | "paused" | "not_start" | "dead"
    "pid": int | null,      // PID du container sur l'hôte
    "healthy": bool,        // True si le container répond aux commandes
    "container_name": str | null,
    "image_name": str | null,
    "timestamp": str
}

Utilise cet outil pour vérifier si un container est actif avant une analyse,
ou pour monitorer l'état après un kill.
"""
    args_schema: type[BaseModel] = GetContainerStatusInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> dict:
        orchestrator = get_orchestrator()
        manager: ContainerManager = orchestrator.manager
        status = manager.get_status()
        pid = manager.get_pid()
        healthy = manager.health_check() if status == "running" else False
        return {
            "status": status,
            "pid": pid,
            "healthy": healthy,
            "container_name": manager.container.name if manager.container else None,
            "image_name": manager.image_name,
            "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        }

    async def _arun(self, *args, **kwargs) -> dict:
        return self._run()


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4 — KILL CONTAINER
# ─────────────────────────────────────────────────────────────────────────────

class KillContainer(BaseTool):
    name: str = "kill_container"
    description: str = """
Tue immédiatement le container sandbox via SIGKILL.
ACTION CRITIQUE — à utiliser si le code analysé semble particulièrement dangereux
ou si le score de menace dépasse le seuil critique.

RETOUR (dict JSON) :
{
    "status": "success" | "error" | "no_container",
    "message": str,
    "timestamp": str
}

Ne pas utiliser en dehors d'une situation d'urgence — préférer laisser
l'orchestrateur gérer le cycle de vie du container automatiquement.
"""
    args_schema: type[BaseModel] = KillContainerInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> dict:
        orchestrator = get_orchestrator()
        manager: ContainerManager = orchestrator.manager
        if not manager.container:
            return {
                "status": "no_container",
                "message": "Aucun container actif à tuer.",
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            }
        try:
            success = manager.kill()
            return {
                "status": "success" if success else "error",
                "message": "Container tué via SIGKILL" if success else "Échec du kill",
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
            }

    async def _arun(self, *args, **kwargs) -> dict:
        return self._run()


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5 — GET LAST REPORT
# ─────────────────────────────────────────────────────────────────────────────

class GetLastReport(BaseTool):
    name: str = "get_last_report"
    description: str = """
Retourne le rapport de la dernière analyse sandbox effectuée.
Utile pour accéder aux détails d'une analyse sans la relancer.

RETOUR (dict JSON) : même structure que analyze_code.
{"error": "Aucune analyse disponible"} si aucune analyse n'a été faite.

Utilise cet outil quand l'orchestrateur a besoin de consulter la dernière
analyse pour prendre une décision (bloquer une IP, alerter un admin, etc.).
"""
    args_schema: type[BaseModel] = GetLastReportInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> dict:
        global _last_report
        if _last_report is None:
            return {"error": "Aucune analyse disponible. Lance d'abord analyze_code ou quick_analyze."}
        return _report_to_dict(_last_report)

    async def _arun(self, *args, **kwargs) -> dict:
        return self._run()


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 6 — GET SUPPORTED LANGUAGES
# ─────────────────────────────────────────────────────────────────────────────

class GetSupportedLanguages(BaseTool):
    name: str = "get_supported_languages"
    description: str = """
Retourne la liste des langages supportés par le sandbox ShieldAI.

RETOUR (dict JSON) :
{
    "languages": list[str],     // Liste des 14 langages
    "count": int
}

Utilise cet outil avant analyze_code si le langage d'un fichier est inconnu
ou si tu dois vérifier qu'un langage est bien supporté.
"""
    args_schema: type[BaseModel] = GetSupportedLanguagesInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> dict:
        langs = get_supported_languages()
        return {"languages": langs, "count": len(langs)}

    async def _arun(self, *args, **kwargs) -> dict:
        return self._run()


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 7 — ESTIMATE RISK (analyse statique, sans exécution)
# ─────────────────────────────────────────────────────────────────────────────

class EstimateRisk(BaseTool):
    name: str = "estimate_risk"
    description: str = """
Analyse statique rapide d'un code pour estimer son niveau de risque
SANS l'exécuter dans le sandbox. Basé sur des patterns textuels suspects.
Beaucoup plus rapide que analyze_code mais moins précis.

RETOUR (dict JSON) :
{
    "risk_level": str,          // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    "risk_score": int,          // Score estimé (0-100)
    "flags": list[str],         // Patterns suspects détectés
    "recommend_sandbox": bool,  // True si une analyse sandbox est recommandée
    "language_detected": str | null
}

Utilise cet outil en pré-filtrage pour décider si le code mérite une
analyse sandbox complète (qui prend plusieurs secondes).
"""
    args_schema: type[BaseModel] = EstimateRiskInput
    description_updated: bool = True

    # Patterns suspects par catégorie
    _PATTERNS = {
        # Credential harvesting
        "/etc/shadow": ("Lecture /etc/shadow", 40),
        "/etc/passwd": ("Lecture /etc/passwd", 20),
        ".ssh/id_rsa": ("Accès clé SSH privée", 45),
        ".ssh/id_ed25519": ("Accès clé SSH privée", 45),

        # Network / C2
        "socket.connect": ("Connexion réseau", 25),
        "requests.get": ("Requête HTTP sortante", 15),
        "urllib.request": ("Requête HTTP sortante", 15),
        "subprocess.Popen": ("Exécution de sous-processus", 30),
        "os.system": ("Exécution commande système", 25),
        "eval(": ("Eval dynamique (obfuscation possible)", 30),
        "exec(": ("Exec dynamique", 30),
        "__import__": ("Import dynamique", 20),

        # Persistence
        "/etc/crontab": ("Modification crontab", 35),
        "/etc/rc.local": ("Persistence rc.local", 35),
        ".bashrc": ("Modification .bashrc", 25),
        "ld.so.preload": ("Injection LD_PRELOAD", 50),

        # Fileless
        "memfd_create": ("Fileless execution", 60),
        "/dev/shm": ("Utilisation /dev/shm", 30),
        "ctypes": ("Ctypes (shellcode possible)", 25),
        "mmap": ("Mmap mémoire", 15),

        # Reverse shell indicators
        "bash -i": ("Pattern reverse shell", 70),
        "/dev/tcp": ("Redirection TCP bash", 70),
        "nc -e": ("Netcat reverse shell", 70),
        "base64.b64decode": ("Décodage base64 (payload possible)", 20),

        # Container escape
        "/var/run/docker.sock": ("Accès socket Docker (escape)", 65),
        "pivot_root": ("Tentative pivot_root", 60),

        # Crypto mining
        "stratum+": ("Pool minage crypto", 55),
        "xmrig": ("Miner XMRig", 65),
    }

    def _run(self, code: str) -> dict:
        return estimate_risk(code, self._PATTERNS)

    async def _arun(self, code: str) -> dict:
        return self._run(code)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 8 — GET SANDBOX CONFIG
# ─────────────────────────────────────────────────────────────────────────────

class GetSandboxConfig(BaseTool):
    name: str = "get_sandbox_config"
    description: str = """
Retourne la configuration par défaut du sandbox ShieldAI.
Utile pour comprendre les paramètres actuels avant de lancer une analyse.

RETOUR (dict JSON) :
{
    "image_name": str,
    "mem_limit": str,
    "cpu_quota": int,
    "pids_limit": int,
    "exec_timeout": float,
    "alert_threshold": int,
    "enable_strace": bool,
    "enable_fs_monitor": bool,
    "network_disabled": bool,
    "supported_languages": list[str]
}
"""
    args_schema: type[BaseModel] = GetSandboxConfigInput
    description_updated: bool = True

    def _run(self, *args, **kwargs) -> dict:
        return {
            "image_name": DEFAULT_SANDBOX_IMAGE,
            "mem_limit": DOCKER_DEFAULTS["mem_limit"],
            "cpu_quota": DOCKER_DEFAULTS["cpu_quota"],
            "pids_limit": DOCKER_DEFAULTS["pids_limit"],
            "exec_timeout": DEFAULT_EXECUTION_TIMEOUT,
            "alert_threshold": ALERT_THRESHOLD,
            "enable_strace": True,
            "enable_fs_monitor": True,
            "network_disabled": DOCKER_DEFAULTS["network_disabled"],
            "supported_languages": get_supported_languages(),
        }

    async def _arun(self, *args, **kwargs) -> dict:
        return self._run()


# ─────────────────────────────────────────────────────────────────────────────
# LISTE DE TOUS LES TOOLS
# ─────────────────────────────────────────────────────────────────────────────

ALL_SANDBOX_TOOLS = [
    AnalyzeCode(),
    QuickAnalyze(),
    GetContainerStatus(),
    KillContainer(),
    GetLastReport(),
    GetSupportedLanguages(),
    EstimateRisk(),
    GetSandboxConfig(),
]