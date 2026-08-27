#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May  9 12:40:39 2026

@author: hounsousamuel

Module d'exécution de code pour le Sandbox ShieldAI V2.
Orchestre la copie du code dans le container Docker et son exécution
isolée, puis retourne un résultat structuré (ExecResult) contenant
toutes les informations sur l'exécution.

Pipeline :
    code + langage
        → détection langage (si absent)
        → génération commande via LANGUAGE_RUNNERS
        → copy_in() dans le container
        → exec_command_async() dans le container
        → ExecResult structuré
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from datetime import datetime
from dataclasses import dataclass
from sandbox_ia.core.container_manager import ContainerManager
from sandbox_ia.executor.detect_language import detect_language, get_language_cmd, get_supported_languages, COMPILED_LANGUAGES
from sandbox_ia.sandbox_utils.logger import get_logger

logger = get_logger()


# =============================================================================
# DATACLASS — Résultat structuré d'une exécution
# =============================================================================

@dataclass
class ExecResult:
    """
    Résultat structuré d'une exécution de code dans le sandbox.

    Retourné par Executor.execute() et Executor.execute_async() après
    chaque exécution, qu'elle soit réussie ou échouée. Contient toutes
    les informations nécessaires pour le behavior_scorer et le rapport final.

    Attributes
    ----------
    success : bool
        True si l'exécution s'est terminée avec exit_code == 0.
        False dans tous les autres cas (erreur, timeout, copy échoué...).
    exit_code : int | None
        Code de retour du process exécuté.
        0 = succès, autre = erreur. None si l'exécution n'a pas démarré.
    stdout : str
        Sortie standard du programme exécuté, décodée en UTF-8.
    stderr : str
        Sortie d'erreur du programme exécuté, décodée en UTF-8.
        Contient aussi les messages d'erreur internes (copy échoué, etc.)
    language : str
        Langage détecté ou fourni pour cette exécution.
    filename : str
        Nom de base du fichier fourni par l'appelant.
        Exemple : "sandbox", "script", "malware_sample"
    code_filename : str | None
        Chemin vers un fichier source local à lire, si fourni.
        None si le code a été passé directement comme string.
    command : str
        Commande shell complète exécutée dans le container.
        Exemple : "python3 /sandbox/work/sandbox.py"
        None si l'exécution n'a pas pu démarrer.
    duration : float
        Durée totale de l'exécution en secondes (perf_counter).
        Inclut la compilation pour les langages compilés.
        0.0 si l'exécution n'a pas démarré.
    timestamp : datetime
        Horodatage UTC de fin d'exécution.
    timeout_passed : bool
        True si le timeout a été atteint pendant l'exécution.
        Détecté via le message "timeout atteint" dans stderr.
    """
    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    language: str
    filename: str
    code_filename: str | None
    command: str
    duration: float
    timestamp: datetime
    timeout_passed: bool
    
    def to_dict(self, max_output_length: int = 500) -> dict:
        """
        Convertit le résultat d'exécution en dictionnaire JSON-serialisable.
        
        Args:
            max_output_length: Longueur max pour stdout/stderr.
                               500 par défaut pour éviter les JSON trop gros.
        
        Returns:
            dict: Tous les champs de l'exécution.
        """
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": (self.stdout or "")[:max_output_length],
            "stderr": (self.stderr or "")[:max_output_length],
            "stdout_length": len(self.stdout or ""),
            "stderr_length": len(self.stderr or ""),
            "language": self.language,
            "filename": self.filename,
            "code_filename": self.code_filename,
            "command": self.command,
            "duration": round(self.duration, 3),
            "timestamp": self.timestamp.isoformat() if hasattr(self.timestamp, 'isoformat') else str(self.timestamp),
            "timeout_passed": self.timeout_passed,
            "summary": {
                "status": "✅ SUCCESS" if self.success else "❌ FAILED",
                "exit": self.exit_code if self.exit_code is not None else "N/A",
                "duration": f"{self.duration:.2f}s",
                "timeout": "⚠️" if self.timeout_passed else "✅",
            }
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ExecResult":
        """Reconstruit un ExecResult depuis un dictionnaire."""
        return cls(
            success=data["success"],
            exit_code=data["exit_code"],
            stdout=data["stdout"],
            stderr=data["stderr"],
            language=data["language"],
            filename=data["filename"],
            code_filename=data["code_filename"],
            command=data["command"],
            duration=data["duration"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            timeout_passed=data["timeout_passed"],
        )
    

# =============================================================================
# EXECUTOR
# =============================================================================

class Executor:
    """
    Exécuteur de code isolé dans le container sandbox ShieldAI.

    Coordonne toute la pipeline d'exécution : détection du langage,
    copie du code dans le container, exécution isolée et retour du
    résultat structuré. S'appuie sur ContainerManager pour toutes
    les interactions avec Docker.

    Attributes
    ----------
    manager : ContainerManager
        Instance du manager Docker déjà connectée à un container actif.
    workdir : str
        Répertoire de travail dans le container où le code est copié
        et exécuté. "/sandbox/work" par défaut.
    """

    def __init__(self, container_manager: ContainerManager):
        """
        Initialise l'exécuteur avec un ContainerManager actif.

        Parameters
        ----------
        container_manager : ContainerManager
            Manager Docker déjà connecté à un container via connect().
            Le container doit être en état "running" avant d'appeler execute().
        """
        self.manager = container_manager
        self.workdir = "/sandbox/work"

    # =============================================================================
    # MÉTHODES INTERNES
    # =============================================================================

    @staticmethod
    def _build_result(
        success: bool,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        language: str,
        filename: str,
        code_filename: str | None,
        command: str,
        duration: float,
        timestamp: datetime,
        timeout_passed: bool = False,
    ) -> ExecResult:
        """
        Construit un ExecResult structuré depuis les données d'exécution.

        Méthode statique centralisée pour garantir que tous les champs
        du dataclass sont toujours correctement remplis, y compris dans
        les cas d'erreur précoce (avant l'exécution réelle).

        Parameters
        ----------
        success : bool
            True si exit_code == 0.
        exit_code : int | None
            Code de retour du process. None si pas démarré.
        stdout : str
            Sortie standard décodée.
        stderr : str
            Sortie d'erreur décodée.
        language : str
            Langage utilisé pour l'exécution.
        filename : str
            Nom de base du fichier.
        code_filename : str | None
            Chemin source local si applicable.
        command : str
            Commande shell exécutée. None si pas démarrée.
        duration : float
            Durée en secondes. 0.0 si pas démarrée.
        timestamp : datetime
            Horodatage UTC.
        timeout_passed : bool, optional
            True si timeout atteint. False par défaut.

        Returns
        -------
        ExecResult
            Résultat structuré complet.
        """
        return ExecResult(
            success=success,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            language=language,
            filename=filename,
            command=command,
            duration=duration,
            timestamp=timestamp,
            code_filename=code_filename,
            timeout_passed=timeout_passed
        )

    # =============================================================================
    # EXÉCUTION PRINCIPALE
    # =============================================================================

    async def execute_async(
        self,
        code: str | None,
        language: str | None,
        code_filename: str | None = None,
        filename: str | None = "sandbox",
        timeout: float | None = 30.0,
        use_subprocess_for_copy: bool = True,
        user: str = "1500:1500",
        strace_enabled:bool = True,
        strace_log_file:str | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """
        Exécute du code dans le container sandbox (version asynchrone).

        Pipeline complète :
        1. Validation — vérifie que le code ou le fichier est fourni
        2. Health check — vérifie que le container est opérationnel
        3. Lecture fichier — si code_filename fourni, lit le fichier local
        4. Détection langage — via detect_language() si non fourni
        5. Génération commande — via get_language_cmd()
        6. Création workdir — mkdir -p dans le container
        7. Copy in — copie le code dans le container
        8. Exécution — exec_command_async() avec timeout
        9. Retour ExecResult — structuré avec durée, exit_code, outputs

        Parameters
        ----------
        code : str | None
            Code source à exécuter. Peut être None si code_filename est fourni.
        language : str | None
            Langage de programmation. Si None, détecté automatiquement
            via detect_language() depuis le nom de fichier et le contenu.
        code_filename : str | None, optional
            Chemin vers un fichier source local à lire et exécuter.
            Utilisé si code est None. None par défaut.
        filename : str | None, optional
            Nom de base à donner au fichier dans le container.
            L'extension correcte est ajoutée automatiquement.
            "sandbox" par défaut.
        timeout : float | None, optional
            Timeout d'exécution en secondes. 30.0 par défaut.
            2 secondes supplémentaires sont ajoutées pour la compilation
            des langages compilés (Java, Rust, C, C++).
            None = pas de timeout.
        use_subprocess_for_copy : bool, optional
            True = copie via subprocess docker exec -i (recommandé).
            False = copie via base64 encode/decode.
            True par défaut.
        user : str, optional
            Utilisateur sous lequel exécuter le code dans le container.
            "1500:1500" par défaut (UID:GID de l'utilisateur sandbox).
            Plus sûr que "sandbox" car ne dépend pas de /etc/passwd.

        Returns
        -------
        ExecResult
            Résultat structuré complet de l'exécution.
            success=False si une étape de la pipeline a échoué.
        """
        ts = datetime.utcnow()
        workdir = workdir or self.workdir
        # ── Validation ────────────────────────────────────────────────────────
        if not code and not code_filename:
            logger.print("❌ Executor: code et fichier absents")
            return self._build_result(
                success=False, exit_code=1,
                stderr="Code et Fichier absent !",
                stdout="", duration=0.0, timestamp=ts,
                filename=filename, command=None,
                language=language, code_filename=code_filename
            )

        # ── Health check ──────────────────────────────────────────────────────
        if not self.manager.health_check():
            logger.print("❌ Executor: container non opérationnel")
            return self._build_result(
                success=False, exit_code=1,
                stderr="Container non lancé !",
                stdout="", duration=0.0, timestamp=ts,
                filename=filename, command=None,
                language=language, code_filename=code_filename
            )

        # ── Lecture fichier local ─────────────────────────────────────────────
        try:
            code = code or open(code_filename, "r").read()
        except Exception as e:
            logger.print(f"❌ Executor: impossible de lire {code_filename}: {e}")
            return self._build_result(
                success=False, exit_code=1,
                stderr=f"Impossible de lire {code_filename}: {e}",
                stdout="", duration=0.0, timestamp=ts,
                filename=filename, command=None,
                language=language, code_filename=code_filename
            )

        # ── Détection langage ─────────────────────────────────────────────────
        language = language or detect_language(code_filename or "", code)
        logger.print(f"🔍 Executor: langage → {language}")

        if language.lower() not in [l.lower() for l in get_supported_languages()]:
            logger.print(f"❌ Executor: langage non supporté → {language}")
            return self._build_result(
                success=False, exit_code=1,
                stderr=f"Langage non supporté: {language}",
                stdout="", duration=0.0, timestamp=ts,
                filename=filename, command=None,
                language=language, code_filename=code_filename
            )

        # ── Génération commande ───────────────────────────────────────────────
        _, filename_completed, command = get_language_cmd(file=filename, language=language)
        dest_path = os.path.join(workdir, filename_completed)
        _, _, command = get_language_cmd(file=dest_path, language=language)
        logger.print(f"⚙️  Executor: commande → {command}")

        # ── Création workdir ──────────────────────────────────────────────────
        self.manager.exec_command(f"mkdir -p {workdir}", user=user)

        # ── Copy in ───────────────────────────────────────────────────────────
        logger.print(f"📁 Executor: copy_in → {dest_path}")
        copy_returncode, copy_stdout, copy_stderr = self.manager.copy_in(
            content=code,
            dest_path=dest_path,
            use_subprocess=use_subprocess_for_copy,
            container=self.manager.container,
            user=user,
        )
        if copy_returncode != 0:
            logger.print(f"❌ Executor: copy_in échoué (code {copy_returncode})")
            logger.print(f"   stderr: {copy_stderr[:200]}")
            return self._build_result(
                success=False, exit_code=1,
                stderr=f"Copy échoué: {copy_stderr[:200]}",
                stdout=str(copy_stdout), duration=0.0, timestamp=ts,
                filename=filename, command=command,
                language=language, code_filename=code_filename
            )
        logger.print("✅ Executor: copy_in réussi")

        # ── Exécution ─────────────────────────────────────────────────────────
        logger.print(f"🚀 Executor: exécution ({language}) timeout={timeout}s")
        st = time.perf_counter()
        
        if any(str(command).startswith(x) for x in COMPILED_LANGUAGES.values()):
            logger.info("Language compilé détecté, exécution de la compilation !")
            compile_cmd, command = str(command).rsplit("&&", 1)
            compile_cmd = compile_cmd.strip()
            command = command.strip()
            
            # Exécuter la compilation sans strace
            compile_returncode, compile_stdout, compile_stderr = await self.manager.exec_command_async(
                cmd=compile_cmd,
                user=user,
                workdir=workdir,
                timeout=timeout + 10 if timeout else None,
            )
            
            if compile_returncode != 0:
                logger.warning("Compilation échoué, sortie directe")
                logger.info(f"Stderr : {compile_stderr}")
                print(compile_stderr, compile_stdout)
                duration = time.perf_counter() - st
                return self._build_result(
                    exit_code=compile_returncode, success=False,
                    stderr=compile_stderr, stdout=compile_stdout, 
                    duration=0.0, timestamp=ts,
                    filename=filename, command=compile_cmd,
                    language=language, code_filename=code_filename
                )
            
            logger.success("Compilation réussie, exécution")
        if strace_enabled and strace_log_file:
            command = f"""strace -tt -T -f -o {strace_log_file} bash -c "{command}" """.strip()

        cmd_returncode, cmd_stdout, cmd_stderr = await self.manager.exec_command_async(
            cmd=command,
            user=user,
            workdir=workdir,
            timeout=timeout + 10 if timeout else None,
        )
        duration = time.perf_counter() - st
        success = cmd_returncode == 0
        timeout_passed = cmd_stderr.lower() == "timeout atteint"

        # ── Affichage résultat ────────────────────────────────────────────────
        if success:
            logger.success("Exécution sécurisé du code réussie")
        icon = "✅" if success else "❌"
        logger.print(f"{icon} Executor: exit_code={cmd_returncode} | duration={duration:.2f}s | timeout={timeout_passed}")
        if cmd_stdout:
            logger.print(f"📤 stdout: {cmd_stdout[:300]}")
        if cmd_stderr:
            logger.print(f"⚠️  stderr: {cmd_stderr[:300]}")

        return self._build_result(
            success=success,
            exit_code=cmd_returncode,
            stderr=cmd_stderr,
            stdout=cmd_stdout,
            duration=duration,
            timestamp=datetime.utcnow(),
            filename=filename,
            command=command,
            language=language,
            code_filename=code_filename,
            timeout_passed=timeout_passed
        )

    def execute(self, *args, **kwargs) -> ExecResult:
        """
        Exécute du code dans le container sandbox (version synchrone).

        Wrapper synchrone autour de execute_async() via asyncio.run().
        À utiliser uniquement hors d'un event loop asyncio existant.
        Si tu es dans un contexte async, utilise execute_async() directement.

        Parameters
        ----------
        *args : any
            Positional arguments passés à execute_async().
        **kwargs : any
            Keyword arguments passés à execute_async().

        Returns
        -------
        ExecResult
            Voir execute_async().
        """
        return asyncio.run(self.execute_async(*args, **kwargs))