#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Orchestrateur principal du Sandbox ShieldAI V2.

Assemble tous les composants (container, strace, FSMonitor, scoring)
en un cycle complet d'analyse comportementale.

Tous les paramètres sont remontés jusqu'à analyze() via SandboxConfig.
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import json
import asyncio
import joblib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Any
from diskcache import Cache
from sklearn.preprocessing import StandardScaler
from sandbox_ia.core.container_manager import ContainerManager
from sandbox_ia.executor.executor import Executor, ExecResult
from sandbox_ia.tracers.fs_monitor import FSMonitor, SandBoxQueue
from sandbox_ia.tracers.syscall_tracer import SyscallTracer, SyscallParser
from sandbox_ia.scorers.behavior_scorer import BehaviorScorer, ThreatReport
from sandbox_ia.configs.fs_monitor_config import (
    CANARY_PATHS as FS_CANARY_PATHS,
    SUSPICIOUS_PATHS as FS_SUSPICIOUS_PATHS,
    SUSPICIOUS_EXTENSIONS as FS_SUSPICIOUS_EXTENSIONS
)
from sandbox_ia.configs.syscall_tracer_config import (
    SYSCALL_FAMILIES as ST_SYSCALL_FAMILIES,
    SYSCALL_BONUS as ST_SYSCALL_BONUS,
    IGNORE_PATTERNS as ST_IGNORE_PATTERNS
)
from sandbox_ia.configs.behavior_scorer_config import (
    ALERT_THRESHOLD as DEFAULT_ALERT_THRESHOLD,
    DECAY_INTERVAL as DEFAULT_DECAY_INTERVAL
)
from sandbox_ia.configs.orchestrator_config import (
    DEFAULT_EXECUTION_TIMEOUT, DEFAULT_SANDBOX_IMAGE, DOCKER_DEFAULTS,
    CACHE_DIR
)

from sandbox_ia.sandbox_utils.logger import get_logger
from sandbox_ia.ml_model.autoencoders import AutoEncoder
from sandbox_ia.ml_model.classifier import Classifier
from sandbox_ia.scorers.realtime_processor import RealtimeProcessor
from sandbox_ia.ml_model.features_extractor_v2 import FeatureExtractor
from sandbox_ia.configs.ml_configs import ML_AVAILABLE, PATH_DICT

logger = get_logger()

CACHE_TIMEOUT = 3600 * 5
CACHE = Cache(directory=CACHE_DIR)
# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class SandboxConfig:
    """
    Configuration complète du sandbox.

    Tous les paramètres sont surchargeables. Les champs listes laissés à None
    sont automatiquement remplacés par les valeurs par défaut des modules.
    """

    # --- Docker / Container -------------------------------------------------
    image_name: str = DEFAULT_SANDBOX_IMAGE
    container_name: str | None = None
    network_disabled: bool = DOCKER_DEFAULTS["network_disabled"]
    mem_limit: str = DOCKER_DEFAULTS["mem_limit"]
    cpu_quota: int = DOCKER_DEFAULTS["cpu_quota"]
    cpu_period: int = DOCKER_DEFAULTS["cpu_period"]
    pids_limit: int = DOCKER_DEFAULTS["pids_limit"]
    read_only: bool = DOCKER_DEFAULTS["read_only"]
    user: str = DOCKER_DEFAULTS["user"]
    workdir: str = DOCKER_DEFAULTS["workdir"]
    extra_env: dict | None = DOCKER_DEFAULTS["extra_env"]

    # --- Exécution ----------------------------------------------------------
    exec_timeout: float = DEFAULT_EXECUTION_TIMEOUT
    exec_user: str = "sandbox"          # nobody:nogroup (universel), "1500:1500" pour sandbox
    exec_use_subprocess_for_copy: bool = True
    exec_strace_enabled: bool = True

    # --- Surveillance -------------------------------------------------------
    enable_strace: bool = True
    enable_fs_monitor: bool = True
    strace_in_file: bool = True

    # --- Scoring ------------------------------------------------------------
    alert_threshold: int = DEFAULT_ALERT_THRESHOLD
    decay_interval: float = DEFAULT_DECAY_INTERVAL
    decay_amount: int = 5

    # --- Listes configurables -----------------------------------------------
    canary_paths: list[str] | None = None
    suspicious_paths: list[str] | None = None
    suspicious_extensions: list[str] | None = None
    syscall_families: dict[str, dict] | None = None
    syscall_bonus: dict[str, int] | None = None
    ignore_patterns: list[str] | None = None

    # --- Callback -----------------------------------------------------------
    on_alert_callback: Callable[[ThreatReport], Any] | None = None
    callback_timeout: float | int = 2.0

    def __post_init__(self):
        """Applique les valeurs par défaut aux listes None."""
        if self.canary_paths is None:
            self.canary_paths = FS_CANARY_PATHS
        if self.suspicious_paths is None:
            self.suspicious_paths = FS_SUSPICIOUS_PATHS
        if self.suspicious_extensions is None:
            self.suspicious_extensions = FS_SUSPICIOUS_EXTENSIONS
        if self.syscall_families is None:
            self.syscall_families = ST_SYSCALL_FAMILIES
        if self.syscall_bonus is None:
            self.syscall_bonus = ST_SYSCALL_BONUS
        if self.ignore_patterns is None:
            self.ignore_patterns = ST_IGNORE_PATTERNS
        
        self.user = "sandbox"
        self.exec_user = "sandbox"
        self.workdir = "/sandbox/work"
    
    def to_dict(self) -> dict:
        """
        Convertit la configuration en dictionnaire JSON-serialisable.
        
        Returns:
            dict: Tous les paramètres de configuration avec leurs valeurs.
                  Les Callback sont convertis en leur nom pour la sérialisation.
        """
        result = {}
        
        for field_name in self.__dataclass_fields__.keys():
            value = getattr(self, field_name)
            
            if field_name == "on_alert_callback":
                if value is not None:
                    result[field_name] = value.__name__ if hasattr(value, "__name__") else str(value)
                else:
                    result[field_name] = None
                continue
            
            try:
                json.dumps(value)
                result[field_name] = value
            except (TypeError, ValueError):
                result[field_name] = str(value)
        
        return result
    
    def cache_key_dict(self) -> dict:
        """Version de la config pour le cache, sans les callables."""
        d = self.to_dict()
        d.pop("on_alert_callback", None)
        d.pop("callback_timeout", None)
        return d
    
    def to_json(self, indent: int = 2) -> str:
        """
        Convertit la configuration en JSON string.
        
        Args:
            indent: Indentation pour le formatage. 2 par défaut.
            
        Returns:
            str: JSON formaté de la configuration.
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)
    
    def __str__(self):
        return self.to_json(4)
    
    @classmethod
    def from_dict(cls, data: dict) -> "SandboxConfig":
        """Reconstruit un SandboxConfig depuis un dictionnaire."""
        return cls(**data)

@dataclass
class SandboxReport:
    """Rapport final d'une session d'analyse."""

    session_id: str
    config: SandboxConfig
    exec_result: ExecResult | None
    final_score: int
    final_level: str
    alerts: list[ThreatReport]
    session_duration: float
    timestamp: datetime
    killed: bool
    stats: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convertit le rapport final en dictionnaire."""
        return {
            "session_id": self.session_id,
            "config": self.config.to_dict() if hasattr(self.config, 'to_dict') else str(self.config),
            "exec_result": self.exec_result.to_dict() if self.exec_result and hasattr(self.exec_result, 'to_dict') else None,
            "final_score": self.final_score,
            "final_level": self.final_level,
            "alerts": [alert.to_dict() for alert in self.alerts] if self.alerts else [],
            "session_duration": round(self.session_duration, 3),
            "timestamp": self.timestamp.isoformat(),
            "killed": self.killed,
            "stats": self.stats,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SandboxReport":
        """Reconstruit un SandboxReport depuis un dictionnaire."""
        # Reconstruire config
        config_data = data["config"]
        if isinstance(config_data, dict):
            config = SandboxConfig.from_dict(config_data)
        else:
            config = config_data

        exec_result = None
        if data["exec_result"]:
            if isinstance(data["exec_result"], dict):
                exec_result = ExecResult.from_dict(data["exec_result"]) 
            else:
                exec_result = data["exec_result"]

        alerts = []
        for alert_data in data.get("alerts", []):
            if isinstance(alert_data, dict):
                alert = ThreatReport.from_dict(alert_data)
                if alert:
                    alerts.append(alert)

        return cls(
            session_id=data["session_id"],
            config=config,
            exec_result=exec_result,
            final_score=data["final_score"],
            final_level=data["final_level"],
            alerts=alerts,
            session_duration=data["session_duration"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            killed=data["killed"],
            stats=data.get("stats", {}),
        )

# =============================================================================
# ORCHESTRATEUR
# =============================================================================

class SandboxOrchestrator:
    """
    Coordinateur principal du sandbox.

    Orchestre le cycle complet : container → monitoring → exécution → scoring → rapport.
    """

    def __init__(self, store_event: bool = False):
        """Initialise l'orchestrateur et ses composants."""
        self.manager = ContainerManager()
        self.scorer: BehaviorScorer | None = None
        self.session_start = 0.0
        self.running = False
        self.exec_result: ExecResult | None = None
        self.killed = False
        self.config: SandboxConfig | None = None
        self.executor: Executor | None = None
        self.fs_monitor: FSMonitor | None = None
        self.syscall_tracer: SyscallTracer | None = None
        self.ae = None
        self.ae_threshold = None
        self.classifier = None
        self.scaler = None
        self.features_extractor = None
        self.realtime_processor = None
        self.ml_ready = False
        self.store_event = store_event
        self.monitors = []
        self.tasks = []
        self.ml_results = []
        self.events = []

    # =========================================================================
    # Application des configurations
    # =========================================================================

    def _build_fs_monitor(
        self, 
        fs_root: str, 
        event_queue: asyncio.Queue,
    ):
        self.fs_monitor = FSMonitor(
            fs_root=fs_root, 
            event_queue=event_queue,
            canary_paths=self.config.canary_paths,
            suspicious_paths=self.config.suspicious_paths,
            suspicious_extensions=self.config.suspicious_extensions,
        )
        return self.fs_monitor
    
    def _build_scorer(self):
        self.scorer = BehaviorScorer(
            alert_threshold=self.config.alert_threshold,
            decay_interval=self.config.decay_interval,
            decay_amount=self.config.decay_amount,
        )
        return self.scorer
    
    def _build_syscall_tracer(
        self, 
        tail_process: asyncio.subprocess.Process,
        event_queue: asyncio.Queue,
    ):
        self.syscall_tracer = SyscallTracer(
            tail_process=tail_process,
            event_queue=event_queue,
            parser=SyscallParser(
                syscall_families=self.config.syscall_families, 
                syscall_bonus=self.config.syscall_bonus,
                ignore_patterns=self.config.ignore_patterns
            )
        )
        
        return self.syscall_tracer


    # =========================================================================
    # Configuration du container
    # =========================================================================

    def setup_container(self) -> bool:
        """
        Configure et démarre le container Docker.

        Utilise les paramètres de la configuration courante pour créer
        ou réutiliser un container avec les bonnes options de sécurité.

        Returns:
            True si le container est opérationnel, False sinon.
        """
        if not self.config:
            return False

        try:
            kwargs = self.manager.get_kwargs_for_container(
                network_disabled=self.config.network_disabled,
                mem_limit=self.config.mem_limit,
                cpu_quota=self.config.cpu_quota,
                cpu_period=self.config.cpu_period,
                pids_limit=self.config.pids_limit,
                read_only=self.config.read_only,
                user=self.config.user,
                workdir=self.config.workdir,
                extra_env=self.config.extra_env,
            )

            container_name = self.config.container_name or f"shieldai_{int(time.time())}"
            self.manager.connect(self.config.image_name, container_name, **kwargs)
            # print(self.manager.exec_command(f"chmod 777 {self.config.workdir}"))
            return self.manager.health_check()
        except Exception as e:
            logger.print(f"[container] error: {e}")
            return False
    
    def init_ml_models(
        self,
        ae: AutoEncoder,
        classifier: Classifier,
        scaler_ae: StandardScaler,
        scaler_ae_ebd: StandardScaler,
        scaler_classsifier: StandardScaler,
        threshold_dict: dict,
    ):
        self.ae = ae
        self.ae_threshold = threshold_dict
        self.classifier = classifier
        self.scaler_ae = scaler_ae
        self.scaler_ae_ebd = scaler_ae_ebd
        self.scaler_classsifier = scaler_classsifier
        self.features_extractor = FeatureExtractor()
        self.realtime_processor = RealtimeProcessor(
            ae=self.ae,
            classifier=self.classifier,
            extractor=self.features_extractor,
            scaler_ae=self.scaler_ae,
            scaler_classifier=self.scaler_classsifier,
            scaler_ebd_ae=self.scaler_ae_ebd,
            anomaly_threshold=self.ae_threshold.get("recommended_threshold", self.ae_threshold.get("score", 0.0))
        )
        self.ml_ready = True
    
    
    def _score_callback(self, event, *args, **kwargs):
        """Callback pour BehaviorScorer."""
        if not self.ml_ready or self.realtime_processor is None:
            return None
        
        result = self.realtime_processor.process(
            event, 
            threat_score_manual=self.scorer.threat_score if hasattr(self, "scorer") else 0,
        )
        self.ml_results.append(result)
        if result.ml_active:
            logger.info(f"🤖 ML active | anomaly={result.anomaly_score:.3f} | "
                       f"prob_malware={result.prob_malware:.3f} | "
                       f"score_sequential={result.score_sequential:.1f}")
        
        return result.score_final

    # =========================================================================
    # Tâches asyncio
    # =========================================================================

    async def _task_execute(
        self, code: str, language: str | None, strace_log_file: str | None = None
    ) -> None:
        """
        Exécute le code suspect dans le container.

        Args:
            code: Code source à exécuter.
            language: Langage (None = détection auto).
            strace_log_file: Chemin du log strace dans le container.
        """
        try:
            if not self.config:
                return

            self.executor = Executor(self.manager)
            self.exec_result = await self.executor.execute_async(
                code=code,
                language=language,
                timeout=self.config.exec_timeout,
                use_subprocess_for_copy=self.config.exec_use_subprocess_for_copy,
                user=self.config.exec_user,
                strace_enabled=self.config.exec_strace_enabled,
                strace_log_file=strace_log_file
                or os.path.join(self.manager.volume_dir_on_container, self.manager.strace_file),
                workdir=self.config.workdir
            )
        except asyncio.CancelledError:
            raise
        finally:
            self.running = False

    async def _task_syscall_tracer(
        self, strace_file_on_host: str, event_queue: SandBoxQueue
    ) -> None | SyscallTracer:
        """
        Suit le fichier strace et parse les syscalls en temps réel.

        Args:
            strace_file_on_host: Chemin du fichier sur l'hôte.
            event_queue: Queue de destination pour les SyscallEvents.

        Returns:
            L'instance du traceur ou None si échec.
        """
        try:
            if not self.config.enable_strace:
                return

            timeout = 30
            start = time.time()
            while not os.path.exists(strace_file_on_host) and time.time() - start < timeout:
                await asyncio.sleep(0.5)

            if not os.path.exists(strace_file_on_host):
                logger.print("[strace] file not created after 30s, abort")
                return

            tail_process = await self.manager.get_file_reader_process_async(
                strace_file_on_host, start_new_session=True
            )
            if tail_process is None:
                return

            self._build_syscall_tracer(tail_process, event_queue)
            self.monitors.append(self.syscall_tracer)
            await self.syscall_tracer.start()
            logger.print("[strace] tracer started")
            return self.syscall_tracer

        except asyncio.CancelledError:
            raise

    async def _task_fs_monitor(self, event_queue: SandBoxQueue) -> FSMonitor | None:
        """
        Surveille le filesystem du container via inotify.

        Args:
            event_queue: Queue de destination pour les FSEvents.

        Returns:
            L'instance du moniteur ou None si échec.
        """
        try:
            if not self.config or not self.config.enable_fs_monitor:
                return None

            fs_root = self.manager.get_fs_root()
            if not fs_root:
                logger.print("[fsmon] root not available, disabled")
                return None

            self._build_fs_monitor(fs_root, event_queue)
            self.monitors.append(self.fs_monitor)
            await self.fs_monitor.start_async()
            logger.print("[fsmon] monitor started")
            return self.fs_monitor

        except asyncio.CancelledError:
            raise

    async def _task_scorer(self, event_queue: SandBoxQueue) -> None:
        """
        Consomme les events et met à jour le score de menace.

        Args:
            event_queue: Queue contenant les FSEvents et SyscallEvents.
        """
        try:
            if not self.config:
                return

            self.scorer = self._build_scorer()
            logger.info("[scorer] started")

            while (self.running or not event_queue.empty()) and not self.killed:
                event = event_queue.get()
                # print("[main]", event, "\n\n")
                    
                if not self.running or self.killed:
                    break
                
                if event is not None:
                    self.scorer.process(
                        event=event,
                        score_function=self._score_callback if self.ml_ready else None
                    )
                    if self.store_event:
                        self.events.append(event)
                        
                    # Callback si seuil atteint
                    if (
                        self.scorer.threat_score >= self.config.alert_threshold
                        and self.config.on_alert_callback
                    ):
                        try:
                            task = asyncio.to_thread(
                                self.config.on_alert_callback,
                                ThreatReport(
                                    timestamp=datetime.utcnow(),
                                    threat_score=self.scorer.threat_score,
                                    threat_level=self.scorer.threat_level,
                                    trigger_event=event,
                                    pattern_detected=self.scorer._last_pattern,
                                    canary_triggered=getattr(event, "is_canary", False),
                                    session_duration=time.time() - self.session_start,
                                ),
                            )
                            await asyncio.wait_for(task, timeout=self.config.callback_timeout)
                        except Exception as e:
                            logger.warning(f"[scorer] callback failed: {e}")

                    # Score CRITICAL → kill immédiat
                    if self.scorer.threat_level == "CRITICAL" and not self.killed:
                        logger.critical(f"[scorer] score={self.scorer.threat_score} -> killing container")
                        await self.kill_container()

                else:
                    await asyncio.sleep(0.05)

            logger.info(
                f"[scorer] stopped | final_score={self.scorer.threat_score} "
                f"level={self.scorer.threat_level} alerts={len(self.scorer.alerts)}"
            )

        except asyncio.CancelledError:
            raise

    async def _task_decay(self) -> None:
        """Applique le decay du score périodiquement."""
        try:
            if not self.config:
                return
            
            while self.running:
                await asyncio.sleep(self.config.decay_interval)
                if self.running and self.scorer and self.scorer.threat_score > 0:
                    self.scorer.decay()
                    logger.info(
                        f"[decay] score={self.scorer.threat_score} level={self.scorer.threat_level}"
                    )

        except asyncio.CancelledError:
            raise

    async def _monitor_running_state(self) -> None:
        """Attend la fin de l'exécution puis arrête proprement tous les composants."""
        while self.running:
            await asyncio.sleep(1)

        logger.info("[orchestrator] execution finished, stopping components")
        await self.stop_tasks_and_monitors(self.monitors, self.tasks)
        try:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        except Exception:
            pass

    # =========================================================================
    # Gestion du cycle de vie
    # =========================================================================

    async def kill_container(self) -> None:
        """Tue le container immédiatement (score CRITICAL)."""
        self.killed = True
        self.running = False
        try:
            await asyncio.to_thread(self.manager.kill)
            logger.info("[container] killed (CRITICAL threshold reached)")
        except Exception as e:
            logger.warning(f"[container] kill failed: {e}")

    def build_report(self, session_id: str, stats: dict | None = None) -> SandboxReport:
        """
        Construit le rapport final de session.

        Args:
            session_id: Identifiant de la session.
            stats: Statistiques supplémentaires.

        Returns:
            SandboxReport complet.
        """
        if not self.config:
            raise ValueError("configuration manquante")

        return SandboxReport(
            session_id=session_id,
            config=self.config,
            exec_result=self.exec_result,
            final_score=self.scorer.threat_score if self.scorer else 0,
            final_level=self.scorer.threat_level if self.scorer else "LOW",
            alerts=self.scorer.alerts.copy() if self.scorer else [],
            session_duration=time.time() - self.session_start,
            timestamp=datetime.utcnow(),
            killed=self.killed,
            stats=stats or {},
        )

    async def stop_tasks_and_monitors(self, monitors: list = None, tasks: list = None) -> None:
        """
        Arrête les moniteurs et annule les tâches asyncio.

        Args:
            monitors: Liste des moniteurs à arrêter.
            tasks: Liste des tâches à annuler.
        """
        if monitors:
            for monitor in monitors:
                if monitor and hasattr(monitor, "stop"):
                    try:
                        r = monitor.stop()
                        if asyncio.iscoroutine(r):
                            r = await r
                    except Exception as e:
                        logger.warning(f"[stop] monitor error: {e}")

        if tasks:
            for task in tasks:
                try:
                    task.cancel()
                except Exception:
                    pass
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    def stop_manager(self) -> None:
        """Détruit le container Docker."""
        try:
            self.manager.stop()
            logger.info("[container] destroyed")
        except Exception as e:
            logger.warning(f"[container] destroy failed: {e}")
        
        try:
            self.manager.client.close()
        except Exception:
            pass
    
    @staticmethod
    def get_key( 
        code: str,
        language: str | None = None,
        config: SandboxConfig | None = None,
    ):
        import hashlib
        key_data = (
            str(code) + str(language) + 
                (json.dumps(config.cache_key_dict(), sort_keys=True, default=str) if config else "")
        )
        return hashlib.md5(key_data.encode()).hexdigest()
    
        
    @staticmethod
    def cache(key: str, value: dict):
        CACHE.set(key=key, value=value, expire=CACHE_TIMEOUT)
        return True
    
    @staticmethod
    def get_cache(
        key: str = None,
        code: str = "",
        language: str | None = None,
        config: SandboxConfig | None = None,
    ):
        if not key:
            key = SandboxOrchestrator.get_key(code, language, config)
        
        return CACHE.get(key=key, default=None)
    # =========================================================================
    # Méthode publique
    # =========================================================================

    async def analyze(
        self,
        code: str,
        language: str | None = None,
        config: SandboxConfig | None = None,
        use_cache: bool = True,
        **kwargs,
    ) -> SandboxReport:
        """
        Lance une analyse comportementale complète.

        Args:
            code: Code source à analyser.
            language: Langage (None = détection auto).
            config: Configuration personnalisée (None = défauts).
            **kwargs: Surcharges rapides de la configuration.

        Returns:
            Rapport final de l'analyse.

        Examples:
            # Défaut
            report = await orchestrator.analyze(code, language="python")

            # Avec config personnalisée
            config = SandboxConfig(mem_limit="1g", alert_threshold=50)
            report = await orchestrator.analyze(code, config=config)

            # Surcharge rapide
            report = await orchestrator.analyze(code, mem_limit="1g", exec_timeout=60)
        """
        # --- Initialisation -------------------------------------------------
        if config is None:
            config = SandboxConfig()
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                logger.warning(f"[config] unknown parameter ignored: {key}")
                
        self.config = config
        cache_key = self.get_key(
            code=code,
            language=language,
            config=self.config
        )
        if use_cache:
            cache = self.get_cache(
                key=cache_key
            )
            if cache:
                logger.info("Cache trouvé et utilisé")
                return SandboxReport.from_dict(cache)

        session_id = config.container_name or f"shieldai_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_start = time.time()
        self.running = True
        self.killed = False

        # --- Header ---------------------------------------------------------
        logger.info("=" * 60)
        logger.info(f"ShieldAI Sandbox | {session_id}")
        logger.info(f"  memory={config.mem_limit} timeout={config.exec_timeout}s")
        logger.info(f"  strace={config.enable_strace} fsmon={config.enable_fs_monitor}")
        logger.info("=" * 60)

        # --- Queue ----------------------------------------------------------
        raw_queue = asyncio.Queue(maxsize=10000)
        event_queue = SandBoxQueue(raw_queue)
        stats = {}

        try:
            # --- Container -------------------------------------------------
            logger.info("[container] starting...")
            if not self.setup_container():
                logger.error("[container] failed to start, aborting")
                self.running = False
                return self.build_report(session_id)

            logger.info("[container] ready")

            # --- Chemins strace --------------------------------------------
            strace_file = os.path.join(self.manager.volume_dir, self.manager.strace_file)
            strace_file_on_container = os.path.join(
                self.manager.volume_dir_on_container, self.manager.strace_file
            )

            # --- Lancement des tâches --------------------------------------
            tasks = [
                self._task_execute(code, language, strace_file_on_container),
                self._task_syscall_tracer(strace_file, event_queue),
                self._task_fs_monitor(event_queue),
                self._task_scorer(event_queue),
                self._task_decay(),
            ]
            self.tasks = [asyncio.create_task(t) for t in tasks]

            start_stats = {
                "container_pid": self.manager.get_pid(),
                "fs_root": self.manager.get_fs_root(),
            }

            await self._monitor_running_state()

            stats = {
                **start_stats,
                "events_processed": len(self.scorer.alerts) if self.scorer else 0,
                "syscall_stats": self.syscall_tracer.stats if self.syscall_tracer else None,
            }

        except Exception as e:
            logger.error(f"[orchestrator] fatal error: {e}")
            self.running = False
            stats = {"error": str(e)}
            import traceback
            traceback.print_exc()

        finally:
            self.stop_manager()

        # --- Rapport -------------------------------------------------------
        report = self.build_report(session_id, stats=stats)

        logger.info("=" * 60)
        logger.info(f"REPORT | {session_id}")
        logger.info(f"  score={report.final_score}/100 [{report.final_level}]")
        logger.info(f"  alerts={len(report.alerts)} duration={report.session_duration:.2f}s")
        logger.info(f"  killed={report.killed}")
        if report.stats:
            logger.info(f"  stats={report.stats}")
        logger.info("=" * 60)
        self.cache(
            key=cache_key, value=report.to_dict()
        )
        return report


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":

    SUSPICIOUS_CODE = """
import os
import time

for path in ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/etc/hosts"]:
    try:
        with open(path, "r") as f:
            print(f"[+] {path} ({len(f.read())} bytes)")
    except Exception as e:
        print(f"[-] {path}: {e}")
    time.sleep(2)

for name in ["backdoor.sh", "exfil.b64", "payload.elf"]:
    with open(f"/tmp/{name}", "w") as f:
        f.write("malicious content")
    print(f"[+] created: /tmp/{name}")
    time.sleep(2)

print("[+] done")
"""

    async def main():
        config = SandboxConfig(
            image_name="shieldai-sandbox:v2-light",
            mem_limit="512m",
            exec_timeout=60.0,
            alert_threshold=50,
            decay_interval=5.0,
            enable_strace=True,
            enable_fs_monitor=True,
            user="root",
            exec_user="root",
            on_alert_callback=lambda alert: print(f"[callback] alert: {alert.threat_score}"),
        )

        orchestrator = SandboxOrchestrator()
        report = await orchestrator.analyze(code=SUSPICIOUS_CODE, language="python", config=config, use_cache=False)

        print(f"\n{'=' * 50}")
        print("FINAL RESULT")
        print(f"{'=' * 50}")
        print(f"Score: {report.final_score}/100 ({report.final_level})")
        print(f"Alerts: {len(report.alerts)}")
        print(f"Killed: {report.killed}")
        print(f"Duration: {report.session_duration:.2f}s")

        for alert in report.alerts[:5]:
            print(f"  • {alert.threat_level} | score={alert.threat_score}")

        if report.exec_result and report.exec_result.stdout:
            print(f"\nstdout: {report.exec_result.stdout[:200]}")

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    asyncio.run(main())