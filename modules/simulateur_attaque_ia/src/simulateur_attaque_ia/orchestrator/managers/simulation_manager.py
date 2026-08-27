#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
SimulationManager – singleton qui orchestre le cycle de vie des simulations.

Responsabilités :
  - Lancer / arrêter des sims (auto ou interactif)
  - Limiter le nombre de sims parallèles (env: SIM_MAX_CONCURRENT)
  - Exposer l'état live de chaque sim
  - Persister l'historique dans diskcache (clé = session_id)
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import json
import asyncio
import diskcache
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from copy import deepcopy
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from simulateur_attaque_ia.configs.config import (
    CACHE_DIR, 
    SIM_MAX_CONCURRENT as _MAX_CONCURRENT,
    SIM_KEEP_DELAY,
    CACHE_EXP,
    DEFAULT_API_KEYS, LLAMA_SERVER_HOST, LLAMA_SERVER_PORT,
    LLAMA_SERVER_PATH, LLAMA_MODELS_PRESET
)
from simulateur_attaque_ia.orchestrator.auto_orchestrator import CONFIG_DIR
from simulateur_attaque_ia.orchestrator.managers.ws_manager import WSManager
from simulateur_attaque_ia.orchestrator.interactive_web_orchestrator import InteractiveWebOrchestrator
from simulateur_attaque_ia.orchestrator.auto_orchestrator import AutoAttackOrchestrator, DEFAULT_INPUT_DICT
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.core.services_manager import ServiceManager
from simulateur_attaque_ia.core.services_validator import validate_services_dict
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager
from simulateur_attaque_ia.api.models.sim_models import (
    LLMConfig,
    SimConfig,
    SimMode,
    SimStatus,
    StartSimRequest,
    SimHistoryEntry,
)
from simulateur_attaque_ia.simulateur_utils.ids_utils import random_session_id
from simulateur_attaque_ia.orchestrator.managers.utils import _sim_config_to_flat

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR,  exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Structure interne d'une simulation active
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActiveSim:
    session_id:    str
    mode:          SimMode
    image:         str
    status:        SimStatus            = SimStatus.STARTING
    started_at:    datetime             = field(default_factory=datetime.utcnow)
    ended_at:      Optional[datetime]   = None
    current_step:  Optional[str]        = None
    progress:      float                = 0.0
    error:         Optional[str]        = None
    actions_done:  List[str]            = field(default_factory=list)

    # Runtime – pas sérialisés
    docker_manager: Any                 = field(default=None, repr=False)
    orchestrator:   Any                 = field(default=None, repr=False)   # Auto ou Interactive
    task:           Optional[asyncio.Task] = field(default=None, repr=False)

    # File d'attente pour le mode interactif (WS handler → orchestrator)
    action_queue:   asyncio.Queue       = field(default_factory=asyncio.Queue, repr=False)

    def to_dict(self) -> dict:
        return {
            "session_id":   self.session_id,
            "mode":         self.mode.value,
            "image":        self.image,
            "status":       self.status.value,
            "started_at":   self.started_at.isoformat(),
            "ended_at":     self.ended_at.isoformat() if self.ended_at else None,
            "current_step": self.current_step,
            "progress":     self.progress,
            "error":        self.error,
            "actions_done": self.actions_done,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SimulationManager
# ─────────────────────────────────────────────────────────────────────────────

class SimulationManager:
    _instance: Optional["SimulationManager"] = None
    _llm_manager: Optional[LLMManager] = None
    _llm_init_failed: bool = False
    _llm_lock: asyncio.Lock = asyncio.Lock()

    def __init__(self) -> None:
        self._sims: Dict[str, ActiveSim] = {}
        self._history = diskcache.Cache(CACHE_DIR)
        self._cleanup_task: Optional[asyncio.Task] = None 
    
    async def _get_llm_manager(self) -> Optional[LLMManager]:
        """Construit le LLMManager UNE SEULE FOIS (partagé entre toutes les sims).
        Retourne None si jamais configuré/indisponible, sans planter l'appelant."""
        if SimulationManager._llm_manager is not None:
            return SimulationManager._llm_manager
        
        if SimulationManager._llm_init_failed:
            return None

        async with SimulationManager._llm_lock:
            if SimulationManager._llm_manager is not None:
                return SimulationManager._llm_manager
            
            if SimulationManager._llm_init_failed:
                return None
            
            try:
                SimulationManager._llm_manager = await asyncio.to_thread(
                    LLMManager,
                    llama_server_path=LLAMA_SERVER_PATH,
                    host=LLAMA_SERVER_HOST,
                    port=LLAMA_SERVER_PORT,
                    api_keys=DEFAULT_API_KEYS,
                    models_preset=LLAMA_MODELS_PRESET,
                    sync=False,
                )
                
            except Exception as e:
                self._llm_init_failed = True
                print(f"⚠️ LLM indisponible, sim continuera sans IA : {e}")
                return None
            
        return SimulationManager._llm_manager
    
    # ── Background cleanup ────────────────────────────────────────────────────
    
    async def _cleanup_loop(self) -> None:
        """Purge les sims terminées de la RAM après SIM_KEEP_DELAY secondes."""
        while True:
            try:
                await asyncio.sleep(120)  # vérifie toutes les 2 min
                now = datetime.now(tz=timezone.utc)
                to_remove = [
                    (sid, sim, sim.task) for sid, sim in list(self._sims.items())
                    if sim.status in (SimStatus.COMPLETED, SimStatus.FAILED, SimStatus.STOPPED)
                    and sim.ended_at is not None
                    and (now - sim.ended_at).total_seconds() > SIM_KEEP_DELAY
                ]
                
                if to_remove:
                    await self._stop_tasks([t[-1] for t in to_remove if not t[-1].done()])
                    for (sid, _, _) in to_remove:
                        self._sims.pop(sid, None)
            except asyncio.CancelledError:
                break
            
            except Exception:
                pass
    
    def start_background_tasks(self) -> None:
        """À appeler dans le lifespan FastAPI (avant le yield)."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    # ── Arrêt propre ──────────────────────────────────────────────────────────
    @staticmethod
    async def _stop_tasks(tasks, timeout: int | float = 10):
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=(timeout or 10.0))
            if pending:
                    for t in pending: 
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
        
        return 
    
    async def stop_all_sims(self, ws_manager) -> None:
        """
        Arrête toutes les sims actives.
        À appeler dans le lifespan FastAPI (après le yield).
        """
        active = [
            sim for sim in self._sims.values()
            if sim.status in (SimStatus.STARTING, SimStatus.RUNNING, SimStatus.WAITING)
        ]
        for sim in active:
            # Signaler aux orchestrateurs interactifs
            if sim.mode == SimMode.INTERACTIVE:
                await sim.action_queue.put(None)
    
            # Annuler la task asyncio
            if sim.task and not sim.task.done():
                sim.task.cancel()
    
        # Attendre que toutes les tasks se terminent (max 10s)
        tasks = [
            sim.task for sim in active
            if sim.task and not sim.task.done()
        ]
        await self._stop_tasks(tasks, 10.0)
                    
        for sim in active:
            sim.status   = SimStatus.STOPPED
            sim.ended_at = sim.ended_at or datetime.now(tz=timezone.utc)
            self._save_history(sim)
    
    async def stop_background_tasks(self) -> None:
        """Annule la task de cleanup."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    @classmethod
    def get_instance(cls) -> "SimulationManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Capacité ─────────────────────────────────────────────────────────────

    def _running_count(self) -> int:
        return sum(
            1 for s in self._sims.values()
            if s.status in (SimStatus.STARTING, SimStatus.RUNNING, SimStatus.WAITING)
        )

    def can_start(self) -> bool:
        return self._running_count() < _MAX_CONCURRENT

    # ── Lancement ────────────────────────────────────────────────────────────
    
    async def _image_exists(self, image: str) -> bool:
        """Vérifie que l'image existe parmi celles connues de Docker (clonées ou pas)."""
        dm = DockerManager()
        images = await asyncio.to_thread(dm.list_images)
        known_tags = {
            tag
            for img in images
            for tag in (img.get("tags") or [])
            if tag != "<none>"
        }
        return image in known_tags

    async def start_sim(
        self,
        request:    StartSimRequest,
        ws_manager: WSManager,
    ) -> str:
        """
        Lance une simulation et retourne le session_id.
        Lève ValueError si le quota max est atteint.
        """
        if not self.can_start():
            raise ValueError(
                f"Quota atteint : {_MAX_CONCURRENT} simulation(s) en parallèle maximum. "
                f"Arrêtez une sim ou augmentez SIM_MAX_CONCURRENT."
            )
        
        if not await self._image_exists(request.image):
            raise ValueError(
                f"Image '{request.image}' introuvable. Clonez-la d'abord via POST /clone/start, "
                f"ou vérifiez GET /images/list pour la liste des images disponibles."
            )
        
        session_id = random_session_id()
        
        sim = ActiveSim(
            session_id=session_id,
            mode=request.mode,
            image=request.image,
            status=SimStatus.STARTING,
        )
        self._sims[session_id] = sim

        # Notif démarrage
        await ws_manager.send(session_id, {
            "type":       "sim_status",
            "status":     SimStatus.STARTING.value,
            "session_id": session_id,
            "message":    "Initialisation de la simulation…",
        })

        if request.mode == SimMode.AUTO:
            task = asyncio.create_task(
                self._run_auto(sim, request, ws_manager)
            )
        else:
            task = asyncio.create_task(
                self._run_interactive(sim, request, ws_manager)
            )

        task.add_done_callback(lambda t: self._on_task_done(session_id, t, ws_manager))
        sim.task = task

        return session_id

    # ── Mode AUTO ────────────────────────────────────────────────────────────
    
    @staticmethod
    async def _handle_run_start(
        sim:        ActiveSim,
        request:    StartSimRequest,
        ws_manager: WSManager,
        docker_manager: DockerManager,
    ):
        # ── Docker ────────────────────────────────────────────────────
        await ws_manager.send(sim.session_id, {
            "type": "sim_status", "status": "starting",
            "message": f"Lancement du container {request.image}…",
        })

        container_name = request.container_name or f"simatk_{sim.session_id}"
        docker_kwargs: dict = {}
        if not request.authorize_network:
            docker_kwargs["network"] = "isolated"
        
        else:
            docker_kwargs["network"] = "bridge"
            
        if request.network_caps:
            docker_kwargs["cap_add"] = ["NET_RAW", "NET_ADMIN"]
        
        docker_kwargs["labels"] = {
            "simatk": "true",
            "simatk.owner": f"sim:{sim.session_id}"
        }
        await asyncio.to_thread(
            docker_manager.connect, 
            name_img=request.image, 
            name=container_name,
            **docker_kwargs
        )
        network_name = docker_kwargs.get("network", "bridge")
        ip = await asyncio.to_thread(docker_manager.get_ip, network_name)
        sim.docker_manager = docker_manager
        await ws_manager.send(sim.session_id, {
            "type": "sim_status", "status": "starting",
            "message": f"Container {container_name} lancé, image({request.image})",
        })
        
        # ── Services ──────────────────────────────────────────────────
        services = request.services
        
        if services is not None and validate_services_dict(services).valid:
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Services fournis valides. Utilisation pour la restauration.",
            })
        
        elif request.auto_capture:
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Services invalides ou non fournis. Capture des services en cours…",
            })
            svc_mgr = ServiceManager()
            services = await asyncio.to_thread(
                svc_mgr.capture_services,
                excluded_pids=request.capture_excluded_pids,
                excludes_names=request.capture_excluded_names,
                excluded_ports=request.capture_excluded_ports,
                only_listening=request.only_listening,
                use_default_excludes=request.use_default_excludes,
            )
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": f"Capture terminée ({len(services)} process retenus).",
            })
        
        else:
            services = {}
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Capture désactivée (auto_capture=False) — default_services uniquement.",
            })
        
        if services or request.default_services:
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Restauration des services…",
            })
            await asyncio.to_thread(
                ServiceManager.restore_services,
                docker_manager,
                list(services.values()) if services else None,
                default_services=request.default_services,
            )
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Services restaurés.",
            })
        
        else:
            await ws_manager.send(sim.session_id, {
                "type": "sim_status", "status": "starting",
                "message": "Pas de services à restaurer.",
            })
        
        return ip
            
    async def _run_auto(
        self,
        sim:        ActiveSim,
        request:    StartSimRequest,
        ws_manager: WSManager,
    ) -> None:
        docker_manager = DockerManager()
        
        ip = None
        try:
            # ── Préparation de l'environnement ───────────────────────
            ip = await self._handle_run_start(sim, request, ws_manager, docker_manager)
            
            # ── Config fichier pour l'orchestrateur ───────────────────────
            config_path = self._write_config(sim.session_id, request.sim_config, ip)

            # ── LLM ───────────────────────────────────────────────────────
            llm = await self._get_llm_manager() if request.use_llm else None
            use_llm_effectif = llm is not None
            if request.use_llm and llm is None:
                await ws_manager.send(sim.session_id, {
                    "type": "sim_status", "status": "starting",
                    "message": "⚠️ LLM demandé mais indisponible sur cette instance — simulation lancée sans IA.",
                })

            # ── Dashboard callback → WS ────────────────────────────────────
            async def dashboard_callback(msg: dict, session_id: str, in_dev: bool = True):
                # Mettre à jour l'état live
                if msg.get("type") == "step_start":
                    sim.current_step = msg.get("step")
                elif msg.get("type") == "step_end":
                    step = msg.get("step")
                    if step and step not in sim.actions_done:
                        sim.actions_done.append(step)
                elif msg.get("type") == "finish":
                    sim.progress = 100.0

                prog = msg.get("progress")
                if prog is not None:
                    sim.progress = float(prog)

                await ws_manager.send(session_id, msg)

            # ── Orchestrateur ─────────────────────────────────────────────
            orchestrator = AutoAttackOrchestrator(
                docker_manager=docker_manager,
                config_path=config_path,
                llm=llm,
                use_llm=use_llm_effectif,
                dashboard_callback=dashboard_callback,
            )
            sim.orchestrator = orchestrator
            sim.status       = SimStatus.RUNNING

            await ws_manager.send(sim.session_id, {
                "type":    "sim_status",
                "status":  SimStatus.RUNNING.value,
                "message": f"Sim auto démarrée — cible {ip}",
                "ip":      ip,
            })

            # ── RUN ───────────────────────────────────────────────────────
            report = await orchestrator.run_async(sim.session_id)
            report["logs"] = list(ws_manager._buffers.get(sim.session_id, report.get("logs", [])))
            sim.status = SimStatus.COMPLETED

            await ws_manager.send(sim.session_id, {
                "type":    "sim_finished",
                "status":  SimStatus.COMPLETED.value,
                "report":  report,
                "message": "Simulation terminée avec succès.",
            })

            self._save_history(sim, report=report)

        except asyncio.CancelledError:
            sim.status = SimStatus.STOPPED
            report = {
                "state": {},
                "report": {}, 
                "out": None, 
                "err": None, 
                "logs": list(ws_manager._buffers.get(sim.session_id, []))
            }
            self._save_history(sim, report=report)
            raise
            
        except Exception as exc:
            sim.status = SimStatus.FAILED
            sim.error  = str(exc)
            import traceback
            trace = traceback.format_exc()
            await ws_manager.send(sim.session_id, {
                "type":    "error",
                "status":  SimStatus.FAILED.value,
                "message": str(exc),
                "trace": trace
            })
            report = {
                "state": {},
                "report": {}, 
                "out": None, 
                "err": None, 
                "logs": list(ws_manager._buffers.get(sim.session_id, []))
            }
            self._save_history(sim, report=report)
            raise
            
        finally:
            self._cleanup_docker(docker_manager)
            self._sims.pop(sim.session_id, None)

    # ── Mode INTERACTIF ───────────────────────────────────────────────────────

    async def _run_interactive(
        self,
        sim:        ActiveSim,
        request:    StartSimRequest,
        ws_manager: WSManager,
    ) -> None:

        docker_manager = DockerManager()
        ip = None
        try:
            # ── Préparation de l'environnement ───────────────────────
            ip = await self._handle_run_start(sim, request, ws_manager, docker_manager)
            
            # ── LLM ───────────────────────────────────────────────────────
            llm = await self._get_llm_manager() if request.use_llm else None

            # ── Orchestrateur interactif ───────────────────────────────────
            orchestrator = InteractiveWebOrchestrator(
                docker_manager=docker_manager,
                ip=ip,
                sim_config=request.sim_config,
                use_llm=llm is not None,
                llm=llm,
                ws_send=lambda msg: ws_manager.send(sim.session_id, msg),
            )
            sim.orchestrator = orchestrator
            sim.status       = SimStatus.WAITING

            # ── Notifier le client que la sim est prête ────────────────────
            await ws_manager.send(sim.session_id, {
                "type":             "sim_ready",
                "session_id":       sim.session_id,
                "ip":               ip,
                "actions_available":orchestrator.available_actions(),
                "state_summary":    orchestrator.get_state_summary(),
                "message":          f"Sim interactive prête — cible {ip}",
            })

            # ── Boucle : attente de messages du WS handler ─────────────────
            # Le WS handler (ws_router.py) push des messages dans action_queue
            while True:
                msg = await sim.action_queue.get()
                if msg is None:
                    break

                msg_type = msg.get("type")

                if msg_type == "execute_action":
                    action = msg.get("action", "")
                    params = msg.get("params", {})
                    sim.current_step = action
                    sim.status = SimStatus.RUNNING
                    
                    if action == "finish":
                        break
                    
                    result = await orchestrator.execute_step(action, params)
                    if action not in sim.actions_done:
                        sim.actions_done.append(action)
                    sim.status = SimStatus.WAITING

                    await ws_manager.send(sim.session_id, {
                        "type":              "step_result",
                        "step":              action,
                        "result":            result,
                        "actions_available": orchestrator.available_actions(),
                        "actions_details": result.get("actions_details", orchestrator.available_actions_with_details()),
                        "actions_done":      sim.actions_done,
                    })
                    
                elif msg_type == "request_llm_suggest":
                    suggestion = await orchestrator.llm_suggest()
                    await ws_manager.send(sim.session_id, {
                        "type":       "llm_suggest",
                        "suggestion": suggestion,
                    })

                elif msg_type == "request_llm_review":
                    action = msg.get("action", "")
                    review = await orchestrator.llm_review(action)
                    await ws_manager.send(sim.session_id, {
                        "type":   "llm_review",
                        "action": action,
                        "review": review,
                    })

                elif msg_type == "get_state":
                    await ws_manager.send(sim.session_id, {
                        "type":  "sim_state",
                        "state": orchestrator.get_state_summary(),
                    })

                elif msg_type == "finish":
                    break

            # ── Rapport final ─────────────────────────────────────────────
            report = orchestrator.build_report()
            sim.status = SimStatus.COMPLETED
            
            report["logs"] = list(ws_manager._buffers.get(sim.session_id, report.get("logs", [])))
            await ws_manager.send(sim.session_id, {
                "type":    "sim_finished",
                "status":  SimStatus.COMPLETED.value,
                "report":  report,
                "message": "Simulation interactive terminée.",
            })
            self._save_history(sim, report=report)

        except asyncio.CancelledError:
            sim.status = SimStatus.STOPPED
            report = InteractiveWebOrchestrator.build_empty_report()
            report["ip"] = ip
            report["logs"] = list(ws_manager._buffers.get(sim.session_id, []))
            self._save_history(sim, report)
            raise
            
        except Exception as exc:
            sim.status = SimStatus.FAILED
            sim.error  = str(exc)
            import traceback
            trace = traceback.format_exc()
            await ws_manager.send(sim.session_id, {
                "type":    "error",
                "status":  SimStatus.FAILED.value,
                "message": str(exc),
                "trace": trace
            })
            report = InteractiveWebOrchestrator.build_empty_report()
            report["ip"] = ip
            report["logs"] = list(ws_manager._buffers.get(sim.session_id, []))
            self._save_history(sim, report)
            raise
            
        finally:
            self._cleanup_docker(docker_manager)
            self._sims.pop(sim.session_id, None)

    # ── Stop ─────────────────────────────────────────────────────────────────

    async def stop_sim(self, session_id: str, ws_manager: WSManager) -> bool:
        sim = self._sims.get(session_id)
        if sim is None:
            return False

        if sim.mode == SimMode.INTERACTIVE:
            await sim.action_queue.put(None)    # signal de terminaison propre

        if sim.task and not sim.task.done():
            sim.task.cancel()
            try:
                await sim.task
            except (asyncio.CancelledError, Exception):
                pass

        sim.status   = SimStatus.STOPPED
        sim.ended_at = datetime.now(tz=timezone.utc)

        await ws_manager.send(session_id, {
            "type":    "sim_status",
            "status":  SimStatus.STOPPED.value,
            "message": "Simulation arrêtée manuellement.",
        })

        ws_manager.schedule_cleanup(session_id)
        return True

    # ── Getters ──────────────────────────────────────────────────────────────

    def get_sim(self, session_id: str) -> Optional[ActiveSim]:
        return self._sims.get(session_id)

    def list_sims(self) -> List[dict]:
        return [s.to_dict() for s in self._sims.values()]

    def get_report(self, session_id: str) -> Optional[dict]:
        entry = self._history.get(session_id)
        if entry:
            return entry.get("sim_result")
        return None

    # ── Historique ────────────────────────────────────────────────────────────

    def _save_history(self, sim: ActiveSim, report: Optional[dict] = None) -> None:
        sim.ended_at = sim.ended_at or datetime.now(tz=timezone.utc)
        entry = {
            **sim.to_dict(),
            "sim_result": report,
        }
        self._history.set(
            key=sim.session_id,
            value=entry,
            expire=CACHE_EXP
        )

    def list_history(self) -> List[dict]:
        return [
            self._history[k]
            for k in self._history.iterkeys()
        ]

    def get_history(self, session_id: str) -> Optional[dict]:
        return self._history.get(session_id)

    # ── Helpers privés ────────────────────────────────────────────────────────

    def _write_config(
        self,
        session_id: str,
        sim_config: Optional[SimConfig],
        ip:         str,
    ) -> str:
        """Écrit le fichier de config JSON5 pour AutoAttackOrchestrator."""

        conf = deepcopy(DEFAULT_INPUT_DICT)
        conf["ip"] = ip

        if sim_config:
            conf.update(_sim_config_to_flat(sim_config))

        path = os.path.join(CONFIG_DIR, "configs", f"{session_id}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(conf, f)
        return path

    # @staticmethod
    # def _build_llm(request: StartSimRequest | None = None):
    #     """Instancie le LLMManager selon la config."""
    #     return LLMManager(
    #         llama_server_path=LLAMA_SERVER_PATH,
    #         host=LLAMA_SERVER_HOST,
    #         port=LLAMA_SERVER_PORT,
    #         api_keys=DEFAULT_API_KEYS,
    #         models_preset=LLAMA_MODELS_PRESET,
    #         sync=False,
    #     )

    @staticmethod
    def _cleanup_docker(docker_manager: DockerManager) -> None:
        try:
            if not docker_manager or not docker_manager.container:
                return
            owner = docker_manager.get_labels().get("simatk.owner", "")
            if owner.startswith("sim:"):
                docker_manager.stop()
            
            else:
                print(
                    f"Container '{docker_manager.container.name}' réutilisé. "
                    f"(pas crée par cette simulation) - conservé après simulation"
                )
        except Exception:
            pass

    def _on_task_done(
        self,
        session_id: str,
        task:       asyncio.Task,
        ws_manager: WSManager,
    ) -> None:
        sim = self._sims.get(session_id)
        if sim and sim.ended_at is None:
            sim.ended_at = datetime.now(tz=timezone.utc)
        ws_manager.schedule_cleanup(session_id)
