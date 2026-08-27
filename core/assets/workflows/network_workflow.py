#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul  3 20:39:32 2026

@author: hounsousamuel
"""

import os, sys

import signal
import asyncio
import subprocess
from pathlib import Path
from ids_ips_ia.config.config_manager import Config, GLOBAL_CONFIG_KEY
from ids_ips_ia.core.capture import detect_all_ifaces
from obsidian_hive.core.assets.workflows.workflow_base import WorkflowBase
from modules_utils.loop_utils import _run_async
from obsidian_hive.core.assets.asset_types import (
    NetworkAsset, NetworkDeploymentMode, DEFAULT_IDS_CONFIG_PATH,
    ObsidianValidationError
)
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.managers.report_manager import ReportManager
from modules_utils.logger import get_logger
from obsidian_hive.core.assets.workflows.workflow_utils.run_ids_ips import __file__ as run_file
logger = get_logger("network_workflow")

GRACEFUL_STOP_TIMEOUT = 15  # secondes avant escalade vers kill()
RUN_IDS_IPS_PATH = run_file
# RUN_IDS_IPS_PATH = os.path.abspath(
#     os.path.join(
#         os.path.dirname(__file__),
#         "workflow_utils", "run_ids_ips.py",
        
#     )
# )



class NetworkWorkflow(WorkflowBase):
    """Workflow pour la surveillance réseau IDS/IPS.
    
    Cette classe gère le déploiement et l'exécution d'un système IDS/IPS
    sur un asset réseau. Elle supporte trois modes de déploiement :
    Gateway, SPAN/Mirroring et Bridge transparent.
    
    Attributes:
        asset (NetworkAsset): L'asset réseau à surveiller.
        process (asyncio.subprocess.Process | None): Le processus IDS/IPS en cours d'exécution.
    """
    
    def __init__(
        self, 
        asset: NetworkAsset, 
        do_silence: bool = False,
        llm_manager: LLMManager = None,
        report_manager: ReportManager = None
    ):
        """Initialise le workflow de surveillance réseau.

        Args:
            asset (NetworkAsset): L'asset réseau à surveiller.
            do_silence (bool, optional): Non utilisé pour ce workflow. Par défaut False.
            llm_manager (LLMManager | None, optional): Gestionnaire LLM optionnel. Par défaut None.
            report_manager (ReportManager | None, optional): Gestionnaire de rapports optionnel. Par défaut None.
        """
        super().__init__(llm_manager=llm_manager, report_manager=report_manager)
        self.asset = asset
        self.process: asyncio.subprocess.Process | None = None
    
    async def _setup_deployment(self):
        """Configure le déploiement réseau en fonction du mode choisi.
        
        - GATEWAY : Utilise les interfaces détectées telles quelles.
        - SPAN_MIRROR : Active le mode promiscuous sur les interfaces.
        - BRIDGE : Crée un bridge Linux et y attache les interfaces.
        
        La configuration est persistée dans le fichier de configuration IDS.
        """
        
        mode = self.asset.deployment_mode
        conf = Config(self.asset.config_path)
        interfaces = conf.CONFIG[GLOBAL_CONFIG_KEY]["interface"] or detect_all_ifaces() or []
        if isinstance(interfaces, str):
            interfaces = [interfaces]
    
        def _run_ip_cmds():
            if mode == NetworkDeploymentMode.SPAN_MIRROR.value:
                for iface in interfaces:
                    subprocess.run(["ip", "link", "set", iface, "promisc", "on"], check=False)
                conf.update("GLOBAL_CONFIG", {"interface": interfaces})
        
            elif mode == NetworkDeploymentMode.BRIDGE.value:
                bridge_name = f"br-{self.asset.id[-8:]}"
        
                # Idempotence : on ne tente la création que si le bridge n'existe
                # pas déjà (utile aux redémarrages — évite un `ip link add` retenté
                # à chaque run_async(), même si check=False l'avalait déjà).
                exists = subprocess.run(
                    ["ip", "link", "show", bridge_name],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                ).returncode == 0
        
                if not exists:
                    subprocess.run(["ip", "link", "add", bridge_name, "type", "bridge"], check=False)
                    for iface in interfaces:
                        subprocess.run(["ip", "link", "set", iface, "master", bridge_name], check=False)
                    subprocess.run(["ip", "link", "set", bridge_name, "up"], check=False)
                else:
                    logger.info(message=f"Bridge {bridge_name} déjà présent, réutilisation (asset {self.asset.id})")
        
                conf.update(GLOBAL_CONFIG_KEY, {"interface": [bridge_name]})
        
            elif mode == NetworkDeploymentMode.GATEWAY.value:
                conf.update(GLOBAL_CONFIG_KEY, {"interface": interfaces})
    
        await asyncio.to_thread(_run_ip_cmds)
    
    async def run_async(self):
        """Exécute le workflow de surveillance réseau de manière asynchrone.
        
        Configure le déploiement, valide le chemin de configuration, puis
        lance le processus IDS/IPS en arrière-plan. Gère l'arrêt propre
        en cas d'annulation.

        Returns:
            None: Le processus tourne en arrière-plan.

        Raises:
            asyncio.CancelledError: Si la tâche est annulée, un arrêt propre est effectué.
        """
        await self._setup_deployment()
        log_path: Path = Path(logger.log_dir) / f"network_{self.asset.id}.log"
        try:
            if log_path.exists():
                os.truncate(log_path.absolute(), 1000)
        except Exception:
            pass
        
        log_file = open(log_path, "a")
        conf_path = self.asset.config_path
        try:
            self.asset.validate_config_path(conf_path)
        except ObsidianValidationError:
            conf_path = DEFAULT_IDS_CONFIG_PATH
            
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, RUN_IDS_IPS_PATH,
            env={
                **os.environ, 
                "IDS_CONFIG_PATH": conf_path,
                "IDS_IPS_INSTANCE_ID": self.asset.id,
            },
            start_new_session=True,
            stdout=log_file,
            stderr=log_file
        )
        try:
            await self.process.wait()
            
        except asyncio.CancelledError:
            await self._graceful_stop()
            raise
        
        finally:
            log_file.close()
    
    async def is_healthy(self) -> bool:
        """Vérifie si le processus IDS/IPS est toujours en vie.

        Returns:
            bool: True si le processus tourne, False sinon.
        """
        if self.process is None or self.process.returncode is not None:
            return False
        return True
    
    # async def health_check_loop(self):
    #     while True:
    #         await asyncio.sleep(30)
    #         if not await self.is_healthy():
    #             logger.warning(f"Network asset {self.asset.id} is dead, restarting...")
    #             await self._graceful_stop()
    #             await self.run_async()
            
    async def _graceful_stop(self):
        """Arrête proprement le processus IDS/IPS.
        
        Envoie d'abord un SIGTERM à tout le groupe de processus, puis
        attend GRACEFUL_STOP_TIMEOUT secondes. Si le processus ne répond
        pas, envoie un SIGKILL.

        Returns:
            None
        """
        if not self.process or self.process.returncode is not None:
            return
    
        try:
            pgid = os.getpgid(self.process.pid)
            logger.info(message=f"Arrêt du process réseau pour asset {self.asset.id}...")
            os.killpg(pgid, signal.SIGTERM)  # SIGTERM à TOUT le groupe (parent + enfants mp.Process)
        except ProcessLookupError:
            logger.info(message="Process déjà terminé")
            self.process = None
            return
        
        try:
            await asyncio.wait_for(self.process.wait(), timeout=GRACEFUL_STOP_TIMEOUT)
            logger.info(message="Arrêt propre réussi")
        except asyncio.TimeoutError:
            logger.warning(message="Process ne répond pas, arrêt forcé (kill du groupe entier)")
            try:
                os.killpg(pgid, signal.SIGKILL)  # même en dernier recours, TOUT le groupe y passe
            except ProcessLookupError:
                pass
            
        except ProcessLookupError:
            pass

        self.process = None

    def run(self):
        """Exécute le workflow de manière synchrone.

        Returns:
            None: Le processus tourne en arrière-plan.
        """
        return _run_async(self.run_async)