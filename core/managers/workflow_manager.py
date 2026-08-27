#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 23 18:08:34 2026

@author: hounsousamuel
"""

import time
import asyncio
import traceback
from obsidian_hive.core.assets.asset_types import AssetItem, AssetType, AssetStatus
from obsidian_hive.core.assets.workflows.web_workflow import WebWorkflow
from obsidian_hive.core.assets.workflows.workflow_base import WorkflowBase
from obsidian_hive.core.assets.workflows.network_workflow import NetworkWorkflow
from obsidian_hive.core.managers.task_manager import TaskManager
from modules_utils.logger import get_logger

logger = get_logger("workflow_manager")

MAPPING = {
    AssetType.WEB_APP.value: WebWorkflow,
    AssetType.WEB_SITE.value: WebWorkflow,
    AssetType.NETWORK.value: NetworkWorkflow,
    # AssetType.EMAIL.value: EmailWorkflow,
}


class WorkflowManager:
    """Gestionnaire des workflows pour les assets.
    
    Orchestre l'exécution des workflows associés aux assets,
    gère la planification périodique et le cycle de vie des tâches.
    
    Attributes:
        task_manager (TaskManager): Gestionnaire des tâches asynchrones.
        do_silence (bool): Si True, supprime les logs de sortie.
        debug (bool): Mode debug.
    """
    
    def __init__(
        self, 
        task_manager: TaskManager,
        do_silence: bool = False,
        debug: bool = False,
    ):
        """Initialise le gestionnaire de workflows.

        Args:
            task_manager (TaskManager): Gestionnaire des tâches asynchrones.
            do_silence (bool, optional): Si True, supprime les logs. Par défaut False.
            debug (bool, optional): Mode debug. Par défaut False.
        """
        self.task_manager = task_manager
        self.do_silence = do_silence
        self.debug = debug
    
    def every(
        self, 
        asset: AssetItem, 
        workflow_class: type[WorkflowBase], 
        workflow_instance_kwargs: dict = None,
        workflow_run_args: list = None,
        workflow_run_kwargs: dict = None,
    ):
        """Crée une coroutine de boucle périodique pour un workflow.

        Args:
            asset (AssetItem): L'asset associé.
            workflow_class (type[WorkflowBase]): La classe du workflow.
            workflow_instance_kwargs (dict, optional): Arguments d'instance du workflow.
            workflow_run_args (list, optional): Arguments d'exécution positionnels.
            workflow_run_kwargs (dict, optional): Arguments d'exécution nommés.

        Returns:
            Callable: Une coroutine qui exécute le workflow en boucle.
        """
        async def _run_workflow() -> None:
            if asset.status.value != AssetStatus.ACTIVE.value:
                return
            workflow = workflow_class(**(workflow_instance_kwargs or {}))
            await workflow.run_async(
                *(workflow_run_args or []),
                **(workflow_run_kwargs or {})
            )
            
        async def _every():
            if asset.last_rest_exec_time not in (0.0, None):
                if asset.every and asset.status.value == AssetStatus.ACTIVE.value:
                    await asyncio.sleep(asset.last_rest_exec_time)
                    await _run_workflow()
                    asset.last_rest_exec_time = None
                    if not asset.already_exec_for_first_time:
                        asset.already_exec_for_first_time = True
                    
            while True:
                if not asset.every or asset.status.value != AssetStatus.ACTIVE.value:
                    await asyncio.sleep(1)
                    continue

                st: float | None = None
                try:
                    st = time.time()
                    await asyncio.sleep(asset.every)
                    await _run_workflow()
                    asset.last_rest_exec_time = None
                    if not asset.already_exec_for_first_time:
                        asset.already_exec_for_first_time = True

                except asyncio.CancelledError:
                    if st is not None:
                        elapsed = time.time() - st
                        asset.last_rest_exec_time = max(0.0, asset.every - elapsed)
                    raise

                except Exception as e:
                    msg = f"Erreur dans every() pour asset {asset.id} : {e}"
                    if self.debug:
                        msg += f"\nTraceback: {traceback.format_exc()}"
                    logger.error(message=msg)
                    
        return _every
    
    async def manage_async(
        self, 
        asset: AssetItem,
    ):
        """Gère l'exécution du workflow pour un asset.

        Démarre le workflow associé à l'asset et, si configuré,
        planifie son exécution périodique.

        Args:
            asset (AssetItem): L'asset à gérer.

        Returns:
            dict | None: Dictionnaire avec les IDs des tâches créées,
                ou None si aucun workflow n'est trouvé.
        """
        asset_type = asset.type.value
        workflow_class = MAPPING.get(asset_type)

        if workflow_class is None:
            logger.warning(message=f"Aucun workflow pour le type d'asset : {asset_type!r}")
            return None
        
        workflow_task_id = f"work-{asset.id}"
        every_task_id = f"every-{asset.id}"  
        asset.workflow_task_id = workflow_task_id
        asset.every_task_id = every_task_id
        
        def _make_work(wf_class: type[WorkflowBase]):
            """Crée une coroutine d'exécution du workflow."""
            async def work() -> None:
                try:
                    workflow_instance_kwargs={
                        "asset": asset,
                        "do_silence": self.do_silence
                    }
                    if asset.status.value == AssetStatus.ACTIVE.value:
                        if not asset.already_exec_for_first_time:
                            await wf_class(**(workflow_instance_kwargs or {})).run_async()
                        asset.already_exec_for_first_time = True
                    
                    if asset.run_every:
                        every_coro = self.every(
                            asset=asset,
                            workflow_class=wf_class,
                            workflow_instance_kwargs=workflow_instance_kwargs
                        )
                        await self.task_manager.add_task(every_coro(), task_id=every_task_id)

                except asyncio.CancelledError:
                    raise

                except Exception as e:
                    msg = f"Erreur dans work() pour asset {asset.id} : {e}"
                    if self.debug:
                        msg += f"\nTraceback: {traceback.format_exc()}"
                    logger.error(message=msg)

            return work

        await self.task_manager.add_task(
            _make_work(workflow_class)(),
            task_id=workflow_task_id
        )

        return {
            "workflow_task_id": workflow_task_id,
            "every_task_id":    every_task_id,
        }