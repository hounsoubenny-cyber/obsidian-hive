#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 26 15:47:02 2026

@author: hounsousamuel
"""

import asyncio
import traceback
from typing import Dict, Tuple, Any
from obsidian_hive.core.managers.asset_manager import AssetManager, AssetItemDB
from obsidian_hive.core.managers.workflow_manager import WorkflowManager
from obsidian_hive.core.assets.asset_types import AssetItem, Priority
from modules_utils.logger import get_logger
logger = get_logger("obsidian_manager")


class ObsidianManager:
    """Gestionnaire principal d'Obsidian Hive.
    
    Coordonne le workflow complet : gestion des assets, planification
    et exécution des workflows via une queue de priorité.
    
    Attributes:
        asset_manager (AssetManager): Gestionnaire des assets.
        workflow_manager (WorkflowManager): Gestionnaire des workflows.
        queue (asyncio.PriorityQueue): Queue de priorité pour les assets.
        debug (bool): Mode debug.
    """
    
    def __init__(
        self,
        asset_manager: AssetManager,
        workflow_manager: WorkflowManager,
        queue: asyncio.PriorityQueue,
        debug: bool = False,
    ):
        """Initialise le gestionnaire principal.

        Args:
            asset_manager (AssetManager): Gestionnaire des assets.
            workflow_manager (WorkflowManager): Gestionnaire des workflows.
            queue (asyncio.PriorityQueue): Queue de priorité pour les assets.
            debug (bool, optional): Mode debug. Par défaut False.

        Raises:
            RuntimeError: Si la queue n'a pas les attributs requis.
        """
        has_all, missing = self._verify_attrs(
            attrs=["get", "get_nowait", "put", "put_nowait", "qsize"],
            detail=True,
            obj=queue
        )
        if not has_all:
            raise RuntimeError(f"Queue object missing some attributs ({missing})")
        self.asset_manager = asset_manager
        self.workflow_manager = workflow_manager
        self.queue = queue
        self.debug = debug
    
    @staticmethod
    def _verify_attrs(attrs: list, obj: Any, detail: bool = False):
        """Vérifie qu'un objet possède tous les attributs requis.

        Args:
            attrs (list): Liste des noms d'attributs à vérifier.
            obj (Any): L'objet à vérifier.
            detail (bool, optional): Si True, retourne la liste des attributs manquants.
                Par défaut False.

        Returns:
            tuple: (bool, list | None) - bool indique si tous les attributs sont présents,
                et la liste des attributs manquants si detail=True.
        """
        if not attrs:
            return False, None
        if not detail:
            return all(hasattr(obj, attr_name) for attr_name in attrs), None
        
        missing = []
        for attr_name in attrs:
            if not hasattr(obj, attr_name):
                missing.append(attr_name)
        
        return len(missing) == 0, missing
    
    def _validate_item(self, item: Dict | AssetItem, priority: Priority) -> AssetItem:
        """Valide et normalise un élément pour la queue.

        Args:
            item (Dict | AssetItem): L'élément à valider.
            priority (Priority): La priorité à appliquer.

        Returns:
            AssetItem: L'asset validé.

        Raises:
            ValueError: Si la priorité est invalide.
        """
        if isinstance(item, dict):
            item = AssetItem.model_validate(item)  
        try:
            item.priority = Priority(priority)
        except ValueError:
            raise ValueError(f"Priorité invalide : {priority!r}. Valeurs acceptées : {list(Priority)}")
        return item

    async def put(self, item: Dict | AssetItem, priority: Priority, is_already_added_in_db: bool = False) -> None:
        """Ajoute un asset dans la queue de manière asynchrone.

        Args:
            item (Dict | AssetItem): L'asset à ajouter.
            priority (Priority): La priorité.
            is_already_added_in_db (bool, optional): Si True, l'asset est déjà en DB.
                Par défaut False.
        """
        item = self._validate_item(item, priority)
        await self.queue.put((item.priority.value, (item, is_already_added_in_db)))

    def put_nowait(self, item: Dict | AssetItem, priority: Priority, is_already_added_in_db: bool = False, raise_: bool = False) -> bool:
        """Ajoute un asset dans la queue sans attendre.

        Args:
            item (Dict | AssetItem): L'asset à ajouter.
            priority (Priority): La priorité.
            is_already_added_in_db (bool, optional): Si True, l'asset est déjà en DB.
                Par défaut False.
            raise_ (bool, optional): Si True, lève l'exception QueueFull.
                Par défaut False.

        Returns:
            bool: True si l'ajout a réussi, False si la queue est pleine.
        """
        item = self._validate_item(item, priority)
        try:
            self.queue.put_nowait((item.priority.value, (item, is_already_added_in_db)))
            return True
        except asyncio.QueueFull:
            if raise_:
                raise
            return False
    
    async def get(self):
        """Récupère un élément de la queue de manière asynchrone.

        Returns:
            tuple: (priorité, (asset, is_already_added_in_db))
        """
        return await self.queue.get()
   
    def get_nowait(self, raise_: bool = False):
        """Récupère un élément de la queue sans attendre.

        Args:
            raise_ (bool, optional): Si True, lève l'exception QueueEmpty.
                Par défaut False.

        Returns:
            tuple: (priorité, (asset, is_already_added_in_db)) ou (None, None) si vide.
        """
        try:
            return self.queue.get_nowait()
        except asyncio.QueueEmpty:
            if raise_:
                raise
            return (None, None)
   
    async def launch(self):
        """Lance les workflows pour tous les assets actifs.

        Returns:
            dict: Résultat du lancement avec 'launched' et 'errors'.
        """
        actives_assets: list[AssetItemDB] = await self.asset_manager.list_active()
        tasks = [
            self.workflow_manager.manage_async(
                self.asset_manager.asset_item_db_to_asset_item(
                    asset_db,
                )
            )
            for asset_db in actives_assets
        ]
        if not tasks:
            return {"launched": 0, "errors": []}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        errors = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                msg = f"Workflow {i} a échoué au démarrage : {result}"
                logger.error(message=msg)
                errors.append(msg)

        return {"launched": len(tasks) - len(errors), "errors": errors}
    
    async def worker(self):
        """Boucle principale du worker qui traite les assets de la queue."""
        while True:
            get_item = False
            try:
                item: Tuple[int | None, Tuple[AssetItem | None, bool]] = await self.get()
                get_item = True
                priority, asset = item
                if not asset:
                    continue
                
                asset, is_already_added_in_db = asset
                if not is_already_added_in_db:
                    asset_db = await self.asset_manager.upsert(asset)
                    asset = self.asset_manager.asset_item_db_to_asset_item(asset_db)
                await self.workflow_manager.manage_async(asset)
            
            except asyncio.CancelledError:
                logger.info(message="Worker arrêté !")
                raise
                
            except Exception as e:
                message = f"Erreur dans le worker du manager principal : {str(e)}"
                if self.debug:
                    message += f"\nTraceback: {traceback.format_exc()}"
                logger.error(message=message)
            
            finally:
                if get_item:
                    self.queue.task_done()
    
    async def start(self):
        """Démarre le gestionnaire principal.

        Returns:
            dict: Résultat du lancement avec 'launch_result'.
        """
        launch_result = {"launched": 0, "errors": []}
        # launch_result = await self.launch()
        await self.workflow_manager.task_manager.add_task(
            self.worker(),
            task_id="main_manager_worker",
            force=True
        )
        return {
            "launch_result": launch_result
        }