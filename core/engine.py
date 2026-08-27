#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 21:26:38 2026

@author: hounsousamuel

ObsidianEngine — Point d'entrée principal du système ShieldAI.
Instancie, relie et démarre tous les composants core.
"""

import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import shutil
import asyncio
import traceback
from obsidian_hive.core.managers.asset_manager import AssetManager
from obsidian_hive.core.managers.task_manager import TaskManager
from obsidian_hive.core.managers.workflow_manager import WorkflowManager
from obsidian_hive.core.managers.main_manager import ObsidianManager
from obsidian_hive.core.assets.asset_types import AssetItem, Priority, AssetStatus, AssetType
from modules_utils.logger import get_logger
from obsidian_hive.agents.config import OBSIDIAN_SANDBOX_ROOTS

logger = get_logger("obsidian_engine")

DEFAULT_DB_URL = f"sqlite+aiosqlite:///{os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shieldai.db'))}"


class ObsidianEngine:
    """Moteur principal d'Obsidian Hive.
    
    Point d'entrée du système qui coordonne tous les composants :
    - Gestion des assets (AssetManager)
    - Gestion des tâches asynchrones (TaskManager)
    - Gestion des workflows (WorkflowManager)
    - File de priorité pour le traitement des assets
    
    Cette classe expose une API complète pour ajouter, supprimer, mettre
    en pause et reprendre des assets, ainsi que pour synchroniser le code
    source et gérer les opérations groupées.
    
    Attributes:
        db_url (str): URL de connexion à la base de données.
        do_silence (bool): Si True, supprime les logs de sortie.
        debug (bool): Mode debug pour les traces d'erreur.
        _started (bool): Indique si le moteur est démarré.
        queue (asyncio.PriorityQueue): File de priorité pour les assets.
        task_manager (TaskManager): Gestionnaire des tâches asynchrones.
        asset_manager (AssetManager): Gestionnaire des assets.
        workflow_manager (WorkflowManager): Gestionnaire des workflows.
        main_manager (ObsidianManager): Gestionnaire principal.
    """
    
    def __init__(
        self,
        db_url: str = DEFAULT_DB_URL,
        queue_maxsize: int = 0,
        do_silence: bool = False,
        debug: bool = False,
    ):
        """Initialise le moteur Obsidian.

        Args:
            db_url (str, optional): URL de connexion à la base de données.
                Par défaut "sqlite+aiosqlite:///shieldai.db".
            queue_maxsize (int, optional): Taille maximale de la file d'attente.
                0 signifie illimitée. Par défaut 0.
            do_silence (bool, optional): Si True, supprime les logs. Par défaut False.
            debug (bool, optional): Mode debug. Par défaut False.
        """
        self.db_url = db_url or DEFAULT_DB_URL
        self.do_silence = do_silence
        self.debug = debug
        self._started = False

        # Composants core
        self.queue = asyncio.PriorityQueue(maxsize=queue_maxsize)
        self.task_manager: TaskManager = TaskManager(debug=debug)
        self.asset_manager: AssetManager = AssetManager(db_url=self.db_url)
        self.workflow_manager: WorkflowManager = WorkflowManager(
            task_manager=self.task_manager,
            do_silence=do_silence,
            debug=debug,
        )
        self.main_manager: ObsidianManager = ObsidianManager(
            asset_manager=self.asset_manager,
            workflow_manager=self.workflow_manager,
            queue=self.queue,
            debug=debug,
        )

    async def init(self):
        """Initialise la base de données et crée les tables si elles n'existent pas."""
        await self.asset_manager.init_db()
        logger.info(message="Base de données initialisée")

    async def start(self) -> dict:
        """
        Démarre le moteur :
        1. Initialise la base de données
        2. Charge les assets actifs et relance leurs workflows
        3. Lance le worker principal (écoute la file d'attente)

        Returns:
            dict: Résultat du démarrage avec le statut et les détails.
        """
        if self._started:
            logger.warning(message="ObsidianEngine déjà démarré")
            return {"status": "already_started"}

        await self.init()
        result = await self.main_manager.start()
        self._started = True

        logger.info(
            message=f"ObsidianEngine démarré — "
                    f"{result['launch_result']['launched']} asset(s) chargé(s), "
                    f"{len(result['launch_result']['errors'])} erreur(s)"
        )
        return {"status": "started", **result}

    async def stop(self):
        """Arrête le moteur proprement.
        
        Vide la file d'attente en persistant chaque asset en base de données,
        puis annule toutes les tâches en cours.
        """
        logger.info(message="Arrêt du moteur en cours...")
    
        # Vide la queue en persistant chaque item en DB
        pending = []
        while not self.queue.empty():
            try:
                _, asset = self.queue.get_nowait()
                if asset:
                    asset, _ = asset
                    pending.append(asset)
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break
    
        if pending:
            await self.asset_manager.upsert_many(pending)
            logger.info(message=f"{len(pending)} asset(s) en attente persistés en DB")
    
        # Annule toutes les tasks après
        for task_id in list(self.task_manager.tasks.keys()):
            await self.task_manager.suppress_task(task_id)
    
        self._started = False
        logger.info(message="ObsidianEngine arrêté")

    async def add_asset(
        self, 
        asset: AssetItem,
        priority: Priority,
        manage_immediatly: bool = False,
    ) -> dict:
        """
        Ajoute un asset :
        1. Persiste en base de données
        2. Déclenche le workflow immédiatement si manage_immediatly est True

        Args:
            asset (AssetItem): L'asset à ajouter.
            priority (Priority): La priorité de l'asset.
            manage_immediatly (bool, optional): Si True, lance le workflow immédiatement.
                Par défaut False.

        Returns:
            dict: Résultat de l'opération avec l'ID de l'asset et les IDs des tâches.

        Raises:
            RuntimeError: Si le moteur n'est pas démarré.
        """
        if not self._started:
            raise RuntimeError("ObsidianEngine non démarré. Appelle start() d'abord.")

        task_ids = {}
        asset = self.main_manager._validate_item(asset, priority)
        asset_db = await self.asset_manager.add(asset)
        asset = self.asset_manager.asset_item_db_to_asset_item(
            asset_db, 
        )
        try:
            if manage_immediatly:
                task_ids = await self.workflow_manager.manage_async(asset)
                logger.info(message=f"Asset ajouté et workflow lancé : {asset.name or asset.id}")
            else:
                await self.main_manager.put(asset, priority, is_already_added_in_db=True)
            return {"status": "ok", "asset_id": asset.id, **(task_ids or {})}

        except Exception as e:
            msg = f"Erreur lors de l'ajout de l'asset : {e}"
            if self.debug:
                msg += f"\nTraceback: {traceback.format_exc()}"
            logger.error(message=msg)
            return {"status": "error", "error": str(e)}

    async def remove_asset(
        self, 
        asset_id: str,
        delete: bool = True,
    ) -> dict:
        """
        Retire un asset :
        1. Annule ses tâches actives
        2. Supprime de la base de données (si delete=True)
        3. Supprime le code source associé

        Args:
            asset_id (str): L'ID de l'asset à retirer.
            delete (bool, optional): Si True, supprime de la base de données.
                Par défaut True.

        Returns:
            dict: Résultat de l'opération.
        """
        if not self._started:
            raise RuntimeError("ObsidianEngine non démarré.")

        # Annule les tasks liées à cet asset
        for prefix in ("work-", "every-"):
            task_id = f"{prefix}{asset_id}"
            if self.task_manager.is_running(task_id):
                await self.task_manager.suppress_task(task_id)
                logger.info(message=f"Task annulée : {task_id}")
            
        if delete:
            asset_db = await self.asset_manager.get_by_identifier(asset_id, first=True)
            if asset_db:
                asset = self.asset_manager.asset_item_db_to_asset_item(asset_db)
                await self.asset_manager.delete_by_identifier(
                    asset_id,
                )
                if getattr(asset, "source_code_dir", None):
                    shutil.rmtree(asset.source_code_dir, ignore_errors=True)
                    
            logger.info(message=f"Asset retiré : {asset_id}")
        return {"status": "ok", "asset_id": asset_id}
    
    async def sync_source_code(self, asset_id: str, admin_source_code_dir: str) -> dict:
        """Recopie le code source fourni par l'admin, écrase l'ancienne copie.

        Args:
            asset_id (str): L'ID de l'asset.
            admin_source_code_dir (str): Le dossier source fourni par l'admin.

        Returns:
            dict: Résultat de l'opération avec statut et erreur éventuelle.
        """
        if not os.path.exists(admin_source_code_dir):
            return {"status": "error", "error": f"Dossier introuvable : {admin_source_code_dir}"}
        
        if not os.path.isdir(admin_source_code_dir):
            return {"status": "error", "error": f"{admin_source_code_dir} pas un dossier"}
    
        asset_db = await self.asset_manager.get_by_identifier(asset_id, first=True)
        if not asset_db:
            return {"status": "error", "error": "Asset non trouvé"}
    
        asset = self.asset_manager.asset_item_db_to_asset_item(asset_db)
        if not hasattr(asset, "source_code_dir"):
            return {"status": "error", "error": "Ce type d'asset n'a pas de source_code_dir"}
    
        dest_dir = os.path.join(OBSIDIAN_SANDBOX_ROOTS[0], asset_id)  # 🎯 même chemin stable qu'à la création
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(admin_source_code_dir, dest_dir)
    
        return await self.update_asset(
            asset_id,
            attrs={"source_code_dir": dest_dir, "fix_allowed": dest_dir and getattr(asset, "fix_allowed", False)},
            restart_workflow=False,
        )

    async def _manage_asset_status(
        self, 
        asset_id: str,
        status: AssetStatus,
        success_message: str = None,
    ):
        """Gère le changement de statut d'un asset.

        Args:
            asset_id (str): L'ID de l'asset.
            status (AssetStatus): Le nouveau statut.
            success_message (str, optional): Message de succès à logger.

        Returns:
            dict: Résultat de l'opération.
        """
        if not (await self.asset_manager.get_by_identifier(asset_id)):
            return {"status": "error", "error": "Asset non trouvé"}
        status = AssetStatus(status)
        updated = await self.asset_manager.update_by_identifier(
            identifier=asset_id,
            attrs={"status": status.value},
            first=True,
        )
        if updated:
            if self._started:
                await self.remove_asset(asset_id=asset_id, delete=False)
                
                if status == AssetStatus.ACTIVE:
                    asset_db = await self.asset_manager.get_by_identifier(asset_id, first=True)
                    asset = self.asset_manager.asset_item_db_to_asset_item(asset_db)
                    await self.workflow_manager.manage_async(asset)
                
                elif status == AssetStatus.INACTIVE:
                    pass
                    
            if success_message:
                logger.info(message=success_message)
            return {"status": "ok", "asset_id": asset_id}
        return {"status": "error", "error": "Erreur lors de la mise à jour"}
    
    async def pause_asset(self, asset_id: str) -> dict:
        """
        Met un asset en pause (INACTIVE) sans le supprimer.
        Le workflow every() s'arrête de lui-même grâce au check de status.

        Args:
            asset_id (str): L'ID de l'asset à mettre en pause.

        Returns:
            dict: Résultat de l'opération.
        """
        return await self._manage_asset_status(
            asset_id=asset_id,
            status=AssetStatus.INACTIVE,
            success_message=f"Asset mis en pause : {asset_id}"
        )

    async def resume_asset(self, asset_id: str) -> dict:
        """
        Reprend un asset en pause (ACTIVE).
        Le workflow every() reprend automatiquement.

        Args:
            asset_id (str): L'ID de l'asset à reprendre.

        Returns:
            dict: Résultat de l'opération.
        """
        return await self._manage_asset_status(
            asset_id=asset_id,
            status=AssetStatus.ACTIVE,
            success_message=f"Asset repris : {asset_id}"
        )
    
    async def _bulk_set_status(
        self,
        status: AssetStatus,
        asset_type: AssetType | str | None = None,
        asset_ids: list[str] | None = None,
        priority: Priority | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, dict]:
        """
        Met à jour le statut (ACTIVE/INACTIVE) sur un ensemble d'assets.

        Args:
            status (AssetStatus): Le nouveau statut.
            asset_type (AssetType | str | None, optional): Filtrer par type.
            asset_ids (list[str] | None, optional): Filtrer par liste d'IDs.
            priority (Priority | None, optional): Filtrer par priorité.
            tags (list[str] | None, optional): Filtrer par tags.

        Returns:
            dict[str, dict]: Dictionnaire des résultats par ID d'asset.
        """
        source_status = AssetStatus.ACTIVE if status == AssetStatus.INACTIVE else AssetStatus.INACTIVE
    
        assets_db = await self.asset_manager.list_by_filter(
            status=source_status,
            type_=AssetType(asset_type) if asset_type is not None else None,
            priority=Priority(priority) if priority is not None else None,
            tags=tags,
        )
    
        if asset_ids is not None:
            wanted = set(asset_ids)
            assets_db = [a for a in assets_db if a.item_id in wanted]
    
        to_return = {}
        if assets_db:
            async def _set(asset):
                asset_id = asset.item_id
                try:
                    r = await self._manage_asset_status(asset_id, status)
                except Exception as e:
                    r = e
                return asset_id, r
    
            results = await asyncio.gather(*[_set(asset) for asset in assets_db])
            for asset_id, result in results:
                if not isinstance(result, Exception):
                    to_return[asset_id] = result
                else:
                    to_return[asset_id] = {"status": "error", "error": f"Erreur lors de la mise à jour: {result!r}"}
    
        return to_return
    
    
    async def pause_assets(
        self,
        asset_type: AssetType | str | None = None,
        asset_ids: list[str] | None = None,
        priority: Priority | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, dict]:
        """
        Met en pause un ensemble d'assets (ACTIVE -> INACTIVE).

        Args:
            asset_type (AssetType | str | None, optional): Filtrer par type.
            asset_ids (list[str] | None, optional): Filtrer par liste d'IDs.
            priority (Priority | None, optional): Filtrer par priorité.
            tags (list[str] | None, optional): Filtrer par tags.

        Returns:
            dict[str, dict]: Résultats par ID d'asset.
        """
        return await self._bulk_set_status(
            status=AssetStatus.INACTIVE,
            asset_type=asset_type, asset_ids=asset_ids,
            priority=priority, tags=tags,
        )
    
    
    async def resume_assets(
        self,
        asset_type: AssetType | str | None = None,
        asset_ids: list[str] | None = None,
        priority: Priority | str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, dict]:
        """
        Reprend un ensemble d'assets (INACTIVE -> ACTIVE).

        Args:
            asset_type (AssetType | str | None, optional): Filtrer par type.
            asset_ids (list[str] | None, optional): Filtrer par liste d'IDs.
            priority (Priority | str | None, optional): Filtrer par priorité.
            tags (list[str] | None, optional): Filtrer par tags.

        Returns:
            dict[str, dict]: Résultats par ID d'asset.
        """
        return await self._bulk_set_status(
            status=AssetStatus.ACTIVE,
            asset_type=asset_type, asset_ids=asset_ids,
            priority=priority, tags=tags,
        )
        
    def status(self) -> dict:
        """Retourne l'état du moteur et les tâches actives.

        Returns:
            dict: État du moteur avec le nombre de tâches actives et leurs détails.
        """
        active_tasks = {
            tid: self.task_manager.get_status(tid)
            for tid in self.task_manager.tasks
            if self.task_manager.is_running(tid)
        }
        return {
            "started": self._started,
            "active_tasks": len(active_tasks),
            "tasks": active_tasks,
        }
        
    async def update_asset(
        self,
        asset_id: str,
        attrs: dict,
        restart_workflow: bool = False,
    ) -> dict:
        """
        Met à jour les attributs d'un asset existant.
    
        Args:
            asset_id (str): Identifiant de l'asset.
            attrs (dict): Champs à modifier.
            restart_workflow (bool, optional): True pour relancer le workflow avec
                la nouvelle configuration. Par défaut False.

        Returns:
            dict: Résultat de l'opération.
        """
        if not self._started:
            raise RuntimeError("ObsidianEngine non démarré.")
    
        updated = await self.asset_manager.update_by_identifier(
            identifier=asset_id,
            attrs=attrs,
            first=True,
        )
        if not updated:
            return {"status": "error", "error": "Asset non trouvé ou mise à jour échouée"}
        
        if restart_workflow:
            await self.remove_asset(asset_id=asset_id, delete=False)
            asset_db = await self.asset_manager.get_by_identifier(asset_id, first=True)
            asset = self.asset_manager.asset_item_db_to_asset_item(asset_db)
            await self.workflow_manager.manage_async(asset)
    
        logger.info(message=f"Asset mis à jour : {asset_id}")
        return {"status": "ok", "asset_id": asset_id}

    async def __aenter__(self):
        """Support du contexte async."""
        await self.start()
        return self

    async def __aexit__(self, *args):
        """Support du contexte async."""
        await self.stop()


# =============================================================================
# TEST RAPIDE
# =============================================================================
async def _test():
    from obsidian_hive.core.assets.asset_types import WebAsset

    print("=" * 60)
    print("🧪 TEST ObsidianEngine")
    print("=" * 60)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    async with ObsidianEngine(
        db_url=f"sqlite+aiosqlite:///{db_path}",
        debug=True,
        do_silence=not True,
    ) as engine:

        print(f"\n✅ Moteur démarré")
        print(f"   Status: {engine.status()}")

        # Ajouter un asset
        asset = WebAsset(
            name="DVWA Test",
            url="http://localhost:8080",
            every=3600,
            run_config={
                "limit_vuln_for_fuzzer": 2,
                "max_test": 5,
                "helpers": [
                    {
                        "name": "dvwa_auth",
                        "kwargs": {
                            "base_url": "http://localhost:8080",
                            "username": "admin",
                            "password": "password",
                            "security_level": "low",
                        }
                    }
                ],
            }
        )

        result = await engine.add_asset(asset, priority=asset.priority)
        print(f"\n✅ Asset ajouté: {result}")
        print(f"   Status moteur: {engine.status()}")

        # Laisser tourner 5 secondes
        print("\n⏳ Attente 5s...")
        await asyncio.sleep(5)

        # Pause
        await engine.pause_asset(asset.id)
        print("\n⏸️  Asset mis en pause")

        # Status final
        print(f"\n📊 Status final: {engine.status()}")

    print("\n✅ Moteur arrêté proprement")
    os.unlink(db_path)


if __name__ == "__main__":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(_test())