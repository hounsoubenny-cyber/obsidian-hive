#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 22 20:08:12 2026

@author: hounsousamuel
"""

import time
import asyncio
import traceback
from typing import Dict, Any
from datetime import datetime, timezone
from uuid import uuid4
from modules_utils.logger import get_logger

logger = get_logger("shared_task_manager")


class TaskManager:
    """Gestionnaire de tâches asynchrones avec suivi d'état.
    
    Fournit un système de gestion des tâches asynchrones avec :
    - Création et suivi des tâches
    - Annulation et suppression
    - Vérification d'état (running, done, cancelled, failed)
    - Nettoyage automatique des tâches terminées
    
    Attributes:
        tasks (Dict[str, Dict[str, Any]]): Dictionnaire des tâches actives.
        cancel_tasks (Dict[str, asyncio.Task]): Tâches d'annulation programmées.
        debug (bool): Mode debug pour les logs d'erreur.
    """
    
    def __init__(self, debug: bool = True):
        """Initialise le gestionnaire de tâches.

        Args:
            debug (bool, optional): Mode debug. Par défaut True.
        """
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.cancel_tasks:dict[str, asyncio.Task] = {}
        self.debug = debug
    
    @staticmethod
    def task_id(tag: str = "sh_ta-"):
        """Génère un identifiant unique pour une tâche.

        Args:
            tag (str, optional): Préfixe pour l'ID. Par défaut "sh_ta-".

        Returns:
            str: Un ID unique au format "{tag}{uuid4}".
        """
        return (tag or "sh_ta-") + str(uuid4())    
    
    async def add_task(
        self, 
        coro, 
        task_id:str, 
        name: str = None, 
        metadata: Dict | None = None,
        force: bool = False,
    ) -> bool:
        """Ajoute une nouvelle tâche asynchrone.

        Args:
            coro (Coroutine): La coroutine à exécuter.
            task_id (str): L'ID unique de la tâche.
            name (str, optional): Nom de la tâche. Par défaut None.
            metadata (Dict | None, optional): Métadonnées associées. Par défaut None.
            force (bool, optional): Si True, supprime une tâche existante avant d'ajouter.
                Par défaut False.

        Returns:
            bool: True si la tâche a été ajoutée, False si une tâche existe déjà.
        """
        if task_id in self.tasks and self.is_running(task_id):
            if not force:
                return False
            else:
                await self.suppress_task(task_id)
        self.tasks.setdefault(task_id, {})
        self.tasks[task_id]["task"] = asyncio.create_task(coro=coro, name=name or task_id)
        self.tasks[task_id]["metadata"] = metadata or {}
        self.tasks[task_id]["created_at"] = datetime.now(timezone.utc)
        self.tasks[task_id]["timestamp"] = time.time()
        return True
    
    async def cancel_task(self, task_id: str, timeout: float = 30):
        """Annule une tâche en cours d'exécution.

        Args:
            task_id (str): L'ID de la tâche à annuler.
        """
        if task_id in self.tasks:
            try:
                task = self.tasks[task_id]["task"]
                task.cancel()
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
                
            except asyncio.TimeoutError:
                logger.warning(
                f"Task {task_id} n'a pas répondu à cancel() sous {timeout}s "
                "— abandon du wait (le thread sous-jacent finira en arrière-plan)"
            )
                
            except asyncio.CancelledError:
                pass
            
            except Exception as e:
                message = f"Erreur: {str(e)}."
                if self.debug:
                    message += f"\nTraceback: {traceback.format_exc()}"
                logger.error(message=message)     
            
    
    async def suppress_task(self, task_id:str):
        """Supprime une tâche après l'avoir annulée.

        Args:
            task_id (str): L'ID de la tâche à supprimer.
        """
        if task_id in self.tasks:
            await self.cancel_task(task_id)
            self.tasks.pop(task_id, None)
    
    async def add_cancel_task(self, task_id:str, timeout:float = 60):
        """Ajoute une tâche d'annulation programmée après un timeout.

        Args:
            task_id (str): L'ID de la tâche à annuler.
            timeout (float, optional): Délai avant annulation en secondes. Par défaut 60.
        """
        if task_id in self.tasks:
            async def cancel_task():
                await asyncio.sleep(timeout)
                await self.cancel_task(task_id)
            
            if task_id in self.cancel_tasks:
                await self.cancel_cancelling_task(task_id)
            self.cancel_tasks[task_id] = asyncio.create_task(cancel_task())
    
    async def cancel_cancelling_task(self, task_id:str):
        """Annule une tâche d'annulation programmée.

        Args:
            task_id (str): L'ID de la tâche d'annulation à annuler.
        """
        if task_id in self.cancel_tasks:
            try:
                self.cancel_tasks[task_id].cancel()
                await self.cancel_tasks[task_id]
            except asyncio.CancelledError:
                pass
            
            except Exception as e:
                message = f"Erreur: {str(e)}."
                if self.debug:
                    message += f"\nTraceback: {traceback.format_exc()}"
                logger.error(message=message) 
    
    def get_task(self, task_id:str):
        """Récupère les informations d'une tâche.

        Args:
            task_id (str): L'ID de la tâche.

        Returns:
            dict | None: Les informations de la tâche ou None.
        """
        return self.tasks.get(task_id, None)
    
    def is_running(self, task_id: str) -> bool:
        """Vérifie si une tâche est en cours d'exécution.

        Args:
            task_id (str): L'ID de la tâche.

        Returns:
            bool: True si la tâche tourne, False sinon.
        """
        task = self.tasks.get(task_id, {}).get("task")
        return task is not None and not task.done()
    
    def get_status(self, task_id: str) -> str:
        """Retourne le statut d'une tâche.

        Args:
            task_id (str): L'ID de la tâche.

        Returns:
            str: Le statut ('running', 'done', 'cancelled', 'failed', 'not_found').
        """
        task = self.tasks.get(task_id, {}).get("task")
        if task is None:
            return "not_found"
        if task.done():
            if task.cancelled():
                return "cancelled"
            if task.exception():
                return "failed"
            return "done"
        return "running"
    
    def list_tasks(self) -> dict:
        """Liste toutes les tâches avec leur statut.

        Returns:
            dict: Dictionnaire des tâches avec leurs métadonnées et statut.
        """
        return {
            tid: {
                **data,
                "status": self.get_status(tid)
            }
            for tid, data in self.tasks.items()
        }
    
    def cleanup(self):
        """Nettoie les tâches terminées (done, cancelled, failed)."""
        done = [tid for tid, data in self.tasks.items() if data["task"].done()]
        for tid in done:
            self.tasks.pop(tid)