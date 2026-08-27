#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 15:34:32 2026

@author: hounsousamuel
"""

"""
Module de gestion et de cycle de vie des conteneurs Docker (ContainerManager).

Ce module implémente un gestionnaire de conteneurs en mémoire sous forme de Singleton,
intégrant un mécanisme de Lazy Re-attachment (auto-restauration sur cache miss).
Il permet de maintenir la continuité des opérations (exécution de commandes, arrêt,
inspection réseau) même après un redémarrage de l'API FastAPI.
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
import docker
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timezone
from uuid import uuid4

from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.configs.config import CONT_INACTIVE_TIMEOUT
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()


class ContainerManager:
    """
    Gestionnaire centralisé des conteneurs Docker avec cache et auto-restauration.

    Attributes:
        _containers (Dict[str, DockerManager]): Registre des instances DockerManager en mémoire.
        _last_used (Dict[str, float]): Timestamp Unix du dernier accès pour chaque conteneur.
        _inactive_timeout (float): Durée d'inactivité maximale (en secondes) avant purge du cache.
        _cleanup_task (Optional[asyncio.Task]): Tâche d'arrière-plan surveillant l'inactivité.
    """

    _instance: Optional["ContainerManager"] = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self, inactive_timeout: Optional[Union[float, int]] = CONT_INACTIVE_TIMEOUT) -> None:
        """
        Initialise le gestionnaire de conteneurs.

        Args:
            inactive_timeout: Délai d'inactivité avant purge de la mémoire (défaut: CONT_INACTIVE_TIMEOUT).
        """
        self._containers: Dict[str, DockerManager] = {}
        self._last_used: Dict[str, float] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

        try:
            self._inactive_timeout = float(inactive_timeout) if inactive_timeout is not None else float(CONT_INACTIVE_TIMEOUT)
        except (ValueError, TypeError):
            self._inactive_timeout = float(CONT_INACTIVE_TIMEOUT)

    @classmethod
    def get_instance(cls) -> "ContainerManager":
        """
        Récupère ou instancie le Singleton du ContainerManager.

        Returns:
            ContainerManager: L'instance unique partagée.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_or_restore_container(self, name: str) -> Optional[DockerManager]:
        """
        Récupère un conteneur depuis le cache RAM ou le réattache à chaud depuis Docker.

        Permet d'éviter les erreurs 'Conteneur introuvable' après un redémarrage du serveur
        lorsque le conteneur existe toujours sur le démon Docker hôte.

        Args:
            name: Nom du conteneur Docker.

        Returns:
            Optional[DockerManager]: L'instance associée au conteneur, ou None s'il n'existe pas.
        """
        if not name:
            return None

        # 1. Vérification en mémoire vive
        if name in self._containers:
            self._last_used[name] = time.time()
            return self._containers[name]

        # 2. Cache Miss : Recherche directe sur le démon Docker
        try:
            dm = DockerManager()
            container = dm.client.containers.get(name)
            dm.container = container
            dm.image_name = container.image.tags[0] if (container.image and container.image.tags) else "<none>"

            # Enregistrement à chaud dans le cache
            self._containers[name] = dm
            self._last_used[name] = time.time()
            logger.print(f"♻️ Conteneur '{name}' réattaché au cache mémoire avec succès.")
            return dm

        except docker.errors.NotFound:
            return None
        except Exception as exc:
            logger.print(f"⚠️ Erreur lors du réattachement du conteneur '{name}': {exc}")
            return None

    def get_or_create_container(
        self,
        image: str,
        name: Optional[str] = None,
        **kwargs: Any
    ) -> DockerManager:
        """
        Récupère un conteneur existant (en RAM ou Docker) ou en déploie un nouveau.

        Args:
            image: Nom du tag de l'image Docker à utiliser (ex: 'ubuntu:22.04').
            name: Nom à attribuer au conteneur (auto-généré si None).
            **kwargs: Options transmises à DockerManager.connect (network, cap_add, labels, etc.).

        Returns:
            DockerManager: L'instance DockerManager connectée au conteneur.
        """
        if name:
            existing = self.get_or_restore_container(name)
            if existing:
                return existing

        dm = DockerManager()
        if not name:
            name = f"simatk_{uuid4().hex[:16]}"

        kwargs.setdefault("labels", {})
        kwargs["labels"].setdefault("simatk", "true")
        kwargs["labels"].setdefault("simatk.created", datetime.now(tz=timezone.utc).isoformat())

        dm.connect(image, name, **kwargs)

        self._containers[name] = dm
        self._last_used[name] = time.time()

        return dm

    async def stop_container(self, name: str) -> bool:
        """
        Arrête et supprime un conteneur Docker de manière asynchrone (non-bloquante).

        Args:
            name: Nom du conteneur à arrêter.

        Returns:
            bool: True si le conteneur a été arrêté et nettoyé, False sinon.
        """
        dm = self.get_or_restore_container(name)
        if not dm:
            return False

        try:
            await asyncio.to_thread(dm.stop)
            self._containers.pop(name, None)
            self._last_used.pop(name, None)
            return True
        except Exception as exc:
            logger.print(f"❌ Erreur lors de l'arrêt du conteneur '{name}': {exc}")
            return False

    async def stop_all_containers(self) -> None:
        """
        Arrête et supprime l'ensemble des conteneurs actuellement enregistrés en cache.
        """
        for name in list(self._containers.keys()):
            await self.stop_container(name)

    async def exec_command(self, name: str, cmd: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Exécute une commande dans un conteneur cible de manière asynchrone.

        Args:
            name: Nom du conteneur Docker.
            cmd: Commande brute sous forme de chaîne de caractères ou de liste d'arguments.

        Returns:
            Dict[str, Any]: Résultat de l'exécution contenant 'stdout', 'stderr', 'exit_code', 'container'.

        Raises:
            ValueError: Si le conteneur n'existe pas ou n'est plus accessible sur le démon Docker.
        """
        dm = self.get_or_restore_container(name)
        if not dm or not dm.container:
            raise ValueError(f"Conteneur '{name}' introuvable ou inaccessible dans Docker.")

        self._last_used[name] = time.time()
        result = await asyncio.to_thread(dm.exec_command_api, cmd)

        return {
            **result,
            "container": name,
        }

    async def cleanup_loop(self) -> None:
        """
        Boucle d'arrière-plan purgeant périodiquement les conteneurs inactifs du cache RAM.
        """
        while True:
            try:
                await asyncio.sleep(60)
                now = time.time()
                to_remove = [
                    name for name, last_used in list(self._last_used.items())
                    if now - last_used > self._inactive_timeout
                ]

                for name in to_remove:
                    logger.print(f"🧹 Purge mémoire du conteneur inactif: {name}")
                    self._containers.pop(name, None)
                    self._last_used.pop(name, None)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.print(f"⚠️ Erreur dans la tâche de nettoyage des conteneurs: {exc}")

    def start_cleanup(self) -> None:
        """
        Démarre la tâche asyncio de nettoyage en arrière-plan si elle n'est pas déjà active.
        """
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self.cleanup_loop())

    async def stop_cleanup(self) -> None:
        """
        Arrête proprement la tâche de nettoyage en arrière-plan.
        """
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    def get_container(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les métadonnées synthétiques d'un conteneur.

        Args:
            name: Nom du conteneur.

        Returns:
            Optional[Dict[str, Any]]: Dictionnaire contenant 'name', 'status', 'image', 'last_used',
                                      ou None si introuvable.
        """
        dm = self.get_or_restore_container(name)
        if not dm or not dm.container:
            return None

        return {
            "name": dm.container.name,
            "status": dm.container.status,
            "image": dm.image_name,
            "last_used": self._last_used.get(name),
        }

    def list_containers(self) -> List[Dict[str, Any]]:
        """
        Retourne la liste des conteneurs actuellement suivis en cache mémoire.

        Returns:
            List[Dict[str, Any]]: Liste des informations de chaque conteneur.
        """
        result = []
        for name, dm in self._containers.items():
            result.append({
                "name": name,
                "status": dm.container.status if dm.container else "unknown",
                "image": dm.image_name,
                "last_used": self._last_used.get(name),
            })
        return result