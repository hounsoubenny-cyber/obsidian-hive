#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 28 15:58:13 2026

@author: hounsousamuel

Module de gestion des containers Docker pour le Sandbox ShieldAI V2.
Ce module fournit une interface complète pour créer, gérer, surveiller
et détruire des containers Docker isolés destinés à l'exécution sécurisée
de code suspect.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import socket
import docker
import base64
import asyncio
import subprocess
from datetime import datetime
from sandbox_ia.sandbox_utils.logger import get_logger
logger = get_logger()
Container = docker.models.containers.Container

class ContainerManager:
    """
    Classe principale de gestion des containers Docker pour le Sandbox ShieldAI.

    Fournit une interface complète pour :
    - Créer et gérer des images Docker
    - Lancer, surveiller et détruire des containers isolés
    - Exécuter des commandes dans les containers
    - Copier des fichiers vers/depuis les containers
    - Attacher des traceurs système (strace) pour la surveillance
    - Gérer les timeouts et les arrêts d'urgence

    Attributes
    ----------
    client : docker.DockerClient
        Client Docker connecté au daemon local.
    image_name : str | None
        Nom de l'image utilisée par le container courant.
    container : docker.models.containers.Container | None
        Container Docker courant géré par cette instance.
    """

    def __init__(self):
        self.client = docker.from_env()
        self.image_name = None
        self.container: docker.models.containers.Container = None
        self._strace_file = self.generate_strace_log_file()
        self.volume_dir = "/tmp/shield-sandbox/"
        self.volume_dir_on_container = "/container/shared"
        os.makedirs(self.volume_dir, exist_ok=True)
        os.chmod(self.volume_dir, 0o777)
    
    @staticmethod
    def format_date():
        return datetime.now().strftime('%Y%m%d_%H%M%S')
    
    @staticmethod
    def generate_strace_log_file():
        return f"strace-shieldai_sandbox-{ContainerManager.format_date()}_{time.time()}.log"
    
    @property
    def strace_file(self):
        return self._strace_file
    # ─────────────────────────────────────────────────────────────────────────
    # GESTION DES IMAGES
    # ─────────────────────────────────────────────────────────────────────────

    def create_image(self, dockerfile_path: str, tag: str) -> bool:
        """
        Construit une image Docker depuis un Dockerfile.

        Parcourt le répertoire spécifié à la recherche d'un Dockerfile,
        puis lance le build Docker avec le tag fourni. Les logs de build
        sont affichés en temps réel via le logger.

        Parameters
        ----------
        dockerfile_path : str
            Chemin vers le répertoire contenant le Dockerfile.
            Exemple : "/opt/shieldai/sandbox/docker/"
        tag : str
            Tag à donner à l'image construite.
            Exemple : "shieldai-sandbox-base:v2"

        Returns
        -------
        bool
            True si le build a réussi, False sinon.
        """
        try:
            logger.print(f"🔨 Build de l'image '{tag}' depuis '{dockerfile_path}'...")
            image, build_logs = self.client.images.build(
                path=dockerfile_path,
                tag=tag,
                rm=True,       # supprimer les containers intermédiaires après build
                forcerm=True,  # supprimer même en cas d'échec
            )
            # Afficher les logs de build en temps réel
            for log in build_logs:
                if "stream" in log:
                    line = log["stream"].strip()
                    if line:
                        logger.print(f"   🐳 {line}", verify=False)
                elif "error" in log:
                    logger.print(f"   ❌ {log['error']}", verify=False)

            logger.print(f"✅ Image '{tag}' construite avec succès ! ID: {image.short_id}")
            return True

        except docker.errors.BuildError as e:
            logger.print(f"❌ Erreur de build: {e}")
            for log in e.build_log:
                if "stream" in log:
                    logger.print(f"   {log['stream'].strip()}", verify=False)
            return False

        except docker.errors.APIError as e:
            logger.print(f"❌ Erreur API Docker lors du build: {e}")
            return False

        except Exception as e:
            logger.print(f"❌ Erreur inattendue lors du build: {e}")
            return False

    def list_images(self) -> list:
        """
        Liste toutes les images Docker disponibles sur le système.

        Affiche les images via le logger avec leurs tags respectifs.
        Les images sans tag (images intermédiaires) sont ignorées
        dans l'affichage mais incluses dans le retour.

        Returns
        -------
        list
            Liste d'objets Image Docker. Peut être vide si aucune
            image n'est disponible.
        """
        images = self.client.images.list()
        logger.print("📋 IMAGES DOCKER DISPONIBLES:")
        for img in images:
            if img.tags:
                logger.print(f"   🐳 {img.tags}")
        return images

    # ─────────────────────────────────────────────────────────────────────────
    # CONFIGURATION ET LANCEMENT
    # ─────────────────────────────────────────────────────────────────────────

    def get_kwargs_for_container(
        self,
        network_disabled: bool = True,
        mem_limit: str = "256m",
        cpu_quota: int = 50000,
        cpu_period: int = 100000,
        pids_limit: int = 64,
        read_only: bool = False,
        user: str = "sandbox",
        workdir: str = "/sandbox/work",
        extra_env: dict | None = None,
    ) -> dict:
        """
        Génère un dictionnaire de configuration sécurisée pour le lancement
        d'un container sandbox.

        Applique les contraintes de sécurité recommandées pour l'isolation :
        - Réseau désactivé par défaut
        - Limites CPU et RAM strictes
        - Nombre de process limité (anti fork-bomb)
        - Drop de toutes les capabilities Linux sauf SYS_PTRACE (pour strace)
        - Pas de privilèges supplémentaires

        Parameters
        ----------
        network_disabled : bool, optional
            Désactive complètement le réseau du container. True par défaut.
        mem_limit : str, optional
            Limite mémoire RAM. Format Docker : "256m", "1g". "256m" par défaut.
        cpu_quota : int, optional
            Quota CPU en microsecondes par période. 50000 = 50% d'un core.
            50000 par défaut.
        cpu_period : int, optional
            Période CPU en microsecondes. 100000 par défaut (100ms).
        pids_limit : int, optional
            Nombre maximum de processus simultanés. 64 par défaut.
            Protège contre les fork bombs.
        read_only : bool, optional
            Rend le filesystem du container en lecture seule. False par défaut.
            Mettre True pour une isolation maximale (certains langages ont besoin
            d'écrire des fichiers temporaires).
        user : str, optional
            Utilisateur sous lequel tourner dans le container. "sandbox" par défaut.
        workdir : str, optional
            Répertoire de travail initial. "/sandbox/work" par défaut.
        extra_env : dict | None, optional
            Variables d'environnement supplémentaires à injecter. None par défaut.

        Returns
        -------
        dict
            Dictionnaire de configuration prêt à être passé en **kwargs
            à client.containers.run().
        """
        environment = {
            "SANDBOX_ID": "shieldai",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "HOME": f"/home/{user}",
            "TERM": "xterm-256color",
        }
        if extra_env:
            environment.update(extra_env)

        return {
            # Comportement
            "detach": True,
            "command": "sleep infinity",   # le container attend les exec_run
            # Réseau
            "network_disabled": network_disabled,
            # Ressources
            "mem_limit": mem_limit,
            "memswap_limit": mem_limit,    # swap = mem_limit → pas de swap
            "cpu_quota": cpu_quota,
            "cpu_period": cpu_period,
            "pids_limit": pids_limit,
            # Filesystem
            "read_only": read_only,
            # Sécurité
            "cap_drop": ["ALL"],           # drop toutes les capabilities
            "cap_add": ["SYS_PTRACE"],     # re-add uniquement pour strace
            "security_opt": ["no-new-privileges"],
            # Utilisateur et workdir
            "user": user,  #"1500:1500"
            "working_dir": workdir,
            # Environnement
            "environment": environment,
            # Nettoyage auto désactivé → on gère nous-mêmes
            "auto_remove": False,
            "volumes": {
                self.volume_dir: {
                    "bind": self.volume_dir_on_container,
                    "mode": "rw"
                }
            }
        }

    def connect(self, name_img: str, name: str, **kwargs) -> Container:
        """
        Lance un container Docker ou réutilise un container existant.

        Tente d'abord de récupérer un container portant le nom fourni.
        Si il existe mais est arrêté ou en pause, il est redémarré.
        Si il n'existe pas, un nouveau container est créé depuis l'image spécifiée.

        En cas d'absence de configuration dans kwargs, les valeurs par défaut
        sécurisées de get_kwargs_for_container() sont appliquées partiellement
        (uniquement detach et command pour ne pas forcer de config non voulue).

        Parameters
        ----------
        name_img : str
            Nom de l'image Docker à utiliser.
            Exemple : "shieldai-sandbox-base:v2"
        name : str | None
            Nom à donner au container. Si None, un nom horodaté est généré
            automatiquement au format "container_YYYYMMDD_HHMMSS".
        **kwargs : dict
            Arguments supplémentaires passés directement à containers.run().
            Permettent de surcharger toute configuration Docker standard.

        Returns
        -------
        Container
            L'objet Container Docker prêt à l'emploi, en état "running".

        Raises
        ------
        docker.errors.ImageNotFound
            Si l'image spécifiée n'existe pas localement.
        docker.errors.APIError
            En cas d'erreur de communication avec le daemon Docker.
        """
        if name is None:
            name = f"container_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.image_name = name_img

        # Tenter de récupérer un container existant
        try:
            self.container = self.client.containers.get(name)
            self.container.reload()

            if self.container.status.lower() == "paused":
                self.container.unpause()
            elif self.container.status.lower() != "running":
                self.container.start()

            logger.print(f"✅ Container existant réutilisé: {name}")
            logger.print(f"📊 Status: {self.container.status}")

        except docker.errors.NotFound:
            # Pas de container existant → on en crée un nouveau
            if "command" not in kwargs:
                kwargs["command"] = "sleep infinity"
            if "detach" not in kwargs:
                kwargs["detach"] = True

            logger.print(f"📦 Création nouveau container depuis: {name_img}")
            logger.print(f"⚙️  Configuration: {kwargs}")

            try:
                self.container = self.client.containers.run(
                    image=name_img,
                    name=name,
                    **kwargs
                )
                logger.print(f"✅ Nouveau container créé: {name}")

            except docker.errors.ImageNotFound:
                logger.print(f"❌ Image non trouvée: {name_img}")
                logger.print("📋 Images disponibles :")
                self.list_images()
                raise

            except docker.errors.APIError as e:
                logger.print(f"❌ Erreur API Docker: {e}")
                raise

        # Attendre que le container soit vraiment "running"
        timeout = 10
        start = time.time()
        while time.time() - start < timeout:
            self.container.reload()
            if self.container.status == "running":
                break
            time.sleep(0.3)

        logger.print(f"📊 Status final: {self.container.status}")
        return self.container

    # ─────────────────────────────────────────────────────────────────────────
    # ÉTAT ET MONITORING
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> str:
        """
        Retourne l'état courant du container.

        Effectue un reload depuis le daemon Docker avant de retourner
        le status pour garantir une valeur fraîche et non cachée.

        Returns
        -------
        str
            État du container parmi : "running", "exited", "paused",
            "restarting", "dead", "created", ou "not_start" si aucun
            container n'est attaché à cette instance.
        """
        if not self.container:
            return "not_start"
        self.container.reload()
        return self.container.status

    def get_pid(self) -> int | None:
        """
        Retourne le PID du process principal du container sur l'hôte.

        Ce PID est celui visible depuis le namespace de l'hôte (pas le PID
        interne au container). C'est ce PID qu'on passe à strace pour
        attacher le traceur depuis l'extérieur du container.

        Returns
        -------
        int | None
            PID du process principal, ou None si aucun container actif.
        """
        if not self.container:
            return None
        self.container.reload()
        return self.container.attrs["State"]["Pid"]

    def get_fs_root(self) -> str | None:
        """
        Retourne le chemin vers le filesystem du container sur l'hôte.

        Docker utilise le driver overlay2 pour stocker les layers des
        containers. Le répertoire "merged" est la vue unifiée du filesystem
        du container, accessible depuis l'hôte. C'est ce chemin qu'on
        fournit à inotifywait pour surveiller les accès fichiers du container
        depuis l'extérieur.

        Exemple de chemin retourné :
        /var/lib/docker/overlay2/abc123.../merged

        Returns
        -------
        str | None
            Chemin absolu vers le filesystem mergé, ou None si aucun
            container actif ou si le driver n'est pas overlay2.
        """
        if not self.container:
            return None
        self.container.reload()
        try:
            return self.container.attrs["GraphDriver"]["Data"]["MergedDir"]
        except KeyError:
            logger.print("⚠️ MergedDir non disponible (driver non overlay2 ?)")
            try:
                pid = self.get_pid()
                if not pid:
                    return None
                with open(f"/proc/{pid}/mounts") as f:
                    for line in f:
                        if not line.startswith("overlay"):
                            continue
                        for opt in line.split(","):
                            if opt.startswith("upperdir="):
                                logger.print("Fsroot trouvé",)
                                return opt.removeprefix("upperdir=").strip()
            except Exception as e:
                logger.print(f"❌ Erreur get_fs_root: {e}")
            return None

    def get_stats(self) -> dict:
        """
        Retourne les statistiques temps réel du container.

        Récupère un snapshot unique des métriques Docker : utilisation CPU,
        mémoire RAM, I/O réseau et disque. Utile pour le resource_monitor
        afin de détecter des comportements anormaux (spike CPU, explosion RAM).

        Returns
        -------
        dict
            Dictionnaire de statistiques Docker contenant notamment :
            - cpu_stats / precpu_stats : métriques CPU
            - memory_stats : usage mémoire
            - networks : I/O réseau par interface
            - blkio_stats : I/O disque
            Retourne un dict vide en cas d'erreur, None si pas de container.
        """
        try:
            if not self.container:
                return None
            return dict(self.container.stats(stream=False))
        except Exception:
            return {}

    def get_logs(self, tail: str | int = "all") -> tuple[str | None, str | None]:
        """
        Récupère les logs stdout et stderr du container.

        Retourne les sorties du process principal du container depuis son
        démarrage (ou depuis la ligne `tail`). Utile pour le débogage et
        pour récupérer les sorties d'un programme exécuté.

        Parameters
        ----------
        tail : str | int, optional
            Nombre de lignes à retourner depuis la fin, ou "all" pour tout.
            "all" par défaut.

        Returns
        -------
        tuple[str | None, str | None]
            Tuple (stdout, stderr) décodé en UTF-8.
            Retourne (None, None) si aucun container actif ou en cas d'erreur.
        """
        try:
            if not self.container:
                return None, None
            stdout = bytes(
                self.container.logs(stream=False, stdout=True, stderr=False, timestamps=True, tail=tail)
            ).decode("utf-8", errors="ignore")
            stderr = bytes(
                self.container.logs(stream=False, stdout=False, stderr=True, timestamps=True, tail=tail)
            ).decode("utf-8", errors="ignore")
            return stdout, stderr
        except Exception:
            return None, None

    def health_check(self) -> bool:
        """
        Vérifie que le container est opérationnel et répond aux commandes.

        Effectue deux vérifications :
        1. Le status Docker est bien "running"
        2. Une commande echo simple retourne exit code 0

        Returns
        -------
        bool
            True si le container est en bonne santé, False sinon.
        """
        if not self.container:
            return False
        try:
            status = self.get_status()
            if status.lower() != "running":
                return False
            code, _, _ = self.exec_command("echo 'SHIELD SANDBOX'")
            return code == 0
        except Exception:
            return False

    async def health_check_async(self) -> bool:
        """
        Version asynchrone de health_check().

        Délègue l'appel bloquant à un thread via asyncio.to_thread
        pour ne pas bloquer l'event loop pendant la vérification.

        Returns
        -------
        bool
            True si le container est en bonne santé, False sinon.
        """
        return await asyncio.to_thread(self.health_check)

    # ─────────────────────────────────────────────────────────────────────────
    # CONTRÔLE DU CYCLE DE VIE
    # ─────────────────────────────────────────────────────────────────────────

    def pause(self) -> bool:
        """
        Met le container en pause via cgroups freezer.

        Le process est gelé : il ne consomme plus de CPU mais la RAM
        est préservée. Utile pour effectuer une analyse forensique de
        l'état du container sans le modifier.

        Returns
        -------
        bool
            True si la pause a réussi, False sinon.
        """
        try:
            if not self.container:
                return False
            self.container.pause()
            logger.print(f"⏸️  Container {self.container.name} mis en pause")
            return True
        except Exception as e:
            logger.print(f"⚠️ Erreur pause: {e}")
            return False

    def unpause(self) -> bool:
        """
        Reprend l'exécution d'un container en pause.

        Relève le freeze cgroups et permet au process de reprendre
        son exécution exactement là où il s'était arrêté.

        Returns
        -------
        bool
            True si la reprise a réussi, False sinon.
        """
        try:
            if not self.container:
                return False
            self.container.unpause()
            logger.print(f"▶️  Container {self.container.name} repris")
            return True
        except Exception as e:
            logger.print(f"⚠️ Erreur unpause: {e}")
            return False

    def update(self, **kwargs) -> bool:
        """
        Met à jour dynamiquement les ressources allouées au container.

        Permet de modifier à chaud certaines contraintes de ressources
        sans redémarrer le container. Attention : les paramètres réseau,
        seccomp et capabilities ne sont pas modifiables à chaud.

        Parameters
        ----------
        **kwargs : dict
            Paramètres Docker à mettre à jour. Principaux supportés :
            - mem_limit (str) : nouvelle limite mémoire ex: "512m"
            - cpu_quota (int) : nouveau quota CPU
            - pids_limit (int) : nouveau max de processus

        Returns
        -------
        bool
            True si la mise à jour a réussi, False sinon.
        """
        try:
            if not self.container:
                return False
            self.container.update(**kwargs)
            logger.print(f"🔧 Container mis à jour: {kwargs}")
            return True
        except Exception as e:
            logger.print(f"⚠️ Erreur update: {e}")
            return False

    def kill(self) -> bool:
        """
        Tue immédiatement le container via SIGKILL.

        Envoie un signal SIGKILL au process principal du container,
        provoquant un arrêt immédiat sans délai de grâce. À utiliser
        quand le container est suspect ou que le timeout est dépassé.
        Ne supprime pas le container — utiliser stop() pour supprimer.

        Returns
        -------
        bool
            True si le kill a réussi, False sinon.
        """
        if self.container:
            logger.print(f"🛑 SIGKILL → container {self.container.name}...")
            try:
                self.container.kill(signal="SIGKILL")
                logger.print("✅ Container tué")
                return True
            except Exception as e:
                logger.print(f"⚠️ Erreur kill: {e}")
                return False
        return False

    def stop(self) -> None:
        """
        Arrête proprement le container et le supprime.

        Envoie d'abord SIGTERM (arrêt gracieux), attend quelques secondes,
        puis supprime définitivement le container. Contrairement à kill(),
        cette méthode nettoie complètement le container après l'arrêt.

        Returns
        -------
        None
        """
        if self.container:
            logger.print(f"🛑 Arrêt container {self.container.name}...")
            try:
                self.container.stop(timeout=5)
                self.container.remove(force=True)
                logger.print("✅ Container arrêté et supprimé")
            except Exception as e:
                logger.print(f"⚠️ Erreur stop: {e}")

    def wait_for_exit(self, timeout: int = 30) -> tuple[bool, int | None, dict | None]:
        """
        Attend la fin naturelle du container.

        Bloque jusqu'à ce que le container s'arrête de lui-même ou
        que le timeout soit atteint. Retourne l'exit code du process
        principal du container.

        Parameters
        ----------
        timeout : int, optional
            Nombre de secondes maximum à attendre. 30 par défaut.

        Returns
        -------
        tuple[bool, int | None, dict | None]
            - bool   : True si le container s'est arrêté normalement
            - int    : Exit code du process (0 = succès, autre = erreur)
            - dict   : Résultat brut Docker {"StatusCode": 0, "Error": None}
            En cas d'erreur/timeout : (False, None, None)
        """
        if not self.container:
            return False, None, None
        try:
            result = self.container.wait(timeout=timeout)
            return True, result["StatusCode"], result
        except Exception as e:
            logger.print(f"⚠️ wait_for_exit: {e}")
            return False, None, None

    async def wait_for_exit_async(self, timeout: int = 30) -> tuple[bool, int | None, dict | None]:
        """
        Version asynchrone de wait_for_exit().

        Délègue l'attente bloquante à un thread pour ne pas bloquer
        l'event loop. Permet d'attendre la fin du container en parallèle
        d'autres coroutines (surveillance, scoring...).

        Parameters
        ----------
        timeout : int, optional
            Nombre de secondes maximum à attendre. 30 par défaut.

        Returns
        -------
        tuple[bool, int | None, dict | None]
            Voir wait_for_exit().
        """
        return await asyncio.to_thread(self.wait_for_exit, timeout)

    async def enforce_timeout_async(
        self, wait_timeout: int = 30, enforce_timeout: int = 40
    ) -> tuple[bool, int | None, dict | None]:
        """
        Attend la fin du container et le tue automatiquement si timeout dépassé.

        Wrapper autour de wait_for_exit_async() avec un double timeout :
        - wait_timeout : timeout passé à container.wait() (niveau Docker)
        - enforce_timeout : timeout asyncio global (niveau Python)
        Si l'un ou l'autre est dépassé, le container est tué via SIGKILL.

        Parameters
        ----------
        wait_timeout : int, optional
            Timeout Docker en secondes. 30 par défaut.
        enforce_timeout : int, optional
            Timeout asyncio global en secondes. Doit être > wait_timeout.
            40 par défaut.

        Returns
        -------
        tuple[bool, int | None, dict | None]
            Résultat de wait_for_exit(), ou (False, None, None) si tué.
        """
        try:
            result = await asyncio.wait_for(
                self.wait_for_exit_async(wait_timeout),
                timeout=enforce_timeout
            )
            return result
        except (asyncio.TimeoutError, Exception) as e:
            logger.print(f"⏰ Timeout dépassé ({enforce_timeout}s) → kill forcé, erreur : {str(e)}")
            self.kill()
            return False, None, None

    def enforce_timeout(
        self, wait_timeout: int = 30, enforce_timeout: int = 40
    ) -> tuple[bool, int | None, dict | None]:
        """
        Version synchrone de enforce_timeout_async().

        À utiliser uniquement hors d'un event loop asyncio existant.
        Si tu es déjà dans un contexte async, utilise enforce_timeout_async().

        Parameters
        ----------
        wait_timeout : int, optional
            Timeout Docker en secondes. 30 par défaut.
        enforce_timeout : int, optional
            Timeout asyncio global en secondes. 40 par défaut.

        Returns
        -------
        tuple[bool, int | None, dict | None]
            Voir enforce_timeout_async().
        """
        return asyncio.run(self.enforce_timeout_async(wait_timeout, enforce_timeout))

    # ─────────────────────────────────────────────────────────────────────────
    # EXÉCUTION DE COMMANDES
    # ─────────────────────────────────────────────────────────────────────────

    def _exec_command(
        self,
        cmd: str,
        container: Container,
        user: str = "root",
        workdir: str | None = None
    ) -> tuple[int, str, str]:
        """
        Méthode interne d'exécution de commande dans un container.

        Exécute une commande shell dans le container via l'API Docker exec.
        stdout et stderr sont capturés séparément grâce à demux=True.
        Si stdout ou stderr est None (process sans output), une chaîne vide
        est retournée pour éviter les erreurs de décodage.

        Parameters
        ----------
        cmd : str
            Commande shell à exécuter. Peut être une string ou une liste.
            Exemple : "python3 /sandbox/work/code.py"
        container : Container
            Container Docker cible. Doit être en état "running".
        user : str, optional
            Utilisateur sous lequel exécuter la commande. "root" par défaut.
        workdir : str | None, optional
            Répertoire de travail pour la commande. None = workdir du container.

        Returns
        -------
        tuple[int, str, str]
            - int : Exit code (0 = succès, autre = erreur)
            - str : Stdout décodé en UTF-8
            - str : Stderr décodé en UTF-8

        Raises
        ------
        ValueError
            Si le container fourni est None ou invalide.
        """
        if not container:
            raise ValueError("Container invalide !")

        try:
            exit_code, (stdout, stderr) = (
                container.exec_run(cmd, stdout=True, stderr=True, user=user, demux=True, workdir=workdir)
                if workdir else
                container.exec_run(cmd, stdout=True, stderr=True, user=user, demux=True)
            )
            stdout = (stdout or b"").decode("utf-8", errors="ignore")
            stderr = (stderr or b"").decode("utf-8", errors="ignore")
            logger.print()
            logger.print("💻 Commande :", cmd[:200], verify=False)
            logger.print("📤 Code retour :", exit_code)
            logger.print()
            return exit_code, stdout, stderr

        except Exception as e:
            logger.print(f"❌ Erreur exécution commande: {e}")
            return 1, "", ""

    def exec_command(
        self, cmd: str, user: str = "root", workdir: str | None = None
    ) -> tuple[int, str, str]:
        """
        Exécute une commande dans le container courant (version synchrone).

        Wrapper public autour de _exec_command() utilisant le container
        courant de l'instance.

        Parameters
        ----------
        cmd : str
            Commande à exécuter.
        user : str, optional
            Utilisateur d'exécution. "root" par défaut.
        workdir : str | None, optional
            Répertoire de travail. None par défaut.

        Returns
        -------
        tuple[int, str, str]
            (exit_code, stdout, stderr)
        """
        return self._exec_command(cmd, self.container, user=user, workdir=workdir)

    async def _exec_command_async(
        self,
        cmd: str,
        container: Container,
        user: str = "root",
        workdir: str | None = None,
        timeout: int | None = 120
    ) -> tuple[int, str, str]:
        """
        Version asynchrone de _exec_command().

        Délègue l'appel bloquant à un thread via asyncio.to_thread, permettant
        d'exécuter des commandes dans le container sans bloquer l'event loop.
        Un timeout asyncio est appliqué pour éviter les blocages infinis.

        Parameters
        ----------
        cmd : str
            Commande à exécuter.
        container : Container
            Container Docker cible.
        user : str, optional
            Utilisateur d'exécution. "root" par défaut.
        workdir : str | None, optional
            Répertoire de travail. None par défaut.
        timeout : int | None, optional
            Timeout en secondes. None = pas de timeout. 120 par défaut.

        Returns
        -------
        tuple[int, str, str]
            (exit_code, stdout, stderr), ou (1, "", "Timeout atteint") si timeout.
        """
        try:
            task = asyncio.create_task(
                asyncio.to_thread(
                    self._exec_command,
                    cmd, container, user, workdir
                )
            )
            if timeout:
                task = asyncio.wait_for(task, timeout=timeout)
            return await task

        except asyncio.TimeoutError:
            logger.print(f"⏰ Timeout ({timeout}s) atteint pour la commande")
            return 1, "", "Timeout atteint"

        except Exception as e:
            logger.print(f"❌ Erreur async exec: {e}")
            return 1, "", ""

    async def exec_command_async(
        self, cmd: str, user: str = "root", workdir: str | None = None, timeout: int | None = 120
    ) -> tuple[int, str, str]:
        """
        Exécute une commande dans le container courant (version asynchrone).

        Wrapper public autour de _exec_command_async() utilisant le container
        courant de l'instance.

        Parameters
        ----------
        cmd : str
            Commande à exécuter.
        user : str, optional
            Utilisateur d'exécution. "root" par défaut.
        workdir : str | None, optional
            Répertoire de travail. None par défaut.
        timeout : int | None, optional
            Timeout en secondes. 120 par défaut.

        Returns
        -------
        tuple[int, str, str]
            (exit_code, stdout, stderr)
        """
        return await self._exec_command_async(
            cmd, self.container, user=user, workdir=workdir, timeout=timeout
        )

    # ─────────────────────────────────────────────────────────────────────────
    # COPIE DE FICHIERS
    # ─────────────────────────────────────────────────────────────────────────

    def copy_in(
        self,
        content: str,
        dest_path: str,
        container: Container | None = None,
        use_subprocess: bool = True,
        user: str = "root",
    ) -> tuple[int, str, str]:
        """
        Copie du contenu texte dans un fichier à l'intérieur du container.

        Deux stratégies disponibles :
        - subprocess (défaut) : pipe stdin via docker exec -i → propre,
          gère les caractères spéciaux et guillemets sans échappement.
        - base64 : encode le contenu en base64 et le décode dans le container
          via exec_run → fallback si subprocess n'est pas disponible.

        Le répertoire parent du fichier de destination est créé automatiquement
        si il n'existe pas.

        Parameters
        ----------
        content : str
            Contenu texte à écrire dans le fichier.
        dest_path : str
            Chemin absolu de destination dans le container.
            Exemple : "/sandbox/work/code.py"
        container : Container | None, optional
            Container cible. Si None, utilise self.container.
        use_subprocess : bool, optional
            True = méthode subprocess (recommandée). False = méthode base64.
            True par défaut.

        Returns
        -------
        tuple[int, str, str]
            (returncode, stdout, stderr)

        Raises
        ------
        ValueError
            Si aucun container valide n'est disponible.
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")

        container_id = container.id
        dirname = os.path.dirname(dest_path)
        if dirname:
            self._exec_command(f"mkdir -p {dirname}", container)

        if use_subprocess:
            result = subprocess.run(
                f"""docker exec -i --user {user} {container_id} bash -c "cat > {dest_path}" """,
                text=True,
                capture_output=True,
                input=content, 
                shell=True
            )
            returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        else:
            encoded = base64.b64encode(content.encode()).decode()
            cmd = f"""bash -c "echo '{encoded}' | base64 -d > {dest_path}" """
            returncode, stdout, stderr = self._exec_command(cmd=cmd, container=container, user=user)

        logger.print(f"📁 copy_in → {dest_path} | code: {returncode}")
        return returncode, stdout, stderr

    def copy_out(
        self,
        src_path: str,
        container: Container | None = None,
        user: str = "root",
    ) -> tuple[int, str, str]:
        """
        Lit le contenu d'un fichier depuis le container.

        Exécute un `cat` sur le fichier cible et retourne son contenu
        via stdout. Simple et efficace pour des fichiers texte.

        Parameters
        ----------
        src_path : str
            Chemin absolu du fichier à lire dans le container.
            Exemple : "/sandbox/work/output.txt"
        container : Container | None, optional
            Container source. Si None, utilise self.container.

        Returns
        -------
        tuple[int, str, str]
            (exit_code, contenu_fichier, stderr)
            Le contenu du fichier est dans le second élément du tuple.

        Raises
        ------
        ValueError
            Si aucun container valide n'est disponible.
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")

        return self._exec_command(f"cat {src_path}", container, user=user)

    # ─────────────────────────────────────────────────────────────────────────
    # SURVEILLANCE — TRACEUR STRACE
    # ─────────────────────────────────────────────────────────────────────────

    def attach_tracer(
        self, pid: int | None = None, in_file: bool = True,
        file:str | None = None
    ) -> tuple[subprocess.Popen | None, str | None]:
        """
        Attache strace au process principal du container (version synchrone).

        Lance strace depuis l'hôte en s'attachant au PID du container.
        strace intercepte tous les appels système effectués par le process
        et ses enfants (-f pour suivre les forks). Le traceur tourne
        en dehors du container → invisible et non tuable depuis l'intérieur.

        Flags strace utilisés :
        - -p <pid> : attacher au process existant
        - -f       : suivre les forks et threads enfants
        - -e trace=all : capturer tous les syscalls
        - -T       : afficher le temps passé dans chaque syscall
        - -tt      : timestamp précis (microsecondes)
        - -o <file>: écrire dans un fichier (si in_file=True)

        Parameters
        ----------
        pid : int | None, optional
            PID hôte du container. Si None, récupéré via get_pid().
        in_file : bool, optional
            Si True, strace écrit dans un fichier log dédié.
            Si False, stdout/stderr du process sont utilisés.
            True par défaut.

        Returns
        -------
        tuple[subprocess.Popen | None, str | None]
            - Popen : process strace actif (lire via process.stdout/stderr)
            - str   : chemin du fichier log, ou None si in_file=False
            Retourne (None, None) en cas d'échec.
        """
        pid = pid or self.get_pid()
        if not pid:
            return None, None

        try:
            cmd = [
                "sudo",
                "strace",
                "-p", str(pid),
                "-f",
                "-e", "trace=all",
                "-T",
                "-tt",
            ]
            file = None
            if in_file:
                file = os.path.join(self.volume_dir, file or self.strace_file)
                cmd.extend(["-o", file])

            process = subprocess.Popen(
                cmd,
                shell=False,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            logger.print(f"🔍 strace attaché au PID {pid} | log: {file}")
            return process, file

        except Exception as e:
            logger.print(f"❌ Erreur attach_tracer: {e}")
            return None, None

    async def attach_tracer_async(
        self, pid: int | None = None, in_file: bool = True,
        file:str | None = None
    ) -> tuple[asyncio.subprocess.Process | None, str | None]:
        """
        Attache strace au process principal du container (version asynchrone).

        Version async de attach_tracer() utilisant asyncio.create_subprocess_exec.
        Permet de lire la sortie de strace ligne par ligne sans bloquer l'event loop :

            async for line in process.stdout:
                syscall = parse_syscall(line.decode())
                await behavior_scorer.add_event(syscall)

        C'est la version recommandée pour l'orchestrateur async du sandbox.

        Parameters
        ----------
        pid : int | None, optional
            PID hôte du container. Si None, récupéré via get_pid().
        in_file : bool, optional
            Si True, strace écrit dans un fichier log dédié. True par défaut.

        Returns
        -------
        tuple[asyncio.subprocess.Process | None, str | None]
            - Process asyncio : lire via async for line in process.stdout
            - str : chemin du fichier log, ou None si in_file=False
            Retourne (None, None) en cas d'échec.
        """
        pid = pid or self.get_pid()
        if not pid:
            return None, None

        try:
            cmd = [
                "sudo",
                "strace",
                "-p", str(pid),
                "-f",
                "-e", "trace=all",
                "-T",
                "-tt",
            ]
            file = None
            if in_file:
                file = os.path.join(self.volume_dir, file or self.strace_file)
                cmd.extend(["-o", file])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stderr=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE
            )
            logger.print(f"🔍 strace async attaché au PID {pid} | log: {file}")
            return process, file

        except Exception as e:
            logger.print(f"❌ Erreur attach_tracer_async: {e}")
            return None, None

    def get_file_reader_process(self, file: str) -> subprocess.Popen | None:
        """
        Lance un processus tail -F pour lire un fichier en temps réel (synchrone).

        Utile pour lire le fichier de log de strace en continu via
        `for line in process.stdout`. tail -F continue même si le fichier
        est recréé (rotation de logs).

        Parameters
        ----------
        file : str
            Chemin absolu du fichier à surveiller.

        Returns
        -------
        subprocess.Popen | None
            Process tail actif, ou None si le fichier est invalide.
        """
        if not file:
            return None
        tail = subprocess.Popen(
            ["tail", "-n", "+1", "-F", file],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return tail

    async def get_file_reader_process_async(self, file: str, start_new_session: bool = False) -> asyncio.subprocess.Process | None:
        """
        Lance un processus tail -F pour lire un fichier en temps réel (asynchrone).

        Version async de get_file_reader_process(). Permet de lire le fichier
        strace ligne par ligne sans bloquer l'event loop :

            process = await manager.get_file_reader_process_async(log_file)
            async for line in process.stdout:
                await handle_strace_line(line.decode())

        Parameters
        ----------
        file : str
            Chemin absolu du fichier à surveiller.

        Returns
        -------
        asyncio.subprocess.Process | None
            Process tail asyncio actif, ou None si le fichier est invalide.
        """
        if not file:
            return None
        tail = await asyncio.create_subprocess_exec(
            "tail", "-n", "0", "-F", file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=start_new_session
        )
        return tail

    # ─────────────────────────────────────────────────────────────────────────
    # RÉSEAU ET IP
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_ip_type(ip: str) -> str:
        """
        Détermine le type d'une adresse IP.

        Tente de parser l'IP avec inet_pton pour IPv4 puis IPv6.
        Accepte les adresses avec préfixe CIDR (ex: "192.168.1.1/24").

        Parameters
        ----------
        ip : str
            Adresse IP à analyser. Peut inclure un préfixe CIDR.

        Returns
        -------
        str
            "ip4" si IPv4 valide, "ip6" si IPv6 valide, "error" sinon.
        """
        try:
            ip = ip.split('/')[0].strip()
            for family, label in [(socket.AF_INET, "ip4"), (socket.AF_INET6, "ip6")]:
                try:
                    socket.inet_pton(family, ip)
                    return label
                except Exception:
                    pass
            return "error"
        except Exception:
            return "error"
        return "error"

    def is_valid_ip(self, ip_string: str) -> bool:
        """
        Vérifie si une chaîne est une adresse IP valide (IPv4 ou IPv6).

        Parameters
        ----------
        ip_string : str
            Chaîne à vérifier.

        Returns
        -------
        bool
            True si l'IP est valide, False sinon.
        """
        return self.get_ip_type(ip_string) != "error"

    def _search_key(self, dic: dict, key: str):
        """
        Recherche récursivement une clé dans un dictionnaire imbriqué.

        Parcourt le dictionnaire en profondeur jusqu'à trouver la première
        occurrence de la clé (insensible à la casse). Utile pour naviguer
        dans les structures attrs Docker qui peuvent varier selon la version.

        Parameters
        ----------
        dic : dict
            Dictionnaire à parcourir.
        key : str
            Clé à rechercher (insensible à la casse).

        Returns
        -------
        any
            Valeur associée à la clé, ou None si non trouvée.
        """
        for k, v in dic.items():
            if str(k).lower() == str(key).lower():
                return v
            if isinstance(v, dict) and v:
                result = self._search_key(v, key)
                if result is not None:
                    return result
        return None

    def get_ip(self, network: str = "bridge") -> str:
        """
        Récupère l'adresse IP du container sur un réseau donné.

        Tente d'abord de lire l'IP depuis le réseau spécifié dans les attrs
        Docker. En cas d'échec (réseau custom, structure différente), effectue
        une recherche récursive dans les NetworkSettings.

        Parameters
        ----------
        network : str, optional
            Nom du réseau Docker. "bridge" par défaut.

        Returns
        -------
        str
            Adresse IP du container sur le réseau spécifié.

        Raises
        ------
        ValueError
            Si aucun container actif, ou si aucune IP valide n'est trouvée.
        """
        if not self.container:
            raise ValueError("Container pas démarré !")

        self.container.reload()
        logger.print("🌐 Clés NetworkSettings :", list(self.container.attrs['NetworkSettings'].keys()))

        try:
            ip = self.container.attrs['NetworkSettings']['Networks'][network]['IPAddress']
        except (KeyError, TypeError):
            dic = self.container.attrs['NetworkSettings']
            ip = self._search_key(dic, "IPAddress")

        if not self.is_valid_ip(str(ip)):
            ip = ''

        if not ip:
            raise ValueError("Container n'a pas d'IP (réseau pas prêt ?)")
        return ip

    def container_list(self) -> list:
        """
        Retourne la liste de tous les containers Docker sur le système.

        Inclut les containers arrêtés (all=True).

        Returns
        -------
        list
            Liste d'objets Container Docker.
        """
        return self.client.containers.list(all=True)


# ─────────────────────────────────────────────────────────────────────────────
# TEST RAPIDE
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cont_manager = ContainerManager()
    print(cont_manager.list_images())
    print(cont_manager.container_list())
    print(dir(cont_manager))
    print(dir(ContainerManager))