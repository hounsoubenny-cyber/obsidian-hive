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

import io    
import time
import socket
import docker
import base64
import shlex
import shutil
import tarfile
import asyncio
import tempfile
import subprocess
from datetime import datetime
from uuid import uuid4
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

    def __init__(self, shared_volume: bool = True):
        """
        shared_volume : True (défaut, comportement historique de l'orchestrator) crée
        le dossier partagé hôte <-> container et le log strace. Mettre False pour un
        container SANS aucun bind mount vers l'hôte (ex: workspace d'Alex).
        """
        self.client = docker.from_env()
        self.image_name = None
        self.container: docker.models.containers.Container = None
        self._strace_file = self.generate_strace_log_file()
        self.volume_dir = None
        self.volume_dir_on_container = "/container/shared"
        if not shared_volume:
            return
        # Dossier partagé hôte <-> container : PRIVÉ à ce manager (nom imprévisible,
        # pas de collision entre analyses). Le code analysé tourne avec un autre
        # UID que l'hôte : le sticky bit (1777) l'empêche de supprimer/renommer un
        # fichier créé par l'hôte, donc de remplacer le log strace par un lien
        # symbolique vers un fichier de l'hôte (que `tail -F` suivrait).
        self.volume_dir = tempfile.mkdtemp(prefix="shield-sandbox-") + os.sep
        self.volume_dir_on_container = "/container/shared"
        os.chmod(self.volume_dir, 0o1777)
        strace_path = os.path.join(self.volume_dir, self._strace_file)
        fd = os.open(strace_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o666)
        os.close(fd)
        os.chmod(strace_path, 0o666)
    
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
        cap_add: list[str] | None = None
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
        home_uid = user.split(":")[0] if ":" in user else user
        environment = {
            "SANDBOX_ID": "shieldai",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "HOME": "/root" if home_uid == "0" else f"/home/{home_uid}",
            "TERM": "xterm-256color",
            "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"
        }
        if extra_env:
            environment.update(extra_env)

        cap_add = list(
            set(
                list(cap_add) if cap_add else [
                    "SYS_PTRACE",
                ]
            )
        )
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
            "cap_add": cap_add,     # re-add uniquement pour strace
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
            } if self.volume_dir else {}
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

    # ─────────────────────────────────────────────────────────────────────────
    # ARCHIVES TAR + EXEC AVEC SORTIE PLAFONNÉE (utilisés par Workspace)
    # ─────────────────────────────────────────────────────────────────────────

    def put_archive_bytes(self, dest_dir: str, data: bytes, container=None) -> bool:
        """Extrait une archive tar (bytes) dans dest_dir du container (via l'API Docker,
        sans shell). Les propriétaires/permissions viennent des en-têtes du tar."""
        container = container or self.container
        if container is None:
            raise ValueError("Container invalide !")
        return bool(container.put_archive(dest_dir, data))

    def get_archive_bytes(self, src_path: str, max_bytes: int, container=None) -> bytes:
        """Récupère src_path du container sous forme de tar (bytes), en abandonnant
        (ValueError) si l'archive dépasse max_bytes — protège la RAM de l'hôte."""
        container = container or self.container
        if container is None:
            raise ValueError("Container invalide !")
        stream, _stat = container.get_archive(src_path)
        buf, size = bytearray(), 0
        for chunk in stream:
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"Archive trop volumineuse (> {max_bytes} octets)")
            buf += chunk
        return bytes(buf)

    def exec_capped(
        self,
        argv: list[str],
        user: str = "1500:1500",
        workdir: str | None = None,
        max_output_bytes: int = 200_000,
        container=None,
    ) -> dict:
        """
        Exécute argv (liste, sans shell hôte) dans le container et renvoie
        {"exit_code", "stdout", "stderr", "truncated"}.

        La sortie est PLAFONNÉE par flux : au-delà, on continue de consommer (pour
        récupérer le vrai code de sortie) mais on jette l'excédent. Le temps est borné
        par l'appelant (préfixer argv par `timeout N`), pas ici.
        """
        container = container or self.container
        if container is None:
            raise ValueError("Container invalide !")
        api = self.client.api
        exec_id = api.exec_create(
            container.id, argv, stdout=True, stderr=True, user=user, workdir=workdir
        )["Id"]
        out, err, truncated = bytearray(), bytearray(), False
        for chunk_out, chunk_err in api.exec_start(exec_id, stream=True, demux=True):
            for buf, chunk in ((out, chunk_out), (err, chunk_err)):
                if not chunk:
                    continue
                room = max_output_bytes - len(buf)
                if room > 0:
                    buf += chunk[:room]
                if len(chunk) > max(room, 0):
                    truncated = True
        info = api.exec_inspect(exec_id)
        return {
            "exit_code": info.get("ExitCode"),
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "truncated": truncated,
        }

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
        cmd: str | list[str],
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
            if isinstance(cmd, str):
                cmd = ["sh", "-c", cmd]
            elif isinstance(cmd, list):
                cmd = ["sh", "-c", shlex.join(cmd)]
            else:
                cmd = ["sh", "-c", str(cmd)]
            exit_code, (stdout, stderr) = (
                container.exec_run(
                    cmd, 
                    stdout=True, 
                    stderr=True,
                    user=user,
                    demux=True, 
                    **(
                        dict(
                            workdir=workdir
                        )
                        if workdir 
                        else {}
                    )
                )
            )
            stdout = (stdout or b"").decode("utf-8", errors="ignore")
            stderr = (stderr or b"").decode("utf-8", errors="ignore")
            logger.print()
            shown = cmd if isinstance(cmd, str) else " ".join(map(str, cmd))
            logger.print("💻 Commande :", shown[:200], verify=False)
            logger.print("📤 Code retour :", exit_code)
            logger.print()
            return exit_code, stdout, stderr

        except Exception as e:
            logger.print(f"❌ Erreur exécution commande: {e}")
            return 1, "", f"Erreur exécution commande: {e}"

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

        except asyncio.TimeoutError as e:
            logger.print(f"⏰ Timeout ({timeout}s) atteint pour la commande")
            return -1, "", f"TIMEOUT: {e!r}"

        except Exception as e:
            logger.print(f"❌ Erreur async exec: {e}")
            return 1, "", f"Erreur async exec: {e}"

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
        content: str | bytes,
        dest_path: str,
        container: Container | None = None,
        use_subprocess: bool = True,
        user: str = "root",
        chown_to: str | None = None
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

        # Normalisation : accepte str OU bytes, tout est traité en bytes à
        # partir d'ici — même principe que copy_out/copy_out_dir (jamais de
        # decode UTF-8 forcé sur du contenu potentiellement binaire).
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content

        container_id = container.id
        dirname = os.path.dirname(dest_path)
        if dirname:
            self._exec_command(["mkdir", "-p", dirname], container)

        if use_subprocess:
            # Pas de shell côté hôte : dest_path est passé en argument positionnel ($1).
            # Mode binaire (pas de text=True) : input attend des bytes désormais.
            result = subprocess.run(
                ["docker", "exec", "-i", "--user", str(user), container_id,
                 "bash", "-c", 'cat > "$1"', "_", dest_path],
                capture_output=True,
                input=content_bytes,
            )
            returncode = result.returncode
            stdout = result.stdout.decode("utf-8", errors="ignore")
            stderr = result.stderr.decode("utf-8", errors="ignore")
        else:
            encoded = base64.b64encode(content_bytes).decode()
            cmd = ["bash", "-c", 'echo "$1" | base64 -d > "$2"', "_", encoded, dest_path]
            returncode, stdout, stderr = self._exec_command(cmd=cmd, container=container, user=user)
        
        if chown_to and returncode == 0:
            self._exec_command(["chown", chown_to, dest_path], container, user="root")
        
        logger.print(f"📁 copy_in → {dest_path} | code: {returncode}")
        return returncode, stdout, stderr
    

    def copy_in_dir(
        self,
        src_path: str,
        dest_path: str,
        container: "Container | None" = None,
        chown_to: str | None = None
    ) -> dict:
        """Copie récursivement un dossier de l'hôte vers le container.
    
        Utilise directement l'API Docker native (container.put_archive), pas
        d'exec/cat impliqué -> aucun risque de corruption binaire (contrairement
        à copy_out_dir qui doit passer par le canal texte de _exec_command).
    
        Parameters
        ----------
        src_path : str
            Dossier source sur l'hôte.
        dest_path : str
            Dossier de destination DANS le container (doit déjà exister —
            put_archive extrait dedans, il ne le crée pas).
    
        Returns
        -------
        dict: {"success": bool, "error": str | None, "dest_path": str | None}
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
    
        if not os.path.isdir(src_path):
            return {"success": False, "error": f"{src_path} n'existe pas ou n'est pas un dossier sur l'hôte", "dest_path": None}
    
        if not self.is_dir(dest_path, container=container):
            self.exec_command(
                f"mkdir -p {dest_path}"
            )
            if not self.is_dir(dest_path, container=container):
                return {"success": False, "error": f"{dest_path} n'existe pas ou n'est pas un dossier dans le container", "dest_path": None}
    
        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                # arcname="." -> le CONTENU de src_path atterrit directement
                # dans dest_path, pas dans un sous-dossier nommé comme src_path
                tar.add(src_path, arcname=".")
            buf.seek(0)
    
            ok = container.put_archive(path=dest_path, data=buf.getvalue())
            if not ok:
                return {"success": False, "error": "put_archive a renvoyé False (échec côté Docker)", "dest_path": None}
            
            if chown_to:
                code, _, err = self._exec_command(
                    ["chown", "-R", chown_to, dest_path], container, user="root"
                )
                if code != 0:
                    return {"success": False, "error": f"chown post-copie échoué: {err}", "dest_path": None}

        except Exception as e:
            return {"success": False, "error": f"échec de la copie vers le container : {e}", "dest_path": None}
    
        return {"success": True, "error": None, "dest_path": dest_path}
    
    
    def is_file(
        self,
        path: str,
        container: "Container | None" = None,
        user: str = "root",
    ) -> bool:
        """Vérifie que `path` existe dans le container ET est un fichier régulier.
    
        S'appuie sur `test -f`, standard POSIX : exit 0 = vrai, exit != 0 = faux
        (chemin absent, dossier, symlink cassé...). Pas de parsing de sortie,
        juste le code de retour.
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
    
        exit_code, _, _ = self._exec_command(f"test -f {path}", container, user=user)
        return exit_code == 0
    
    
    def is_dir(
        self,
        path: str,
        container: "Container | None" = None,
        user: str = "root",
    ) -> bool:
        """Vérifie que `path` existe dans le container ET est un dossier.
    
        Même principe que is_file, avec `test -d`.
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
    
        exit_code, _, _ = self._exec_command(f"test -d {path}", container, user=user)
        return exit_code == 0

    def copy_out(
        self,
        src_path: str,
        container: Container | None = None,
        user: str = "root",
    ) -> dict[str, bool | str | None]:
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
        dict: {
            "success": bool,
            "error": str | None,
            "content": str | None,
        }

        Raises
        ------
        ValueError
            Si aucun container valide n'est disponible.
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
        
        marker = str(uuid4())
        code = (
            f"import shutil, base64\n"
            f"with open({src_path!r}, 'rb') as f:\n"
            f"    payload = base64.b64encode(f.read()).decode('ascii')\n"
            f"print({marker!r}, '=', payload, sep='', flush=True)\n"
        )
        cmd = f"python3 -c {shlex.quote(code)}"
        
        result = self._exec_command(cmd, container)
        if result[0] != 0:
            return {"content": None, "success": False, "error": f"Erreur de lecture du fichier: {result[2]!r}"}
        
        lines = [ln for ln in result[1].split("\n") if ln.startswith(f"{marker}=")]
        if not lines:
            return {"content": None, "success": False, "error": "marqueur de sortie introuvable dans stdout"}
     
        b64_payload = lines[0].removeprefix(f"{marker}=")
    
        try:
            content = base64.b64decode(b64_payload)
            return {"content": content, "success": True, "error": ""}
        
        except Exception as e:
            return {"success": False, "error": f"payload base64 invalide : {e}", "content": None}
     
    
    def copy_out_dir(
        self,
        src_path: str,
        dest_path: str,
        container: "Container | None" = None,
    ) -> dict:
        """Copie récursivement un dossier du container vers l'hôte.
     
        Version avec container.get_archive() — API Docker native, binaire de
        bout en bout. Remplace la version exec+base64+make_archive : plus
        simple, une seule opération, pas de risque de corruption puisqu'on ne
        passe plus jamais par le canal texte de _exec_command pour du binaire.
     
        Returns
        -------
        dict: {"success": bool, "error": str | None, "dest_path": str | None}
        """
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
     
        if not self.is_dir(src_path, container=container):
            return {"success": False, "error": f"{src_path} n'existe pas ou n'est pas un dossier dans le container", "dest_path": None}
     
        if not os.path.isdir(dest_path):
            os.makedirs(dest_path, exist_ok=True)
            # return {"success": False, "error": f"{dest_path} n'existe pas ou n'est pas un dossier sur l'hôte", "dest_path": None}
     
        try:
            # "/." en suffixe = "le CONTENU du dossier", pas le dossier lui-même
            # -> sans ça, get_archive enveloppe tout dans un dossier nommé
            # d'après le basename de src_path (même convention que `docker cp`)
            stream, _stat = container.get_archive(src_path.rstrip("/") + "/.")
     
            buf = io.BytesIO()
            for chunk in stream:
                buf.write(chunk)
            buf.seek(0)
     
            with tarfile.open(fileobj=buf) as tar:
                tar.extractall(dest_path, filter="data")
        except Exception as e:
            return {"success": False, "error": f"échec de la copie depuis le container : {e}", "dest_path": None}
     
        return {"success": True, "error": None, "dest_path": dest_path}
 
    def exists_in_container(
        self, 
        path: str,
        container: Container | None = None
    ):
        if container is None:
            container = self.container
        if container is None:
            raise ValueError("Container invalide !")
        return self._exec_command(f"test -e {path}", container)[0] == 0
    
    def read_file(
        self, 
        path: str,
        container: Container | None = None
    ):
        return self.copy_out(path, container)
    
    # def content_is_greater_than(
    #     self, 
    #     path: str,
    #     max_bytes_size: int,
    #     container: Container | None = None
    # ):
    #     if container is None:
    #         container = self.container
    #     if container is None:
    #         raise ValueError("Container invalide !")
    #     result = self._exec_command(f"wc -c {path}", container)
    #     if result[0] == 0:
    #         stdout = result[1]
    #         try:
    #             return int(stdout.replace(path, "")) > max_bytes_size
            
    #         except ValueError:
    #             return None
        
    #     return None
    
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
        if os.path.islink(file):
            logger.print(f"🚨 {file} est un lien symbolique — lecture refusée")
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
        if os.path.islink(file):
            logger.print(f"🚨 {file} est un lien symbolique — lecture refusée")
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