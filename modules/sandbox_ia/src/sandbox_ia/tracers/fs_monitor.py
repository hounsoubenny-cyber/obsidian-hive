#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May  9 07:25:06 2026

@author: hounsousamuel

Module de surveillance du filesystem pour le Sandbox ShieldAI V2.
Surveille en temps réel le filesystem du container Docker depuis l'hôte
via watchdog/inotify, détecte les accès aux fichiers honeypot (canary tokens)
et émet des événements structurés vers le behavior_scorer.

Architecture :
    FSMonitor
        └── SandboxFSHandler (FileSystemEventHandler)
                └── SandBoxQueue → behavior_scorer
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
import queue
from dataclasses import dataclass
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.events import (
    EVENT_TYPE_CLOSED, EVENT_TYPE_DELETED, EVENT_TYPE_MODIFIED, EVENT_TYPE_MOVED,
    EVENT_TYPE_CREATED, EVENT_TYPE_OPENED
)
from sandbox_ia.configs.fs_monitor_config import CANARY_PATHS, SUSPICIOUS_PATHS, SUSPICIOUS_EXTENSIONS
from sandbox_ia.sandbox_utils.logger import get_logger
logger = get_logger()

# ─────────────────────────────────────────────────────────────────────────────
# DATACLASS — Représentation d'un événement filesystem
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FSEvent:
    """
    Représente un événement filesystem détecté dans le container sandbox.

    Chaque accès, modification, création ou suppression de fichier dans
    le container génère un FSEvent qui circule dans la SandBoxQueue vers
    le behavior_scorer pour mise à jour du threat score.

    Attributes
    ----------
    timestamp_date : datetime
        Date et heure UTC de l'événement (pour les rapports).
    timestamp_time : float
        Timestamp Unix précis de l'événement (pour les calculs de délai).
    event_type : str
        Type d'événement watchdog parmi : "created", "modified",
        "deleted", "opened", "moved", "closed".
    path : str
        Chemin normalisé du fichier, sans le préfixe fs_root.
        Exemple : "/etc/passwd" au lieu de "/var/lib/docker/.../etc/passwd"
    src_path : str
        Chemin source brut retourné par watchdog (avec le préfixe fs_root).
    dest_path : str
        Chemin destination, uniquement rempli pour les événements "moved".
        Chaîne vide pour tous les autres types d'événements.
    is_directory : bool
        True si l'événement concerne un répertoire, False pour un fichier.
        Le threat_score est divisé par 2 pour les répertoires.
    is_canary : bool
        True si le fichier accédé est un fichier honeypot contenant
        des canary tokens. Déclenche une alerte critique.
    is_suspicious : bool
        True si le chemin correspond à un chemin système sensible.
        Déclenche une alerte moyenne.
    threat_score : int
        Score de menace de 0 à 100 calculé par _classify().
        Canary : +40, Suspicious : +15, Extension suspecte : +10.
        Divisé par 2 si is_directory.
    """
    timestamp_date: datetime
    timestamp_time: float
    event_type: str
    path: str
    src_path: str
    dest_path: str
    is_directory: bool
    is_canary: bool
    is_suspicious: bool
    threat_score: int
    
    def to_dict(self) -> dict:
        return {
            "timestamp_date": self.timestamp_date.isoformat(),
            "timestamp_time": self.timestamp_time,
            "event_type": self.event_type,
            "path": self.path,
            "src_path": self.src_path,
            "dest_path": self.dest_path,
            "is_directory": self.is_directory,
            "is_canary": self.is_canary,
            "is_suspicious": self.is_suspicious,
            "threat_score": self.threat_score,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "FSEvent":
        return cls(
            timestamp_date=datetime.fromisoformat(data["timestamp_date"]),
            timestamp_time=data["timestamp_time"],
            event_type=data["event_type"],
            path=data["path"],
            src_path=data["src_path"],
            dest_path=data["dest_path"],
            is_directory=data["is_directory"],
            is_canary=data["is_canary"],
            is_suspicious=data["is_suspicious"],
            threat_score=data["threat_score"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# SANDBOXQUEUE — File d'attente unifiée sync/async
# ─────────────────────────────────────────────────────────────────────────────

class SandBoxQueue:
    """
    Wrapper unifié autour de asyncio.Queue et queue.Queue.

    Permet à SandboxFSHandler (qui tourne dans le thread watchdog)
    de mettre des FSEvents dans une queue sans se soucier de son type.
    Les méthodes put/get délèguent directement aux versions nowait,
    ce qui garantit la compatibilité thread-safe avec asyncio.Queue
    (put_nowait et get_nowait sont des méthodes synchrones sur les deux types).

    Attributes
    ----------
    _queue : asyncio.Queue | queue.Queue
        La queue sous-jacente.
    _is_async_queue : bool
        True si la queue est une asyncio.Queue, False sinon.
    """

    def __init__(self, q: queue.Queue | asyncio.Queue):
        """
        Initialise le wrapper avec une queue existante.

        Parameters
        ----------
        q : queue.Queue | asyncio.Queue
            Queue à wrapper. Les deux types sont supportés.
        """
        self._queue = q
        self._is_async_queue = isinstance(self._queue, asyncio.Queue)

    def get(self, *args, **kwargs):
        """
        Récupère un élément de la queue sans bloquer.

        Délègue à get_nowait() — retourne None si la queue est vide
        au lieu de lever une exception, pour simplifier la consommation
        depuis un thread watchdog.

        Returns
        -------
        FSEvent | None
            Le prochain événement, ou None si la queue est vide.
        """
        try:
            return self.get_nowait()
        except Exception:
            return None

    def get_nowait(self):
        """
        Récupère immédiatement un élément sans bloquer.

        Lève queue.Empty ou asyncio.QueueEmpty si la queue est vide.

        Returns
        -------
        FSEvent
            Le prochain événement filesystem.

        Raises
        ------
        queue.Empty | asyncio.QueueEmpty
            Si la queue est vide.
        """
        return self._queue.get_nowait()

    def put(self, item):
        """
        Ajoute un élément dans la queue sans bloquer.

        Délègue à put_nowait() — silencieux si la queue est pleine
        pour éviter de bloquer le thread watchdog.

        Parameters
        ----------
        item : FSEvent
            L'événement filesystem à ajouter.
        """
        try:
            return self.put_nowait(item)
        except Exception:
            return

    def put_nowait(self, item):
        """
        Ajoute immédiatement un élément sans bloquer.

        Méthode principale utilisée par SandboxFSHandler depuis le thread
        watchdog. asyncio.Queue.put_nowait() est une méthode synchrone —
        elle est donc thread-safe et appelable depuis n'importe quel thread
        sans avoir besoin de run_coroutine_threadsafe.

        Parameters
        ----------
        item : FSEvent
            L'événement filesystem à ajouter.

        Raises
        ------
        queue.Full | asyncio.QueueFull
            Si la queue est pleine.
        """
        return self._queue.put_nowait(item)

    def __len__(self) -> int:
        """
        Retourne le nombre d'éléments actuellement dans la queue.

        Returns
        -------
        int
            Taille courante de la queue.
        """
        return self._queue.qsize()

    def task_done(self):
        """
        Signale qu'un élément récupéré a été traité.

        À appeler après chaque get() dans le behavior_scorer pour
        permettre à join() de débloquer quand tous les events sont traités.
        """
        self._queue.task_done()

    async def join(self, timeout: int = 30):
        """
        Attend que tous les éléments de la queue soient traités.

        Bloque jusqu'à ce que task_done() ait été appelé pour chaque
        élément mis dans la queue, ou jusqu'au timeout.

        Parameters
        ----------
        timeout : int, optional
            Nombre de secondes maximum à attendre. 30 par défaut.
            Si le timeout est atteint, retourne silencieusement.
        """
        if self._is_async_queue:
            task = asyncio.create_task(self._queue.join())
        else:
            task = asyncio.create_task(
                asyncio.to_thread(self._queue.join)
            )
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except Exception:
            return

    def empty(self) -> bool:
        """
        Vérifie si la queue est vide.

        Returns
        -------
        bool
            True si la queue ne contient aucun élément.
        """
        return self._queue.empty()

    def full(self) -> bool:
        """
        Vérifie si la queue est pleine.

        Returns
        -------
        bool
            True si la queue a atteint sa capacité maximale.
        """
        return self._queue.full()

    @property
    def maxsize(self) -> int:
        """
        Retourne la capacité maximale de la queue.

        Returns
        -------
        int
            Taille maximale. 0 signifie illimitée.
        """
        return self._queue.maxsize


# ─────────────────────────────────────────────────────────────────────────────
# HANDLER — Traitement des événements watchdog
# ─────────────────────────────────────────────────────────────────────────────

class SandboxFSHandler(FileSystemEventHandler):
    """
    Handler watchdog pour la surveillance du filesystem du container.

    Hérite de FileSystemEventHandler et surcharge les callbacks on_*
    pour intercepter tous les événements filesystem du container sandbox.
    Chaque événement est normalisé, classifié et transformé en FSEvent
    avant d'être mis dans la SandBoxQueue vers le behavior_scorer.

    Ce handler tourne dans le thread interne de watchdog/Observer —
    il ne doit donc jamais faire d'opérations bloquantes longues.

    Attributes
    ----------
    fs_root : str
        Chemin vers le filesystem mergé du container sur l'hôte.
        Obtenu via ContainerManager.get_fs_root().
        Exemple : "/var/lib/docker/overlay2/abc123.../merged"
    event_queue : SandBoxQueue
        Queue vers laquelle les FSEvents sont envoyés pour traitement
        par le behavior_scorer.
    """

    def __init__(
        self, 
        fs_root: str, 
        event_queue: SandBoxQueue,
        canary_paths: list[str] | None = None,
        suspicious_paths: list[str] | None = None,
        suspicious_extensions: list[str] | None = None,
    ):
        """
        Initialise le handler avec le filesystem root et la queue.

        Parameters
        ----------
        fs_root : str
            Chemin absolu du filesystem mergé du container.
            Le slash final est retiré pour faciliter les opérations
            de normalisation des chemins.
        event_queue : SandBoxQueue
            Queue de destination pour les FSEvents produits.
        """
        super().__init__()
        self.fs_root = fs_root.rstrip("/")
        self.event_queue = event_queue
        self.canary_paths = canary_paths or CANARY_PATHS
        self.suspicious_paths = suspicious_paths or SUSPICIOUS_PATHS
        self.suspicious_extensions = suspicious_extensions or SUSPICIOUS_EXTENSIONS

    def _normalize_path(self, raw_path: str) -> str:
        """
        Normalise un chemin brut watchdog en chemin interne au container.

        Retire le préfixe fs_root du chemin pour obtenir le chemin
        tel qu'il serait vu depuis l'intérieur du container.

        Exemple :
            fs_root  = "/var/lib/docker/overlay2/abc.../merged"
            raw_path = "/var/lib/docker/overlay2/abc.../merged/etc/passwd"
            résultat = "/etc/passwd"

        Le rstrip("/") sur fs_root est crucial : sans lui, le replace
        laisserait un slash résiduel ou ne fonctionnerait pas si le
        chemin ne se termine pas exactement par fs_root.

        Parameters
        ----------
        raw_path : str
            Chemin brut retourné par watchdog, incluant le préfixe fs_root.

        Returns
        -------
        str
            Chemin normalisé depuis la racine du container.
            Retourne "/" si le résultat est vide (événement sur fs_root lui-même).
        """
        return raw_path.replace(self.fs_root, "") or "/"

    def _classify(
        self,
        path: str,
        is_directory: bool = False,
        n_max: int = 2,
        is_normalized: bool = False
    ) -> tuple[bool, bool, int]:
        """
        Classifie un chemin et calcule son threat score.

        Vérifie le chemin contre les listes CANARY_PATHS et SUSPICIOUS_PATHS,
        ainsi que l'extension du fichier contre SUSPICIOUS_EXTENSIONS.
        Limite le nombre de matches via n_max pour éviter le sur-scoring
        sur des chemins qui correspondraient à de nombreux patterns.

        Scoring :
            - Chaque match canary    : +40 points
            - Chaque match suspicious : +15 points
            - Extension suspecte     : +10 points
            - Score final plafonné à 100
            - Divisé par 2 (division entière) si is_directory

        Parameters
        ----------
        path : str
            Chemin à classifier. Peut être brut ou normalisé selon is_normalized.
        is_directory : bool, optional
            True si le chemin est un répertoire. Le score final est divisé
            par 2 car un accès à un dossier est moins précis qu'un accès
            à un fichier spécifique. False par défaut.
        n_max : int, optional
            Nombre maximum de matches autorisés par liste (canary/suspicious).
            Évite le sur-scoring si un chemin matche plusieurs patterns.
            2 par défaut.
        is_normalized : bool, optional
            True si le chemin est déjà normalisé (sans préfixe fs_root).
            False par défaut → _normalize_path() est appelé automatiquement.

        Returns
        -------
        tuple[bool, bool, int]
            - bool : is_canary — True si un canary path a été matché
            - bool : is_suspicious — True si un suspicious path a été matché
            - int  : threat_score — Score entre 0 et 100
        """
        score = 0
        is_canary = False
        is_suspicious = False

        if not is_normalized:
            path = self._normalize_path(path)

        find_count = 0
        for canary in self.canary_paths:
            if canary in path:
                is_canary = True
                score += 40
                find_count += 1
                if find_count >= n_max:
                    break

        find_count = 0
        for suspicious in self.suspicious_paths:
            if suspicious in path:
                is_suspicious = True
                score += 15
                find_count += 1
                if find_count >= n_max:
                    break

        ext = os.path.splitext(path)[1].lower()
        if ext in self.suspicious_extensions:
            score += 10

        return is_canary, is_suspicious, min(score, 100) if not is_directory else min(score, 100) // 2

    def _build_event(
        self,
        src_path: str,
        dest_path: str,
        path: str,
        threat_score: int,
        is_directory: bool,
        is_canary: bool,
        is_suspicious: bool,
        timestamp_date: datetime,
        timestamp_time: float,
        event_type: str
    ) -> FSEvent:
        """
        Construit un FSEvent structuré depuis les données classifiées.

        Centralise la construction du dataclass FSEvent pour garantir
        que tous les champs sont correctement remplis.

        Parameters
        ----------
        src_path : str
            Chemin source brut (avec préfixe fs_root).
        dest_path : str
            Chemin destination (uniquement pour les événements "moved").
        path : str
            Chemin normalisé (sans préfixe fs_root).
        threat_score : int
            Score de menace calculé par _classify().
        is_directory : bool
            True si l'événement concerne un répertoire.
        is_canary : bool
            True si un fichier honeypot a été accédé.
        is_suspicious : bool
            True si un chemin sensible a été accédé.
        timestamp_date : datetime
            Horodatage UTC de l'événement.
        timestamp_time : float
            Timestamp Unix de l'événement.
        event_type : str
            Type d'événement watchdog.

        Returns
        -------
        FSEvent
            Événement filesystem structuré prêt pour la queue.
        """
        return FSEvent(
            src_path=src_path,
            dest_path=dest_path,
            threat_score=threat_score,
            is_canary=is_canary,
            is_directory=is_directory,
            is_suspicious=is_suspicious,
            timestamp_date=timestamp_date,
            timestamp_time=timestamp_time,
            path=path,
            event_type=event_type
        )

    def _handle(
        self,
        watchdog_event: FileSystemEvent,
        event_type: str,
        add_to_queue: bool = True
    ) -> tuple[FSEvent, bool]:
        """
        Méthode centrale de traitement des événements watchdog.

        Appelée par tous les callbacks on_* — regroupe la normalisation,
        la classification, la construction et l'envoi en queue en une
        seule pipeline cohérente.

        Gère la conversion bytes → str sur src_path et dest_path car
        watchdog peut retourner des bytes ou des str selon l'OS et
        la version de la bibliothèque.

        Parameters
        ----------
        watchdog_event : FileSystemEvent
            Événement brut retourné par watchdog.
        event_type : str
            Type d'événement. Utilise watchdog_event.event_type si vide.
        add_to_queue : bool, optional
            Si True, le FSEvent est mis dans event_queue via put_nowait.
            Si False, l'événement est construit mais pas envoyé — utile
            pour les tests ou l'analyse sans surveillance active.
            True par défaut.

        Returns
        -------
        tuple[FSEvent, bool]
            - FSEvent : l'événement construit
            - bool    : True si mis en queue avec succès, False sinon
                        (queue pleine ou add_to_queue=False)
        """
        src_path = (
            watchdog_event.src_path
            if isinstance(watchdog_event.src_path, str)
            else watchdog_event.src_path.decode()
        )
        dest_path = (
            watchdog_event.dest_path
            if isinstance(watchdog_event.dest_path, str)
            else watchdog_event.dest_path.decode()
        )
        path = self._normalize_path(src_path)
        event_type = event_type or watchdog_event.event_type
        is_directory = watchdog_event.is_directory

        is_canary, is_suspicious, threat_score = self._classify(
            path, is_directory=is_directory, is_normalized=True, n_max=3
        )

        timestamp_date = datetime.utcnow()
        timestamp_time = time.time()

        sd_event = self._build_event(
            src_path=src_path,
            dest_path=dest_path,
            threat_score=threat_score,
            is_canary=is_canary,
            is_directory=is_directory,
            is_suspicious=is_suspicious,
            timestamp_date=timestamp_date,
            timestamp_time=timestamp_time,
            path=path,
            event_type=event_type
        )
        
        # print("[fs_monitor]", sd_event, "\n\n")
        if add_to_queue and sd_event is not None:
            try:
                self.event_queue.put_nowait(sd_event)
                return sd_event, True
            except Exception:
                return sd_event, False

        return sd_event, True

    def on_created(self, event: FileSystemEvent):
        """
        Callback déclenché quand un fichier ou répertoire est créé.

        Indique qu'un nouveau fichier a été créé dans le container.
        Particulièrement intéressant pour détecter :
        - Création de scripts de persistence (.sh, .py...)
        - Création de fichiers de staging pour exfiltration
        - Création de répertoires cachés (/tmp/.hidden/)

        Parameters
        ----------
        event : FileSystemEvent
            Événement watchdog de type FileCreatedEvent ou DirCreatedEvent.
        """
        self._handle(event, event.event_type, add_to_queue=True)

    def on_modified(self, event: FileSystemEvent):
        """
        Callback déclenché quand un fichier ou répertoire est modifié.

        Indique qu'un fichier existant a été modifié dans le container.
        Particulièrement intéressant pour détecter :
        - Modification de fichiers système (/etc/crontab → persistence)
        - Modification de fichiers de config (injection de backdoor)

        Parameters
        ----------
        event : FileSystemEvent
            Événement watchdog de type FileModifiedEvent ou DirModifiedEvent.
        """
        self._handle(event, event.event_type, add_to_queue=True)

    def on_deleted(self, event: FileSystemEvent):
        """
        Callback déclenché quand un fichier ou répertoire est supprimé.

        Indique qu'un fichier a été supprimé dans le container.
        Particulièrement intéressant pour détecter :
        - Suppression de logs pour couvrir les traces
        - Suppression de fichiers système critiques

        Parameters
        ----------
        event : FileSystemEvent
            Événement watchdog de type FileDeletedEvent ou DirDeletedEvent.
        """
        self._handle(event, event.event_type, add_to_queue=True)

    def on_opened(self, event: FileSystemEvent):
        """
        Callback déclenché quand un fichier est ouvert en lecture.

        Linux uniquement — utilise inotify IN_OPEN sous le capot.
        C'est le callback le plus important pour ShieldAI car il détecte
        les lectures de fichiers canary avant même que le code ait pu
        exfiltrer le contenu.

        Particulièrement intéressant pour détecter :
        - Lecture de /etc/shadow (credential harvesting)
        - Lecture de clés SSH (exfiltration)
        - Lecture de fichiers .env (credential harvesting)

        Parameters
        ----------
        event : FileSystemEvent
            Événement watchdog de type FileOpenedEvent.
        """
        self._handle(event, event.event_type, add_to_queue=True)

    def on_moved(self, event: FileSystemEvent):
        """
        Callback déclenché quand un fichier ou répertoire est déplacé.

        Seul callback où dest_path est rempli dans le FSEvent.
        Particulièrement intéressant pour détecter :
        - Renommage de binaires malveillants pour éviter la détection
        - Déplacement de fichiers exfiltrés vers /tmp/

        Parameters
        ----------
        event : FileSystemEvent
            Événement watchdog de type FileMovedEvent ou DirMovedEvent.
            Contient src_path (origine) et dest_path (destination).
        """
        self._handle(event, event.event_type, add_to_queue=True)


# ─────────────────────────────────────────────────────────────────────────────
# FSMONITOR — Orchestrateur de la surveillance
# ─────────────────────────────────────────────────────────────────────────────

class FSMonitor:
    """
    Orchestrateur principal de la surveillance filesystem du container.

    Lance et gère un Observer watchdog qui surveille récursivement
    le filesystem du container depuis l'hôte. Expose des méthodes
    sync et async pour s'intégrer proprement dans l'orchestrateur
    du sandbox.

    L'Observer tourne dans son propre thread daemon — il s'arrête
    automatiquement si le process principal se termine.

    Attributes
    ----------
    fs_root : str
        Chemin vers le filesystem mergé du container sur l'hôte.
    event_queue : asyncio.Queue
        Queue de destination pour les FSEvents produits par le handler.
    observer : Observer
        Thread Observer watchdog interne.
    handler : SandboxFSHandler
        Handler de traitement des événements filesystem.
    """

    def __init__(
        self, 
        fs_root: str, 
        event_queue: asyncio.Queue,
        canary_paths: list[str] | None = None,
        suspicious_paths: list[str] | None = None,
        suspicious_extensions: list[str] | None = None,
    ):
        """
        Initialise le moniteur avec le filesystem root et la queue.

        Parameters
        ----------
        fs_root : str
            Chemin absolu du filesystem mergé du container.
            Obtenu via ContainerManager.get_fs_root().
        event_queue : asyncio.Queue
            Queue asyncio vers laquelle les FSEvents seront envoyés.
            Consommée par le behavior_scorer dans l'event loop principal.
        """
        self.fs_root = fs_root.rstrip("/")
        self.event_queue = event_queue
        self.observer = Observer()
        self.handler = SandboxFSHandler(
            fs_root, event_queue,
            canary_paths=canary_paths,
            suspicious_paths=suspicious_paths,
            suspicious_extensions=suspicious_extensions    
        )

    @property
    def name(self) -> str:
        """
        Retourne le nom du thread Observer.

        Returns
        -------
        str
            Nom du thread watchdog.
        """
        return self.observer.name

    @property
    def native_id(self):
        """
        Retourne l'identifiant natif du thread Observer.

        Returns
        -------
        int | None
            ID natif du thread, ou None si pas encore démarré.
        """
        return self.observer.native_id

    def is_alive(self) -> bool:
        """
        Vérifie si le thread Observer est actif.

        Returns
        -------
        bool
            True si l'Observer tourne, False sinon.
        """
        return self.observer.is_alive()

    def isDaemon(self) -> bool:
        """
        Vérifie si le thread Observer est en mode daemon.

        Un thread daemon s'arrête automatiquement quand le process
        principal se termine, sans bloquer la fin du programme.

        Returns
        -------
        bool
            True si l'Observer est un thread daemon.
        """
        return self.observer.isDaemon()

    def start(self) -> bool:
        """
        Démarre la surveillance filesystem (version synchrone).

        Configure et lance l'Observer watchdog sur le filesystem du container.
        La surveillance est récursive — tous les sous-répertoires sont inclus.
        Le thread Observer est configuré en mode daemon pour ne pas bloquer
        la fin du programme.

        Returns
        -------
        bool
            True si le démarrage a réussi.
        """
        self.observer.schedule(
            event_handler=self.handler,
            path=self.fs_root,
            recursive=True,
        )
        self.observer.daemon = True
        self.observer.name = "ShieldAI SandBox File System scheduler"
        self.observer.start()
        logger.print(f"👁️  FSMonitor démarré sur {self.fs_root}")
        return True

    def stop(self, timeout: int | None = 30) -> bool:
        """
        Arrête la surveillance filesystem (version synchrone).

        Envoie le signal d'arrêt à l'Observer et attend qu'il termine
        proprement via join(). Le timeout évite un blocage infini si
        l'Observer ne répond plus.

        Parameters
        ----------
        timeout : int | None, optional
            Secondes maximum à attendre pour l'arrêt propre. 30 par défaut.
            None = attendre indéfiniment.

        Returns
        -------
        bool
            True si l'arrêt a réussi.
        """
        self.observer.stop()
        self.observer.join(timeout=timeout)
        logger.print("🛑 FSMonitor arrêté")
        return True

    async def start_async(self) -> bool:
        """
        Démarre la surveillance filesystem (version asynchrone).

        Délègue start() à un thread via asyncio.to_thread pour ne pas
        bloquer l'event loop pendant l'initialisation de l'Observer.

        Returns
        -------
        bool
            True si le démarrage a réussi.
        """
        return await asyncio.to_thread(self.start)

    async def stop_async(self, timeout: int | None = 30) -> bool:
        """
        Arrête la surveillance filesystem (version asynchrone).

        Délègue stop() à un thread via asyncio.to_thread pour ne pas
        bloquer l'event loop pendant l'attente du join() de l'Observer.

        Parameters
        ----------
        timeout : int | None, optional
            Secondes maximum à attendre pour l'arrêt propre. 30 par défaut.

        Returns
        -------
        bool
            True si l'arrêt a réussi.
        """
        return await asyncio.to_thread(self.stop, timeout)