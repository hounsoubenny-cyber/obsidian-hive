#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 21 10:53:41 2026

@author: hounsousamuel

Module WorkSpace — orchestration haut-niveau d'un sandbox de travail pour
l'agent Analyst (Alex). Fait le lien entre le filesystem hôte (le code
original de l'utilisateur) et un container Docker isolé (via ContainerManager)
où Alex lit, édite et exécute du code.

Cycle de vie typique :
    1. copy_in()   → copie un fichier/dossier hôte dans un "slot" du sandbox
    2. exec_*()    → exécute des commandes (tests, scripts...) dans le sandbox
    3. str_replace()→ édite un fichier du sandbox
    4. export()    → recopie les modifications du sandbox vers l'hôte, calcule
                      le diff, et retourne un rapport structuré par slot

Filtrage ignore_dirs / ignore_files
------------------------------------
Le sandbox exécute potentiellement des tests, installe des dépendances, etc.
Cela génère des artefacts (`__pycache__`, `.pytest_cache`, `node_modules`...)
qui n'ont jamais été écrits intentionnellement par Alex. Sans filtrage, ces
artefacts :
    - polluent le rapport final (faux "new_file" / "modified" dans le diff)
    - risquent d'écraser le vrai `.git` (ou autre) du projet hôte lors du
      dernier `copy()` de `_export_slot` (sandbox -> original_path)

`ignore_dirs`/`ignore_files` (config `WorkspaceConfig`) sont donc appliqués à
trois endroits :
    1. copy_in()      : ne pas envoyer ces dossiers/fichiers DANS le sandbox
    2. _export_slot() : ne pas les compter dans le diff/report (list_files filtré)
    3. _export_slot() : ne pas les recopier par-dessus original_path (copie finale)
"""

import os
import docker
import shutil
import hashlib
import asyncio
import fnmatch
import tempfile
from uuid import uuid4
from typing import Callable
from dataclasses import dataclass, fields
from sandbox_ia.core.container_manager import ContainerManager
from modules_utils.agent_utils import (
    _validate_path, _compute_diff
)
from modules_utils.loop_utils import _run_async
from modules_utils.text_edit import (
    TextEditError, apply_str_replace, numbered_context
)

# ─────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────────────

# Dossiers ignorés PAR DÉFAUT (VCS, dépendances, caches de build/test, IDE...).
# Comparés au NOM du dossier (pas au chemin complet) via fnmatch, donc les
# motifs avec '*' fonctionnent aussi (ex: '*.egg-info').
#
# Volontairement PAS de dist/build/target/.next/... ici : contrairement à
# .git ou node_modules (toujours généré/vendorisé, jamais du code source),
# un dossier "build" ou "dist" peut être committé volontairement (artefacts
# de release, site statique) et contenir du code (minifié/bundlé) avec de
# vraies vulnérabilités qu'Alex doit justement pouvoir analyser. Les
# ignorer par défaut risquerait de cacher du code à un outil de sécurité.
# Voir OPTIONAL_BUILD_IGNORE_DIRS pour les activer explicitement projet par
# projet si on SAIT que c'est bien du généré à ignorer.
DEFAULT_IGNORE_DIRS = (
    # VCS
    ".git", ".hg", ".svn",
    # Python
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".venv", "venv", ".eggs", "*.egg-info",
    # JS / Node (dépendances, jamais du code écrit à la main)
    "node_modules",
    # IDE / OS
    ".idea", ".vscode", "__MACOSX", ".ipynb_checkpoints",
    # Infra as code (état/cache d'outillage, pas du code applicatif)
    ".terraform", ".serverless",
)

# Dossiers de sortie de build — À N'AJOUTER qu'explicitement à
# `WorkspaceConfig.ignore_dirs` (via from_dict/override) pour un projet où
# l'on est certain que ce contenu est généré et sans intérêt pour l'analyse.
OPTIONAL_BUILD_IGNORE_DIRS = (
    "dist", "build", "target", ".cache",
    ".next", ".nuxt", ".parcel-cache", ".turbo", ".gradle",
)

# Fichiers ignorés (bytecode compilé, logs, temporaires, fichiers OS...).
DEFAULT_IGNORE_FILES = (
    "*.pyc", "*.pyo", "*.pyd",
    ".coverage", ".coverage.*",
    ".DS_Store", "Thumbs.db",
    "*.log", "*.tmp", "*.swp", "*.swo",
    "*.class", "*.o", "*.so", "*.dylib", "*.dll",
    "*.bak", "*.orig",
)

_FALLBACK_IMAGE = "shieldai-sandbox:v2-light"

PROXY_IMAGE: str = "analyst-proxy:latest"
PROXY_CONTAINER_NAME: str = f"analyst-proxy_{str(uuid4())}"
PROXY_CONF_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "analyst_proxy", "analyst_proxy_squid.conf"
    )
)
if not os.path.exists(PROXY_CONF_FILE):
    raise RuntimeError(
        "The proxy config file is missing"
    )


# ─────────────────────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────────────────────

class WorkSpaceError(Exception):
    """Erreur "attendue" du workspace (message destiné à l'agent, jamais de stack trace)."""


# ─────────────────────────────────────────────────────────────────────────
# HELPERS MODULE-LEVEL
# ─────────────────────────────────────────────────────────────────────────

def _default_image() -> str:
    """Retourne l'image Docker par défaut du sandbox (config centrale si
    disponible, sinon fallback statique)."""
    try:
        from sandbox_ia.configs.orchestrator_config import DEFAULT_SANDBOX_IMAGE
        return DEFAULT_SANDBOX_IMAGE
    except Exception:
        return _FALLBACK_IMAGE


def sha256_of_file(path: str) -> str | None:
    """Hash SHA-256 d'un fichier, lu par chunks (pas de gros fichier en RAM
    d'un coup). Retourne None si le fichier est illisible."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def read(path: str, binary: bool = False):
    """Lecture complète d'un fichier par chunks. Retourne str ou bytes
    selon `binary`."""
    default = b"" if binary else ""
    mode = "rb" if binary else "r"
    content = default
    with open(path, mode) as f:
        for chunk in iter(lambda: f.read(8192), default):
            content += chunk
    return content


def _name_matches(name: str, patterns: tuple[str, ...]) -> bool:
    """True si `name` (un simple nom de fichier/dossier, pas un chemin)
    correspond à un des motifs glob fournis."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _relpath_is_ignored(
    relpath: str, ignore_dirs: tuple[str, ...], ignore_files: tuple[str, ...]
) -> bool:
    """True si un chemin relatif (fichier) doit être ignoré : soit un de ses
    dossiers parents matche `ignore_dirs`, soit son nom de fichier matche
    `ignore_files`."""
    parts = relpath.replace("\\", "/").split("/")
    *dir_parts, filename = parts
    if any(_name_matches(part, ignore_dirs) for part in dir_parts):
        return True
    return _name_matches(filename, ignore_files)


# ─────────────────────────────────────────────────────────────────────────
# CONFIG & MODELES
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class WorkspaceConfig:
    """Configuration d'un WorkSpace : ressources du container, réseau,
    limites, et motifs de fichiers à ignorer lors des copies."""

    image_name: str = _default_image()
    mem_limit: str = "512m"
    cpu_quota: int = 100_000
    cpu_period: int = 100_000
    pids_limit: int = 256
    exec_user: str = "0:0"  # root
    workdir: str = "/work"
    exec_timeout: int = 30
    max_exec_timeout: int = 600
    max_file_bytes: int = 5 * 1024 * 1024  # fichier plus gros : ignoré (copy_in) / refusé (export)
    network: str = "proxy"
    docker_network: str = "workspace_internal"  # réseau Docker `internal: true` (proxy uniquement)
    ignore_dirs: tuple = DEFAULT_IGNORE_DIRS
    ignore_files: tuple = DEFAULT_IGNORE_FILES

    def __post_init__(self):
        if self.network not in ("none", "proxy"):
            raise WorkSpaceError("network doit valoir 'none' ou 'proxy'")
        self.ignore_dirs = tuple(self.ignore_dirs)
        self.ignore_files = tuple(self.ignore_files)

    @property
    def proxy_url(self):
        return f"http://{PROXY_CONTAINER_NAME}:8888"

    @classmethod
    def from_dict(cls, data: dict | None) -> "WorkspaceConfig":
        data = dict(data or {})
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:  # une faute de frappe dans la config ne doit pas passer en silence
            raise WorkSpaceError(f"Clés de config workspace inconnues : {sorted(unknown)}")
        return cls(**data)


@dataclass
class Slot:
    """Un slot = un fichier ou dossier copié dans le sandbox, avec ses
    hashs SHA-256 d'origine (base de comparaison pour le diff à l'export)."""

    key: str
    name: str
    is_dir: bool
    original_path: str
    path_in_container: str
    path_on_host: str
    hashs: dict[str, str]
    ext: str | None = None

    def to_dict(self, exlude: list[str] | None = None):
        to_return = {
            "key": self.key,
            "name": self.name,
            "is_dir": self.is_dir,
            "original_path": self.original_path,
            "path_on_host": self.path_on_host,
            "path_in_container": self.path_in_container,
            "hashs": self.hashs,
        }
        return (
            to_return if not exlude
            else {k: v for k, v in to_return.items() if k not in exlude}
        )


# ─────────────────────────────────────────────────────────────────────────
# WORKSPACE
# ─────────────────────────────────────────────────────────────────────────

class WorkSpace:
    """
    Orchestre un container sandbox pour l'agent Alex : copie de fichiers,
    exécution de commandes, édition, export des modifications vers l'hôte.

    Un WorkSpace peut gérer plusieurs "slots" simultanément (plusieurs
    fichiers/dossiers copiés dans le même container).
    """

    INTERNAL_WORKDIR_PREFIX: str = "ob-agent-workspace-"
    WORKSPACE_COPY_PREFIX: str = "subworkspace-"
    PROXY_CONTAINER: docker.models.containers.Container | None = None

    # ─────────────────────────────────────────────────────────────
    # CONSTRUCTION
    # ─────────────────────────────────────────────────────────────

    def __init__(
        self,
        config: Callable | WorkspaceConfig,
        manager: Callable | ContainerManager,
    ):
        try:
            self.manager: ContainerManager = (
                manager() if callable(manager) else manager
            )
            if not isinstance(self.manager, ContainerManager):
                raise RuntimeError("Manager should be instance or callable that return ContainerManager instance")
        except Exception as e:
            raise RuntimeError(*e.args)

        try:
            self.config: WorkspaceConfig = (
                config() if callable(config) else config
            )
            if not isinstance(self.config, WorkspaceConfig):
                raise RuntimeError("Config should be instance or callable that return WorkspaceConfig instance")
        except Exception as e:
            raise RuntimeError(*e.args)

        self.internal_workdir: str = tempfile.mkdtemp(prefix=self.INTERNAL_WORKDIR_PREFIX)
        self._exported: bool = False
        self._closed: bool = False
        self.base_name: str = f"workspace_{str(uuid4())}"
        self._generation = 0
        self._started = False
        self._slots: dict[str, Slot] = {}
        self.lock = asyncio.Lock()

    # ─────────────────────────────────────────────────────────────
    # ÉTAT / GARDE-FOUS
    # ─────────────────────────────────────────────────────────────

    def close(self):
        self._closed = True

    def check_open(self):
        if self._closed:
            raise WorkSpaceError("Workspace fermé")

    def timeout_is_valid(self, timeout: int | float | None):
        return (
            timeout is not None and timeout > 0
            and timeout <= self.config.max_exec_timeout
        )

    def generate_name(self):
        return f"{self.base_name}_gen-{self._generation}"

    def up_generation(self):
        self._generation += 1

    @property
    def slots(self) -> dict[str, Slot]:
        return dict(self._slots)

    def slot_exists(self, key):
        return key in self._slots

    def is_copied_in(self, key: str):
        return self.slot_exists(key)

    def list_slots(self):
        return {k: v.to_dict() for k, v in list(self._slots.items())}

    # ─────────────────────────────────────────────────────────────
    # RÉSEAU / PROXY
    # ─────────────────────────────────────────────────────────────

    def _network_env(self) -> dict:
        """Variables d'environnement proxy à injecter dans le container si
        network == 'proxy' (aucun accès réseau direct pour Alex)."""
        if self.config.network != "proxy":
            return {}
        u = self.config.proxy_url
        return {
            "HTTP_PROXY": u, "HTTPS_PROXY": u, "http_proxy": u, "https_proxy": u,
            "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1",
        }
    
    def _cleanup_orphan_proxies(self, prefix: str = "analyst-proxy_"):
        """Supprime les conteneurs proxy orphelins d'un process précédent
        qui aurait crashé sans passer par kill_proxy_container (sinon ils
        s'accumulent indéfiniment, un par crash — voir PROXY_CONTAINER_NAME
        qui change à chaque démarrage du process).
        """
        for c in self.manager.client.containers.list(all=True):
            if c.name.startswith(prefix) and c.name != PROXY_CONTAINER_NAME:
                try:
                    c.stop(timeout=5)
                except Exception:
                    pass
                try:
                    c.remove(force=True)
                    print(f"🧹 Proxy orphelin supprimé : {c.name}")
                except Exception as e:
                    print(f"⚠️ Impossible de supprimer le proxy orphelin {c.name} : {e}")

    def reload_proxy_allowlist(self, proxy_name: str = PROXY_CONTAINER_NAME) -> bool:
        """Recharge la config Squid à chaud après modification du fichier
        monté en volume — pas de redémarrage de conteneur nécessaire.
        """
        try:
            proxy = self.manager.client.containers.get(proxy_name)
        except docker.errors.NotFound:
            return False
        exit_code, _ = proxy.exec_run("squid -k reconfigure")
        return exit_code == 0


    def ensure_network(self, name: str = "workspace_internal") -> None:
        """Crée le réseau Docker interne s'il n'existe pas déjà (idempotent).

        internal=True : aucune route vers internet pour les conteneurs
        connectés à ce réseau — seul un conteneur avec une patte sur un
        AUTRE réseau (le proxy) peut faire le pont vers l'extérieur.
        """
        existing = self.manager.client.networks.list(names=[name])
        if existing:
            return
        self.manager.client.networks.create(name, driver="bridge", internal=True)
        print(f"🌐 Réseau '{name}' créé (internal=True)")

    def ensure_analyst_proxy(
        self,
        proxy_image: str = PROXY_IMAGE,
        proxy_name: str = "analyst-proxy",
        internal_network: str = "workspace_internal",
        egress_network: str = "bridge",
    ) -> None:
        """Démarre le conteneur proxy s'il n'est pas déjà en cours d'exécution
        (idempotent — appelable à chaque démarrage d'un WorkSpace sans risque).

        Le proxy a DEUX pattes réseau : `internal_network` (pour parler aux
        conteneurs Alex) et `egress_network` (pour vraiment sortir sur
        internet). Aucun conteneur Alex n'est jamais connecté à `egress_network`.
        """
        self.ensure_network(internal_network)
        self._cleanup_orphan_proxies()
        try:
            existing = self.manager.client.containers.get(proxy_name)
            if existing.status == "running":
                WorkSpace.set_proxy_container(existing)
                return
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass

        container = self.manager.client.containers.run(
            proxy_image,
            name=proxy_name,
            network=internal_network,
            detach=True,
            restart_policy={"Name": "unless-stopped"},
        )
        WorkSpace.set_proxy_container(container)
        # deuxième patte réseau : vers l'extérieur
        self.manager.client.networks.get(egress_network).connect(container)
        print(f"🧭 Proxy '{proxy_name}' démarré ({internal_network} + {egress_network})")

    @classmethod
    def set_proxy_container(cls, container):
        cls.PROXY_CONTAINER = container

    @classmethod
    def kill_proxy_container(cls):
        if cls.PROXY_CONTAINER:
            try:
                cls.PROXY_CONTAINER.stop(timeout=5)
                cls.PROXY_CONTAINER.remove(force=True)
                print("✅ Container proxy arrêté et supprimé")
            except Exception as e:
                print(f"⚠️ Erreur stop proxy: {e}")
            cls.PROXY_CONTAINER = None
        return

    @classmethod
    async def kill_proxy_container_async(cls):
        return await asyncio.to_thread(cls.kill_proxy_container)

    # ─────────────────────────────────────────────────────────────
    # CYCLE DE VIE DU CONTAINER
    # ─────────────────────────────────────────────────────────────

    def start_container(self):
        """Démarre (ou relance) le container sandbox pour ce WorkSpace,
        avec les capabilities Linux nécessaires à Alex (voir cap_add ci-dessous)."""
        if self.config.network == "proxy":
            self.ensure_analyst_proxy(
                internal_network=self.config.docker_network,
                proxy_image=PROXY_IMAGE,
                proxy_name=PROXY_CONTAINER_NAME,
            )

        env = {
            "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "HOME": "/root",  # séparé du workdir exporté : aucun cache/dotfile
                       # ne peut polluer le diff ou écraser le repo hôte
        }
        env.update(self._network_env())

        kwargs = self.manager.get_kwargs_for_container(
            network_disabled=(self.config.network == "none"),
            mem_limit=self.config.mem_limit,
            cpu_quota=self.config.cpu_quota,
            cpu_period=self.config.cpu_period,
            pids_limit=self.config.pids_limit,
            read_only=False,
            user=self.config.exec_user,
            extra_env=env,
            workdir=self.config.workdir,
        )
        # Capabilities Alex : DAC_OVERRIDE/CHOWN/FOWNER pour éditer des
        # fichiers copiés depuis l'hôte (uid différent), SETUID/SETGID pour
        # les outils de test/build qui changent temporairement d'utilisateur,
        # SYS_PTRACE pour le traceur strace, SYS_RESOURCE/NET_BIND_SERVICE
        # en confort pour certains runners. Alex tourne en root dans SON
        # propre container isolé (network proxy/none) — pas dans le sandbox
        # d'exécution de code externe/suspect, qui reste beaucoup plus strict.
        kwargs["cap_add"] = [
            "SYS_PTRACE", "CAP_SETGID", "FOWNER",
            "CAP_SETUID", "DAC_OVERRIDE", "CHOWN",
            "CAP_SYS_RESOURCE", "CAP_NET_BIND_SERVICE",
        ]
        kwargs.pop("volumes", None)
        if self.config.network == "proxy":
            kwargs["network"] = self.config.docker_network

        name = self.generate_name()
        try:
            self.manager.connect(self.config.image_name or _default_image(), name, **kwargs)
        except Exception as e:
            raise WorkSpaceError(f"Impossible de démarrer le container : {e!r}")

        self.up_generation()
        self._started = True
        return True

    def _ensure_container(self):
        self.reload_proxy_allowlist(PROXY_CONTAINER_NAME)
        if self._started:
            return
        self.start_container()

    def kill(self):
        """Tue le container sans nettoyer les slots ni le dossier interne
        (utilisé en interne par stop())."""
        if self.manager is not None:
            try:
                self.manager.stop()
            except Exception:
                pass
            try:
                self.manager.container = None
            except Exception:
                pass
        self._started = False

    def reset(self):
        """Supprime tous les slots actifs (et leur contenu dans le container),
        sans arrêter le container lui-même."""
        if not self._slots:
            self._exported = False
            return
        self._ensure_container()
        for slot in list(self.slots.values()):
            self.delete_slot(slot)
        self._exported = False

    def stop(self):
        """Arrêt complet et nettoyage : slots, container, dossier interne."""
        self.reset()
        self.kill()
        self.rm_internal_wordir(force=True)

    def rm_internal_wordir(self, force: bool = False):
        if not force and not self._exported:
            raise RuntimeError("Can't remove internal workspace dir, call export before even if no file are modified")
        shutil.rmtree(self.internal_workdir, ignore_errors=True)
        self.close()
        return True

    # ─────────────────────────────────────────────────────────────
    # HELPERS FILESYSTEM (hôte) — copie brute + filtrage ignore_*
    # ─────────────────────────────────────────────────────────────

    def _ignore_callback(self) -> Callable[[str, list[str]], set[str]]:
        """Construit le callback `ignore` attendu par `shutil.copytree` à
        partir de `config.ignore_dirs` + `config.ignore_files`. Le callback
        reçoit (dossier_courant, noms_enfants) et retourne l'ensemble des
        noms à NE PAS copier — c'est le contrat standard `shutil`."""
        patterns = self.config.ignore_dirs + self.config.ignore_files

        def _ignore(_directory: str, names: list[str]) -> set[str]:
            return {n for n in names if _name_matches(n, patterns)}

        return _ignore

    def _is_relpath_ignored(self, relpath: str) -> bool:
        """Version "chemin relatif complet" du filtre, utilisée pour exclure
        des entrées déjà listées (ex: résultat de `list_files`)."""
        return _relpath_is_ignored(relpath, self.config.ignore_dirs, self.config.ignore_files)

    def copy_file(self, src: str, dst: str):
        # L'appelant a la responsabilité de s'assurer l'existance des fichiers
        with open(src, mode="rb") as fsrc, open(dst, mode="wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
        return True

    def copy_dir(self, src: str, dst: str, ignore: Callable | None = None):
        # L'appelant a la responsabilité de s'assurer l'existance des dossiers
        shutil.copytree(
            src,
            dst,
            ignore_dangling_symlinks=True,
            symlinks=False,
            dirs_exist_ok=True,
            ignore=ignore,
        )
        return True

    def copy(self, src: str, dst: str, is_dir: bool, ignore: Callable | None = None):
        if is_dir:
            return self.copy_dir(src, dst, ignore=ignore)
        return self.copy_file(src, dst)

    def rm(self, path):
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path=path, ignore_errors=True)
            else:
                os.unlink(path)
        return

    def compute_hash_for_dir(self, path: str):
        if not os.path.exists(path):
            return {}
        if os.path.isfile(path):
            sha = sha256_of_file(path)
            return {"path": sha}
        elif os.path.isdir(path):
            result = {}
            files = [os.path.join(path, f) for f in list(os.listdir(path))]
            for f in files:
                if os.path.isfile(f):
                    result[f] = sha256_of_file(f)
                elif os.path.isdir(f):
                    result.update(self.compute_hash_for_dir(f))
            return result
        return {}

    def _build_temp_path(self, is_dir: bool, ext: str = ""):
        if is_dir:
            path = tempfile.mkdtemp(prefix=self.WORKSPACE_COPY_PREFIX, dir=self.internal_workdir)
        else:
            with tempfile.NamedTemporaryFile(
                suffix=ext, delete=False,
                prefix=self.WORKSPACE_COPY_PREFIX, dir=self.internal_workdir
            ) as f:
                path = f.name
        return path

    @staticmethod
    def list_files(path: str):
        if not os.path.exists(path):
            return None
        if os.path.isfile(path):
            return [path]
        if not os.path.isdir(path):
            return None
        all_filenames = []
        for dirpath, _dirname, filenames in os.walk(path, onerror=None):
            all_filenames.extend([os.path.join(dirpath, f) for f in filenames])
        return all_filenames

    def _list_files_filtered(self, path: str) -> list[str]:
        """Comme `list_files`, mais exclut tout fichier situé sous un
        `ignore_dirs` ou matchant `ignore_files` (chemin relatif à `path`)."""
        all_files = self.list_files(path) or []
        return [
            f for f in all_files
            if not self._is_relpath_ignored(os.path.relpath(f, path))
        ]

    # ─────────────────────────────────────────────────────────────
    # SLOTS
    # ─────────────────────────────────────────────────────────────

    def delete_slot(self, slot: Slot | str):
        if isinstance(slot, str):
            if not self.slot_exists(slot):
                raise ValueError("This slot doesn't exists (try delete non-existant slot)")
            slot = self._slots[slot]

        self._ensure_container()
        path_in_container = slot.path_in_container
        base = os.path.basename(path_in_container)
        dirname = os.path.dirname(path_in_container)
        self.manager.exec_command(f"cd {dirname} && rm -rf {base}")
        self.rm(slot.path_on_host)
        self._slots.pop(slot.key, None)
        return True

    def copy_in(
        self,
        original_path: str,
        name: str | None = None,
        force: bool = False,
    ):
        """
        Copie un fichier/dossier hôte dans un nouveau slot du sandbox.

        Pour un dossier, `ignore_dirs`/`ignore_files` sont appliqués DEUX
        fois : une fois lors de la copie hôte -> dossier interne (ci-dessous),
        et implicitement une deuxième fois côté container puisque seul le
        contenu filtré est envoyé — le VCS, les dépendances, les caches de
        build du repo original n'entrent jamais dans le sandbox.
        """
        try:
            original_path = os.path.realpath(_validate_path(
                original_path, check_exists=True
            ))
        except ValueError as e:
            raise WorkSpaceError(*e.args) from e

        self._ensure_container()
        name = name or os.path.basename(original_path)
        name = os.path.splitext(name)[0]
        is_dir = os.path.isdir(original_path)
        ext = os.path.splitext(original_path)[1] or ""
        path = self._build_temp_path(is_dir=is_dir, ext=ext)
        path_in_container = os.path.join(self.config.workdir, f"{name}{ext}")
        key = os.path.relpath(path_in_container, self.config.workdir)

        if not force and self.slot_exists(key):
            raise WorkSpaceError(
                f"This slot already exist (the path {original_path} is already copied. "
                f"To force, use force=True"
            )

        exists_in_container = self.manager.exists_in_container(path_in_container)
        if not force and exists_in_container:
            raise WorkSpaceError(
                f"This path already exists in container path = {path_in_container}, given name = {name!r}, "
                f"use force=True, or delete the directory or file before"
            )

        if exists_in_container:
            base = os.path.basename(path_in_container)
            dirname = os.path.dirname(path_in_container)
            self.manager.exec_command(f"cd {dirname} && rm -rf {base}")

        self.rm(path)

        try:
            # on est sûr, plus de symlink éventuel ; filtre ignore_* appliqué
            # ici pour ne jamais envoyer .git/node_modules/venv/... au sandbox
            self.copy(
                original_path, path, is_dir=is_dir,
                ignore=self._ignore_callback() if is_dir else None,
            )
        except Exception as e:
            self.rm(path)
            raise WorkSpaceError(*e.args) from e

        try:
            if is_dir:
                copy_result = self.manager.copy_in_dir(
                    path,
                    path_in_container,
                    chown_to=self.config.exec_user,
                )
                if not copy_result["success"]:
                    raise WorkSpaceError(
                        f"Error during copy host to container {path!r} -> {path_in_container!r}: {copy_result['error']!r}"
                    )
            else:
                content = read(path, binary=True)
                copy_result = self.manager.copy_in(
                    content=content,
                    dest_path=path_in_container,
                    user=self.config.exec_user,
                    use_subprocess=True,
                )
                if not copy_result[0] == 0:
                    raise WorkSpaceError(
                        f"Error during copy host to container {path!r} -> {path_in_container!r}: {copy_result[2]!r}"
                    )
        except Exception as e:
            self.rm(path)
            raise WorkSpaceError(*e.args) from e

        if is_dir:
            sha256s = {
                os.path.relpath(f, path): sha256_of_file(f)
                for f in self.list_files(path)
            }
        else:
            sha256s = {os.path.basename(original_path): sha256_of_file(path)}

        slot = Slot(
            name=name, is_dir=is_dir,
            original_path=original_path, path_on_host=path,
            path_in_container=path_in_container,
            hashs=sha256s, key=key, ext=ext,
        )

        if self.slot_exists(key):
            self.delete_slot(key)

        self._slots[key] = slot
        return {
            "success": True,
            "slot": slot.to_dict(),
            "is_dir": is_dir,
            "key": key,
            "name": name,
            "message": f"{'Dossier' if is_dir else 'Fichier'} copié dans {path_in_container}.",
        }

    # ─────────────────────────────────────────────────────────────
    # EXÉCUTION
    # ─────────────────────────────────────────────────────────────

    async def exec_async(
        self, cmd: str | list,
        timeout: int | float,
        check_open: bool = True,
    ):
        if check_open:
            self.check_open()
        self._ensure_container()
        result = await self.manager.exec_command_async(
            cmd=cmd, user=self.config.exec_user,
            workdir=self.config.workdir,
            timeout=timeout if self.timeout_is_valid(timeout) else self.config.exec_timeout,
        )
        to_return = dict(zip(["exit_code", "stdout", "stderr"], result))
        to_return["timed_out"] = (
            to_return["exit_code"] == -1 and to_return["stdout"] == "" and to_return["stderr"].startswith("TIMEOUT:")
        )
        to_return["success"] = to_return["exit_code"] == 0
        return to_return

    def exec_sync(
        self, cmd: str | list, timeout: int | float,
        check_open: bool = True,
    ):
        return _run_async(self.exec_async, cmd, timeout)

    # ─────────────────────────────────────────────────────────────
    # ÉDITION
    # ─────────────────────────────────────────────────────────────

    def str_replace(
        self,
        path: str,
        old_str: str,
        new_str: str,
        replace_all: bool = False,
    ):
        self.check_open()
        self._ensure_container()

        if not self.manager.exists_in_container(path):
            raise WorkSpaceError(f"The path {path} doesn't exists in container !")
        if not self.manager.is_file(path):
            raise WorkSpaceError(f"The path {path} is not a file, may be a directory ? File is required !")

        read_result = self.manager.read_file(path)
        if not read_result["success"]:
            return {"success": False, "error": read_result["error"]}

        raw = read_result["content"]
        if len(raw) > self.config.max_file_bytes:
            raise WorkSpaceError(f"{path} is too large for str_replace (> {self.config.max_file_bytes} octets) : use sandbox_exec")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise WorkSpaceError(f"{path} is not a UTF-8 texte file: use sandbox_exec")

        try:
            updated, n_done, first_line = apply_str_replace(text, old_str, new_str, replace_all)
        except TextEditError as e:
            return {"success": False, "path": path, "error": str(e)}

        result = self.manager.copy_in(
            content=updated,
            dest_path=path,
            user=self.config.exec_user,
            use_subprocess=True,
            chown_to=self.config.exec_user,
        )
        # print("copy in str replace", result)
        return {
            "success": result[0] == 0,
            "path": path,
            "replacements": n_done,
            "first_line_that_match": first_line,
            "context": numbered_context(updated, first_line, new_str.count("\n") + 1),
        }

    async def str_replace_async(self, *args, **kwargs):
        return await asyncio.to_thread(self.str_replace, *args, **kwargs)

    # ─────────────────────────────────────────────────────────────
    # EXPORT (sandbox -> hôte)
    # ─────────────────────────────────────────────────────────────

    def _export_slot(self, slot: Slot, delete: bool = False):
        """
        Rapatrie un slot du container vers l'hôte, calcule le diff par
        fichier, puis écrase `slot.original_path` avec le résultat.

        Filtrage ignore_* : les fichiers/dossiers sous `ignore_dirs` ou
        matchant `ignore_files` (typiquement des artefacts générés PENDANT
        l'exécution des tests d'Alex, ex: `__pycache__`, `.pytest_cache`) ne
        sont :
            - ni comptés dans les états retournés (pas de faux "new_file")
            - ni recopiés vers `original_path` (le vrai repo hôte n'est
              jamais pollué/écrasé par ces artefacts)
        """
        self._ensure_container()

        path_in_container = slot.path_in_container
        if not self.manager.exists_in_container(path_in_container):
            raise WorkSpaceError(
                f"Try to export slot {slot.name!r}, with path {slot.path_in_container!r} in container "
                f"but it doesn't exists ! May be deleted ?"
            )

        temp_path = self._build_temp_path(is_dir=slot.is_dir, ext=slot.ext)

        def _check(copy_result):
            print("Export:", copy_result)
            if not copy_result["success"]:
                raise WorkSpaceError(
                    f"Error during copy container to host {path_in_container!r} -> {temp_path!r}: "
                    f"{copy_result['error']!r}"
                )

        try:
            if slot.is_dir:
                copy_result = self.manager.copy_out_dir(
                    src_path=path_in_container,
                    dest_path=temp_path,
                )
                _check(copy_result)
            else:
                copy_result = self.manager.copy_out(
                    src_path=path_in_container, container=self.manager.container
                )
                _check(copy_result)
                with open(temp_path, "wb") as f:
                    f.write(copy_result["content"])
        except Exception as e:
            self.rm(temp_path)
            raise WorkSpaceError(*e.args) from e

        # ── Calcul du diff et du statut par fichier ────────────────
        hashs = slot.hashs
        if not hashs:
            return {
                "success": False,
                "message": "no hash to compare, may it be a success if the initial dir was empty",
                "states": {},
            }

        if slot.is_dir:
            # filtré : les artefacts générés pendant l'exécution (cache de
            # test, bytecode...) ne sont pas comparés/rapportés
            all_filenames = [
                os.path.relpath(f, temp_path) for f in (self._list_files_filtered(temp_path) or [])
            ]
        else:
            all_filenames = self.list_files(temp_path) or []

        if not all_filenames:
            raise WorkSpaceError("All files was deleted !")

        states = {}
        if not slot.is_dir:  # fichier unique
            filename = os.path.basename(slot.original_path)
            fid = str(uuid4())
            state = {
                "filename": filename, "modified": False, "deleted": False,
                "new_file": False, "diff": None, "fid": fid,
            }
            if filename not in hashs:
                raise WorkSpaceError(
                    "A filename was copied, but it was deleted or renamed, his export failed. "
                    "Rename it or create it, and work on it if needed before export."
                )
            fhash = sha256_of_file(all_filenames[0])
            fhash_ori = hashs[filename]
            if fhash != fhash_ori:
                state["modified"] = True
                state["diff"] = _compute_diff(
                    path=filename,
                    original_lines=read(slot.path_on_host).splitlines(),
                    new_lines=read(temp_path).splitlines(),
                )
            states[fid] = state
        else:  # dossier
            for filename in all_filenames:
                fid = str(uuid4())
                state = {
                    "filename": filename, "modified": False, "deleted": False,
                    "new_file": False, "diff": None, "fid": fid,
                }
                fhash = sha256_of_file(os.path.join(temp_path, filename))
                fhash_ori = hashs.get(filename)
                state["new_file"] = filename not in hashs
                modified = fhash != fhash_ori
                if modified:
                    state["modified"] = True
                    state["diff"] = _compute_diff(
                        path=filename,
                        original_lines=read(os.path.join(slot.path_on_host, filename)).splitlines(),
                        new_lines=read(os.path.join(temp_path, filename)).splitlines(),
                    )
                states[fid] = state

            # fichiers présents à l'origine mais absents à l'export = supprimés
            # (les entrées ignore_* de `hashs` n'existent pas puisqu'elles
            # n'ont jamais été envoyées au sandbox par copy_in filtré)
            for ofilename in hashs:
                if ofilename not in all_filenames:
                    fid = str(uuid4())
                    states[fid] = {
                        "filename": ofilename, "modified": False, "deleted": True,
                        "new_file": False, "diff": None, "fid": fid,
                    }

        # ── Application sur l'hôte (avec sauvegarde + rollback) ────
        temp_path2 = self._build_temp_path(is_dir=slot.is_dir, ext=slot.ext)
        if slot.is_dir:
            os.makedirs(temp_path2, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(temp_path2), exist_ok=True)

        self.copy(slot.original_path, temp_path2, is_dir=slot.is_dir)  # backup

        try:
            # Dernier copy() de l'export : celui qui écrase original_path.
            # ignore_* filtré ici en priorité — c'est le point critique qui
            # empêche des artefacts de test (cache pytest, __pycache__...)
            # générés dans le sandbox de polluer le vrai repo de l'utilisateur.
            self.copy(
                temp_path, slot.original_path, is_dir=slot.is_dir,
                ignore=self._ignore_callback() if slot.is_dir else None,
            )
            self.rm(temp_path2)
            if delete:
                self.delete_slot(slot)
        except Exception as e:
            self.rm(temp_path)
            self.copy(temp_path2, slot.original_path, is_dir=slot.is_dir)  # rollback
            raise WorkSpaceError(*e.args) from e

        self.rm(temp_path)
        return {"states": states, "success": True, "slot": slot.to_dict()}

    def export(self, all_slots: bool = False, slot_keys: list[str] | None = None, delete: bool = False):
        """Exporte un ou plusieurs slots (voir `_export_slot`). Un seul des
        deux modes doit être utilisé : `all_slots=True` ou `slot_keys=[...]`."""
        if not self._slots:
            return {
                "success": True,
                "message": "Try to export while no slot was copied. If there are no slot you can skip after this attempt",
                "ignored": [],
                "result": {},
            }

        self._ensure_container()
        ignored = []

        if slot_keys:
            slots = []
            for key in slot_keys:
                if key and self.slot_exists(key):
                    slots.append(self._slots[key])
                else:
                    ignored.append(key)
        elif all_slots:
            slots = list(self._slots.values())
        else:
            return {
                "success": False,
                "message": "No slot exported, call with a least one slot to export",
                "result": {},
                "ignored": [],
            }

        result = {slot.key: self._export_slot(slot, delete) for slot in slots}
        return {"success": True, "message": "", "result": result, "ignored": ignored}