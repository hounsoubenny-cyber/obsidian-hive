#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système de logging avancé avec instances indépendantes
Auteur: Hounsou Samuel

Variables d'environnement :
    OBSIDIAN_LOG_FILE     "0"/"false"/"no" -> désactive l'écriture fichier (défaut : activé)
    OBSIDIAN_LOG_LEVEL    DEBUG/INFO/SUCCESS/WARNING/ERROR/CRITICAL
                          (défaut : DEBUG ; toute valeur invalide retombe sur DEBUG)
    OBSIDIAN_LOG_CONSOLE  niveau console uniquement (défaut : = OBSIDIAN_LOG_LEVEL)
"""

# Fait avec deepseek

import atexit
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Union
from modules_utils.signal_manager import signal_manager

# ==================== CONSTANTES GLOBALES ====================
LOGDIR = os.path.dirname(os.path.abspath(__file__))
PROD_PATH = os.path.join(os.sep, "var", "log", "obsidian")
# Rotation des fichiers
LOG_MAX_BYTES    = 10 * 1024 * 1024   # 10 Mo max par fichier
LOG_BACKUP_COUNT = 3                  # 3 fichiers de rotation 

# Comportement (mettre False pour gain de perf)
CONSOLE_FLUSH = False    # flush après chaque écriture console
FILE_ASYNC    = True    # écriture fichier via QueueListener (hors thread appelant)

# ==================== NIVEAU PERSONNALISÉ SUCCESS ====================
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")

# ==================== HELPERS ENV ====================
def _env_bool(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "y", "on", "oui", "vrai")


def _env_level(name: str, default: int = logging.DEBUG) -> int:
    """Lit un niveau depuis l'env. Valeur inconnue ou absente -> default (DEBUG)."""
    val = os.environ.get(name)
    if not val:
        return default
    key = val.strip().upper()
    if key == "SUCCESS":
        return SUCCESS_LEVEL_NUM
    lvl = getattr(logging, key, None)
    return lvl if isinstance(lvl, int) else default


# ==================== VARIABLES D'ENVIRONNEMENT ====================
FILE_LOGGING_ENABLED = _env_bool("OBSIDIAN_LOG_FILE", True)             # défaut : activé
DEFAULT_LOG_LEVEL    = _env_level("OBSIDIAN_LOG_LEVEL", logging.DEBUG)  # invalide -> DEBUG
_CONSOLE_LEVEL       = _env_level("OBSIDIAN_LOG_CONSOLE", DEFAULT_LOG_LEVEL)

# État global (utilisé par get_logger pour activer fichiers sur les nouveaux loggers)
_FILE_LOGGING: Optional[tuple] = (DEFAULT_LOG_LEVEL, FILE_ASYNC) if FILE_LOGGING_ENABLED else None

# ==================== REGEX COMPILÉS ====================
_SUCCESS_RE = re.compile(r'\b(success|succ[eè]s|termin[eé]\s*(avec\s*succ[eè]s)?|done|ok)\b', re.I)
_ERROR_RE   = re.compile(r'\b(error|erreur|fail(ed|ure)?|critical|fatal|exception|échec|échoué)\b', re.I)
_WARNING_RE = re.compile(r'\b(warning|warn|attention|deprecated)\b', re.I)
_DEBUG_RE   = re.compile(r'\b(debug|trace|verbose)\b', re.I)


# ==================== PATCH logging.Logger.success ====================
def _success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kws)

logging.Logger.success = _success


# ==================== HANDLER THREAD-SAFE ====================
class ThreadSafeStreamHandler(logging.StreamHandler):
    """StreamHandler avec lock par instance pour éviter l'interleaving."""

    def __init__(self, stream=None):
        super().__init__(stream)
        self._write_lock = threading.Lock()
        if hasattr(self.stream, "reconfigure"):
            try:
                self.stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    def emit(self, record):
        with self._write_lock:
            try:
                msg = self.format(record)
                self.stream.write(msg + self.terminator)
                if CONSOLE_FLUSH:
                    self.stream.flush()
            except Exception:
                self.handleError(record)


# ==================== FORMATTEURS ====================
class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour la console."""

    COLORS = {
        'DEBUG':    '\033[36m',
        'INFO':     '\033[32m',
        'SUCCESS':  '\033[92m',
        'WARNING':  '\033[33m',
        'ERROR':    '\033[31m',
        'CRITICAL': '\033[41m',
        'RESET':    '\033[0m',
    }
    ICONS = {
        'DEBUG':    '🐛',
        'INFO':     'ℹ️',
        'SUCCESS':  '✅',
        'WARNING':  '⚠️',
        'ERROR':    '❌',
        'CRITICAL': '🔥',
    }

    def format(self, record):
        levelname = record.levelname  # sauvegarde AVANT modification
        color = self.COLORS.get(levelname, self.COLORS['RESET'])
        icon  = self.ICONS.get(levelname, '')

        # Padding calculé sur le texte brut AVANT les codes ANSI
        padded = f"{icon} {levelname}".ljust(12)
        record.levelname      = f"{color}{padded}{self.COLORS['RESET']}"
        record.filename_color = f"\033[35m{record.filename}\033[0m"
        record.funcname_color = f"\033[36m{record.funcName}\033[0m"
        record.lineno_color   = f"\033[33m{record.lineno}\033[0m"
        record.module_color   = f"\033[36m{getattr(record, 'module_name', '?')}\033[0m"
        
        fmt = (
            "%(asctime)s | %(levelname)s | %(module_color)s | "
            "%(filename_color)s:%(lineno_color)s | %(message)s"
        )
        
        # if record.levelno >= logging.ERROR:
        #     fmt = (
        #         "%(asctime)s | %(levelname)s | %(module_color)s | "
        #         "%(filename_color)s:%(lineno_color)s | %(messagse)s"
        #     )
        # else:
        #     fmt = "%(asctime)s | %(levelname)s | %(module_color)s | %(message)s"
        #     fmt = (
        #         "%(asctime)s | %(levelname)s | %(module_color)s | "
        #         "%(filename_color)s:%(lineno_color)s | %(message)s"
        #     )

        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        result = formatter.format(record)

        # Restore pour que les autres handlers (fichiers) reçoivent le nom propre
        record.levelname = levelname
        return result


class JsonFormatter(logging.Formatter):
    """Formatter JSON structuré pour les logs fichiers."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "module":    getattr(record, 'module_name', 'unknown'),
            "filename":  record.filename,
            "function":  record.funcName,
            "line":      record.lineno,
            "message":   record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False, default=str)


# ==================== FILTRE MODULE ====================
class ModuleNameFilter(logging.Filter):
    """Injecte module_name dans chaque record."""

    def __init__(self, module_name: str):
        super().__init__()
        self.module_name = module_name

    def filter(self, record):
        record.module_name = self.module_name
        return True


# ==================== UTILITAIRES ====================
def _to_level(level) -> int:
    if isinstance(level, int):
        return level
    name = str(level).upper()
    return SUCCESS_LEVEL_NUM if name == "SUCCESS" else getattr(logging, name, logging.INFO)


def _fmt(args, sep: str = " ") -> str:
    """Assemble les arguments COMME print() : logger.error('a', x, 3) -> 'a x 3'."""
    if not args:
        return ""
    if len(args) == 1:
        a = args[0]
        return a if isinstance(a, str) else str(a)
    return sep.join(str(a) for a in args)


def _safe_filename(name: str) -> str:
    """Nettoie un nom de module pour un usage en tant que nom de fichier."""
    return name.replace("/", "_").replace("\\", "_").replace("..", "_")


# ==================== LOGGER INDÉPENDANT ====================
class Logger:
    """Logger indépendant avec détection automatique du niveau."""

    def __init__(
        self, module_name: str, log_dir: Optional[Path] = None, structured: bool = True
    ):
        self.module_name = module_name

        # --- Résolution du dossier de logs (toujours en Path) ---
        base = Path(log_dir) if log_dir is not None else get_default_log_dir()
        self.base_log_dir = base
        self.log_dir = base / module_name
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Ne casse pas le logger si on ne peut pas créer le dossier
            print(f"[logger] Impossible de créer {self.log_dir} : {e}", file=sys.stderr)
            self.log_dir = base  # fallback : on écrit à la racine

        self.logger = logging.getLogger(f"module_{module_name}")
        self.logger.setLevel(DEFAULT_LOG_LEVEL)
        self.logger.handlers.clear()
        self.logger.propagate = False
        self.structured = structured

        self.logger.addFilter(ModuleNameFilter(module_name))
        self.console_level = _CONSOLE_LEVEL
        self._file_enabled = None          # (niveau, asynchrone) si le fichier est actif
        self._file_handlers = ()
        self._qlistener = None
        self._qhandler = None

        self._setup_handlers()
        self.logger.debug(f"Logger initialisé pour '{module_name}' dans {self.log_dir}")

    # ── Handlers ────────────────────────────────────────────────────────────
    def _setup_handlers(self):
        # (Re)créer le dossier si besoin (peut avoir changé via set_default_log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        # Console (thread-safe)
        console_handler = ThreadSafeStreamHandler(sys.stdout)
        console_handler.setLevel(self.console_level)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)
        # NB : les handlers fichiers sont ajoutés via enable_file_logging()
        # pour être correctement suivis dans self._file_handlers.

    def _detect_level(self, message: str) -> int:
        """Détection par regex — SUCCESS avant ERROR (gère 'Erreur corrigée avec succès')."""
        if _SUCCESS_RE.search(message):
            return SUCCESS_LEVEL_NUM
        if _ERROR_RE.search(message):
            return logging.ERROR
        if _WARNING_RE.search(message):
            return logging.WARNING
        if _DEBUG_RE.search(message):
            return logging.DEBUG
        return logging.INFO

    # ── Émission ────────────────────────────────────────────────────────────
    def _emit(self, level, args, sep=" ", extra=None, exc_info=None, stack_info=False):
        """
        - filtre de niveau AVANT construction de la chaîne ;
        - stacklevel=3 : %(filename)s:%(lineno)d désignent l'APPELANT.
        """
        if not self.logger.isEnabledFor(level):
            return
        kw = {"stacklevel": 3}
        if extra:
            kw["extra"] = extra
        if exc_info:
            kw["exc_info"] = exc_info
        if stack_info:
            kw["stack_info"] = True
        self.logger.log(level, _fmt(args, sep), **kw)

    # ── API publique ────────────────────────────────────────────────────────
    # Les méthodes de niveau se comportent COMME print : logger.error("Echec", ip, code).
    # (sep= respecté ; end=, flush=, file=, verify= acceptés et ignorés.)

    def print(self, *args, **kwargs):
        """Ancienne API : niveau DEVINÉ par regex. Préférer debug/info/success/warning/error."""
        message = _fmt(args, kwargs.get("sep", " "))
        verify = kwargs.get('verify', True)
        extra = kwargs.get('extra') or None
        level = self._detect_level(message) if verify else logging.INFO
        if not self.logger.isEnabledFor(level):
            return
        kw = {"stacklevel": 2}
        if extra:
            kw["extra"] = extra
        self.logger.log(level, message, **kw)

    def debug(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(logging.DEBUG, args if message is None else (message, *args), sep, extra, exc_info)

    def info(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(logging.INFO, args if message is None else (message, *args), sep, extra, exc_info)

    def success(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(SUCCESS_LEVEL_NUM, args if message is None else (message, *args), sep, extra, exc_info)

    def warning(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(logging.WARNING, args if message is None else (message, *args), sep, extra, exc_info)

    def error(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(logging.ERROR, args if message is None else (message, *args), sep, extra, exc_info)

    def critical(self, *args, sep=" ", extra=None, exc_info=None, message=None, **_):
        self._emit(logging.CRITICAL, args if message is None else (message, *args), sep, extra, exc_info)

    def exception(self, *args, sep=" ", extra=None, message=None, **_):
        """Comme error(), avec la trace de l'exception en cours."""
        self._emit(logging.ERROR, args if message is None else (message, *args), sep, extra, exc_info=True)

    # ── Sorties : console réglable + fichier (sync ou async) ────────────────
    def set_console_level(self, level):
        """Niveau MINIMAL affiché en console. Le fichier n'est pas touché."""
        self.console_level = _to_level(level)
        for h in self.logger.handlers:
            if isinstance(h, ThreadSafeStreamHandler):
                h.setLevel(self.console_level)

    @staticmethod
    def _rotating(path, level, fmt):
        h = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding='utf-8',
            delay=True,
        )
        h.setLevel(level)
        h.setFormatter(fmt)
        return h

    def enable_file_logging(self, level=logging.DEBUG, asynchronous: bool = None):
        """
        Écrit les logs dans <log_dir>/<module>.log (+ errors_<module>.log pour ERROR et plus).
        asynchronous=True : le thread appelant ne fait qu'ENFILER (QueueHandler) ; un thread
        dédié écrit (QueueListener) -> aucune écriture disque sur le chemin chaud.
        """
        if self._file_enabled:
            return self
        level = _to_level(level)
        if asynchronous is None:
            asynchronous = FILE_ASYNC

        # Le dossier peut avoir changé (set_default_log_dir) : on s'assure qu'il existe
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"[logger] Impossible de créer {self.log_dir} : {e}", file=sys.stderr)
            return self

        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(module_name)s | "
            "%(filename)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        safe = _safe_filename(self.module_name)
        fh = self._rotating(self.log_dir / f"{safe}.log", level, fmt)
        eh = self._rotating(self.log_dir / f"errors_{safe}.log", logging.ERROR, fmt)

        if asynchronous:
            q = queue.Queue(-1)
            self._qhandler = logging.handlers.QueueHandler(q)
            self.logger.addHandler(self._qhandler)
            self._qlistener = logging.handlers.QueueListener(
                q, fh, eh, respect_handler_level=True
            )
            self._qlistener.start()
            atexit.register(self.close_file_logging)
            def _stop(*args, **kwargs):
                self.close_file_logging()
                
            signal_manager(_stop)
        else:
            self.logger.addHandler(fh)
            self.logger.addHandler(eh)

        self._file_handlers = (fh, eh)
        self._file_enabled = (level, asynchronous)
        return self

    def close_file_logging(self):
        """Vide la file d'écriture et ferme les fichiers (appelé aussi à la sortie)."""
        if self._qlistener is not None:
            try:
                self._qlistener.stop()
            except Exception:
                pass
            self._qlistener = None
        if self._qhandler is not None:
            try:
                self.logger.removeHandler(self._qhandler)
            except Exception:
                pass
            self._qhandler = None
        for h in getattr(self, "_file_handlers", ()):
            try:
                self.logger.removeHandler(h)
            except Exception:
                pass
            try:
                h.close()
            except Exception:
                pass
        self._file_handlers = ()
        self._file_enabled = None

    def get_logger(self):
        return self.logger

    def setup(self, level: Union[str, int] = None, structured: bool = None):
        if level is not None:
            if isinstance(level, str):
                level = getattr(logging, level.upper(), DEFAULT_LOG_LEVEL)
            self.logger.setLevel(level)

        if structured is not None:
            self.structured = bool(structured)

        file_state = self._file_enabled
        self.close_file_logging()
        for h in self.logger.handlers[:]:
            try:
                self.logger.removeHandler(h)
                h.close()
            except Exception:
                pass
        self._setup_handlers()
        if file_state:
            self.enable_file_logging(*file_state)
        return self

    def remove_handlers(self, all_handlers: bool = False):
        to_remove = [
            h for h in self.logger.handlers
            if all_handlers or h.__class__.__name__ in ("ThreadSafeStreamHandler", "StreamHandler")
        ]
        for h in to_remove:
            self.logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass

    def remove(self, all_handlers: bool = False):
        self.remove_handlers(all_handlers)


# ==================== REGISTRY ====================
_LOGGER_REGISTRY: dict = {}
_DEFAULT_LOG_DIR: Optional[Path] = None


def get_default_log_dir() -> Path:
    global _DEFAULT_LOG_DIR
    if _DEFAULT_LOG_DIR is not None:
        return _DEFAULT_LOG_DIR
    mode = os.environ.get('OBSIDIAN_MODE', 'dev').lower()
    if mode == 'prod':
        _DEFAULT_LOG_DIR = Path(PROD_PATH)
    else:
        _DEFAULT_LOG_DIR = Path(LOGDIR).parent / 'logs'
    _DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    return _DEFAULT_LOG_DIR


def set_default_log_dir(log_dir: Union[str, Path], reconfigure_existing: bool = True):
    global _DEFAULT_LOG_DIR
    _DEFAULT_LOG_DIR = Path(log_dir)
    _DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    if reconfigure_existing and _LOGGER_REGISTRY:
        for module_name, lg in _LOGGER_REGISTRY.items():
            lg.base_log_dir = _DEFAULT_LOG_DIR
            lg.log_dir = _DEFAULT_LOG_DIR / module_name
            try:
                lg.log_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            lg.setup(lg.logger.level, lg.structured)
    return _DEFAULT_LOG_DIR


def get_logger(module_name: str,
               log_dir: Optional[Union[str, Path]] = None,
               structured: bool = True) -> Logger:
    if module_name in _LOGGER_REGISTRY:
        return _LOGGER_REGISTRY[module_name]
    if log_dir is not None:
        log_dir = Path(log_dir)
    lg = Logger(module_name, log_dir, structured)
    _LOGGER_REGISTRY[module_name] = lg
    if _FILE_LOGGING:
        lg.enable_file_logging(*_FILE_LOGGING)
    return lg


def set_console_level(level) -> None:
    """Niveau console de TOUS les loggers (existants et futurs)."""
    global _CONSOLE_LEVEL
    _CONSOLE_LEVEL = _to_level(level)
    for lg in _LOGGER_REGISTRY.values():
        lg.set_console_level(_CONSOLE_LEVEL)


def enable_file_logging(level=logging.DEBUG, asynchronous: bool = None) -> None:
    """Active l'écriture fichier pour TOUS les loggers (existants et futurs)."""
    global _FILE_LOGGING
    if asynchronous is None:
        asynchronous = FILE_ASYNC
    _FILE_LOGGING = (_to_level(level), asynchronous)
    for lg in _LOGGER_REGISTRY.values():
        lg.enable_file_logging(*_FILE_LOGGING)


def disable_file_logging() -> None:
    """Désactive l'écriture fichier pour tous les loggers."""
    global _FILE_LOGGING
    _FILE_LOGGING = None
    for lg in _LOGGER_REGISTRY.values():
        lg.close_file_logging()


def list_loggers() -> List[str]:
    return list(_LOGGER_REGISTRY.keys())


def get_logger_registry() -> dict:
    return _LOGGER_REGISTRY


def remove_all_handlers(module_name: str = None, all_handlers: bool = True):
    if module_name:
        lg = _LOGGER_REGISTRY.get(module_name)
        if lg:
            lg.remove_handlers(all_handlers)
    else:
        for lg in _LOGGER_REGISTRY.values():
            lg.remove_handlers(all_handlers)


def setup_logger(module_name: str,
                 level: Union[str, int] = None,
                 structured: bool = None,
                 log_dir: Optional[Union[str, Path]] = None) -> Logger:
    lg = get_logger(module_name, log_dir, structured if structured is not None else True)
    if level is not None:
        lg.setup(level=level, structured=lg.structured)
    return lg


# ==================== EXPORTS ====================
__all__ = [
    'get_logger', 'setup_logger', 'remove_all_handlers',
    'set_default_log_dir', 'set_console_level', 'enable_file_logging',
    'disable_file_logging', 'list_loggers', 'get_logger_registry',
    'Logger', 'SUCCESS_LEVEL_NUM',
    'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'CONSOLE_FLUSH', 'FILE_ASYNC',
]


if __name__ == "__main__":
    print("=== TEST DU SYSTÈME DE LOGGING ===\n")

    logger_scanner = get_logger('scanner', structured=True)
    logger_parser  = get_logger('parser')

    logger_scanner.print("Démarrage du scanner")
    logger_scanner.info("Fichier chargé", extra={"file": "data.csv"})
    logger_scanner.print("Attention: fichier volumineux")
    logger_scanner.print("Erreur: impossible d'accéder au fichier")
    logger_scanner.print("Succès: scan terminé")

    logger_parser.warning("Format non standard")
    logger_parser.error("Parse échoué")
    logger_parser.success("Parse réussi")

    # Force l'écriture sur disque avant sortie
    for lg in get_logger_registry().values():
        lg.close_file_logging()

    print(f"\nLoggers actifs : {list_loggers()}")