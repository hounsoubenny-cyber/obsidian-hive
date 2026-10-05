#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système de logging avancé avec instances indépendantes
Auteur: Hounsou Samuel
"""

import os
import re
import sys
import time
import queue
import atexit
import logging
import logging.handlers
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Union, List
import json

# ==================== CONSTANTES ====================
LOGDIR = os.path.dirname(os.path.abspath(__file__))

# Regex compilés une seule fois (perf : évite de parcourir les tuples à chaque print)
_SUCCESS_RE = re.compile(r'\b(success|succ[eè]s|termin[eé]\s*(avec\s*succ[eè]s)?|done|ok)\b', re.I)
_ERROR_RE   = re.compile(r'\b(error|erreur|fail(ed|ure)?|critical|fatal|exception|échec|échoué)\b', re.I)
_WARNING_RE = re.compile(r'\b(warning|warn|attention|deprecated)\b', re.I)
_DEBUG_RE   = re.compile(r'\b(debug|trace|verbose)\b', re.I)
# Niveau personnalisé SUCCESS (entre INFO et WARNING)
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, 'SUCCESS')

def success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kws)

logging.Logger.success = success


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
                # Remplace les \n internes pour éviter le décalage console
                # msg = msg.replace('\n', ' ↵ ')
                self.stream.write(msg + self.terminator)
                self.stream.flush()
            except Exception:
                self.handleError(record)


# ==================== FORMATTEURS ====================
class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour la console."""

    COLORS = {
        'DEBUG':   '\033[36m',
        'INFO':    '\033[32m',
        'SUCCESS': '\033[92m',
        'WARNING': '\033[33m',
        'ERROR':   '\033[31m',
        'CRITICAL':'\033[41m',
        'RESET':   '\033[0m'
    }

    ICONS = {
        'DEBUG':   '🐛',
        'INFO':    'ℹ️',
        'SUCCESS': '✅',
        'WARNING': '⚠️',
        'ERROR':   '❌',
        'CRITICAL':'🔥'
    }

    def format(self, record):
        levelname = record.levelname  # sauvegarde AVANT modification
        color = self.COLORS.get(levelname, self.COLORS['RESET'])
        icon  = self.ICONS.get(levelname, '')

        # Padding calculé sur le texte brut AVANT d'ajouter les codes ANSI
        # → évite le décalage lié aux séquences invisibles comptées comme des chars
        padded = f"{icon} {levelname}".ljust(12)
        record.levelname      = f"{color}{padded}{self.COLORS['RESET']}"
        record.filename_color = f"\033[35m{record.filename}\033[0m"
        record.funcname_color = f"\033[36m{record.funcName}\033[0m"
        record.lineno_color   = f"\033[33m{record.lineno}\033[0m"
        record.module_color   = f"\033[36m{record.module_name}\033[0m"

        if record.levelno >= logging.ERROR:
            fmt = (
                "%(asctime)s | %(levelname)s | %(module_color)s | "
                "%(filename_color)s:%(lineno_color)s | %(message)s"
            )
        else:
            fmt = "%(asctime)s | %(levelname)s | %(module_color)s | %(message)s"

        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        result = formatter.format(record)

        # Restore pour que les autres handlers (fichiers) reçoivent le nom propre
        record.levelname = levelname
        return result


class JsonFormatter(logging.Formatter):
    """Formatter JSON structuré pour les logs fichiers."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level":     record.levelname,
            "module":    getattr(record, 'module_name', 'unknown'),
            "filename":  record.filename,
            "function":  record.funcName,
            "line":      record.lineno,
            "message":   record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, 'extra'):
            log_entry["extra"] = record.extra
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


# ==================== PIPELINE DE LOGS ASYNCHRONE ====================
#
#   module A ─┐                                        ┌─> console (UNE seule, ligne par ligne, jamais mélangée)
#   module B ─┼─> QueueHandler ─> queue.Queue ─> QueueListener (1 thread) ─┼─> <module>.log        (rotation)
#   module C ─┘   (~13 µs, jamais   (bornée)      "le facteur"            └─> errors_<module>.log (rotation)
#                  bloquant)
#
# L'appelant (ta détection) dépose le message et repart : un terminal/disque lent ne le ralentit plus.
# Tout est réglable par variables d'environnement (valeurs par défaut ci-dessous).

def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _env_level(name: str, default: int) -> int:
    return getattr(logging, os.environ.get(name, "").upper(), default) if os.environ.get(name) else default


LOG_QUEUE_MAXSIZE     = _env_int("OBSIDIAN_LOG_QUEUE_MAXSIZE", 50_000)      # file pleine => messages jetés (et comptés)
LOG_FILES_ENABLED     = os.environ.get("OBSIDIAN_LOG_FILES", "1") != "0"      # 0 = console seulement
LOG_FILE_MAX_BYTES    = _env_int("OBSIDIAN_LOG_FILE_MAX_MB", 10) * 1024 * 1024  # taille max d'UN fichier
LOG_FILE_BACKUP_COUNT = _env_int("OBSIDIAN_LOG_FILE_BACKUPS", 5)             # => max (1 + 5) x 10 Mo = 60 Mo par fichier
LOG_FILE_LEVEL        = _env_level("OBSIDIAN_LOG_FILE_LEVEL", logging.INFO)  # niveau du <module>.log
LOG_JSON_FILES        = os.environ.get("OBSIDIAN_LOG_JSON", "0") == "1"      # désactivé, comme avant
LOG_DEFAULT_LEVEL     = _env_level("OBSIDIAN_LOG_LEVEL", logging.DEBUG)      # niveau des loggers (INFO/WARNING = beaucoup plus rapide)
LOG_SIGNAL_HOOK       = os.environ.get("OBSIDIAN_LOG_SIGNAL_HOOK", "1") != "0"  # fermeture via signal_manager
LOG_SHUTDOWN_TIMEOUT  = 5.0

_FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(module_name)s | %(filename)s:%(funcName)s:%(lineno)d | %(message)s"
_MUTED_CONSOLE: set = set()          # modules dont la console est coupée (remove_handlers())
_PIPELINE: Optional["_Pipeline"] = None
_PIPELINE_LOCK = threading.Lock()


class _ConsoleModuleFilter(logging.Filter):
    def filter(self, record):
        return not getattr(record, "mute_console", False)     # décidé à l'ÉMISSION (voir _DropQueueHandler.prepare)


class _ConsoleHandler(ThreadSafeStreamHandler):
    """Console du listener : flush seulement quand la file est vide (1 appel système par rafale, pas par ligne)."""

    def emit(self, record):
        with self._write_lock:
            try:
                self.stream.write(self.format(record) + self.terminator)
                pipe = _PIPELINE
                if pipe is None or pipe.closed or pipe.queue.empty():
                    self.stream.flush()
            except Exception:
                self.handleError(record)


class _QuietRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Disque plein / permission : UNE ligne sur stderr par minute au lieu d'un traceback par message."""
    _last_report = 0.0

    def handleError(self, record):
        now = time.monotonic()
        if now - self._last_report > 60:
            self._last_report = now
            sys.stderr.write(f"[logger] écriture impossible dans {self.baseFilename} (disque plein ?)\n")


def _proc_suffix() -> str:
    """Process enfant (mp.Process) => fichiers à part (pas de rotation à deux process sur le même fichier)."""
    try:
        import multiprocessing as mp
        if mp.parent_process() is None:
            return ""
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", mp.current_process().name).strip("_")
        return f".{name}" if name else f".pid{os.getpid()}"
    except Exception:
        return ""


class _FileRouter(logging.Handler):
    """UN handler pour tous les modules : crée à la demande un fichier tournant par module (dans log_dir/<module>/)."""

    def __init__(self, kind: str, level: int):
        super().__init__(level)
        self.kind = kind                                   # "log" | "errors" | "json"
        self._children: dict = {}
        self._failed: set = set()
        self._children_lock = threading.Lock()
        self.setFormatter(JsonFormatter() if kind == "json" else logging.Formatter(_FILE_FORMAT))

    def _path(self, module: str) -> Path:
        lg = _LOGGER_REGISTRY.get(module)
        base = Path(lg.log_dir) if lg is not None else get_default_log_dir() / module
        prefix = "errors_" if self.kind == "errors" else ""
        ext = "json" if self.kind == "json" else "log"
        return base / f"{prefix}{module}{_proc_suffix()}.{ext}"

    def _child(self, module: str):
        h = self._children.get(module)
        if h is not None or module in self._failed:
            return h
        with self._children_lock:
            h = self._children.get(module)
            if h is None and module not in self._failed:
                try:
                    path = self._path(module)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    h = _QuietRotatingFileHandler(path, maxBytes=LOG_FILE_MAX_BYTES,
                                                  backupCount=LOG_FILE_BACKUP_COUNT, encoding="utf-8", delay=True)
                    h.setFormatter(self.formatter)
                    self._children[module] = h
                except Exception as e:
                    self._failed.add(module)
                    sys.stderr.write(f"[logger] fichier de log indisponible pour '{module}' : {e}\n")
        return h

    def emit(self, record):
        try:
            h = self._child(getattr(record, "module_name", "unknown"))
            if h is not None:
                h.handle(record)
        except Exception:
            self.handleError(record)

    def reset(self, module: Optional[str] = None):
        """Ferme (flush) les fichiers ; ils seront rouverts à la demande (ex: après un changement de log_dir)."""
        with self._children_lock:
            for m in ([module] if module else list(self._children)):
                h = self._children.pop(m, None)
                if h is not None:
                    h.close()
                self._failed.discard(m)


class _Listener(logging.handlers.QueueListener):
    """QueueListener durci : ne meurt jamais à cause d'un message, et s'arrête même si la file est pleine."""

    def enqueue_sentinel(self):
        try:
            self.queue.put(self._sentinel, timeout=LOG_SHUTDOWN_TIMEOUT)
        except queue.Full:
            pass

    def handle(self, record):
        try:
            super().handle(record)
        except Exception:
            pass


class _Pipeline:
    def __init__(self):
        self.queue = queue.Queue(maxsize=LOG_QUEUE_MAXSIZE)
        self.closed = False
        self.dropped = 0
        self._stop_lock = threading.Lock()

        self.console = _ConsoleHandler(sys.stdout)
        self.console.setLevel(logging.DEBUG)
        self.console.setFormatter(ColoredFormatter())
        self.console.addFilter(_ConsoleModuleFilter())
        self.routers: list = []
        if LOG_FILES_ENABLED:
            self.routers = [_FileRouter("log", LOG_FILE_LEVEL), _FileRouter("errors", logging.ERROR)]
            if LOG_JSON_FILES:
                self.routers.append(_FileRouter("json", LOG_FILE_LEVEL))
        self.handlers = [self.console, *self.routers]

        self.listener = _Listener(self.queue, *self.handlers, respect_handler_level=True)
        self.listener.start()

    def handle_sync(self, record):
        """Après l'arrêt du listener : écriture directe (plus rapide à écrire qu'à perdre un message)."""
        for h in self.handlers:
            if record.levelno >= h.level:
                try:
                    h.handle(record)
                except Exception:
                    pass

    def stop(self, timeout: float) -> bool:
        with self._stop_lock:
            if self.closed:
                return True
            self.closed = True               # dès maintenant, les nouveaux messages passent en direct
        done = threading.Event()

        def _stop():
            try:
                self.listener.stop()         # vide la file (la sentinelle est la dernière) puis termine le thread
            except Exception:
                pass
            finally:
                done.set()

        threading.Thread(target=_stop, name="log-stop", daemon=True).start()
        ok = done.wait(timeout)
        if ok:
            for r in self.routers:
                r.reset()                    # flush + fermeture des fichiers
            try:
                self.console.flush()
            except Exception:
                pass
        else:
            sys.stderr.write("[logger] arrêt du listener expiré : certains messages n'ont pas été écrits\n")
        if self.dropped:
            sys.stderr.write(f"[logger] {self.dropped} message(s) perdus (file pleine)\n")
        return ok


class _DropQueueHandler(logging.handlers.QueueHandler):
    """Dépose le message dans la file SANS JAMAIS BLOQUER : file pleine => on jette et on compte."""

    def __init__(self, pipeline: _Pipeline):
        super().__init__(pipeline.queue)
        self._pipeline = pipeline

    def prepare(self, record):
        record.msg = record.getMessage()     # fige le message (les args pourraient être modifiés ensuite)
        record.args = None
        # l'état "console coupée" est figé MAINTENANT : le listener traite le message plus tard, après un éventuel setup()
        record.mute_console = getattr(record, "module_name", None) in _MUTED_CONSOLE
        return record                        # exc_info conservé : file en mémoire, pas de pickle

    def emit(self, record):
        try:
            record = self.prepare(record)
            if self._pipeline.closed:
                self._pipeline.handle_sync(record)
            else:
                self.queue.put_nowait(record)
        except queue.Full:
            self._pipeline.dropped += 1
        except Exception:
            self.handleError(record)


def shutdown_logging(timeout: float = LOG_SHUTDOWN_TIMEOUT) -> bool:
    """Vide la file puis arrête le listener. Idempotent. Ensuite les logs continuent, en écriture directe."""
    p = _PIPELINE
    return True if p is None else p.stop(timeout)


def get_log_stats() -> dict:
    p = _PIPELINE
    if p is None:
        return {"started": False}
    t = getattr(p.listener, "_thread", None)
    return {"started": True, "queued": p.queue.qsize(), "queue_max": p.queue.maxsize, "dropped": p.dropped,
            "closed": p.closed, "listener_alive": bool(t and t.is_alive())}


def _on_signal(sig, frame):
    shutdown_logging()


def _install_shutdown_hooks():
    atexit.register(shutdown_logging)            # fin normale du programme (atexit passe en dernier => logs finaux gardés)
    if not LOG_SIGNAL_HOOK:
        return
    try:                                         # Ctrl+C / SIGTERM : via TON signal_manager (process principal seulement)
        import multiprocessing as mp
        if mp.parent_process() is None:
            from modules_utils.signal_manager import signal_manager
            signal_manager(_on_signal)
    except Exception:
        pass                                     # hors thread principal / module absent : atexit prend le relais


def _get_pipeline() -> _Pipeline:
    global _PIPELINE
    p = _PIPELINE
    if p is None:
        with _PIPELINE_LOCK:
            if _PIPELINE is None:
                _PIPELINE = _Pipeline()
                _install_shutdown_hooks()
            p = _PIPELINE
    return p


def _after_fork_in_child():
    """Un fork ne copie pas les threads : le listener du parent n'existe plus. On repart d'un pipeline neuf."""
    global _PIPELINE, _PIPELINE_LOCK
    _PIPELINE_LOCK = threading.Lock()
    _PIPELINE = None
    for lg in list(_LOGGER_REGISTRY.values()):
        lg._attach_queue_handler(force=True)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


# ==================== LOGGER INDÉPENDANT ====================
class Logger:
    """Logger indépendant avec détection automatique du niveau."""

    def __init__(self, module_name: str, log_dir: Optional[Path] = None, structured: bool = True):
        self.module_name = module_name

        if log_dir is None:
            log_dir = get_default_log_dir()

        self.log_dir = log_dir / module_name
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(f"module_{module_name}")
        self.logger.setLevel(LOG_DEFAULT_LEVEL)
        self.logger.handlers.clear()
        self.logger.propagate = False
        self.structured = structured

        self.logger.addFilter(ModuleNameFilter(module_name))
        self._setup_handlers()
        self.logger.debug(f"Logger initialisé pour '{module_name}' dans {self.log_dir}")

    def _setup_handlers(self):
        self._attach_queue_handler()

    def _detach_queue_handlers(self):
        for h in [h for h in self.logger.handlers if isinstance(h, _DropQueueHandler)]:
            self.logger.removeHandler(h)

    def _attach_queue_handler(self, force: bool = False):
        """Un seul handler par module : il dépose les messages dans la file commune (console + fichiers = listener)."""
        if not force and any(isinstance(h, _DropQueueHandler) for h in self.logger.handlers):
            return
        self._detach_queue_handlers()
        self.logger.addHandler(_DropQueueHandler(_get_pipeline()))

    def _detect_level(self, message: str) -> int:
        """Détecte le niveau via regex compilés — ordre : SUCCESS avant ERROR
        pour gérer les messages du type 'Erreur corrigée avec succès'."""
        if _SUCCESS_RE.search(message):
            return SUCCESS_LEVEL_NUM
        if _ERROR_RE.search(message):
            return logging.ERROR
        if _WARNING_RE.search(message):
            return logging.WARNING
        if _DEBUG_RE.search(message):
            return logging.DEBUG
        return logging.INFO


    # ── API publique ─────────────────────────────────────────────────────────

    def print(self, *args, **kwargs):
        message = ' '.join(str(a) for a in args)
        verify  = kwargs.get('verify', True)
        extra   = kwargs.get('extra', {})
        level   = self._detect_level(message) if verify else logging.INFO
        self.logger.log(level, message, **({"extra": extra} if extra else {}))

    def debug(self, message, *args, extra=None, **kwargs):
        self.logger.debug(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def info(self, message, *args, extra=None, **kwargs):
        self.logger.info(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def success(self, message, *args, extra=None, **kwargs):
        self.logger.success(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def warning(self, message, *args, extra=None, **kwargs):
        self.logger.warning(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def error(self, message, *args, extra=None, **kwargs):
        self.logger.error(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def critical(self, message, *args, extra=None, **kwargs):
        self.logger.critical(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def exception(self, message, *args, extra=None, **kwargs):
        self.logger.exception(message, *args, **({"extra": extra} if extra else {}), **kwargs)

    def get_logger(self):
        return self.logger

    def setup(self, level: Union[str, int] = "DEBUG", structured: bool = None):
        if level is not None:
            if isinstance(level, str):
                level = getattr(logging, level.upper(), logging.DEBUG)
            self.logger.setLevel(level)      # coupe AVANT la file : un message sous ce niveau ne coûte presque rien

        if structured is not None:
            self.structured = bool(structured)

        _MUTED_CONSOLE.discard(self.module_name)   # comme avant : setup() recrée la console
        self._attach_queue_handler()
        return self

    def remove_handlers(self, all_handlers: bool = False):
        """False : coupe la console de ce module (les fichiers continuent). True : ce module ne sort plus nulle part."""
        if all_handlers:
            self._detach_queue_handlers()
        else:
            _MUTED_CONSOLE.add(self.module_name)

    def remove(self, all_handlers: bool = False):
        self.remove_handlers(all_handlers)


# ==================== REGISTRY ====================
_LOGGER_REGISTRY: dict[str, Logger] = {}
_DEFAULT_LOG_DIR: Optional[Path] = None


def get_default_log_dir() -> Path:
    global _DEFAULT_LOG_DIR
    if _DEFAULT_LOG_DIR is not None:
        return _DEFAULT_LOG_DIR
    mode = os.environ.get('OBSIDIAN_MODE', 'dev').lower()
    if mode == 'prod':
        _DEFAULT_LOG_DIR = Path('/var/log/obsidian')
    else:
        _DEFAULT_LOG_DIR = Path(LOGDIR).parent / 'logs'
    return _DEFAULT_LOG_DIR


def set_default_log_dir(log_dir: Union[str, Path], reconfigure_existing: bool = True):
    global _DEFAULT_LOG_DIR
    _DEFAULT_LOG_DIR = Path(log_dir)
    _DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    if reconfigure_existing and _LOGGER_REGISTRY:
        for module_name, lg in _LOGGER_REGISTRY.items():
            lg.log_dir = _DEFAULT_LOG_DIR / module_name
            lg.log_dir.mkdir(parents=True, exist_ok=True)
            p = _PIPELINE
            if p is not None:
                for r in p.routers:
                    r.reset(module_name)         # les fichiers se rouvriront dans le nouveau dossier
            lg.setup(lg.logger.level, lg.structured)
    return _DEFAULT_LOG_DIR


def get_logger(module_name: str, log_dir: Optional[Union[str, Path]] = None, structured: bool = True) -> Logger:
    if module_name in _LOGGER_REGISTRY:
        return _LOGGER_REGISTRY[module_name]
    if log_dir is not None:
        log_dir = Path(log_dir)
    lg = Logger(module_name, log_dir, structured)
    _LOGGER_REGISTRY[module_name] = lg
    return lg


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


def setup_logger(
    module_name: str,
    level: Union[str, int] = None,
    structured: bool = None,
    log_dir: Optional[Union[str, Path]] = None
) -> Logger:
    lg = get_logger(module_name, log_dir, structured)
    if level is not None:
        lg.setup(level=level, structured=lg.structured)
    return lg


# ==================== EXPORTS ====================
__all__ = [
    'get_logger', 'setup_logger', 'remove_all_handlers',
    'set_default_log_dir', 'list_loggers', 'get_logger_registry',
    'Logger', 'SUCCESS_LEVEL_NUM', 'shutdown_logging', 'get_log_stats',
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

    print(f"\nLoggers actifs : {list_loggers()}")