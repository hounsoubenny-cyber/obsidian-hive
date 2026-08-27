#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système de logging avancé avec instances indépendantes
Auteur: Hounsou Samuel
"""

import os
import re
import sys
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
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()
        self.logger.propagate = False
        self.structured = structured

        self.logger.addFilter(ModuleNameFilter(module_name))
        self._setup_handlers()
        self.logger.debug(f"Logger initialisé pour '{module_name}' dans {self.log_dir}")

    def _setup_handlers(self):
        # Console (thread-safe)
        console_handler = ThreadSafeStreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)

        # Fichier JSON structuré
        if self.structured:
            log_file = self.log_dir / f"{self.module_name}.json"
            fh = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=100*1024*1024, backupCount=30, encoding='utf-8'
            )
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(JsonFormatter())
            self.logger.addHandler(fh)

        # Fichier texte lisible
        log_file = self.log_dir / f"{self.module_name}.log"
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=100*1024*1024, backupCount=30, encoding='utf-8'
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(module_name)s | "
            "%(filename)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(fh)

        # Fichier erreurs uniquement
        error_file = self.log_dir / f"errors_{self.module_name}.log"
        eh = logging.handlers.RotatingFileHandler(
            error_file, maxBytes=50*1024*1024, backupCount=90, encoding='utf-8'
        )
        eh.setLevel(logging.ERROR)
        eh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(module_name)s | "
            "%(filename)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(eh)

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
            self.logger.setLevel(level)
            for handler in self.logger.handlers:
                handler.setLevel(level)

        if structured is not None:
            self.structured = bool(structured)

        old = self.logger.handlers[:]
        self.logger.handlers.clear()
        for h in old:
            h.close()
        self._setup_handlers()
        return self

    def remove_handlers(self, all_handlers: bool = False):
        to_remove = [
            h for h in self.logger.handlers
            if all_handlers or h.__class__.__name__ in ("ThreadSafeStreamHandler", "StreamHandler")
        ]
        for h in to_remove:
            self.logger.removeHandler(h)
            h.close()

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
            lg.log_dir = _DEFAULT_LOG_DIR
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
    'Logger', 'SUCCESS_LEVEL_NUM',
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