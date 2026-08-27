#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 15 08:37:54 2026

@author: hounsousamuel
"""


import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from pathlib import Path
from typing import Optional, Union

from modules_utils.logger import (
    get_logger as _get_logger,
    setup_logger as _setup_logger,
    remove_all_handlers as _remove_all_handlers,
    Logger,
    set_default_log_dir as _set_default_log_dir,
    list_loggers as _list_loggers,
    get_logger_registry as _get_registry
)

MODULE_NAME = "trust_signal"
STRUCTURED = True  
LOG_DIR: Optional[Union[str, Path]] = None

def get_logger(*args, **kwargs):
    """
    Retourne le logger du module trust_signal
    
    Returns:
        Logger: Instance du logger trust_signal
    """
    return _get_logger(
        module_name=MODULE_NAME,
        log_dir=LOG_DIR,
        structured=STRUCTURED,
    )


def setup_logger(
    logger: Optional[Logger] = None,
    level: Optional[str] = None,
    structured: Optional[bool] = None,
    *args,
    **kwargs
):
    """
    Configure le logger du module trust_signal
    
    Args:
        logger: Logger existant (si None, crée un nouveau)
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        structured: Format structuré (JSON) si True
    
    Returns:
        Logger: Logger configuré
    """
    
    if structured is None:
        structured = STRUCTURED
    
    if logger:
        return logger.setup(
            level=level or logger.logger.level,
            structured=structured
        )
    
    return _setup_logger(
        module_name=MODULE_NAME,
        level=level,
        structured=structured,
        log_dir=LOG_DIR,
    )


def remove_all_handlers(
    logger: Optional[Logger] = None,
    module_name: Optional[str] = None,
    all_handlers: bool = False,
    *args,
    **kwargs
):
    """
    Supprime les handlers d'un logger
    
    Args:
        logger: Logger spécifique (si None, utilise celui du module)
        module_name: Nom du module (si logger None)
        all_handlers: Si True, supprime TOUS les handlers
    
    Returns:
        None
    """
    if logger:
        return logger.remove_handlers(all_handlers=all_handlers)
    
    if module_name is None:
        module_name = MODULE_NAME
    
    return _remove_all_handlers(
        module_name=module_name,
        all_handlers=all_handlers,
    )


def set_log_dir(log_dir: Union[str, Path], reconfigure_existing: bool = True):
    """
    Change le dossier des logs.
    
    Args:
        log_dir: Nouveau dossier
        reconfigure_existing: Reconfigurer les loggers existants
    
    Returns:
        Path: Le nouveau dossier
    """
    global LOG_DIR
    LOG_DIR = Path(log_dir)
    return _set_default_log_dir(LOG_DIR, reconfigure_existing)


def get_logger_registry():
    """Retourne le registre des loggers"""
    return _get_registry()


def list_loggers():
    """Liste tous les loggers actifs"""
    return _list_loggers()


__all__ = [
    'get_logger',
    'setup_logger',
    'remove_all_handlers',
    'set_log_dir',
    'list_loggers',
    'get_logger_registry',
    'MODULE_NAME',
    'STRUCTURED',
    'LOG_DIR',
    'Logger'
]


if __name__ == "__main__":
    # Tester le logger trust_signal
    logger = get_logger()
    logger.print("Démarrage de trust_signal")
    logger.info("trust_signal initialisé")
    logger.setup(level='DEBUG')
    logger.debug("Mode debug activé")
    
    print(f"\n✅ Logger '{MODULE_NAME}' configuré")
    print(f"   Dossier: {logger.log_dir}")
    print(f"   Structuré: {STRUCTURED}")