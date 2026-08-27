#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 11:04:37 2026

@author: hounsousamuel
"""

import os
import time
import functools
import difflib
import asyncio

def timer(func):
    """
    Décorateur qui mesure le temps d'exécution et l'ajoute au résultat.
    """
    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = await func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            
            if isinstance(result, dict):
                result["execution_time"] = elapsed
            elif hasattr(result, "__dict__"):
                result.execution_time = elapsed
            
            return result
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            
            if isinstance(result, dict):
                result["execution_time"] = elapsed
            elif hasattr(result, "__dict__"):
                result.execution_time = elapsed
            
            return result
    
    return wrapper

def _compute_diff(path: str, original_lines: list[str], new_lines: list[str]) -> str:
    path = str(path).lstrip("/")
    return "".join(difflib.unified_diff(
        original_lines, new_lines,
        fromfile=f"a/{path}", tofile=f"b/{path}"
    ))

def _get_allowed_roots() -> list[str]:
    """
    Dossiers dans lesquels Alex a le droit de lire/écrire.
    Fail-closed : si rien n'est configuré, AUCUN accès fichier n'est permis.
    """
    from obsidian_hive.agents.config import OBSIDIAN_SANDBOX_ROOTS
    return [os.path.realpath(r) for r in OBSIDIAN_SANDBOX_ROOTS]

def _validate_confined(path: str) -> str:
    if not _get_allowed_roots():
        raise RuntimeError(
            "OBSIDIAN_SANDBOX_ROOTS non configuré — accès fichier bloqué "
            "par défaut tant qu'aucun périmètre n'est explicitement défini."
        )
    real = os.path.realpath(path)
    if not any(real == root or real.startswith(root + os.sep) for root in _get_allowed_roots()):
        raise ValueError(f"Accès refusé : {path!r} est hors du périmètre autorisé.")
    return path

def _validate_path(path: str, check_exists: bool = True) -> str:
    """
    Valide qu'un chemin existe et n'est pas vide.
    
    Args:
        path: Chemin à valider
        
    Returns:
        Le chemin validé
        
    Raises:
        ValueError: Si le chemin est vide ou n'existe pas
    """
    if not path:
        raise ValueError("The path is falsy")
    
    if check_exists and (not os.path.exists(path)):
        raise ValueError("This path doesn't exist")
    
    return _validate_confined(path)

