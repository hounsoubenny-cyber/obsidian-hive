#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 09:40:04 2026

@author: hounsousamuel
"""

from functools import wraps
from obsidian_hive.core.assets.asset_types import Severity


def risk(level: Severity | str):
    """Marque le niveau de risque d'un tool. Défaut fail-closed géré côté
    tool_risk() (Severity.HIGH si le décorateur est absent), donc ce
    décorateur sert surtout à DESCENDRE le risque explicitement pour les
    tools jugés sûrs — pas à le déclarer pour les tools sensibles, qui
    restent 'high' par défaut même sans y penser."""
    level = Severity(level)
    
    def decorator(func):
        func.__risk__ = level.value
        return func
    return decorator


def confirmation(required: bool = True):
    """Marque si ce tool exige une confirmation humaine avant exécution.
    Même logique fail-closed : par défaut (décorateur absent), un tool
    exige confirmation. Ce décorateur sert surtout à explicitement
    DÉSACTIVER la confirmation pour les tools jugés inoffensifs
    (get_system_info, read_log...)."""
    def decorator(func):
        func.__need_confirmation__ = required
        return func
    return decorator


def tool_policy(risk_level: Severity | str = Severity.HIGH, need_confirmation: bool = True):
    """Raccourci pour poser les deux d'un coup — équivalent à empiler
    @risk(...) et @confirmation(...), pratique quand tu déclares beaucoup
    de tools d'affilée."""
    
    def decorator(func):
        func = risk(risk_level)(func)
        func = confirmation(need_confirmation)(func)
        return func
    return decorator

