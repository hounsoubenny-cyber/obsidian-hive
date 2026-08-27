#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 13:55:45 2026

@author: hounsousamuel
"""

import os
import json5
import tempfile
from typing import Optional

class ConfigError(Exception):
    pass

def deep_merge(default: dict, override: dict, max_depth: int = 10, _depth: int = 0) -> dict:
    """Fusionne récursivement deux dictionnaires, avec une profondeur maximale.

    Pour chaque clé, si la valeur existe dans les deux dicts et que les deux
    sont des dict, fusionne récursivement. Sinon, la valeur de `override`
    remplace celle de `default`. Au-delà de `max_depth`, la valeur de
    `override` remplace celle de `default` sans fusion supplémentaire
    (protection contre une config imbriquée à l'infini).

    Args:
        default (dict): Le dictionnaire de base.
        override (dict): Le dictionnaire dont les valeurs priment.
        max_depth (int, optional): Profondeur maximale de récursion. Par défaut 10.
        _depth (int, optional): Profondeur actuelle (usage interne, ne pas fournir).

    Returns:
        dict: Le dictionnaire fusionné (nouveau dict, ne modifie pas les entrées).
    """
    if _depth >= max_depth:
        return {**default, **override}

    result = dict(default)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value, max_depth=max_depth, _depth=_depth + 1)
        else:
            result[key] = value
    return result

def validate_and_merge_config(
    user_config_str: str, 
    default_config_path: str,
    config_temp_dir:str,
    id:str,
    max_size: int = 20 * 1024,
    write_path: str | None = None,
    check_size: bool = True,
) -> Optional[str]:
    """
    Valide et fusionne la config utilisateur avec la config par défaut.
    
    Args:
        user_config_str: JSON5 string de l'utilisateur
        default_config_path: chemin vers la config par défaut
        max_size: taille max autorisée
    
    Returns:
        Chemin du fichier temporaire, ou None si aucune config utilisateur
    
    Raises:
        ConfigError: si la config est invalide
    """
    
    if not user_config_str:
        return None
    
    if check_size and len(user_config_str) > max_size:
        raise ConfigError(
            f"Configuration trop volumineuse: {len(user_config_str)} > {max_size} bytes"
        )
    
    try:
        user_config = json5.loads(user_config_str)
    except (ValueError, OSError) as e:
        raise ConfigError(f"JSON5 invalide: {e}")
    
    if not isinstance(user_config, dict):
        raise ConfigError("La configuration doit être un objet JSON")
    
    try:
        with open(default_config_path, "r") as f:
            default_config = json5.load(f)
    except Exception as e:
        raise ConfigError(f"Impossible de charger la config par défaut: {e}")
    
    merged = deep_merge(default_config, user_config)
    os.makedirs(config_temp_dir, exist_ok=True)
    
    if write_path:
        with open(write_path, "w") as f:
            json5.dump(merged, f, indent=2)
        return write_path
    
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json5',
        prefix=f"{id}_",
        dir=config_temp_dir,
        delete=False,
    ) as tmp:
        json5.dump(merged, tmp, indent=2)
        tmp_path = tmp.name
    
    return tmp_path

