#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul  9 09:49:30 2026

@author: hounsousamuel
"""

from pydantic import BaseModel

def entry_model(model_cls: type[BaseModel]):
    """
    Attache le modèle Pydantic qui décrit fidèlement les arguments de ce
    tool. tool_builder l'utilise pour générer un schéma JSON complet
    (enums, objets imbriqués, dicts typés...) au lieu de deviner depuis
    les type hints Python bruts, qui ne savent représenter que 6 types
    basiques.
    """
    def decorator(func):
        func.__entry_model__ = model_cls
        return func
    return decorator