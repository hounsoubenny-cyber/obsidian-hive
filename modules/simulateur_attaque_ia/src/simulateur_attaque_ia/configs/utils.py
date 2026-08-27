#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 11:10:30 2026

@author: hounsousamuel
"""

import os

def _get_llm_env(name: str, default, cast_to: callable = None, prefix:str = "SIMATK_"):
    if not name:
        raise ValueError("Name is required")
        
    key = prefix + name
    value = os.environ.get(key, default)
    if value is ...:
        raise RuntimeError(f"The key {key} is required but any value has find for it")
        
    if cast_to:
        value = cast_to(value)
    return value

def _get_api_keys(name: str, default, prefix:str = "SIMATK_"):
    if not name:
        raise ValueError("Name is required")
    
    i = 1
    api_keys: list[tuple[str, str]] = []
    key = prefix + name + "_" + str(i)
    val = os.environ.get(key, None)
    while val:
        val_split = val.split(",")
        if len(val_split) in (2, 3):
            if len(val_split) == 2:
                model_name, api_key = val_split
                provider = None
            else:
                model_name, provider, api_key = val_split
                provider = provider.strip()
            model_name = model_name.strip()
            api_key = api_key.strip()
            api_keys.append((model_name, provider, api_key))
        i += 1
        key = prefix + name + "_" + str(i)
        val = os.environ.get(key, None)
    
    return api_keys or default