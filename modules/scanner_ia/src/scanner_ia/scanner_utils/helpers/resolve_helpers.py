#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 20 21:47:25 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from pydantic import BaseModel, Field
import scanner_ia.scanner_utils.helpers.helpers_registry as registry

class HelperCall(BaseModel):
    """
    Représente un appel de helper sérialisable en JSON.
 
    Exemples :
        {"name": "dvwa_auth",       "kwargs": {"base_url": "http://localhost:8080"}}
        {"name": "form_login",      "kwargs": {"login_url": "...", "username": "a", "password": "b"}}
        {"name": "bearer_token",    "kwargs": {"token": "eyJ..."}}
        {"name": "inject_cookies",  "kwargs": {"cookies": {"PHPSESSID": "abc"}}}
        {"name": "noop"}   ← site sans auth
    """
    name: str = Field(..., description="Nom du helper (voir GET /api/helpers)")
    args: list  = Field(default_factory=list,  description="Arguments positionnels (rare)")
    kwargs: dict = Field(default_factory=dict, description="Arguments nommés JSON-sérialisables")

def create_helpers_call(helper_calls: list[dict]) -> list[HelperCall]:
    return [
        HelperCall(
            name=helper.get("name", "noop"),
            args=helper.get("args", []),
            kwargs=helper.get("kwargs", {}),
        ) for helper in helper_calls
    ]

def resolve_helpers(helper_calls: list[HelperCall] | list[dict]) -> list:
    resolved = []
    if not helper_calls:
        return []
    
    if isinstance(helper_calls[0], dict):
        helper_calls = create_helpers_call(helper_calls)
    for h in helper_calls:
        try:
            func = registry.get(h.name)
            resolved.append([func, h.args, h.kwargs])
        except KeyError as e:
            raise e
    return resolved
