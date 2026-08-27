#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 09:41:48 2026

@author: hounsousamuel
"""


import typing
import inspect

def get_primitive_types(annotation):
    origin = typing.get_origin(annotation)

    if origin is None:
        # Type "simple" (pas générique)
        if annotation is type(None):
            return ["none"]
        return [annotation.__name__]

    # Type générique (Union, Optional, List, Dict, ...)
    result = []
    for arg in typing.get_args(annotation):
        result.extend(get_primitive_types(arg))
    return result


def infer_input_type(annotation, types, name):
    origin = typing.get_origin(annotation)
    
    # Extraire le type réel si c'est un Optional/Union
    if origin is typing.Union:
        # Récupérer les vrais types (ignorer NoneType)
        args = typing.get_args(annotation)
        non_none_args = [arg for arg in args if arg is not type(None)]
        if non_none_args:
            # Prendre le premier type non-None (dans le cas d'un Optional)
            annotation = non_none_args[0]
            origin = typing.get_origin(annotation)
            # Mettre à jour les types aussi
            types = get_primitive_types(annotation) if annotation else types
    
    # Détection dict/list par ORIGIN, pas par les types internes
    if origin is dict or annotation is dict:
        return "json"
    if origin in (list, set, tuple) or annotation in (list, set, tuple):
        return "list"
    
    if "bool" in types:
        return "boolean"
    if "int" in types:
        return "number"
    if "float" in types:
        return "float"
    if "str" in types:
        tokens = name.lower().split("_")
        if any(tok in ("url", "uri", "link") for tok in tokens):
            return "url"
        return "text"
    return "text"


def get_func_kwargs(func, exclude = None):
    sig = inspect.signature(func)
    exclude = exclude or []
    required_value = "REQUIRED_ARG"
    kwargs = {}

    for k, v in sig.parameters.items():
        if any(c in exclude for c in (k, v.name)):
            continue

        default = v.default if v.default != inspect._empty else required_value
        name = v.name
        annotation = v.annotation if v.annotation != inspect._empty else None

        types = get_primitive_types(annotation) if annotation else ["any"]

        kwargs[k] = {
            "name": name,
            "default": default,
            "type": types,
            "input_type": infer_input_type(annotation, types, name),
        }

    return kwargs