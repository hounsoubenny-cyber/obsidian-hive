#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 16:50:07 2026

@author: hounsousamuel
"""

"""
Helper Registry pour ShieldAI
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import importlib
import inspect
import typing
from typing import Dict, List, Callable, Awaitable, Any

# =============================================================================
# REGISTRY - Le grand dictionnaire
# =============================================================================

HELPERS_REGISTRY: Dict[str, Callable[..., Awaitable[bool]]] = {}


def register(name: str, func: Callable[..., Awaitable[bool]]) -> None:
    """Enregistre un helper dans le registre."""
    HELPERS_REGISTRY[name] = func


def get(name: str) -> Callable[..., Awaitable[bool]]:
    """Récupère un helper par son nom."""
    if name not in HELPERS_REGISTRY:
        raise KeyError(f"Helper '{name}' non trouvé")
    return HELPERS_REGISTRY[name]


def has(name: str) -> bool:
    """Vérifie si un helper existe."""
    return name in HELPERS_REGISTRY


def list_all() -> List[str]:
    """Retourne la liste de tous les helpers disponibles."""
    return list(HELPERS_REGISTRY.keys())

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


def _infer_input_type(annotation, types, name):
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


def _get_helper_kwargs(func):
    sig = inspect.signature(func)
    exclude = ("args", "kwargs", "session")
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
            "input_type": _infer_input_type(annotation, types, name),
        }

    return kwargs
    
def list_helpers() -> list[dict]:
    """
    Retourne la liste des helpers disponibles avec leur docstring.
    Utilisé par la route GET /helpers.
    """
    result = []
    for name, func in sorted(HELPERS_REGISTRY.items()):
        doc = (func.__doc__ or "").strip()
        # Extraire juste la première ligne de la docstring
        first_line = doc.split("\n")[0].strip() if doc else ""
        result.append(
            {
                "name": name,
                "description": first_line,
                "module": func.__module__,
                "args": _get_helper_kwargs(func)
            }
        )
    return result


def load_module(module_path: str) -> None:
    """Charge un module et enregistre automatiquement ses helpers."""
    module = importlib.import_module(module_path)
    if hasattr(module, "HELPERS"):
        for name, func in module.HELPERS.items():
            register(name, func)


def normalize(helpers_config: List[dict]) -> List[list]:
    """Transforme la config JSON en format scanner."""
    if not helpers_config:
        return [["noop", [], {}]]

    return [[h.get("name", "noop"), h.get("args", []), h.get("kwargs", {})] for h in helpers_config]


# =============================================================================
# DECORATOR
# =============================================================================


def helper(name: str = None):
    """Décorateur pour enregistrer automatiquement une fonction helper."""

    def decorator(func):
        func_name = name or func.__name__
        register(func_name, func)
        return func

    return decorator


# =============================================================================
# HELPERS PAR DÉFAUT (à importer depuis helpers.py)
# =============================================================================


def _register_default_helpers():
    """Enregistre les helpers du module helpers.py."""
    try:
        from scanner_ia.scanner_utils.helpers.auth_helpers import (
            form_login,
            csrf_form_login,
            basic_auth,
            bearer_token,
            api_key_header,
            api_key_cookie,
            inject_cookies,
            inject_headers,
            jwt_login,
            oauth2_password,
            digest_auth,
            multi_step_login,
            dvwa_auth,
            juice_shop_auth,
            webgoat_auth,
            bwapp_auth,
            mutillidae_auth,
            wordpress_auth,
            joomla_auth,
            phpmyadmin_auth,
            grafana_auth,
            jenkins_auth,
            gitlab_auth,
            gitea_auth,
            nextcloud_auth,
            portainer_auth,
            keycloak_auth,
            metabase_auth,
            awx_auth,
            roundcube_auth,
            openwrt_auth,
            pfsense_auth,
            noop,
        )
        from scanner_ia.scanner_utils.helpers.dvwa_helpers import (
            dvwa_full_setup,
            dvwa_login,
            dvwa_set_security_level,
        )

        HELPERS_REGISTRY.update(
            {
                "dvwa_login": dvwa_login,
                "dvwa_set_security_level": dvwa_set_security_level,
                "dvwa_full_setup": dvwa_full_setup,
                "form_login": form_login,
                "csrf_form_login": csrf_form_login,
                "basic_auth": basic_auth,
                "bearer_token": bearer_token,
                "api_key_header": api_key_header,
                "api_key_cookie": api_key_cookie,
                "inject_cookies": inject_cookies,
                "inject_headers": inject_headers,
                "jwt_login": jwt_login,
                "oauth2_password": oauth2_password,
                "digest_auth": digest_auth,
                "multi_step_login": multi_step_login,
                "dvwa_auth": dvwa_auth,
                "juice_shop_auth": juice_shop_auth,
                "webgoat_auth": webgoat_auth,
                "bwapp_auth": bwapp_auth,
                "mutillidae_auth": mutillidae_auth,
                "wordpress_auth": wordpress_auth,
                "joomla_auth": joomla_auth,
                "phpmyadmin_auth": phpmyadmin_auth,
                "grafana_auth": grafana_auth,
                "jenkins_auth": jenkins_auth,
                "gitlab_auth": gitlab_auth,
                "gitea_auth": gitea_auth,
                "nextcloud_auth": nextcloud_auth,
                "portainer_auth": portainer_auth,
                "keycloak_auth": keycloak_auth,
                "metabase_auth": metabase_auth,
                "awx_auth": awx_auth,
                "roundcube_auth": roundcube_auth,
                "openwrt_auth": openwrt_auth,
                "pfsense_auth": pfsense_auth,
                "noop": noop,
            }
        )
    except ImportError:
        pass  # Les helpers seront chargés plus tard


_register_default_helpers()
