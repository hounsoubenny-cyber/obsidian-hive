#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 07:20:48 2026

@author: hounsousamuel
"""

import os
from dotenv import load_dotenv
from fastapi import Request
from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.assets.asset_types import ServerAsset
from obsidian_hive.api.state import _get_contextguard_client
from obsidian_hive.api.ap_config import CHECK_PROMPT_KEY
from contextguard.sdk.models import AnalyseResponse

async def _get_asset_by_valid_install_token(engine: ObsidianEngine, token: str) -> ServerAsset | None:
    if not token or not ServerAsset.is_server_asset_token(token):
        return None
    asset_db = await engine.asset_manager.get_server_asset_by_install_token(token)
    if not asset_db:
        return None
    asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset_db)
    if not asset.is_install_token_valid(token):
        return None
    return asset

def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    return token or None

def get_extension_token_manager(request: Request):
    """Récupère l'instance ExtensionTokenManager depuis l'état de l'application.

    Args:
        request (Request): La requête FastAPI en cours.

    Returns:
        ExtensionTokenManager: L'instance partagée, instanciée dans le lifespan.
    """
    return request.app.state.extension_token_manager

async def check_prompt(prompt: str, threshold: float = 0.5) -> tuple[bool | None, AnalyseResponse | None]:
    """
    Analyse un prompt via ContextGuard.

    Returns
    -------
    tuple[bool | None, AnalyseResponse | None]
        - (True,  resp)  : prompt safe
        - (False, resp)  : prompt dangereux
        - (None,  resp)  : ContextGuard indisponible → fail-open côté appelant
    """
    from obsidian_hive.api.main_api import logger
    try:
        client = await _get_contextguard_client()
        if not client.connected:
            conn = await client.connect_async(intelligent=True)
            if not conn.success:
                logger.info(f"ContextGuard : connexion impossible — {conn.errors}")
                return None, None
        result = await client.analyse_async(
            prompts=[prompt],
            thresholds=[threshold],
            auto_recover=True,
        )
        if result.success and prompt in result.results:
            return result.results[prompt].is_safe, result
        logger.warning(f"ContextGuard : réponse incohérente pour prompt={prompt[:60]!r}")
        return None, result
    except Exception as e:
        logger.error("Erreur check_prompt :", e)
        return None, None

def can_check_prompt():
    load_dotenv()
    
    c = os.environ.get(CHECK_PROMPT_KEY, None)
    if c is None:
        return False
    c = str(c).strip().lower()
    if c in ("1", "true"):
        return True
    return False

def activate_prompt_checking():
    os.environ[CHECK_PROMPT_KEY] = "1"
    return True

def deactivate_prompt_checking():
    os.environ[CHECK_PROMPT_KEY] = "0"
    return True
    
    