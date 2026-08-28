#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 07:20:48 2026

@author: hounsousamuel
"""

from fastapi import Request
from obsidian_hive.core.assets.asset_types import ServerAsset
from obsidian_hive.core.engine import ObsidianEngine

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