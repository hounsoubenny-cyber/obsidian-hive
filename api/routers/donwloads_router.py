#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 11 22:28:56 2026

@author: hounsousamuel
"""

import os
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import FileResponse, Response
from obsidian_hive.core.assets.asset_types import ServerAsset
from obsidian_hive.core.engine import ObsidianEngine
from modules_utils.cryto_utils import checkpw
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import (
    LIMITE, AGENT_CORE_BINARY_PATH, TOOL_ENGINE_BINARY_PATH
)
from obsidian_hive.api.api_utils.helpers import _get_asset_by_valid_install_token, _extract_bearer_token
from obsidian_hive.core.assets.server_asset.scripts.install_script import INSTALL_SCRIPT_TEMPLATE
from obsidian_hive.core.assets.server_asset.scripts.reregister_script import REREGISTER_SCRIPT_TEMPLATE

router = APIRouter()
public_router = APIRouter()


def get_engine(request: Request) -> ObsidianEngine:
    """Retourne l'instance du moteur Obsidian depuis l'état de l'application.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        ObsidianEngine: L'instance du moteur.
    """
    return request.app.state.core_engine


@limiter.limit(f"{LIMITE}/minute")
@public_router.get("/agent/tool_engine")
async def download_tool_engine(request: Request, asset_id: str, version: str = "latest"):
    """
    Télécharge le binaire tool_engine pour un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        asset_id (str): L'ID de l'asset serveur.
        version (str, optional): Version du binaire. Par défaut "latest".

    Returns:
        FileResponse: Le binaire tool_engine.

    Raises:
        HTTPException: 404 si l'asset n'existe pas ou le binaire est introuvable.
        HTTPException: 403 si l'agent n'est pas autorisé.
    """
    auth_header = request.headers.get("authorization", "")
    secret = auth_header.removeprefix("Bearer ").strip()

    engine = get_engine(request)
    asset_db = await engine.asset_manager.get_by_identifier(asset_id, first=True)
    if not asset_db:
        raise HTTPException(status_code=404, detail="Asset introuvable")
        
    asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset_db)

    if asset.is_revoked() or not asset.agent_credential_hash:
        raise HTTPException(status_code=403, detail="Agent non autorisé")
        
    if not secret or not checkpw(ServerAsset.hash_secret_input(secret), asset.agent_credential_hash.encode()):
        raise HTTPException(status_code=403, detail="Credential invalide")

    if not os.path.exists(TOOL_ENGINE_BINARY_PATH):
        raise HTTPException(status_code=404, detail="Binaire introuvable")

    return FileResponse(
        path=TOOL_ENGINE_BINARY_PATH,
        media_type="application/octet-stream",
        filename="tool_engine",
    )


@limiter.limit(f"{LIMITE}/minute")
@public_router.get("/agent/agent_core")
async def download_agent_core(request: Request, version: str = "latest"):
    """
    Télécharge le binaire agent_core (agent principal).

    Args:
        request (Request): La requête FastAPI.
        version (str, optional): Version du binaire. Par défaut "latest".

    Returns:
        FileResponse: Le binaire agent_core.

    Raises:
        HTTPException: 403 si le token est invalide.
        HTTPException: 404 si le binaire est introuvable.
    """
    engine = get_engine(request)
    token = _extract_bearer_token(request)
    asset = await _get_asset_by_valid_install_token(engine, token)
    if not asset:
        raise HTTPException(status_code=403, detail="Token invalide ou expiré")
        
    if not os.path.exists(AGENT_CORE_BINARY_PATH):
        raise HTTPException(status_code=404, detail="Binaire introuvable")
        
    return FileResponse(
        path=AGENT_CORE_BINARY_PATH,
        media_type="application/octet-stream",
        filename="obsidian-agent",
    )


# =============================================================================
# INSTALL 
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@public_router.get("/agent/install.sh")
async def get_install_script(request: Request):
    """
    Génère le script d'installation pour l'agent serveur.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        Response: Le script shell d'installation.

    Raises:
        HTTPException: 403 si le token est invalide.
    """
    engine = get_engine(request)
    token = _extract_bearer_token(request)
    asset = await _get_asset_by_valid_install_token(engine, token)
    if not asset:
        raise HTTPException(status_code=403, detail="Token invalide ou expiré")
    
    scheme = request.url.scheme               # "http" en local, "https" en vrai prod
    netloc = request.url.netloc                # host:port déjà combinés, ex: "192.168.x.x:8000"
    ws_scheme = "wss" if scheme == "https" else "ws"

    central_http_url = f"{scheme}://{netloc}"
    central_ws_url = f"{ws_scheme}://{netloc}/api/core_ws/ws/server_agent"
    script = INSTALL_SCRIPT_TEMPLATE.format(
        token=token,
        asset_id=asset.id,
        central_http_url=central_http_url,
        central_ws_url=central_ws_url,
    )
    return Response(content=script, media_type="text/x-shellscript")


@limiter.limit(f"{LIMITE}/minute")
@public_router.get("/agent/reregister.sh")
async def get_reregister_script(request: Request):
    """
    Génère le script de réenregistrement pour un asset serveur.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        Response: Le script shell de réenregistrement.

    Raises:
        HTTPException: 403 si le token est invalide.
    """
    engine = get_engine(request)
    token = _extract_bearer_token(request)
    asset = await _get_asset_by_valid_install_token(engine, token)
    if not asset:
        raise HTTPException(status_code=403, detail="Token invalide ou expiré")

    script = REREGISTER_SCRIPT_TEMPLATE.format(token=token)
    return Response(content=script, media_type="text/x-shellscript")