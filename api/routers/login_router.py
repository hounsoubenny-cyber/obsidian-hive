#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul  4 15:44:12 2026

@author: hounsousamuel
"""

from datetime import datetime, timezone
from fastapi import (
    HTTPException, APIRouter, status,
    Request
)
from obsidian_hive.api.models.models import LoginData, RefreshTokenData
from modules_utils.api_dependencies import AuthManager
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE

router = APIRouter()


def get_auth_manager(state) -> AuthManager:
    """Retourne le gestionnaire d'authentification depuis l'état de l'application.

    Args:
        state: L'état de l'application FastAPI.

    Returns:
        AuthManager: Le gestionnaire d'authentification.
    """
    return getattr(state, "auth_manager")


@limiter.limit(f"{LIMITE}/minute")
@router.post("/auth/login")
async def login(request: Request, data: LoginData):
    """
    Authentifie un utilisateur et génère un token JWT.

    Args:
        request (Request): La requête FastAPI.
        data (LoginData): Identifiants de connexion (username, password).

    Returns:
        dict: Token d'accès JWT.

    Raises:
        HTTPException: 401 si les identifiants sont invalides.
        HTTPException: 500 en cas d'erreur interne.
    """
    try:
        from obsidian_hive.api.main_api import _get_auth_manager
        auth_manager = _get_auth_manager()
        print(data, auth_manager.passwd, auth_manager.user)
        auth_manager.verify_username(data.username)
        auth_manager.verify_password(data.password)
        token = auth_manager.create_token({"username": data.username})
        return {"access_token": token, "token_type": "bearer"}
    
    except HTTPException:
        raise
    
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e), "type": type(e).__name__}
        )


@limiter.limit(f"{LIMITE}/minute")
@router.get("/health")
async def health(request: Request):
    """
    Endpoint de santé pour vérifier l'état du moteur.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        dict: État de l'API et du moteur Obsidian.
    """
    from obsidian_hive.core.engine import ObsidianEngine
    engine: ObsidianEngine | None = getattr(request.app.state, "core_engine", None)
    if not engine:
        return {
            "status": "error", 
            "time": datetime.now(timezone.utc).isoformat(),
            "engine_status": {}
        }    
    
    return {
        "status": "ok", 
        "time": datetime.now(timezone.utc).isoformat(),
        "engine_status": {**engine.status()}
    }


@limiter.limit(f"{LIMITE}/minute")
@router.post("/token/refresh")
async def refresh_token(request: Request, data: RefreshTokenData):
    """
    Rafraîchit un token JWT avant son expiration.

    Args:
        request (Request): La requête FastAPI.
        data (RefreshTokenData): Token à rafraîchir et nom d'utilisateur.

    Returns:
        dict: Nouveau token d'accès JWT.
    """
    auth_manager = get_auth_manager(request.app.state)
    auth_manager.verify_token_without_exp_verify(data.token)
    auth_manager.verify_username(data.username)
    token = auth_manager.create_token({"username": data.username})
    return {"access_token": token, "token_type": "bearer"}