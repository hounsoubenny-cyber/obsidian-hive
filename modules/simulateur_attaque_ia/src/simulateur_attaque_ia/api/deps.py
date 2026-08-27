#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dépendances FastAPI.

require_auth  → utilisé par les routers /api/* (montés dans cette app)
no_auth       → utilisé par les routers /ext/* (exportés pour Obsidian)

Le router /ext/* N'EST PAS monté ici : Obsidian l'importe comme module
et y ajoute son propre layer d'auth.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from typing import Optional
from fastapi import Header, HTTPException, status, Request

from simulateur_attaque_ia.simulateur_utils.jwt_utils import verify_token
from simulateur_attaque_ia.api.routers import AUTH_DATA, JWT_KEY

async def require_auth(request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    """
    Vérifie le JWT Bearer présent dans le header Authorization.
    Lève HTTP 401 si absent ou invalide.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization manquant ou format invalide (Bearer <token>)",
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = verify_token(token, AUTH_DATA[JWT_KEY])
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token invalide : {exc}",
        )


async def no_auth() -> dict:
    """Dépendance neutre pour les routers sans auth (Obsidian)."""
    return {}
