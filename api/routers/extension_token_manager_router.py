#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 07:04:35 2026

@author: hounsousamuel
"""

"""
Routes admin (dashboard) pour créer/lister/révoquer les tokens d'extension
navigateur.
"""

from fastapi import APIRouter, Request, HTTPException, status

from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE
from obsidian_hive.api.api_utils.helpers import get_extension_token_manager
from obsidian_hive.api.models.extension_token_models import (
    CreateExtensionTokenRequest,
    ExtensionTokenPublic,
    CreateExtensionTokenResponse,
    RevokeExtensionTokenResponse,
)

router = APIRouter()

def _to_public(row) -> ExtensionTokenPublic:
    """Convertit une ligne ExtensionTokenDB en représentation publique (sans hash).

    Args:
        row (ExtensionTokenDB): La ligne brute issue du manager.

    Returns:
        ExtensionTokenPublic: La version exposable côté dashboard.
    """
    return ExtensionTokenPublic(
        token_id=row.token_id,
        label=row.label,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        revoked=row.revoked,
        revoked_at=row.revoked_at,
    )


@router.post("/", response_model=CreateExtensionTokenResponse)
@limiter.limit(f"{LIMITE}/minute")
async def create_extension_token(request: Request, data: CreateExtensionTokenRequest):
    """Crée un nouveau token d'extension navigateur.

    Le token complet n'est retourné qu'une seule fois, à cet instant précis —
    il n'est jamais récupérable ensuite (seul le hash est conservé en base).

    Args:
        request (Request): La requête FastAPI (requis par le rate limiter).
        data (CreateExtensionTokenRequest): Le label du nouveau token.

    Returns:
        CreateExtensionTokenResponse: Le token en clair et ses métadonnées.
    """
    manager = get_extension_token_manager(request)
    row, full_token = await manager.create(data.label)
    return CreateExtensionTokenResponse(
        token=full_token,
        token_id=row.token_id,
        label=row.label,
        created_at=row.created_at,
    )


@router.get("/", response_model=list[ExtensionTokenPublic])
@limiter.limit(f"{LIMITE}/minute")
async def list_extension_tokens(request: Request, include_revoked: bool = True):
    """Liste tous les tokens d'extension enregistrés.

    Args:
        request (Request): La requête FastAPI (requis par le rate limiter).
        include_revoked (bool, optional): Inclut les tokens révoqués si True.
            Par défaut True.

    Returns:
        list[ExtensionTokenPublic]: La liste des tokens, sans secret ni hash.
    """
    manager = get_extension_token_manager(request)
    rows = await manager.list_all(include_revoked=include_revoked)
    return [_to_public(row) for row in rows]


@router.post("/{token_id}/revoke", response_model=RevokeExtensionTokenResponse)
@limiter.limit(f"{LIMITE}/minute")
async def revoke_extension_token(request: Request, token_id: str):
    """Révoque un token d'extension.

    Args:
        request (Request): La requête FastAPI (requis par le rate limiter).
        token_id (str): L'identifiant public du token à révoquer.

    Returns:
        RevokeExtensionTokenResponse: Confirmation de la révocation.

    Raises:
        HTTPException: 404 si le token n'existe pas.
    """
    manager = get_extension_token_manager(request)
    ok = await manager.revoke(token_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token introuvable")
    return RevokeExtensionTokenResponse(revoked=True, token_id=token_id)