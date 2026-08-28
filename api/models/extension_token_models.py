#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 07:04:03 2026

@author: hounsousamuel
"""

"""
Modèles Pydantic pour la gestion des tokens d'extension navigateur (dashboard admin).
"""

from datetime import datetime
from pydantic import BaseModel, Field


class CreateExtensionTokenRequest(BaseModel):
    """Requête de création d'un nouveau token d'extension.

    Attributes:
        label (str): Nom donné au token par l'admin (ex: "Chrome - PC bureau").
    """
    label: str = Field(..., min_length=1, max_length=100, description="Nom du token (ex: 'Chrome - PC bureau')")


class ExtensionTokenPublic(BaseModel):
    """Représentation publique d'un token — jamais le secret ni le hash.

    Attributes:
        token_id (str): Identifiant public du token.
        label (str): Nom donné au token.
        created_at (datetime): Date de création.
        last_used_at (datetime | None): Dernière utilisation.
        revoked (bool): True si révoqué.
        revoked_at (datetime | None): Date de révocation.
    """
    token_id: str
    label: str
    created_at: datetime
    last_used_at: datetime | None
    revoked: bool
    revoked_at: datetime | None


class CreateExtensionTokenResponse(BaseModel):
    """Réponse à la création — contient le token en clair, une seule fois.

    Attributes:
        token (str): Le token complet "token_id.secret", à copier immédiatement.
        token_id (str): Identifiant public (pour un futur revoke).
        label (str): Nom donné au token.
        created_at (datetime): Date de création.
    """
    token: str = Field(..., description="Token complet 'token_id.secret' — jamais réaffiché après cet appel")
    token_id: str
    label: str
    created_at: datetime


class RevokeExtensionTokenResponse(BaseModel):
    """Réponse à une révocation de token.

    Attributes:
        revoked (bool): True si la révocation a réussi.
        token_id (str): L'identifiant du token concerné.
    """
    revoked: bool
    token_id: str