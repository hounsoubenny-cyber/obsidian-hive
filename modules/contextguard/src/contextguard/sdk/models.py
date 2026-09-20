#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 12:01:58 2026

@author: hounsousamuel
"""

"""
ContextGuard SDK — Modèles Pydantic
====================================

Ce module regroupe tous les modèles Pydantic utilisés par le SDK
ContextGuard, répartis en deux familles :

- **Modèles d'entrée** (:class:`ConnectParams`, :class:`AnalyseParams`, ...)
  utilisés pour valider et transporter les paramètres vers l'API.
- **Modèles de sortie** (:class:`ConnectResponse`, :class:`AnalyseResponse`, ...)
  qui encapsulent les réponses de l'API avec un typage fort.

Tous les modèles de réponse héritent de :class:`SDKResponse`, qui fournit
une **double interface** :

- Accès par attribut typé (``resp.success``, ``resp.token``...)
- Accès par clé, comme un dictionnaire (``resp["success"]``, ``resp.get(...)``)

Ainsi que les méthodes usuelles (``keys()``, ``values()``, ``items()``).

Auteur : HOUNSOU Samuel Benny
Version : 2.0.0
"""

from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict, Field
from contextguard.api.config import SAFE_CLASSE

from contextguard.api.utils import (  # noqa: E402
    USERNAME_NOT_AVAILABLE_REASON,
    TOKEN_USURPATION_DETAIL,
    VERIFY_CONNECT_ERROR,
    TOKEN_EXPIRED_DETAIL,
    USER_NOT_REGISTERED_REASON,
)


# ═══════════════════════════════════════════════════════════
# Base commune : double interface dict + attributs typés
# ═══════════════════════════════════════════════════════════

class SDKResponse(BaseModel):
    """
    Classe de base pour toutes les réponses du SDK.

    Fournit une **double interface** :

    - Accès par attribut (Pydantic) : ``resp.success``
    - Accès par clé (dict-like) : ``resp["success"]``
    - Méthodes dict : ``keys()``, ``values()``, ``items()``, ``get()``
    - Conversion : ``to_dict()``

    Examples
    --------
    >>> resp = ConnectResponse(success=True, token="abc", username="alice")
    >>> resp.success                      # attribut typé
    True
    >>> resp["success"]                   # accès dict
    True
    >>> "token" in resp                   # test d'appartenance
    True
    >>> list(resp.keys())                 # clés
    ['errors', 'status_code', 'success', ...]
    """

    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in type(self).model_fields:
            raise KeyError(f"Champ inconnu : {key!r}")
        setattr(self, key, value)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in type(self).model_fields

    def __iter__(self) -> Iterator[str]:
        return iter(type(self).model_fields)

    def keys(self) -> list[str]:
        return list(type(self).model_fields.keys())

    def values(self) -> list[Any]:
        return [getattr(self, k) for k in type(self).model_fields]

    def items(self) -> list[tuple[str, Any]]:
        return [(k, getattr(self, k)) for k in type(self).model_fields]

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def __repr__(self) -> str:
        fields = ", ".join(
            f"{k}={v!r}" for k, v in self.items()
            if v not in (None, [], {}, "")
        )
        return f"{self.__class__.__name__}({fields})"


# ═══════════════════════════════════════════════════════════
# Modèles d'entrée
# ═══════════════════════════════════════════════════════════

class ConnectParams(BaseModel):
    """
    Paramètres pour :meth:`ContextGuardClient.connect`.

    Attributes
    ----------
    username : str | None
    password : str | None
    salt : str | None
        Ignoré par le serveur, conservé pour compat.
    connect : bool | None
        - ``True``  → connexion uniquement
        - ``False`` → création uniquement
        - ``None``  → comportement intelligent (login-first)
    """

    username: str | None = None
    password: str | None = None
    connect: bool | None = None


class AnalyseParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.analyse`."""

    username: str | None = None
    password: str | None = None
    token: str | None = None
    prompts: list[str] = Field(default_factory=list)
    thresholds: list[float] = Field(default_factory=list)


class RefreshParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.refresh_token`."""

    username: str | None = None
    token: str | None = None


class HealthParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.health`."""

    username: str | None = None
    password: str | None = None
    token: str | None = None


class SaltParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.get_salt` (aucun requis)."""


class LogoutParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.logout`."""

    username: str | None = None
    token: str | None = None


class DeleteAccountParams(BaseModel):
    """Paramètres pour :meth:`ContextGuardClient.delete_account`."""

    username: str | None = None
    password: str | None = None
    token: str | None = None


# ═══════════════════════════════════════════════════════════
# Modèles de sortie
# ═══════════════════════════════════════════════════════════

class ConnectResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.connect`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    state: str | None = None
    username: str | None = None
    token: str | None = None
    reason: str = ""


class AnalyseItem(SDKResponse):
    """
    Résultat d'analyse d'un prompt unique.

    Attributes
    ----------
    label : str
        ``"safe"``, ``"injection"``, ``"jailbreak"`` ou ``"exfiltration"``.
    prob : float
        Probabilité associée au label (0..1).
    threshold : float
        Seuil utilisé pour la décision.
    """

    label: str = ""
    prob: float = 0.0
    threshold: float = 0.5

    @property
    def is_safe(self) -> bool:
        """``True`` si le label est ``safe``."""
        return str(self.label).lower() == SAFE_CLASSE


class AnalyseResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.analyse`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    token: str | None = None
    results: dict[str, AnalyseItem] = Field(default_factory=dict)
    history_updated: bool = False


class RefreshResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.refresh_token`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    token: str | None = None


class HealthResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.health`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    username: str | None = None
    num_analyse: int = 0
    stats: dict[str, int] = Field(default_factory=dict)
    history: dict[str, str] = Field(default_factory=dict)


class SaltResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.get_salt`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    salt: str | None = None
    datetime: str | None = None


class LogoutResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.logout`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    username: str | None = None
    message: str = ""


class DeleteAccountResponse(SDKResponse):
    """Réponse de :meth:`ContextGuardClient.delete_account`."""

    errors: list[str] = Field(default_factory=list)
    status_code: int | None = None
    success: bool = False
    username: str | None = None
    message: str = ""



__all__ = [
    # Base
    "SDKResponse",
    # Constantes réexportées depuis api.utils
    "USERNAME_NOT_AVAILABLE_REASON",
    "TOKEN_USURPATION_DETAIL",
    "VERIFY_CONNECT_ERROR",
    "TOKEN_EXPIRED_DETAIL",
    "USER_NOT_REGISTERED_REASON",
    # Params (input)
    "ConnectParams",
    "AnalyseParams",
    "RefreshParams",
    "HealthParams",
    "SaltParams",
    "LogoutParams",
    "DeleteAccountParams",
    # Responses (output)
    "ConnectResponse",
    "AnalyseResponse",
    "AnalyseItem",
    "RefreshResponse",
    "HealthResponse",
    "SaltResponse",
    "LogoutResponse",
    "DeleteAccountResponse",
]