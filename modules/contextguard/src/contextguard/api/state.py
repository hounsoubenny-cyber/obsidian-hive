#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 11:28:43 2026

@author: hounsousamuel
"""

"""
ContextGuard — État partagé et helpers de vérification.

- ``USERS`` est un cache de sessions en mémoire (dict + RLock).
- Le JWT est signé avec ``CONTEXTGUARD_JWT_SECRET`` (env var).
- Le salt est généré au signup, stocké en DB, mis en cache à la
  connexion, et sert **uniquement** à dériver la clé Fernet.
"""

import threading
import time
from dataclasses import dataclass
from typing import Optional

from transformers import BertTokenizer
from fastapi import HTTPException, status

from contextguard.model.onnx_utils import ONNXUtils
from contextguard.contextguard_utils.jwt_utils import verify_token
from contextguard.database.db_manager import DBManager
from contextguard.api.config import (
    CONTEXTGUARD_JWT_SECRET,
    MODEL_PATH,
    TOKENIZER_PATH,
)
from contextguard.model.model_guard import PredictWrapper, ContextGuardModel
from contextguard.api.utils import (
    VERIFY_CONNECT_ERROR,
    TOKEN_USURPATION_DETAIL,
)


# ═══════════════════════════════════════════════════════════
# Cache de sessions (dict + RLock)
# ═══════════════════════════════════════════════════════════


@dataclass
class SessionEntry:
    """Entrée de session en mémoire."""
    salt: str
    password_hash: bytes
    created_at: float
    expires_at: float | None  # None = pas d'expiration


class SessionCache:
    """
    Cache de sessions thread-safe basé sur un simple dict protégé
    par un :class:`threading.RLock`.

    Les opérations sont synchrones et très rapides — le GIL garantit
    déjà l'atomicité des accès dict simples, le lock est là pour
    sécuriser les opérations composées (get + purge d'expirés).
    """

    def __init__(self) -> None:
        self._data: dict[str, SessionEntry] = {}
        self._lock = threading.RLock()

    def set(
        self,
        username: str,
        salt: str,
        password_hash: bytes,
        ttl: float | None = None,
    ) -> None:
        """Enregistre (ou écrase) la session d'un utilisateur."""
        now = time.time()
        entry = SessionEntry(
            salt=salt,
            password_hash=password_hash,
            created_at=now,
            expires_at=now + ttl if ttl else None,
        )
        with self._lock:
            self._data[username] = entry

    def get(self, username: str) -> SessionEntry | None:
        """
        Récupère l'entrée de session.

        Retourne ``None`` si absente ou expirée (purge silencieuse).
        """
        with self._lock:
            entry = self._data.get(username)
            if entry is None:
                return None
            if entry.expires_at is not None and entry.expires_at < time.time():
                del self._data[username]
                return None
            return entry

    def delete(self, username: str) -> None:
        with self._lock:
            self._data.pop(username, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __contains__(self, username: str) -> bool:
        return self.get(username) is not None

    def __len__(self) -> int:
        return len(self._data)


USERS = SessionCache()


# ═══════════════════════════════════════════════════════════
# Singletons
# ═══════════════════════════════════════════════════════════
SESSION_TTL = 10 * 3600
_DB: Optional[DBManager] = None
_MODEL: Optional[PredictWrapper] = None
_ONNX_MODEL: Optional[ONNXUtils] = None


def get_db() -> DBManager:
    global _DB
    if not _DB:
        _DB = DBManager()
    return _DB


def get_onnx() -> ONNXUtils:
    global _ONNX_MODEL
    if not _ONNX_MODEL:
        _ONNX_MODEL = ONNXUtils()
    return _ONNX_MODEL


def get_model() -> PredictWrapper:
    global _MODEL
    if not _MODEL:
        tokenizer = BertTokenizer.from_pretrained(TOKENIZER_PATH)
        model = ContextGuardModel(
            vocab_size=tokenizer.vocab_size,
            d_model=128, max_seq_len=128,
            num_heads=4, feed_forward_factor=4,
            dropout=0.2, num_layer=3, num_classe=4,
        )
        model.load(MODEL_PATH)
        model.eval()
        _MODEL = PredictWrapper(tokenizer, model)
    return _MODEL


# ═══════════════════════════════════════════════════════════
# Vérifications
# ═══════════════════════════════════════════════════════════

def verify_username_is_avalable(name: str) -> bool:
    """``True`` si aucun utilisateur de ce nom n'existe en base."""
    try:
        db = get_db()
        users = db.get_user_by_name(name)
        return not users["user"]
    except Exception as e:
        print("Erreur dans verify_username_is_avalable :", str(e))
        return True


def verify_username(
    name: str,
    token: str,
    verify_exp: bool = True,
    verify_connect: bool = True,
) -> bool:
    """
    Vérifie qu'un utilisateur est légitime.

    Parameters
    ----------
    name : str
        Nom attendu.
    token : str
        JWT fourni par le client.
    verify_exp : bool, default True
        Contrôle l'expiration du JWT (mettre ``False`` pour le refresh).
    verify_connect : bool, default True
        - ``True``  → vérifie seulement que l'utilisateur est en session
          (présent dans ``USERS``). Rapide, pas de vérification JWT.
        - ``False`` → vérifie la signature JWT avec ``JWT_SECRET`` et
          que le ``sub`` correspond bien à ``name``.
    """
    if verify_connect:
        if name not in USERS:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail=VERIFY_CONNECT_ERROR,
            )

    sub = verify_token(token, CONTEXTGUARD_JWT_SECRET, verify_exp=verify_exp)
    if sub != name:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail=TOKEN_USURPATION_DETAIL,
        )
    return True
