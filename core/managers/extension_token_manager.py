#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 27 17:51:11 2026

@author: hounsousamuel
"""


"""
extension_token_manager.py

Gestionnaire des tokens d'extension navigateur, sur le même modèle que
AssetManager mais pour une table indépendante (ExtensionTokenDB) — pas un
asset, juste un credential révocable par device.
"""

import os
import secrets
from typing import Optional
from sqlmodel import SQLModel, select, Field
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from datetime import datetime
from contextlib import asynccontextmanager

from obsidian_hive.core.assets.asset_types import utcnow
from modules_utils.cryto_utils import hashpw
from modules_utils.loop_utils import _run_async
from modules_utils.cryto_utils import checkpw



class ExtensionTokenDB(SQLModel, table=True):
    """Table des tokens d'extension navigateur.

    Attributes:
        id (int): PK auto-incrémentée.
        token_id (str): Identifiant public du token (permet de retrouver la ligne
            sans avoir à re-hasher/comparer toute la table).
        label (str): Nom donné par l'utilisateur (ex: "Chrome - PC bureau").
        token_hash (str): Hash du secret, jamais le clair.
        created_at (datetime): Date de création.
        last_used_at (datetime | None): Dernière utilisation (mis à jour à chaque requête validée).
        revoked (bool): True si révoqué.
        revoked_at (datetime | None): Date de révocation.
    """
    __tablename__ = "extension_token_db"

    id: Optional[int] = Field(primary_key=True, default=None)
    token_id: str = Field(index=True, unique=True)
    label: str
    token_hash: str
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = Field(default=None)
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)

    def verify(self, secret: str) -> bool:
        """Vérifie un secret fourni contre le hash stocké.

        Args:
            secret (str): Le secret en clair fourni par l'extension
                (partie après le "." dans le token complet).

        Returns:
            bool: True si le secret correspond et que le token n'est pas révoqué,
                False sinon.
        """
        if self.revoked:
            return False
        return checkpw(secret, self.token_hash)

class ExtensionTokenManager:
    """Gestionnaire des tokens d'extension navigateur avec persistance en base.

    Fournit la génération, la vérification, le listing et la révocation des
    tokens d'extension — un token par device/navigateur, révocable individuellement.

    Attributes:
        db_url (str): URL de connexion à la base de données.
        engine (AsyncEngine): Moteur SQLAlchemy asynchrone.
    """

    def __init__(self, db_url: str):
        """Initialise le gestionnaire de tokens d'extension.

        Args:
            db_url (str): URL de connexion à la base de données.
                Ex: "sqlite+aiosqlite:///extension_tokens.db"
        """
        self.db_url = db_url
        db_path = db_url.removeprefix("sqlite+aiosqlite:///")
        if db_path and db_path != ":memory:":
            dirname = os.path.dirname(db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
        self._initialized = False
        _run_async(self.init_db)

    async def init_db(self):
        """Initialise la base de données et crée la table si elle n'existe pas."""
        if self._initialized:
            return
        self.engine = create_async_engine(self.db_url)
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        self._initialized = True
    
    @asynccontextmanager
    async def get_session(self):
        """Retourne un contexte de session de base de données.

        Yields:
            AsyncSession: Une session SQLAlchemy asynchrone.
        """
        async with AsyncSession(self.engine, expire_on_commit=False) as session:
            yield session

    @staticmethod
    def generate_token() -> tuple[str, str, str]:
        """Génère un nouveau couple token_id/secret et le hash correspondant.

        Returns:
            tuple[str, str, str]: (token_id, secret_en_clair, token_hash).
                Le secret_en_clair n'est jamais persisté — à ne renvoyer
                qu'une seule fois à l'appelant, au moment de la création.
        """
        token_id = secrets.token_urlsafe(16)
        secret = secrets.token_urlsafe(32)
        token_hash = hashpw(secret).decode()
        return token_id, secret, token_hash

    async def create(self, label: str) -> tuple[ExtensionTokenDB, str]:
        """Crée un nouveau token d'extension.

        Args:
            label (str): Nom donné par l'utilisateur (ex: "Chrome - PC bureau").

        Returns:
            tuple[ExtensionTokenDB, str]: (la ligne créée, le token complet en
                clair "token_id.secret" — à afficher une seule fois à l'utilisateur).
        """
        token_id, secret, token_hash = self.generate_token()
        row = ExtensionTokenDB(token_id=token_id, label=label, token_hash=token_hash)
        async with self.get_session() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        return row, f"{token_id}.{secret}"

    async def get_by_token_id(self, token_id: str) -> ExtensionTokenDB | None:
        """Récupère un token par son token_id public.

        Args:
            token_id (str): L'identifiant public du token.

        Returns:
            ExtensionTokenDB | None: La ligne trouvée ou None.
        """
        async with self.get_session() as session:
            result = await session.execute(
                select(ExtensionTokenDB).where(ExtensionTokenDB.token_id == token_id)
            )
            return result.scalar_one_or_none()

    async def list_all(self, include_revoked: bool = True) -> list[ExtensionTokenDB]:
        """Liste tous les tokens d'extension enregistrés.

        Args:
            include_revoked (bool, optional): Si False, exclut les tokens révoqués.
                Par défaut True.

        Returns:
            list[ExtensionTokenDB]: La liste des tokens.
        """
        async with self.get_session() as session:
            statement = select(ExtensionTokenDB)
            if not include_revoked:
                statement = statement.where(ExtensionTokenDB.revoked == False)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def revoke(self, token_id: str) -> bool:
        """Révoque un token d'extension.

        Args:
            token_id (str): L'identifiant public du token à révoquer.

        Returns:
            bool: True si le token a été trouvé et révoqué, False sinon.
        """
        async with self.get_session() as session:
            result = await session.execute(
                select(ExtensionTokenDB).where(ExtensionTokenDB.token_id == token_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            row.revoked = True
            row.revoked_at = utcnow()
            session.add(row)
            await session.commit()
            return True

    async def touch_last_used(self, token_id: str):
        """Met à jour la date de dernière utilisation d'un token.

        Args:
            token_id (str): L'identifiant public du token utilisé.
        """
        async with self.get_session() as session:
            result = await session.execute(
                select(ExtensionTokenDB).where(ExtensionTokenDB.token_id == token_id)
            )
            row = result.scalar_one_or_none()
            if row is not None:
                row.last_used_at = utcnow()
                session.add(row)
                await session.commit()