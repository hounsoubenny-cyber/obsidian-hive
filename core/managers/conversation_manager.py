#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 01:35:59 2026

@author: hounsousamuel
"""

"""
conversation_manager.py — Persistance des conversations Coralie.
"""

import os
import json
import asyncio
import functools
from uuid import uuid4
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship, select
from pydantic import BaseModel, Field as Pydantic_Field
from sqlalchemy import func as sa_func
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from modules_utils.loop_utils import _run_async
from obsidian_hive.core.managers.shared import _configure_sqlite_pragmas

def utcnow():
    """Retourne la date/heure UTC actuelle avec fuseau horaire.

    Returns:
        datetime: Date/heure actuelle en UTC.
    """
    return datetime.now(tz=timezone.utc)


DEFAULT_TITLE = "Nouvelle conversation"
TITLE_MAX_LEN = 100


# =============================================================================
# MODÈLES
# =============================================================================

class ConversationDB(SQLModel, table=True):
    """Modèle de base de données pour les conversations.
    
    Stocke les métadonnées d'une conversation (titre, propriétaire, état)
    et sa relation avec les messages.
    """
    __tablename__ = "conversation_db"
    __table_args__ = {"extend_existing": True}

    id: Optional[int] = Field(
        primary_key=True, default=None,
        description="Clé primaire interne (auto-incrémentée). Utilisable partout à la place de conversation_id."
    )
    conversation_id: str = Field(
        default_factory=lambda: "conv-" + str(uuid4()), unique=True, index=True,
        description="Identifiant public unique de la conversation (ex: exposé côté frontend/API)."
    )
    owner: str = Field(index=True, description="Identifiant de l'admin propriétaire")
    title: str = Field(
        default=DEFAULT_TITLE,
        description="Titre affiché dans la liste des conversations. Auto-généré depuis le 1er message user "
                     "si laissé par défaut, sinon renommable manuellement."
    )
    created_at: datetime = Field(default_factory=utcnow, description="Date de création de la conversation.")
    updated_at: datetime = Field(
        default_factory=utcnow,
        description="Date de dernière activité (nouveau message, renommage...). Sert au tri de list_by_owner."
    )
    archived: bool = Field(default=False, description="Conversation archivée (masquée de la liste par défaut, pas supprimée).")
    is_favorite: bool = Field(default=False, description="Conversation épinglée/favorite par l'utilisateur.")

    messages: list["MessageDB"] = Relationship(
        back_populates="conversation",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
            "order_by": "MessageDB.id",
        },
    )


class MessageDB(SQLModel, table=True):
    """Modèle de base de données pour les messages d'une conversation.
    
    Stocke le contenu du message, son rôle (user/assistant) et les métadonnées
    d'exécution de l'agent (steps, temps, appels d'outils).
    """
    __tablename__ = "message_db"
    __table_args__ = {"extend_existing": True}

    id: Optional[int] = Field(
        primary_key=True, default=None,
        description="Clé primaire interne (auto-incrémentée) du message."
    )
    conversation_pk: Optional[int] = Field(
        default=None, foreign_key="conversation_db.id",
        description="FK vers ConversationDB.id — conversation à laquelle appartient ce message."
    )
    role: str = Field(
        description="'user' | 'assistant'. Les tool_calls ne sont pas persistés comme role à part, "
                     "ils vivent dans `steps` du message assistant correspondant."
    )
    content: str = Field(
        default="",
        description="Contenu final (texte user tel quel, ou réponse finale synthétisée de l'assistant)."
    )
    steps: Optional[str] = Field(
        default=None,
        description="JSON sérialisé de la liste `steps` retournée par run_agent (thinking, tool_calls, "
                     "résultats, timing, par itération). Toujours None pour un message role='user'. "
                     "Utiliser get_steps() pour récupérer la liste Python désérialisée."
    )
    total_time: Optional[float] = Field(
        default=None, description="Durée totale (en secondes) prise par run_agent pour produire ce message."
    )
    tool_calls_count: Optional[int] = Field(
        default=None, description="Nombre total de tool_calls exécutés, toutes itérations confondues, pour ce message."
    )
    iterations: Optional[int] = Field(
        default=None, description="Nombre d'itérations de la boucle agent ayant produit ce message."
    )
    max_iter_reached: bool =  Field(default=False, description="Nombre max d'iteration atteint")
    created_at: datetime = Field(default_factory=utcnow, description="Date de création du message.")

    conversation: Optional[ConversationDB] = Relationship(
        back_populates="messages",
        sa_relationship_kwargs={"lazy": "selectin"},
    )

    def get_steps(self) -> list:
        """Désérialise `steps` (stocké en JSON texte) en liste de dicts Python.

        Returns:
            list: La liste des étapes désérialisée, ou [] si vide.
        """
        if not self.steps:
            return []
        try:
            return json.loads(self.steps)
        except (json.JSONDecodeError, TypeError):
            return []

    def to_chat_message(self) -> dict:
        """Format minimal réinjectable directement dans LLMManager.run_agent(messages=...).

        Returns:
            dict: Dictionnaire avec 'role' et 'content'.
        """
        return {"role": self.role, "content": self.content}


class ConversationNotFoundError(Exception):
    """Exception levée lorsqu'une conversation n'est pas trouvée."""
    pass


class Message(BaseModel):
    """
    Version "lecture" de MessageDB : mêmes champs, sauf `steps` déjà
    désérialisé en liste Python (au lieu du JSON texte tel que stocké en DB).

    C'est ce type que renvoient toutes les méthodes de LECTURE (get_message,
    get_messages, get_last_message) via le décorateur `with_parsed_steps`.
    add_message / save_agent_turn restent sur MessageDB brut (chemin écriture,
    steps déjà fourni en Python par l'appelant, pas besoin de round-trip JSON).
    """
    id: Optional[int] = Pydantic_Field(
        default=None,
        description="Clé primaire (auto-incrémentée) du message."
    )
    conversation_pk: Optional[int] = Pydantic_Field(
        default=None, 
        description="FK vers ConversationDB.id — conversation à laquelle appartient ce message."
    )
    role: str = Pydantic_Field(
        description="'user' | 'assistant'. Les tool_calls ne sont pas persistés comme role à part, "
                     "ils vivent dans `steps` du message assistant correspondant."
    )
    content: str = Pydantic_Field(
        default="",
        description="Contenu final (texte user tel quel, ou réponse finale synthétisée de l'assistant)."
    )
    steps: Optional[list] = Pydantic_Field(
        default=None,
        description="Step en liste (chargé depuis MessagDB)"
    )
    total_time: Optional[float] = Pydantic_Field(
        default=None, description="Durée totale (en secondes) prise par run_agent pour produire ce message."
    )
    tool_calls_count: Optional[int] = Pydantic_Field(
        default=None, description="Nombre total de tool_calls exécutés, toutes itérations confondues, pour ce message."
    )
    iterations: Optional[int] = Pydantic_Field(
        default=None, description="Nombre d'itérations de la boucle agent ayant produit ce message."
    )
    max_iter_reached: bool =  Field(default=False, description="Nombre max d'iteration atteint")
    created_at: datetime = Pydantic_Field(description="Date de création du message.")

    def to_chat_message(self) -> dict:
        """Format minimal réinjectable directement dans LLMManager.run_agent(messages=...).

        Returns:
            dict: Dictionnaire avec 'role' et 'content'.
        """
        return {"role": self.role, "content": self.content}


def with_parsed_steps(func):
    """
    Décore une méthode qui retourne un MessageDB (ou une liste/None) et
    convertit chaque résultat en `Message`, avec `steps` désérialisé
    (JSON texte -> liste Python) au passage.

    Ne jamais appliquer sur add_message/save_agent_turn : ces méthodes créent
    le message à partir d'une liste `steps` déjà en Python côté appelant,
    pas besoin d'un round-trip JSON juste après écriture.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)

        def _hydrate(msg: MessageDB) -> Message:
            return Message(
                id=msg.id,
                conversation_pk=msg.conversation_pk,
                role=msg.role,
                content=msg.content,
                steps=msg.get_steps(),
                total_time=msg.total_time,
                tool_calls_count=msg.tool_calls_count,
                iterations=msg.iterations,
                created_at=msg.created_at,
                max_iter_reached=msg.max_iter_reached
            )

        if result is None:
            return None
        if isinstance(result, MessageDB):
            return _hydrate(result)
        if isinstance(result, list):
            return [_hydrate(m) if isinstance(m, MessageDB) else m for m in result]
        return result
    return wrapper


# =============================================================================
# MANAGER
# =============================================================================

class ConversationManager:
    """Gestionnaire des conversations et messages avec persistance en base de données.
    
    Fournit des opérations CRUD complètes pour les conversations et les messages,
    avec support de la pagination, du filtrage et de la recherche.
    
    Attributes:
        db_url (str): URL de connexion à la base de données.
        engine (AsyncEngine): Moteur SQLAlchemy asynchrone.
    """
    
    def __init__(self, db_url: str):
        """Initialise le gestionnaire de conversations.

        Args:
            db_url (str): URL de connexion à la base de données.
                Ex: "sqlite+aiosqlite:///conversations.db"
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
        if "sqlite" in self.db_url:
            _configure_sqlite_pragmas(self.engine)
            
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

    # =========================================================================
    # Résolution interne : conversation_id (str) OU id (int)
    # =========================================================================

    async def _resolve_conversation(
        self,
        session: AsyncSession,
        conversation_id: str | None = None,
        id: int | None = None,
    ) -> Optional[ConversationDB]:
        """Résout une conversation par conversation_id ou id primaire.

        Args:
            session (AsyncSession): La session de base de données.
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.

        Returns:
            Optional[ConversationDB]: La conversation trouvée ou None.

        Raises:
            ValueError: Si ni conversation_id ni id n'est fourni.
        """
        if conversation_id is None and id is None:
            raise ValueError("Il faut fournir conversation_id ou id")
        if id is not None:
            return await session.get(ConversationDB, id)
        statement = select(ConversationDB).where(ConversationDB.conversation_id == conversation_id)
        result = await session.execute(statement)
        return result.scalar_one_or_none()

    # =========================================================================
    # Conversations — CRUD
    # =========================================================================

    async def create_conversation(self, owner: str, title: str | None = None) -> ConversationDB:
        """Crée une nouvelle conversation vide.

        Args:
            owner (str): L'identifiant du propriétaire de la conversation.
            title (str | None, optional): Le titre de la conversation. Si None, utilise DEFAULT_TITLE.

        Returns:
            ConversationDB: La conversation créée.
        """
        async with self.get_session() as session:
            conv = ConversationDB(owner=owner, title=title or DEFAULT_TITLE)
            session.add(conv)
            await session.commit()
            await session.refresh(conv)
            return conv

    async def get_conversation(
        self, conversation_id: str | None = None, id: int | None = None
    ) -> Optional[ConversationDB]:
        """Récupère une conversation (messages eager-loadés), par conversation_id OU id.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.

        Returns:
            Optional[ConversationDB]: La conversation trouvée ou None.
        """
        async with self.get_session() as session:
            return await self._resolve_conversation(session, conversation_id=conversation_id, id=id)

    async def get_by_conversation_id(self, conversation_id: str) -> Optional[ConversationDB]:
        """Alias conservé pour compat avec l'existant.

        Args:
            conversation_id (str): L'ID public de la conversation.

        Returns:
            Optional[ConversationDB]: La conversation trouvée ou None.
        """
        return await self.get_conversation(conversation_id=conversation_id)

    async def list_by_owner(
        self,
        owner: str,
        include_archived: bool = False,
        favorites_only: bool = False,
        limit: int | None = 50,
        offset: int = 0,
    ) -> list[ConversationDB]:
        """Liste les conversations d'un admin, plus récentes en premier.

        Args:
            owner (str): L'identifiant du propriétaire.
            include_archived (bool, optional): Si True, inclut les conversations archivées.
                Par défaut False.
            favorites_only (bool, optional): Si True, ne liste que les favorites.
                Par défaut False.
            limit (int | None, optional): Nombre maximum de résultats. Par défaut 50.
            offset (int, optional): Décalage pour la pagination. Par défaut 0.

        Returns:
            list[ConversationDB]: La liste des conversations.
        """
        async with self.get_session() as session:
            statement = select(ConversationDB).where(ConversationDB.owner == owner)
            if not include_archived:
                statement = statement.where(ConversationDB.archived == False)  # noqa: E712
            if favorites_only:
                statement = statement.where(ConversationDB.is_favorite == True)  # noqa: E712
            
            statement = statement.order_by(ConversationDB.updated_at.desc())
            if limit is not None:
                statement = statement.limit(limit).offset(offset)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def count_by_owner(self, owner: str, include_archived: bool = False) -> int:
        """Compte les conversations d'un admin (pour la pagination côté UI).

        Args:
            owner (str): L'identifiant du propriétaire.
            include_archived (bool, optional): Si True, inclut les conversations archivées.
                Par défaut False.

        Returns:
            int: Le nombre de conversations.
        """
        async with self.get_session() as session:
            statement = select(sa_func.count()).select_from(ConversationDB).where(ConversationDB.owner == owner)
            if not include_archived:
                statement = statement.where(ConversationDB.archived == False)  # noqa: E712
            result = await session.execute(statement)
            return result.scalar_one()

    async def update_title(
        self, conversation_id: str | None = None, id: int | None = None, *, title: str
    ) -> bool:
        """Renomme une conversation manuellement.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            title (str): Le nouveau titre.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return False
            conv.title = title
            conv.updated_at = utcnow()
            session.add(conv)
            await session.commit()
            return True

    async def set_archived(
        self, conversation_id: str | None = None, id: int | None = None, archived: bool = True
    ) -> bool:
        """Archive ou désarchive une conversation (juste un flag, rien n'est supprimé).

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            archived (bool, optional): True pour archiver, False pour désarchiver.
                Par défaut True.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return False
            conv.archived = archived
            conv.updated_at = utcnow()
            session.add(conv)
            await session.commit()
            return True

    async def set_favorite(
        self, conversation_id: str | None = None, id: int | None = None, favorite: bool = True
    ) -> bool:
        """Marque/démarque une conversation comme favorite.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            favorite (bool, optional): True pour marquer comme favorite, False pour démarrer.
                Par défaut True.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return False
            conv.is_favorite = favorite
            conv.updated_at = utcnow()
            session.add(conv)
            await session.commit()
            return True

    async def delete_conversation(
        self, conversation_id: str | None = None, id: int | None = None
    ) -> bool:
        """Supprime une conversation ET tous ses messages (cascade ORM).

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.

        Returns:
            bool: True si la suppression a réussi, False sinon.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return False
            await session.delete(conv)
            await session.commit()
            return True

    async def touch_conversation(
        self, conversation_id: str | None = None, id: int | None = None
    ) -> None:
        """Met juste à jour updated_at (ex: après un nouveau message).

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if conv:
                conv.updated_at = utcnow()
                session.add(conv)
                await session.commit()

    async def search_conversations(
        self, owner: str, query: str, limit: int = 20
    ) -> list[ConversationDB]:
        """Recherche simple par titre (LIKE, insensible à la casse).

        Args:
            owner (str): L'identifiant du propriétaire.
            query (str): La chaîne de recherche.
            limit (int, optional): Nombre maximum de résultats. Par défaut 20.

        Returns:
            list[ConversationDB]: La liste des conversations correspondantes.
        """
        async with self.get_session() as session:
            statement = (
                select(ConversationDB)
                .where(ConversationDB.owner == owner)
                .where(ConversationDB.title.ilike(f"%{query}%"))
                .order_by(ConversationDB.updated_at.desc())
                .limit(limit)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())

    # =========================================================================
    # Messages — CRUD
    # =========================================================================
    
    async def _insert_message(
        self,
        session: AsyncSession,
        conv: ConversationDB,
        *,
        role: str,
        content: str,
        steps: list | None = None,
        total_time: float | None = None,
        tool_calls_count: int | None = None,
        iterations: int | None = None,
        max_iter_reached: bool = False,
    ) -> MessageDB:
        """Insère un message SANS commit — laisse l'appelant décider quand commiter.

        Args:
            session (AsyncSession): La session de base de données.
            conv (ConversationDB): La conversation parente.
            role (str): 'user' ou 'assistant'.
            content (str): Le contenu du message.
            steps (list | None, optional): Les étapes d'exécution.
            total_time (float | None, optional): Durée totale.
            tool_calls_count (int | None, optional): Nombre d'appels d'outils.
            iterations (int | None, optional): Nombre d'itérations.

        Returns:
            MessageDB: Le message créé.
        """
        msg = MessageDB(
            conversation_pk=conv.id,
            role=role,
            content=content,
            steps=json.dumps(steps, ensure_ascii=False, default=str) if steps is not None else None,
            total_time=total_time,
            tool_calls_count=tool_calls_count,
            iterations=iterations,
            max_iter_reached=max_iter_reached
        )
        session.add(msg)
    
        conv.updated_at = utcnow()
        if role == "user" and conv.title == DEFAULT_TITLE:
            snippet = " ".join(content.strip().split())[:TITLE_MAX_LEN]
            if len(content.strip()) > TITLE_MAX_LEN:
                snippet += "…"
            conv.title = snippet or DEFAULT_TITLE
        session.add(conv)
    
        return msg
    
    
    async def add_message(
        self,
        conversation_id: str | None = None,
        id: int | None = None,
        *,
        role: str,
        content: str,
        steps: list | None = None,
        total_time: float | None = None,
        tool_calls_count: int | None = None,
        iterations: int | None = None,
        max_iter_reached: bool = False,
    ) -> MessageDB:
        """
        Ajoute un message à une conversation existante.
        Met à jour updated_at, et auto-titre la conversation sur son 1er message
        user si elle a encore le titre par défaut.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            role (str): 'user' ou 'assistant'.
            content (str): Le contenu du message.
            steps (list | None, optional): Les étapes d'exécution.
            total_time (float | None, optional): Durée totale.
            tool_calls_count (int | None, optional): Nombre d'appels d'outils.
            iterations (int | None, optional): Nombre d'itérations.

        Returns:
            MessageDB: Le message créé.

        Raises:
            ConversationNotFoundError: Si la conversation n'est pas trouvée.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                raise ConversationNotFoundError(
                    f"Conversation introuvable (conversation_id={conversation_id!r}, id={id!r})"
                )
            msg = await self._insert_message(
                session, conv, role=role, content=content, steps=steps,
                total_time=total_time, tool_calls_count=tool_calls_count, iterations=iterations,
                max_iter_reached=max_iter_reached
            )
            await session.commit()
            await session.refresh(msg)
            return msg
    
    
    async def save_agent_turn(
        self,
        conversation_id: str | None = None,
        id: int | None = None,
        *,
        user_content: str,
        agent_result: dict,
        max_iter_reached: bool = False,
    ) -> tuple[MessageDB, MessageDB]:
        """
        Sauvegarde en un coup un tour complet de façon atomique (un seul commit): le message user + la réponse
        assistant enrichie (steps/total_time/tool_calls/iterations), directement
        à partir du dict retourné par LLMManager.run_agent() / chat().

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            user_content (str): Le contenu du message utilisateur.
            agent_result (dict): Le résultat de l'agent (response, steps, total_time, tool_calls, iterations).

        Returns:
            tuple[MessageDB, MessageDB]: Le message user et le message assistant.

        Raises:
            ConversationNotFoundError: Si la conversation n'est pas trouvée.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                raise ConversationNotFoundError(
                    f"Conversation introuvable (conversation_id={conversation_id!r}, id={id!r})"
                )
    
            user_msg = await self._insert_message(session, conv, role="user", content=user_content)
            assistant_msg = await self._insert_message(
                session, conv,
                role="assistant",
                content=agent_result.get("response", ""),
                steps=agent_result.get("steps"),
                total_time=agent_result.get("total_time"),
                tool_calls_count=agent_result.get("tool_calls"),
                iterations=agent_result.get("iterations"),
                max_iter_reached=max_iter_reached or bool(agent_result.get("max_iter_reached")),
            )
    
            await session.commit() 
            await session.refresh(user_msg)
            await session.refresh(assistant_msg)
            return user_msg, assistant_msg
        
    @with_parsed_steps
    async def get_message(self, message_id: int) -> Optional[Message]:
        """Récupère un message par son id (int, PK). `steps` est renvoyé désérialisé (liste).

        Args:
            message_id (int): L'ID primaire du message.

        Returns:
            Optional[Message]: Le message trouvé ou None.
        """
        async with self.get_session() as session:
            return await session.get(MessageDB, message_id)

    @with_parsed_steps
    async def get_messages(
        self,
        conversation_id: str | None = None,
        id: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Message]:
        """Historique complet (ou paginé) d'une conversation, ordre chronologique. `steps` désérialisé.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            limit (int | None, optional): Nombre maximum de messages.
            offset (int, optional): Décalage pour la pagination. Par défaut 0.

        Returns:
            list[Message]: La liste des messages.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return []
            statement = (
                select(MessageDB)
                .where(MessageDB.conversation_pk == conv.id)
                .order_by(MessageDB.id)
            )
            if limit is not None:
                statement = statement.limit(limit).offset(offset)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def get_chat_history(
        self, conversation_id: str | None = None, id: int | None = None
    ) -> list[dict]:
        """
        Historique au format directement réinjectable dans
        LLMManager.run_agent(messages=...) : [{"role":, "content":}, ...]

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.

        Returns:
            list[dict]: L'historique formaté pour LLM.
        """
        messages = await self.get_messages(conversation_id=conversation_id, id=id)
        return [m.to_chat_message() for m in messages]

    @with_parsed_steps
    async def get_last_message(
        self,
        conversation_id: str | None = None,
        id: int | None = None,
        role: str | None = None,
    ) -> Optional[Message]:
        """Dernier message d'une conversation, filtrable par role. `steps` désérialisé.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.
            role (str | None, optional): Filtrer par role ('user' ou 'assistant').

        Returns:
            Optional[Message]: Le dernier message trouvé ou None.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return None
            statement = select(MessageDB).where(MessageDB.conversation_pk == conv.id)
            if role:
                statement = statement.where(MessageDB.role == role)
            statement = statement.order_by(MessageDB.id.desc()).limit(1)
            result = await session.execute(statement)
            return result.scalar_one_or_none()

    async def update_message_content(self, message_id: int, content: str) -> bool:
        """Édite le contenu d'un message existant (ex: correction manuelle).

        Args:
            message_id (int): L'ID primaire du message.
            content (str): Le nouveau contenu.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        async with self.get_session() as session:
            msg = await session.get(MessageDB, message_id)
            if not msg:
                return False
            msg.content = content
            session.add(msg)
            await session.commit()
            return True

    async def delete_message(self, message_id: int) -> bool:
        """Supprime un seul message.

        Args:
            message_id (int): L'ID primaire du message.

        Returns:
            bool: True si la suppression a réussi, False sinon.
        """
        async with self.get_session() as session:
            msg = await session.get(MessageDB, message_id)
            if not msg:
                return False
            await session.delete(msg)
            await session.commit()
            return True

    async def delete_messages_after(self, message_id: int) -> int:
        """
        Supprime tous les messages venant après `message_id` dans la même
        conversation. Utile pour un "regénère à partir d'ici" (edit + retry).

        Args:
            message_id (int): L'ID du message à partir duquel supprimer.

        Returns:
            int: Le nombre de messages supprimés.
        """
        async with self.get_session() as session:
            anchor = await session.get(MessageDB, message_id)
            if not anchor:
                return 0
            statement = select(MessageDB).where(
                MessageDB.conversation_pk == anchor.conversation_pk,
                MessageDB.id > anchor.id,
            )
            result = await session.execute(statement)
            to_delete = list(result.scalars().all())
            for m in to_delete:
                await session.delete(m)
            await session.commit()
            return len(to_delete)

    async def count_messages(
        self, conversation_id: str | None = None, id: int | None = None
    ) -> int:
        """Nombre de messages dans une conversation.

        Args:
            conversation_id (str | None, optional): L'ID public de la conversation.
            id (int | None, optional): L'ID primaire de la conversation.

        Returns:
            int: Le nombre de messages.
        """
        async with self.get_session() as session:
            conv = await self._resolve_conversation(session, conversation_id=conversation_id, id=id)
            if not conv:
                return 0
            statement = (
                select(sa_func.count())
                .select_from(MessageDB)
                .where(MessageDB.conversation_pk == conv.id)
            )
            result = await session.execute(statement)
            return result.scalar_one()
        

async def test_conversation_manager():
    """Test complet du ConversationManager."""
    import tempfile
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    db_url = f"sqlite+aiosqlite:///{db_path}"
    print(f"\n📁 Base de données: {db_path}")
    mgr = ConversationManager(db_url)
    # 1. Créer une conversation
    conv = await mgr.create_conversation(owner="benny", title=None)
    print("✅ create_conversation:", conv.conversation_id, conv.id, conv.title)
 
    # 2. add_message via conversation_id
    m1 = await mgr.add_message(
        conversation_id=conv.conversation_id,
        role="user",
        content="Salut, comment va Alex sur les tests CPU ?",
    )
    print("✅ add_message (user, via conversation_id):", m1.id, m1.role)
 
    # 3. Vérifier l'auto-titre
    conv_reloaded = await mgr.get_conversation(conversation_id=conv.conversation_id)
    # print(conv_reloaded.messages)
    print("✅ auto-titre:", conv_reloaded.title)
 
    # 4. add_message via id (int) cette fois, avec steps (simulate run_agent output)
    fake_agent_result = {
        "response": "Alex tourne bien sur Ornith-1.0-9B, CPU only.",
        "total_time": 3.42,
        "tool_calls": 1,
        "iterations": 2,
        "steps": [
            {"think": "je dois vérifier le modèle", "tool_calls": {"tc_1": {"name": "check_model", "result": "ok"}}},
            {"think": "", "tool_calls": {}},
        ],
    }
    m2 = await mgr.add_message(
        id=conv.id,
        role="assistant",
        content=fake_agent_result["response"],
        steps=fake_agent_result["steps"],
        total_time=fake_agent_result["total_time"],
        tool_calls_count=fake_agent_result["tool_calls"],
        iterations=fake_agent_result["iterations"],
    )
    print("✅ add_message (assistant, via id):", m2.id)
    print("   m2.get_steps() (objet brut MessageDB, add_message n'est pas wrapped):", m2.get_steps())
 
    # 5. save_agent_turn (méthode tout-en-un)
    u, a = await mgr.save_agent_turn(
        conversation_id=conv.conversation_id,
        user_content="Et niveau RAM ?",
        agent_result={
            "response": "Environ 4 Go en usage courant.",
            "total_time": 1.1,
            "tool_calls": 0,
            "iterations": 1,
            "steps": [{"think": "pas besoin de tool", "tool_calls": {}}],
        },
    )
    print("✅ save_agent_turn:", u.id, a.id)
 
    # 6. get_chat_history (format LLMManager-ready)
    history = await mgr.get_chat_history(conversation_id=conv.conversation_id)
    print("✅ get_chat_history:", history)
 
    # 6bis. Vérifier le wrapper with_parsed_steps
    fetched = await mgr.get_message(m2.id)
    print("✅ get_message via wrapper -> steps déjà liste:", type(fetched.steps), fetched.steps)
    assert isinstance(fetched.steps, list)
 
    all_msgs = await mgr.get_messages(conversation_id=conv.conversation_id)
    print("✅ get_messages via wrapper -> types steps:", [type(m.steps).__name__ for m in all_msgs])
    assert all(m.steps is None or isinstance(m.steps, list) for m in all_msgs)
 
    # 7. get_messages / count_messages
    msgs = await mgr.get_messages(id=conv.id)
    print(f"✅ get_messages: {len(msgs)} messages")
    count = await mgr.count_messages(conversation_id=conv.conversation_id)
    print("✅ count_messages:", count)
 
    # 8. get_last_message avec filtre role
    last_assistant = await mgr.get_last_message(id=conv.id, role="assistant")
    print("✅ get_last_message(role=assistant):", last_assistant.content)
 
    # 9. update_title / set_favorite / set_archived (via id cette fois)
    await mgr.update_title(id=conv.id, title="Test Alex CPU")
    await mgr.set_favorite(id=conv.id, favorite=True)
    await mgr.set_archived(conversation_id=conv.conversation_id, archived=True)
    conv2 = await mgr.get_conversation(id=conv.id)
    print("✅ update_title/set_favorite/set_archived:", conv2.title, conv2.is_favorite, conv2.archived)
 
    # 10. list_by_owner (avec archived inclus)
    convs = await mgr.list_by_owner(owner="benny", include_archived=True)
    print(f"✅ list_by_owner: {len(convs)} conversation(s)")
 
    # 11. search_conversations
    found = await mgr.search_conversations(owner="benny", query="Alex")
    print(f"✅ search_conversations('Alex'): {len(found)} résultat(s)")
 
    # 12. update_message_content
    ok = await mgr.update_message_content(m1.id, "Salut (édité)")
    print("✅ update_message_content:", ok)
 
    # 13. delete_messages_after
    deleted = await mgr.delete_messages_after(m1.id)
    print("✅ delete_messages_after:", deleted, "messages supprimés")
 
    # 14. ConversationNotFoundError
    try:
        await mgr.add_message(conversation_id="conv-inexistant", role="user", content="x")
        print("❌ aurait dû lever ConversationNotFoundError")
    except ConversationNotFoundError:
        print("✅ ConversationNotFoundError bien levée pour conversation inexistante")
 
    # 15. delete_conversation (cascade)
    ok = await mgr.delete_conversation(id=conv.id)
    remaining = await mgr.get_conversation(id=conv.id)
    print("✅ delete_conversation:", ok, "| relue après suppression:", remaining)
 
    print("\n🎉 TOUS LES TESTS SONT PASSÉS")
 
 
if __name__ == "__main__":
    import nest_asyncio, asyncio
    nest_asyncio.apply()
    asyncio.run(test_conversation_manager())