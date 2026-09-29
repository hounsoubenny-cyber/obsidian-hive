#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 27 08:35:17 2026

@author: hounsousamuel
"""

import os
import re
import gzip
import json
import asyncio
from enum import StrEnum
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from sqlmodel import SQLModel, Field, select, and_
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from modules_utils.loop_utils import _run_async
from obsidian_hive.core.assets.asset_types import utcnow, ensure_naive
from obsidian_hive.core.managers.shared import _configure_sqlite_pragmas
from obsidian_hive.config.config_manager import DEFAULT_TOOL_LOG_ARCHIVE_DIR, DEFAULT_TOOL_LOG_MAX_AGE_DAYS

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|secret|token|api_key|apikey|credential|authorization|private_key)",
    re.IGNORECASE,
)

def redact_sensitive(obj):
    """Masque récursivement les valeurs des clés sensibles dans un dict/list.
    
    Ne touche jamais aux clés elles-mêmes ni à la structure — juste aux
    valeurs des champs dont le NOM matche un pattern connu (password,
    secret, token...). Pas d'anonymisation de contenu, juste un masquage
    ciblé et prévisible.
    """
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if _SENSITIVE_KEY_PATTERN.search(str(k)):
                result[k] = "***REDACTED***"
            else:
                result[k] = redact_sensitive(v)
        return result
    if isinstance(obj, list):
        return [redact_sensitive(v) for v in obj]
    return obj

class ToolCallLog(SQLModel, table=True):
    __tablename__ = "tool_call_log"

    id: str = Field(primary_key=True)            # call_id du ToolCall
    asset_id: str = Field(index=True)
    tool_name: str = Field(index=True)
    tool_args: str                                 # JSON, rédigé
    caller: str = Field(index=True)
    success: bool = Field(index=True)
    code: str                                      # tool_not_found, tool_not_allowed, tool_exec_successfuly...
    error: str | None = Field(default=None)
    execution_time: float | None = Field(default=None)
    created_at: datetime = Field(default_factory=utcnow, index=True)


class ToolCallCode(StrEnum):
    identity_theft              = "identity_theft"
    tool_not_found              = "tool_not_found"
    asset_not_found             = "asset_not_found"
    tool_send_failed            = "tool_send_failed"
    tool_not_allowed            = "tool_not_allowed"
    tool_confirmation_denied    = "tool_confirmation_denied"
    tool_confirmation_timeout   = "tool_confirmation_timeout"
    tool_exec_successfuly       = "tool_exec_successfuly"
    
class ToolCallLogManager:
    """Gère l'écriture, la lecture et l'archivage de l'historique des tool calls."""

    def __init__(
        self, 
        db_url: str, 
        interval_seconds: float = 3600 * 10,
        max_age_days: int = DEFAULT_TOOL_LOG_MAX_AGE_DAYS,
        archive_dir: str = DEFAULT_TOOL_LOG_ARCHIVE_DIR
    ):
        self.db_url = db_url
        db_path = db_url.removeprefix("sqlite+aiosqlite:///")
        if db_path and db_path != ":memory:":
            dirname = os.path.dirname(db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
                
        self.archive_dir = archive_dir
        self.interval_seconds = interval_seconds or 3600 * 10
        self.max_age_days = max_age_days
        self._stop_event = asyncio.Event()
        self._n_run = 0
        self._task: asyncio.Task | None = None
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

    async def log(
        self,
        call_id: str,
        asset_id: str,
        tool_name: str,
        tool_args: dict,
        caller: str,
        success: bool,
        code: ToolCallCode,
        error: str | None = None,
        execution_time: float | None = None,
    ):
        """Enregistre un tool call. Best-effort — ne doit jamais faire planter l'appelant."""
        try:
            entry = ToolCallLog(
                id=call_id,
                asset_id=asset_id,
                tool_name=tool_name,
                tool_args=json.dumps(redact_sensitive(tool_args or {}), default=str, ensure_ascii=False),
                caller=caller,
                success=success,
                code=code,
                error=error,
                execution_time=execution_time,
            )
            async with self.get_session() as session:
                session.add(entry)
                await session.commit()
                
        except Exception as e:
            print(f"[tool_call_log] échec d'écriture (non bloquant): {e!r}")
    
    async def list_by_filter(
        self,
        asset_id: str | None = None,
        tool_name: str | None = None,
        caller: str | None = None,
        success: bool | None = None,
        code: ToolCallCode | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ToolCallLog]:
        """Liste les tool calls loggés, avec filtrage combiné et pagination.

        Args:
            asset_id (str | None, optional): Filtrer par asset.
            tool_name (str | None, optional): Filtrer par nom de tool.
            caller (str | None, optional): Filtrer par utilisateur appelant.
            success (bool | None, optional): Filtrer par succès/échec.
            code (ToolCallCode | None, optional): Filtrer par code de résultat.
            since (datetime | None, optional): Depuis cette date (incluse).
            until (datetime | None, optional): Jusqu'à cette date (incluse).
            limit (int, optional): Nombre max de résultats. Par défaut 100, plafonné à 500.
            offset (int, optional): Décalage pour la pagination. Par défaut 0.

        Returns:
            list[ToolCallLog]: Les entrées correspondantes, les plus récentes en premier.
        """
        conditions = []
        if asset_id:
            conditions.append(ToolCallLog.asset_id == asset_id)
        if tool_name:
            conditions.append(ToolCallLog.tool_name == tool_name)
        if caller:
            conditions.append(ToolCallLog.caller == caller)
        if success is not None:
            conditions.append(ToolCallLog.success == success)
        if code:
            conditions.append(ToolCallLog.code == ToolCallCode(code))
        if since:
            conditions.append(ToolCallLog.created_at >= ensure_naive(since))
        if until:
            conditions.append(ToolCallLog.created_at <= ensure_naive(until))

        limit = min(max(limit, 1), 500)   # borne dure — jamais de requête non bornée
        offset = max(offset, 0)

        async with self.get_session() as session:
            statement = select(ToolCallLog)
            if conditions:
                statement = statement.where(and_(*conditions))
            statement = (
                statement
                .order_by(ToolCallLog.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
        
    async def archive_and_delete_older_than(
        self, days: int = 90,
        keep: bool = False
    ) -> int:
        """Exporte en JSONL compressé les entrées plus vieilles que `days`, puis les supprime.

        Un fichier par cycle d'archivage : tool_calls_<date>.jsonl.gz
        """
        cutoff = ensure_naive(utcnow() - timedelta(days=days))
        os.makedirs(self.archive_dir, exist_ok=True)

        async with self.get_session() as session:
            result = await session.execute(
                select(ToolCallLog).where(ToolCallLog.created_at < ensure_naive(cutoff))
            )
            rows = result.scalars().all()
            if not rows:
                return 0
            
            if keep:
                archive_path = os.path.join(
                    self.archive_dir,
                    f"tool_calls_{cutoff.strftime('%Y_%m_%d_%H_%M_%s')}.jsonl.gz",
                )
                with gzip.open(archive_path, "at", encoding="utf-8") as f:
                    for row in rows:
                        f.write(json.dumps(row.model_dump(mode="json")) + "\n")
                        await session.delete(row)
            else:
                for row in rows:
                    await session.delete(row)
            await session.commit()

        return len(rows)
    
    async def _loop(self):
        while not self._stop_event.is_set():
            try:
                n = await self.archive_and_delete_older_than(days=self.max_age_days, keep=False)
                if n:
                    print(f"[cleanup] {n} tool_call(s) archivées")
                self._n_run += 1
            except Exception as e:
                print(f"[cleanup] erreur : {e}")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass  # cycle normal, on relance
    
    def start(self):
        if self._task is None:
            self._stop_event.clear()
            self._task = asyncio.create_task(self._loop())
        
        print("[tool_call_loger] Tâche de fond démarée")
    
    async def stop(self):
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), 2)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            except asyncio.CancelledError:
                # stop() lui-même a été annulé par son appelant — on nettoie
                # quand même avant de laisser l'annulation remonter
                self._task.cancel()
                raise
            finally:
                self._task = None