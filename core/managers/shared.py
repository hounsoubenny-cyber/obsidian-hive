#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 12:47:06 2026

@author: hounsousamuel
"""

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

def _configure_sqlite_pragmas(engine: AsyncEngine):
    """Active le mode WAL et le timeout anti-verrouillage sur SQLite."""
    if not isinstance(engine, AsyncEngine):
        return
    
    if getattr(engine.sync_engine, "_pragmas_configured", False):
        return
    engine.sync_engine._pragmas_configured = True

    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # 1. Active le Write-Ahead Logging (lectures et écritures concurrentes)
        cursor.execute("PRAGMA journal_mode=WAL;")
        # 2. Si la base est occupée, attend jusqu'à 5000ms avant de lever une erreur
        cursor.execute("PRAGMA busy_timeout=5000;")
        # 3. Synchronisation optimisée pour WAL (sécurisé et 3x plus rapide)
        cursor.execute("PRAGMA synchronous=NORMAL;")
        # 4. Cache mémoire de 64 Mo pour les requêtes fréquentes
        cursor.execute("PRAGMA cache_size=-64000;")
        cursor.close()