#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
WSManager – gère les connexions WebSocket avec buffer replay.

Fonctionnement :
  - Chaque message envoyé est stocké dans un buffer par session_id
  - Si le WS est connecté → envoi immédiat + mise en buffer
  - Si déconnecté (ex : user reload) → buffer continue de se remplir
  - À la reconnexion → replay complet du buffer puis stream en live
  - Après fin de sim → cleanup du buffer après SIM_BUFFER_CLEAR_DELAY secondes
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Deque

from fastapi import WebSocket
from collections import deque
from simulateur_attaque_ia.configs.config import (
    SIM_BUFFER_MAX_MESSAGES as _BUFFER_MAX_MESSAGES,
    SIM_BUFFER_CLEAR_DELAY as _BUFFER_CLEAR_DELAY
)


class WSManager:
    """Singleton — une seule instance partagée par toute l'app."""

    _instance: Optional["WSManager"] = None

    # ── Constructeur / singleton ────────────────────────────────────────────

    def __init__(self) -> None:
        # session_id → WebSocket actif (None si déconnecté)
        self._connections: Dict[str, WebSocket] = {}

        # session_id → liste ordonnée de messages (replay buffer)
        self._buffers: Dict[str, Deque[dict]] = {}
        
        # session_id → asyncio.Task de cleanup programmé
        self._cleanup_tasks: Dict[str, asyncio.Task] = {}

    @classmethod
    def get_instance(cls) -> "WSManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Connexion / déconnexion ─────────────────────────────────────────────

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        """
        Accepte la connexion WS.
        Si un buffer existe déjà → replay avant de commencer le stream live.
        """
        await websocket.accept()
        self._connections[session_id] = websocket

        # Annuler un éventuel cleanup programmé (user reconnecte avant expiry)
        if session_id in self._cleanup_tasks:
            self._cleanup_tasks[session_id].cancel()
            del self._cleanup_tasks[session_id]

        # Replay du buffer existant
        buffer = self._buffers.get(session_id, [])
        if buffer:
            await self._replay(session_id, websocket, buffer)

    async def _replay(
        self,
        session_id: str,
        websocket:  WebSocket,
        buffer:     Deque[dict],
    ) -> None:
        """Envoie un marqueur de début de replay, tous les messages bufférisés,
        puis un marqueur de fin."""
        try:
            await websocket.send_json({
                "type":    "replay_start",
                "count":   len(buffer),
                "message": f"Replay de {len(buffer)} message(s) précédent(s)",
            })
            for msg in buffer:
                # print("Replay: ", msg)
                await websocket.send_json(msg)
            await websocket.send_json({"type": "replay_end"})
        except Exception:
            # WS fermé pendant le replay → on nettoie
            self._connections.pop(session_id, None)

    def disconnect(self, session_id: str) -> None:
        """
        Marque la session comme déconnectée sans supprimer le buffer.
        Le buffer reste disponible pour un éventuel replay.
        """
        self._connections.pop(session_id, None)

    # ── Envoi de messages ───────────────────────────────────────────────────

    async def send(self, session_id: str, message: dict) -> None:
        """
        Envoie un message au client connecté ET le met en buffer.
        Si le client est déconnecté, on continue de buffer silencieusement.
        """
        # Ajout timestamp si absent
        if "timestamp" not in message:
            message = {**message, "timestamp": datetime.now(tz=timezone.utc).isoformat()}

        # Buffer
        self._buffers.setdefault(session_id, deque(maxlen=_BUFFER_MAX_MESSAGES)).append(message) 

        # Tentative d'envoi live
        ws = self._connections.get(session_id)
        if not ws:
            return

        if ws is not None:
            try:
                payload = json.dumps(message, default=str)   
            except Exception as e:
                print(f"⚠️ Message '{message.get('type')}' non sérialisable pour {session_id}: {e}")
                return
            
            try:
                # print("Sending: ", message)
                await ws.send_text(payload)
            except Exception:
                # WS fermé (user reload etc.) → on retire proprement
                self._connections.pop(session_id, None)

    async def send_to_all(self, message: dict) -> None:
        """Broadcast à tous les clients actuellement connectés."""
        for session_id in list(self._connections.keys()):
            await self.send(session_id, message)

    # ── Réception (mode interactif) ─────────────────────────────────────────

    async def receive(self, session_id: str) -> Optional[dict]:
        """
        Attend le prochain message JSON envoyé par le client.
        Retourne None si la connexion est fermée.
        """
        ws = self._connections.get(session_id)
        if ws is None:
            return None
        try:
            return await ws.receive_json()
        except Exception:
            self._connections.pop(session_id, None)
            return None

    # ── Cleanup ─────────────────────────────────────────────────────────────

    def schedule_cleanup(self, session_id: str, delay: int = _BUFFER_CLEAR_DELAY) -> None:
        """
        Programme la suppression du buffer N secondes après la fin d'une sim.
        Si le user se reconnecte avant l'expiry, le cleanup est annulé.
        """
        async def _do_cleanup():
            try:
                await asyncio.sleep(delay)
                self._buffers.pop(session_id, None)
                self._cleanup_tasks.pop(session_id, None)
            except asyncio.CancelledError:
                pass

        # Annuler l'ancien si existant
        existing = self._cleanup_tasks.get(session_id)
        if existing:
            existing.cancel()

        task = asyncio.create_task(_do_cleanup())
        self._cleanup_tasks[session_id] = task

    def clear_session(self, session_id: str) -> None:
        """Force la suppression immédiate (stop de sim explicite)."""
        self._connections.pop(session_id, None)
        self._buffers.pop(session_id, None)
        task = self._cleanup_tasks.pop(session_id, None)
        if task:
            task.cancel()

    # ── Introspection ───────────────────────────────────────────────────────

    def is_connected(self, session_id: str) -> bool:
        return session_id in self._connections

    def buffer_size(self, session_id: str) -> int:
        return len(self._buffers.get(session_id, []))

    def active_sessions(self) -> List[str]:
        return list(self._connections.keys())
