#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
Router WebSocket.

/api/ws/{session_id}?token=xxx  → avec vérification JWT (query param)
/ext/ws/{session_id}            → sans auth (Obsidian gère)

Comportement commun :
  1. Connexion → replay buffer si disponible
  2. Mode AUTO        → client écoute uniquement (lecture seule)
  3. Mode INTERACTIVE → bidirectionnel : client envoie des messages JSON
                        que le SimulationManager traite via action_queue
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Callable

from simulateur_attaque_ia.orchestrator.managers.simulation_manager import SimulationManager
from simulateur_attaque_ia.orchestrator.managers.ws_manager import WSManager
from simulateur_attaque_ia.api.models.sim_models import SimMode, SimStatus
from simulateur_attaque_ia.api.routers import AUTH_DATA, JWT_KEY
from simulateur_attaque_ia.simulateur_utils.jwt_utils import verify_token

def _check(token):
    verify_token(token, AUTH_DATA[JWT_KEY])
    
def make_ws_router(verify_token_function: Callable | None = None) -> APIRouter:
    router  = APIRouter()
    sim_mgr = SimulationManager.get_instance()
    ws_mgr  = WSManager.get_instance()

    @router.websocket("/{session_id}")
    async def ws_endpoint(
        websocket: WebSocket,
        session_id: str,
        token: str = Query(None)
    ) -> None:
        
        if verify_token_function is not None and callable(verify_token_function):
            # ── Auth ──────────────────────────────────────────────────────────────
            if not token:
                await websocket.close(code=4001, reason="Token manquant.")
                return
            try:
                verify_token_function(token)
            except Exception:
                await websocket.close(code=4003, reason="Token invalide.")
                return
            

        # ── Session existante ? ───────────────────────────────────────────────
        sim = sim_mgr.get_sim(session_id)
        if sim is None:
            await websocket.close(code=4004, reason=f"Session '{session_id}' introuvable.")
            return

        # ── Connexion + replay ────────────────────────────────────────────────
        await ws_mgr.connect(session_id, websocket)

        # Envoyer l'état courant au moment de la connexion
        try:
            await websocket.send_json({
                "type":         "connected",
                "session_id":   session_id,
                "mode":         sim.mode.value,
                "status":       sim.status.value,
                "current_step": sim.current_step,
                "actions_done": sim.actions_done,
                "progress":     sim.progress,
            })
        except Exception:
            ws_mgr.disconnect(session_id)
            return

        # ── Boucle selon le mode ──────────────────────────────────────────────
        try:
            if sim.mode == SimMode.AUTO:
                await _loop_auto(websocket, sim, ws_mgr, session_id)
            else:
                await _loop_interactive(websocket, sim, ws_mgr, session_id)

        except WebSocketDisconnect:
            pass
        
        except Exception:
            pass
        
        finally:
            ws_mgr.disconnect(session_id)

    return router


async def _loop_auto(websocket, sim, ws_mgr, session_id):
    """
    Mode auto : client écoute seulement.
    On attend juste la déconnexion (ou la fin de sim).
    On garde le WS ouvert tant que la sim tourne.
    """

    while True:
        if sim.status in (
            SimStatus.COMPLETED,
            SimStatus.FAILED,
            SimStatus.STOPPED,
        ):
            break
        # Ping léger pour détecter une déconnexion
        try:
            await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
        except asyncio.TimeoutError:
            continue    # pas de message du client = normal en mode auto
        except Exception:
            break


async def _loop_interactive(websocket, sim, ws_mgr, session_id):
    """
    Mode interactif : bidirectionnel.
    On lit les messages JSON du client et on les push dans action_queue.
    Le SimulationManager._run_interactive() consomme cette queue.
    """

    # Si la sim attend (WAITING) → envoyer l'état actuel au client
    if sim.status == SimStatus.WAITING and sim.orchestrator:
        try:
            await websocket.send_json({
                "type":              "sim_ready",
                "session_id":        session_id,
                "actions_available": sim.orchestrator.available_actions(),
                "actions_done":      sim.actions_done,
                "state_summary":     sim.orchestrator.get_state_summary(),
            })
        except Exception:
            return

    while True:
        try:
            data = await websocket.receive_json()
            # print("WS Router: ", data)
        except Exception:
            break

        msg_type = data.get("type", "")

        # Messages valides côté client
        if msg_type in (
            "execute_action",
            "request_llm_suggest",
            "request_llm_review",
            "get_state",
            "finish",
        ):
            if msg_type == "finish" or (msg_type == "execute_action" and data.get("action", "") == "finish"):
                await sim.action_queue.put(None)    
            else:
                await sim.action_queue.put(data)
        else:
            # Message inconnu → on notifie le client
            try:
                await websocket.send_json({
                    "type":    "error",
                    "message": f"Type de message inconnu : '{msg_type}'. "
                               "Types valides : execute_action, request_llm_suggest, "
                               "request_llm_review, get_state, finish.",
                })
            except Exception:
                break


# ── Instances exportées ───────────────────────────────────────────────────────

ws_router = make_ws_router(verify_token_function=_check)
