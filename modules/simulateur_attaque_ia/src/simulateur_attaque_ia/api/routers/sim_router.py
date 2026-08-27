#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
Router /sim – gestion du cycle de vie des simulations.

Utilisé deux fois :
  - /api/sim  (avec auth)   → monté dans main.py
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from fastapi import APIRouter, HTTPException, status, Request

from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.orchestrator.managers.simulation_manager import SimulationManager
from simulateur_attaque_ia.orchestrator.managers.ws_manager import WSManager
from simulateur_attaque_ia.api.models.sim_models import StartSimRequest, StartSimResponse, SimStatus


def make_sim_router() -> APIRouter:
    router = APIRouter()
    sim_mgr = SimulationManager.get_instance()
    ws_mgr  = WSManager.get_instance()

    # ── POST /start ──────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/start",
        response_model=StartSimResponse,
        summary="Lancer une simulation",
        description="""
Lance une simulation (auto ou interactive) sur l'image Docker donnée.

- **image** : image Docker locale (obligatoire).
- **services** : contenu services.json (optionnel — auto-capturé si absent).
- **use_llm** : active le LLM pour les décisions/suggestions.
- **mode** : `auto` (simulation autonome) ou `interactive` (dirigée via WS).
- **sim_config** : paramètres fins de chaque tactic (tout optionnel, defaults appliqués).
""",
    )
    async def start_sim(
        request: Request,
        data: StartSimRequest
    ) -> StartSimResponse:
        
        if not sim_mgr.can_start():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Quota de simulations parallèles atteint.",
            )
        
        try:
            session_id = await sim_mgr.start_sim(data, ws_mgr)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
            
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
            )

        return StartSimResponse(
            session_id=session_id,
            status=SimStatus.STARTING,
            message=f"Simulation démarrée — connectez-vous au WS /{session_id} pour suivre.",
        )

    # ── POST /{session_id}/stop ───────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{session_id}/stop",
        summary="Arrêter une simulation",
    )
    async def stop_sim(
        request: Request,
        session_id: str
    ) -> dict:
        ok = await sim_mgr.stop_sim(session_id, ws_mgr)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' introuvable.",
            )
        return {"session_id": session_id, "status": SimStatus.STOPPED.value, "message": "Simulation arrêtée."}

    # ── GET /{session_id}/status ──────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/{session_id}/status",
        summary="Status d'une simulation active",
    )
    async def sim_status(
        request: Request,
        session_id: str
    ) -> dict:
        sim = sim_mgr.get_sim(session_id)
        if sim is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' introuvable.",
            )
        return sim.to_dict()

    # ── GET /list ─────────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/list",
        summary="Liste des simulations actives",
    )
    async def list_sims(request: Request) -> dict:
        r =  {"sims": sim_mgr.list_sims()}
        return r

    # ── GET /{session_id}/report ──────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/{session_id}/report",
        summary="Rapport final d'une simulation",
    )
    async def sim_report(request: Request, session_id: str) -> dict:
        report = sim_mgr.get_report(session_id)
        if report is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rapport introuvable pour '{session_id}'. "
                       "La simulation est-elle terminée ?",
            )
        return report

    # ── GET /{session_id}/actions ─────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/{session_id}/actions",
        summary="Actions disponibles (mode interactif)",
    )
    async def available_actions(request: Request, session_id: str) -> dict:
        sim = sim_mgr.get_sim(session_id)
        if sim is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' introuvable.",
            )
        if sim.orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="La simulation n'est pas encore prête.",
            )
        if not hasattr(sim.orchestrator, "available_actions"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cette route n'est disponible qu'en mode interactif.",
            )
        
        if hasattr(sim.orchestrator, "available_actions_with_details"):
            details = sim.orchestrator.available_actions_with_details()
        else:
            details = None
            
        return {
            "session_id":        session_id,
            "actions_available": sim.orchestrator.available_actions(),
            "actions_available_with_details":  details,
            "actions_done":      sim.actions_done,
        }

    # ── GET /history ──────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/history",
        summary="Historique de toutes les simulations",
    )
    async def list_history(request: Request,) -> dict:
        return {"history": sim_mgr.list_history()}

    # ── GET /history/{sim_id} ─────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/history/{sim_id}",
        summary="Détail d'une simulation passée",
    )
    async def get_history(request: Request, sim_id: str) -> dict:
        entry = sim_mgr.get_history(sim_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Historique introuvable pour '{sim_id}'.",
            )
        return entry

    return router


# Instances exportées
sim_router       = make_sim_router()    
sim_router_noauth = make_sim_router()   
