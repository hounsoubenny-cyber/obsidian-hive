#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
Router /services – gestion du services.json.

GET  /services/capture   → capture les services actuels du host
POST /services/validate  → valide un services.json fourni
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import asyncio
from fastapi import APIRouter, HTTPException, status, Request
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.api.models.sim_models import ValidateServicesRequest, ValidateServicesResponse
from simulateur_attaque_ia.core.services_manager import ServiceManager
from simulateur_attaque_ia.core.services_validator import validate_services_dict

def make_services_router() -> APIRouter:
    router = APIRouter()

    # ── GET /capture ──────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/capture",
        summary="Capturer les services actuels du host",
        description="Lance `ServiceManager.capture_services()` et retourne le "
                    "services.json correspondant au système actuel.",
    )
    async def capture_services(request: Request) -> dict:
        try:
            services = await asyncio.to_thread(ServiceManager.capture_services)
            return {"services": services}
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail=f"Erreur capture services : {exc}"
            )

    # ── POST /validate ────────────────────────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/validate",
        response_model=ValidateServicesResponse,
        summary="Valider un services.json",
        description="Vérifie la structure d'un services.json avant de lancer une simulation.",
    )
    async def validate_services(
        request: Request,
        data: ValidateServicesRequest
    ) -> ValidateServicesResponse:
        return validate_services_dict(data.services)

    return router


services_router = make_services_router()
services_router_noauth = make_services_router()
