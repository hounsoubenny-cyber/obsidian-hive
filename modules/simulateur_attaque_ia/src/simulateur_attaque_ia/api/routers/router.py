#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 02:05:02 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from fastapi import APIRouter, Depends
from simulateur_attaque_ia.api.deps import require_auth
from simulateur_attaque_ia.api.routers.auth_router import auth_router
from simulateur_attaque_ia.api.routers.sim_router import sim_router
from simulateur_attaque_ia.api.routers.images_router import images_router
from simulateur_attaque_ia.api.routers.clone_router import clone_router
from simulateur_attaque_ia.api.routers.services_router import services_router
from simulateur_attaque_ia.api.routers.ws_router import ws_router
from simulateur_attaque_ia.api.routers.containers_router import containers_router
from simulateur_attaque_ia.api.routers.network_router import network_router

def router():
    _router = APIRouter()
    deps = [Depends(require_auth)]
    _router.include_router(
        auth_router, 
        prefix="/auth",   
        tags=["Auth"]
    )
    _router.include_router(
        sim_router,      
        prefix="/sim",   
        tags=["Simulations"],
        dependencies=deps
    )
    _router.include_router(
        images_router,   
        prefix="/images",  
        tags=["Images"],   
        dependencies=deps
    )
    _router.include_router(
        clone_router,   
        prefix="/clone", 
        tags=["Clone"],   
        dependencies=deps
    )
    _router.include_router(
        services_router,
        prefix="/services", 
        tags=["Services"],  
        dependencies=deps
    )
    _router.include_router(
        containers_router,
        prefix="/containers",
        tags=["Containers"],
        dependencies=deps,
    )
    _router.include_router(
        network_router,
        prefix="/network",
        tags=["Network"],
        dependencies=deps,
    )
    _router.include_router(
        ws_router,      
        prefix="/ws",   
        tags=["WebSocket"]
    )
    return _router