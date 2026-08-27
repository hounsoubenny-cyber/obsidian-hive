#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 02:05:02 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from fastapi import APIRouter
from simulateur_attaque_ia.api.routers.sim_router import sim_router_noauth
from simulateur_attaque_ia.api.routers.images_router import images_router_noauth
from simulateur_attaque_ia.api.routers.clone_router import clone_router_noauth
from simulateur_attaque_ia.api.routers.services_router import services_router_noauth
from simulateur_attaque_ia.api.routers.containers_router import containers_router_noauth
from simulateur_attaque_ia.api.routers.ws_router import make_ws_router
from simulateur_attaque_ia.orchestrator.managers.simulation_manager import SimulationManager
from simulateur_attaque_ia.orchestrator.managers.ws_manager import WSManager
from simulateur_attaque_ia.core.containers_manager import ContainerManager
from simulateur_attaque_ia.api.routers.network_router import network_router_noauth

def attach_to_state(state):
    state.sim_manager_instance = SimulationManager.get_instance()
    state.sim_wsmanager_instance = WSManager.get_instance()
    state.sim_container_manager_instance = ContainerManager().get_instance()
    
def router(verify_token_function):
    if not verify_token_function or not callable(verify_token_function):
        raise ValueError("Fonction de vérification de token requis")
        
    _router = APIRouter()
    _ws_router = APIRouter()
    _router.include_router(
        sim_router_noauth,      
        prefix="/sim",   
        tags=["Simulations"],
    )
    _router.include_router(
        images_router_noauth,
        prefix="/images",  
        tags=["Images"],   
    )
    _router.include_router(
        clone_router_noauth,
        prefix="/clone", 
        tags=["Clone"],   
    )
    _router.include_router(
        services_router_noauth,
        prefix="/services", 
        tags=["Services"],  
    )
    _router.include_router(
        containers_router_noauth,
        prefix="/containers",
        tags=["Containers"],
    )
    _router.include_router(
        network_router_noauth,
        prefix="/network",
        tags=["Network"],
    )
    _ws_router.include_router(
        make_ws_router(verify_token_function),
        prefix="/ws",   
        tags=["WebSocket"]
    )
    return _router, _ws_router