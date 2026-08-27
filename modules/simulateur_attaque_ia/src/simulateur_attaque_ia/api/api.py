#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:06:55 2026

@author: hounsousamuel
"""

"""
API principale du simulateur d'attaque.

Architecture :
  /api/*     → routes avec auth JWT  (usage normal)

Routers /api :
  POST   /api/auth/login
  ──────────────────────────────────────────
  POST   /api/sim/start
  POST   /api/sim/{id}/stop
  GET    /api/sim/{id}/status
  GET    /api/sim/list
  GET    /api/sim/{id}/report
  GET    /api/sim/{id}/actions       (mode interactif)
  GET    /api/sim/history
  GET    /api/sim/history/{id}
  ──────────────────────────────────────────
  GET    /api/images/list
  ──────────────────────────────────────────
  POST   /api/clone/start
  GET    /api/clone/{id}/status
  POST  /clone/{id}/stop → arrête la tâche de clonage
  ──────────────────────────────────────────
  GET    /api/services/capture
  POST   /api/services/validate
  POST   /api/services/generate
  ──────────────────────────────────────────
  WS     /api/ws/{session_id}?token=xxx

WebSocket protocol :
  Serveur → Client :
    { type: "connected",          session_id, mode, status, ... }
    { type: "replay_start",       count }
    { type: "replay_end" }
    { type: "sim_status",         status, message }
    { type: "sim_ready",          ip, actions_available, state_summary }   (interactif)
    { type: "step_start",         step, message }
    { type: "step_progress",      step, message, data? }
    { type: "step_result",        step, result, actions_available }        (interactif)
    { type: "step_end",           step }
    { type: "llm_suggest",        suggestion }
    { type: "llm_review",         action, review }
    { type: "sim_state",          state }
    { type: "sim_finished",       report }
    { type: "error",              message }

  Client → Serveur (mode interactif seulement) :
    { type: "execute_action",         action, params: { ... } }
    { type: "request_llm_suggest" }
    { type: "request_llm_review",     action }
    { type: "get_state" }
    { type: "finish" }
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import nest_asyncio
import asyncio
import uvicorn
import aiohttp
import atexit
import time
import threading
from fastapi import FastAPI
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from slowapi.errors import RateLimitExceeded
from simulateur_attaque_ia.configs.config import (
    LIMITE, REACT_EXISTS, IP, PORT,
    INDEX_FILE, STATIC_DIR, STATIC_URL,
    BUILD_DIR, BUILD_URL, ALLOWED_ORIGINS
)
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.orchestrator.managers.simulation_manager import SimulationManager
from simulateur_attaque_ia.orchestrator.managers.ws_manager import WSManager
from simulateur_attaque_ia.core.containers_manager import ContainerManager
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.api.routers.router import router
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.api.routers.clone_router import start_clone_cleanup, stop_clone_cleanup
from simulateur_attaque_ia.api.routers.network_router import (
    remove_all_networks, stop_network_cleanup, start_network_cleanup,
    remove_ephemeral_networks
)
from simulateur_attaque_ia.api.endpoints import ENDPOINTS

logger = get_logger()


async def start_tasks(sim_mgr: SimulationManager, sim_cm: ContainerManager):
    await start_clone_cleanup()    
    sim_mgr.start_background_tasks()
    sim_cm.start_cleanup()
    start_network_cleanup()

async def stop_task(sim_mgr: SimulationManager, ws_mgr: WSManager, sim_cm: ContainerManager):
    await sim_mgr.stop_all_sims(ws_mgr)
    await sim_mgr.stop_background_tasks()
    await stop_clone_cleanup()
    
    await sim_cm.stop_cleanup()
    # await sim_cm.stop_all_containers()
    
    await stop_network_cleanup()
    await asyncio.to_thread(remove_ephemeral_networks, DockerManager().client, True)

async def lifespan_start(app: FastAPI):
    app.state.sim_manager_instance = SimulationManager.get_instance()
    app.state.sim_wsmanager_instance = WSManager.get_instance()
    app.state.sim_container_manager_instance = ContainerManager.get_instance()
    
    dm = DockerManager()
    await asyncio.to_thread(dm.ensure_network, "isolated", True)
    app.state.sim_main_docker_manager = dm
    await start_tasks(app.state.sim_manager_instance, app.state.sim_container_manager_instance)    

async def lifespan_end(app: FastAPI):
    if getattr(app.state, "sim_manager_instance", None):
        await stop_task(
            app.state.sim_manager_instance,
            app.state.sim_wsmanager_instance,
            app.state.sim_container_manager_instance
        )
    if getattr(app.state, "sim_main_docker_manager", None):
        if not app.state.sim_main_docker_manager._network_already_exists:
            app.state.sim_main_docker_manager.remove_network("isolated")
            
    
# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await lifespan_start(app)
    logger.print("Simulateur API lancé")
    
    yield
    
    await lifespan_end(app)
    logger.print("Fermeture")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Simulateur d'Attaque IA — API",
    version="2.0.0",
    description=__doc__,
    lifespan=lifespan,
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router=router(), prefix="/api", tags=["Main API"])

if REACT_EXISTS:
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")
    app.mount(STATIC_URL, StaticFiles(directory=STATIC_DIR), name="static")
    
app.state.limiter = limiter


serveur = None 
LIMITE_STR = f"{LIMITE}/minute"

# =============================================================================
# HANDLER
# =============================================================================

@app.exception_handler(RateLimitExceeded)
async def _handler(request: Request, exc:RateLimitExceeded):
    return JSONResponse(
          content= {
            "status_code": 400,
            "message": "Trop de requêtes, veuillez patientez !"
            },
          status_code=429
        )

# =============================================================================
# ROUTES
# =============================================================================

@app.get('/api/close')
def _close_api():
    global serveur
    if serveur is None:
        print('Serveur non lancé !', serveur)
        return {
            "message ": "Serveur non lancé !"
            }
    else:
        __close_api()
        print('Serveur fermé.')
        return {
            "message ": 'Serveur fermé.'
            }
    
@app.get("/api/test", tags=["Test"])
def _test():
    return {
        "message": "Test de l'api !"
    }

@app.get("/health", tags=["Health"])
async def health() -> dict:
    sim_mgr = SimulationManager.get_instance()
    ws_mgr  = WSManager.get_instance()
    return {
        "status":          "ok",
        "active_sims":     len(sim_mgr.list_sims()),
        "ws_sessions":     len(ws_mgr.active_sessions()),
    }

@app.get("/api/")
async def _home():
    if REACT_EXISTS:
       return FileResponse(INDEX_FILE)
    else:
        return ENDPOINTS

@app.get("/")
async def _home1():
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
   
    else:
        return ENDPOINTS
    

@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """Capture toutes les routes pour React Router"""
    excluded_prefixes = ["api/", "docs", "redoc", "openapi.json"]
    print(full_path)
    print()
    if any(full_path.startswith(prefix) for prefix in excluded_prefixes):
        raise HTTPException(404, detail="Route non trouvée")
        
    if full_path.startswith(STATIC_URL):
        return FileResponse(os.path.join(STATIC_DIR, full_path))
    
    elif full_path.startswith(BUILD_URL):
        return FileResponse(os.path.join(BUILD_DIR, full_path))
    
    elif REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    
    else:
        raise HTTPException(status_code=404, detail="Route non trouvée")
        
    
# =============================================================================
# DEMARRAGE
# =============================================================================

def start(app, host, port):
    global serveur
    conf = uvicorn.Config(
        app=app, 
        workers=10,
        host=host,
        port=port, 
        loop='uvloop' if sys.platform != "win32" else "asyncio", 
        use_colors=True,
        ws_max_size=5 * 1024 * 1024 * 1024,
    )
    serveur = uvicorn.Server(config=conf)
    th = threading.Thread(target=serveur.run, daemon=True)
    return th, serveur

def stop(th: threading.Thread, timeout: int = 5):
    """Arrête proprement le thread serveur."""
    logger.info("Arrêt en cours.")
    th.join(timeout)
    logger.info("Arrêt terminé.")
    
def __close_api():
    global serveur
    serveur.should_exit = True

async def close_api(url):
    """Ferme l'API (utilitaire)."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            print('Statut : ', response.status)


def close_api_atexit(url):
    """Enregistre la fermeture de l'API à la sortie."""
    def _close():
        try:
            from modules_utils.loop_utils import _run_async
            _run_async(close_api, url)
        except Exception:
            pass
    atexit.register(_close)
    
def _routes():
    for route in app.routes:
        print("Nom :", type(route).__name__)
        print("Name :", route.name)
        print("Path :", route.path)
        try:
            print("Methode :", route.methods)
        except Exception: 
            print("Methode : N/A")
        print()
        
if __name__ == "__main__":
    nest_asyncio.apply()
    th, serveur = start(app, IP, PORT)
    th.start()
    time.sleep(2)
    URL = f"http://{IP}:{PORT}/api/"
    URL1 = f"http://{IP}:{PORT}/"
    async def test():
        async with aiohttp.ClientSession() as session:
            async with session.get(URL+"test") as response:
                return {
                    "status_code": response.status,
                    "text": await response.text(),
                    "json": await response.json(),
                    "headers": dict(response.headers)
                    }
    
    async def test1():
        async with aiohttp.ClientSession() as session:
            async with session.get(URL1) as response:
                return {
                    "status_code": response.status,
                    "text": await response.text(),
                    "json": await response.json(),
                    "headers": dict(response.headers)
                    }
            
    async def test_login():
        login_url = URL+"dash/login"
        data = {
            "username": "admin1ZZ",
            "password":"ChangeMe123ZZZD",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(login_url, json=data) as response:
                return await response.json()
    # print(asyncio.run(test()))
    # print(asyncio.run(test1()))
    print(asyncio.run(test_login()))
    time.sleep(4)
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            asyncio.run(close_api(URL+"close"))                
            break
        
    # asyncio.run(close_api(URL+"close"))