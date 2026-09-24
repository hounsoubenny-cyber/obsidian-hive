#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 23:28:18 2026

@author: hounsousamuel
"""

import os
import aiohttp
import atexit
import uvicorn
import threading
import contextlib
from dotenv import load_dotenv
from fastapi import (
    FastAPI, Depends, HTTPException,
    Request
)
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from modules_utils.api_dependencies import get_loop
from scanner_ia.api.api import ( # noqa
    router as scanner_router, get_shared_scanner_ia,
    ws_router as scanner_ws_router,
    REPORT_DIR
)
from anti_phishing_ia.main_phish import router as ap_router, get_ap_instance # noqa
from sandbox_ia.api.router import ( # noqa
    router as sandbox_router, get_orchestrator, 
    get_models as get_sandbox_models, ML_AVAILABLE as SANDBOX_ML_AVAILABLE
)
from ids_ips_ia.main.api import (
    router_no_auth as ids_ips_router
)
from simulateur_attaque_ia.api.routers.router_no_auth import (
    router as make_sim_router
)
from simulateur_attaque_ia.api.api import (
    lifespan_start as sim_lifespan_start, lifespan_end as sim_lifespan_end
)
from contextguard.api.router import (
    router as contextguard_router
)
from obsidian_hive.api.api_utils.core_shared import get_engine
from obsidian_hive.api.routers.core_router import (
    router as core_router,
    router_no_auth as core_public_router
)
from obsidian_hive.api.routers.core_ws_router import ws_router
from obsidian_hive.api.routers.donwloads_router import (
    router as download_router, 
    public_router as download_public_router
)
from obsidian_hive.api.routers.scanner_report_manager_router import (
    router as scanner_report_manager_router, MOUNT_PATH, WEB_ASSET_SCAN_REPORT_DIR
)
from obsidian_hive.api.routers.anti_phishing_extension_router import (
    router_ext as anti_phishing_extension_router
)
from obsidian_hive.api.routers.extension_token_manager_router import (
    router as extension_token_manager_router
)
from obsidian_hive.api.routers.utils_router import router as utils_router
from obsidian_hive.api.routers.manager_router import router as manager_router
from obsidian_hive.api.routers.login_router import router as login_router
from modules_utils.logger import get_logger
from modules_utils.limiter import limiter, get_remote_address
from obsidian_hive.api.ap_config import (
    ALLOWED_ORIGINS, LIMITE,
    REACT_EXISTS, INDEX_FILE, STATIC_DIR,
    BUILD_DIR, BUILD_URL, STATIC_URL,
)
from obsidian_hive.api.state import (
    _get_auth_manager, _get_contextguard_client, _get_conversation_manager,
    _get_extension_token_manager, _get_job_manager, _get_llm_manager,
    _get_report_manager
)
from obsidian_hive.agents.analyst.analayst_workspace.workspace import WorkSpace
load_dotenv()

logger = get_logger("main_shield_api")
server = None

async def lifespan_start(app: FastAPI):
    """
    Initialise tous les composants de l'API au démarrage.

    Args:
        app (FastAPI): L'application FastAPI.
    """
    _get_auth_manager().verify_env_utils()
    # app.state.ap_instance = get_ap_instance()
    
    # app.state.shared_scanner_ia_instance = get_shared_scanner_ia()
    
    # app.state.sandbox_orchestrator_instance = get_orchestrator()
    # app.state.sandbox_models = None
    # if SANDBOX_ML_AVAILABLE:
    #     app.state.sandbox_models = get_sandbox_models()   
    
    app.state.core_engine = get_engine()
    app.state.llm_manager = _get_llm_manager()
    app.state.auth_manager = _get_auth_manager()
    app.state.report_manager = await _get_report_manager()
    app.state.job_manager = await _get_job_manager()
    app.state.conversation_manager = await _get_conversation_manager()
    app.state.extension_token_manager = await _get_extension_token_manager()
    app.state.context_guard_client = await _get_contextguard_client()
    
    await sim_lifespan_start(app)
    await app.state.core_engine.start()
    
    logger.success("API démaré")


async def lifespan_end(app: FastAPI):
    """
    Nettoie tous les composants de l'API à l'arrêt.

    Args:
        app (FastAPI): L'application FastAPI.
    """
    
    await sim_lifespan_end(app)
    await WorkSpace.kill_proxy_container_async()
    logger.success("API fermée")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestionnaire de cycle de vie de l'application FastAPI.

    Args:
        app (FastAPI): L'application FastAPI.
    """
    await lifespan_start(app)
    yield
    await lifespan_end(app)
    

app = FastAPI(
    title="Obsidian-Hive",
    version="1.0.0",
    lifespan=lifespan,
    description="API de obsidian",
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/api/scanner_reports", StaticFiles(directory=REPORT_DIR), name="reports")
app.mount(MOUNT_PATH, StaticFiles(directory=WEB_ASSET_SCAN_REPORT_DIR), name="asset_scan_reports")

if REACT_EXISTS:
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")
    app.mount(STATIC_URL, StaticFiles(directory=STATIC_DIR), name="static")
    
sim_router, sim_ws_router = make_sim_router(_get_auth_manager().verify_token_params)

_ROUTERS = [
    # Scanner
    (scanner_router, "scanner", True),
    (scanner_ws_router, "scanner", False),
    
    # Anti Phishing
    (ap_router, "anti_phishing", True),
    
    # IDS-IPS
    (ids_ips_router, "ids_ips", True),
    
    # Sandbox
    (sandbox_router, "sandbox", True),
    
    # Simulateur
    (sim_router, "simulator", True),
    (sim_ws_router, "simulator", False),
    
    # ContextGuard
    (contextguard_router, "contextguard", True),
    
    # Core
    (core_router, "core", True),
    (core_public_router, "core", False),
    (ws_router, "core_ws", False),
    
    # Managers
    (manager_router, "managers", True),
    
    # Utils
    (utils_router, "utils", True),
    
    # Login
    (login_router, "auth_routes", False),
    
    # Download
    (download_router, "download", True),
    (download_public_router, "download", False),
    
    # Extentions
    # Anti Phishing ectension
    (anti_phishing_extension_router, "anti_phishing_extension", False),
    (extension_token_manager_router, "extension_tokens", True),
    
    # Scanner report routes (WebAsset reports)
    (scanner_report_manager_router, "web_asset_report", True),
]

dependencies = [Depends(
    _get_auth_manager().verify_token
)]

for router, name, dependencie in _ROUTERS:
    app.include_router(
        router=router,
        prefix=f"/api/{name}",
        **({"dependencies": dependencies} if dependencie else {})
    )

app.state.limiter = limiter

# =============================================================================
# Fontions utilitaires
# =============================================================================

def __close_api():
    """Ferme l'API en arrêtant le serveur uvicorn."""
    global server
    server.should_exit = True


# =============================================================================
# Handler
# =============================================================================

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Gère les erreurs de dépassement de limite de taux.

    Args:
        request (Request): La requête FastAPI.
        exc (RateLimitExceeded): L'exception de limite dépassée.

    Returns:
        JSONResponse: Réponse 429 avec un message d'erreur.
    """
    return JSONResponse(
        status_code=429,
        content={
            "error": "Trop de requêtes, veuillez patienter avant de retenter !",
            "message": f"{LIMITE} requêtes max par minute",
            "retry_after": 60
        }
    )


# =============================================================================
# Routes
# =============================================================================

@app.get('/api/close')
def _close_api():
    """
    Endpoint pour fermer proprement l'API.

    Returns:
        dict: Message de confirmation.
    """
    global server
    if server is None:
        logger.info('Serveur non lancé !', server)
        return {
            "message ": "Serveur non lancé !"
            }
    else:
        __close_api()
        logger.info('Serveur fermé.')
        return {
            "message ": 'Serveur fermé.'
            }


@app.get("/api/rate-limit-status")
@limiter.limit(f"{LIMITE}/minute")
async def rate_limit_status(request: Request):
    """
    Retourne l'état de la limitation de taux pour l'IP actuelle.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        dict: Informations sur la limite de taux.
    """
    return {
        "ip": get_remote_address(request),
        "limit": f"{LIMITE}/minute"
    }


@app.get("/")
async def serve_react_app():
    """
    Sert l'application React - point d'entrée principal.

    Returns:
        FileResponse | dict: Le fichier index.html ou un message vide.
    """
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    else:
        return {
        }

    
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """
    Capture toutes les routes pour React Router.

    Args:
        full_path (str): Le chemin complet de la requête.

    Returns:
        FileResponse | dict: Le fichier demandé ou index.html pour React.

    Raises:
        HTTPException: 404 si la route n'existe pas.
    """
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
# DÉMARRAGE
# =============================================================================

def start(app, host: str = "0.0.0.0", port: int = 8000):
    """
    Démarre le serveur dans un thread séparé.

    Args:
        app (FastAPI): L'application FastAPI.
        host (str, optional): L'hôte d'écoute. Par défaut "0.0.0.0".
        port (int, optional): Le port d'écoute. Par défaut 8000.

    Returns:
        tuple: (thread, server) - Le thread et l'instance du serveur.
    """
    global server
    config = uvicorn.Config(
        app=app, 
        host=host, 
        port=port, 
        loop=get_loop(), 
        use_colors=True, 
        workers=1,
    )
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True)
    return th, server


def stop(th: threading.Thread, timeout: int = 5):
    """
    Arrête proprement le thread serveur.

    Args:
        th (threading.Thread): Le thread du serveur.
        timeout (int, optional): Timeout d'attente. Par défaut 5.
    """
    logger.info("Arrêt du serveur...")
    th.join(timeout)
    logger.info("Serveur arrêté.")


async def close_api(url):
    """
    Ferme l'API via une requête HTTP.

    Args:
        url (str): L'URL de l'API.
    """
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            logger.print('Statut : ', response.status)


def close_api_atexit(url):
    """
    Enregistre la fermeture de l'API à la sortie du programme.

    Args:
        url (str): L'URL de l'API.
    """
    def _close():
        try:
            from modules_utils.loop_utils import _run_async
            _run_async(close_api, url)
        except Exception:
            pass
        
    atexit.register(_close)

    
def _routes():
    """
    Affiche toutes les routes enregistrées dans l'application.

    Utile pour le débogage.
    """
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
    _routes()