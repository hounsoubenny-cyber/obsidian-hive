#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 23:28:18 2026

@author: hounsousamuel
"""

import os
import aiohttp
import asyncio
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
from modules_utils.api_dependencies import AuthManager, get_loop
from scanner_ia.api.api import (
    router as scanner_router, get_shared_scanner_ia,
    ws_router as scanner_ws_router,
    REPORT_DIR
)
from anti_phishing_ia.main_phish import router as ap_router, get_ap_instance
from sandbox_ia.api.router import (
    router as sandbox_router, get_orchestrator, 
    get_models as get_sandbox_models, ML_AVAILABLE as SANDBOX_ML_AVAILABLE
)
from ids_ips_ia.main.api import (
    router_no_auth as ids_ips_router
)
from ids_ips_ia.main.services import(
    _do_start_logic as ids_ips_start, _do_stop_logic as ids_ips_stop
)
from simulateur_attaque_ia.api.routers.router_no_auth import (
    router as make_sim_router, attach_to_state as sim_attach_to_state,
    SimulationManager, WSManager as SimWSManager, ContainerManager as SimContainerManager
)
from simulateur_attaque_ia.api.api import (
    start_tasks as sim_start_tasks, stop_task as sim_stop_task,
    lifespan_start as sim_lifespan_start, lifespan_end as sim_lifespan_end
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
from obsidian_hive.api.routers.anti_phishing_extension_router import (
    router_ext as anti_phishing_extension_router
)
from obsidian_hive.core.managers.extension_token_manager import ExtensionTokenManager
from obsidian_hive.api.routers.utils_router import router as utils_router
from obsidian_hive.api.routers.manager_router import router as manager_router
from obsidian_hive.api.routers.login_router import router as login_router
from modules_utils.logger import get_logger
from modules_utils.limiter import limiter, get_remote_address
from obsidian_hive.core.assets.workflows.workflow_base import WorkflowBase
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.managers.conversation_manager import ConversationManager

from obsidian_hive.api.ap_config import (
    ALLOWED_ORIGINS, EXP, NOT_BEFORE,
    USER_ENV_KEY, PASSWD_ENV_KEY, 
    SECRET_KEY_ENV_KEY, LIMITE,
    REACT_EXISTS, INDEX_FILE, STATIC_DIR,
    BUILD_DIR, BUILD_URL, STATIC_URL,
)

from obsidian_hive.config.config import (
    LLM_MANAGER_CONFIG, ENGINE_CONFIG,
)

load_dotenv()
_auth_manager = None
_shared_llm_manager = None
_shared_llm_manager_is_set = False
_shared_report_manager = None
_shared_conversation_manager = None
_shared_extension_token_manager = None
_shared_report_manager_is_set = False
_shared_job_manager = None
logger = get_logger("main_shield_api")
server = None


def _get_auth_manager() -> AuthManager:
    """
    Retourne l'instance singleton du gestionnaire d'authentification.

    Returns:
        AuthManager: L'instance du gestionnaire d'authentification.
    """
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager(
            exp=EXP,
            not_before=NOT_BEFORE,
            user_env_key=USER_ENV_KEY,
            passwd_env_key=PASSWD_ENV_KEY,
            secret_key_env_key=SECRET_KEY_ENV_KEY,
        )
        _auth_manager.verify_env_utils()
    return _auth_manager


def _get_llm_manager():
    """
    Retourne l'instance singleton du gestionnaire LLM.

    Returns:
        LLMManager: L'instance du gestionnaire LLM.
    """
    global _shared_llm_manager, _shared_llm_manager_is_set
    if not _shared_llm_manager:
        _shared_llm_manager = LLMManager(
            **LLM_MANAGER_CONFIG
        )
    if not _shared_llm_manager_is_set:
        WorkflowBase.set_llm_manager(_shared_llm_manager)
        _shared_llm_manager_is_set = True
    return _shared_llm_manager


async def _get_report_manager():
    """
    Retourne l'instance singleton du gestionnaire de rapports.

    Returns:
        ReportManager: L'instance du gestionnaire de rapports.
    """
    global _shared_report_manager, _shared_report_manager_is_set
    if not _shared_report_manager:
        _shared_report_manager = ReportManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_report_manager.init_db()
    if not _shared_report_manager_is_set:
        WorkflowBase.set_report_manager(_shared_report_manager)
        _shared_report_manager_is_set = True
    return _shared_report_manager


async def _get_job_manager():
    """
    Retourne l'instance singleton du gestionnaire de jobs.

    Returns:
        JobManager: L'instance du gestionnaire de jobs.
    """
    global _shared_job_manager
    if not _shared_job_manager:
        _shared_job_manager = JobManager(db_url=ENGINE_CONFIG["db_url"]) 
        _shared_job_manager.start()
    return _shared_job_manager


async def _get_conversation_manager():
    """
    Retourne l'instance singleton du gestionnaire de conversations.

    Returns:
        ConversationManager: L'instance du gestionnaire de conversations.
    """
    global _shared_conversation_manager
    if not _shared_conversation_manager:
        _shared_conversation_manager = ConversationManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_conversation_manager.init_db()
    return _shared_conversation_manager

async def _get_extension_token_manager():
    global _shared_extension_token_manager
    if not _shared_extension_token_manager:
        _shared_extension_token_manager = ExtensionTokenManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_extension_token_manager.init_db()
    return _shared_extension_token_manager

async def lifespan_start(app: FastAPI):
    """
    Initialise tous les composants de l'API au démarrage.

    Args:
        app (FastAPI): L'application FastAPI.
    """
    _get_auth_manager().verify_env_utils()
    # app.state.ap_instance = get_ap_instance()
    
    # app.state.sandbox_orchestrator_instance = get_orchestrator()
    
    # app.state.sandbox_models = None
    # if SANDBOX_ML_AVAILABLE:
    #     app.state.sandbox_models = get_sandbox_models()    
    
    # app.state.shared_scanner_ia_instance = get_shared_scanner_ia()
    
    # await sim_lifespan_start(app)
    
    app.state.core_engine = get_engine()
    app.state.llm_manager = _get_llm_manager()
    app.state.auth_manager = _get_auth_manager()
    app.state.report_manager = await _get_report_manager()
    app.state.job_manager = await _get_job_manager()
    app.state.conversation_manager = await _get_conversation_manager()
    app.state.extension_token_manager = await _get_extension_token_manager()
    
    await app.state.core_engine.start()
    
    logger.success("API démaré")


async def lifespan_end(app: FastAPI):
    """
    Nettoie tous les composants de l'API à l'arrêt.

    Args:
        app (FastAPI): L'application FastAPI.
    """
    
    # await sim_lifespan_end(app)
    
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
    title="ShieldAI App",
    version="1.0.0",
    lifespan=lifespan,
    description="API de shield AI",
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],
)

app.mount("/api/scanner_reports", StaticFiles(directory=REPORT_DIR), name="reports")

if REACT_EXISTS:
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")
    app.mount(STATIC_URL, StaticFiles(directory=STATIC_DIR), name="static")
    
sim_router, sim_ws_router = make_sim_router(_get_auth_manager().verify_token_params)

_ROUTERS = [
    (scanner_router, "scanner", True),
    (scanner_ws_router, "scanner", False),
    
    (ap_router, "anti_phishing", True),
    
    (ids_ips_router, "ids_ips", True),
    
    (sandbox_router, "sandbox", True),
    
    (sim_router, "simulator", True),
    (sim_ws_router, "simulator", False),
    
    (core_router, "core", True),
    (core_public_router, "core", False),
    (ws_router, "core_ws", False),
    
    (manager_router, "managers", True),
    (utils_router, "utils", True),
    (login_router, "auth_routes", False),
    
    (download_router, "download", True),
    (download_public_router, "download", False),
    
    (anti_phishing_extension_router, "anti_phishing_extension", False)
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
            "error": "Trop rapide !",
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