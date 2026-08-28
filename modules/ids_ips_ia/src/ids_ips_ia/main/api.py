#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 07:02:26 2026

@author: hounsousamuel


Point d'entrée de l'API IDS/IPS.
Contient uniquement : création de l'app FastAPI, lifespan, montage des
routers, routes "infra" (React/catch-all/rate-limit), et le bloc
`if __name__ == "__main__"`. Toute la logique vit dans services.py /
orchestrator.py, tous les schémas dans schemas.py, toutes les routes API
dans routes.py.

"""

import os
import sys
import threading
import traceback
import warnings
from contextlib import asynccontextmanager

import nest_asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded

from ids_ips_ia.config.config_ids import ALLOWED_ORIGINS, REQUEST_LIMIT as REQUEST, API_CONFIG, GRAPH
from ids_ips_ia.config.frontend_config import (
    STATICDIR, BUILD_DIR, INDEX_FILE, REACT_EXISTS, BUILD_URL, STATIC_URL
)
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.warnings_manager import suppres_warnings
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from modules_utils.limiter import limiter, get_remote_address

from ids_ips_ia.main.routes import router, router_no_auth
from ids_ips_ia.main.orchestrator import IDS_IPS, graph
from ids_ips_ia.main.server_state import start, stop
from ids_ips_ia.main.services import _do_help

warnings.filterwarnings("ignore")

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

logger = get_logger()
suppres_warnings()

host = API_CONFIG.get('host', '0.0.0.0')
port = API_CONFIG.get('port', 8080)


@asynccontextmanager
async def lifespan(app: FastAPI):
    ids_ips = None
    thread = None

    if __name__ != "__main__":
        ids_ips = IDS_IPS()
        thread = threading.Thread(
            target=ids_ips.main,
            args=(True,),
            daemon=True,
            name="IDS_IPS_Main"
        )
        thread.start()
        ids_ips._setup_signal_handlers()
        app.state._ids_ips = ids_ips
        app.state._ids_thread = thread
        app.state._ids_is_started = True

    logger.print("API lancée !!!")
    yield

    if ids_ips:
        ids_ips.stop()
        
    if thread and thread.is_alive():
        thread.join(timeout=10)
        
    logger.print("API fermée !!!")


app = FastAPI(
    title='IDS/IPS',
    version="2.0.0",
    description="Système de détction et de prévention d'intrusions",
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if REACT_EXISTS:
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")
    app.mount(STATIC_URL, StaticFiles(directory=STATICDIR), name="static")

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Trop rapide!",
            "message": f"{REQUEST} requêtes max par minute",
            "retry_after": 60
        }
    )


# =============================================================================
# INTÉGRATION DES ROUTEURS
# =============================================================================
app.include_router(router, prefix="/api")
# app.include_router(router_no_auth, prefix="/api_gateway")  # à activer côté gateway


@app.get("/api/rate-limit-status")
@limiter.limit(f"{REQUEST}/minute")
async def rate_limit_status(request: Request):
    return {
        "ip": get_remote_address(request),
        "limit": f"{REQUEST}/minute"
    }


@app.get(path="/api/openapi")
async def _open_api():
    return app.openapi()


@app.get("/")
async def serve_react_app():
    """Sert l'application React - point d'entrée"""
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    else:
        return {
            "message": "API IDS/IPS - Interface React non disponible",
            "Port graphe": graph.port if graph else "Pas de graph",
            "instructions": "Build React manquant. Exécutez: npm run build dans le dossier frontend",
            "api_available": True,
            "api_docs": "/api/docs",
            "endpoints": {
                "GET /api/action": "Éffectué une action",
                "GET /api/help": "Obtenir de l'aide et des rensignement",
                "GET /api/rate-limit-status": "Obtenir la limitation de requête par minute",
                "GET /api/docs": "Documentation FastAPI",
                "GET /api/redoc": "Documentation FastAPI",
                "GET /api/openapi.json": "Info sur l'api actuellement",
            },
            "rate_limit": f"{REQUEST} requêtes/minute",
            "doc": _do_help()
        }


@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """Capture toutes les routes pour React Router"""
    excluded_prefixes = ["api/", "docs", "redoc", "openapi.json"]
    if any(full_path.startswith(prefix) for prefix in excluded_prefixes):
        raise HTTPException(404, detail="Route non trouvée")

    if full_path.startswith("static/"):
        return FileResponse(os.path.join(STATICDIR, full_path))

    elif full_path.startswith("build/"):
        return FileResponse(os.path.join(BUILD_DIR, full_path))

    elif REACT_EXISTS:
        return FileResponse(INDEX_FILE)

    else:
        raise HTTPException(status_code=404, detail="Route non trouvée")


# =============================================================================
# ENTRÉE PRINCIPALE
# =============================================================================
if __name__ == "__main__":
    nest_asyncio.apply()
    ids_ips = IDS_IPS()
    try:
        th, _ = start(app, host, port)
        th.start()

        def _main_signal_handler(*args, **kwargs):
            logger.print("\n[SIGNAL] Arrêt demandé...")
            ids_ips.stop()

        signal_manager(_main_signal_handler)
        app.state._ids_ips = ids_ips
        app.state._ids_is_started = True
        ids_ips.main(True)
        ids_ips.stop()

    except Exception as e:
        logger.print(f"[ERROR] Exception dans main : {e}")
        if GRAPH:
            graph.end()
        traceback.print_exc()

    except KeyboardInterrupt:
        import time
        time.sleep(10)
        sys.exit(0)