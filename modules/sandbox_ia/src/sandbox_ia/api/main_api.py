#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API FastAPI — Sandbox ShieldAI
Auteur: HOUNSOU Samuel
Version: 2.0.0
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import json
import uvicorn
import threading
import time
import signal
import asyncio
import aiohttp
import atexit
import contextlib
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from sandbox_ia.api.api_config import (
    API_HOST, API_PORT, LIMITE, ALLOWED_ORIGINS,
    REACT_EXISTS, BUILD_DIR, INDEX_FILE, STATIC_DIR,
)
from sandbox_ia.api.router import router
from modules_utils.limiter import limiter, get_remote_address
from modules_utils.api_dependencies import get_loop
# =============================================================================
# CRÉATION DE L'APP
# =============================================================================

async def lifespan(app: FastAPI):
    print("API SandBox lancé !")
    yield
    print("API fermé !")
    
app = FastAPI(
    title="Sandbox ShieldAI API",
    version="2.0.0",
    description="API d'analyse comportementale de code malveillant dans un sandbox isolé",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.include_router(router, prefix="/api")

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Trop de requêtes !",
            "message": f"{LIMITE} requêtes max par minute",
            "retry_after": 60
        }
    )

# =============================================================================
# ROUTES PRINCIPALES
# =============================================================================

@app.get("/api/help")
@limiter.limit(f"{LIMITE}/minute")
async def help_api(request: Request):
    """Documentation de l'API Sandbox."""
    return {
        "message": "API Sandbox ShieldAI - Documentation",
        "version": "2.0.0",
        "endpoints": {
            "POST /api/analyse_code": {
                "description": "Analyse un code source dans le sandbox (supporte upload de fichier)",
                "content_type": "multipart/form-data",
                "params": {
                    "code": "str (optionnel) - Code source à analyser",
                    "file": "file (optionnel) - Fichier de code à analyser",
                    "language": "str (optionnel) - Langage (None = auto)",
                    "config_str": "str (optionnel) - JSON de configuration",
                    "use_cache": "int (défaut: 1) - 1=activer le cache, 0=désactiver"
                },
                "config_options": {
                    "network_disabled": "bool (défaut: true)",
                    "mem_limit": "str (défaut: 256m)",
                    "extra_env": "dict (optionnel)",
                    "exec_timeout": "float (défaut: 30.0)",
                    "enable_strace": "bool (défaut: true)",
                    "enable_fs_monitor": "bool (défaut: true)",
                    "alert_threshold": "int (défaut: 60)",
                    "decay_interval": "float (défaut: 10.0)",
                    "decay_amount": "int (défaut: 5)"
                },
                "exemple_curl": "curl -X POST http://localhost:8100/api/analyse_code -F 'code=print(\"hello\")' -F 'language=python'",
                "exemple_upload": "curl -X POST http://localhost:8100/api/analyse_code -F 'file=@script.py' -F 'config_str={\"exec_timeout\":60,\"mem_limit\":\"512m\"}'"
            },
            "POST /api/estimate_risk": {
                "description": "Estimation de risque statique (sans exécution) - < 1s",
                "content_type": "multipart/form-data",
                "params": {
                    "code": "str (optionnel) - Code source à analyser",
                    "file": "file (optionnel) - Fichier de code"
                },
                "exemple_curl": "curl -X POST http://localhost:8100/api/estimate_risk -F 'code=import os; os.system(\"ls\")'",
                "exemple_upload": "curl -X POST http://localhost:8100/api/estimate_risk -F 'file=@script.py'"
            },
            "GET /api/languages": {
                "description": "Liste des langages supportés par le sandbox",
                "exemple": "curl http://localhost:8100/api/languages"
            },
            "GET /api/config": {
                "description": "Configuration par défaut du sandbox",
                "exemple": "curl http://localhost:8100/api/config"
            },
            "GET /api/status/container": {
                "description": "État du container sandbox",
                "exemple": "curl http://localhost:8100/api/status/container"
            },
            "GET /api/status/health": {
                "description": "Health check de l'API",
                "exemple": "curl http://localhost:8100/api/status/health"
            },
            "GET /api/help": {
                "description": "Cette documentation"
            },
            "GET /api/close": {
                "description": "Ferme le serveur",
                "exemple": "curl http://localhost:8100/api/close"
            },
            "GET /api/rate-limit-status": {
                "description": "Statut du rate limiting",
                "exemple": "curl http://localhost:8100/api/rate-limit-status"
            }
        },
        "rate_limit": f"{LIMITE} requêtes par minute",
        "auth": "Aucune authentification requise pour le moment",
        "reponse_type": "JSON",
        "exemple_reponse": {
            "session_id": "shieldai_20260621_123456",
            "final_score": 86,
            "final_level": "CRITICAL",
            "alerts_count": 6,
            "killed": True,
            "session_duration": 1.36
        }
    }


@app.get("/api/close")
async def close_api():
    """Ferme proprement le serveur."""
    global server
    if server is None:
        return {"message": "Serveur non lancé"}
    
    server.should_exit = True
    print("🔴 Serveur fermé")
    return {"message": "Serveur fermé"}


@app.get("/api/rate-limit-status")
@limiter.limit(f"{LIMITE}/minute")
async def rate_limit_status(request: Request):
    return {
        "ip": get_remote_address(request),
        "limit": f"{LIMITE}/minute"
    }


# =============================================================================
# ROUTES REACT (si présentes)
# =============================================================================

if REACT_EXISTS:
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.mount("/build", StaticFiles(directory=BUILD_DIR), name="build")

@app.get("/")
async def serve_react():
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    return {
        "message": "API Sandbox ShieldAI",
        "api_docs": "/api/docs",
        "api_redoc": "/api/redoc",
        "rate_limit": f"{LIMITE} requêtes/minute"
    }


@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    excluded = ["api/", "docs", "redoc", "openapi.json", "reports/"]
    if any(full_path.startswith(p) for p in excluded):
        raise HTTPException(404, detail="Route non trouvée")
    
    if full_path.startswith("static/") or full_path.startswith("build/"):
        return FileResponse(os.path.join(BUILD_DIR, full_path))
    
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    
    raise HTTPException(404, detail="Route non trouvée")

# =============================================================================
# SERVEUR
# =============================================================================

server = None

def start(app, host: str = API_HOST, port: int = API_PORT):
    """Démarre le serveur dans un thread séparé."""
    global server
    config = uvicorn.Config(app, host=host, port=port, loop=get_loop(), workers=4, use_colors=True)
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True)
    return th, server

def stop(th: threading.Thread, timeout: int = 5):
    """Arrête proprement le serveur."""
    print("Arrêt du serveur...")
    th.join(timeout)
    print("Serveur arrêté")


async def close_api_async(url: str):
    """Ferme l'API de manière asynchrone."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            print(f"Statut fermeture: {response.status}")


def close_api_atexit(url: str):
    """Enregistre la fermeture de l'API à la sortie."""
    def _close():
        try:
            from modules_utils.loop_utils import _run_async
            _run_async(close_api, url)
        except Exception:
            pass
    atexit.register(_close)