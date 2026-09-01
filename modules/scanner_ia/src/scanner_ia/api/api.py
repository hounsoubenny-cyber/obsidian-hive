#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API FastAPI — Scanner IA
Auteur: HOUNSOU Samuel
Version: 2.0.0
"""

import os
import json5
import shutil
import uvicorn
import aiohttp
import atexit
import threading
import asyncio
import traceback
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, HTTPException, status, WebSocketDisconnect
from fastapi import WebSocket, Body, APIRouter
from fastapi.responses import JSONResponse, FileResponse
from fastapi import Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from contextlib import asynccontextmanager
from typing import Optional
from datetime import datetime
from scanner_ia.scanner_utils.mock_logger import get_mock_logger
import scanner_ia.scanner_utils.logger as _ml
logger = _ml.get_logger()

from scanner_ia.scanner_utils.ids_utils import create_scan_id
from scanner_ia.scanner_utils.stdout_capture import WSTextIO
from scanner_ia.api.scanner_task_manager import ScannerTaskManager
from scanner_ia.api.ws_manager import WSManager
from scanner_ia.scanner_utils.cryto_utils import hashpw, checkpw
from scanner_ia.api.api_config import (
    LIMITE, ALLOWED_ORIGINS, DEFAULT_SCAN_PATH,
    DEFAULT_SCANNER_ARGS, WS_DISCONNECT_TIMEOUT,
    CONFIG_TEMP_DIR, MAX_CONFIG_SIZE, INDEX_FILE,
    STATICDIR, BUILD_DIR, REACT_EXISTS, API_HOST_PUBLIC,
    API_PORT
)
from scanner_ia.api.validate_config import validate_and_merge_config, ConfigError
from scanner_ia.main_scanner import Scanner, MODEL_DIR, REPORT_DIR
from scanner_ia.scanner_utils.helpers.resolve_helpers import HelperCall, resolve_helpers as __resolve_helpers
import scanner_ia.scanner_utils.helpers.helpers_registry as registry
import scanner_ia.main_scanner as _ms
from modules_utils.api_dependencies import get_loop
from modules_utils.limiter import limiter, get_remote_address

_ms.RICH_AVAILABLE = False
_ms.logger = get_mock_logger(logger)

# =============================================================================
# CRÉATION DE L'APP
# =============================================================================

def _initial_conf_api():
    import scanner_ia.main_scanner as _ms
    logger = _ml.get_logger()
    logger.remove(all_handlers=False)
    _ms.RICH_AVAILABLE = False
    _ms.logger = get_mock_logger(logger)
    
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("API Scanner IA démarrée !")
    if os.path.exists(CONFIG_TEMP_DIR):
        shutil.rmtree(CONFIG_TEMP_DIR, ignore_errors=True)
    os.makedirs(CONFIG_TEMP_DIR, exist_ok=True)
    get_shared_scanner_ia()
    _initial_conf_api()
    
    yield
    
    print("API Scanner IA fermée !")

app = FastAPI(
    title="Scanner IA",
    version="2.0.0",
    description="Scanner de vulnérabilités web augmenté par IA",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],
)
app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")
app.state.limiter = limiter

router = APIRouter()
ws_router = APIRouter()

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Trop rapide !",
            "message": f"{LIMITE} requêtes max par minute",
            "retry_after": 60
        }
    )


# =============================================================================
# MODÈLES PYDANTIC
# =============================================================================

class ScanInstanceArgs(BaseModel):
    """Paramètres de construction du Scanner — correspond à Scanner.__init__"""
    
    # Obligatoire
    config_path: str | None = DEFAULT_SCAN_PATH
    
    # Mode
    active_scan: bool = True
    use_cache: bool = True
    restore: bool = False
    debug: bool = False
    
    # Performances
    semaphore: int = Field(default=50, ge=1, le=200)
    limit_payloads: Optional[int] = Field(default=None, ge=1, le=10000)
    
    # Analyses
    use_semantic: bool = True
    headers_sev_map: Optional[dict] = None
    theme: Optional[str] = "multi"
    
    # Modèle ML
    model_dir: str | None = MODEL_DIR
    
    # Arjun et params query
    use_arjun: bool = False
    arjun_timeout: int = Field(default=30, ge=5, le=120)
    known_params_dir: Optional[str] = None
    
    # Config utilisateur (contenu JSON)
    conf_content: str = ""
    
    @model_validator(mode="after")
    def validate_model(self) -> "ScanInstanceArgs":
        self.config_path = self.config_path or DEFAULT_SCAN_PATH
        self.model_dir = self.model_dir or MODEL_DIR
        return self
        
# class HelperCall(BaseModel):
#     """
#     Représente un appel de helper sérialisable en JSON.
 
#     Exemples :
#         {"name": "dvwa_auth",       "kwargs": {"base_url": "http://localhost:8080"}}
#         {"name": "form_login",      "kwargs": {"login_url": "...", "username": "a", "password": "b"}}
#         {"name": "bearer_token",    "kwargs": {"token": "eyJ..."}}
#         {"name": "inject_cookies",  "kwargs": {"cookies": {"PHPSESSID": "abc"}}}
#         {"name": "noop"}   ← site sans auth
#     """
#     name: str = Field(..., description="Nom du helper (voir GET /api/helpers)")
#     args: list  = Field(default_factory=list,  description="Arguments positionnels (rare)")
#     kwargs: dict = Field(default_factory=dict, description="Arguments nommés JSON-sérialisables")


class ScanArgs(BaseModel):
    """Paramètres d'exécution — correspond à Scanner.scan()"""
    
    # Cible (obligatoire)
    url: str
    
    # Comportement général
    fetch: bool = True
    use_cache: bool = False
    put_result_in_cache: bool = True
    filename: Optional[str] = None
    
    # Fuzzer
    limit_vuln_for_fuzzer: int | list [str] | None = Field(default=None)
    time_between_for_fuzzer: float = Field(default=0.001, ge=0, le=1.0)
    dynamic_timeout_for_fuzzer: bool = True
    
    # Scope
    allowed_domains: Optional[list[str]] = Field(default=["http://127.0.0.1", "http://localhost"])
    
    max_test: Optional[int] = Field(default=None)
    
    # ML et helpers
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    helpers: list[HelperCall] = Field(
        default_factory=list,
        description=(
            "Liste de helpers d'authentification à exécuter avant le scan. "
            "Voir GET /api/helpers pour la liste complète. "
            "Laisser vide si le site ne requiert pas d'auth."
        )
    )
    raise_on_helper_error: bool = True
    is_spa: bool = False


class StartScanBody(BaseModel):
    """Body de la route /start_scan."""
    pass_phrase:   str
    instance_args: ScanInstanceArgs = Field(default_factory=ScanInstanceArgs)
    scan_args:     ScanArgs


class WSConnectBody(BaseModel):
    """Body envoyé au WS pour authentification."""
    pass_phrase: str


# =============================================================================
# VARIABLES GLOBALES & SINGLETONS
# =============================================================================

_shared_scanner_ia = None   # ScannerIA partagé (ML chargé une seule fois)
_ws_manager = None
_scan_task_manager = None
_lock = threading.Lock()
server = None

# { scan_id: hashed_pass_phrase }
PASS_PHRASE: dict[str, bytes] = {}


def get_shared_scanner_ia():
    """Charge le ScannerIA une seule fois au premier appel."""
    global _shared_scanner_ia
    with _lock:
        if _shared_scanner_ia is None:
            args_copy = DEFAULT_SCANNER_ARGS.copy()
            for key in ("config_path", "model_dir"):
                if key in args_copy:
                    args_copy.pop(key)
                
            _tmp = Scanner(
                **DEFAULT_SCANNER_ARGS, 
                config_path=DEFAULT_SCAN_PATH,
                model_dir=MODEL_DIR,
            )
            _tmp.scanner_ia.model_manager.verify_model()
            _shared_scanner_ia = _tmp.scanner_ia
        return _shared_scanner_ia

def get_ws_manager() -> WSManager:
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WSManager()
    return _ws_manager

def get_scan_task_manager() -> ScannerTaskManager:
    global _scan_task_manager
    if _scan_task_manager is None:
        _scan_task_manager = ScannerTaskManager()
    return _scan_task_manager

def __close_api():
    global server
    server.should_exit = True

def _resolve_helpers(helper_calls: list[HelperCall]) -> list:
    try:
        return __resolve_helpers(helper_calls=helper_calls)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=str(e))

# =============================================================================
# LOGIQUE DU SCAN
# =============================================================================

async def _run_scan(
    instance_args: ScanInstanceArgs,
    scan_args:     ScanArgs,
    scan_id:       str
):
    """
    Coroutine principale du scan.

    - Crée un Scanner dédié à ce scan
    - Injecte le ScannerIA partagé (ML chargé une seule fois)
    - Redirige stdout/stderr vers le WebSocket
    - Gère annulation et erreurs proprement
    """
    import sys
    ws_manager = get_ws_manager()
    scan_task_manager = get_scan_task_manager()
    loop = asyncio.get_running_loop()
    # Redirection stdout/stderr → WS 
    capture = WSTextIO(ws_manager, loop, scan_id)
    mock_logger = get_mock_logger(logger)
    mock_logger.register(scan_id, capture)
    new_instance = None

    try:
        #  Création du scanner 
        await ws_manager.send(scan_id, message="[{scan_id}]🔧 Initialisation du scanner...", type="scan_info")
        new_instance = Scanner(**instance_args.model_dump(exclude={"conf_content"}))
        new_instance.scanner_ia = get_shared_scanner_ia()
        await ws_manager.send(scan_id, message="✅ Scanner initialisé", type="scan_info")

        #  Résolution helpers 
        await ws_manager.send(scan_id, message=f"[{scan_id}]🔐 Résolution de {len(scan_args.helpers)} helper(s)...", type="scan_info")
        resolved_helpers = _resolve_helpers(scan_args.helpers)
        await ws_manager.send(scan_id, message="✅ Helpers résolus", type="scan_info")

        # Lancement du scan
        await ws_manager.send(scan_id, message=f"[{scan_id}]🚀 Scan démarré sur {scan_args.url}", type="scan_info")
        scan_kwargs = scan_args.model_dump(exclude={"helpers"})
        scan_kwargs["helpers"] = resolved_helpers  
        scan_kwargs["filename"] = f"{scan_id}_{scan_args.filename}" if scan_args.filename else scan_id
        result = await new_instance.scan(**scan_kwargs)
        report_paths = getattr(new_instance, "_last_report_paths", {})
        
        report_urls = {
             k: f"http://{API_HOST_PUBLIC}:{API_PORT}/reports/{os.path.relpath(path, REPORT_DIR).replace(os.sep, '/')}"
             for k, path in report_paths.items()
         }

        fuzzer_phases = result.phases_result.get("fuzzer") or result.phases_result.get("fuzzer (active)")
        fuzzer_stats  = getattr(fuzzer_phases, "stats", {}) or {}

        summary = {
            "scan_id":      scan_id,
            "url":          scan_args.url,
            "elapsed":      result.elapsed,
            "date":         result.date,
            "errors":       len(result.errors),
            "pages_crawled": len(
                getattr(
                    result.phases_result.get("analyzer_helper (crawl & parse)"),
                    "elements", {}
                )
            ),
            "total_vulns":  fuzzer_stats.get("total_vulns", 0),
            "vuln_count":   fuzzer_stats.get("vuln_count", {}),
            "report_paths": report_urls,
        }
        # Résultat 
        await ws_manager.send(scan_id, message="[{scan_id}] ✅ Scan terminé", type="scan_info")
        await ws_manager.send(
            scan_id, 
            message=summary,
            type="scan_result"
        )
        PASS_PHRASE.pop(scan_id, None)

    except asyncio.CancelledError:
        await ws_manager.send(scan_id, message="[{scan_id}] ⚠️ Scan annulé", type="scan_info")
        try:
            ws = ws_manager._scans.get(scan_id)
            if ws:
                await ws.close()
        except:
            pass
        
        PASS_PHRASE.pop(scan_id, None)

    except HTTPException:
        raise

    except Exception as e:
        tb = traceback.format_exc()
        await ws_manager.send(scan_id, message=f"[{scan_id}] ❌ {type(e).__name__}: {e}. \nTraceback: {tb}", type="scan_error")
        PASS_PHRASE.pop(scan_id, None)

    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        mock_logger.unregister(scan_id)
        if new_instance is not None:
            new_instance.scanner_ia = None
            del new_instance
        await scan_task_manager.suppress_scan_task(scan_id)
        if instance_args.config_path.startswith(CONFIG_TEMP_DIR):
            os.unlink(instance_args.config_path)
        
        ws_manager.disconnect(scan_id)


# =============================================================================
# ROUTES
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/start_scan")
async def start_scan(request: Request, body: StartScanBody):
    """
    Lance un nouveau scan.

    - Génère un scan_id unique
    - Hash la pass_phrase pour sécuriser l'accès au WS
    - Crée la task asyncio et la confie au ScannerTaskManager
    - Retourne le scan_id immédiatement (non-bloquant)
    """
    scan_id = create_scan_id()
    
    PASS_PHRASE[scan_id] = hashpw(body.pass_phrase)

    ws_manager = get_ws_manager()
    scan_task_manager = get_scan_task_manager()
    ws_manager.register(scan_id)
    
    # Validation config utilisateur
    if body.instance_args.conf_content:
        defalut_conf_path = DEFAULT_SCAN_PATH
        if body.instance_args.config_path != DEFAULT_SCAN_PATH and os.path.exists(body.instance_args.config_path):
            try:
                import json5
                json5.loads(open(body.instance_args.config_path).read())
                defalut_conf_path = body.instance_args.config_path
            except json5.JSON5DecodeError:
                pass
            
        try:
            config_path = validate_and_merge_config(
                max_size=MAX_CONFIG_SIZE,
                config_temp_dir=CONFIG_TEMP_DIR,
                default_config_path=defalut_conf_path,
                user_config_str=body.instance_args.conf_content,
                scan_id=scan_id,
            )
            body.instance_args.config_path = config_path
        except ConfigError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": "configuration_invalide", "message": str(e)}
            )
            
    # Validation précoce des helpers 
    # On valide AVANT de démarrer la task pour renvoyer une 400 claire au client
    _resolve_helpers(body.scan_args.helpers)
    coro = _run_scan(
        instance_args=body.instance_args,
        scan_args=body.scan_args,
        scan_id=scan_id
    )
    await scan_task_manager.add_task(coro, scan_id)

    return {
        "scan_id": scan_id,
        "status":  "started",
        "date":    datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        "message": "Connectez-vous au WebSocket /ws_scan_status avec votre scan_id et pass_phrase"
    }

@router.get("/reports/{scan_id}")
async def list_scan_reports(scan_id: str):
    """
    Liste les fichiers de rapport disponibles pour un scan.
    
    Retourne les URLs complètes accessibles via GET /reports/<path>.
    """
    results = {}
    for fmt, subdir in [("html", "HTML"), ("json", "JSON"), ("pdf", "PDF"), ("llm", "LLM_REPORT")]:
        folder = os.path.join(REPORT_DIR, subdir)
        if os.path.isdir(folder):
            files = [
                f for f in os.listdir(folder)
                if scan_id in f
            ]
            results[fmt] = [f"/reports/{subdir}/{f}" for f in files]
    return results
 
@router.get("/default_config")
@limiter.limit(f"{LIMITE}/minute")
async def get_default_config(request: Request):
    """Config par défaut du scanner (JSON) — pour l'éditeur frontend."""
    with open(DEFAULT_SCAN_PATH, "r", encoding="utf-8") as f:
        return json5.loads(f.read())

@router.get("/supported_vulns")
@limiter.limit(f"{LIMITE}/minute")
async def get_supported_vulns(request: Request):
    from scanner_ia.ml_model.config import VULNS
    return VULNS
    
@router.get("/validate_know_param_dir")
@limiter.limit(f"{LIMITE}/minute")
async def _validate_know_params_dir(request: Request, path: str):
    if not path or not os.path.exists(path):
        return {"can": False, "reason": "Chemin inexistant"}
    
    files_in = os.listdir(path)
    if "known_params.json" in files_in:
        try:
            with open(os.path.join(path, 'known_params.json')) as f:
                json5.load(f)
            return {'can': True, 'reason': None}
        except (ValueError, OSError) as e:
            return {'can': False, 'reason': f"Fichier invalide ({str(e)})"}
    
    return {'can': False, 'reason': "Dossier invalide, absence du fichier known_params.json"}

@router.get("/helpers")
async def get_helpers():
    """
    Liste tous les helpers d'authentification disponibles.
 
    Utile pour que le client sache quels noms passer dans scan_args.helpers.
    """
    return {
        "helpers": registry.list_helpers(),
        "total": len(registry.list_helpers()),
        "usage": (
            "Dans scan_args.helpers, passer une liste de "
            "{\"name\": \"<helper_name>\", \"kwargs\": {...}}. "
            "Laisser vide si le site ne requiert pas d'authentification."
        )
    }


@ws_router.websocket("/ws_scan_status")
async def ws_scan_status(
    websocket: WebSocket,
    scan_id: str,
    pass_phrase: str
):
    """
    WebSocket de suivi d'un scan en temps réel.

    - Vérifie que scan_id est enregistré
    - Vérifie la pass_phrase (bcrypt) pour éviter qu'un tiers suive le scan
    - Streame les logs/résultats jusqu'à la fin du scan
    - Si déconnexion : lance une task d'annulation après WS_DISCONNECT_TIMEOUT secondes
    """
    ws_manager = get_ws_manager()
    scan_task_manager = get_scan_task_manager()
    # Vérification scan_id
    if not ws_manager.is_register(scan_id):
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="scan_id invalide ou expiré"
        )
        return

    # Vérification pass_phrase 
    hashed = PASS_PHRASE.get(scan_id)
    if hashed is None or not checkpw(pass_phrase, hashed):
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Pass phrase incorrecte"
        )
        return

    # Connexion acceptée
    await ws_manager.connect(scan_id, websocket)

    # Annuler la task d'annulation si reconnexion après disconnect
    await scan_task_manager.cancel_cancelling_task(scan_id)

    try:
        # Garder la connexion ouverte
        # Le client peut envoyer "ping" pour maintenir la connexion
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                # Timeout lecture, on vérifie si le scan est encore actif
                task = scan_task_manager.get_scan_task(scan_id)
                if task is None:
                    print("Scan rask", task)
                    break  # scan terminé, on ferme 

    except WebSocketDisconnect:
        # Disconnect, task d'annulation avec timeout 
        await scan_task_manager.add_cancel_task(scan_id, timeout=WS_DISCONNECT_TIMEOUT)

    except Exception:
        await scan_task_manager.add_cancel_task(scan_id, timeout=WS_DISCONNECT_TIMEOUT)

    finally:
        try:
            await websocket.close()
        except:
            pass
        ws_manager.disconnect(scan_id)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/cancel_scan")
async def cancel_scan(request: Request, scan_id: str = Body(...), pass_phrase: str = Body(...)):
    """
    Annule un scan en cours.

    Vérifie la pass_phrase avant d'annuler.
    """
    hashed = PASS_PHRASE.get(scan_id)
    if hashed is None:
        raise HTTPException(status_code=404, detail="scan_id introuvable")

    if not checkpw(pass_phrase, hashed):
        raise HTTPException(status_code=403, detail="Pass phrase incorrecte")

    scan_task_manager = get_scan_task_manager()
    await scan_task_manager.cancel_task(scan_id)
    get_ws_manager().disconnect(scan_id)
    return {
        "scan_id": scan_id,
        "status":  "cancelled",
        "date":    datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
    }

@router.get("/status")
async def api_status(request: Request):
    """Statut de l'API — nombre de scans actifs."""
    scan_task_manager = get_scan_task_manager()
    return {
        "status":       "running",
        "active_scans": len(scan_task_manager.SCANS_TASK),
        "date":         datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
    }

# =============================================================================
# INCLUSION DU ROUTER
# =============================================================================

app.include_router(router, prefix="/api")
app.include_router(ws_router, prefix="/api")

# =============================================================================
# Routes principales
# =============================================================================

@app.get('/api/close')
def _close_api():
    global server
    if server is None:
        print('Serveur non lancé !', server)
        return {
            "message ": "Serveur non lancé !"
            }
    else:
        __close_api()
        print('Serveur fermé.')
        return {
            "message ": 'Serveur fermé.'
            }

@app.get("/api/rate-limit-status")
@limiter.limit(f"{LIMITE}/minute")
async def rate_limit_status(request: Request):
    return {
        "ip": get_remote_address(request),
        "limit": f"{LIMITE}/minute"
    }

@app.get("/")
async def serve_react_app():
    """Sert l'application React - point d'entrée"""
    if REACT_EXISTS:
        return FileResponse(INDEX_FILE)
    else:
        return {
        }
    
    
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    """Capture toutes les routes pour React Router"""
    excluded_prefixes = ["api/", "docs", "redoc", "openapi.json"]
    print(full_path)
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
# DÉMARRAGE
# =============================================================================

def start(app, host: str = "0.0.0.0", port: int = 8000):
    """Démarre le serveur dans un thread séparé."""
    global server
    config = uvicorn.Config(app, host=host, port=port, loop=get_loop(), use_colors=True, workers=10)
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True)
    return th, server


def stop(th: threading.Thread, timeout: int = 5):
    """Arrête proprement le thread serveur."""
    print("Arrêt du serveur...")
    th.join(timeout)
    print("Serveur arrêté.")

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