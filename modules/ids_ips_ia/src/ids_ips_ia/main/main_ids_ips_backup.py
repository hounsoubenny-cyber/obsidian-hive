#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Oct 25 20:38:59 2025

@author: hounsousamuel
"""

import os
import sys
import threading
import time
import dill
import json
import json5
import queue
import asyncio
import aiohttp
import atexit
import nest_asyncio
import traceback
import multiprocessing as mp
from jose import jwt, JWTError
from jose.jwt import ExpiredSignatureError
from datetime import datetime, timedelta
from uuid import uuid4
from fastapi import FastAPI, Request, HTTPException, Depends, status, APIRouter
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi.errors import RateLimitExceeded
import uvicorn
import warnings
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ids_ips_ia.core.capture import collect_and_process, detect_all_ifaces
from ids_ips_ia.models.models import Models
from ids_ips_ia.models.config import MODEL_DIR
from ids_ips_ia.core.capture import Capture
from ids_ips_ia.detection.detection_module import AnomalyDetector, CONFIG as CONFIG_DET
from ids_ips_ia.detection.mocks import _get_list_blocked_ip_mocked
from ids_ips_ia.ids_ips_utils.real_time_plot import RealTimePLot
from ids_ips_ia.ids_ips_utils.suricata_integration import Utils, state
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.ids_ips_utils.model_file_validation import validate_model_file
from ids_ips_ia.refit_system.refit_system import ModelRefitMonitor
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.warnings_manager import suppres_warnings
from ids_ips_ia.reaction.reaction_module import GeoLocator
from ids_ips_ia.refit_system.refit_queue import RefitQueue
# from ids_ips_ia.memory_managers.shared_memory_packet_manager import MemoryManager
from ids_ips_ia.ids_ips_utils.loader import save
from ids_ips_ia.config.config_ids import (
    GLOBAL_CONFIG as CONFIG, GRAPH, REQUEST_LIMIT as REQUEST,
    API_CONFIG,
    ALLOWED_ORIGINS,
    JWT_EXPIRE_MINUTES, 
    ADMIN_DATA, NOT_BEFORE,
    CAPTURE_FILENAME,
    ADD_DATA_TO_CAPTURE_PATH,
    FILTER, Config, _config_path as DEFAULT_IDS_CONFIG_PATH
)
from ids_ips_ia.config.frontend_config import (
    STATICDIR, BUILD_DIR, INDEX_FILE, REACT_EXISTS,
    BUILD_URL, STATIC_URL
)
from ids_ips_ia.ids_ips_utils.utils import _get_ip_type
from ids_ips_ia.auth.auth import verify_password
from modules_utils.api_dependencies import get_loop
from modules_utils.limiter import limiter, get_remote_address

try:
    mp.set_start_method('spawn')
except RuntimeError:
    pass
    
host = API_CONFIG.get('host', '0.0.0.0')
port =  API_CONFIG.get('port', 8080)
URL = f'http://{host}:{port}/api'
warnings.filterwarnings("ignore")
nest_asyncio.apply()

SEQ_LENGTH = 60
DEFAULT_DURATION = 3600 * 7 * 24
DEFAULT_SAVE_INTERVAL = 36000
DEFAULT_ANOMALY_DIR = "anomalies"
dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(dir_, exist_ok=True)

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

server = None
ALREADY_UNLOCK = set()
TOKEN = ""
_lock = threading.Lock()
_api_lock = asyncio.Lock()
_dir_ = os.path.dirname(os.path.abspath(__file__))

barer = HTTPBearer(
    scheme_name="JWT",
    auto_error=True,
    description="JWT vérifcation!"
    )

logger = get_logger()
suppres_warnings()
_default_locator = GeoLocator()
# =============================================================================
# CLASSE DES DONNÉES
# =============================================================================
class Data(BaseModel):
    username: str 
    password:str 

class Conf(BaseModel):
    key:str
    data:dict
    username: str 
    password:str 
    token:str 
    
class UnlockData(BaseModel):
    input:bool
    rule:str
    whitelist:str = 'false'
    ip:str = ""
    username: str 
    password: str 
    token: str

class WhitelistData(BaseModel):
    add:bool = True
    ip:str = ""
    token:str 
    username:str
    password:str 
        
class BasicData(BaseModel):
    username:str
    token:str 

class ChangeModeData(BaseModel):
    username:str
    password:str
    token:str 
    mode:str

class BlockIPData(BaseModel):
    username:str
    password:str
    token:str 
    input:bool
    rule:str
    ip:str = ""
    

class IgnoreIPData(BaseModel):
    ip: str
    direction: str          # "src" ou "dst"
    add: bool = True        # True = ajouter, False = retirer
    username: str
    password: str
    token: str
    
# =============================================================================
# FONCTIONS UTILITAIRES    
# =============================================================================
def validate_admin_data():
    return all(v for v in ADMIN_DATA.values())

def create_acces_token(data: dict):
    global TOKEN
    if not isinstance(data, dict):
        raise ValueError('data doit être dict !')
    copy = {k:v for k,v in data.items()}
    expiry_date = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    copy['sub'] = data.get('username', '')
    copy['exp'] = expiry_date
    copy['nbf'] =  datetime.utcnow() + timedelta(seconds=NOT_BEFORE)
    copy["iat"] = datetime.utcnow()
    copy['type'] = "access"
    token = jwt.encode(copy, ADMIN_DATA.get('secret_key', ""), algorithm="HS256")
    TOKEN = token
    return token

def verify_token(token, expire:bool = True):
    try:
       initial_data = jwt.decode(
           token, 
           ADMIN_DATA.get('secret_key', ""), 
           algorithms=['HS256'],
           options={
               "verify_exp" : expire,
               "verify_nbf" : True
               }
       )
       user = initial_data.get('sub', "")
       if not user:
           raise HTTPException(
               status_code=status.HTTP_401_UNAUTHORIZED, 
               detail="Token invalide", 
               headers={"WWW-Authenticate": "Bearer"}
           )
       return user
   
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="TOKEN_EXPIRED",  # Code identifiable côté client
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTError:
       raise HTTPException(
           status_code=status.HTTP_401_UNAUTHORIZED, 
           detail="Token invalide", 
           headers={"WWW-Authenticate": "Bearer"}
       )
           
def verify_admin(username:str, password:str):
    if validate_admin_data():
        if username != ADMIN_DATA.get('username', '') :
            raise HTTPException(status_code=401, detail="Authentification échoué (Nom user ne correspond pas)")
        
        if not verify_password(password, ADMIN_DATA.get('hash_password', "")):
            raise HTTPException(status_code=401, detail="Authentification échoué (Mot de passe user ne correspond pas)")
            
    else:
        raise HTTPException(status_code=401, detail="Veuillez d'abord configurer les infos admin.")

def validate_username(token, username, expire:bool = True):
    user = verify_token(token, expire)
    if not(user == ADMIN_DATA.get("username", "") == username):
        raise HTTPException(
            detail="Username invalide ou token bizarre",
            status_code=401
            )
    return True

# =============================================================================
# APP
# =============================================================================

from contextlib import asynccontextmanager

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
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],  
)

router = APIRouter()
router_no_auth = APIRouter()

if REACT_EXISTS:
    app.mount(BUILD_URL, StaticFiles(directory=BUILD_DIR), name="build")
    app.mount(STATIC_URL, StaticFiles(directory=STATICDIR), name="static")
    
app.state.limiter = limiter

# =============================================================================
# FONCTIONS DE DÉMARRAGE ET D'ARRÈT
# =============================================================================
def start(app,host,port):
    global server
    config = uvicorn.Config(app,host=host, port=port, loop=get_loop(), workers=10, use_colors=True)
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True, name="API Thread")
    return th, server

def stop(th,timeout=5):
    logger.print('Arrêt des threads...')
    th.join(timeout)
    logger.print('Threads arrêtés')
    
# =============================================================================
# DÉPENDANCE POUR RÉCUPÉRER IDS_IPS
# =============================================================================
def get_ids_ips(request: Request) -> Optional["IDS_IPS"]:
    """Dépendance FastAPI pour récupérer l'instance IDS_IPS depuis l'état de l'application."""
    return getattr(request.app.state, "_ids_ips", None)

# =============================================================================
# LOGIQUE MÉTIER
# =============================================================================
async def _do_login(username: str, password: str):
    verify_admin(username, password)
    return {
        "access_token": create_acces_token({"username": username}),
        "token_type": "bearer",
        "expires_in": JWT_EXPIRE_MINUTES * 60,
        "success": True,
        "username": username,
    }

async def _do_start_logic(app_state):
    if getattr(app_state, "_ids_is_started", False):
        return {"started": True, "detail": "Déjà en cours"}
    
    ids_ips = IDS_IPS()
    thread = threading.Thread(
        target=ids_ips.main,
        args=(True,),
        daemon=True,
        name="IDS_IPS_Main"
    )
    thread.start()
    ids_ips._setup_signal_handlers()
    
    app_state._ids_ips = ids_ips
    app_state._ids_thread = thread
    app_state._ids_is_started = True
    
    return {"started": True, "detail": "IDS/IPS démarré"}

async def _do_start(request: Request):
    return await _do_start(request.app.state)
    
async def _do_get_alerts(ids_ips: Optional["IDS_IPS"], n: int):
    if ids_ips is None or ids_ips.detector is None:
        return {"alerts": [], "detail": "IDS non démarré"}
    alerts = ids_ips.detector._get_last_alerts(n)
    return {
        "alerts": alerts,
        "total": len(alerts),
        "ids_running": True
    }

async def _do_stop_logic(app_state):
    ids_ips: "IDS_IPS" | None  = getattr(app_state, "_ids_ips", None)
    if ids_ips is None:
        return {"stopped": False, "detail": "IDS non démarré"}
    
    ids_ips.stop()
    threading.Thread(
        target=ids_ips._cleanup,
        args=(ids_ips.process, ids_ips.threads),
        daemon=True
    ).start()
    thread = getattr(app_state, "_ids_thread", None)
    if thread and thread.is_alive():
        await asyncio.to_thread(thread.join, timeout=10)
    
    app_state._ids_is_started = False
    app_state._ids_ips = None
    app_state._ids_thread = None
    threading.Thread(target=lambda: (
        logger.print("[WATCHDOG] ⚠️ Arrêt forcé après 8s"),
        time.sleep(8),
        os._exit(0)
    )).start()
    
    return {"stopped": True, "detail": "IDS/IPS arrêté"}

async def _do_stop(request: Request):
    return await _do_stop_logic(request.app.state)
    

async def _do_help():
    """Documentation complète de l'API IDS/IPS."""
    return {
        "message": "API IDS/IPS SHIELD IA - Documentation",
        "version": "2.0.0",
        "authentification": {
            "description": "Toutes les routes critiques nécessitent un token JWT et les identifiants admin",
            "login": "POST /api/login - {username, password} → retourne access_token",
            "refresh": "POST /api/refresh_token - {username, token} → retourne nouveau access_token",
            "token_expiry": f"{JWT_EXPIRE_MINUTES} minutes",
            "note": "Le refresh token accepte les tokens expirés pour renouvellement"
        },
        "endpoints": {
            # ============================================================
            # ROUTES PUBLIQUES (sans auth)
            # ============================================================
            "public": [
                {
                    "method": "GET",
                    "path": "/api/help",
                    "description": "Cette documentation"
                },
                {
                    "method": "GET",
                    "path": "/api/health",
                    "description": "État du système (detector ready, graph port)"
                },
                {
                    "method": "GET",
                    "path": "/api/geo_location",
                    "params": {"ip": "Adresse IP"},
                    "description": "Géolocalisation d'une IP (code pays)"
                },
                {
                    "method": "GET",
                    "path": "/api/rate-limit-status",
                    "description": "Statut du rate limiting"
                },
                {
                    "method": "GET",
                    "path": "/api/docs",
                    "description": "Documentation Swagger UI"
                },
                {
                    "method": "GET",
                    "path": "/api/redoc",
                    "description": "Documentation ReDoc"
                }
            ],
            # ============================================================
            # ROUTES AUTHENTIFIÉES (token requis)
            # ============================================================
            "authenticated": [
                {
                    "method": "POST",
                    "path": "/api/login",
                    "body": {"username": "admin", "password": "xxx"},
                    "response": {"access_token": "string", "expires_in": "int", "success": "bool"}
                },
                {
                    "method": "POST",
                    "path": "/api/refresh_token",
                    "body": {"username": "admin", "token": "refresh_token"},
                    "response": {"access_token": "string"}
                }
            ],
            # ============================================================
            # ROUTES CRITIQUES (token + username + password)
            # ============================================================
            "critical": [
                {
                    "method": "POST",
                    "path": "/api/blocked",
                    "body": {"username": "admin", "token": "access_token"},
                    "description": "Liste toutes les IPs bloquées avec leurs données",
                    "response": {"blocked": "object", "message": "SUCCESS"}
                },
                {
                    "method": "POST",
                    "path": "/api/unlock",
                    "body": {
                        "ip": "192.168.1.1",
                        "input": "True",
                        "rule": "drop",
                        "whitelist": "false",
                        "username": "admin",
                        "password": "xxx",
                        "token": "access_token"
                    },
                    "description": "Débloque une IP et optionnellement l'ajoute à la whitelist"
                },
                {
                    "method": "POST",
                    "path": "/api/manage_whitelist",
                    "body": {
                        "ip": "192.168.1.1",
                        "add": "True",
                        "username": "admin",
                        "password": "xxx",
                        "token": "access_token"
                    },
                    "description": "Ajoute (add=true) ou retire (add=false) une IP de la whitelist"
                },
                {
                    "method": "POST",
                    "path": "/api/config",
                    "body": {"username": "admin", "token": "access_token"},
                    "description": "Récupère la configuration complète"
                },
                {
                    "method": "POST",
                    "path": "/api/update_config",
                    "body": {
                        "key": "SEUIL",
                        "data": {"decision": -0.5},
                        "username": "admin",
                        "password": "xxx",
                        "token": "access_token"
                    },
                    "description": "Met à jour une partie de la configuration"
                },
                {
                    "method": "POST",
                    "path": "/api/change_mode",
                    "description": "Change le mode de fonctionnement à chaud"
                },
                {
                    "method": "GET",
                    "path": "/api/close",
                    "params": {"token": "access_token"},
                    "description": "Arrête le serveur API"
                }
            ]
        },
        "exemples_curl": {
            "login": 'curl -X POST "http://localhost:8080/api/login" -H "Content-Type: application/json" -d \'{"username":"admin","password":"admin"}\'',
            "blocked": 'curl -X POST "http://localhost:8080/api/blocked" -H "Content-Type: application/json" -d \'{"username":"admin","token":"eyJ..."}\'',
            "unlock": 'curl -X POST "http://localhost:8080/api/unlock" -H "Content-Type: application/json" -d \'{"ip":"192.168.1.1","input":true,"rule":"drop","whitelist":"false","username":"admin","password":"admin","token":"eyJ..."}\''
        },
        "niveaux_decision": {
            "log_only": {"score_range": "0-75", "action": "Surveillance uniquement"},
            "rate_limit_data": {"score_range": "75-125", "action": "Limite volume données (2h)"},
            "rate_limit": {"score_range": "125-180", "action": "Limite connexions (4h)"},
            "block_temp": {"score_range": "180-230", "action": "Blocage temporaire (24h)"},
            "block_perm": {"score_range": "230-300", "action": "Blocage permanent"}
        },
        "rate_limit": f"{REQUEST} requêtes par minute",
        "contact": "Admin IDS/IPS"
    }

async def _do_get_blocked(ids_ips: Optional["IDS_IPS"], data: BasicData, verify_auth: bool = True):
    # return {"blocked": _get_list_blocked_ip_mocked(), "message": "SUCCESS"}
    if ids_ips is None or ids_ips.detector is None: 
        return {
            'message': "ERREUR",
            "detail": "Detector non initialisé, réessayez plus tard",
            }
    
    if verify_auth:
        validate_username(data.token, data.username)
    async with _api_lock:
        return {"blocked": ids_ips.detector.AnomalyScorer.get_list_blocked_ip(), "message": "SUCCESS"}

async def _do_get_config(data: BasicData, verify_auth: bool = True):
    if verify_auth:
        validate_username(data.token, data.username)
    return {
            'ids/ips_config': CONFIG,
            "api_config": API_CONFIG,
            "host": API_CONFIG.get('host', ""),
            "port": API_CONFIG.get('port', ""),
        }

async def _do_refresh_token(data: BasicData, verify_auth: bool = True):
    username = data.username
    token = data.token
    if verify_auth:
        validate_username(token, username, expire=False)
    return {
        "access_token": create_acces_token({"username": username})
        }

async def _do_unlock(ids_ips: Optional["IDS_IPS"], data: UnlockData, verify_auth: bool = True):
    if ids_ips is None or ids_ips.detector is None:
        return {
            "success": False,
            "message": "Detector non initialisé, réessayez plus tard",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }
    
    detector_instance = ids_ips.detector
    if verify_auth:
        username = data.username
        password = data.password
        validate_username(data.token, username)
        verify_admin(username, password)
    ip = data.ip
    input = data.input
    rule = data.rule
    whitelist = data.whitelist
    unlock = False
    async with _api_lock:
        success = detector_instance.React.unlock(
            ip=ip,
            input=input,
            rule=rule,
        )
        already_unlocked = not success and ip not in detector_instance.React.blocked

        if success or already_unlocked:
            unlock = True
            if ip in detector_instance.AnomalyScorer.ip_data:
                detector_instance.AnomalyScorer.ip_data.pop(ip)
                 # detector_instance.AnomalyScorer.ip_data[ip]['score'] = 0
                 # detector_instance.AnomalyScorer.ip_data[ip]['blocked_count'] = 0
                 # detector_instance.AnomalyScorer.ip_data[ip]['anomaly_count'] = 0
                 # detector_instance.AnomalyScorer.ip_data[ip]['last_update'] = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
                 # detector_instance.AnomalyScorer.ip_data[ip]['last_update_timestamp'] = time.time()
                 # detector_instance.AnomalyScorer.ip_data[ip]['decision']['action'] = ""
                 # detector_instance.AnomalyScorer.save(detector_instance.AnomalyScorer.ip_score_dir, detector_instance.AnomalyScorer.ip_data)
                 
        if whitelist.strip().lower() in ['true', 'yes', '1']:
           detector_instance.React.add_to_whitelist(ip)
           logger.print(f'{ip} ajouté à la whitelist !')

        # Utiliser la vraie liste des IP bloquées
        LIST = list(detector_instance.AnomalyScorer.get_list_blocked_ip().keys())
        
    return  {
        "success" : ip not in LIST,
        'message': f"{'OK' if (unlock) else 'FAIL'} ({ip})",
        "code": status.HTTP_200_OK
    }

async def _do_manage_ignore_ip(ids_ips: Optional["IDS_IPS"], data: IgnoreIPData, verify_auth: bool = True):
    if ids_ips is None or ids_ips.Capture is None:
        return {
            "success": False,
            "message": "Capture non initialisée, réessayez plus tard",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }

    if verify_auth:
        username = data.username
        password = data.password
        validate_username(data.token, username)
        verify_admin(username, password)
    
    if data.direction not in ("src", "dst"):
        return {
            "success": False,
            "message": "Direction invalide !",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }
    
    if _get_ip_type(data.ip) == "error":
        return {
            "success": False,
            "message": "IP invalide",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }
    async with _api_lock:
        if data.add:
            success = ids_ips.add_ignored_ip(data.ip, direction=data.direction)
        else:
            success = ids_ips.remove_ignored_ip(data.ip, direction=data.direction)

    return {
        'success': success,
        'message': f"{'OK' if success else 'FAIL'} ({data.ip}, {data.direction})",
        "code": status.HTTP_200_OK
    }

async def _do_manage_whitelist(ids_ips: Optional["IDS_IPS"], data: WhitelistData, verify_auth: bool = True):
    if ids_ips is None or ids_ips.detector is None:
        return {
            "success": False,
            "message": "Detector non initialisé, réessayez plus tard",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }

    detector_instance = ids_ips.detector
    ip = data.ip
    add = data.add

    if verify_auth:
        username = data.username
        password = data.password
        validate_username(data.token, username)
        verify_admin(username, password)
    async with _api_lock:
        if add:
            detector_instance.React.add_to_whitelist(ip)
        else:
            detector_instance.React.remove_from_whitelist(ip)
        
        success = ip in detector_instance.React.whitelist if add else ip not in detector_instance.React.whitelist
    return  {
        'success' : success,
        'message': f"{'OK' if (success) else 'FAIL'} ({ip})",
        "code": status.HTTP_200_OK
    }

async def _do_block_ip(ids_ips: Optional["IDS_IPS"], data: BlockIPData, verify_auth: bool = True):
    if ids_ips is None or ids_ips.detector is None:
        return {
            "success": False,
            "message": "Detector non initialisé, réessayez plus tard",
            "code": status.HTTP_406_NOT_ACCEPTABLE
        }

    detector_instance = ids_ips.detector
    ip = data.ip
    if verify_auth:
        username = data.username
        password = data.password
        validate_username(data.token, username)
        verify_admin(username, password)
    async with _api_lock:
        if detector_instance.React.get_ip_type(ip) == "error":
            return {
                "success": False,
                "message": "IP invalide !",
                "code": 406,
            }
        success = detector_instance.React.block(
            ip=ip,
            rule=data.rule,
            input=data.input,
            timeout=data.timeout
        )
    return  {
        'success' : success,
        'message': f"{'OK' if (success) else 'FAIL'} ({ip})",
        "code": status.HTTP_200_OK
    }

async def _do_update(data: Conf, verify_auth: bool = True):
    key = data.key
    value = data.data
    if verify_auth:
        username = data.username
        password = data.password
        validate_username(data.token, username)
        verify_admin(username, password)
    response = CONFIG_DET.update(key, value)
    response["code"] = status.HTTP_200_OK if response.get("success", False) else status.HTTP_400_BAD_REQUEST
    # logger.print(response)
    return response

async def _do_geo_location(ids_ips: Optional["IDS_IPS"], ip: str):
    """Endpoint pour localisation IP (sans auth)."""
    if ids_ips is not None and ids_ips.detector is not None:
        loc = ids_ips.detector.AnomalyScorer.GeoLocator.locate(ip)
    else:
        loc = _default_locator.locate(ip)
    return {"location": loc}

async def _do_change_mode(ids_ips: Optional["IDS_IPS"], data: ChangeModeData, verify_auth: bool = True):
    if verify_auth:
        validate_username(data.token, data.username)
        verify_admin(data.username, data.password)
    return {"success": IDS_IPS.change_mode(data.mode, detector=ids_ips.detector if ids_ips else None)}

async def _do_get_mode(ids_ips: Optional["IDS_IPS"]):
    if ids_ips is not None and ids_ips.detector is not None:
        return {"mode": ids_ips.detector.mode}
    return {"mode": CONFIG.get("ids_mode", "ids")}

async def _do_get_port():
    return {"port": graph.port if graph else None}

async def _do_health_check(ids_ips: Optional["IDS_IPS"]):
    """Endpoint pour monitoring (sans auth)."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "detector_ready": (ids_ips is not None and ids_ips.detector is not None),
        "graph_port": graph.port if graph else None
    }

async def _do_close_api(token: str):
    global server
    validate_username(token, username=ADMIN_DATA.get("username"))
    if server is None:
        logger.print('Serveur non lancé !')
        return {
            "message ": "Serveur non lancé !"
            }
    else:
        server.should_exit = True
        logger.print('Serveur fermé.')
        return {
            "message ": 'Serveur fermé.'
            }



# =============================================================================
# ROUTES FASTAPI
# =============================================================================
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
# ROUTER AVEC AUTH (standalone)
# =============================================================================

@router.post(path="/login")
@limiter.limit(f"{REQUEST}/minute")
async def _login(request: Request, data: Data):
    return await _do_login(data.username, data.password)

@router.get(path="/start")
@limiter.limit(f"{REQUEST}/minute")
async def _start(request: Request):
    try:
        return await _do_start(request)
    except Exception as e:
        return {"started": False, "detail": f"Erreur: {str(e)}"}

@router.get("/alerts")
async def get_alerts(
    n: int = 10,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_alerts(ids_ips, n)

@router.get("/stop")
async def _stop(request: Request):
    return await _do_stop(request)

@router.get(path="/help")
@limiter.limit(f"{REQUEST}/minute")
async def _help(request: Request):
    """Documentation complète de l'API IDS/IPS."""
    return await _do_help()

@router.post("/blocked")
async def get_blocked(
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_blocked(ids_ips, data, verify_auth=True)

@router.post("/config")
@limiter.limit(f"{REQUEST}/minute")
async def get_config(
    request: Request,
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)  # Pas utilisé mais conservé pour cohérence
):
    return await _do_get_config(data, verify_auth=True)

@router.post("/refresh_token")
@limiter.limit(f"{REQUEST}/minute")
async def _refresh_token(
    request: Request,
    data: BasicData
):
    return await _do_refresh_token(data, verify_auth=True)

@router.post(path="/unlock")
@limiter.limit(f"{REQUEST}/minute")
async def _unlock(
    request: Request,
    data: UnlockData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_unlock(ids_ips, data, verify_auth=True)

@router.post(path="/manage_whitelist")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_whitelist(
    request: Request,
    data: WhitelistData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_manage_whitelist(ids_ips, data, verify_auth=True)

@router.post(path="/block_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _block_ip(
    request: Request,
    data: BlockIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_block_ip(ids_ips, data, verify_auth=True)

@router.post(path="/manage_ignored_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_ignored_ip(
    request: Request,
    data: IgnoreIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_manage_ignore_ip(ids_ips, data, verify_auth=True)


@router.post("/update_config")
@limiter.limit(f"{REQUEST}/minute")
async def _update(
    request: Request,
    data: Conf
):
    return await _do_update(data, verify_auth=True)

@router.get("/geo_location")
async def _geo_location(
    ip: str,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour localisation IP (sans auth)."""
    return await _do_geo_location(ids_ips, ip)

@router.post("/change_mode")
@limiter.limit(f"{REQUEST}/minute")
async def _change_mode(
    request: Request,
    data: ChangeModeData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_change_mode(ids_ips, data, verify_auth=True)

@router.get("/get_mode")
async def _get_mode(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_mode(ids_ips)

@router.get("/get_port")
async def _get_port():
    return await _do_get_port()

@router.get("/default_config")
async def get_default_config_ids():
    """Config par défaut IDS/IPS (JSON) — pour l'éditeur frontend."""
    conf = Config(DEFAULT_IDS_CONFIG_PATH)
    return conf.CONFIG

@router.get("/health")
async def _health_check(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour monitoring (sans auth)."""
    return await _do_health_check(ids_ips)

@router.get('/close')
async def _close_api(token: str):
    return await _do_close_api(token)

@app.get(path="/api/openapi")
async def _open_api():
    return app.openapi()

# =============================================================================
# ROUTER SANS AUTH (pour gateway)
# =============================================================================

# @router_no_auth.post("/login")
# @limiter.limit(f"{REQUEST}/minute")
# async def _login_no_auth(request: Request, data: Data):
#     return await _do_login(data.username, data.password)

@router_no_auth.get("/start")
@limiter.limit(f"{REQUEST}/minute")
async def _start_no_auth(request: Request):
    try:
        return await _do_start(request)
    except Exception as e:
        return {"started": False, "detail": f"Erreur: {str(e)}"}

@router_no_auth.get("/alerts")
async def get_alerts_no_auth(
    n: int = 10,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_alerts(ids_ips, n)

@router_no_auth.get("/stop")
async def _stop_no_auth(request: Request):
    return await _do_stop(request)

@router_no_auth.get("/help")
@limiter.limit(f"{REQUEST}/minute")
async def _help_no_auth(request: Request):
    """Documentation complète de l'API IDS/IPS."""
    return await _do_help()

@router_no_auth.post("/blocked")
async def get_blocked_no_auth(
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_blocked(ids_ips, data, verify_auth=False)

@router_no_auth.post("/config")
@limiter.limit(f"{REQUEST}/minute")
async def get_config_no_auth(
    request: Request,
    data: BasicData
):
    return await _do_get_config(data, verify_auth=False)

# @router_no_auth.post("/refresh_token")
# @limiter.limit(f"{REQUEST}/minute")
# async def _refresh_token_no_auth(request: Request, data: BasicData):
#     return await _do_refresh_token(data)

@router_no_auth.post("/unlock")
@limiter.limit(f"{REQUEST}/minute")
async def _unlock_no_auth(
    request: Request,
    data: UnlockData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_unlock(ids_ips, data, verify_auth=False)

@router_no_auth.post("/manage_whitelist")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_whitelist_no_auth(
    request: Request,
    data: WhitelistData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_manage_whitelist(ids_ips, data, verify_auth=False)

@router_no_auth.post("/block_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _block_ip_no_auth(
    request: Request,
    data: BlockIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_block_ip(ids_ips, data, verify_auth=False)

@router_no_auth.post("/update_config")
@limiter.limit(f"{REQUEST}/minute")
async def _update_no_auth(
    request: Request,
    data: Conf
):
    return await _do_update(data, verify_auth=False)

@router_no_auth.get("/geo_location")
async def _geo_location_no_auth(
    ip: str,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour localisation IP (sans auth)."""
    return await _do_geo_location(ids_ips, ip)

@router_no_auth.post("/change_mode")
@limiter.limit(f"{REQUEST}/minute")
async def _change_mode_no_auth(
    request: Request,
    data: ChangeModeData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_change_mode(ids_ips, data, verify_auth=False)

@router_no_auth.get("/get_mode")
async def _get_mode_no_auth(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_get_mode(ids_ips)

@router_no_auth.get("/get_port")
async def _get_port_no_auth():
    return await _do_get_port()

@router_no_auth.get("/default_config")
async def _get_default_config_ids_no_auth():
    """Config par défaut IDS/IPS (JSON) — pour l'éditeur frontend."""
    conf = Config(DEFAULT_IDS_CONFIG_PATH)
    return conf.CONFIG

@router_no_auth.post(path="/manage_ignored_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_ignored_ip_no_auth(
    request: Request,
    data: IgnoreIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await _do_manage_ignore_ip(ids_ips, data, verify_auth=False)

@router_no_auth.get("/health")
async def _health_check_no_auth(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour monitoring (sans auth)."""
    return await _do_health_check(ids_ips)

@router_no_auth.get('/close')
async def _close_api_no_auth(token: str):
    return await _do_close_api(token)

# =============================================================================
# INTÉGRATION DES ROUTEURS
# =============================================================================

app.include_router(router, prefix="/api")

@app.get("/api/rate-limit-status")
@limiter.limit(f"{REQUEST}/minute")
async def rate_limit_status(request: Request):
    return {
        "ip": get_remote_address(request),
        "limit": f"{REQUEST}/minute"
    }

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
            "endpoints" : {
                "GET /api/action" : "Éffectué une action",
                "GET /api/help" : "Obtenir de l'aide et des rensignement",
                "GET /api/rate-limit-status": "Obtenir la limitation de requête par minute",
                "GET /api/docs": "Documentation FastAPI",
                "GET /api/redoc": "Documentation FastAPI",
                "GET /api/openapi.json": "Info sur l'api actuellement",
                },
            "rate_limit": f"{REQUEST} requêtes/minute"
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
# DRENIÈRES CLASSES ET FONCTIONS
# =============================================================================
async def close_api(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params={"token": TOKEN}) as response:
            logger.print('Statut : ', response.status)

def close_api_atexit(url):
    def _close():
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(close_api(url))
            loop.close()
        except Exception:
            pass
    atexit.register(_close)
    


if GRAPH:
    graph = RealTimePLot()
else:
    graph = None

class IDS_IPS:
    EPOCHS = 1
    BATCH_SIZE = 32
    
    def __init__(self):
        self.history = {}
        self.stop_event = threading.Event()
        self.monitor_ready = threading.Event()
        self.stop_event_mp = mp.Event()
        self.model = Models(lock=_lock)
        self.Utils = Utils()
        self.session_id = str(uuid4())
        self.RefitQueue = RefitQueue(session_id=self.session_id)
        self.Capture = None
        self.whiltelist = "whitelist.json"
        self.detector = None  # sera assigné dans _detection_coroutine
        self.process = []
        self.threads = []
        self._cleaned = False
    
    @staticmethod
    def change_mode(mode, detector: Optional[AnomalyDetector] = None):
        mode = str(mode).strip().lower()
        if detector:
            if mode in ("ids", "ips"):
                detector._change_mode(mode)
            return mode == detector.mode
        return False
            
    
    def stop(self):
        self.stop_event.set()
        self.stop_event_mp.set()
        if self.detector:
            self.detector.stop()
     
    def _create_refit_monitor(self):
        self.ModelRefitMonitor = ModelRefitMonitor(
            capture_path=CAPTURE_FILENAME,
            session_id=self.session_id,
            model_path=self.model_file,
            mode=self.mode,
            epochs=self.EPOCHS,
            batch_size=self.BATCH_SIZE,
            refit_delay=7 * 24 * 3600,
            min_new_packets=1_000_000
            )
    
    def add_ignored_ip(self, ip: str, direction: str = "src") -> bool:
        """Ajoute une IP à la liste des IPs ignorées (src ou dst)."""
        if self.Capture is None:
            return False
        if direction == "src":
            return self.Capture.add_src_ip_to_ignore(ip)
        elif direction == "dst":
            return self.Capture.add_dst_ip_to_ignore(ip)
        return False
    
    def remove_ignored_ip(self, ip: str, direction: str = "src") -> bool:
        """Retire une IP de la liste des IPs ignorées (src ou dst)."""
        if self.Capture is None:
            return False
        if direction == "src":
            return self.Capture.remove_src_ip_to_ignore(ip)
        elif direction == "dst":
            return self.Capture.remove_dst_ip_to_ignore(ip)
        return False

    def main(self, config=False):
         try:
             # 1. Récupération de la configuration (interactive ou fichier)
             self._load_configuration(config)
     
             # 2. Affichage de la configuration
             self._print_configuration()
     
             # 3. Initialisation des conteneurs partagés
             model_ready = threading.Event()
             model_ready_mp = mp.Event()
             
             detect_queue = queue.Queue(maxsize=100_000_000)
             # memory = MemoryManager(size=16)
             # self.memory = memory
             process = []
             
             self._create_refit_monitor()
             # 4. Création des threads d'apprentissage et de détection
             threads = self._start_learning_and_detection_threads(
                 model_ready, model_ready_mp, detect_queue,
             )

             r_process = self._start_refit_manager_process(model_ready_mp, self.stop_event_mp)
             # process.append(p_detect)
             process.append(r_process)
             self.process = process
             self.threads = threads
             # 5. Gestion des signaux d'arrêt
             self._setup_signal_handlers(process, threads)
     
             # 6. Attente de l'arrêt
             self._wait_for_stop()
     
             # 7. Nettoyage final
             self._cleanup(process, threads)
     
         except Exception as e:
             logger.print(f"[ERROR] Exception fatale dans main : {e}")
             self._emergency_cleanup()
     
    # ----------------------------------------------------------------------
    # Méthodes privées de configuration
    # ----------------------------------------------------------------------
    def _load_configuration(self, config_flag):
        """Charge la configuration depuis l'utilisateur ou un fichier."""
        if not config_flag:
            self._interactive_config()
        else:
            self._file_config()

        # Conversion et validation des types
        self.ids_mode = str(self.ids_mode)
        self.mode = self.mode.lower()
        self.duration = int(self.duration)
        self.save_interval = int(self.save_interval)
        self.combination_mode = self.combination_mode.lower()
        self.packet_anomaly = float(self.packet_anomaly)
        self.model_file = os.path.join(MODEL_DIR, self.model_file)
        os.makedirs(self.anomaly_dir, exist_ok=True)
        self.verbose = int(self.verbose)
        if not self.interface:
            self.interface = detect_all_ifaces()
            
        if isinstance(self.interface, str):
            if self.interface in ("all", "none"):
                self.interface = detect_all_ifaces()
            else:
                self.interface = [self.interface]
        
    def _interactive_config(self):
        """Demande interactivement chaque paramètre."""
        self.model_file = input("Nom du fichier modèle (ex: model.pkl) : ").strip() or "model.pkl"
        self.anomaly_dir = input(f"Dossier pour anomalies (default: {DEFAULT_ANOMALY_DIR}/) : ").strip() or DEFAULT_ANOMALY_DIR
        self.duration = input(f"Durée collecte pour fit initial en secondes (default: {DEFAULT_DURATION}) : ").strip() or str(DEFAULT_DURATION)
        self.save_interval = input(f"Durée sauvegarde périodique en secondes (default: {DEFAULT_SAVE_INTERVAL}) : ").strip() or str(DEFAULT_SAVE_INTERVAL)
        self.mode = input("Mode d'entraînement du modèle (full ou fast, par défaut full) : ").strip() or "full"
        self.combination_mode = input("Mode combinaison anomalies (or/and/weighted, default or) : ").strip() or "or"
        self.packet_anomaly = input("Seuil proportion anomalies packets (default 0.3) : ").strip() or "0.4"
        self.interface = input("Interface réseau (ex: wlp2s0, default: toutes) : ").strip() or None
        self.ids_mode = input("Mode de fonctionnement de l'ids/ips (default: ids) : ").strip() or "ids"
        self.verbose = input("Verbosité : (1 ou 0, default 1) : ").strip() or 1
        self.clear_sets_at_exit = input("Nettoyé les sets à la sortie (1 ou 0, default 0)").strip().lower() == "1"
        self.unlock_at_exit = input("Débloqué les ips bloqué à la sortie (1 ou 0, default 1)").strip().lower() == "1"
        self.do_not_fit = input(
            "Capturer le traffic pour fit un modèle ? Mettre 0 pour non, si vous avez un modèle, si il est imcompatible le fit sera quand même lancé (1/0, default 0)"
        ).strip().lower() == "O"
        
    def _file_config(self):
        """Charge la configuration depuis le dictionnaire CONFIG."""
        date = datetime.now().isoformat()
        self.model_file = CONFIG.get("model_file", f"model_{date}.pkl")
        self.mode = CONFIG.get("mode", "full")
        self.duration = CONFIG.get("duration", 1)
        self.save_interval = CONFIG.get("save_interval", 1)
        self.combination_mode = CONFIG.get("combination_mode", "or")
        self.packet_anomaly = CONFIG.get("packet_anomaly", 0.4)
        self.ids_mode = CONFIG.get("ids_mode", "ids")
        self.interface = CONFIG.get("interface", None)
        self.anomaly_dir = CONFIG.get("anomaly_dir", DEFAULT_ANOMALY_DIR) or DEFAULT_ANOMALY_DIR
        self.verbose = CONFIG.get("verbose", 1)
        self.clear_sets_at_exit = CONFIG.get("clear_sets_at_exit", False)
        self.unlock_at_exit = CONFIG.get("unlock_at_exit", True)
        self.do_not_fit = CONFIG.get("do_not_fit", False)

    def _print_configuration(self):
        """Affiche la configuration courante."""
        logger.print("Configuration de l'ids/ips : ")
        logger.print("    -Fichier de sauvegarde du model : ", self.model_file)
        logger.print("    -Mode de creation du model : ", self.mode)
        logger.print("    -Durée d'appretissage : ", self.duration)
        logger.print("    -Intervalle de sauvegarde : ", self.save_interval)
        logger.print("    -Mode de l'ids/ips : ", self.ids_mode)
        logger.print("    -Pourcentage d'anomaly suspecté : ", self.packet_anomaly)
        logger.print("    -Mode de combinaison pour prediction du model : ", self.combination_mode)
        logger.print("    -Dossier d'anomalie : ", self.anomaly_dir)
        logger.print("    -Niveau de verbosité : ", self.verbose)

    # ----------------------------------------------------------------------
    # Méthodes privées pour les process d'apprentissage et détection
    # ----------------------------------------------------------------------
    def _start_learning_and_detection_threads(self, model_ready, model_ready_mp, queue_or_mem):
        """Crée et démarre les threads d'apprentissage et de détection."""

        # Thread d'apprentissage (exécute une coroutine asyncio)
        t_learn = threading.Thread(
            target=self._run_async_learning,
            args=(model_ready, model_ready_mp, ),
            daemon=True, name="Learning Thread"
        )   
        
        # Thread de détection
        t_detect = threading.Thread(
            target=self._run_async_detection,
            args=(model_ready, queue_or_mem,),
            daemon=True, name="Detection Thread"
        )

        t_learn.start()
        t_detect.start()
        return [t_learn, t_detect]

    def _run_async_learning(self, model_ready, model_ready_mp):
        """Wrapper synchrone pour la coroutine d'apprentissage."""
        try:
            asyncio.run(self._learning_coroutine(model_ready, model_ready_mp))
        except KeyboardInterrupt:
            logger.print("[INFO] Learning thread interrompu")
            self.stop_event.set()
            self.stop_event_mp.set()

    async def _learning_coroutine(self, model_ready, model_ready_mp):
        """Coroutine principale d'apprentissage du modèle."""
        while not self.monitor_ready.is_set():
            await asyncio.sleep(0.01)
            
        if self.do_not_fit:
            logger.print("[INFO] L'utilisateur spécifie de ne pas entrainer de modèle, nous allons vérifier son fichier pour décider !")
            if validate_model_file(self.model_file):
                logger.print("FICHIER validé, fit skippé, la détection sera lancé immédiatement !")
                model_ready.set()
                model_ready_mp.set()
                # Bascule de Suricata en mode IDS après apprentissage
                await self._switch_suricata_to_ids(ids_is_launch=False)
                return
            
            logger.print("FICHIER incompatible, le fit sera lancé !")
            
        logger.print(f"[INFO] Démarrage de Suricata en arrière-plan({self.ids_mode.upper()})...")
        suricata_thread = self.Utils.run_suricata_background(self.ids_mode, self.interface)
        await asyncio.sleep(2)
        logger.print(f"Suricata lancé dans le thread: {suricata_thread.name}")

        try:
            logger.print("[INFO] Collecte des paquets et préparation des features...")
            X_sequences, scaler, scaler_pkt, X_packets = await collect_and_process(
                duration=self.duration,
                save_interval=self.save_interval,
                ifaces=self.interface,
                maxsize=0,
                filename=CAPTURE_FILENAME,
                add_data_path=ADD_DATA_TO_CAPTURE_PATH
            )
            if X_sequences is None or X_packets is None:
                logger.print("[ERROR] Échec de la collecte ou traitement")
                self.stop_event.set()
                self.stop_event_mp.set()
                return

            n_seq, seq_len, n_seq_features = X_sequences.shape
            n_pkt_features = X_packets.shape[1]
            logger.print("\n📊 Dimensions des données :")
            logger.print(f"   Séquences : {X_sequences.shape}")
            logger.print(f"   Paquets : {X_packets.shape}")

            # Construction et entraînement des modèles
            models = Models(lock=_lock)
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.build_models(
                n_pkt=seq_len, n_seq_features=n_seq_features,
                n_pkt_features=n_pkt_features, mode=self.mode
            )
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.fit_models(
                ae_seq=ae_seq, cnn_seq=cnn_seq, if_seq=if_seq, lof_seq=lof_seq,
                ae_pkt=ae_pkt, if_pkt=if_pkt, lof_pkt=lof_pkt,
                X_sequences=X_sequences, X_packets=X_packets,
                epochs=self.EPOCHS, batch_size=self.BATCH_SIZE, verbose=self.verbose
            )

            self.model = models
            
            model = {
                "ae_seq": ae_seq, "cnn_seq": cnn_seq,
                "if_seq": if_seq, "lof_seq": lof_seq,
                "ae_pkt": ae_pkt, "if_pkt": if_pkt, 
                "lof_pkt": lof_pkt, "scaler_pkt": scaler_pkt,
                "scaler_seq": scaler, 
            }
            # Sauvegarde du modèle
            # with open(self.model_file, "wb") as f:
            #     dill.dump(model, f)
            save(dill.dumps(model), self.model_file)
            logger.print(f"[INFO] Modèle sauvegardé dans {self.model_file}")

            # Partage des données avec le thread de détection
            model_ready.set()
            model_ready_mp.set()
            
            # Bascule de Suricata en mode IDS après apprentissage
            await self._switch_suricata_to_ids()

        except Exception as e:
            logger.print(f"[ERROR] Exception dans _learning_coroutine : {e}")
            traceback.print_exc()
            self.stop_event.set()
            self.stop_event_mp.set()
            self._stop_suricata_safe()

    async def _switch_suricata_to_ids(self, ids_is_launch:bool = True):
        """Arrête Suricata actuel et le relance en mode IDS."""
        try:
            if ids_is_launch:
                logger.print("[INFO] Arret de Suricata(IPS)...")
                stop_ready = threading.Event()
                def stop():
                    state.stop()
                    stop_ready.set()
                stop()
                logger.print('En attente de l\'arret ...')
                stop_ready.wait()
            logger.print('Lancement Suricata en mode IDS ')
            logger.print("[INFO] Démarrage de Suricata en arrière-plan(IDS)...")
            suricata_thread = self.Utils.run_suricata_background("ids", self.interface)
            await asyncio.sleep(2)
            logger.print(f"Suricata lancé dans le thread: {suricata_thread.name}")
        except Exception as e:
            logger.print("[ERREUR] Suricata lancement ids  : ", e)

    def _stop_suricata_safe(self):
        """Tente d'arrêter Suricata sans lever d'exception bloquante."""
        try:
            logger.print("[INFO] Arret de Suricata...")
            state.stop()
        except Exception as e:
            logger.print("[ERREUR] Suricata task cancelling : ", e)
    
    
    def _start_refit_queue(self):
        self.RefitQueue.start()
        return self.RefitQueue
    
    def _stop_refit_queue(self):
        if hasattr(self, "RefitQueue"):
            if self.RefitQueue is not None:
                self.RefitQueue.stop()
            
    def _start_capture(self, queue_or_mem):
        logger.print()
        logger.print("=" * 60)
        logger.print("📡 DÉMARRAGE DE LA CAPTURE")
        logger.print("=" * 60)
        logger.print(f"   PID              : {os.getpid()}")
        logger.print(f"   Interfaces       : {self.interface}")
        logger.print(f"   Filtre           : {FILTER}")
        logger.print("=" * 60)
        logger.print()
        refitQueue = self._start_refit_queue()
        self.Capture = Capture(queue=queue_or_mem, backup_queue=refitQueue)
        self.Capture.capture(
            ifaces=self.interface,
            filter=FILTER, 
        )
        logger.print("Capture Démaréé")
        return self.Capture
    
    # def _start_capture_process(self, queue_or_mem, model_ready):
    #     process = mp.Process(
    #         target=self._start_capture,
    #         args=(queue_or_mem, model_ready),
    #         daemon=True, name="Capture Process"
    #     )
    #     process.start()
    #     return process
    
    def _stop_capture(self):
        if hasattr(self, "Capture"):
            if self.Capture is not None:
                self.Capture.stop(1)
    
    # ----------------------------------------------------------------------
    # Thread de détection
    # ----------------------------------------------------------------------
    
    def _run_refit_manager(self, model_ready_mp, mp_event):
        model_ready_mp.wait()
        if mp_event.is_set():
            return
        
        logger.print()
        logger.print("=" * 60)
        logger.print("🔄 DÉMARRAGE DU PROCESSUS DE REFIT (RÉ-APPRENTISSAGE)")
        logger.print("=" * 60)
        logger.print(f"   PID              : {os.getpid()}")
        logger.print(f"   Session ID       : {self.session_id}")
        logger.print(f"   Délai refit      : {self.ModelRefitMonitor.refit_delay // 3600} heures")
        logger.print("=" * 60)
        logger.print()
        self.ModelRefitMonitor.start()
    
    def _start_refit_manager_process(self, model_ready, mp_event):
        process = mp.Process(
            target=self._run_refit_manager,
            args=(model_ready, mp_event),
            daemon=True, name="Refit Manager Process"
        )
        process.start()
        return process
    
    def _run_async_detection(self, model_ready, queue_or_mem):
        """Wrapper synchrone pour la coroutine de détection."""
        try:
            asyncio.run(self._detection_coroutine(model_ready, queue_or_mem))
            
        except KeyboardInterrupt:
            logger.print("[INFO] Detection thread interrompu")
            self.stop_event.set()
            self.stop_event_mp.set()

    async def _detection_coroutine(self, model_ready, queue_or_mem):
        """Coroutine principale de détection en temps réel."""
        # Plus de global detector
        try:
            if graph:
                graph.control()
            async with _api_lock:
                detector = AnomalyDetector(
                    enable_graph=GRAPH and graph is not None,
                    graph=graph,
                    Models_instance=self.model, 
                    interfaces=self.interface,
                    clear_sets_at_exit=self.clear_sets_at_exit,
                    unlock_at_exit=self.unlock_at_exit,
                    mode=self.ids_mode, 
                    queue=queue_or_mem,
                    whiltelist=self.whiltelist,
                )
                self.detector = detector
            
            detector._monitor_task = asyncio.create_task(
                detector.monitor_suricata_alerts(
                    verbose=self.verbose,
                    ready_event=self.monitor_ready
                )
            )
            
            logger.print()
            logger.print("=" * 60)
            logger.print("✅ DETECTOR CRÉÉ DANS LE PROCESSUS DE DÉTECTION")
            logger.print("=" * 60)
            logger.print(f"   PID du processus de détection : {os.getpid()}")
            logger.print(f"   Detector prêt                 : {self.detector is not None}")
            logger.print("=" * 60)
            logger.print()
            # =======================
            
            logger.print("[INFO] Attente du modèle pour démarrer la détection...")
            while not model_ready.is_set():
                if self.stop_event.is_set():
                    return
                await asyncio.sleep(0.5)
            
            self._start_capture(queue_or_mem)
            logger.print("[INFO] Lancement de la détection temps réel...")
            await self.detector.detect(
                self.model_file,
                combination_mode=self.combination_mode,
                packet_anomaly=self.packet_anomaly,
                verbose=self.verbose,
                new_model_available=self.ModelRefitMonitor.new_model_available,
                model_path=self.ModelRefitMonitor.model_path,
                refit_delay=self.ModelRefitMonitor.refit_delay
            )
        except Exception as e:
            logger.print(f"[ERROR] Exception dans _detection_coroutine : {e}")
            traceback.print_exc()
            self.stop_event.set()
            self.stop_event_mp.set()
        
        finally:
            if detector is not None and detector._monitor_task is not None and not detector._monitor_task.done():
                detector._monitor_task.cancel()
                try:
                    await detector._monitor_task
                except asyncio.CancelledError:
                    pass
                
                detector._monitor_task = None
    
    # ----------------------------------------------------------------------
    # Gestion des signaux et nettoyage
    # ----------------------------------------------------------------------
    def _setup_signal_handlers(self, process:list[mp.Process] = None, threads:list[threading.Thread] = None):
        """Configure les gestionnaires de signaux pour un arrêt propre."""
        def signal_handler(*args, **kwargs):
            logger.print("\n[INFO] Interruption détectée. Arrêt des threads...")
            print(self.detector.detect_start_time)
            print(self.detector.detect_end_time)
            print(self.detector.pkt_proccessed)
            self._cleanup(process or self.process, threads or self.threads)
            os._exit(0)
            # sys.exit(0)
        
        if threading.main_thread() is threading.current_thread():
            signal_manager(signal_handler)
        
    def _wait_for_stop(self):
        """Boucle d'attente jusqu'à ce que l'arrêt soit demandé."""
        try:
            while not self.stop_event.is_set() or self.stop_event_mp.is_set():
                time.sleep(1)
            
        except KeyboardInterrupt:
            logger.print("\n[INFO] Ctrl+C reçu dans _wait_for_stop")
            self.stop_event.set()
            self.stop_event_mp.set()
        
        except Exception as e:
            logger.print(f"\n[INFO] Erreur{str(e)} reçu dans _wait_for_stop")
            self.stop_event.set()
            self.stop_event_mp.set()
        
        finally:
            if self.detector:
                self.detector.stop()
            
            self._cleanup(self.process, self.threads)
            
    def _cleanup(self, process:list[mp.Process], threads:list[threading.Thread]):
        """Effectue toutes les opérations de nettoyage (sauvegardes, arrêt threads, etc.)."""
        if self._cleaned:
            logger.print("[INFO] Cleanup déjà effectué")
            return
        logger.print("[INFO] Nettoyage en cours...")
        
        with _lock:
            # Sauvegarde des états internes
            self._save_detector_state()

        # # Signal d'arrêt aux threads
        # self.stop_event.set()
        # self.stop_event_mp.set()

        # Arrêt de Suricata
        self.Utils.stop_suricata()
        self._stop_capture()
        self._stop_refit_queue()
        
        try:
            self.detector.React._sig_manager()
        except Exception:
            pass
        
        try:
            self.detector.stop()
        except Exception:
            pass
        
        try:
            state._sig_manager()
        except Exception:
            pass
        
        try:
            self.ModelRefitMonitor.stop()
        except Exception:
            pass        
        
        # Notification API (optionnel)
        self._notify_api_close()

        # Attente de la fin des threads
        for p in process:
            if p.is_alive():
                try:
                    p.join(timeout=1)
                    p.kill()
                except Exception:
                    pass
                
        for th in threads:
            if th.is_alive():
                try:
                    th.join(1)
                except Exception:
                    pass
        
        if hasattr(self, "memory"):
            self.memory.close()
        self._cleaned = True
        logger.print("[INFO] Arrêt terminé.")

    def _save_detector_state(self):
        """Sauvegarde l'état du détecteur (whitelist, scores, etc.)."""
        if not hasattr(self, 'detector') or not self.detector:
            return
        
        # Sauvegarde des scores IP
        try:
            logger.print("AnomalyScorer saving.")
            self.detector.AnomalyScorer.save(
                self.detector.AnomalyScorer.ip_score_dir,
                self.detector.AnomalyScorer.ip_data
            )
        except Exception:
            pass

        # Sauvegarde de la whitelist
        try:
            logger.print('Detector saving whitelist')
            self.detector.React.save_whitelist(
                    self.detector.React.whitelist_filename,
                    self.detector.React.whitelist
                )
        except Exception:
            pass

        # Sauvegarde de l'historique des réactions
        try:
            logger.print('React saving History.')
            self.detector.React.save_history(
                self.detector.React.history_filename,
                self.detector.React.blocked
            )
        except Exception:
            pass

    def _notify_api_close(self):
        """Envoie une requête de fermeture à l'API."""
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(close_api(URL + "/close"))
            loop.close()
        except Exception:
            pass

    def _emergency_cleanup(self):
        """Nettoyage d'urgence en cas d'exception fatale."""
        self.stop_event.set()
        self.stop_event_mp.set()
        self.Utils.stop_suricata()
        logger.print("[INFO] Nettoyage d'urgence terminé.")
        
        
def all_threads():
    for thread in threading.enumerate():
        logger.print(f"Thread: {thread.name}")
        logger.print(f"  ID: {thread.ident}")
        logger.print(f"  Démarré: {thread.is_alive()}")
        logger.print(f"  Daemon: {thread.daemon}")
        logger.print("-" * 40)

def asyncio_threads():
    tasks = asyncio.all_tasks()
    logger.print(f"Tâches actives: {len(tasks)}")
    
    for task in tasks:
        logger.print(f"Task: {task.get_name()}")
        logger.print(f"  En cours: {not task.done()}")
        logger.print(f"  Annulée: {task.cancelled()}")
        logger.print(f"  Résultat: {task.result() if task.done() else 'En cours'}")
        
if __name__ == "__main__":
    try:
        ids_ips = IDS_IPS()
        # if GRAPHS:
        #     graph = RealTimePLot()
        #     det_mod.GLOBAL_GRAPHS = {
        #         "graph": graph,
        #     }
            # graph.control()
        th, _ = start(app, host, port)
        th.start()
        def _main_signal_handler(*args, **kwargs):
            logger.print("\n[SIGNAL] Arrêt demandé...")
            ids_ips.stop()
        
        signal_manager(_main_signal_handler)
        # while 1:    
        #     time.sleep(2)
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
        time.sleep(10)
        sys.exit(0)
        # os._exit(0)
    
    finally:
        IS_EXECUTED = False