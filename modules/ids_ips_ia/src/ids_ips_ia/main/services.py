#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 06:59:40 2026

@author: hounsousamuel

Logique métier "pure" de l'API IDS/IPS (fonctions _do_* + helpers auth).
Indépendant de FastAPI côté routing : routes.py appelle ces fonctions avec
des données déjà validées par les schémas Pydantic (schemas.py).
"""

import os
import re
import asyncio
import threading
from typing import Optional
from datetime import datetime, timedelta

from jose import jwt, JWTError
from jose.jwt import ExpiredSignatureError
from fastapi import HTTPException, Request, status

from ids_ips_ia.auth.auth import verify_password
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.utils import _get_ip_type
from ids_ips_ia.detection.anomaly_logger import iter_anomalies
from ids_ips_ia.detection.mocks import _get_list_blocked_ip_mocked # noqa
from ids_ips_ia.detection.detection_module import CONFIG as CONFIG_DET
from ids_ips_ia.reaction.reaction_module import GeoLocator
from ids_ips_ia.config.config_ids import (
    GLOBAL_CONFIG as CONFIG,
    API_CONFIG,
    JWT_EXPIRE_MINUTES,
    ADMIN_DATA,
    NOT_BEFORE,
    REQUEST_LIMIT as REQUEST,
)

from ids_ips_ia.main.schemas import (
    Conf, UnlockData, WhitelistData, BasicData,
    ChangeModeData, BlockIPData, IgnoreIPData,
)
from ids_ips_ia.main.orchestrator import IDS_IPS, graph
from ids_ips_ia.main import server_state
from ids_ips_ia.main.server_state import set_token

logger = get_logger()
_api_lock = asyncio.Lock()
_default_locator = GeoLocator()


# =============================================================================
# AUTH HELPERS
# =============================================================================

def validate_admin_data():
    return all(v for v in ADMIN_DATA.values())


def create_acces_token(data: dict):
    if not isinstance(data, dict):
        raise ValueError('data doit être dict !')
    copy = {k: v for k, v in data.items()}
    expiry_date = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    copy['sub'] = data.get('username', '')
    copy['exp'] = expiry_date
    copy['nbf'] = datetime.utcnow() + timedelta(seconds=NOT_BEFORE)
    copy["iat"] = datetime.utcnow()
    copy['type'] = "access"
    token = jwt.encode(copy, ADMIN_DATA.get('secret_key', ""), algorithm="HS256")
    set_token(token)  # remplace `global TOKEN` (TOKEN vit maintenant dans server_state.py)
    return token


def verify_token(token, expire: bool = True):
    try:
        initial_data = jwt.decode(
            token,
            ADMIN_DATA.get('secret_key', ""),
            algorithms=['HS256'],
            options={
                "verify_exp": expire,
                "verify_nbf": True
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
            detail="TOKEN_EXPIRED",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide",
            headers={"WWW-Authenticate": "Bearer"}
        )


def verify_admin(username: str, password: str):
    if validate_admin_data():
        if username != ADMIN_DATA.get('username', ''):
            raise HTTPException(status_code=401, detail="Authentification échoué (Nom user ne correspond pas)")

        if not verify_password(password, ADMIN_DATA.get('hash_password', "")):
            raise HTTPException(status_code=401, detail="Authentification échoué (Mot de passe user ne correspond pas)")

    else:
        raise HTTPException(status_code=401, detail="Veuillez d'abord configurer les infos admin.")


def validate_username(token, username, expire: bool = True):
    user = verify_token(token, expire)
    if not (user == ADMIN_DATA.get("username", "") == username):
        raise HTTPException(
            detail="Username invalide ou token bizarre",
            status_code=401
        )
    return True


# =============================================================================
# LOGIQUE MÉTIER (_do_*)
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
    return await _do_start_logic(request.app.state)


async def _do_get_alerts(ids_ips: Optional["IDS_IPS"], n: int):
    if ids_ips is None or ids_ips.detector is None:
        return {"alerts": [], "detail": "IDS non démarré"}
    alerts = ids_ips.detector._get_last_alerts(n)
    return {
        "alerts": alerts,
        "total": len(alerts),
        "ids_running": True
    }

async def _do_get_system_alerts(ids_ips: Optional["IDS_IPS"], n: int, status: Optional[str]):
    """Alertes SYSTEME (ex. inférence en panne), distinctes des alertes d'attaque de /alerts."""
    if ids_ips is None or ids_ips.detector is None:
        return {"system_alerts": [], "total": 0, "open": 0, "detail": "IDS non démarré"}
    
    if status not in (None, "open", "resolved"):
        raise HTTPException(status_code=400, detail="status doit être 'open' ou 'resolved'")
        
    n = max(1, min(int(n), 200))
    items = ids_ips.detector._get_system_alerts(n, status)
    return {
        "system_alerts": items,
        "total": len(items),
        "open": sum(1 for a in ids_ips.detector._get_system_alerts(200, "open")),
    }


def _read_anomaly_file(path: str, offset: int, limit: int, include_features: bool):
    """Bloquant (pickle) : à lancer dans un thread. Lit [offset, offset+limit[ sans tout charger en mémoire."""
    out, total = [], 0
    for i, e in enumerate(iter_anomalies(path)):
        total = i + 1
        if i < offset or len(out) >= limit:
            continue                                  # on continue de compter pour renvoyer le total
        feats = e.get("features")
        row = {k: v for k, v in e.items() if k != "features"}
        row["index"] = i
        row["features_shape"] = list(getattr(feats, "shape", []))
        if include_features and feats is not None:
            row["features"] = feats.tolist()
        out.append(row)
    return out, total


def _format_time(t):
    return datetime.fromtimestamp(t).isoformat(timespec="seconds")

async def _do_get_anomaly_files(
    ids_ips: Optional["IDS_IPS"], name: Optional[str], offset: int, limit: int, include_features: bool
):
    """
    Sans `name` : liste des fichiers d'anomalies actuels. Avec `name` : leur contenu (paginé).
    `name` doit être EXACTEMENT '<prefix>_<n>.pkl' dans le dossier d'anomalies : pas de chemin, pas de '..'.
    """
    if ids_ips is None or ids_ips.detector is None:
        return {"files": [], "detail": "IDS non démarré"}
    al = ids_ips.detector.anomaly_logger
    directory, prefix = os.path.realpath(al.dir), al.prefix
    pattern = re.compile(rf"{re.escape(prefix)}_(\d+)\.pkl")

    if name is None:
        files = []
        for f in os.listdir(directory):
            m = pattern.fullmatch(f)
            if m:
                st = os.stat(os.path.join(directory, f))
                files.append({
                    "name": f, "index": int(m.group(1)), "size_bytes": st.st_size,
                    "modified": _format_time(st.st_mtime)
                })
        files.sort(key=lambda x: x["index"])
        return {"files": files, "total": len(files), "directory_name": os.path.basename(directory)}

    if not pattern.fullmatch(name):                              # rejette '../x', chemins absolus, autres extensions
        raise HTTPException(status_code=400, detail=f"Nom invalide : attendu '{prefix}_<n>.pkl'")
    path = os.path.realpath(os.path.join(directory, name))
    if os.path.dirname(path) != directory or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    offset, limit = max(0, int(offset)), max(1, min(int(limit), 500 if not include_features else 50))
    try:
        entries, total = await asyncio.to_thread(_read_anomaly_file, path, offset, limit, include_features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lecture impossible : {type(e).__name__}")
    
    stats = {
        "size_bytes": None,
        "last_accès": None,
        "modified": None,
    }
    try:
        st = os.stat(path)
        stats = {
            "size_bytes": st.st_size,
            "last_accès": _format_time(st.st_atime),
            "modified": _format_time(st.st_mtime),
        }
    except Exception:  # Permisssion, autre
        pass
    
    return {
        "name": name, "total": total, "offset": offset, "limit": limit,
        "include_features": include_features, "entries": entries,
        **stats
    }

def _safe_stats(fn):
    """Une stats() cassée ne doit pas faire tomber la route : on renvoie l'erreur à la place."""
    try:
        return fn()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


async def _do_get_stats(ids_ips: Optional["IDS_IPS"]):
    """
    Statistiques de tous les composants : capture, file, détecteur, anomaly logger, blocked skipper.
    Lecture seule, instantanée (compteurs en mémoire).
    """
    if ids_ips is None:
        return {"running": False, "detail": "IDS non démarré"}
    det, cap = ids_ips.detector, ids_ips.Capture
    out = {"running": det is not None, "session_id": getattr(ids_ips, "session_id", None)}
    out["capture"] = _safe_stats(cap.metrics) if cap is not None else None
    if det is None:
        return out
    out["detector"] = _safe_stats(det.stats)
    def _logger_stats():
        st = det.anomaly_logger.stats()
        st["file"] = os.path.basename(st.get("file") or "") or None      # pas de chemin absolu dans la réponse
        return st
    out["anomaly_logger"] = _safe_stats(_logger_stats)
    out["blocked_skipper"] = _safe_stats(det.skipper.stats)
    if hasattr(det.q, "stats"):                       # BuffuredQueue (capture vers disque) ; queue.Queue : voir detector.queue
        out["queue"] = _safe_stats(det.q.stats)
    return out



async def _do_stop_logic(app_state):
    ids_ips: Optional["IDS_IPS"] = getattr(app_state, "_ids_ips", None)
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
    # threading.Thread(target=lambda: (
    #     logger.print("[WATCHDOG] ⚠️ Arrêt forcé après 8s"),
    #     time.sleep(8),
    #     os._exit(0)
    # )).start()
    if thread and thread.is_alive():
        logger.print("[WARN] Le thread IDS_IPS n'a pas terminé son cleanup après 10s (il continue en arrière-plan, daemon).")


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
            "public": [
                {"method": "GET", "path": "/api/help", "description": "Cette documentation"},
                {"method": "GET", "path": "/api/health", "description": "État du système (detector ready, graph port)"},
                {"method": "GET", "path": "/api/geo_location", "params": {"ip": "Adresse IP"}, "description": "Géolocalisation d'une IP (code pays)"},
                {"method": "GET", "path": "/api/rate-limit-status", "description": "Statut du rate limiting"},
                {"method": "GET", "path": "/api/docs", "description": "Documentation Swagger UI"},
                {"method": "GET", "path": "/api/redoc", "description": "Documentation ReDoc"}
            ],
            "monitoring_bearer": [
                {"method": "GET", "path": "/api/stats", "header": "Authorization: Bearer <token>", "description": "Stats de tous les composants : capture (débit, % de pertes), détecteur (débit, file, taille moyenne des lots, séquences), anomaly logger, blocked skipper"},
                {"method": "GET", "path": "/api/system-alerts", "header": "Authorization: Bearer <token>", "params": {"n": "1-200 (défaut 50)", "status": "open | resolved (optionnel)"}, "description": "Alertes système (ex. inférence IA en panne) : open = en cours, resolved = refermée par un lot sain"},
                {"method": "GET", "path": "/api/anomaly-files", "header": "Authorization: Bearer <token>", "params": {"name": "ex. anomalies_0.pkl (sans name : liste des fichiers)", "offset": "0", "limit": "100 (50 max avec features)", "include_features": "false"}, "description": "Liste les fichiers d'anomalies, ou renvoie le contenu paginé d'un fichier"}
            ],
            "authenticated": [
                {"method": "POST", "path": "/api/login", "body": {"username": "admin", "password": "xxx"}, "response": {"access_token": "string", "expires_in": "int", "success": "bool"}},
                {"method": "POST", "path": "/api/refresh_token", "body": {"username": "admin", "token": "refresh_token"}, "response": {"access_token": "string"}}
            ],
            "critical": [
                {"method": "POST", "path": "/api/blocked", "body": {"username": "admin", "token": "access_token"}, "description": "Liste toutes les IPs bloquées avec leurs données", "response": {"blocked": "object", "message": "SUCCESS"}},
                {"method": "POST", "path": "/api/unlock", "body": {"ip": "192.168.1.1", "input": "True", "rule": "drop", "whitelist": "false", "username": "admin", "password": "xxx", "token": "access_token"}, "description": "Débloque une IP et optionnellement l'ajoute à la whitelist"},
                {"method": "POST", "path": "/api/manage_whitelist", "body": {"ip": "192.168.1.1", "add": "True", "username": "admin", "password": "xxx", "token": "access_token"}, "description": "Ajoute (add=true) ou retire (add=false) une IP de la whitelist"},
                {"method": "POST", "path": "/api/config", "body": {"username": "admin", "token": "access_token"}, "description": "Récupère la configuration complète"},
                {"method": "POST", "path": "/api/update_config", "body": {"key": "SEUIL", "data": {"decision": -0.5}, "username": "admin", "password": "xxx", "token": "access_token"}, "description": "Met à jour une partie de la configuration"},
                {"method": "POST", "path": "/api/change_mode", "description": "Change le mode de fonctionnement à chaud"},
                {"method": "GET", "path": "/api/close", "params": {"token": "access_token"}, "description": "Arrête le serveur API"}
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
    input_ = data.input
    rule = data.rule
    whitelist = data.whitelist
    unlock = False
    async with _api_lock:
        success = detector_instance.React.unlock(
            ip=ip,
            input=input_,
            rule=rule,
        )
        already_unlocked = not success and ip not in detector_instance.React.blocked

        if success or already_unlocked:
            unlock = True
            if ip in detector_instance.AnomalyScorer.ip_data:
                detector_instance.AnomalyScorer.ip_data.pop(ip)

        if whitelist.strip().lower() in ['true', 'yes', '1']:
            detector_instance.React.add_to_whitelist(ip)
            logger.print(f'{ip} ajouté à la whitelist !')

        LIST = list(detector_instance.AnomalyScorer.get_list_blocked_ip().keys())

    return {
        "success": ip not in LIST,
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
    return {
        'success': success,
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
            timeout=data.timeout  # 🐛 nécessitait l'ajout du champ `timeout` dans schemas.BlockIPData
        )
    return {
        'success': success,
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
    validate_username(token, username=ADMIN_DATA.get("username"))
    if server_state.server is None:
        logger.print('Serveur non lancé !')
        return {"message ": "Serveur non lancé !"}
    else:
        server_state.server.should_exit = True
        logger.print('Serveur fermé.')
        return {"message ": 'Serveur fermé.'}