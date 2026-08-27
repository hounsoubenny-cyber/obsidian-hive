#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 11:36:50 2026

@author: hounsousamuel
"""

import time
import asyncio
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, status, Form, File, UploadFile
from pydantic import BaseModel
from sandbox_ia.core.orchestrator import SandboxOrchestrator, SandboxConfig, SandboxReport
from sandbox_ia.core.estimate_risk import estimate_risk_async
from sandbox_ia.api.api_config import LIMITE
from modules_utils.limiter import limiter
from sandbox_ia.configs.orchestrator_config import DOCKER_DEFAULTS, DEFAULT_EXECUTION_TIMEOUT
from sandbox_ia.configs.behavior_scorer_config import DECAY_AMOUNT, DECAY_INTERVAL, ALERT_THRESHOLD
from sandbox_ia.executor.detect_language import get_supported_languages
from sandbox_ia.ml_model.load_models import load_models
from sandbox_ia.configs.ml_configs import ML_AVAILABLE, PATH_DICT

from typing import Any

router = APIRouter()
_orchestrator: Optional[SandboxOrchestrator] = None

MAX_CONCURRENT_ANALYSES = 10
_analysis_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)
_active_sessions: dict[str, SandboxOrchestrator] = {}  
_models: dict[str, Any] = None

def get_models():
    global _models
    if not _models:
        _models = load_models(**PATH_DICT)
    return _models
    
# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def get_orchestrator() -> SandboxOrchestrator:
    """Retourne l'instance unique de l'orchestrateur."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SandboxOrchestrator()
        if ML_AVAILABLE:
            _orchestrator.init_ml_models(**get_models())
    return _orchestrator


async def _analyze_code(
    orchestrator: SandboxOrchestrator,
    code: str,
    language: str | None = None,
    config: SandboxConfig | None = None,
    use_cache: bool = True,
) -> SandboxReport:
    return await orchestrator.analyze(
        code=code, 
        language=language,
        config=config, 
        use_cache=use_cache
    )

def _server_error(e: Exception):
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": str(e), "type": type(e).__name__}
    )

# =============================================================================
# MODELS
# =============================================================================

class ConfigData(BaseModel):
    network_disabled: bool = DOCKER_DEFAULTS["network_disabled"]
    mem_limit: str = DOCKER_DEFAULTS["mem_limit"]
    extra_env: dict | None = DOCKER_DEFAULTS["extra_env"]
    exec_timeout: float = DEFAULT_EXECUTION_TIMEOUT
    enable_strace: bool = True
    enable_fs_monitor: bool = True
    alert_threshold: int = ALERT_THRESHOLD
    decay_interval: float = DECAY_INTERVAL
    decay_amount: int = DECAY_AMOUNT

# =============================================================================
# ROUTES
# =============================================================================
@router.post("/analyse_code")
@limiter.limit(f"{LIMITE}/minute")
async def analyze_code(
    request: Request, 
    config_str: str = Form(default=None),
    code: str = Form(default=None),
    language: str | None = Form(None),
    file: UploadFile = File(None),
    use_cache: int = Form(default=1)
):
    try:
        if not code and not file:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail="Code ou fichier requis"
            )
        
        code_to_use = None
        if code:
            code_to_use = code
        else:
            code_to_use = await file.read()
        
        if isinstance(code_to_use, bytes):
            code_to_use = code_to_use.decode("utf-8", errors="ignore")
            
        config = ConfigData.model_validate_json(config_str)
        config = SandboxConfig(**config.model_dump())
        config.network_disabled = True
        use_cache = bool(int(use_cache))
        async with _analysis_semaphore:
            orchestrator = SandboxOrchestrator()
            if ML_AVAILABLE:
                orchestrator.init_ml_models(**get_models())
            session_id = f"shieldai_{int(time.time())}_{id(orchestrator)}"
            _active_sessions[session_id] = orchestrator
            
            try:
                result = await _analyze_code(
                    orchestrator=orchestrator,
                    use_cache=use_cache,
                    code=code_to_use,
                    config=config,
                    language=language,
                )
                
            finally:
                _active_sessions.pop(session_id, None)
                
        return result.to_dict()
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise _server_error(e)

@router.post("/estimate_risk")
@limiter.limit(f"{LIMITE}/minute")
async def estimate_risk(
    request: Request,
    code: str = Form(default=None),
    file: UploadFile = File(None),
):
    """TPException:
        raise
    Estime le risque d'un code SANS l'exécuter (analyse statique).
    
    Rapide (< 1s) mais moins précis qu'une analyse complète.
    """
    try:
        if not code and not file:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail="Code ou fichier requis"
            )
        
        code_to_use = None
        if code:
            code_to_use = code
        else:
            code_to_use = await file.read()
         
        if isinstance(code_to_use, bytes):
            code_to_use = code_to_use.decode("utf-8", errors="ignore")
            
        return await estimate_risk_async(code=code_to_use)
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise _server_error(e)

@router.get("/languages")
@limiter.limit(f"{LIMITE}/minute")
async def supported_languages(request: Request):
    """Retourne la liste des langages supportés."""
    return {
        "languages": get_supported_languages(),
        "count": len(get_supported_languages()),
        "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }

@router.get("/config")
@limiter.limit(f"{LIMITE}/minute")
async def sandbox_config(request: Request):
    """Retourne la configuration par défaut du sandbox."""
    from sandbox_ia.configs.orchestrator_config import (
        DEFAULT_SANDBOX_IMAGE, DEFAULT_EXECUTION_TIMEOUT, DOCKER_DEFAULTS
    )
    from sandbox_ia.configs.behavior_scorer_config import ALERT_THRESHOLD
    
    return {
        "image_name": DEFAULT_SANDBOX_IMAGE,
        "mem_limit": DOCKER_DEFAULTS["mem_limit"],
        "cpu_quota": DOCKER_DEFAULTS["cpu_quota"],
        "pids_limit": DOCKER_DEFAULTS["pids_limit"],
        "exec_timeout": DEFAULT_EXECUTION_TIMEOUT,
        "alert_threshold": ALERT_THRESHOLD,
        "network_disabled": DOCKER_DEFAULTS["network_disabled"],
        "supported_languages": get_supported_languages(),
        "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }

@router.get("/status/containers")
async def container_status(request: Request):
    """Retourne l'état du container sandbox."""
    def _get_statut(sid, manager):
        try:
            
            status = manager.get_status()
            pid = manager.get_pid()
            healthy = manager.health_check() if status == "running" else False
            
            return {
                "status": status,
                "pid": pid,
                "healthy": healthy,
                "session_id": sid,
                "container_name": manager.container.name if manager.container else None,
                "image_name": manager.image_name,
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
                "error": None
            }
            
        except HTTPException:
            raise
            
        except Exception as e:
            return {
                "status": "error",
                "pid": None,
                "healthy": False,
                "session_id": sid,
                "container_name": None,
                "image_name": None,
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
                "error": str(e)
            }
    
    return [
        _get_statut(sid, o.manager) for sid, o in list(_active_sessions.items())
    ]


@router.get("/status/health")
async def health(request: Request):
    """Health check de l'API."""
    try:
        # orchestrator = get_orchestrator()
        # status = orchestrator.manager.get_status() if orchestrator.manager else "unknown"
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "active_sessions": list(_active_sessions),
            # "detector_ready": orchestrator is not None,
            # "container_status": status,
            "error": None,
        }
    except HTTPException:
        raise
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            # "detector_ready": False,
            # "container_status": "error",
            "error": str(e),
            "active_sessions": list(_active_sessions)
        }
