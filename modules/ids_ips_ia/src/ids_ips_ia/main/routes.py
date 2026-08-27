#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 07:00:11 2026

@author: hounsousamuel


Routes FastAPI de l'API IDS/IPS.
Deux routers : `router` (avec vérif username/password/token) et
`router_no_auth` (mêmes routes, sans vérif — pour inclusion dans une gateway
qui gère déjà l'auth en amont). Les routes restent fines : elles parsent la
requête puis délèguent tout à services.py.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPBearer

from modules_utils.limiter import limiter
from ids_ips_ia.config.config_ids import REQUEST_LIMIT as REQUEST, Config, _config_path as DEFAULT_IDS_CONFIG_PATH

from ids_ips_ia.main import services as svc
from ids_ips_ia.main.orchestrator import IDS_IPS
from ids_ips_ia.main.schemas import (
    Data, Conf, UnlockData, WhitelistData, BasicData,
    ChangeModeData, BlockIPData, IgnoreIPData,
)

barer = HTTPBearer(
    scheme_name="JWT",
    auto_error=True,
    description="JWT vérifcation!"
)

router = APIRouter()
router_no_auth = APIRouter()


def get_ids_ips(request: Request) -> Optional["IDS_IPS"]:
    """Dépendance FastAPI pour récupérer l'instance IDS_IPS depuis l'état de l'application."""
    return getattr(request.app.state, "_ids_ips", None)


# =============================================================================
# ROUTER AVEC AUTH (standalone)
# =============================================================================

@router.post(path="/login")
@limiter.limit(f"{REQUEST}/minute")
async def _login(request: Request, data: Data):
    return await svc._do_login(data.username, data.password)


@router.get(path="/start")
@limiter.limit(f"{REQUEST}/minute")
async def _start(request: Request):
    try:
        return await svc._do_start(request)
    except Exception as e:
        return {"started": False, "detail": f"Erreur: {str(e)}"}


@router.get("/alerts")
async def get_alerts(
    n: int = 10,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_alerts(ids_ips, n)


@router.get("/stop")
async def _stop(request: Request):
    return await svc._do_stop(request)


@router.get(path="/help")
@limiter.limit(f"{REQUEST}/minute")
async def _help(request: Request):
    """Documentation complète de l'API IDS/IPS."""
    return await svc._do_help()


@router.post("/blocked")
async def get_blocked(
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_blocked(ids_ips, data, verify_auth=True)


@router.post("/config")
@limiter.limit(f"{REQUEST}/minute")
async def get_config(
    request: Request,
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)  # Pas utilisé mais conservé pour cohérence
):
    return await svc._do_get_config(data, verify_auth=True)


@router.post("/refresh_token")
@limiter.limit(f"{REQUEST}/minute")
async def _refresh_token(
    request: Request,
    data: BasicData
):
    return await svc._do_refresh_token(data, verify_auth=True)


@router.post(path="/unlock")
@limiter.limit(f"{REQUEST}/minute")
async def _unlock(
    request: Request,
    data: UnlockData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_unlock(ids_ips, data, verify_auth=True)


@router.post(path="/manage_whitelist")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_whitelist(
    request: Request,
    data: WhitelistData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_manage_whitelist(ids_ips, data, verify_auth=True)


@router.post(path="/block_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _block_ip(
    request: Request,
    data: BlockIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_block_ip(ids_ips, data, verify_auth=True)


@router.post(path="/manage_ignored_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_ignored_ip(
    request: Request,
    data: IgnoreIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_manage_ignore_ip(ids_ips, data, verify_auth=True)


@router.post("/update_config")
@limiter.limit(f"{REQUEST}/minute")
async def _update(
    request: Request,
    data: Conf
):
    return await svc._do_update(data, verify_auth=True)


@router.get("/geo_location")
async def _geo_location(
    ip: str,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour localisation IP (sans auth)."""
    return await svc._do_geo_location(ids_ips, ip)


@router.post("/change_mode")
@limiter.limit(f"{REQUEST}/minute")
async def _change_mode(
    request: Request,
    data: ChangeModeData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_change_mode(ids_ips, data, verify_auth=True)


@router.get("/get_mode")
async def _get_mode(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_mode(ids_ips)


@router.get("/get_port")
async def _get_port():
    return await svc._do_get_port()


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
    return await svc._do_health_check(ids_ips)


@router.get('/close')
async def _close_api(token: str):
    return await svc._do_close_api(token)


# =============================================================================
# ROUTER SANS AUTH (pour gateway)
# =============================================================================

@router_no_auth.get("/start")
@limiter.limit(f"{REQUEST}/minute")
async def _start_no_auth(request: Request):
    try:
        return await svc._do_start(request)
    except Exception as e:
        return {"started": False, "detail": f"Erreur: {str(e)}"}


@router_no_auth.get("/alerts")
async def get_alerts_no_auth(
    n: int = 10,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_alerts(ids_ips, n)


@router_no_auth.get("/stop")
async def _stop_no_auth(request: Request):
    return await svc._do_stop(request)


@router_no_auth.get("/help")
@limiter.limit(f"{REQUEST}/minute")
async def _help_no_auth(request: Request):
    """Documentation complète de l'API IDS/IPS."""
    return await svc._do_help()


@router_no_auth.post("/blocked")
async def get_blocked_no_auth(
    data: BasicData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_blocked(ids_ips, data, verify_auth=False)


@router_no_auth.post("/config")
@limiter.limit(f"{REQUEST}/minute")
async def get_config_no_auth(
    request: Request,
    data: BasicData
):
    return await svc._do_get_config(data, verify_auth=False)


@router_no_auth.post("/unlock")
@limiter.limit(f"{REQUEST}/minute")
async def _unlock_no_auth(
    request: Request,
    data: UnlockData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_unlock(ids_ips, data, verify_auth=False)


@router_no_auth.post("/manage_whitelist")
@limiter.limit(f"{REQUEST}/minute")
async def _manage_whitelist_no_auth(
    request: Request,
    data: WhitelistData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_manage_whitelist(ids_ips, data, verify_auth=False)


@router_no_auth.post("/block_ip")
@limiter.limit(f"{REQUEST}/minute")
async def _block_ip_no_auth(
    request: Request,
    data: BlockIPData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_block_ip(ids_ips, data, verify_auth=False)


@router_no_auth.post("/update_config")
@limiter.limit(f"{REQUEST}/minute")
async def _update_no_auth(
    request: Request,
    data: Conf
):
    return await svc._do_update(data, verify_auth=False)


@router_no_auth.get("/geo_location")
async def _geo_location_no_auth(
    ip: str,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour localisation IP (sans auth)."""
    return await svc._do_geo_location(ids_ips, ip)


@router_no_auth.post("/change_mode")
@limiter.limit(f"{REQUEST}/minute")
async def _change_mode_no_auth(
    request: Request,
    data: ChangeModeData,
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_change_mode(ids_ips, data, verify_auth=False)


@router_no_auth.get("/get_mode")
async def _get_mode_no_auth(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    return await svc._do_get_mode(ids_ips)


@router_no_auth.get("/get_port")
async def _get_port_no_auth():
    return await svc._do_get_port()


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
    return await svc._do_manage_ignore_ip(ids_ips, data, verify_auth=False)


@router_no_auth.get("/health")
async def _health_check_no_auth(
    ids_ips: Optional["IDS_IPS"] = Depends(get_ids_ips)
):
    """Endpoint pour monitoring (sans auth)."""
    return await svc._do_health_check(ids_ips)


@router_no_auth.get('/close')
async def _close_api_no_auth(token: str):
    return await svc._do_close_api(token)