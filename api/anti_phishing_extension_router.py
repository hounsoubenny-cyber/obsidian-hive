#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 27 17:56:01 2026

@author: hounsousamuel
"""


import asyncio
from pydantic import BaseModel
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from anti_phishing_ia.main_phish import get_ap_instance, AnalyzeUrlData

bearer_scheme = HTTPBearer(
    scheme_name="ExtensionToken",
    auto_error=True,
    description="Token d'extension navigateur (format token_id.secret)"
)
router_ext = APIRouter()

def get_extension_token_manager(request: Request):
    return request.app.state.extension_token_manager

class AnalyzeUrlBatchData(BaseModel):
    urls: list[str]
    check_blacklists: list[bool] | None = None
    check_right_clicks: list[bool] | None = None
    explains: list[bool] | None = None


def _build_analyse_error(e: Exception):
    return {
        'error': str(e),
        'ia_pred': {'predict': {'0': 'error'}},
        'passive_pred': {'risk_level': '❌ ERREUR'}
    }


async def verify_extension_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
) -> str:
    """Vérifie le Bearer token d'une extension navigateur.

    Args:
        credentials (HTTPAuthorizationCredentials): Les credentials extraits du header Authorization.

    Returns:
        str: Le token_id validé (utile pour logger/tracer quel device a fait l'appel).

    Raises:
        HTTPException: 401 si le format est invalide, le token introuvable, ou révoqué.
    """
    raw = credentials.credentials
    if "." not in raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Format de token invalide")

    token_id, secret = raw.split(".", 1)
    manager = get_extension_token_manager()
    token_row = await manager.get_by_token_id(token_id)

    if token_row is None or not token_row.verify(secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide ou révoqué")

    await manager.touch_last_used(token_id)
    return token_id


@router_ext.post("/check_url")
async def check_url(data: AnalyzeUrlData, token_id: str = Depends(verify_extension_token)):
    """Analyse une URL unique (typiquement la page chargée)."""
    ap = get_ap_instance()
    try:
        predict = await ap.predict_url_async(
            url=data.url,
            explain=data.explain,
            features_func=None,
            check_blacklist=data.check_blacklist,
            check_right_click=data.check_right_click,
        )
        return predict
    except Exception as e:
        return _build_analyse_error(e)


def _update_list_with(data: list, value, number: int):
    if number > 0:
        for _ in range(number):
            data.append(value) 
    return data

@router_ext.post("/check_urls_batch")
async def check_urls_batch(data: AnalyzeUrlBatchData, token_id: str = Depends(verify_extension_token)):
    """Analyse plusieurs URLs en un seul appel (liens visibles sur la page)."""
    urls = list(data.urls)
    if not urls:
        return {}
    
    ap = get_ap_instance()
    url_length = len(data.urls)
    
    check_blacklists = list(data.check_blacklists or [])
    check_blacklists = _update_list_with(
        check_blacklists, False, url_length - len(check_blacklists)
    )
    
    check_right_clicks = list(data.check_right_clicks or [])
    check_right_clicks = _update_list_with(
        check_blacklists, False, url_length - len(check_right_clicks)
    )
    
    explains = list(data.explains or [])
    explains = _update_list_with(
        explains, False, url_length - len(explains)
    )
    
    tasks = [
        asyncio.create_task(
                ap.predict_url_async(
                url=data.url,
                explain=data.explain,
                features_func=None,
                check_blacklist=data.check_blacklist,
                check_right_click=data.check_right_click,
            )
        )
        for (url, explain, check_blacklist, check_right_click) in zip(
                urls, explains, check_blacklists, check_right_clicks
            )
    ]
    results = await asyncio.gather(tasks, return_exceptions=True)
    to_return = {}
    for url, r in zip(urls, results):
        to_return[url] = r if not isinstance(r, Exception) else _build_analyse_error(r)
    return to_return