#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 07:03:26 2026

@author: hounsousamuel

État global partagé lié au process serveur (uvicorn) : `server`, `TOKEN`,
et les fonctions qui en dépendent (`close_api`, `start`, `stop`).

Ce module est volontairement une "feuille" : il n'importe RIEN depuis
schemas.py / orchestrator.py / services.py / routes.py / api.py.
Comme ça, tout le monde peut l'importer sans jamais créer de boucle
d'import (api -> routes -> ids_service -> orchestrator -> server_state,
et api -> server_state directement, api -> orchestrator directement :
tout descend, rien ne remonte).
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import asyncio
import atexit
import threading
import aiohttp
import uvicorn
from modules_utils.api_dependencies import get_loop
    
from ids_ips_ia.ids_ips_utils.logger import get_logger

logger = get_logger()

server = None
TOKEN = ""


def set_token(token: str) -> None:
    global TOKEN
    TOKEN = token

def get_token() -> str:
    return TOKEN

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


def start(app, host, port):
    """Démarre uvicorn dans un thread dédié. Appelé depuis api.py (__main__)."""
    global server
    config = uvicorn.Config(app, host=host, port=port, loop=get_loop(), workers=10, use_colors=True)
    server = uvicorn.Server(config=config)
    th = threading.Thread(target=server.run, daemon=True, name="API Thread")
    return th, server


def stop(th, timeout=5):
    logger.print('Arrêt des threads...')
    th.join(timeout)
    logger.print('Threads arrêtés')
