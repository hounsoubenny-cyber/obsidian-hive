#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conftest.py — fixtures partagées pour toute la suite.

Options CLI (voir pytest.ini pour les défauts) :
    pytest --base-url http://127.0.0.1:8000/api \
           --username admin --password *** \
           --image mon_image:latest \
           --run-clone --clone-src /home/toi/test_dir

Dépendances :
    pip install pytest pytest-asyncio httpx websockets
"""

import asyncio
import json
from typing import AsyncIterator

import httpx
import pytest
import websockets


# ─────────────────────────────────────────────────────────────────────────────
# Options CLI
# ─────────────────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption("--base-url", default="http://127.0.0.1:8000/api")
    parser.addoption("--username", default="admin")
    parser.addoption("--password", default="admin")
    parser.addoption("--image", default=None, help="Image Docker existante pour lancer des sims")
    parser.addoption("--run-clone", action="store_true", help="Active les tests de clonage (lourds)")
    parser.addoption("--clone-src", default=None, help="Répertoire source pour le clonage")


@pytest.fixture(scope="session")
def base_url(request) -> str:
    return request.config.getoption("--base-url")


@pytest.fixture(scope="session")
def ws_base_url(base_url: str) -> str:
    return base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"


@pytest.fixture(scope="session")
def credentials(request) -> dict:
    return {
        "username": request.config.getoption("--username"),
        "password": request.config.getoption("--password"),
    }


@pytest.fixture(scope="session")
def test_image(request) -> str:
    image = request.config.getoption("--image")
    if not image:
        pytest.skip("--image non fourni : impossible de lancer une simulation sans image Docker existante")
    return image


@pytest.fixture(scope="session")
def run_clone_enabled(request) -> bool:
    return request.config.getoption("--run-clone")


@pytest.fixture(scope="session")
def clone_src(request):
    return request.config.getoption("--clone-src")


# ─────────────────────────────────────────────────────────────────────────────
# Client HTTP + auth
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
async def client(base_url: str) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="session")
async def token(client: httpx.AsyncClient, credentials: dict) -> str:
    r = await client.post("/auth/login", json=credentials)
    r.raise_for_status()
    data = r.json()
    assert data.get("success") is True, f"login a échoué : {data}"
    assert data.get("token"), "pas de token renvoyé par /auth/login"
    return data["token"]


@pytest.fixture(scope="session")
def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────────────────────────────────────
# Helper WS réutilisable dans les tests
# ─────────────────────────────────────────────────────────────────────────────

class WSRecorder:
    """
    Se connecte à un canal WS de simulation et garde tous les messages
    reçus, pour que les tests puissent faire des assertions dessus.
    """

    def __init__(self, url: str):
        self.url = url
        self.messages: list[dict] = []
        self._ws = None

    async def __aenter__(self) -> "WSRecorder":
        self._ws = await websockets.connect(self.url)
        return self

    async def __aexit__(self, *exc):
        if self._ws is not None:
            await self._ws.close()

    async def send(self, message: dict) -> None:
        await self._ws.send(json.dumps(message))

    async def recv_until(self, *stop_types: str, timeout: float = 120.0) -> dict:
        """Lit les messages jusqu'à en recevoir un dont le type est dans stop_types."""
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            assert remaining > 0, f"timeout en attendant un message parmi {stop_types}"
            raw = await asyncio.wait_for(self._ws.recv(), timeout=remaining)
            msg = json.loads(raw)
            self.messages.append(msg)
            if msg.get("type") in stop_types:
                return msg

    async def recv_one(self, timeout: float = 30.0) -> dict:
        raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        msg = json.loads(raw)
        self.messages.append(msg)
        return msg


@pytest.fixture
def ws_recorder_factory(ws_base_url: str, token: str):
    """Fixture-factory : ws_recorder_factory(session_id) -> WSRecorder prêt à connecter."""
    def _make(session_id: str) -> WSRecorder:
        return WSRecorder(f"{ws_base_url}/{session_id}?token={token}")
    return _make
