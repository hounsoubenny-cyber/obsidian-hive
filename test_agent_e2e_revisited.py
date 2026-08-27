#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 14 20:17:11 2026

@author: hounsousamuel
"""

"""
test_agent_e2e.py — harness interactif pour tester le cœur de l'agent
ServerAsset de bout en bout, sans dashboard.

Prérequis : le serveur central tourne déjà dans un autre terminal.
"""

import os
import sys
import json
import uuid
import httpx
import asyncio
import tempfile
import subprocess
import websockets

from obsidian_hive.core.assets.server_asset.core_agent.config import AgentConfig
from obsidian_hive.api.ap_config import (
    USER_ENV_KEY, PASSWD_ENV_KEY, SECRET_KEY_ENV_KEY, EXP, NOT_BEFORE,
)
from modules_utils.api_dependencies import AuthManager

CENTRAL_HTTP_URL = "http://127.0.0.1:8000"
CENTRAL_WS_BASE = "ws://127.0.0.1:8000"


def get_admin_token_and_username() -> tuple[str, str]:
    """Même construction que _get_auth_manager() dans main.py — génère un
    JWT valide sans passer par une vraie route de login."""
    auth_manager = AuthManager(
        exp=EXP, not_before=NOT_BEFORE,
        user_env_key=USER_ENV_KEY, passwd_env_key=PASSWD_ENV_KEY,
        secret_key_env_key=SECRET_KEY_ENV_KEY,
    )
    username = os.environ[USER_ENV_KEY]
    token = auth_manager.create_token(dict(username=username))
    return token, username


async def create_test_asset(client: httpx.AsyncClient) -> dict:
    resp = await client.post("/api/core/asset/create/server_asset", json={
        "name": "test-agent-e2e",
    })
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") == "error" or data.get("error"):
        raise RuntimeError(f"Création de l'asset échouée: {data}")
    return data


async def allow_tool(client: httpx.AsyncClient, asset_id: str, tool_name: str):
    resp = await client.post("/api/core/assets/server_asset/tools/allow", json={
        "asset_id": asset_id, "tools": [tool_name],
    })
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") == "error":
        raise RuntimeError(f"Autorisation du tool échouée: {data}")


def write_agent_config(asset_id: str, install_token: str, path: str):
    config = AgentConfig(
        asset_id=asset_id,
        central_http_url=CENTRAL_HTTP_URL,
        central_ws_url=f"{CENTRAL_WS_BASE}/api/core_ws/ws/server_agent",
        register_path="/api/core/assets/server_asset/register",
        download_tool_engine_path="/api/download/agent/tool_engine",
        pending_token=install_token,
    )
    config._path = path
    config.persist()


def start_agent_process(config_path: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["OBSIDIAN_AGENT_CONFIG_PATH"] = config_path
    return subprocess.Popen(
        [sys.executable, "-m", "obsidian_hive.core.assets.server_asset.core_agent.main"],
        env=env,
    )


async def wait_connected(client: httpx.AsyncClient, asset_id: str, timeout: float = 15.0) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        resp = await client.post("/api/core/assets/get_asset", json={"identifier": asset_id})
        resp.raise_for_status()
        assets = resp.json().get("assets") or []
        if assets and str(assets[0].get("agent_status", "")).lower() == "connected":
            return True
        await asyncio.sleep(0.3)
    return False


async def admin_listener(ws, pending: dict[str, asyncio.Future]):
    async for raw in ws:
        data = json.loads(raw)
        if data.get("type") == "tool_result":
            call_id = data.get("call_id")
            fut = pending.pop(call_id, None)
            if fut and not fut.done():
                fut.set_result(data)
            else:
                print("\nMessage reçu (non attendu):", json.dumps(data, indent=2, ensure_ascii=False))


async def interactive_loop(ws, asset_id: str, username: str):
    pending: dict[str, asyncio.Future] = {}
    listener_task = asyncio.create_task(admin_listener(ws, pending))
    print(f"\nAgent connecté ({asset_id}). Tape un nom de tool (vide pour quitter).\n")
    loop = asyncio.get_event_loop()
    try:
        while True:
            tool_name = (await loop.run_in_executor(None, input, "tool_name > ")).strip()
            if not tool_name:
                break
            raw_args = (await loop.run_in_executor(None, input, "tool_args (JSON, vide = {}) > ")).strip()
            try:
                tool_args = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError as e:
                print(f"JSON invalide: {e}")
                continue

            call_id = str(uuid.uuid4())
            fut = loop.create_future()
            pending[call_id] = fut

            await ws.send(json.dumps({
                "type": "server_tool_call",
                "asset_id": asset_id,
                "tool_call": {
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "caller": username,
                },
            }))

            try:
                result = await asyncio.wait_for(fut, timeout=30)
                print("Résultat:", json.dumps(result, indent=2, ensure_ascii=False))
            except asyncio.TimeoutError:
                print("Timeout, pas de réponse.")
                pending.pop(call_id, None)
    finally:
        listener_task.cancel()
        try:
            await listener_task
        except asyncio.CancelledError:
            pass


async def main():
    token, username = get_admin_token_and_username()
    async with httpx.AsyncClient(base_url=CENTRAL_HTTP_URL, timeout=30, headers={"Authorization": f"Bearer {token}"}) as client:
        # print("Création de l'asset de test...")
        # created = await create_test_asset(client)
        # asset_id = created["asset_id"]
        # install_token = created["asset_data"]["install_token"]
        # print(f"Asset créé: {asset_id}, token: {install_token}")

        # print("Autorisation du tool get_system_info...")
        # await allow_tool(client, asset_id, "get_system_info")
        # await allow_tool(client, asset_id, "list_logged_in_users")
        # await allow_tool(client, asset_id, "last_logins")
        # await allow_tool(client, asset_id, "disk_usage")
        asset_id = "sh_as-7936a940-73c6-402a-bf3e-d269377af082"
        install_token = "obds_tok-b6308b9d-a587-4f35-8be8-e5e2f3f2a2cf"
        # while True:
        #     await asyncio.sleep(10)
        with tempfile.TemporaryDirectory() as tmp:
            # config_path = os.path.join(tmp, "config.toml")
            # write_agent_config(asset_id, install_token, config_path)

            # print("Démarrage de l'agent...")
            # proc = start_agent_process(config_path)
            try:
                if not await wait_connected(client, asset_id):
                    print("L'agent ne s'est jamais connecté — regarde les logs ci-dessus.")
                    return

                admin_ws_url = f"{CENTRAL_WS_BASE}/api/core_ws/ws?token={token}"
                async with websockets.connect(admin_ws_url) as ws:
                    await interactive_loop(ws, asset_id, username)
            finally:
                print("Arrêt de l'agent...")
                # proc.terminate()
                # try:
                #     proc.wait(timeout=5)
                # except subprocess.TimeoutExpired:
                #     proc.kill()


if __name__ == "__main__":
    asyncio.run(main())