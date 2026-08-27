#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_clone.py — POST /clone/start, GET /clone/{id}/status, POST /clone/{id}/stop.

Ces tests sont lourds (clonage disque réel) donc désactivés par défaut.
Lancer avec : pytest --run-clone --clone-src /chemin/a/cloner
"""

import asyncio
import time

import pytest


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _skip_unless_enabled(run_clone_enabled):
    if not run_clone_enabled:
        pytest.skip("clonage désactivé (passe --run-clone pour l'activer, c'est lourd)")


async def test_clone_full_flow(client, auth_headers, clone_src):
    payload = {"src": clone_src} if clone_src else {}
    r = await client.post("/clone/start", headers=auth_headers, json=payload)
    assert r.status_code == 200
    clone_id = r.json()["clone_id"]

    deadline = time.monotonic() + 300
    status = None
    while time.monotonic() < deadline:
        r = await client.get(f"/clone/{clone_id}/status", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        status = data["status"]
        if status in ("completed", "failed", "stopped"):
            break
        await asyncio.sleep(3)

    assert status == "completed", f"clonage terminé avec status={status}"
    assert data.get("image"), "pas d'image renvoyée après un clonage réussi"
    assert isinstance(data.get("services"), dict), "pas de services renvoyés après un clonage réussi"


async def test_clone_stop_mid_flight(client, auth_headers, clone_src):
    payload = {"src": clone_src} if clone_src else {}
    r = await client.post("/clone/start", headers=auth_headers, json=payload)
    assert r.status_code == 200
    clone_id = r.json()["clone_id"]

    await asyncio.sleep(0.5)  # laisse la task démarrer avant de couper
    r = await client.post(f"/clone/{clone_id}/stop", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"

    # Le statut doit rester cohérent après coup
    r = await client.get(f"/clone/{clone_id}/status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"


async def test_clone_status_unknown_id(client, auth_headers):
    r = await client.get("/clone/id-qui-nexiste-pas/status", headers=auth_headers)
    assert r.status_code == 200  # clone_status renvoie 200 + status="not_found", pas une 404
    data = r.json()
    assert data["status"] == "not_found"


async def test_clone_stop_unknown_id(client, auth_headers):
    r = await client.post("/clone/id-qui-nexiste-pas/stop", headers=auth_headers)
    assert r.status_code == 404  # ici stop_clone lève bien une 404


async def test_clone_stop_already_finished(client, auth_headers, clone_src):
    """Un 2e stop sur un clone déjà arrêté doit renvoyer 409 (pas 'running')."""
    payload = {"src": clone_src} if clone_src else {}
    r = await client.post("/clone/start", headers=auth_headers, json=payload)
    assert r.status_code == 200
    clone_id = r.json()["clone_id"]

    await asyncio.sleep(0.5)
    r = await client.post(f"/clone/{clone_id}/stop", headers=auth_headers)
    assert r.status_code == 200

    r = await client.post(f"/clone/{clone_id}/stop", headers=auth_headers)
    assert r.status_code == 409
