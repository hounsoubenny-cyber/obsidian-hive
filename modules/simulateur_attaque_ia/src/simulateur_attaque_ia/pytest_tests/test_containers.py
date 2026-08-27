#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug  4 04:39:45 2026

@author: hounsousamuel
"""


"""test_containers.py — /containers/list, /create, /{name}/stop, /{name}/exec, /cache."""

import uuid

import pytest


pytestmark = pytest.mark.asyncio


@pytest.fixture
def container_name() -> str:
    return f"pytest_ct_{uuid.uuid4().hex[:8]}"


async def test_list_containers(client, auth_headers):
    r = await client.get("/containers/list", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "containers" in data
    assert isinstance(data["containers"], list)
    assert data["total"] == len(data["containers"])


async def test_create_unknown_image_fails_cleanly(client, auth_headers, container_name):
    r = await client.post(
        "/containers/create",
        headers=auth_headers,
        json={"image": "image_qui_nexiste_pas:latest", "name": container_name},
    )
    assert r.status_code == 200  # pas de 500, une réponse structurée
    data = r.json()
    assert data["success"] is False
    assert "introuvable" in data["message"].lower()


async def test_create_unknown_network_fails_cleanly(client, auth_headers, test_image, container_name):
    r = await client.post(
        "/containers/create",
        headers=auth_headers,
        json={"image": test_image, "name": container_name, "network": "reseau_qui_nexiste_pas"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is False
    assert "introuvable" in data["message"].lower()


async def test_full_container_lifecycle(client, auth_headers, test_image, container_name):
    """create → list (le retrouve) → exec → stop, cycle complet."""
    r = await client.post(
        "/containers/create",
        headers=auth_headers,
        json={"image": test_image, "name": container_name, "network": "bridge"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True, f"création échouée : {data['message']}"
    assert data["container"]["name"] == container_name

    try:
        r = await client.get("/containers/list", headers=auth_headers)
        assert r.status_code == 200
        names = [c["name"] for c in r.json()["containers"]]
        assert container_name in names

        r = await client.post(
            f"/containers/{container_name}/exec",
            headers=auth_headers,
            json={"command": "echo hello_pytest"},
        )
        assert r.status_code == 200
        exec_data = r.json()
        assert exec_data["success"] is True
        assert "hello_pytest" in (exec_data["stdout"] or "")

    finally:
        r = await client.post(f"/containers/{container_name}/stop", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["success"] is True


async def test_stop_unknown_container(client, auth_headers):
    r = await client.post("/containers/nexiste_pas_du_tout/stop", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_exec_on_unknown_container(client, auth_headers):
    r = await client.post(
        "/containers/nexiste_pas_du_tout/exec",
        headers=auth_headers,
        json={"command": "whoami"},
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_list_cached_containers(client, auth_headers):
    r = await client.get("/containers/cache", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "containers" in data
    assert data["total"] == len(data["containers"])