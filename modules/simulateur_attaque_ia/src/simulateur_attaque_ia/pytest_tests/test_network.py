#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug  4 04:39:39 2026

@author: hounsousamuel
"""

"""
test_network.py — /network/list, /create, /{name}/containers, /{name}/remove,
/{name}/connect, /{name}/disconnect, /move.

Pas de test sur /network/remove_all ici volontairement — il filtre par label
'simatk' mais purge TOUS les réseaux qui matchent (y compris d'éventuels
réseaux d'autres sims en cours ailleurs sur la machine). Trop destructif
pour un test automatique ; à tester à la main si besoin.
"""

import uuid

import pytest


pytestmark = pytest.mark.asyncio


@pytest.fixture
def network_name() -> str:
    return f"pytest_net_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def container_name() -> str:
    return f"pytest_net_ct_{uuid.uuid4().hex[:8]}"


async def test_list_networks(client, auth_headers):
    r = await client.get("/network/list", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "networks" in data
    assert data["total"] == len(data["networks"])


async def test_create_and_remove_network(client, auth_headers, network_name):
    r = await client.post(
        "/network/create", headers=auth_headers,
        json={"name": network_name, "driver": "bridge", "internal": True},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True, data.get("message")
    assert data["network"]["name"] == network_name

    r = await client.get("/network/list?only_simatk=true", headers=auth_headers)
    assert r.status_code == 200
    names = [n["name"] for n in r.json()["networks"]]
    assert network_name in names

    r = await client.post(f"/network/{network_name}/remove", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["success"] is True


async def test_create_duplicate_network_fails_cleanly(client, auth_headers, network_name):
    r = await client.post("/network/create", headers=auth_headers, json={"name": network_name})
    assert r.status_code == 200
    assert r.json()["success"] is True

    try:
        r = await client.post("/network/create", headers=auth_headers, json={"name": network_name})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is False
        assert "existe déjà" in data["message"].lower() or "existe" in data["message"].lower()
    finally:
        await client.post(f"/network/{network_name}/remove", headers=auth_headers)


async def test_containers_of_unknown_network(client, auth_headers):
    r = await client.get("/network/reseau_qui_nexiste_pas/containers", headers=auth_headers)
    assert r.status_code == 200  # pas une 404 ici, comme pour clone_status
    data = r.json()
    assert data["total"] == 0
    assert "introuvable" in data["message"].lower()


async def test_remove_unknown_network(client, auth_headers):
    r = await client.post("/network/reseau_qui_nexiste_pas/remove", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_network_containers_and_connect_disconnect(
    client, auth_headers, test_image, network_name, container_name
):
    """Cycle complet : crée un réseau + un container, connecte, vérifie l'IP, déconnecte."""
    r = await client.post("/network/create", headers=auth_headers, json={"name": network_name})
    assert r.status_code == 200
    assert r.json()["success"] is True

    r = await client.post(
        "/containers/create", headers=auth_headers,
        json={"image": test_image, "name": container_name, "network": "bridge"},
    )
    assert r.status_code == 200
    assert r.json()["success"] is True

    try:
        r = await client.post(
            f"/network/{network_name}/connect", headers=auth_headers,
            json={"container_name": container_name},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True, data.get("message")
        assert data["ip"]

        r = await client.get(f"/network/{network_name}/containers", headers=auth_headers)
        assert r.status_code == 200
        names = [c["name"] for c in r.json()["containers"]]
        assert container_name in names

        # Reconnecter au même réseau doit échouer proprement (déjà connecté)
        r = await client.post(
            f"/network/{network_name}/connect", headers=auth_headers,
            json={"container_name": container_name},
        )
        assert r.status_code == 200
        assert r.json()["success"] is False

        r = await client.post(
            f"/network/{network_name}/disconnect", headers=auth_headers,
            json={"container_name": container_name},
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    finally:
        await client.post(f"/containers/{container_name}/stop", headers=auth_headers)
        await client.post(f"/network/{network_name}/remove", headers=auth_headers)


async def test_move_container_between_networks(
    client, auth_headers, test_image, container_name
):
    net_a = f"pytest_move_a_{uuid.uuid4().hex[:8]}"
    net_b = f"pytest_move_b_{uuid.uuid4().hex[:8]}"

    for name in (net_a, net_b):
        r = await client.post("/network/create", headers=auth_headers, json={"name": name})
        assert r.status_code == 200 and r.json()["success"] is True

    r = await client.post(
        "/containers/create", headers=auth_headers,
        json={"image": test_image, "name": container_name, "network": net_a},
    )
    assert r.status_code == 200 and r.json()["success"] is True

    try:
        r = await client.post(
            "/network/move", headers=auth_headers,
            json={
                "container_name": container_name,
                "source_network": net_a,
                "destination_network": net_b,
                "force": True,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True, data.get("message")
        assert net_b in data["networks"]
        assert net_a not in data["networks"]

    finally:
        await client.post(f"/containers/{container_name}/stop", headers=auth_headers)
        for name in (net_a, net_b):
            await client.post(f"/network/{name}/remove", headers=auth_headers)


async def test_move_unknown_container(client, auth_headers, network_name):
    r = await client.post("/network/create", headers=auth_headers, json={"name": network_name})
    assert r.status_code == 200

    try:
        r = await client.post(
            "/network/move", headers=auth_headers,
            json={
                "container_name": "nexiste_pas_du_tout",
                "source_network": network_name,
                "destination_network": "bridge",
            },
        )
        assert r.status_code == 200
        assert r.json()["success"] is False
    finally:
        await client.post(f"/network/{network_name}/remove", headers=auth_headers)