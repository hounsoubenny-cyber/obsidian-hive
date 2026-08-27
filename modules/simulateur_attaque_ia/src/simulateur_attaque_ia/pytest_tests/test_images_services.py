#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_images_services.py — /images/list, /services/capture, /services/validate."""

import pytest


pytestmark = pytest.mark.asyncio


async def test_list_images(client, auth_headers):
    r = await client.get("/images/list", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "images" in data
    assert isinstance(data["images"], list)


async def test_capture_services(client, auth_headers):
    r = await client.get("/services/capture", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "services" in data
    assert isinstance(data["services"], dict)


async def test_capture_then_validate_is_valid(client, auth_headers):
    """Les services qu'on vient de capturer en live doivent passer le validateur qu'on a écrit ensemble."""
    r = await client.get("/services/capture", headers=auth_headers)
    assert r.status_code == 200
    services = r.json()["services"]

    r = await client.post("/services/validate", headers=auth_headers, json={"services": services})
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True, f"erreurs inattendues : {data.get('errors')}"


async def test_validate_rejects_malformed_dict(client, auth_headers):
    bad_services = {
        "not_a_pid": {"cmdline": "devrait etre une liste"},
        "1251": {"name": "x", "cmdline": ["x"], "ports": [999999]},  # port hors plage
    }
    r = await client.post("/services/validate", headers=auth_headers, json={"services": bad_services})
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is False
    assert len(data["errors"]) >= 2


async def test_validate_empty_dict_is_valid_with_warning(client, auth_headers):
    r = await client.post("/services/validate", headers=auth_headers, json={"services": {}})
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert any("vide" in w.lower() for w in data["warnings"])
