#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_auth.py — POST /auth/login."""

import pytest


pytestmark = pytest.mark.asyncio


async def test_login_success(client, credentials):
    r = await client.post("/auth/login", json=credentials)
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["token"]


async def test_login_wrong_password(client, credentials):
    bad = {**credentials, "password": credentials["password"] + "_wrong"}
    r = await client.post("/auth/login", json=bad)
    assert r.status_code == 401


async def test_login_missing_fields(client):
    r = await client.post("/auth/login", json={"username": "admin"})
    assert r.status_code == 422  # erreur de validation Pydantic


async def test_protected_route_without_token(client):
    r = await client.get("/images/list")
    assert r.status_code == 401


async def test_protected_route_with_bad_token(client):
    r = await client.get("/images/list", headers={"Authorization": "Bearer n_importe_quoi"})
    assert r.status_code == 401
