#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_simulation_auto.py — /sim/start, /stop, /status, /list, /report, /history (mode auto).

Nécessite --image (une image Docker déjà existante) pour tourner.
"""

import asyncio

import pytest


pytestmark = pytest.mark.asyncio


async def test_start_auto_sim(client, auth_headers, test_image):
    r = await client.post(
        "/sim/start",
        headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["session_id"]
    assert data["status"] == "starting"

    # cleanup : on arrête tout de suite, ce test ne teste que le démarrage
    await client.post(f"/sim/{data['session_id']}/stop", headers=auth_headers)


async def test_start_unknown_image_fails_immediately(client, auth_headers):
    r = await client.post(
        "/sim/start",
        headers=auth_headers,
        json={"image": "image_qui_nexiste_absolument_pas:latest", "mode": "auto"},
    )
    assert r.status_code == 400
    assert "introuvable" in r.json()["detail"].lower()


async def test_sim_status_unknown_session(client, auth_headers):
    r = await client.get("/sim/session_qui_nexiste_pas/status", headers=auth_headers)
    assert r.status_code == 404


async def test_sim_stop_unknown_session(client, auth_headers):
    r = await client.post("/sim/session_qui_nexiste_pas/stop", headers=auth_headers)
    assert r.status_code == 404


async def test_report_available_only_after_terminal_state(client, auth_headers, test_image):
    """
    Invariant à vérifier, peu importe la vitesse d'exécution de la sim :
    tant que le statut n'est pas terminal (failed/completed/stopped),
    /report doit renvoyer 404. Dès qu'il devient terminal, /report doit
    renvoyer 200. On poll les deux ensemble pour ne jamais rater la
    fenêtre, que la sim prenne 200ms ou 2 minutes.
    """
    r = await client.post(
        "/sim/start", headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    session_id = r.json()["session_id"]

    terminal_statuses = {"failed", "completed", "stopped"}
    reached_terminal = False

    for _ in range(120):  # jusqu'à 60s (0.5s par itération)
        r_status = await client.get(f"/sim/{session_id}/status", headers=auth_headers)
        status = r_status.json()["status"]

        r_report = await client.get(f"/sim/{session_id}/report", headers=auth_headers)

        if status not in terminal_statuses:
            assert r_report.status_code == 404, (
                f"/report a renvoyé {r_report.status_code} alors que status='{status}' (pas terminal)"
            )
        else:
            assert r_report.status_code == 200, (
                f"/report a renvoyé {r_report.status_code} alors que status='{status}' (terminal)"
            )
            reached_terminal = True
            break

        await asyncio.sleep(0.5)

    assert reached_terminal, "la simulation n'a jamais atteint un état terminal en 60s"


async def test_list_sims_contains_started_session(client, auth_headers, test_image):
    r = await client.post(
        "/sim/start", headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    session_id = r.json()["session_id"]

    r = await client.get("/sim/list", headers=auth_headers)
    assert r.status_code == 200
    sims = r.json()["sims"]
    assert any(s["session_id"] == session_id for s in sims)

    await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_stop_then_appears_in_history(client, auth_headers, test_image):
    r = await client.post(
        "/sim/start", headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    session_id = r.json()["session_id"]

    await asyncio.sleep(1)
    r = await client.post(f"/sim/{session_id}/stop", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"

    # Laisse le temps à _on_task_done / _save_history de s'exécuter
    await asyncio.sleep(1)
    r = await client.get(f"/sim/history/{session_id}", headers=auth_headers)
    assert r.status_code == 200
    entry = r.json()
    assert entry["status"] == "stopped"


async def test_full_run_via_websocket(client, auth_headers, test_image, ws_recorder_factory):
    """
    Lance une sim auto, suit son cycle de vie complet via WS jusqu'à
    sim_finished/error, puis vérifie que /report est bien rempli après coup.
    """
    r = await client.post(
        "/sim/start", headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    assert r.status_code == 200
    session_id = r.json()["session_id"]

    async with ws_recorder_factory(session_id) as rec:
        final_msg = await rec.recv_until("sim_finished", "error", timeout=300.0)

    assert final_msg["type"] in ("sim_finished", "error")

    if final_msg["type"] == "sim_finished":
        r = await client.get(f"/sim/{session_id}/report", headers=auth_headers)
        assert r.status_code == 200
        report = r.json()
        assert "logs" in report
        assert isinstance(report["logs"], list)