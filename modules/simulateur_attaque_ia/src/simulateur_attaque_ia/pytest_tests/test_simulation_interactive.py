#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_simulation_interactive.py — mode interactive : démarrage + pilotage via WS.

Nécessite --image. Les tests d'exécution réelle de steps sont tolérants
au résultat (pas de garantie que le port scan trouve quoi que ce soit
sur l'image de test) — ils vérifient surtout que le protocole WS et le
gate `available_actions()` se comportent correctement, pas le contenu
métier de chaque tactic (déjà couvert par les tests unitaires des tactics
elles-mêmes, hors scope ici).
"""

import asyncio

import pytest


pytestmark = pytest.mark.asyncio


async def _start_interactive(client, auth_headers, test_image) -> str:
    r = await client.post(
        "/sim/start",
        headers=auth_headers,
        json={"image": test_image, "mode": "interactive", "use_llm": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["session_id"]
    return data["session_id"]


async def test_start_interactive_and_get_ready(client, auth_headers, test_image, ws_recorder_factory):
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            ready = await rec.recv_until("sim_ready", "error", timeout=60.0)
            # print("Data :", ready)
            assert ready["type"] == "sim_ready", f"attendu sim_ready, reçu {ready}"
            assert ready["session_id"] == session_id
            assert ready["ip"]
            # Au tout début, reconnaissance doit être la seule action dispo
            assert "reconnaissance" in ready["actions_available"]
            assert "execution" not in ready["actions_available"]
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_actions_route_reflects_ws_state(client, auth_headers, test_image, ws_recorder_factory):
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            await rec.recv_until("sim_ready", timeout=60.0)

        r = await client.get(f"/sim/{session_id}/actions", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "reconnaissance" in data["actions_available"]
        assert data["actions_done"] == []
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_actions_route_409_for_auto_mode(client, auth_headers, test_image):
    r = await client.post(
        "/sim/start", headers=auth_headers,
        json={"image": test_image, "mode": "auto", "use_llm": False},
    )
    session_id = r.json()["session_id"]
    try:
        # laisse le temps à l'orchestrateur auto d'être assigné à sim.orchestrator
        await asyncio.sleep(1)
        r = await client.get(f"/sim/{session_id}/actions", headers=auth_headers)
        assert r.status_code == 409  # AutoAttackOrchestrator n'a pas available_actions()
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_execute_unavailable_action_is_rejected(client, auth_headers, test_image, ws_recorder_factory):
    """Tenter 'execution' avant toute reconnaissance doit être refusé proprement (pas de crash)."""
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            await rec.recv_until("sim_ready", timeout=60.0)

            await rec.send({"type": "execute_action", "action": "execution", "params": {}})
            result = await rec.recv_until("step_error", timeout=30.0)

            assert result["type"] == "step_error"
            assert result["step"] == "execution"
            assert result.get("error_type") == "unavailable_action"
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_execute_unknown_action_name(client, auth_headers, test_image, ws_recorder_factory):
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            await rec.recv_until("sim_ready", timeout=60.0)

            await rec.send({"type": "execute_action", "action": "ceci_nexiste_pas", "params": {}})
            result = await rec.recv_until("step_error", timeout=30.0)
            assert result["type"] == "step_error"
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_execute_reconnaissance_updates_state(client, auth_headers, test_image, ws_recorder_factory):
    """
    Vérifie le protocole complet d'un step réussi : step_start puis
    step_success, et que 'reconnaissance' passe dans actions_done.
    Tolérant sur le contenu (ports trouvés ou pas).
    """
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            await rec.recv_until("sim_ready", timeout=60.0)

            await rec.send({
                "type": "execute_action",
                "action": "reconnaissance",
                "params": {"port_range": [22, 80, 443], "timeout_socket": 0.5},
            })

            start_msg = await rec.recv_until("step_start", timeout=10.0)
            assert start_msg["step"] == "reconnaissance"

            done_msg = await rec.recv_until("step_success", "step_error", timeout=60.0)
            assert done_msg["type"] == "step_success", f"reconnaissance a échoué : {done_msg}"
            assert "reconnaissance" in done_msg["actions_done"]
            assert "reconnaissance" not in done_msg["actions_available"]

        r = await client.get(f"/sim/{session_id}/actions", headers=auth_headers)
        assert r.status_code == 200
        assert "reconnaissance" in r.json()["actions_done"]
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_llm_suggest_without_llm_configured(client, auth_headers, test_image, ws_recorder_factory):
    """use_llm=False → llm_suggest doit renvoyer un message clair, pas planter."""
    session_id = await _start_interactive(client, auth_headers, test_image)
    try:
        async with ws_recorder_factory(session_id) as rec:
            await rec.recv_until("sim_ready", timeout=60.0)
            await rec.send({"type": "request_llm_suggest"})
            result = await rec.recv_until("llm_suggest", timeout=30.0)
            assert result["type"] == "llm_suggest"
            assert result["suggestion"]  # non vide, même si "Assistant indisponible"
    finally:
        await client.post(f"/sim/{session_id}/stop", headers=auth_headers)


async def test_finish_via_ws(client, auth_headers, test_image, ws_recorder_factory):
    session_id = await _start_interactive(client, auth_headers, test_image)
    async with ws_recorder_factory(session_id) as rec:
        await rec.recv_until("sim_ready", timeout=60.0)
        await rec.send({"type": "finish"})
        final_msg = await rec.recv_until("sim_finished", timeout=30.0)
        assert final_msg["type"] == "sim_finished"
        assert "report" in final_msg
