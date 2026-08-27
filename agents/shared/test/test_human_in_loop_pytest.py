#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 17 07:39:27 2026

@author: hounsousamuel
"""

"""
test_human_in_loop.py

Suite pytest pour le wrapper human-in-the-loop. Simule un agent (type
CoreTools/Coralie) qui appelle des tools protégés par confirmation humaine.

Lancement :
    pytest test_human_in_loop.py -v

Nécessite : pytest, pytest-asyncio (asyncio_mode = auto dans pytest.ini,
donc pas besoin de @pytest.mark.asyncio sur chaque test).
"""

import asyncio
from functools import partial

import pytest

from obsidian_hive.agents.shared.human_in_loop import (
    Decision,
    ConfirmationDenied,
    ConfirmationTimeout,
    confirm,
    WSConfirmer,
)


# --------------------------------------------------------------------------- #
# Confirmer scriptable, pilotable depuis les tests
# --------------------------------------------------------------------------- #

class FakeConfirmer:
    """Confirmer de test : répond immédiatement selon un script fourni,
    ou ne répond jamais (pour simuler un timeout).
    """

    def __init__(self, approve: bool = True, reason: str | None = None, never_respond: bool = False):
        self.approve = approve
        self.reason = reason
        self.never_respond = never_respond
        self.calls: list[dict] = []

    async def __call__(self, *, req_id, tool_name, risk, args):
        self.calls.append({"req_id": req_id, "tool": tool_name, "risk": risk, "args": args})
        if self.never_respond:
            await asyncio.sleep(3600)
        return Decision(approved=self.approve, reason=self.reason)


# --------------------------------------------------------------------------- #
# Agent factice, construit dynamiquement pour isoler chaque test
# (le décorateur @confirm_ est figé à la définition de classe -> un
# confirmer par test, pas un confirmer global partagé)
# --------------------------------------------------------------------------- #

def build_agent(confirmer, timeout: float = 1.0):
    confirm_ = partial(confirm, confirmer)

    class FakeAgentTools:
        def __init__(self):
            self.firewall_rules = {"fw-1", "fw-2"}
            self.scans_done = []

        @confirm_(risk="critical", timeout=timeout)
        async def delete_firewall_rule(self, rule_id: str):
            self.firewall_rules.discard(rule_id)
            return f"règle {rule_id} supprimée"

        @confirm_(risk="low", timeout=timeout)
        async def scan_network(self, subnet: str):
            self.scans_done.append(subnet)
            return f"scan {subnet} terminé"

    return FakeAgentTools()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def sent_messages():
    """Liste qui capture les messages envoyés par un WSConfirmer de test."""
    return []


@pytest.fixture
def ws_confirmer(sent_messages):
    async def fake_ws_send(msg: dict):
        sent_messages.append(msg)
    return WSConfirmer(ws_send=fake_ws_send)


# --------------------------------------------------------------------------- #
# Cas simples : approved / denied
# --------------------------------------------------------------------------- #

async def test_approved_executes_tool_and_mutates_state():
    confirmer = FakeConfirmer(approve=True)
    agent = build_agent(confirmer)

    result = await agent.delete_firewall_rule(rule_id="fw-1")

    assert result == "règle fw-1 supprimée"
    assert "fw-1" not in agent.firewall_rules
    assert len(confirmer.calls) == 1
    assert confirmer.calls[0]["risk"] == "critical"
    assert confirmer.calls[0]["tool"] == "delete_firewall_rule"


async def test_denied_raises_and_does_not_mutate_state():
    confirmer = FakeConfirmer(approve=False, reason="prod chargée")
    agent = build_agent(confirmer)

    with pytest.raises(ConfirmationDenied) as exc_info:
        await agent.delete_firewall_rule(rule_id="fw-2")

    assert exc_info.value.reason == "prod chargée"
    assert exc_info.value.tool_name == "delete_firewall_rule"
    assert "fw-2" in agent.firewall_rules  # le tool n'a pas tourné


@pytest.mark.parametrize("subnet", ["10.0.0.0/24", "192.168.1.0/24"])
async def test_approved_low_risk_scan(subnet):
    """Vérifie que le paramétrage (parametrize) marche sur plusieurs inputs."""
    confirmer = FakeConfirmer(approve=True)
    agent = build_agent(confirmer)

    result = await agent.scan_network(subnet=subnet)

    assert result == f"scan {subnet} terminé"
    assert agent.scans_done == [subnet]


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #

async def test_timeout_raises_and_does_not_mutate_state():
    confirmer = FakeConfirmer(never_respond=True)
    agent = build_agent(confirmer, timeout=0.2)

    with pytest.raises(ConfirmationTimeout) as exc_info:
        await agent.scan_network(subnet="10.0.0.0/24")

    assert exc_info.value.tool_name == "scan_network"
    assert agent.scans_done == []


# --------------------------------------------------------------------------- #
# WSConfirmer : round-trip complet avec résolution asynchrone
# --------------------------------------------------------------------------- #

async def test_ws_confirmer_round_trip(ws_confirmer, sent_messages):
    agent = build_agent(ws_confirmer)

    async def simulate_client_response():
        while not sent_messages:
            await asyncio.sleep(0.01)
        req_id = sent_messages[0]["id"]
        await asyncio.sleep(0.05)
        ws_confirmer.resolve(req_id, approved=True)

    agent_call = asyncio.create_task(agent.delete_firewall_rule(rule_id="fw-1"))
    responder = asyncio.create_task(simulate_client_response())

    result = await agent_call
    await responder

    assert result == "règle fw-1 supprimée"
    assert sent_messages[0]["type"] == "confirmation_request"
    assert sent_messages[0]["risk"] == "critical"
    assert ws_confirmer.pending_count() == 0  # nettoyage fait après coup


async def test_ws_confirmer_round_trip_denied(ws_confirmer, sent_messages):
    agent = build_agent(ws_confirmer)

    async def simulate_client_response():
        while not sent_messages:
            await asyncio.sleep(0.01)
        req_id = sent_messages[0]["id"]
        ws_confirmer.resolve(req_id, approved=False, reason="refusé par l'opérateur")

    agent_call = asyncio.create_task(agent.delete_firewall_rule(rule_id="fw-1"))
    responder = asyncio.create_task(simulate_client_response())

    with pytest.raises(ConfirmationDenied) as exc_info:
        await agent_call
    await responder

    assert exc_info.value.reason == "refusé par l'opérateur"
    assert "fw-1" in agent.firewall_rules


async def test_ws_confirmer_double_resolve_is_ignored_safely(ws_confirmer, sent_messages):
    agent = build_agent(ws_confirmer)

    async def simulate_double_response():
        while not sent_messages:
            await asyncio.sleep(0.01)
        req_id = sent_messages[0]["id"]
        first = ws_confirmer.resolve(req_id, approved=True)
        second = ws_confirmer.resolve(req_id, approved=False)  # doublon tardif
        assert first is True
        assert second is False

    agent_call = asyncio.create_task(agent.scan_network(subnet="192.168.1.0/24"))
    responder = asyncio.create_task(simulate_double_response())

    result = await agent_call
    await responder

    assert result == "scan 192.168.1.0/24 terminé"


async def test_ws_confirmer_resolve_unknown_req_id_returns_false(ws_confirmer):
    """resolve() sur un req_id qui n'a jamais existé ne doit jamais crasher."""
    assert ws_confirmer.resolve("req-id-inexistant", approved=True) is False


async def test_ws_confirmer_pending_count_tracks_in_flight_requests(ws_confirmer, sent_messages):
    agent = build_agent(ws_confirmer, timeout=5)

    agent_call = asyncio.create_task(agent.delete_firewall_rule(rule_id="fw-1"))
    while not sent_messages:
        await asyncio.sleep(0.01)

    assert ws_confirmer.pending_count() == 1  # la demande est bien "en vol"

    ws_confirmer.resolve(sent_messages[0]["id"], approved=True)
    await agent_call

    assert ws_confirmer.pending_count() == 0

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v", "-p", "no:logfire"]))