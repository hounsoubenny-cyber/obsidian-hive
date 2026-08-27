#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 17 07:27:14 2026

@author: hounsousamuel
"""

"""
test_human_in_loop.py

Simule un agent (genre Coralie) qui appelle des tools protégés par
human-in-the-loop, et vérifie les différents scénarios :
    - confirmation approuvée -> le tool s'exécute
    - confirmation refusée   -> ConfirmationDenied
    - pas de réponse à temps -> ConfirmationTimeout
    - WSConfirmer avec résolution asynchrone simulée (round-trip complet)
    - double resolve() sur le même req_id -> pas de crash, juste ignoré

Lancement : python3 test_human_in_loop.py
Pas de dépendance à pytest, juste des assert + un run manuel de chaque cas.
"""

import asyncio
from functools import partial

from obsidian_hive.agents.shared.human_in_loop import (
    Decision,
    ConfirmationDenied,
    ConfirmationTimeout,
    confirm,
    WSConfirmer,
)


# --------------------------------------------------------------------------- #
# Un confirmer 100% scriptable, pour piloter les tests sans input() humain
# --------------------------------------------------------------------------- #

class FakeConfirmer:
    """Confirmer de test : répond immédiatement selon un script fourni,
    ou ne répond jamais (pour simuler un timeout).
    """

    def __init__(self, approve: bool = True, reason: str | None = None, never_respond: bool = False):
        self.approve = approve
        self.reason = reason
        self.never_respond = never_respond
        self.calls: list[dict] = []  # historique des appels, pratique pour assert

    async def __call__(self, *, req_id, tool_name, risk, args):
        self.calls.append({"req_id": req_id, "tool": tool_name, "risk": risk, "args": args})
        if self.never_respond:
            await asyncio.sleep(3600)  # simule "personne ne répond jamais"
        return Decision(approved=self.approve, reason=self.reason)


# --------------------------------------------------------------------------- #
# Un agent factice avec deux tools sensibles, comme CoreTools chez Benny
# --------------------------------------------------------------------------- #

def build_agent(confirmer):
    """Construit une classe CoreTools-like avec le confirmer donné.

    On reconstruit la classe à chaque appel car les décorateurs sont
    appliqués à la définition de classe -> il faut un confirmer figé
    par test, pas un confirmer partagé entre tous les scénarios.
    """
    confirm_ = partial(confirm, confirmer)

    class FakeAgentTools:
        def __init__(self):
            self.firewall_rules = {"fw-1", "fw-2"}
            self.scans_done = []

        @confirm_(risk="critical", timeout=1)
        async def delete_firewall_rule(self, rule_id: str):
            self.firewall_rules.discard(rule_id)
            return f"règle {rule_id} supprimée"

        @confirm_(risk="low", timeout=1)
        async def scan_network(self, subnet: str):
            self.scans_done.append(subnet)
            return f"scan {subnet} terminé"

    return FakeAgentTools()


# --------------------------------------------------------------------------- #
# Scénario 1 : confirmation approuvée -> le tool s'exécute normalement
# --------------------------------------------------------------------------- #

async def test_approved():
    confirmer = FakeConfirmer(approve=True)
    agent = build_agent(confirmer)

    result = await agent.delete_firewall_rule(rule_id="fw-1")

    assert result == "règle fw-1 supprimée"
    assert "fw-1" not in agent.firewall_rules
    assert len(confirmer.calls) == 1
    assert confirmer.calls[0]["risk"] == "critical"
    print("[OK] test_approved")


# --------------------------------------------------------------------------- #
# Scénario 2 : confirmation refusée -> ConfirmationDenied, le tool ne tourne pas
# --------------------------------------------------------------------------- #

async def test_denied():
    confirmer = FakeConfirmer(approve=False, reason="pas maintenant, prod chargée")
    agent = build_agent(confirmer)

    try:
        await agent.delete_firewall_rule(rule_id="fw-2")
        assert False, "aurait dû lever ConfirmationDenied"
    except ConfirmationDenied as e:
        assert e.reason == "pas maintenant, prod chargée"
        assert "fw-2" in agent.firewall_rules  # le tool n'a pas tourné
    print("[OK] test_denied")


# --------------------------------------------------------------------------- #
# Scénario 3 : personne ne répond -> ConfirmationTimeout
# --------------------------------------------------------------------------- #

async def test_timeout():
    confirmer = FakeConfirmer(never_respond=True)
    agent = build_agent(confirmer)  # timeout=1s sur les tools

    try:
        await agent.scan_network(subnet="10.0.0.0/24")
        assert False, "aurait dû lever ConfirmationTimeout"
    except ConfirmationTimeout as e:
        assert e.tool_name == "scan_network"
        assert agent.scans_done == []  # le tool n'a pas tourné
    print("[OK] test_timeout")


# --------------------------------------------------------------------------- #
# Scénario 4 : WSConfirmer, round-trip complet avec résolution async
# simule : l'agent demande confirmation -> un "client WS" répond 0.3s après
# --------------------------------------------------------------------------- #

async def test_ws_confirmer_round_trip():
    sent_messages = []

    async def fake_ws_send(msg: dict):
        sent_messages.append(msg)

    ws_confirmer = WSConfirmer(ws_send=fake_ws_send)
    agent = build_agent(ws_confirmer)

    async def simulate_client_response():
        # attend que la demande soit bien partie avant de répondre
        while not sent_messages:
            await asyncio.sleep(0.01)
        req_id = sent_messages[0]["id"]
        await asyncio.sleep(0.3)  # latence réseau/réflexion humaine simulée
        ws_confirmer.resolve(req_id, approved=True)

    agent_call = asyncio.create_task(agent.delete_firewall_rule(rule_id="fw-1"))
    client_response = asyncio.create_task(simulate_client_response())

    result = await agent_call
    await client_response

    assert result == "règle fw-1 supprimée"
    assert sent_messages[0]["type"] == "confirmation_request"
    assert sent_messages[0]["risk"] == "critical"
    assert ws_confirmer.pending_count() == 0  # nettoyage bien fait
    print("[OK] test_ws_confirmer_round_trip")


# --------------------------------------------------------------------------- #
# Scénario 5 : double resolve() sur le même req_id -> pas de crash
# (ex: message dupliqué côté client, ou réponse tardive après un timeout déjà géré)
# --------------------------------------------------------------------------- #

async def test_ws_confirmer_double_resolve():
    sent_messages = []

    async def fake_ws_send(msg: dict):
        sent_messages.append(msg)

    ws_confirmer = WSConfirmer(ws_send=fake_ws_send)
    agent = build_agent(ws_confirmer)

    async def simulate_double_response():
        while not sent_messages:
            await asyncio.sleep(0.01)
        req_id = sent_messages[0]["id"]
        await asyncio.sleep(0.1)
        first = ws_confirmer.resolve(req_id, approved=True)
        second = ws_confirmer.resolve(req_id, approved=False)  # doublon, arrive après coup
        assert first is True
        assert second is False  # ignoré proprement, pas d'exception

    agent_call = asyncio.create_task(agent.scan_network(subnet="192.168.1.0/24"))
    responder = asyncio.create_task(simulate_double_response())

    result = await agent_call
    await responder

    assert result == "scan 192.168.1.0/24 terminé"
    print("[OK] test_ws_confirmer_double_resolve")


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

async def main():
    tests = [
        test_approved,
        test_denied,
        test_timeout,
        test_ws_confirmer_round_trip,
        test_ws_confirmer_double_resolve,
    ]
    for t in tests:
        await t()
    print(f"\n{len(tests)}/{len(tests)} tests passés ✅")


if __name__ == "__main__":
    asyncio.run(main())