#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 29 21:40:01 2026

@author: hounsousamuel
"""

"""Tests de plan_memory (budget mémoire). Lancer : python test_plan_memory.py"""
import random

EST_PKT_BYTES = 1200

def plan_memory(max_size, workers, budget, allow_over_budget=False):
    wanted = max_size * EST_PKT_BYTES
    slots = workers + 1 + 2      # workers + 1 en remplissage + 2 en file au minimum
    chunk = wanted if allow_over_budget else max(256_000, min(wanted, budget // slots))
    queue_max = max(2, budget // chunk - workers - 1)
    ram_max = (queue_max + workers + 1) * chunk
    warning = None
    if ram_max > budget:
        warning = f"RAM max {ram_max/1e6:.0f} Mo > budget {budget/1e6:.0f} Mo"
    return dict(max_size=max(100, chunk // EST_PKT_BYTES),
                queue_max=queue_max, ram_max=ram_max, warning=warning)

MO = 1_000_000

def test_exemples():
    r = plan_memory(20_000, 4, 100 * MO)
    assert r["ram_max"] <= 100 * MO and r["queue_max"] == 2 and r["warning"] is None
    r = plan_memory(20_000, 4, 100 * MO, allow_over_budget=True)
    assert r["ram_max"] == 168 * MO and r["warning"] and r["max_size"] == 20_000
    r = plan_memory(20_000, 4, 1500 * MO)                 # budget confortable : chunk inchangé
    assert r["max_size"] == 20_000 and r["ram_max"] <= 1500 * MO

def test_invariant_budget_jamais_depasse():
    """Dès que le budget permet le plancher (7 places x 256 Ko), la RAM max reste <= budget."""
    rnd = random.Random(1)
    for _ in range(100_000):
        w = rnd.randint(1, 16)
        budget = rnd.randint((w + 3) * 256_000, 64_000 * MO)
        r = plan_memory(rnd.randint(100, 500_000), w, budget)
        assert r["ram_max"] <= budget, (w, budget, r)
        assert r["queue_max"] >= 2 and r["max_size"] >= 100 and r["warning"] is None

def test_budget_minuscule_previent_sans_erreur():
    for budget in (0, 1, 50_000, 500_000, 1 * MO):
        r = plan_memory(20_000, 4, budget)                # ne doit jamais lever
        assert r["queue_max"] >= 2 and r["max_size"] >= 100
        if r["ram_max"] > budget:
            assert r["warning"]

def test_mode_avance_respecte_la_demande():
    rnd = random.Random(2)
    for _ in range(10_000):
        ms, w, b = rnd.randint(100, 100_000), rnd.randint(1, 8), rnd.randint(1, 4000 * MO)
        r = plan_memory(ms, w, b, allow_over_budget=True)
        assert r["max_size"] == ms                        # taille imposée, jamais réduite
        assert (r["warning"] is not None) == (r["ram_max"] > b)

if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            f(); print("✅", n)
    print("\nTableau (max_size=20 000, 4 workers) :")
    print(f"{'budget':>9} | {'mode':<7} | {'chunk Mo':>8} | {'file':>4} | {'RAM max Mo':>10} | avertissement")
    for b in (2000, 1500, 500, 100, 20, 5, 1, 0.5):
        for over in (False, True):
            r = plan_memory(20_000, 4, int(b * MO), over)
            print(f"{b:>6g} Mo | {'avancé' if over else 'défaut':<7} | {r['max_size']*EST_PKT_BYTES/MO:8.1f} | "
                  f"{r['queue_max']:>4} | {r['ram_max']/MO:10.0f} | {r['warning'] or ''}")
