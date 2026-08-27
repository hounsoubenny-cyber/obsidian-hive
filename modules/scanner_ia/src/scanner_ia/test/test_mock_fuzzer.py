#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — test_mock_fuzzer.py                                            ║
║   Tests complets du MockFuzzer                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Couvre :                                                                   ║
║    TEST 1 — Structure FuzzerResult                                          ║
║    TEST 2 — Reproductibilité (seed fixe)                                    ║
║    TEST 3 — Taux de vulnérabilité                                           ║
║    TEST 4 — Limite vulnérabilités (limit_vuln)                              ║
║    TEST 5 — Stats cohérentes                                                ║
║    TEST 6 — WorkerFuzzerResult complets                                     ║
║    TEST 7 — Réalisme (diversité des vulns)                                  ║
║    TEST 8 — URLs vides (AnalyzerHelperResult vide)                          ║
║    TEST 9 — Flag mock dans stats                                            ║
║    TEST 10 — ResponseAnalyzerResult cohérent                               ║
║    TEST 11 — Elapsed plausible                                             ║
║    TEST 12 — BaseURL propagé dans workers                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
Usage :
    python test_mock_fuzzer.py
"""

import os, sys, time
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

from loguru import logger
logger.remove()
logger.add(sys.stdout,
    format="<yellow>{time:HH:mm:ss}</yellow> | <level>{level:<8}</level> | └─ <level>{message}</level>",
    level="INFO", colorize=True)

from fuzzer.mock_fuzzer import MockFuzzer
from base_class.analyser_helper_base_class import (
    AnalyzerHelperResult, OneAnalyzerHelperResult
)
from base_class.fetcher_base_class  import FetcherResult
from base_class.fuzzer_base_class   import FuzzerResult, WorkerFuzzerResult
from base_class.response_analyzer_base_class import ResponseAnalyzerResult


# ── Helpers ───────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0

def ok(msg: str):
    global PASS
    PASS += 1
    logger.success(f"✅ {msg}")

def fail(msg: str, detail: str = ""):
    global FAIL
    FAIL += 1
    logger.error(f"❌ {msg}" + (f" — {detail}" if detail else ""))

def check(cond: bool, msg_ok: str, msg_fail: str = "", detail: str = ""):
    if cond:
        ok(msg_ok)
    else:
        fail(msg_fail or msg_ok, detail)
    return cond


def _make_ah(urls: list[str]) -> AnalyzerHelperResult:
    """Crée un AnalyzerHelperResult avec les URLs données."""
    ah = AnalyzerHelperResult()
    for url in urls:
        el = OneAnalyzerHelperResult()
        f  = FetcherResult()
        f.url         = url
        f.final_url   = url
        f.status_code = 200
        f.body        = f"<html><body>Page {url}</body></html>"
        f.headers     = {"Content-Type": "text/html"}
        f.delay       = 0.05
        el.fetched    = f
        ah.elements[url] = el
    return ah


def _sep(title: str):
    print(f"\n{'─' * 65}")
    print(f"  {title}")
    print(f"{'─' * 65}")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════════════

def test_structure():
    _sep("TEST 1 — Structure FuzzerResult")
    mock  = MockFuzzer(seed=42, vuln_rate=0.5)
    ah    = _make_ah(["http://localhost:5000/page1", "http://localhost:5000/page2"])
    result = mock.simulate_scan("http://localhost:5000", ah)

    check(isinstance(result, FuzzerResult),         "result est FuzzerResult")
    check(result.url == "http://localhost:5000",     "result.url correct")
    check(isinstance(result.results, list),          "result.results est une liste")
    check(isinstance(result.stats, dict),            "result.stats est un dict")
    check(result.elapsed > 0,                        "result.elapsed > 0",
          "elapsed doit être positif", str(result.elapsed))
    check("total_tests" in result.stats,             "stats.total_tests présent")
    check("total_vulns" in result.stats,             "stats.total_vulns présent")
    check("vuln_count"  in result.stats,             "stats.vuln_count présent")
    check("mock"        in result.stats,             "stats.mock présent")


def test_reproducibility():
    _sep("TEST 2 — Reproductibilité (seed fixe)")
    ah = _make_ah(["http://localhost:5000/a", "http://localhost:5000/b",
                   "http://localhost:5000/c"])

    r1 = MockFuzzer(seed=99, vuln_rate=0.6).simulate_scan("http://localhost:5000", ah)
    r2 = MockFuzzer(seed=99, vuln_rate=0.6).simulate_scan("http://localhost:5000", ah)

    check(len(r1.results) == len(r2.results),
          f"Même nb de workers ({len(r1.results)})",
          "Nb workers différents entre deux exécutions seed=99")

    check(r1.stats.get("total_vulns") == r2.stats.get("total_vulns"),
          f"Même nb de vulns ({r1.stats.get('total_vulns')})",
          "Nb vulns différent entre deux exécutions")

    # Seed différente → résultat différent (probabilistique, peut échouer rarement)
    r3 = MockFuzzer(seed=1, vuln_rate=0.5).simulate_scan("http://localhost:5000", ah)
    # On vérifie juste que ça tourne sans erreur
    ok("Seed différente s'exécute sans erreur")


def test_vuln_rate():
    _sep("TEST 3 — Taux de vulnérabilité")
    # Avec vuln_rate=1.0, toutes les URLs doivent avoir des vulns
    urls = [f"http://localhost:5000/page{i}" for i in range(20)]
    ah   = _make_ah(urls)

    r_full = MockFuzzer(seed=42, vuln_rate=1.0).simulate_scan("http://localhost:5000", ah)
    check(r_full.stats.get("total_vulns", 0) > 0,
          "vuln_rate=1.0 → vulns détectées")

    # Avec vuln_rate=0.0, aucune vulnérabilité
    r_none = MockFuzzer(seed=42, vuln_rate=0.0).simulate_scan("http://localhost:5000", ah)
    check(r_none.stats.get("total_vulns", 0) == 0,
          "vuln_rate=0.0 → aucune vuln",
          f"vuln_rate=0.0 mais {r_none.stats.get('total_vulns')} vulns trouvées")


def test_limit_vuln():
    _sep("TEST 4 — Limite vulnérabilités (limit_vuln)")
    urls = [f"http://localhost:5000/p{i}" for i in range(30)]
    ah   = _make_ah(urls)
    LIMIT = 2

    r = MockFuzzer(seed=42, vuln_rate=1.0).simulate_scan(
        "http://localhost:5000", ah, limit_vuln=LIMIT
    )
    total = r.stats.get("total_vulns", 0)
    check(total <= LIMIT,
          f"Limite respectée : {total} ≤ {LIMIT}",
          f"Limite non respectée : {total} > {LIMIT}")


def test_stats_coherence():
    _sep("TEST 5 — Stats cohérentes")
    urls = [f"http://localhost:5000/p{i}" for i in range(10)]
    ah   = _make_ah(urls)
    r    = MockFuzzer(seed=42, vuln_rate=0.4).simulate_scan("http://localhost:5000", ah)

    total_urls_stat    = r.stats.get("total_urls", -1)
    total_tests_stat   = r.stats.get("total_tests", 0)
    total_vuln_count   = sum(r.stats.get("vuln_count", {}).values())
    total_vulns_stat   = r.stats.get("total_vulns", 0)

    check(total_urls_stat == len(urls),
          f"stats.total_urls correct ({total_urls_stat})",
          f"total_urls={total_urls_stat} ≠ {len(urls)}")

    check(total_tests_stat > 0,
          f"stats.total_tests > 0 ({total_tests_stat})")

    check(total_vuln_count == total_vulns_stat,
          f"vuln_count total == total_vulns ({total_vuln_count})",
          f"Incohérence : sum(vuln_count)={total_vuln_count} ≠ total_vulns={total_vulns_stat}")

    # vuln_by_url ↔ vulns_url
    vuln_by_url  = r.stats.get("vuln_by_url", {})
    vulns_url    = set(r.stats.get("vulns_url", []))
    check(set(vuln_by_url.keys()) == vulns_url,
          "vuln_by_url.keys() == vulns_url",
          f"Incohérence keys: {set(vuln_by_url.keys())} ≠ {vulns_url}")


def test_worker_completeness():
    _sep("TEST 6 — WorkerFuzzerResult complets")
    ah = _make_ah(["http://localhost:5000/login", "http://localhost:5000/admin"])
    r  = MockFuzzer(seed=42, vuln_rate=1.0).simulate_scan("http://localhost:5000", ah)

    vuln_workers = [w for w in r.results if w.response_analyzer_result.is_vulnerable]
    check(len(vuln_workers) > 0, "Au moins un worker vulnérable")

    for w in vuln_workers[:3]:
        check(bool(w.url),             f"worker.url non vide ({w.url[:40]})")
        check(bool(w.base_url),        f"worker.base_url non vide")
        check(bool(w.vuln_name),       f"worker.vuln_name non vide ({w.vuln_name})")
        check(bool(w.vuln_full_name),  f"worker.vuln_full_name non vide")
        check(w.cvss > 0,              f"worker.cvss > 0 ({w.cvss})")
        check(w.payload is not None,   f"worker.payload non None")
        check(bool(w.payload.payload_injected),   f"payload.value non vide")
        check(w.baseline is not None,  f"worker.baseline non None")
        check(w.payload_result is not None, f"worker.payload_result non None")

        rar = w.response_analyzer_result
        check(isinstance(rar, ResponseAnalyzerResult), "rar est ResponseAnalyzerResult")
        check(rar.is_vulnerable is True,  f"rar.is_vulnerable = True")
        check(0 < rar.score <= 100,       f"rar.score dans [0,100] ({rar.score})")
        check(0 < rar.prob <= 1.0,        f"rar.prob dans [0,1] ({rar.prob})")
        check(isinstance(rar.found_indicators, dict), "rar.found_indicators est dict")


def test_realism():
    _sep("TEST 7 — Réalisme (diversité des vulns)")
    urls = [f"http://localhost:5000/p{i}" for i in range(50)]
    ah   = _make_ah(urls)
    r    = MockFuzzer(seed=0, vuln_rate=0.6).simulate_scan("http://localhost:5000", ah)

    vuln_types = set(r.stats.get("vuln_count", {}).keys())
    check(len(vuln_types) >= 2,
          f"Au moins 2 types de vulns différents ({vuln_types})",
          f"Seulement {len(vuln_types)} type(s)")

    # Vérifier que des workers clean existent aussi
    clean_workers = [w for w in r.results if not w.response_analyzer_result.is_vulnerable]
    check(len(clean_workers) > 0,
          f"Des workers clean existent ({len(clean_workers)})",
          "Aucun worker clean — pas réaliste")

    # Vérifier la diversité des URLs testées
    tested_urls = set(w.url for w in r.results)
    check(len(tested_urls) > 1,
          f"Plusieurs URLs testées ({len(tested_urls)})")


def test_empty_ah():
    _sep("TEST 8 — AnalyzerHelperResult vide")
    ah = AnalyzerHelperResult()  # aucune URL
    r  = MockFuzzer(seed=42, vuln_rate=0.5).simulate_scan("http://localhost:5000", ah)

    check(isinstance(r, FuzzerResult), "FuzzerResult retourné même avec AH vide")
    check(r.url == "http://localhost:5000", "URL base correcte")
    # Avec AH vide, le mock utilise base_url comme fallback
    check(isinstance(r.results, list), "results est une liste")
    ok("Pas de crash avec AnalyzerHelperResult vide")


def test_mock_flag():
    _sep("TEST 9 — Flag mock dans stats")
    ah = _make_ah(["http://localhost:5000/"])
    r  = MockFuzzer().simulate_scan("http://localhost:5000", ah)

    check(r.stats.get("mock") is True,
          "stats.mock = True",
          f"stats.mock = {r.stats.get('mock')} (doit être True)")


def test_response_analyzer_consistency():
    _sep("TEST 10 — ResponseAnalyzerResult cohérent")
    ah = _make_ah(["http://localhost:5000/test"])
    r  = MockFuzzer(seed=42, vuln_rate=1.0).simulate_scan("http://localhost:5000", ah)

    for w in r.results:
        rar = w.response_analyzer_result
        check(rar.vuln_name == w.vuln_name,
              f"rar.vuln_name cohérent avec worker.vuln_name ({w.vuln_name})",
              f"rar.vuln_name={rar.vuln_name} ≠ worker.vuln_name={w.vuln_name}")
        if rar.is_vulnerable:
            check(rar.score > 0,
                  f"is_vulnerable → score > 0 ({rar.score})",
                  f"is_vulnerable mais score={rar.score}")
        else:
            check(rar.score <= 20,
                  f"not vulnerable → score ≤ 20 ({rar.score})")


def test_elapsed():
    _sep("TEST 11 — Elapsed plausible")
    ah = _make_ah(["http://localhost:5000/p1"])
    DELAY = 0.15
    t0 = time.time()
    r  = MockFuzzer(seed=42, fake_delay=DELAY).simulate_scan("http://localhost:5000", ah)
    wall = time.time() - t0

    check(r.elapsed >= DELAY * 0.8,
          f"elapsed ≥ fake_delay ({r.elapsed:.3f}s ≥ {DELAY*0.8:.3f}s)")
    check(wall >= DELAY * 0.8,
          f"wall-clock ≥ fake_delay ({wall:.3f}s)")


def test_base_url_propagation():
    _sep("TEST 12 — base_url propagé dans workers")
    BASE = "http://localhost:5000"
    urls = [f"{BASE}/page{i}" for i in range(5)]
    ah   = _make_ah(urls)
    r    = MockFuzzer(seed=42, vuln_rate=1.0).simulate_scan(BASE, ah)

    for w in r.results:
        check(w.base_url == BASE,
              f"base_url correct ({w.base_url})",
              f"base_url={w.base_url} ≠ {BASE}")
        check(w.url.startswith(BASE),
              f"url commence par base_url ({w.url[:50]})",
              f"url={w.url} ne commence pas par {BASE}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — Tests MockFuzzer                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    t0 = time.time()

    test_structure()
    test_reproducibility()
    test_vuln_rate()
    test_limit_vuln()
    test_stats_coherence()
    test_worker_completeness()
    test_realism()
    test_empty_ah()
    test_mock_flag()
    test_response_analyzer_consistency()
    test_elapsed()
    test_base_url_propagation()

    elapsed = time.time() - t0
    print(f"\n{'═' * 65}")
    print(f"  BILAN — {PASS + FAIL} assertions en {elapsed:.2f}s")
    print(f"  ✅ {PASS} passées   ❌ {FAIL} échouées")
    print(f"{'═' * 65}\n")

    if FAIL == 0:
        logger.success("Tous les tests MockFuzzer passent ✅")
    else:
        logger.error(f"{FAIL} test(s) échoué(s) ❌")

    import sys
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
