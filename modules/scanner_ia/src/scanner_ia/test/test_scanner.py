#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — test_scanner.py                                                ║
║   Script de test complet du Scanner (main_scanner.py)                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Teste les 3 modes :                                                        ║
║    TEST A — Scan passif uniquement (active_scan=False, MockFuzzer)          ║
║    TEST B — Scan actif complet     (active_scan=True, vuln_server_v3)       ║
║    TEST C — Cache hit              (deuxième appel sur même URL)            ║
║                                                                             ║
║  Usage :                                                                    ║
║    # Scan passif (pas de serveur nécessaire)                                ║
║    python test_scanner.py --mode passive --url https://books.toscrape.com   ║
║                                                                             ║
║    # Scan actif (lancer vuln_server_v3 d'abord)                             ║
║    python test_scanner.py --mode active  --url http://localhost:5000        ║
║                                                                             ║
║    # Tous les tests                                                         ║
║    python test_scanner.py --mode all                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
Author : Samuel — ShieldAI
"""

import os, sys
import time
import argparse
import traceback
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

from loguru import logger

# ── Logger ────────────────────────────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stdout,
    format=(
        "<yellow>{time:HH:mm:ss}</yellow> | "
        "<level>{level: <8}</level> | "
        "<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
        "└─ <level>{message}</level>"
    ),
    level="INFO", colorize=True
)

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_PATH          = os.path.join(os.path.dirname(__file__), "shieldai_scanner.config.json5")
TARGET_PASSIVE       = "http://localhost:5000" #"https://books.toscrape.com"
TARGET_ACTIVE        = "http://localhost:5000"
ALLOWED_PASSIVE      = ["http://localhost:5000"] #["https://books.toscrape.com"]
ALLOWED_ACTIVE       = ["http://localhost:5000", "http://127.0.0.1:5000"]


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _sep(title: str):
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def _check_config():
    """Vérifie que le fichier de config existe, en crée un minimal sinon."""
    if os.path.exists(CONFIG_PATH):
        logger.success(f"Config trouvée : {CONFIG_PATH}")
        return
    logger.warning(f"Config absente — création d'un fichier minimal : {CONFIG_PATH}")
    import json
    minimal = {
        "scanner": {"use_cache": True, "debug": True},
        "crawler": {"MAX_DEEPTH": 2, "MAX_PAGES": 20},
        "fetcher": {"TIMEOUT": 5}
    }
    with open(CONFIG_PATH, "w") as f:
        # JSON5 minimal (commentaire retiré pour compatibilité json.dump)
        json.dump(minimal, f, indent=2)
    logger.success("Config minimale créée")


def _print_result_summary(result, label: str):
    """Affiche un résumé lisible du ScannerResult."""
    _sep(f"RÉSULTAT — {label}")
    if result is None:
        logger.error("result = None — le scan a échoué")
        return

    # Phases
    phases_result = getattr(result, "phases_result", {}) or {}
    timings       = getattr(result, "timings",       {}) or {}
    errors        = getattr(result, "errors",         []) or []

    print(f"  📅 Date        : {getattr(result, 'date', '?')}")
    print(f"  🔑 Cache key   : {getattr(result, 'cache_key', '?')[:60]}...")
    print(f"  ⚠️  Erreurs     : {len(errors)}")
    if errors:
        for e in errors[:3]:
            print(f"      ❌ {e.get('error_type','?')}: {e.get('error_message','?')[:80]}")

    # Timings
    if timings:
        print(f"\n  ⏱️  Timings par phase :")
        for phase, t in timings.items():
            bar = "█" * max(1, int(t / max(timings.values()) * 20))
            print(f"    {phase:<40} {bar:<20} {t:.2f}s")

    # Phases
    if phases_result:
        print(f"\n  📦 Phases complétées : {list(phases_result.keys())}")

    # Fuzzer / MockFuzzer
    fuzzer_result = phases_result.get("fuzzer")
    if fuzzer_result:
        stats     = getattr(fuzzer_result, "stats", {}) or {}
        is_mock   = stats.get("mock", False)
        n_tests   = stats.get("total_tests", 0)
        n_vulns   = stats.get("total_vulns", 0)
        vuln_ct   = stats.get("vuln_count", {})
        elapsed   = getattr(fuzzer_result, "elapsed", 0)

        print(f"\n  {'🎭 MOCK Fuzzer' if is_mock else '⚡ Fuzzer actif'}")
        print(f"    Tests         : {n_tests}")
        print(f"    Vulns trouvées: {n_vulns}")
        print(f"    Elapsed       : {elapsed:.3f}s")
        if vuln_ct:
            print(f"    Distribution  :")
            for vn, cnt in sorted(vuln_ct.items(), key=lambda x: -x[1]):
                print(f"      {'🔴' if cnt > 0 else '🟢'} {vn:<25} {cnt}")

    # AnalyzerHelper
    ah = phases_result.get("analyzer_helper(crawl_and_parse)")
    if ah:
        n_pages = len(getattr(ah, "elements", {}) or {})
        print(f"\n  🕷️  Pages crawlées : {n_pages}")

    # Features extraction
    feat = phases_result.get("features_extraction")
    if feat is not None:
        try:
            import pandas as pd
            if hasattr(feat, "shape"):
                print(f"\n  🔢 Features extraites : {feat.shape}")
        except Exception:
            pass

    # ML prediction
    ml = phases_result.get("ml_prediction")
    if ml:
        print(f"\n  🤖 Prédictions ML :")
        proba = ml.get("proba", {})
        if proba:
            first = proba.get(0, {})
            top5  = sorted(first.items(), key=lambda x: -x[1])[:5]
            for vuln, prob in top5:
                bar = "█" * int(prob * 20)
                print(f"    {vuln:<25} {bar:<20} {prob:.3f}")

    # Rapport
    report = phases_result.get("report")
    if report:
        print(f"\n  📄 Rapport généré :")
        if isinstance(report, dict):
            for fmt, path in report.items():
                print(f"    {fmt:<6} → {path}")


def _assert(condition: bool, msg: str):
    if condition:
        logger.success(f"✅ {msg}")
    else:
        logger.error(f"❌ {msg}")
    return condition


# ══════════════════════════════════════════════════════════════════════════════
# TEST A — Scan passif (MockFuzzer)
# ══════════════════════════════════════════════════════════════════════════════

def test_passive(url: str = TARGET_PASSIVE):
    _sep("TEST A — Scan passif (active_scan=False)")

    from main_scanner import Scanner

    try:
        scanner = Scanner(
            config_path  = CONFIG_PATH,
            active_scan  = False,      # ← MockFuzzer
            use_cache    = True,       # ← pas de cache pour ce test
            restore      = True,
            debug        = True,
            semaphore    = 20,
            use_semantic = True,
        )
        logger.success("Scanner instancié")
    except Exception as e:
        logger.error(f"Échec instanciation Scanner : {e}")
        traceback.print_exc()
        return False

    try:
        t0     = time.time()
        result = scanner.scan_sync(
            url             = url,
            fetch           = True,
            allowed_domains = [url.split("/")[2] if "://" in url else url],
            limit_vuln_for_fuzzer    = 5,
            time_between_for_fuzzer  = 0.0,
            dynamic_timeout_for_fuzzer = False,
        )
        elapsed = time.time() - t0
        logger.success(f"Scan terminé en {elapsed:.1f}s")
    except Exception as e:
        logger.error(f"Échec scan : {e}")
        traceback.print_exc()
        return False

    _print_result_summary(result, f"Passif — {url}")

    # Assertions
    ok = True
    ok &= _assert(result is not None,                                  "result non None")
    ok &= _assert(getattr(result, "date", None) is not None,           "result.date rempli")
    ok &= _assert(len(getattr(result, "errors", []) or []) == 0,       "aucune erreur")

    phases = getattr(result, "phases_result", {}) or {}
    ok &= _assert("analyzer_helper(crawl_and_parse)" in phases,        "phase 1 OK (analyzer_helper)")
    ok &= _assert("passive_code_analyzer"             in phases,        "phase 2 OK (passive)")
    ok &= _assert("code_analyzer"                     in phases,        "phase 3 OK (code)")
    ok &= _assert("fuzzer"                            in phases,        "phase 4 OK (fuzzer)")

    fuzzer = phases.get("fuzzer")
    if fuzzer:
        stats = getattr(fuzzer, "stats", {}) or {}
        ok &= _assert(stats.get("mock", False) is True,                "fuzzer = mock ✓")
        ok &= _assert(stats.get("total_tests", 0) > 0,                 "mock a généré des tests")

    report = phases.get("report")
    if report:
        for fmt, path in (report or {}).items():
            ok &= _assert(os.path.exists(path), f"rapport {fmt} sauvegardé")

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# TEST B — Scan actif (Fuzzer réel)
# ══════════════════════════════════════════════════════════════════════════════

def test_active(url: str = TARGET_ACTIVE):
    _sep("TEST B — Scan actif (active_scan=True)")

    # Vérifier que le serveur tourne
    from scanner_ia.scanner_utils.utils_scanner import is_url_reachable
    if not is_url_reachable(url, timeout=3):
        logger.warning(f"Serveur inaccessible : {url}")
        logger.warning("Lance vuln_server_v3.py avant ce test.")
        logger.warning("Skipping TEST B.")
        return None   # skip, pas fail

    from main_scanner import Scanner

    try:
        scanner = Scanner(
            config_path    = CONFIG_PATH,
            active_scan    = True,
            use_cache      = False,
            debug          = True,
            semaphore      = 10,
            # limit_payloads = 3,        # limiter pour que le test reste rapide
            use_semantic   = True,
        )
        logger.success("Scanner actif instancié")
    except Exception as e:
        logger.error(f"Échec instanciation : {e}")
        traceback.print_exc()
        return False

    try:
        t0     = time.time()
        result = scanner.scan_sync(
            url                      = url,
            fetch                    = True,
            allowed_domains          = ALLOWED_ACTIVE,
            limit_vuln_for_fuzzer    = 3,
            time_between_for_fuzzer  = 0.05,
            dynamic_timeout_for_fuzzer = True,
        )
        elapsed = time.time() - t0
        logger.success(f"Scan actif terminé en {elapsed:.1f}s")
    except Exception as e:
        logger.error(f"Échec scan actif : {e}")
        traceback.print_exc()
        return False

    _print_result_summary(result, f"Actif — {url}")

    ok = True
    ok &= _assert(result is not None,                       "result non None")
    ok &= _assert(len(getattr(result, "errors", []) or []) == 0, "aucune erreur")

    phases = getattr(result, "phases_result", {}) or {}
    ok &= _assert("fuzzer" in phases,                       "phase fuzzer présente")

    fuzzer = phases.get("fuzzer")
    if fuzzer:
        stats = getattr(fuzzer, "stats", {}) or {}
        ok &= _assert(stats.get("mock", False) is False,    "fuzzer = réel (pas mock)")
        ok &= _assert(stats.get("total_tests", 0) > 0,      "tests réels effectués")

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# TEST C — Cache hit
# ══════════════════════════════════════════════════════════════════════════════

def test_cache(url: str = TARGET_PASSIVE):
    _sep("TEST C — Cache hit (deuxième scan = résultat depuis cache)")

    from main_scanner import Scanner

    # Premier scan — remplit le cache
    logger.info("Premier scan (remplit le cache)...")
    try:
        scanner = Scanner(
            config_path = CONFIG_PATH,
            active_scan = False,
            use_cache   = True,
            debug       = False,
        )
        t0 = time.time()
        r1 = scanner.scan_sync(
            url             = url,
            allowed_domains = [url.split("/")[2] if "://" in url else url],
        )
        t1 = time.time() - t0
        logger.info(f"Premier scan : {t1:.2f}s")
    except Exception as e:
        logger.error(f"Échec premier scan : {e}")
        return False

    # Deuxième scan — doit venir du cache
    logger.info("Deuxième scan (doit être instantané depuis le cache)...")
    try:
        t0 = time.time()
        r2 = scanner.scan_sync(
            url             = url,
            allowed_domains = [url.split("/")[2] if "://" in url else url],
        )
        t2 = time.time() - t0
        logger.info(f"Deuxième scan (cache) : {t2:.3f}s")
    except Exception as e:
        logger.error(f"Échec deuxième scan : {e}")
        return False

    ok = True
    ok &= _assert(t2 < t1,    f"cache < temps original ({t2:.3f}s < {t1*0.1:.3f}s)")
    ok &= _assert(r2 is not None,    "résultat cache non None")
    ok &= _assert(
        getattr(r2, "cache_key", None) == getattr(r1, "cache_key", "?"),
        "même cache_key entre les deux scans"
    )
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# TEST D — Instanciation seule (smoke test)
# ══════════════════════════════════════════════════════════════════════════════

def test_instantiation():
    _sep("TEST D — Smoke test instanciation")

    from main_scanner import Scanner

    ok = True
    for active in (True, False):
        label = "active_scan=True" if active else "active_scan=False"
        try:
            s = Scanner(
                config_path = CONFIG_PATH,
                active_scan = active,
                use_cache   = False,
                debug       = False,
            )
            ok &= _assert(hasattr(s, "AnalyzerHelper"),    f"[{label}] AnalyzerHelper présent")
            ok &= _assert(hasattr(s, "PassiveCodeAnalyzer"),f"[{label}] PassiveCodeAnalyzer présent")
            ok &= _assert(hasattr(s, "CodeAnalyzer"),       f"[{label}] CodeAnalyzer présent")
            ok &= _assert(hasattr(s, "FeatureExtractor"),   f"[{label}] FeatureExtractor présent")
            ok &= _assert(hasattr(s, "ScannerIA"),          f"[{label}] ScannerIA présent")
            ok &= _assert(hasattr(s, "ReportGenerator"),    f"[{label}] ReportGenerator présent")

            if active:
                ok &= _assert(s.Fuzzer is not None,         f"[{label}] Fuzzer instancié")
                ok &= _assert(s.FuzzerMock is not None,     f"[{label}] MockFuzzer aussi présent")
            else:
                ok &= _assert(s.Fuzzer is None,             f"[{label}] Fuzzer = None")
                ok &= _assert(s.FuzzerMock is not None,     f"[{label}] MockFuzzer instancié")

        except Exception as e:
            logger.error(f"[{label}] Échec : {e}")
            traceback.print_exc()
            ok = False

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# TEST E — URL hors scope
# ══════════════════════════════════════════════════════════════════════════════

def test_out_of_scope():
    _sep("TEST E — URL hors scope (doit lever RuntimeError)")

    from main_scanner import Scanner

    scanner = Scanner(
        config_path = CONFIG_PATH,
        active_scan = False,
        use_cache   = False,
        debug       = False,
    )

    ok = False
    try:
        scanner.scan_sync(
            url             = "https://google.com",
            allowed_domains = ["http://localhost:5000"],
        )
        logger.error("Attendu RuntimeError — aucune exception levée ❌")
    except RuntimeError as e:
        ok = _assert(True, f"RuntimeError levée correctement : {str(e)[:60]}")
    except Exception as e:
        logger.error(f"Mauvaise exception : {type(e).__name__} — {e}")

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ShieldAI — Script de test du Scanner")
    parser.add_argument(
        "--mode",
        choices=["passive", "active", "cache", "smoke", "scope", "all"],
        default="all",
        help="Mode de test"
    )
    parser.add_argument("--url-passive", default=TARGET_PASSIVE, help="URL cible scan passif")
    parser.add_argument("--url-active",  default=TARGET_ACTIVE,  help="URL cible scan actif")
    args = parser.parse_args()

    _check_config()

    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — Test Scanner                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")

    results = {}

    run_passive = args.mode in ("passive", "all")
    run_active  = args.mode in ("active",  "all")
    run_cache   = args.mode in ("cache",   "all")
    run_smoke   = args.mode in ("smoke",   "all")
    run_scope   = args.mode in ("scope",   "all")

    t_global = time.time()

    if run_smoke:
        results["D — Smoke"]    = test_instantiation()

    if run_scope:
        results["E — Scope"]    = test_out_of_scope()

    if run_passive:
        results["A — Passif"]   = test_passive(args.url_passive)

    if run_active:
        results["B — Actif"]    = test_active(args.url_active)

    if run_cache:
        results["C — Cache"]    = test_cache(args.url_passive)

    # ── Bilan ────────────────────────────────────────────────────────────────
    elapsed_total = time.time() - t_global
    _sep(f"BILAN ({elapsed_total:.1f}s)")

    all_pass = True
    for label, ok in results.items():
        if ok is None:
            print(f"  ⏭️  {label:<30} SKIPPED")
        elif ok:
            print(f"  ✅ {label:<30} PASSED")
        else:
            print(f"  ❌ {label:<30} FAILED")
            all_pass = False

    print()
    if all_pass:
        logger.success("Tous les tests passent ✅")
    else:
        logger.error("Certains tests ont échoué ❌")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()