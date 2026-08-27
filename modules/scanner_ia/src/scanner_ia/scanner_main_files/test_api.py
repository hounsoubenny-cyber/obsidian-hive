#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — test_api.py                                                    ║
║   Script de test complet de l'API Scanner                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Teste les routes :                                                          ║
║    TEST A — GET  /api/status          (API en ligne)                        ║
║    TEST B — POST /api/start_scan      (lancement scan passif)               ║
║    TEST C — WS   /api/ws_scan_status  (suivi temps réel)                   ║
║    TEST D — POST /api/cancel_scan     (annulation)                          ║
║    TEST E — POST /api/start_scan      (config custom json5)                 ║
║    TEST F — WS   mauvaise pass_phrase (refus connexion)                     ║
║    TEST G — POST /api/cancel_scan     mauvaise pass_phrase (403)            ║
║                                                                             ║
║  Usage :                                                                    ║
║    # Lance l'API d'abord dans un terminal séparé :                          ║
║    python main_scanner.py --api                                             ║
║                                                                             ║
║    # Puis dans un autre terminal :                                          ║
║    python test_api.py                                                       ║
║    python test_api.py --host 0.0.0.0 --port 9000                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
Auteur: HOUNSOU Samuel — ShieldAI
"""

import os
import sys
import time
import asyncio
import argparse
import traceback

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import aiohttp
import websockets
from loguru import logger

# ── Logger ─────────────────────────────────────────────────────────────────
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

# ── Config ─────────────────────────────────────────────────────────────────
HOST         = "localhost"
PORT         = 9000
BASE_URL     = f"http://{HOST}:{PORT}/api"
WS_BASE_URL  = f"ws://{HOST}:{PORT}/api"
TARGET_URL   = "http://localhost:5000"
PASS_PHRASE  = "shieldai_test_2026"
BAD_PHRASE   = "mauvaise_phrase"

# Config custom minimale (JSON5 string)
CUSTOM_CONFIG = """
{
  // Config test — profondeur réduite pour rapidité
  "crawler": {
    "MAX_DEEPTH": 2,
    "MAX_PAGES": 10
  },
  "fetcher": {
    "TIMEOUT": 3
  }
}
"""


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _sep(title: str):
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def _assert(condition: bool, msg: str) -> bool:
    if condition:
        logger.success(f"✅ {msg}")
    else:
        logger.error(f"❌ {msg}")
    return condition


async def _check_api_online(session: aiohttp.ClientSession) -> bool:
    """Vérifie que l'API est accessible avant de lancer les tests."""
    try:
        async with session.get(f"{BASE_URL}/status", timeout=aiohttp.ClientTimeout(total=5)) as r:
            return r.status == 200
    except Exception:
        return False


async def _start_scan(
    session:     aiohttp.ClientSession,
    pass_phrase: str = PASS_PHRASE,
    active:      bool = False,
    conf_content: str = "",
) -> dict:
    """Lance un scan et retourne la réponse JSON."""
    body = {
        "pass_phrase": pass_phrase,
        "instance_args": {
            "active_scan":  active,
            "use_cache":    False,
            "debug":        True,
            "conf_content": conf_content,
        },
        "scan_args": {
            "url":       TARGET_URL,
            "threshold": 0.5,
        }
    }
    async with session.post(
        f"{BASE_URL}/start_scan",
        json=body,
        timeout=aiohttp.ClientTimeout(total=10)
    ) as r:
        data = await r.json()
        return {"status_code": r.status, "data": data}


async def _collect_ws_messages(
    scan_id:     str,
    pass_phrase: str,
    max_wait:    float = 120.0,
    max_msgs:    int   = 200,
) -> list[dict]:
    """
    Se connecte au WS et collecte les messages jusqu'à scan_result/scan_error
    ou timeout.
    """
    uri = f"{WS_BASE_URL}/ws_scan_status?scan_id={scan_id}&pass_phrase={pass_phrase}"
    messages = []

    try:
        async with websockets.connect(uri, open_timeout=10) as ws:
            deadline = asyncio.get_event_loop().time() + max_wait
            while asyncio.get_event_loop().time() < deadline and len(messages) < max_msgs:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    import json
                    msg = json.loads(raw)
                    messages.append(msg)
                    msg_type = msg.get("type", "")
                    if msg_type in ("scan_result", "scan_error"):
                        break
                    if msg_type == "scan_info" and "annulé" in str(msg.get("message", "")):
                        break
                except asyncio.TimeoutError:
                    # Envoyer ping pour maintenir la connexion
                    await ws.send("ping")
    except Exception as e:
        logger.warning(f"WS exception : {e}")

    return messages


# ══════════════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════════════

async def test_status(session: aiohttp.ClientSession) -> bool:
    """TEST A — GET /api/status"""
    _sep("TEST A — GET /api/status")
    try:
        async with session.get(f"{BASE_URL}/status") as r:
            data = await r.json()
            ok = True
            ok &= _assert(r.status == 200,                          "status HTTP 200")
            ok &= _assert(data.get("status") == "running",          "status = running")
            ok &= _assert("active_scans" in data,                   "champ active_scans présent")
            ok &= _assert("date" in data,                           "champ date présent")
            logger.info(f"Scans actifs : {data.get('active_scans', '?')}")
            return ok
    except Exception as e:
        logger.error(f"Erreur : {e}")
        return False


async def test_start_scan(session: aiohttp.ClientSession) -> tuple[bool, str]:
    """TEST B — POST /api/start_scan (scan passif)"""
    _sep("TEST B — POST /api/start_scan")
    try:
        resp = await _start_scan(session, pass_phrase=PASS_PHRASE, active=False)
        data = resp["data"]
        ok   = True
        ok  &= _assert(resp["status_code"] == 200,                  "status HTTP 200")
        ok  &= _assert("scan_id" in data,                           "scan_id présent")
        ok  &= _assert("status" in data,                            "status présent")
        ok  &= _assert(data.get("status") == "started",             "status = started")
        ok  &= _assert(data.get("scan_id", "").startswith("sh_sc-"),"scan_id format sh_sc-...")

        scan_id = data.get("scan_id", "")
        logger.info(f"scan_id : {scan_id}")
        return ok, scan_id
    except Exception as e:
        logger.error(f"Erreur : {e}")
        traceback.print_exc()
        return False, ""


async def test_ws_followup(scan_id: str) -> bool:
    """TEST C — WS /api/ws_scan_status (suivi temps réel)"""
    _sep("TEST C — WS /api/ws_scan_status")

    if not scan_id:
        logger.warning("scan_id vide — TEST C skipped")
        return None

    logger.info(f"Connexion WS pour scan_id : {scan_id}")
    messages = await _collect_ws_messages(scan_id, PASS_PHRASE, max_wait=120.0)

    ok = True
    ok &= _assert(len(messages) > 0,                                "au moins 1 message reçu")

    types = [m.get("type") for m in messages]
    logger.info(f"Types reçus : {types}")

    has_info   = any(t == "scan_info"   for t in types)
    has_result = any(t == "scan_result" for t in types)
    has_error  = any(t == "scan_error"  for t in types)

    ok &= _assert(has_info,                                         "message scan_info reçu")
    ok &= _assert(has_result or has_error,                          "scan_result ou scan_error reçu")

    if has_result:
        result_msg = next(m for m in messages if m.get("type") == "scan_result")
        result_data = result_msg.get("message", {})
        ok &= _assert(isinstance(result_data, dict),                "scan_result est un dict")
        ok &= _assert("date" in result_data or "errors" in result_data, "scan_result contient data")
        logger.info(f"Clés du résultat : {list(result_data.keys())[:8]}")

    log_count = sum(1 for t in types if t == "log")
    logger.info(f"Messages log reçus : {log_count}")

    return ok


async def test_cancel_scan(session: aiohttp.ClientSession) -> bool:
    """TEST D — POST /api/cancel_scan"""
    _sep("TEST D — POST /api/cancel_scan")

    # Lancer un scan actif pour avoir le temps de l'annuler
    resp = await _start_scan(session, pass_phrase=PASS_PHRASE, active=False)
    scan_id = resp["data"].get("scan_id", "")

    if not scan_id:
        logger.error("Impossible d'obtenir un scan_id pour le test d'annulation")
        return False

    # Attendre 2 secondes que le scan démarre
    await asyncio.sleep(2)

    try:
        async with session.post(
            f"{BASE_URL}/cancel_scan",
            json={"scan_id": scan_id, "pass_phrase": PASS_PHRASE},
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            data = await r.json()
            ok   = True
            ok  &= _assert(r.status == 200,                         "status HTTP 200")
            ok  &= _assert(data.get("status") == "cancelled",       "status = cancelled")
            ok  &= _assert(data.get("scan_id") == scan_id,          "scan_id correct")
            logger.info(f"Annulation : {data}")
            return ok
    except Exception as e:
        logger.error(f"Erreur annulation : {e}")
        return False


async def test_custom_config(session: aiohttp.ClientSession) -> tuple[bool, str]:
    """TEST E — POST /api/start_scan avec config custom json5"""
    _sep("TEST E — Config custom json5")
    try:
        resp = await _start_scan(
            session,
            pass_phrase=PASS_PHRASE,
            active=False,
            conf_content=CUSTOM_CONFIG
        )
        data = resp["data"]
        ok   = True
        ok  &= _assert(resp["status_code"] == 200,                  "status HTTP 200 avec config custom")
        ok  &= _assert("scan_id" in data,                           "scan_id présent")

        scan_id = data.get("scan_id", "")
        logger.info(f"scan_id config custom : {scan_id}")

        # Annuler immédiatement — on teste juste le lancement
        if scan_id:
            await asyncio.sleep(1)
            async with session.post(
                f"{BASE_URL}/cancel_scan",
                json={"scan_id": scan_id, "pass_phrase": PASS_PHRASE}
            ) as r:
                pass

        return ok, scan_id
    except Exception as e:
        logger.error(f"Erreur config custom : {e}")
        return False, ""


async def test_bad_passphrase_ws(session: aiohttp.ClientSession) -> bool:
    """TEST F — WS avec mauvaise pass_phrase (doit être refusé)"""
    _sep("TEST F — WS mauvaise pass_phrase (refus attendu)")

    # Lancer un scan valide
    resp = await _start_scan(session, pass_phrase=PASS_PHRASE)
    scan_id = resp["data"].get("scan_id", "")
    if not scan_id:
        return False

    # Tenter de se connecter avec la mauvaise phrase
    uri = f"{WS_BASE_URL}/ws_scan_status?scan_id={scan_id}&pass_phrase={BAD_PHRASE}"
    refused = False
    try:
        async with websockets.connect(uri, open_timeout=5) as ws:
            # Si on arrive ici, le serveur n'a pas refusé → fail
            await ws.recv()
    except websockets.exceptions.ConnectionClosedError as e:
        refused = True
        logger.info(f"Connexion refusée comme attendu : code={e.code}")
    except Exception as e:
        refused = True
        logger.info(f"Connexion refusée : {type(e).__name__}")

    ok = _assert(refused, "WS refusé avec mauvaise pass_phrase")

    # Annuler le scan laissé en vie
    await asyncio.sleep(1)
    async with session.post(
        f"{BASE_URL}/cancel_scan",
        json={"scan_id": scan_id, "pass_phrase": PASS_PHRASE}
    ) as r:
        pass

    return ok


async def test_bad_passphrase_cancel(session: aiohttp.ClientSession) -> bool:
    """TEST G — /api/cancel_scan avec mauvaise pass_phrase (403 attendu)"""
    _sep("TEST G — cancel_scan mauvaise pass_phrase (403 attendu)")

    resp = await _start_scan(session, pass_phrase=PASS_PHRASE)
    scan_id = resp["data"].get("scan_id", "")
    if not scan_id:
        return False

    try:
        async with session.post(
            f"{BASE_URL}/cancel_scan",
            json={"scan_id": scan_id, "pass_phrase": BAD_PHRASE},
            timeout=aiohttp.ClientTimeout(total=5)
        ) as r:
            ok = _assert(r.status == 403, f"HTTP 403 avec mauvaise phrase (reçu {r.status})")

        # Annuler proprement après
        await asyncio.sleep(1)
        async with session.post(
            f"{BASE_URL}/cancel_scan",
            json={"scan_id": scan_id, "pass_phrase": PASS_PHRASE}
        ) as r:
            pass

        return ok
    except Exception as e:
        logger.error(f"Erreur : {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main_async(args):
    global HOST, PORT, BASE_URL, WS_BASE_URL, TARGET_URL
    HOST        = args.host
    PORT        = args.port
    BASE_URL    = f"http://{HOST}:{PORT}/api"
    WS_BASE_URL = f"ws://{HOST}:{PORT}/api"
    TARGET_URL  = args.target

    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — Test API Scanner                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")

    async with aiohttp.ClientSession() as session:

        # Vérification API en ligne
        logger.info(f"Vérification API sur {BASE_URL}...")
        online = await _check_api_online(session)
        if not online:
            logger.error(f"API inaccessible sur {BASE_URL}")
            logger.error("Lance d'abord : python main_scanner.py --api")
            sys.exit(1)
        logger.success("API en ligne ✅")

        results = {}
        t_global = time.time()

        # ── TEST A ──────────────────────────────────────────────────────────
        results["A — Status"]         = await test_status(session)

        # ── TEST B ──────────────────────────────────────────────────────────
        ok_b, scan_id_b               = await test_start_scan(session)
        results["B — Start scan"]     = ok_b

        # ── TEST C — WS suivi du scan lancé en B ────────────────────────────
        results["C — WS suivi"]       = await test_ws_followup(scan_id_b)

        # ── TEST D ──────────────────────────────────────────────────────────
        results["D — Cancel scan"]    = await test_cancel_scan(session)

        # ── TEST E ──────────────────────────────────────────────────────────
        ok_e, _                       = await test_custom_config(session)
        results["E — Config custom"]  = ok_e

        # ── TEST F ──────────────────────────────────────────────────────────
        results["F — Bad phrase WS"]  = await test_bad_passphrase_ws(session)

        # ── TEST G ──────────────────────────────────────────────────────────
        results["G — Bad phrase cancel"] = await test_bad_passphrase_cancel(session)

        # ── BILAN ────────────────────────────────────────────────────────────
        elapsed_total = time.time() - t_global
        _sep(f"BILAN ({elapsed_total:.1f}s)")

        all_pass = True
        for label, ok in results.items():
            if ok is None:
                print(f"  ⏭️  {label:<35} SKIPPED")
            elif ok:
                print(f"  ✅ {label:<35} PASSED")
            else:
                print(f"  ❌ {label:<35} FAILED")
                all_pass = False

        print()
        if all_pass:
            logger.success("Tous les tests passent ✅")
        else:
            logger.error("Certains tests ont échoué ❌")

        sys.exit(0 if all_pass else 1)


def main():
    parser = argparse.ArgumentParser(description="ShieldAI — Test API Scanner")
    parser.add_argument("--host",   default=HOST,       help=f"Hôte API (défaut: {HOST})")
    parser.add_argument("--port",   default=PORT, type=int, help=f"Port API (défaut: {PORT})")
    parser.add_argument("--target", default=TARGET_URL, help=f"URL cible du scan (défaut: {TARGET_URL})")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
