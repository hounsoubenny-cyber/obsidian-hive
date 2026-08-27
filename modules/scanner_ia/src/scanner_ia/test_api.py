#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_api.py — Test du scanner ShieldAI via l'API
=================================================
Équivalent de test_scan.py mais passe par l'API REST + WebSocket.

Flow :
    1. POST /api/start_scan  → reçoit scan_id
    2. WS  /api/ws_scan_status → stream logs + résultat final

Usage:
    python test_api.py
"""

import asyncio
import json
import aiohttp
# =============================================================================
# CONFIGURATION
# =============================================================================

API_BASE    = "http://localhost:9000/api"
TARGET_URL  = "http://localhost:8080"       # ← URL à scanner (DVWA ici)
PASS_PHRASE = "test_secret_phrase"          # ← pass_phrase pour sécuriser le WS

# Paramètres du scanner
INSTANCE_ARGS = {
    "active_scan":    True,
    "use_cache":      False,
    "debug":          False,
    "semaphore":      10,
    "limit_payloads": 2,
    "use_semantic":   False,
    "theme":          "multi",
}

SCAN_ARGS = {
    "url":                      TARGET_URL,
    "fetch":                    True,
    "use_cache":                False,
    "put_result_in_cache":      True,
    "time_between_for_fuzzer":  0.01,
    "dynamic_timeout_for_fuzzer": True,
    "threshold":                0.5,
    "allowed_domains":          [TARGET_URL],

    # ── Helper DVWA ──────────────────────────────────────────────────────────
    # Equivalent de : [dvwa_full_setup, (URL, "admin", "password", "low")]
    # mais JSON-sérialisable pour l'API
    "helpers": [
        {
            "name": "dvwa_auth",
            "kwargs": {
                "base_url":       TARGET_URL,
                "username":       "admin",
                "password":       "password",
                "security_level": "low",
            }
        }
    ],
    "raise_on_helper_error": True,
}


# =============================================================================
# HELPERS D'AFFICHAGE
# =============================================================================

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


def log(msg: str, style: str = ""):
    if RICH:
        console.print(msg)
    else:
        # Strip rich markup basique
        import re
        print(re.sub(r'\[.*?\]', '', msg))


def print_header():
    if RICH:
        console.print(Panel(
            f"[bold cyan]🌐 TEST API SCANNER[/bold cyan]\n"
            f"API     : {API_BASE}\n"
            f"Cible   : {TARGET_URL}\n"
            f"Helper  : dvwa_auth",
            title="ShieldAI — test_api.py",
            border_style="cyan"
        ))
    else:
        print("\n" + "=" * 70)
        print("🌐 TEST API SCANNER")
        print(f"API    : {API_BASE}")
        print(f"Cible  : {TARGET_URL}")
        print("Helper : dvwa_auth")
        print("=" * 70)


def print_result(data: dict):
    """Affiche le résumé du scan reçu via WS."""
    elapsed    = data.get("elapsed", "?")
    url        = data.get("url", "?")
    pages      = data.get("pages_crawled", 0)
    total_vulns= data.get("total_vulns", 0)
    vuln_count = data.get("vuln_count", {})
    report_paths = data.get("report_paths", {})
    errors     = data.get("errors", 0)

    if RICH:
        console.print(Panel(
            f"[bold green]✅ SCAN TERMINÉ[/bold green]\n"
            f"URL     : {url}\n"
            f"Elapsed : {elapsed:.2f}s\n"
            f"Pages   : {pages}\n"
            f"Vulns   : {total_vulns}\n"
            f"Erreurs : {errors}",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 70)
        print(f"✅ SCAN TERMINÉ — {url}")
        print(f"   Elapsed : {elapsed:.2f}s | Pages : {pages} | Vulns : {total_vulns}")
        print("=" * 70)

    # Vulnérabilités
    if vuln_count:
        if RICH:
            vt = Table(title="⚡ Vulnérabilités", style="red")
            vt.add_column("Type")
            vt.add_column("Occurrences", justify="right")
            for vuln, count in sorted(vuln_count.items(), key=lambda x: -x[1]):
                vt.add_row(vuln, str(count))
            console.print(vt)
        else:
            print("\n⚡ Vulnérabilités :")
            for vuln, count in sorted(vuln_count.items(), key=lambda x: -x[1]):
                print(f"   ├─ {vuln:<25} : {count}")

    # Rapports
    if report_paths:
        if RICH:
            console.print("\n[bold green]📄 Rapports :[/bold green]")
            for fmt, url_path in report_paths.items():
                console.print(f"   • [cyan]{fmt.upper()}[/cyan] : {url_path}")
        else:
            print("\n📄 Rapports :")
            for fmt, url_path in report_paths.items():
                print(f"   ├─ {fmt.upper()} : {url_path}")
    print(data)

# =============================================================================
# FLOW PRINCIPAL
# =============================================================================

async def start_scan(session: aiohttp.ClientSession) -> str:
    """POST /api/start_scan → retourne scan_id."""
    body = {
        "pass_phrase":   PASS_PHRASE,
        "instance_args": INSTANCE_ARGS,
        "scan_args":     SCAN_ARGS,
    }

    log(f"\n[bold yellow]📤 POST {API_BASE}/start_scan...[/bold yellow]")

    async with session.post(f"{API_BASE}/start_scan", json=body) as resp:
        if resp.status != 200:
            text = await resp.text()
            raise Exception(f"start_scan failed {resp.status}: {text}")
        data = await resp.json()

    scan_id = data["scan_id"]
    log(f"[green]✅ Scan lancé — scan_id: {scan_id}[/green]")
    return scan_id


async def follow_scan(scan_id: str):
    """WS /api/ws_scan_status → stream jusqu'au résultat final."""
    ws_url = (
        f"ws://localhost:9000/api/ws_scan_status"
        f"?scan_id={scan_id}&pass_phrase={PASS_PHRASE}"
    )

    log(f"\n[bold yellow]🔌 Connexion WebSocket...[/bold yellow]")

    async with aiohttp.ClientSession() as ws_session:
        async with ws_session.ws_connect(ws_url) as ws:
            log("[green]✅ WebSocket connecté — en attente des logs...[/green]\n")

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except json.JSONDecodeError:
                        log(f"[dim]{msg.data}[/dim]")
                        continue

                    msg_type = payload.get("type", "")
                    message  = payload.get("message", "")

                    if msg_type == "log":
                        if message.startswith(f"[{scan_id}]"):
                            message = str(message).lstrip(f"[{scan_id}]")
                            log(f"[dim]{message}[/dim]")
                    
                    elif msg_type == "scan_info":
                        if isinstance(message, str) and message.startswith(f"[{scan_id}]"):
                            message = str(message).lstrip(f"[{scan_id}]")
                            log(f"[cyan]ℹ️  {message}[/cyan]")
                    
                    elif msg_type == "scan_result":
                        # Pas de filtre scan_id — c'est un dict, toujours le bon scan
                        log("\n[bold green]📦 Résultat reçu ![/bold green]")
                        print_result(message)
                        break
                    
                    elif msg_type == "scan_error":
                        if message.startswith(f"[{scan_id}]"):
                            message = str(message).lstrip(f"[{scan_id}]")
                            log(f"[red]❌ Erreur scan: {message}[/red]")
                            break
                    
                    elif msg_type == "scan_cancelled":
                        log("[yellow]⚠️  Scan annulé[/yellow]")
                        break

                    elif msg_type == "pong":
                        pass  # keepalive silencieux

                    else:
                        log(f"[dim][{msg_type}] {message}[/dim]")

                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log(f"[red]❌ WS error: {ws.exception()}[/red]")
                    break

                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break


async def main():
    print_header()

    async with aiohttp.ClientSession() as session:
        try:
            scan_id = await start_scan(session)
        except Exception as e:
            log(f"[red]❌ Impossible de lancer le scan: {e}[/red]")
            return

    await follow_scan(scan_id)


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":
    import nest_asyncio

    nest_asyncio.apply()
    asyncio.run(main())