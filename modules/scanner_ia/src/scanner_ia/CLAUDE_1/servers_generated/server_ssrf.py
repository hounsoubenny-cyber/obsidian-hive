#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Server-Side Request Forgery (SSRF)                            ║
║   Port: 5015                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "SSRF_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Server-Side Request Forgery Vulnerable Server",
        "port": 5015,
        "vuln_type": "SSRF",
        "endpoints": [
        "/fetch?url=test",
        "/proxy?target=test",
        "/webhook?callback=test",
        "/image?url=test",
        "/preview?link=test",
        "/avatar?url=test",
        "/import?url=test",
        "/load?resource=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Server-Side Request Forgery
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/fetch')
def endpoint_fetch():
    """URL fetch SSRF"""
    url = request.args.get('url', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /fetch: {url}"
    return response


@app.route('/proxy')
def endpoint_proxy():
    """Proxy SSRF"""
    target = request.args.get('target', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /proxy: {target}"
    return response


@app.route('/webhook')
def endpoint_webhook():
    """Webhook SSRF"""
    callback = request.args.get('callback', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /webhook: {callback}"
    return response


@app.route('/image')
def endpoint_image():
    """Image fetch SSRF"""
    url = request.args.get('url', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /image: {url}"
    return response


@app.route('/preview')
def endpoint_preview():
    """Link preview SSRF"""
    link = request.args.get('link', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /preview: {link}"
    return response


@app.route('/avatar')
def endpoint_avatar():
    """Avatar SSRF"""
    url = request.args.get('url', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /avatar: {url}"
    return response


@app.route('/import')
def endpoint_import():
    """Import SSRF"""
    url = request.args.get('url', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /import: {url}"
    return response


@app.route('/load')
def endpoint_load():
    """Resource load SSRF"""
    resource = request.args.get('resource', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSRF - /load: {resource}"
    return response


# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS SAFE (pour équilibrer dataset)
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/safe1')
def safe1():
    """Endpoint safe avec validation"""
    data = request.args.get('data', 'default')
    # Sécurisé: validation stricte
    import re
    safe_data = re.sub(r'[^a-zA-Z0-9]', '', data)[:50]
    return jsonify({"status": "safe", "data": safe_data})

@app.route('/safe2')
def safe2():
    """Endpoint safe - JSON only"""
    value = request.args.get('value', '')
    # Sécurisé: pas de réflexion directe
    return jsonify({"status": "ok", "length": len(value)})

if __name__ == '__main__':
    print("🔥 Server-Side Request Forgery (SSRF) Vulnerable Server starting on port 5015...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5015, debug=False)
