#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Information Disclosure (InfoDisc)                            ║
║   Port: 5007                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "InfoDisc_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Information Disclosure Vulnerable Server",
        "port": 5007,
        "vuln_type": "InfoDisc",
        "endpoints": [
        "/debug",
        "/error?msg=test",
        "/trace",
        "/version",
        "/info",
        "/status",
        "/health",
        "/metrics",
        "/logs",
        "/env",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Information Disclosure
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/debug')
def endpoint_debug():
    """Debug information"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /debug: Vulnerable endpoint"
    return response


@app.route('/error')
def endpoint_error():
    """Error details exposure"""
    msg = request.args.get('msg', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /error: {msg}"
    return response


@app.route('/trace')
def endpoint_trace():
    """Stack trace exposure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /trace: Vulnerable endpoint"
    return response


@app.route('/version')
def endpoint_version():
    """Version disclosure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /version: Vulnerable endpoint"
    return response


@app.route('/info')
def endpoint_info():
    """System information"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /info: Vulnerable endpoint"
    return response


@app.route('/status')
def endpoint_status():
    """Status disclosure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /status: Vulnerable endpoint"
    return response


@app.route('/health')
def endpoint_health():
    """Health check details"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /health: Vulnerable endpoint"
    return response


@app.route('/metrics')
def endpoint_metrics():
    """Metrics exposure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /metrics: Vulnerable endpoint"
    return response


@app.route('/logs')
def endpoint_logs():
    """Logs exposure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /logs: Vulnerable endpoint"
    return response


@app.route('/env')
def endpoint_env():
    """Environment variables"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InfoDisc - /env: Vulnerable endpoint"
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
    print("🔥 Information Disclosure (InfoDisc) Vulnerable Server starting on port 5007...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5007, debug=False)
