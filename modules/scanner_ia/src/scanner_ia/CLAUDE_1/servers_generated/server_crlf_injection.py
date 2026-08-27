#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - CRLF Injection (CRLF_Injection)                            ║
║   Port: 5003                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "CRLF_Injection_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "CRLF Injection Vulnerable Server",
        "port": 5003,
        "vuln_type": "CRLF_Injection",
        "endpoints": [
        "/header?name=test",
        "/redirect?url=test",
        "/log?data=test",
        "/response?value=test",
        "/cookie?name=test",
        "/location?path=test",
        "/cache?control=test",
        "/setcookie?value=test",
        "/custom?header=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - CRLF Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/header')
def endpoint_header():
    """CRLF in custom header"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /header: {name}"
    return response


@app.route('/redirect')
def endpoint_redirect():
    """CRLF in redirect"""
    url = request.args.get('url', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /redirect: {url}"
    return response


@app.route('/log')
def endpoint_log():
    """CRLF in logging"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /log: {data}"
    return response


@app.route('/response')
def endpoint_response():
    """CRLF in response"""
    value = request.args.get('value', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /response: {value}"
    return response


@app.route('/cookie')
def endpoint_cookie():
    """CRLF in Set-Cookie"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /cookie: {name}"
    return response


@app.route('/location')
def endpoint_location():
    """CRLF in Location"""
    path = request.args.get('path', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /location: {path}"
    return response


@app.route('/cache')
def endpoint_cache():
    """CRLF in Cache-Control"""
    control = request.args.get('control', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /cache: {control}"
    return response


@app.route('/setcookie')
def endpoint_setcookie():
    """CRLF via cookie value"""
    value = request.args.get('value', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /setcookie: {value}"
    return response


@app.route('/custom')
def endpoint_custom():
    """CRLF in custom header"""
    header = request.args.get('header', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CRLF_Injection - /custom: {header}"
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
    print("🔥 CRLF Injection (CRLF_Injection) Vulnerable Server starting on port 5003...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5003, debug=False)
