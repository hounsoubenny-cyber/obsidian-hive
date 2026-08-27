#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Cross-Site Scripting (XSS)                            ║
║   Port: 5018                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "XSS_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Cross-Site Scripting Vulnerable Server",
        "port": 5018,
        "vuln_type": "XSS",
        "endpoints": [
        "/reflected?q=test",
        "/search?query=test",
        "/comment?text=test",
        "/profile?name=test",
        "/message?msg=test",
        "/input?data=test",
        "/form?value=test",
        "/display?content=test",
        "/echo?text=test",
        "/render?html=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Cross-Site Scripting
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/reflected')
def endpoint_reflected():
    """Reflected XSS"""
    q = request.args.get('q', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /reflected: {q}"
    return response


@app.route('/search')
def endpoint_search():
    """Search XSS"""
    query = request.args.get('query', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /search: {query}"
    return response


@app.route('/comment')
def endpoint_comment():
    """Comment XSS"""
    text = request.args.get('text', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /comment: {text}"
    return response


@app.route('/profile')
def endpoint_profile():
    """Profile XSS"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /profile: {name}"
    return response


@app.route('/message')
def endpoint_message():
    """Message XSS"""
    msg = request.args.get('msg', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /message: {msg}"
    return response


@app.route('/input')
def endpoint_input():
    """Input XSS"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /input: {data}"
    return response


@app.route('/form')
def endpoint_form():
    """Form XSS"""
    value = request.args.get('value', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /form: {value}"
    return response


@app.route('/display')
def endpoint_display():
    """Display XSS"""
    content = request.args.get('content', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /display: {content}"
    return response


@app.route('/echo')
def endpoint_echo():
    """Echo XSS"""
    text = request.args.get('text', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /echo: {text}"
    return response


@app.route('/render')
def endpoint_render():
    """Render XSS"""
    html = request.args.get('html', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XSS - /render: {html}"
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
    print("🔥 Cross-Site Scripting (XSS) Vulnerable Server starting on port 5018...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5018, debug=False)
