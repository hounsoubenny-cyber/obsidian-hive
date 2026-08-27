#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Server-Side Template Injection (SSTI)                            ║
║   Port: 5016                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "SSTI_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Server-Side Template Injection Vulnerable Server",
        "port": 5016,
        "vuln_type": "SSTI",
        "endpoints": [
        "/greet?name=test",
        "/render?template=test",
        "/email?body=test",
        "/page?content=test",
        "/message?text=test",
        "/preview?tmpl=test",
        "/format?pattern=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Server-Side Template Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/greet')
def endpoint_greet():
    """Template greeting SSTI"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /greet: {name}"
    return response


@app.route('/render')
def endpoint_render():
    """Template render SSTI"""
    template = request.args.get('template', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /render: {template}"
    return response


@app.route('/email')
def endpoint_email():
    """Email template SSTI"""
    body = request.args.get('body', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /email: {body}"
    return response


@app.route('/page')
def endpoint_page():
    """Page render SSTI"""
    content = request.args.get('content', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /page: {content}"
    return response


@app.route('/message')
def endpoint_message():
    """Message SSTI"""
    text = request.args.get('text', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /message: {text}"
    return response


@app.route('/preview')
def endpoint_preview():
    """Preview SSTI"""
    tmpl = request.args.get('tmpl', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /preview: {tmpl}"
    return response


@app.route('/format')
def endpoint_format():
    """Format string SSTI"""
    pattern = request.args.get('pattern', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SSTI - /format: {pattern}"
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
    print("🔥 Server-Side Template Injection (SSTI) Vulnerable Server starting on port 5016...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5016, debug=False)
