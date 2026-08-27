#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Session Fixation (SessFix)                            ║
║   Port: 5017                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "SessFix_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Session Fixation Vulnerable Server",
        "port": 5017,
        "vuln_type": "SessFix",
        "endpoints": [
        "/login?sessionid=test",
        "/auth?sid=test",
        "/session/set?id=test",
        "/token?session=test",
        "/fixate?sessid=test",
        "/setsession?id=test",
        "/auth/session?sid=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Session Fixation
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/login')
def endpoint_login():
    """Session fixation login"""
    sessionid = request.args.get('sessionid', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /login: {sessionid}"
    return response


@app.route('/auth')
def endpoint_auth():
    """Auth session fixation"""
    sid = request.args.get('sid', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /auth: {sid}"
    return response


@app.route('/session/set')
def endpoint_session_set():
    """Set session ID"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /session/set: {id}"
    return response


@app.route('/token')
def endpoint_token():
    """Token session fixation"""
    session = request.args.get('session', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /token: {session}"
    return response


@app.route('/fixate')
def endpoint_fixate():
    """Session fixation"""
    sessid = request.args.get('sessid', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /fixate: {sessid}"
    return response


@app.route('/setsession')
def endpoint_setsession():
    """Set session"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /setsession: {id}"
    return response


@app.route('/auth/session')
def endpoint_auth_session():
    """Auth with session"""
    sid = request.args.get('sid', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SessFix - /auth/session: {sid}"
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
    print("🔥 Session Fixation (SessFix) Vulnerable Server starting on port 5017...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5017, debug=False)
