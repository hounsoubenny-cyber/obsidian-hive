#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - JWT Vulnerabilities (JWT)                            ║
║   Port: 5010                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "JWT_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "JWT Vulnerabilities Vulnerable Server",
        "port": 5010,
        "vuln_type": "JWT",
        "endpoints": [
        "/jwt/login?username=test",
        "/jwt/decode?token=test",
        "/jwt/verify?jwt=test",
        "/jwt/none?token=test",
        "/jwt/weak",
        "/auth/token?user=test",
        "/api/jwt?token=test",
        "/verify?jwt=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - JWT Vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/jwt/login')
def endpoint_jwt_login():
    """JWT weak secret"""
    username = request.args.get('username', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /jwt/login: {username}"
    return response


@app.route('/jwt/decode')
def endpoint_jwt_decode():
    """JWT decode"""
    token = request.args.get('token', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /jwt/decode: {token}"
    return response


@app.route('/jwt/verify')
def endpoint_jwt_verify():
    """JWT verification bypass"""
    jwt = request.args.get('jwt', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /jwt/verify: {jwt}"
    return response


@app.route('/jwt/none')
def endpoint_jwt_none():
    """Algorithm none"""
    token = request.args.get('token', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /jwt/none: {token}"
    return response


@app.route('/jwt/weak')
def endpoint_jwt_weak():
    """Weak JWT secret"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /jwt/weak: Vulnerable endpoint"
    return response


@app.route('/auth/token')
def endpoint_auth_token():
    """Token generation"""
    user = request.args.get('user', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /auth/token: {user}"
    return response


@app.route('/api/jwt')
def endpoint_api_jwt():
    """JWT API"""
    token = request.args.get('token', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /api/jwt: {token}"
    return response


@app.route('/verify')
def endpoint_verify():
    """Token verification"""
    jwt = request.args.get('jwt', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"JWT - /verify: {jwt}"
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
    print("🔥 JWT Vulnerabilities (JWT) Vulnerable Server starting on port 5010...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5010, debug=False)
