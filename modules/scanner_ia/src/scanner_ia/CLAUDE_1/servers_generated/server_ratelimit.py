#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Rate Limiting Issues (RateLimit)                            ║
║   Port: 5013                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "RateLimit_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Rate Limiting Issues Vulnerable Server",
        "port": 5013,
        "vuln_type": "RateLimit",
        "endpoints": [
        "/api/endpoint",
        "/login?username=test",
        "/register?email=test",
        "/otp?code=test",
        "/reset?email=test",
        "/api/data",
        "/download?file=test",
        "/upload",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Rate Limiting Issues
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/api/endpoint')
def endpoint_api_endpoint():
    """No rate limit"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /api/endpoint: Vulnerable endpoint"
    return response


@app.route('/login')
def endpoint_login():
    """Login no rate limit"""
    username = request.args.get('username', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /login: {username}"
    return response


@app.route('/register')
def endpoint_register():
    """Register no limit"""
    email = request.args.get('email', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /register: {email}"
    return response


@app.route('/otp')
def endpoint_otp():
    """OTP no rate limit"""
    code = request.args.get('code', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /otp: {code}"
    return response


@app.route('/reset')
def endpoint_reset():
    """Password reset no limit"""
    email = request.args.get('email', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /reset: {email}"
    return response


@app.route('/api/data')
def endpoint_api_data():
    """Data API no limit"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /api/data: Vulnerable endpoint"
    return response


@app.route('/download')
def endpoint_download():
    """Download no limit"""
    file = request.args.get('file', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /download: {file}"
    return response


@app.route('/upload')
def endpoint_upload():
    """Upload no limit"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"RateLimit - /upload: Vulnerable endpoint"
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
    print("🔥 Rate Limiting Issues (RateLimit) Vulnerable Server starting on port 5013...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5013, debug=False)
