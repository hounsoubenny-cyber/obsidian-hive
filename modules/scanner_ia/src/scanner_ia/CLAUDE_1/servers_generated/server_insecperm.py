#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Insecure Permissions (InsecPerm)                            ║
║   Port: 5009                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "InsecPerm_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Insecure Permissions Vulnerable Server",
        "port": 5009,
        "vuln_type": "InsecPerm",
        "endpoints": [
        "/admin",
        "/api/users?id=test",
        "/api/admin",
        "/dashboard",
        "/config",
        "/settings",
        "/users",
        "/delete?id=test",
        "/edit?id=test",
        "/manage",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Insecure Permissions
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/admin')
def endpoint_admin():
    """Admin without auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /admin: Vulnerable endpoint"
    return response


@app.route('/api/users')
def endpoint_api_users():
    """User data no auth"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /api/users: {id}"
    return response


@app.route('/api/admin')
def endpoint_api_admin():
    """Admin API no auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /api/admin: Vulnerable endpoint"
    return response


@app.route('/dashboard')
def endpoint_dashboard():
    """Dashboard no auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /dashboard: Vulnerable endpoint"
    return response


@app.route('/config')
def endpoint_config():
    """Config access"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /config: Vulnerable endpoint"
    return response


@app.route('/settings')
def endpoint_settings():
    """Settings no auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /settings: Vulnerable endpoint"
    return response


@app.route('/users')
def endpoint_users():
    """Users list no auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /users: Vulnerable endpoint"
    return response


@app.route('/delete')
def endpoint_delete():
    """Delete no auth"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /delete: {id}"
    return response


@app.route('/edit')
def endpoint_edit():
    """Edit no auth"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /edit: {id}"
    return response


@app.route('/manage')
def endpoint_manage():
    """Management no auth"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"InsecPerm - /manage: Vulnerable endpoint"
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
    print("🔥 Insecure Permissions (InsecPerm) Vulnerable Server starting on port 5009...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5009, debug=False)
