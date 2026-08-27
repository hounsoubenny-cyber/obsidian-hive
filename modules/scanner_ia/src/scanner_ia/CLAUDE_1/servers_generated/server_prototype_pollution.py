#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Prototype Pollution (Prototype_Pollution)                            ║
║   Port: 5012                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "Prototype_Pollution_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Prototype Pollution Vulnerable Server",
        "port": 5012,
        "vuln_type": "Prototype_Pollution",
        "endpoints": [
        "/merge?obj=test",
        "/extend?props=test",
        "/assign?data=test",
        "/clone?object=test",
        "/parse?json=test",
        "/update?fields=test",
        "/set?key=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Prototype Pollution
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/merge')
def endpoint_merge():
    """Object merge pollution"""
    obj = request.args.get('obj', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /merge: {obj}"
    return response


@app.route('/extend')
def endpoint_extend():
    """Extend pollution"""
    props = request.args.get('props', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /extend: {props}"
    return response


@app.route('/assign')
def endpoint_assign():
    """Object assign"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /assign: {data}"
    return response


@app.route('/clone')
def endpoint_clone():
    """Clone pollution"""
    object = request.args.get('object', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /clone: {object}"
    return response


@app.route('/parse')
def endpoint_parse():
    """JSON parse pollution"""
    json = request.args.get('json', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /parse: {json}"
    return response


@app.route('/update')
def endpoint_update():
    """Update pollution"""
    fields = request.args.get('fields', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /update: {fields}"
    return response


@app.route('/set')
def endpoint_set():
    """Property set pollution"""
    key = request.args.get('key', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"Prototype_Pollution - /set: {key}"
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
    print("🔥 Prototype Pollution (Prototype_Pollution) Vulnerable Server starting on port 5012...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5012, debug=False)
