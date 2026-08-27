#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Insecure Deserialization (InsecDeser)                            ║
║   Port: 5008                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "InsecDeser_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Insecure Deserialization Vulnerable Server",
        "port": 5008,
        "vuln_type": "InsecDeser",
        "endpoints": [
        "/deserialize?data=test",
        "/pickle?obj=test",
        "/unmarshal?payload=test",
        "/unserialize?input=test",
        "/load?object=test",
        "/restore?state=test",
        "/decode?encoded=test",
        "/parse?serialized=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Insecure Deserialization
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/deserialize')
def endpoint_deserialize():
    """Unsafe deserialization"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /deserialize: {data}"
    return response


@app.route('/pickle')
def endpoint_pickle():
    """Pickle deserialization"""
    obj = request.args.get('obj', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /pickle: {obj}"
    return response


@app.route('/unmarshal')
def endpoint_unmarshal():
    """Unmarshal injection"""
    payload = request.args.get('payload', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /unmarshal: {payload}"
    return response


@app.route('/unserialize')
def endpoint_unserialize():
    """PHP unserialize"""
    input = request.args.get('input', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /unserialize: {input}"
    return response


@app.route('/load')
def endpoint_load():
    """Object load"""
    object = request.args.get('object', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /load: {object}"
    return response


@app.route('/restore')
def endpoint_restore():
    """State restoration"""
    state = request.args.get('state', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /restore: {state}"
    return response


@app.route('/decode')
def endpoint_decode():
    """Decode serialized"""
    encoded = request.args.get('encoded', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /decode: {encoded}"
    return response


@app.route('/parse')
def endpoint_parse():
    """Parse serialized data"""
    serialized = request.args.get('serialized', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"InsecDeser - /parse: {serialized}"
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
    print("🔥 Insecure Deserialization (InsecDeser) Vulnerable Server starting on port 5008...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5008, debug=False)
