#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Buffer Overflow (BufOvr)                            ║
║   Port: 5001                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "BufOvr_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Buffer Overflow Vulnerable Server",
        "port": 5001,
        "vuln_type": "BufOvr",
        "endpoints": [
        "/format?data=test",
        "/input?text=test",
        "/header",
        "/sprintf?str=test",
        "/copy?src=test",
        "/overflow?buffer=test",
        "/stack?value=test",
        "/heap?size=test",
        "/boundary?index=test",
        "/printf?format=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Buffer Overflow
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/format')
def endpoint_format():
    """Format string vulnerability"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /format: {data}"
    return response


@app.route('/input')
def endpoint_input():
    """Input buffer overflow"""
    text = request.args.get('text', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /input: {text}"
    return response


@app.route('/header')
def endpoint_header():
    """Header buffer overflow"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /header: Vulnerable endpoint"
    return response


@app.route('/sprintf')
def endpoint_sprintf():
    """sprintf-like vulnerability"""
    str = request.args.get('str', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /sprintf: {str}"
    return response


@app.route('/copy')
def endpoint_copy():
    """strcpy-like overflow"""
    src = request.args.get('src', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /copy: {src}"
    return response


@app.route('/overflow')
def endpoint_overflow():
    """Buffer overflow"""
    buffer = request.args.get('buffer', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /overflow: {buffer}"
    return response


@app.route('/stack')
def endpoint_stack():
    """Stack buffer overflow"""
    value = request.args.get('value', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /stack: {value}"
    return response


@app.route('/heap')
def endpoint_heap():
    """Heap overflow"""
    size = request.args.get('size', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /heap: {size}"
    return response


@app.route('/boundary')
def endpoint_boundary():
    """Boundary check"""
    index = request.args.get('index', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /boundary: {index}"
    return response


@app.route('/printf')
def endpoint_printf():
    """Printf format string"""
    format = request.args.get('format', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"BufOvr - /printf: {format}"
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
    print("🔥 Buffer Overflow (BufOvr) Vulnerable Server starting on port 5001...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5001, debug=False)
