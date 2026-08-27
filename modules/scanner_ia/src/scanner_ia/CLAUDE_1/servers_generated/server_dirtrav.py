#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Directory Traversal (DirTrav)                            ║
║   Port: 5005                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "DirTrav_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Directory Traversal Vulnerable Server",
        "port": 5005,
        "vuln_type": "DirTrav",
        "endpoints": [
        "/read?file=test",
        "/download?path=test",
        "/include?page=test",
        "/load?template=test",
        "/view?doc=test",
        "/get?resource=test",
        "/fetch?file=test",
        "/static?path=test",
        "/assets?name=test",
        "/image?img=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Directory Traversal
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/read')
def endpoint_read():
    """File read via traversal"""
    file = request.args.get('file', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /read: {file}"
    return response


@app.route('/download')
def endpoint_download():
    """Download with traversal"""
    path = request.args.get('path', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /download: {path}"
    return response


@app.route('/include')
def endpoint_include():
    """Include file traversal"""
    page = request.args.get('page', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /include: {page}"
    return response


@app.route('/load')
def endpoint_load():
    """Template traversal"""
    template = request.args.get('template', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /load: {template}"
    return response


@app.route('/view')
def endpoint_view():
    """Document view traversal"""
    doc = request.args.get('doc', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /view: {doc}"
    return response


@app.route('/get')
def endpoint_get():
    """Resource get traversal"""
    resource = request.args.get('resource', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /get: {resource}"
    return response


@app.route('/fetch')
def endpoint_fetch():
    """Fetch file traversal"""
    file = request.args.get('file', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /fetch: {file}"
    return response


@app.route('/static')
def endpoint_static():
    """Static file traversal"""
    path = request.args.get('path', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /static: {path}"
    return response


@app.route('/assets')
def endpoint_assets():
    """Assets traversal"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /assets: {name}"
    return response


@app.route('/image')
def endpoint_image():
    """Image traversal"""
    img = request.args.get('img', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"DirTrav - /image: {img}"
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
    print("🔥 Directory Traversal (DirTrav) Vulnerable Server starting on port 5005...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5005, debug=False)
