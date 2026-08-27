#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - XML External Entity (XXE)                            ║
║   Port: 5019                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "XXE_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "XML External Entity Vulnerable Server",
        "port": 5019,
        "vuln_type": "XXE",
        "endpoints": [
        "/xml/parse?xml=test",
        "/xml/upload",
        "/xml/import?data=test",
        "/xml/process?xml=test",
        "/soap?request=test",
        "/rss?feed=test",
        "/xml/read?file=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - XML External Entity
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/xml/parse')
def endpoint_xml_parse():
    """XML parse XXE"""
    xml = request.args.get('xml', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /xml/parse: {xml}"
    return response


@app.route('/xml/upload')
def endpoint_xml_upload():
    """XML upload XXE"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /xml/upload: Vulnerable endpoint"
    return response


@app.route('/xml/import')
def endpoint_xml_import():
    """XML import XXE"""
    data = request.args.get('data', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /xml/import: {data}"
    return response


@app.route('/xml/process')
def endpoint_xml_process():
    """XML process XXE"""
    xml = request.args.get('xml', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /xml/process: {xml}"
    return response


@app.route('/soap')
def endpoint_soap():
    """SOAP XXE"""
    request = request.args.get('request', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /soap: {request}"
    return response


@app.route('/rss')
def endpoint_rss():
    """RSS XXE"""
    feed = request.args.get('feed', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /rss: {feed}"
    return response


@app.route('/xml/read')
def endpoint_xml_read():
    """XML read XXE"""
    file = request.args.get('file', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"XXE - /xml/read: {file}"
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
    print("🔥 XML External Entity (XXE) Vulnerable Server starting on port 5019...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5019, debug=False)
