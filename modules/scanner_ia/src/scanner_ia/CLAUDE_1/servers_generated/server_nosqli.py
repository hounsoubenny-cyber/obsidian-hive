#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - NoSQL Injection (NoSQLi)                            ║
║   Port: 5011                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "NoSQLi_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "NoSQL Injection Vulnerable Server",
        "port": 5011,
        "vuln_type": "NoSQLi",
        "endpoints": [
        "/nosql/login?username=test",
        "/nosql/search?query=test",
        "/nosql/find?filter=test",
        "/mongo/query?q=test",
        "/api/search?term=test",
        "/find?criteria=test",
        "/filter?condition=test",
        "/query?nosql=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - NoSQL Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/nosql/login')
def endpoint_nosql_login():
    """NoSQL login bypass"""
    username = request.args.get('username', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /nosql/login: {username}"
    return response


@app.route('/nosql/search')
def endpoint_nosql_search():
    """NoSQL search injection"""
    query = request.args.get('query', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /nosql/search: {query}"
    return response


@app.route('/nosql/find')
def endpoint_nosql_find():
    """NoSQL find injection"""
    filter = request.args.get('filter', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /nosql/find: {filter}"
    return response


@app.route('/mongo/query')
def endpoint_mongo_query():
    """MongoDB injection"""
    q = request.args.get('q', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /mongo/query: {q}"
    return response


@app.route('/api/search')
def endpoint_api_search():
    """NoSQL search"""
    term = request.args.get('term', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /api/search: {term}"
    return response


@app.route('/find')
def endpoint_find():
    """Find injection"""
    criteria = request.args.get('criteria', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /find: {criteria}"
    return response


@app.route('/filter')
def endpoint_filter():
    """Filter injection"""
    condition = request.args.get('condition', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /filter: {condition}"
    return response


@app.route('/query')
def endpoint_query():
    """NoSQL query"""
    nosql = request.args.get('nosql', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"NoSQLi - /query: {nosql}"
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
    print("🔥 NoSQL Injection (NoSQLi) Vulnerable Server starting on port 5011...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5011, debug=False)
