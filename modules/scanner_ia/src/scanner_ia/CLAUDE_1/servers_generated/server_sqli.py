#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - SQL Injection (SQLi)                            ║
║   Port: 5014                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "SQLi_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "SQL Injection Vulnerable Server",
        "port": 5014,
        "vuln_type": "SQLi",
        "endpoints": [
        "/login?username=test",
        "/search?q=test",
        "/user?id=test",
        "/product?pid=test",
        "/query?sql=test",
        "/filter?where=test",
        "/order?sort=test",
        "/union?id=test",
        "/blind?id=test",
        "/time?id=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - SQL Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/login')
def endpoint_login():
    """SQL login bypass"""
    username = request.args.get('username', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /login: {username}"
    return response


@app.route('/search')
def endpoint_search():
    """SQL search injection"""
    q = request.args.get('q', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /search: {q}"
    return response


@app.route('/user')
def endpoint_user():
    """SQL user injection"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /user: {id}"
    return response


@app.route('/product')
def endpoint_product():
    """SQL product injection"""
    pid = request.args.get('pid', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /product: {pid}"
    return response


@app.route('/query')
def endpoint_query():
    """Direct SQL injection"""
    sql = request.args.get('sql', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /query: {sql}"
    return response


@app.route('/filter')
def endpoint_filter():
    """SQL filter injection"""
    where = request.args.get('where', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /filter: {where}"
    return response


@app.route('/order')
def endpoint_order():
    """SQL order injection"""
    sort = request.args.get('sort', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /order: {sort}"
    return response


@app.route('/union')
def endpoint_union():
    """UNION-based SQLi"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /union: {id}"
    return response


@app.route('/blind')
def endpoint_blind():
    """Blind SQLi"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /blind: {id}"
    return response


@app.route('/time')
def endpoint_time():
    """Time-based SQLi"""
    id = request.args.get('id', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"SQLi - /time: {id}"
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
    print("🔥 SQL Injection (SQLi) Vulnerable Server starting on port 5014...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5014, debug=False)
