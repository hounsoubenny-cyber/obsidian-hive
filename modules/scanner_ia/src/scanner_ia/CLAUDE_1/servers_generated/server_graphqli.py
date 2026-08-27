#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - GraphQL Injection (GraphQLi)                            ║
║   Port: 5006                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "GraphQLi_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "GraphQL Injection Vulnerable Server",
        "port": 5006,
        "vuln_type": "GraphQLi",
        "endpoints": [
        "/graphql?query=test",
        "/graphql/batch?queries=test",
        "/api/graphql?mutation=test",
        "/gql?q=test",
        "/graphql/playground",
        "/graphql/introspection",
        "/api/gql?operation=test",
        "/query?gql=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - GraphQL Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/graphql')
def endpoint_graphql():
    """GraphQL query injection"""
    query = request.args.get('query', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /graphql: {query}"
    return response


@app.route('/graphql/batch')
def endpoint_graphql_batch():
    """Batch query injection"""
    queries = request.args.get('queries', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /graphql/batch: {queries}"
    return response


@app.route('/api/graphql')
def endpoint_api_graphql():
    """Mutation injection"""
    mutation = request.args.get('mutation', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /api/graphql: {mutation}"
    return response


@app.route('/gql')
def endpoint_gql():
    """GraphQL endpoint"""
    q = request.args.get('q', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /gql: {q}"
    return response


@app.route('/graphql/playground')
def endpoint_graphql_playground():
    """GraphQL playground"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /graphql/playground: Vulnerable endpoint"
    return response


@app.route('/graphql/introspection')
def endpoint_graphql_introspection():
    """Introspection enabled"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /graphql/introspection: Vulnerable endpoint"
    return response


@app.route('/api/gql')
def endpoint_api_gql():
    """GraphQL operation"""
    operation = request.args.get('operation', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /api/gql: {operation}"
    return response


@app.route('/query')
def endpoint_query():
    """Direct GraphQL query"""
    gql = request.args.get('gql', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"GraphQLi - /query: {gql}"
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
    print("🔥 GraphQL Injection (GraphQLi) Vulnerable Server starting on port 5006...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5006, debug=False)
