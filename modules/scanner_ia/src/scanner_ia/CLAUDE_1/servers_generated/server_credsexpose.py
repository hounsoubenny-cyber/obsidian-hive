#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Credentials Exposure (CredsExpose)                            ║
║   Port: 5004                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "CredsExpose_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Credentials Exposure Vulnerable Server",
        "port": 5004,
        "vuln_type": "CredsExpose",
        "endpoints": [
        "/.env",
        "/config.json",
        "/database.yml",
        "/secrets.yml",
        "/id_rsa",
        "/.git/config",
        "/backup.sql",
        "/credentials.json",
        "/.aws/credentials",
        "/phpinfo.php",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Credentials Exposure
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/.env')
def endpoint_env():
    """Exposed .env file"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /.env: Vulnerable endpoint"
    return response


@app.route('/config.json')
def endpoint_config_json():
    """Exposed config"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /config.json: Vulnerable endpoint"
    return response


@app.route('/database.yml')
def endpoint_database_yml():
    """Database credentials"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /database.yml: Vulnerable endpoint"
    return response


@app.route('/secrets.yml')
def endpoint_secrets_yml():
    """Secrets file"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /secrets.yml: Vulnerable endpoint"
    return response


@app.route('/id_rsa')
def endpoint_id_rsa():
    """SSH private key"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /id_rsa: Vulnerable endpoint"
    return response


@app.route('/.git/config')
def endpoint_git_config():
    """Git config"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /.git/config: Vulnerable endpoint"
    return response


@app.route('/backup.sql')
def endpoint_backup_sql():
    """SQL backup"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /backup.sql: Vulnerable endpoint"
    return response


@app.route('/credentials.json')
def endpoint_credentials_json():
    """Credentials JSON"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /credentials.json: Vulnerable endpoint"
    return response


@app.route('/.aws/credentials')
def endpoint_aws_credentials():
    """AWS credentials"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /.aws/credentials: Vulnerable endpoint"
    return response


@app.route('/phpinfo.php')
def endpoint_phpinfo_php():
    """PHPInfo exposure"""
    # No parameters
    # Vulnérable: reflète le payload sans validation
    response = f"CredsExpose - /phpinfo.php: Vulnerable endpoint"
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
    print("🔥 Credentials Exposure (CredsExpose) Vulnerable Server starting on port 5004...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5004, debug=False)
