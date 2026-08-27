#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - Command Injection (CMDi)                            ║
║   Port: 5002                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "CMDi_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({
        "server": "Command Injection Vulnerable Server",
        "port": 5002,
        "vuln_type": "CMDi",
        "endpoints": [
        "/ping?host=test",
        "/exec?cmd=test",
        "/system?command=test",
        "/lookup?domain=test",
        "/shell?input=test",
        "/run?script=test",
        "/execute?prog=test",
        "/cmd?action=test",
        "/process?name=test",
        "/tool?util=test",
        "/safe1",
        "/safe2"
]
    })

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - Command Injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route('/ping')
def endpoint_ping():
    """OS command injection via ping"""
    host = request.args.get('host', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /ping: {host}"
    return response


@app.route('/exec')
def endpoint_exec():
    """Direct command execution"""
    cmd = request.args.get('cmd', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /exec: {cmd}"
    return response


@app.route('/system')
def endpoint_system():
    """System call injection"""
    command = request.args.get('command', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /system: {command}"
    return response


@app.route('/lookup')
def endpoint_lookup():
    """DNS lookup injection"""
    domain = request.args.get('domain', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /lookup: {domain}"
    return response


@app.route('/shell')
def endpoint_shell():
    """Shell command injection"""
    input = request.args.get('input', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /shell: {input}"
    return response


@app.route('/run')
def endpoint_run():
    """Script execution"""
    script = request.args.get('script', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /run: {script}"
    return response


@app.route('/execute')
def endpoint_execute():
    """Program execution"""
    prog = request.args.get('prog', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /execute: {prog}"
    return response


@app.route('/cmd')
def endpoint_cmd():
    """Windows cmd injection"""
    action = request.args.get('action', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /cmd: {action}"
    return response


@app.route('/process')
def endpoint_process():
    """Process spawn injection"""
    name = request.args.get('name', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /process: {name}"
    return response


@app.route('/tool')
def endpoint_tool():
    """Tool execution injection"""
    util = request.args.get('util', 'default')
    # Vulnérable: reflète le payload sans validation
    response = f"CMDi - /tool: {util}"
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
    print("🔥 Command Injection (CMDi) Vulnerable Server starting on port 5002...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port=5002, debug=False)
