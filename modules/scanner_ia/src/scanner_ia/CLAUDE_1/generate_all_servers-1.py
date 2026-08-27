#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   MASTER GENERATOR - SERVEURS VULNÉRABLES                                   ║
║   Génère automatiquement 20 serveurs Flask (19 vulns + 1 safe)              ║
║   Pour génération dataset ShieldAI V2                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   Usage: python generate_all_servers.py                                     ║
║   Output: 20 fichiers server_*.py dans ./servers/                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import json

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION - 19 VULNÉRABILITÉS
# ══════════════════════════════════════════════════════════════════════════════

VULNS_CONFIG = {
    "BufOvr": {
        "port": 5001,
        "full_name": "Buffer Overflow",
        "endpoints": [
            {"path": "/format", "params": "data", "desc": "Format string vulnerability"},
            {"path": "/input", "params": "text", "desc": "Input buffer overflow"},
            {"path": "/header", "params": None, "desc": "Header buffer overflow"},
            {"path": "/sprintf", "params": "str", "desc": "sprintf-like vulnerability"},
            {"path": "/copy", "params": "src", "desc": "strcpy-like overflow"},
            {"path": "/overflow", "params": "buffer", "desc": "Buffer overflow"},
            {"path": "/stack", "params": "value", "desc": "Stack buffer overflow"},
            {"path": "/heap", "params": "size", "desc": "Heap overflow"},
            {"path": "/boundary", "params": "index", "desc": "Boundary check"},
            {"path": "/printf", "params": "format", "desc": "Printf format string"},
        ]
    },
    
    "CMDi": {
        "port": 5002,
        "full_name": "Command Injection",
        "endpoints": [
            {"path": "/ping", "params": "host", "desc": "OS command injection via ping"},
            {"path": "/exec", "params": "cmd", "desc": "Direct command execution"},
            {"path": "/system", "params": "command", "desc": "System call injection"},
            {"path": "/lookup", "params": "domain", "desc": "DNS lookup injection"},
            {"path": "/shell", "params": "input", "desc": "Shell command injection"},
            {"path": "/run", "params": "script", "desc": "Script execution"},
            {"path": "/execute", "params": "prog", "desc": "Program execution"},
            {"path": "/cmd", "params": "action", "desc": "Windows cmd injection"},
            {"path": "/process", "params": "name", "desc": "Process spawn injection"},
            {"path": "/tool", "params": "util", "desc": "Tool execution injection"},
        ]
    },
    
    "CRLF_Injection": {
        "port": 5003,
        "full_name": "CRLF Injection",
        "endpoints": [
            {"path": "/header", "params": "name", "desc": "CRLF in custom header"},
            {"path": "/redirect", "params": "url", "desc": "CRLF in redirect"},
            {"path": "/log", "params": "data", "desc": "CRLF in logging"},
            {"path": "/response", "params": "value", "desc": "CRLF in response"},
            {"path": "/cookie", "params": "name", "desc": "CRLF in Set-Cookie"},
            {"path": "/location", "params": "path", "desc": "CRLF in Location"},
            {"path": "/cache", "params": "control", "desc": "CRLF in Cache-Control"},
            {"path": "/setcookie", "params": "value", "desc": "CRLF via cookie value"},
            {"path": "/custom", "params": "header", "desc": "CRLF in custom header"},
        ]
    },
    
    "CredsExpose": {
        "port": 5004,
        "full_name": "Credentials Exposure",
        "endpoints": [
            {"path": "/.env", "params": None, "desc": "Exposed .env file"},
            {"path": "/config.json", "params": None, "desc": "Exposed config"},
            {"path": "/database.yml", "params": None, "desc": "Database credentials"},
            {"path": "/secrets.yml", "params": None, "desc": "Secrets file"},
            {"path": "/id_rsa", "params": None, "desc": "SSH private key"},
            {"path": "/.git/config", "params": None, "desc": "Git config"},
            {"path": "/backup.sql", "params": None, "desc": "SQL backup"},
            {"path": "/credentials.json", "params": None, "desc": "Credentials JSON"},
            {"path": "/.aws/credentials", "params": None, "desc": "AWS credentials"},
            {"path": "/phpinfo.php", "params": None, "desc": "PHPInfo exposure"},
        ]
    },
    
    "DirTrav": {
        "port": 5005,
        "full_name": "Directory Traversal",
        "endpoints": [
            {"path": "/read", "params": "file", "desc": "File read via traversal"},
            {"path": "/download", "params": "path", "desc": "Download with traversal"},
            {"path": "/include", "params": "page", "desc": "Include file traversal"},
            {"path": "/load", "params": "template", "desc": "Template traversal"},
            {"path": "/view", "params": "doc", "desc": "Document view traversal"},
            {"path": "/get", "params": "resource", "desc": "Resource get traversal"},
            {"path": "/fetch", "params": "file", "desc": "Fetch file traversal"},
            {"path": "/static", "params": "path", "desc": "Static file traversal"},
            {"path": "/assets", "params": "name", "desc": "Assets traversal"},
            {"path": "/image", "params": "img", "desc": "Image traversal"},
        ]
    },
    
    "GraphQLi": {
        "port": 5006,
        "full_name": "GraphQL Injection",
        "endpoints": [
            {"path": "/graphql", "params": "query", "desc": "GraphQL query injection"},
            {"path": "/graphql/batch", "params": "queries", "desc": "Batch query injection"},
            {"path": "/api/graphql", "params": "mutation", "desc": "Mutation injection"},
            {"path": "/gql", "params": "q", "desc": "GraphQL endpoint"},
            {"path": "/graphql/playground", "params": None, "desc": "GraphQL playground"},
            {"path": "/graphql/introspection", "params": None, "desc": "Introspection enabled"},
            {"path": "/api/gql", "params": "operation", "desc": "GraphQL operation"},
            {"path": "/query", "params": "gql", "desc": "Direct GraphQL query"},
        ]
    },
    
    "InfoDisc": {
        "port": 5007,
        "full_name": "Information Disclosure",
        "endpoints": [
            {"path": "/debug", "params": None, "desc": "Debug information"},
            {"path": "/error", "params": "msg", "desc": "Error details exposure"},
            {"path": "/trace", "params": None, "desc": "Stack trace exposure"},
            {"path": "/version", "params": None, "desc": "Version disclosure"},
            {"path": "/info", "params": None, "desc": "System information"},
            {"path": "/status", "params": None, "desc": "Status disclosure"},
            {"path": "/health", "params": None, "desc": "Health check details"},
            {"path": "/metrics", "params": None, "desc": "Metrics exposure"},
            {"path": "/logs", "params": None, "desc": "Logs exposure"},
            {"path": "/env", "params": None, "desc": "Environment variables"},
        ]
    },
    
    "InsecDeser": {
        "port": 5008,
        "full_name": "Insecure Deserialization",
        "endpoints": [
            {"path": "/deserialize", "params": "data", "desc": "Unsafe deserialization"},
            {"path": "/pickle", "params": "obj", "desc": "Pickle deserialization"},
            {"path": "/unmarshal", "params": "payload", "desc": "Unmarshal injection"},
            {"path": "/unserialize", "params": "input", "desc": "PHP unserialize"},
            {"path": "/load", "params": "object", "desc": "Object load"},
            {"path": "/restore", "params": "state", "desc": "State restoration"},
            {"path": "/decode", "params": "encoded", "desc": "Decode serialized"},
            {"path": "/parse", "params": "serialized", "desc": "Parse serialized data"},
        ]
    },
    
    "InsecPerm": {
        "port": 5009,
        "full_name": "Insecure Permissions",
        "endpoints": [
            {"path": "/admin", "params": None, "desc": "Admin without auth"},
            {"path": "/api/users", "params": "id", "desc": "User data no auth"},
            {"path": "/api/admin", "params": None, "desc": "Admin API no auth"},
            {"path": "/dashboard", "params": None, "desc": "Dashboard no auth"},
            {"path": "/config", "params": None, "desc": "Config access"},
            {"path": "/settings", "params": None, "desc": "Settings no auth"},
            {"path": "/users", "params": None, "desc": "Users list no auth"},
            {"path": "/delete", "params": "id", "desc": "Delete no auth"},
            {"path": "/edit", "params": "id", "desc": "Edit no auth"},
            {"path": "/manage", "params": None, "desc": "Management no auth"},
        ]
    },
    
    "JWT": {
        "port": 5010,
        "full_name": "JWT Vulnerabilities",
        "endpoints": [
            {"path": "/jwt/login", "params": "username", "desc": "JWT weak secret"},
            {"path": "/jwt/decode", "params": "token", "desc": "JWT decode"},
            {"path": "/jwt/verify", "params": "jwt", "desc": "JWT verification bypass"},
            {"path": "/jwt/none", "params": "token", "desc": "Algorithm none"},
            {"path": "/jwt/weak", "params": None, "desc": "Weak JWT secret"},
            {"path": "/auth/token", "params": "user", "desc": "Token generation"},
            {"path": "/api/jwt", "params": "token", "desc": "JWT API"},
            {"path": "/verify", "params": "jwt", "desc": "Token verification"},
        ]
    },
    
    "NoSQLi": {
        "port": 5011,
        "full_name": "NoSQL Injection",
        "endpoints": [
            {"path": "/nosql/login", "params": "username", "desc": "NoSQL login bypass"},
            {"path": "/nosql/search", "params": "query", "desc": "NoSQL search injection"},
            {"path": "/nosql/find", "params": "filter", "desc": "NoSQL find injection"},
            {"path": "/mongo/query", "params": "q", "desc": "MongoDB injection"},
            {"path": "/api/search", "params": "term", "desc": "NoSQL search"},
            {"path": "/find", "params": "criteria", "desc": "Find injection"},
            {"path": "/filter", "params": "condition", "desc": "Filter injection"},
            {"path": "/query", "params": "nosql", "desc": "NoSQL query"},
        ]
    },
    
    "Prototype_Pollution": {
        "port": 5012,
        "full_name": "Prototype Pollution",
        "endpoints": [
            {"path": "/merge", "params": "obj", "desc": "Object merge pollution"},
            {"path": "/extend", "params": "props", "desc": "Extend pollution"},
            {"path": "/assign", "params": "data", "desc": "Object assign"},
            {"path": "/clone", "params": "object", "desc": "Clone pollution"},
            {"path": "/parse", "params": "json", "desc": "JSON parse pollution"},
            {"path": "/update", "params": "fields", "desc": "Update pollution"},
            {"path": "/set", "params": "key", "desc": "Property set pollution"},
        ]
    },
    
    "RateLimit": {
        "port": 5013,
        "full_name": "Rate Limiting Issues",
        "endpoints": [
            {"path": "/api/endpoint", "params": None, "desc": "No rate limit"},
            {"path": "/login", "params": "username", "desc": "Login no rate limit"},
            {"path": "/register", "params": "email", "desc": "Register no limit"},
            {"path": "/otp", "params": "code", "desc": "OTP no rate limit"},
            {"path": "/reset", "params": "email", "desc": "Password reset no limit"},
            {"path": "/api/data", "params": None, "desc": "Data API no limit"},
            {"path": "/download", "params": "file", "desc": "Download no limit"},
            {"path": "/upload", "params": None, "desc": "Upload no limit"},
        ]
    },
    
    "SQLi": {
        "port": 5014,
        "full_name": "SQL Injection",
        "endpoints": [
            {"path": "/login", "params": "username", "desc": "SQL login bypass"},
            {"path": "/search", "params": "q", "desc": "SQL search injection"},
            {"path": "/user", "params": "id", "desc": "SQL user injection"},
            {"path": "/product", "params": "pid", "desc": "SQL product injection"},
            {"path": "/query", "params": "sql", "desc": "Direct SQL injection"},
            {"path": "/filter", "params": "where", "desc": "SQL filter injection"},
            {"path": "/order", "params": "sort", "desc": "SQL order injection"},
            {"path": "/union", "params": "id", "desc": "UNION-based SQLi"},
            {"path": "/blind", "params": "id", "desc": "Blind SQLi"},
            {"path": "/time", "params": "id", "desc": "Time-based SQLi"},
        ]
    },
    
    "SSRF": {
        "port": 5015,
        "full_name": "Server-Side Request Forgery",
        "endpoints": [
            {"path": "/fetch", "params": "url", "desc": "URL fetch SSRF"},
            {"path": "/proxy", "params": "target", "desc": "Proxy SSRF"},
            {"path": "/webhook", "params": "callback", "desc": "Webhook SSRF"},
            {"path": "/image", "params": "url", "desc": "Image fetch SSRF"},
            {"path": "/preview", "params": "link", "desc": "Link preview SSRF"},
            {"path": "/avatar", "params": "url", "desc": "Avatar SSRF"},
            {"path": "/import", "params": "url", "desc": "Import SSRF"},
            {"path": "/load", "params": "resource", "desc": "Resource load SSRF"},
        ]
    },
    
    "SSTI": {
        "port": 5016,
        "full_name": "Server-Side Template Injection",
        "endpoints": [
            {"path": "/greet", "params": "name", "desc": "Template greeting SSTI"},
            {"path": "/render", "params": "template", "desc": "Template render SSTI"},
            {"path": "/email", "params": "body", "desc": "Email template SSTI"},
            {"path": "/page", "params": "content", "desc": "Page render SSTI"},
            {"path": "/message", "params": "text", "desc": "Message SSTI"},
            {"path": "/preview", "params": "tmpl", "desc": "Preview SSTI"},
            {"path": "/format", "params": "pattern", "desc": "Format string SSTI"},
        ]
    },
    
    "SessFix": {
        "port": 5017,
        "full_name": "Session Fixation",
        "endpoints": [
            {"path": "/login", "params": "sessionid", "desc": "Session fixation login"},
            {"path": "/auth", "params": "sid", "desc": "Auth session fixation"},
            {"path": "/session/set", "params": "id", "desc": "Set session ID"},
            {"path": "/token", "params": "session", "desc": "Token session fixation"},
            {"path": "/fixate", "params": "sessid", "desc": "Session fixation"},
            {"path": "/setsession", "params": "id", "desc": "Set session"},
            {"path": "/auth/session", "params": "sid", "desc": "Auth with session"},
        ]
    },
    
    "XSS": {
        "port": 5018,
        "full_name": "Cross-Site Scripting",
        "endpoints": [
            {"path": "/reflected", "params": "q", "desc": "Reflected XSS"},
            {"path": "/search", "params": "query", "desc": "Search XSS"},
            {"path": "/comment", "params": "text", "desc": "Comment XSS"},
            {"path": "/profile", "params": "name", "desc": "Profile XSS"},
            {"path": "/message", "params": "msg", "desc": "Message XSS"},
            {"path": "/input", "params": "data", "desc": "Input XSS"},
            {"path": "/form", "params": "value", "desc": "Form XSS"},
            {"path": "/display", "params": "content", "desc": "Display XSS"},
            {"path": "/echo", "params": "text", "desc": "Echo XSS"},
            {"path": "/render", "params": "html", "desc": "Render XSS"},
        ]
    },
    
    "XXE": {
        "port": 5019,
        "full_name": "XML External Entity",
        "endpoints": [
            {"path": "/xml/parse", "params": "xml", "desc": "XML parse XXE"},
            {"path": "/xml/upload", "params": None, "desc": "XML upload XXE"},
            {"path": "/xml/import", "params": "data", "desc": "XML import XXE"},
            {"path": "/xml/process", "params": "xml", "desc": "XML process XXE"},
            {"path": "/soap", "params": "request", "desc": "SOAP XXE"},
            {"path": "/rss", "params": "feed", "desc": "RSS XXE"},
            {"path": "/xml/read", "params": "file", "desc": "XML read XXE"},
        ]
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# TEMPLATE SERVEUR GÉNÉRIQUE
# ══════════════════════════════════════════════════════════════════════════════

SERVER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR VULNÉRABLE - {full_name} ({vuln_code})                            ║
║   Port: {port}                                                               ║
║   Auto-généré pour dataset ShieldAI V2                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   ⚠️  INTENTIONNELLEMENT VULNÉRABLE - LOCAL UNIQUEMENT ⚠️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "{vuln_code}_server_secret"
CORS(app, origins="*", supports_credentials=True)

@app.route('/')
def index():
    return jsonify({{
        "server": "{full_name} Vulnerable Server",
        "port": {port},
        "vuln_type": "{vuln_code}",
        "endpoints": {endpoints_list}
    }})

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS VULNÉRABLES - {full_name}
# ═══════════════════════════════════════════════════════════════════════════

{vuln_endpoints}

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
    return jsonify({{"status": "safe", "data": safe_data}})

@app.route('/safe2')
def safe2():
    """Endpoint safe - JSON only"""
    value = request.args.get('value', '')
    # Sécurisé: pas de réflexion directe
    return jsonify({{"status": "ok", "length": len(value)}})

if __name__ == '__main__':
    print("🔥 {full_name} ({vuln_code}) Vulnerable Server starting on port {port}...")
    print("⚠️  INTENTIONALLY VULNERABLE - LOCAL USE ONLY")
    app.run(host='0.0.0.0', port={port}, debug=False)
'''

# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINT TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════

ENDPOINT_TEMPLATE = '''
@app.route('{path}')
def endpoint_{func_name}():
    """{desc}"""
    {param_code}
    # Vulnérable: reflète le payload sans validation
    response = f"{response_format}"
    return response
'''

# ══════════════════════════════════════════════════════════════════════════════
# FONCTIONS DE GÉNÉRATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_endpoint_code(endpoint, vuln_code):
    """Génère le code d'un endpoint vulnérable"""
    path = endpoint['path']
    params = endpoint.get('params')
    desc = endpoint['desc']
    func_name = path.replace('/', '_').replace('.', '_').strip('_')
    
    if params:
        param_code = f"{params} = request.args.get('{params}', 'default')"
        response_format = f"{vuln_code} - {path}: {{{params}}}"
    else:
        param_code = "# No parameters"
        response_format = f"{vuln_code} - {path}: Vulnerable endpoint"
    
    return ENDPOINT_TEMPLATE.format(
        path=path,
        func_name=func_name,
        desc=desc,
        param_code=param_code,
        response_format=response_format
    )

def generate_server(vuln_code, config):
    """Génère le code complet d'un serveur"""
    full_name = config['full_name']
    port = config['port']
    endpoints = config['endpoints']
    
    # Générer tous les endpoints vulnérables
    vuln_endpoints_code = '\n'.join([
        generate_endpoint_code(ep, vuln_code) 
        for ep in endpoints
    ])
    
    # Liste des endpoints pour l'index
    endpoints_list = [
        f"{ep['path']}{'?'+ep['params']+'=test' if ep.get('params') else ''}"
        for ep in endpoints
    ] + ["/safe1", "/safe2"]
    
    # Générer le serveur complet
    server_code = SERVER_TEMPLATE.format(
        vuln_code=vuln_code,
        full_name=full_name,
        port=port,
        endpoints_list=json.dumps(endpoints_list, indent=8),
        vuln_endpoints=vuln_endpoints_code
    )
    
    return server_code

def generate_safe_server():
    """Génère le serveur 100% safe"""
    safe_server = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   SERVEUR SAFE - AUCUNE VULNÉRABILITÉ                                       ║
║   Port: 5020                                                                 ║
║   Pour équilibrer le dataset (label = "SAFE")                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
app.secret_key = "safe_server_secret_key_2026"
CORS(app, origins="*", supports_credentials=True)

def sanitize(text, max_len=50):
    """Sanitize input - remove special chars"""
    clean = re.sub(r'[^a-zA-Z0-9 ]', '', str(text))
    return clean[:max_len]

@app.route('/')
def index():
    return jsonify({
        "server": "SAFE Server - No Vulnerabilities",
        "port": 5020,
        "total_endpoints": 100,
        "all_secure": True
    })

# 100 endpoints SAFE
'''
    
    # Générer 100 endpoints safe
    for i in range(1, 101):
        safe_server += f'''
@app.route('/api/endpoint{i}')
def safe_endpoint_{i}():
    """Safe endpoint {i}"""
    data = request.args.get('data', 'default')
    safe_data = sanitize(data)
    return jsonify({{"endpoint": {i}, "data": safe_data, "safe": True}})
'''
    
    safe_server += '''
if __name__ == '__main__':
    print("✅ SAFE Server starting on port 5020...")
    print("✅ 100% SECURE - NO VULNERABILITIES")
    app.run(host='0.0.0.0', port=5020, debug=False)
'''
    
    return safe_server

def generate_ground_truth():
    """Génère le fichier ground_truth.json"""
    ground_truth = {}
    
    # Pour chaque serveur vulnérable
    for vuln_code, config in VULNS_CONFIG.items():
        port = config['port']
        for endpoint in config['endpoints']:
            path = endpoint['path']
            params = endpoint.get('params')
            
            if params:
                url = f"http://localhost:{port}{path}?{params}=test"
            else:
                url = f"http://localhost:{port}{path}"
            
            ground_truth[url] = [vuln_code]
        
        # Endpoints safe du serveur
        ground_truth[f"http://localhost:{port}/safe1"] = ["SAFE"]
        ground_truth[f"http://localhost:{port}/safe2"] = ["SAFE"]
    
    # Serveur 100% safe
    for i in range(1, 101):
        ground_truth[f"http://localhost:5020/api/endpoint{i}"] = ["SAFE"]
    
    return ground_truth

# ══════════════════════════════════════════════════════════════════════════════
# MAIN - GÉNÉRATION DE TOUS LES SERVEURS
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """Génère tous les serveurs et fichiers nécessaires"""
    
    print("="*80)
    print("🔥 GÉNÉRATION DES SERVEURS VULNÉRABLES")
    print("="*80)
    
    # Créer dossier de sortie
    output_dir = "servers_generated"
    os.makedirs(output_dir, exist_ok=True)
    
    # Générer les 19 serveurs vulnérables
    print("\n📂 Génération des 19 serveurs vulnérables...")
    for vuln_code, config in VULNS_CONFIG.items():
        server_code = generate_server(vuln_code, config)
        filename = f"server_{vuln_code.lower()}.py"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(server_code)
        
        print(f"  ✅ {filename} (port {config['port']})")
    
    # Générer le serveur safe
    print("\n📂 Génération du serveur SAFE...")
    safe_code = generate_safe_server()
    safe_filepath = os.path.join(output_dir, "server_safe.py")
    with open(safe_filepath, 'w', encoding='utf-8') as f:
        f.write(safe_code)
    print(f"  ✅ server_safe.py (port 5020)")
    
    # Générer ground_truth.json
    print("\n📂 Génération ground_truth.json...")
    ground_truth = generate_ground_truth()
    gt_filepath = os.path.join(output_dir, "ground_truth.json")
    with open(gt_filepath, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    print(f"  ✅ ground_truth.json ({len(ground_truth)} URLs)")
    
    # Générer start_all.sh
    print("\n📂 Génération script start_all.sh...")
    start_script = "#!/bin/bash\n\n"
    start_script += "echo '🔥 Starting all 20 vulnerable servers...'\n\n"
    
    for vuln_code, config in VULNS_CONFIG.items():
        filename = f"server_{vuln_code.lower()}.py"
        start_script += f"python3 {filename} &\n"
    
    start_script += "python3 server_safe.py &\n\n"
    start_script += "echo '✅ All 20 servers started!'\n"
    start_script += "echo 'Ports: 5001-5020'\n"
    start_script += "wait\n"
    
    start_filepath = os.path.join(output_dir, "start_all.sh")
    with open(start_filepath, 'w', encoding='utf-8') as f:
        f.write(start_script)
    os.chmod(start_filepath, 0o755)
    print(f"  ✅ start_all.sh")
    
    # Générer stop_all.sh
    stop_script = "#!/bin/bash\n\n"
    stop_script += "echo '🛑 Stopping all servers...'\n"
    stop_script += "pkill -f 'python3 server_.*\\.py'\n"
    stop_script += "echo '✅ All servers stopped!'\n"
    
    stop_filepath = os.path.join(output_dir, "stop_all.sh")
    with open(stop_filepath, 'w', encoding='utf-8') as f:
        f.write(stop_script)
    os.chmod(stop_filepath, 0o755)
    print(f"  ✅ stop_all.sh")
    
    # Stats finales
    print("\n" + "="*80)
    print("✅ GÉNÉRATION TERMINÉE !")
    print("="*80)
    print(f"\n📊 Statistiques:")
    print(f"  • Serveurs vulnérables: 19")
    print(f"  • Serveur safe: 1")
    print(f"  • Total serveurs: 20")
    print(f"  • Total URLs: {len(ground_truth)}")
    print(f"  • Ports: 5001-5020")
    print(f"\n📁 Fichiers générés dans: {output_dir}/")
    print(f"\n🚀 Pour lancer tous les serveurs:")
    print(f"  cd {output_dir}")
    print(f"  ./start_all.sh")
    print(f"\n🛑 Pour arrêter tous les serveurs:")
    print(f"  ./stop_all.sh")
    print("\n" + "="*80)

if __name__ == '__main__':
    main()
