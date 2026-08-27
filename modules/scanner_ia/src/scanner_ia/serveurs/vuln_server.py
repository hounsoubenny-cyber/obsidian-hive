#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SERVEUR DE TEST VULNÉRABLE - ShieldAI V2
⚠️  ATTENTION : NE JAMAIS DÉPLOYER EN PRODUCTION ! ⚠️

Ce serveur contient TOUTES les vulnérabilités pour tester le scanner.
Utilisez UNIQUEMENT en local (localhost) !

Author: Samuel - ShieldAI
Date: 2026-03-12
"""

import os
import re
import time
import json
import pickle
import base64
import subprocess
from flask import (
    Flask, request, render_template_string, redirect, 
    make_response, jsonify, send_file, session
)
from flask_cors import CORS
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "insecure_secret_key_123"  # ⚠️ Weak secret
CORS(app, origins="*", supports_credentials=True)  # ⚠️ CORS vuln

# Base de données SQLite en mémoire
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            is_admin INTEGER
        )
    ''')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com', 1)")
    cursor.execute("INSERT INTO users VALUES (2, 'user', 'password', 'user@test.com', 0)")
    cursor.execute("INSERT INTO users VALUES (3, 'test', 'test', 'test@test.com', 0)")
    conn.commit()
    return conn

DB = init_db()

# HTML Templates vulnérables
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ShieldAI - Vulnerable Test Server</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial; max-width: 1200px; margin: 50px auto; padding: 20px; }
        h1 { color: #e74c3c; }
        .vuln-category { margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .vuln-category h2 { color: #3498db; margin-top: 0; }
        ul { list-style: none; padding: 0; }
        li { margin: 10px 0; }
        a { color: #2c3e50; text-decoration: none; padding: 8px 15px; background: #ecf0f1; 
            border-radius: 4px; display: inline-block; transition: 0.3s; }
        a:hover { background: #3498db; color: white; }
        .warning { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; 
                   border-radius: 8px; margin: 20px 0; }
        code { background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="warning">
        <h2>⚠️ SERVEUR VULNÉRABLE - TEST SEULEMENT ⚠️</h2>
        <p>Ce serveur contient TOUTES les vulnérabilités web pour tester ShieldAI.</p>
        <p><strong>NE JAMAIS utiliser en production !</strong></p>
    </div>

    <h1>🔥 ShieldAI - Vulnerable Test Server</h1>
    <p>Serveur local avec {{ total_vulns }} vulnérabilités testables</p>

    <!-- XSS -->
    <div class="vuln-category">
        <h2>🎯 XSS (Cross-Site Scripting)</h2>
        <ul>
            <li><a href="/xss/reflected?q=test">Reflected XSS (GET)</a></li>
            <li><a href="/xss/stored">Stored XSS</a></li>
            <li><a href="/xss/dom">DOM-based XSS</a></li>
            <li><a href="/xss/header">XSS via Header</a></li>
        </ul>
    </div>

    <!-- SQLi -->
    <div class="vuln-category">
        <h2>💉 SQLi (SQL Injection)</h2>
        <ul>
            <li><a href="/sqli/login">Login SQLi</a></li>
            <li><a href="/sqli/search?id=1">Search SQLi (GET)</a></li>
            <li><a href="/sqli/time">Time-based SQLi</a></li>
            <li><a href="/sqli/union">UNION SQLi</a></li>
        </ul>
    </div>

    <!-- CMDi -->
    <div class="vuln-category">
        <h2>💻 CMDi (Command Injection)</h2>
        <ul>
            <li><a href="/cmdi/ping">Ping Command</a></li>
            <li><a href="/cmdi/system">System Info</a></li>
        </ul>
    </div>

    <!-- Directory Traversal -->
    <div class="vuln-category">
        <h2>📁 Directory Traversal / LFI</h2>
        <ul>
            <li><a href="/file/read?path=test.txt">File Read</a></li>
            <li><a href="/download?file=document.pdf">File Download</a></li>
        </ul>
    </div>

    <!-- CSRF -->
    <div class="vuln-category">
        <h2>🔄 CSRF (Cross-Site Request Forgery)</h2>
        <ul>
            <li><a href="/csrf/transfer">Money Transfer (no token)</a></li>
            <li><a href="/csrf/delete">Delete Account</a></li>
        </ul>
    </div>

    <!-- File Upload -->
    <div class="vuln-category">
        <h2>📤 Insecure File Upload</h2>
        <ul>
            <li><a href="/upload">Upload Form</a></li>
        </ul>
    </div>

    <!-- Auth -->
    <div class="vuln-category">
        <h2>🔐 Broken Authentication</h2>
        <ul>
            <li><a href="/auth/login">Weak Login</a></li>
            <li><a href="/auth/reset">Password Reset</a></li>
        </ul>
    </div>

    <!-- Info Disclosure -->
    <div class="vuln-category">
        <h2>ℹ️ Information Disclosure</h2>
        <ul>
            <li><a href="/.env">Exposed .env</a></li>
            <li><a href="/.git/config">Exposed .git</a></li>
            <li><a href="/phpinfo">PHP Info</a></li>
            <li><a href="/debug">Debug Info</a></li>
        </ul>
    </div>

    <!-- Deserialization -->
    <div class="vuln-category">
        <h2>🔓 Insecure Deserialization</h2>
        <ul>
            <li><a href="/deserialize">Pickle Deserialize</a></li>
        </ul>
    </div>

    <!-- IDOR -->
    <div class="vuln-category">
        <h2>🔑 IDOR / Insecure Permissions</h2>
        <ul>
            <li><a href="/user/profile/1">User Profile</a></li>
            <li><a href="/api/admin/users">Admin Panel</a></li>
        </ul>
    </div>

    <!-- CORS -->
    <div class="vuln-category">
        <h2>🌐 CORS Misconfiguration</h2>
        <ul>
            <li><a href="/api/data">CORS Test Endpoint</a></li>
        </ul>
    </div>

    <!-- XXE -->
    <div class="vuln-category">
        <h2>📋 XXE (XML External Entity)</h2>
        <ul>
            <li><a href="/xml/parse">XML Parser</a></li>
        </ul>
    </div>

    <!-- NoSQL -->
    <div class="vuln-category">
        <h2>🗄️ NoSQL Injection</h2>
        <ul>
            <li><a href="/nosql/search">NoSQL Search</a></li>
        </ul>
    </div>

    <!-- Session -->
    <div class="vuln-category">
        <h2>🍪 Session Fixation</h2>
        <ul>
            <li><a href="/session/fixate">Session Fixation Test</a></li>
        </ul>
    </div>

    <!-- SSRF -->
    <div class="vuln-category">
        <h2>🔗 SSRF</h2>
        <ul>
            <li><a href="/ssrf/fetch">Fetch URL</a></li>
        </ul>
    </div>

    <hr style="margin: 40px 0;">
    <p style="text-align: center; color: #7f8c8d;">
        Total: <strong>{{ total_vulns }}</strong> vulnérabilités | 
        ShieldAI V2 Test Server | 
        Port: <code>5000</code>
    </p>
</body>
</html>
"""

# ============================================================================
# 🎯 XSS (Cross-Site Scripting)
# ============================================================================

@app.route('/')
def index():
    return render_template_string(HOME_TEMPLATE, total_vulns=50)

@app.route('/xss/reflected')
def xss_reflected():
    """⚠️ Reflected XSS - Payload directement dans response"""
    query = request.args.get('q', '')
    html = f"""
    <html><body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    """⚠️ Stored XSS"""
    if not hasattr(app, 'comments'):
        app.comments = []
    
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        app.comments.append(comment)
    
    comments_html = ''.join([f'<li>{c}</li>' for c in app.comments])
    html = f"""
    <html><body>
        <h1>Comments</h1>
        <form method="post">
            <textarea name="comment"></textarea>
            <button>Post</button>
        </form>
        <ul>{comments_html}</ul>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/xss/dom')
def xss_dom():
    """⚠️ DOM XSS"""
    html = """
    <html><body>
        <h1>DOM XSS</h1>
        <div id="output"></div>
        <script>
            var hash = window.location.hash.substr(1);
            document.getElementById('output').innerHTML = "Welcome " + hash;
        </script>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/xss/header')
def xss_header():
    """⚠️ XSS via User-Agent header"""
    user_agent = request.headers.get('User-Agent', 'Unknown')
    html = f"""
    <html><body>
        <h1>Your Browser</h1>
        <p>User-Agent: {user_agent}</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 💉 SQLi (SQL Injection)
# ============================================================================

@app.route('/sqli/login', methods=['GET', 'POST'])
def sqli_login():
    """⚠️ SQL Injection in login"""
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # ⚠️ VULNERABLE - Direct string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            cursor = DB.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                message = f"✅ Login successful! Welcome {user[1]}"
            else:
                message = "❌ Invalid credentials"
        except Exception as e:
            message = f"❌ SQL Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>Login</h1>
        <form method="post">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button>Login</button>
        </form>
        <p>{message}</p>
        <p>Hint: Try <code>admin' --</code> as username</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/sqli/search')
def sqli_search():
    """⚠️ SQL Injection in GET parameter"""
    user_id = request.args.get('id', '1')
    
    # ⚠️ VULNERABLE
    query = f"SELECT * FROM users WHERE id={user_id}"
    
    try:
        cursor = DB.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            result = f"User: {user[1]}, Email: {user[3]}"
        else:
            result = "User not found"
    except Exception as e:
        result = f"SQL Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>User Search</h1>
        <p>{result}</p>
        <p>Hint: Try <code>?id=1 OR 1=1</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/sqli/time')
def sqli_time():
    """⚠️ Time-based SQL Injection"""
    user_id = request.args.get('id', '1')
    
    # ⚠️ VULNERABLE - Time-based
    query = f"SELECT * FROM users WHERE id={user_id}"
    
    start = time.time()
    try:
        cursor = DB.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        result = "Query executed"
    except Exception as e:
        result = f"Error: {str(e)}"
    
    elapsed = time.time() - start
    
    html = f"""
    <html><body>
        <h1>Time-based SQLi</h1>
        <p>{result}</p>
        <p>Query took: {elapsed:.3f} seconds</p>
        <p>Hint: Try <code>?id=1' AND SLEEP(5)--</code> (SQLite doesn't support SLEEP, but errors show)</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/sqli/union')
def sqli_union():
    """⚠️ UNION-based SQLi"""
    user_id = request.args.get('id', '1')
    
    query = f"SELECT username, email FROM users WHERE id={user_id}"
    
    try:
        cursor = DB.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        
        output = "<ul>"
        for row in results:
            output += f"<li>{row[0]} - {row[1]}</li>"
        output += "</ul>"
    except Exception as e:
        output = f"SQL Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>UNION SQLi</h1>
        {output}
        <p>Hint: Try <code>?id=1 UNION SELECT password, 'dummy' FROM users--</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 💻 CMDi (Command Injection)
# ============================================================================

@app.route('/cmdi/ping', methods=['GET', 'POST'])
def cmdi_ping():
    """⚠️ Command Injection - ping"""
    output = ""
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # ⚠️ VULNERABLE - Direct shell execution
        try:
            cmd = f"ping -c 2 {host}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>Ping Tool</h1>
        <form method="post">
            <input name="host" placeholder="127.0.0.1">
            <button>Ping</button>
        </form>
        <pre>{output}</pre>
        <p>Hint: Try <code>127.0.0.1; whoami</code> or <code>127.0.0.1 | ls</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/cmdi/system', methods=['GET', 'POST'])
def cmdi_system():
    """⚠️ Command Injection - system info"""
    output = ""
    if request.method == 'POST':
        cmd = request.form.get('cmd', 'uname -a')
        
        # ⚠️ VULNERABLE
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>System Info</h1>
        <form method="post">
            <input name="cmd" value="uname -a">
            <button>Execute</button>
        </form>
        <pre>{output}</pre>
        <p>Hint: Direct command execution!</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 📁 Directory Traversal / LFI
# ============================================================================

@app.route('/file/read')
def file_read():
    """⚠️ Directory Traversal"""
    filepath = request.args.get('path', 'test.txt')
    
    # ⚠️ VULNERABLE - No path validation
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        content = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>File Reader</h1>
        <pre>{content}</pre>
        <p>Hint: Try <code>?path=../../../../etc/passwd</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/download')
def file_download():
    """⚠️ Directory Traversal in download"""
    filename = request.args.get('file', 'test.pdf')
    
    # ⚠️ VULNERABLE
    try:
        return send_file(filename)
    except Exception as e:
        return f"Error: {str(e)}"

# ============================================================================
# 🔄 CSRF (Cross-Site Request Forgery)
# ============================================================================

@app.route('/csrf/transfer', methods=['GET', 'POST'])
def csrf_transfer():
    """⚠️ CSRF - No token validation"""
    message = ""
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '')
        message = f"✅ Transferred ${amount} to {to}"
    
    html = f"""
    <html><body>
        <h1>Money Transfer</h1>
        <form method="post">
            <input name="to" placeholder="Recipient"><br>
            <input name="amount" placeholder="Amount"><br>
            <button>Transfer</button>
        </form>
        <p>{message}</p>
        <p>⚠️ No CSRF token protection!</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/csrf/delete', methods=['GET', 'POST'])
def csrf_delete():
    """⚠️ CSRF - Account deletion"""
    message = ""
    if request.method == 'POST':
        message = "✅ Account deleted!"
    
    html = f"""
    <html><body>
        <h1>Delete Account</h1>
        <form method="post">
            <button style="background:red;color:white">Delete My Account</button>
        </form>
        <p>{message}</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 📤 Insecure File Upload
# ============================================================================

UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """⚠️ Insecure File Upload - No validation"""
    message = ""
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # ⚠️ VULNERABLE - No extension/type check
            filename = file.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            message = f"✅ File uploaded: {filename}"
    
    html = f"""
    <html><body>
        <h1>File Upload</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <button>Upload</button>
        </form>
        <p>{message}</p>
        <p>Hint: Try uploading shell.php or shell.exe</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🔐 Broken Authentication
# ============================================================================

@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    """⚠️ Weak authentication"""
    message = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # ⚠️ VULNERABLE - Default credentials
        if username == "admin" and password == "admin":
            message = "✅ Admin login successful!"
        elif username == password:  # ⚠️ username==password bypass
            message = f"✅ Login successful as {username}!"
        else:
            message = "❌ Invalid credentials"
    
    html = f"""
    <html><body>
        <h1>Weak Login</h1>
        <form method="post">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button>Login</button>
        </form>
        <p>{message}</p>
        <p>Hint: Try <code>admin:admin</code> or <code>test:test</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

@app.route('/auth/reset', methods=['GET', 'POST'])
def auth_reset():
    """⚠️ Insecure password reset"""
    message = ""
    if request.method == 'POST':
        email = request.form.get('email', '')
        message = f"✅ Reset link sent to {email}"
    
    html = f"""
    <html><body>
        <h1>Password Reset</h1>
        <form method="post">
            <input name="email" placeholder="Email"><br>
            <button>Reset Password</button>
        </form>
        <p>{message}</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# ℹ️ Information Disclosure
# ============================================================================

@app.route('/.env')
def exposed_env():
    """⚠️ Exposed .env file"""
    content = """
DB_PASSWORD=super_secret_password_123
API_KEY=sk-1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET=my_jwt_secret_key
STRIPE_SECRET=sk_test_1234567890
    """
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/.git/config')
def exposed_git():
    """⚠️ Exposed .git"""
    content = """
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/company/secret-project.git
    """
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/phpinfo')
def phpinfo():
    """⚠️ Info disclosure"""
    info = {
        "php_version": "7.4.3",
        "server": "Apache/2.4.41",
        "document_root": "/var/www/html",
        "mysql_version": "5.7.29",
        "loaded_extensions": ["mysqli", "pdo", "curl", "xml"]
    }
    return jsonify(info)

@app.route('/debug')
def debug_info():
    """⚠️ Debug info exposed"""
    debug_data = {
        "environment": "production",
        "debug": True,
        "database": "mysql://root:password@localhost/mydb",
        "api_keys": {
            "stripe": "sk_live_123",
            "sendgrid": "SG.123abc"
        },
        "internal_ips": ["192.168.1.10", "10.0.0.5"]
    }
    return jsonify(debug_data)

# ============================================================================
# 🔓 Insecure Deserialization
# ============================================================================

@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    """⚠️ Pickle deserialization"""
    result = ""
    if request.method == 'POST':
        data = request.form.get('data', '')
        
        try:
            # ⚠️ VULNERABLE - Unpickle untrusted data
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = f"Deserialized: {obj}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>Deserialize Data</h1>
        <form method="post">
            <textarea name="data" placeholder="Base64 encoded pickle data"></textarea><br>
            <button>Deserialize</button>
        </form>
        <pre>{result}</pre>
        <p>Hint: Send malicious pickle payload</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🔑 IDOR / Insecure Permissions
# ============================================================================

@app.route('/user/profile/<int:user_id>')
def user_profile(user_id):
    """⚠️ IDOR - No authorization check"""
    cursor = DB.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    
    if user:
        data = {
            "id": user[0],
            "username": user[1],
            "password": user[2],  # ⚠️ Password exposed
            "email": user[3],
            "is_admin": user[4]
        }
        return jsonify(data)
    return jsonify({"error": "User not found"}), 404

@app.route('/api/admin/users')
def admin_users():
    """⚠️ Admin endpoint without auth"""
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    data = []
    for user in users:
        data.append({
            "id": user[0],
            "username": user[1],
            "password": user[2],
            "email": user[3]
        })
    
    return jsonify(data)

# ============================================================================
# 🌐 CORS Misconfiguration
# ============================================================================

@app.route('/api/data')
def cors_data():
    """⚠️ CORS allows any origin"""
    origin = request.headers.get('Origin', '*')
    
    response = make_response(jsonify({
        "secret": "sensitive_data_here",
        "api_key": "sk-123456"
    }))
    
    # ⚠️ VULNERABLE - Reflects origin
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

# ============================================================================
# 📋 XXE (XML External Entity)
# ============================================================================

@app.route('/xml/parse', methods=['GET', 'POST'])
def xxe_parse():
    """⚠️ XXE vulnerability"""
    result = ""
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        
        try:
            # ⚠️ VULNERABLE - XML parsing without protection
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            result = f"Parsed: {ET.tostring(root, encoding='unicode')}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>XML Parser</h1>
        <form method="post">
            <textarea name="xml" rows="10" cols="50">&lt;root&gt;&lt;data&gt;test&lt;/data&gt;&lt;/root&gt;</textarea><br>
            <button>Parse XML</button>
        </form>
        <pre>{result}</pre>
        <p>Hint: Try XXE payload to read /etc/passwd</p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🗄️ NoSQL Injection
# ============================================================================

@app.route('/nosql/search')
def nosql_search():
    """⚠️ NoSQL Injection simulation"""
    username = request.args.get('username', '')
    
    # Simulate MongoDB-like query
    if "$ne" in username or "$gt" in username:
        result = "✅ Authentication bypassed! All users returned."
    else:
        result = f"Searching for: {username}"
    
    html = f"""
    <html><body>
        <h1>NoSQL Search</h1>
        <p>{result}</p>
        <p>Hint: Try <code>?username[$ne]=null</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🍪 Session Fixation
# ============================================================================

@app.route('/session/fixate')
def session_fixate():
    """⚠️ Session Fixation"""
    session_id = request.args.get('sessionid', None)
    
    if session_id:
        # ⚠️ VULNERABLE - Accepts fixed session ID
        session['id'] = session_id
        message = f"Session fixed to: {session_id}"
    else:
        message = "No session ID provided"
    
    html = f"""
    <html><body>
        <h1>Session Fixation</h1>
        <p>{message}</p>
        <p>Hint: Try <code>?sessionid=attacker_session_123</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🔗 SSRF (Server-Side Request Forgery)
# ============================================================================

@app.route('/ssrf/fetch', methods=['GET', 'POST'])
def ssrf_fetch():
    """⚠️ SSRF vulnerability"""
    result = ""
    if request.method == 'POST':
        url = request.form.get('url', '')
        
        try:
            # ⚠️ VULNERABLE - Fetches any URL
            import urllib.request
            response = urllib.request.urlopen(url, timeout=3)
            result = response.read().decode('utf-8')[:500]
        except Exception as e:
            result = f"Error: {str(e)}"
    
    html = f"""
    <html><body>
        <h1>Fetch URL</h1>
        <form method="post">
            <input name="url" value="http://example.com" style="width:400px"><br>
            <button>Fetch</button>
        </form>
        <pre>{result}</pre>
        <p>Hint: Try <code>http://localhost:5000/.env</code> or <code>file:///etc/passwd</code></p>
        <a href="/">Back</a>
    </body></html>
    """
    return html

# ============================================================================
# 🚀 MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔥 SERVEUR VULNÉRABLE - ShieldAI V2 Test Server")
    print("="*70)
    print("\n⚠️  ATTENTION: Ce serveur contient TOUTES les vulnérabilités!")
    print("⚠️  Utilisez UNIQUEMENT en local (localhost)")
    print("⚠️  NE JAMAIS déployer en production!\n")
    print("🌐 Serveur: http://localhost:5000")
    print("📊 Total: ~50 vulnérabilités testables")
    print("\n" + "="*70 + "\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except SystemExit:
        pass