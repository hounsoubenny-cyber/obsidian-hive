#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur de test vulnérable SIMPLE pour ShieldAI V2
Auteur: Samuel
Date: 2026-03-12
"""

from flask import Flask, request, render_template_string, jsonify
import subprocess
import os

app = Flask(__name__)

# DÉSACTIVER COMPLÈTEMENT LE DEBUG WATCHDOG
app.config['DEBUG'] = False

@app.route('/')
def home():
    """Page d'accueil avec liens de test"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShieldAI Test Server</title>
        <style>
            body { font-family: Arial; margin: 40px; background: #f0f0f0; }
            .container { background: white; padding: 30px; border-radius: 10px; }
            h1 { color: #e74c3c; }
            .vuln-section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; background: #ecf0f1; }
            a { color: #3498db; text-decoration: none; font-weight: bold; }
            a:hover { text-decoration: underline; }
            .warning { background: #e74c3c; color: white; padding: 10px; border-radius: 5px; margin: 20px 0; }
            form { margin: 10px 0; }
            input[type="text"] { padding: 5px; width: 300px; }
            input[type="submit"] { padding: 5px 15px; background: #3498db; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 ShieldAI V2 - Serveur Vulnérable de Test</h1>
            <div class="warning">
                ⚠️ CE SERVEUR CONTIENT DES VULNÉRABILITÉS INTENTIONNELLES ⚠️<br>
                Utilisez UNIQUEMENT en local (localhost) pour tester votre scanner
            </div>
            
            <div class="vuln-section">
                <h2>🎯 XSS - Cross-Site Scripting</h2>
                <form action="/xss" method="GET">
                    <input type="text" name="name" placeholder="Votre nom">
                    <input type="submit" value="Tester XSS">
                </form>
                <a href="/xss?name=<script>alert('XSS')</script>">Test XSS</a>
            </div>
            
            <div class="vuln-section">
                <h2>💉 SQLi - SQL Injection</h2>
                <form action="/sqli" method="GET">
                    <input type="text" name="id" placeholder="User ID">
                    <input type="submit" value="Tester SQLi">
                </form>
                <a href="/sqli?id=1' OR '1'='1">Test SQLi</a>
            </div>
            
            <div class="vuln-section">
                <h2>💻 CMDi - Command Injection</h2>
                <form action="/cmd" method="GET">
                    <input type="text" name="file" placeholder="Nom du fichier">
                    <input type="submit" value="Tester CMDi">
                </form>
                <a href="/cmd?file=test.txt; whoami">Test CMDi</a>
            </div>
            
            <div class="vuln-section">
                <h2>📁 Directory Traversal</h2>
                <a href="/file?path=../../../../etc/passwd">Test DirTrav</a>
            </div>
            
            <div class="vuln-section">
                <h2>🔓 IDOR - Insecure Direct Object Reference</h2>
                <a href="/user/1">User 1</a> | 
                <a href="/user/2">User 2</a> | 
                <a href="/user/999">User 999 (unauthorized)</a>
            </div>
            
            <div class="vuln-section">
                <h2>🌐 CORS Misconfiguration</h2>
                <a href="/api/data">API avec CORS *</a>
            </div>
            
            <div class="vuln-section">
                <h2>📄 Info Disclosure</h2>
                <a href="/.env">Fichier .env</a> | 
                <a href="/config.php">Config PHP</a> |
                <a href="/phpinfo.php">PHPInfo</a>
            </div>
            
        </div>
    </body>
    </html>
    """
    return html


# ========== XSS VULNÉRABLE ==========
@app.route('/xss')
def xss_vuln():
    """XSS reflected - pas de sanitization"""
    name = request.args.get('name', 'Guest')
    # VULNÉRABLE: Pas d'escape HTML
    html = f"""
    <html>
    <head><title>XSS Test</title></head>
    <body>
        <h1>Bonjour {name}!</h1>
        <a href="/">Retour</a>
    </body>
    </html>
    """
    return html


# ========== SQLi VULNÉRABLE ==========
@app.route('/sqli')
def sqli_vuln():
    """SQL Injection simulée"""
    user_id = request.args.get('id', '1')
    
    # Simuler une erreur SQL si injection détectée
    if "'" in user_id or "--" in user_id or "OR" in user_id.upper():
        return f"""
        <html>
        <body>
            <h1>Error</h1>
            <p style="color: red;">
            SQL Error: You have an error in your SQL syntax near '{user_id}'<br>
            Query: SELECT * FROM users WHERE id = '{user_id}'
            </p>
            <pre>
            MySQL error: Syntax error near '{user_id}' at line 1
            </pre>
            <a href="/">Retour</a>
        </body>
        </html>
        """, 500
    
    return f"""
    <html>
    <body>
        <h1>User ID: {user_id}</h1>
        <p>Username: admin</p>
        <p>Email: admin@example.com</p>
        <a href="/">Retour</a>
    </body>
    </html>
    """


# ========== CMDi VULNÉRABLE ==========
@app.route('/cmd')
def cmd_vuln():
    """Command Injection - VULNÉRABLE"""
    filename = request.args.get('file', 'test.txt')
    
    try:
        # VULNÉRABLE: Exécute directement la commande
        result = subprocess.run(
            f"cat {filename}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=2
        )
        
        output = result.stdout if result.stdout else result.stderr
        
        return f"""
        <html>
        <body>
            <h1>File Content</h1>
            <pre>{output}</pre>
            <a href="/">Retour</a>
        </body>
        </html>
        """
    
    except Exception as e:
        return f"Error: {str(e)}", 500


# ========== Directory Traversal VULNÉRABLE ==========
@app.route('/file')
def file_vuln():
    """Directory Traversal - VULNÉRABLE"""
    path = request.args.get('path', 'test.txt')
    
    try:
        # VULNÉRABLE: Pas de validation du path
        with open(path, 'r') as f:
            content = f.read()
        
        return f"""
        <html>
        <body>
            <h1>File: {path}</h1>
            <pre>{content}</pre>
            <a href="/">Retour</a>
        </body>
        </html>
        """
    
    except Exception as e:
        return f"Error reading file: {str(e)}", 404


# ========== IDOR VULNÉRABLE ==========
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    """IDOR - Pas de vérification d'autorisation"""
    users = {
        1: {"name": "Admin", "email": "admin@example.com", "role": "admin"},
        2: {"name": "User", "email": "user@example.com", "role": "user"},
        999: {"name": "Secret User", "email": "secret@private.com", "role": "secret"}
    }
    
    user = users.get(user_id, None)
    
    if not user:
        return "User not found", 404
    
    return f"""
    <html>
    <body>
        <h1>User Profile #{user_id}</h1>
        <p>Name: {user['name']}</p>
        <p>Email: {user['email']}</p>
        <p>Role: {user['role']}</p>
        <a href="/">Retour</a>
    </body>
    </html>
    """


# ========== CORS VULNÉRABLE ==========
@app.route('/api/data')
def api_cors():
    """CORS Misconfiguration"""
    origin = request.headers.get('Origin', '*')
    
    response = jsonify({
        "secret": "api_key_12345",
        "data": "sensitive information"
    })
    
    # VULNÉRABLE: CORS wildcard + credentials
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response


# ========== Info Disclosure VULNÉRABLE ==========
@app.route('/.env')
def env_file():
    """Fichier .env exposé"""
    return """
DB_PASSWORD=super_secret_password_123
API_KEY=sk-1234567890abcdef
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SECRET_KEY=django-insecure-secret-key-12345
    """


@app.route('/config.php')
def config_php():
    """Fichier config.php exposé"""
    return """
<?php
$db_host = "localhost";
$db_user = "root";
$db_pass = "root123";
$db_name = "myapp";
$api_key = "secret_api_key_12345";
?>
    """


@app.route('/phpinfo.php')
def phpinfo():
    """PHPInfo simulé"""
    return """
    <html>
    <body>
        <h1>PHP Version 7.4.3</h1>
        <table>
            <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
            <tr><td>System</td><td>Linux localhost 5.4.0</td></tr>
            <tr><td>allow_url_fopen</td><td>On</td></tr>
            <tr><td>display_errors</td><td>On</td></tr>
        </table>
    </body>
    </html>
    """


if __name__ == '__main__':
    print("=" * 70)
    print("🔥 SERVEUR VULNÉRABLE - ShieldAI V2 Test Server")
    print("=" * 70)
    print("⚠️  ATTENTION: Ce serveur contient des vulnérabilités!")
    print("⚠️  Utilisez UNIQUEMENT en local (localhost)")
    print("⚠️  NE JAMAIS déployer en production!")
    print("🌐 Serveur: http://localhost:5000")
    print("📊 Vulnérabilités: XSS, SQLi, CMDi, DirTrav, IDOR, CORS, InfoDisc")
    print("=" * 70)
    
    # Lancer SANS debug mode (pas de watchdog)
    app.run(host='0.0.0.0', port=5000, debug=False)
