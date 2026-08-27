#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SERVEUR DE TEST VULNÉRABLE V2 - ShieldAI Scanner
═══════════════════════════════════════════════════════════════════════════════
⚠️  ATTENTION : NE JAMAIS DÉPLOYER EN PRODUCTION ! ⚠️

Ce serveur expose INTENTIONNELLEMENT toutes les vulnérabilités couvertes par
les payloads_v2.json v3.0.0 pour permettre de tester le scanner ShieldAI.

Vulnérabilités couvertes (30) :
  XSS, SQLi, CMDi, DirTrav, XXE, SSRF, SSTI, NoSQLi, LDAPi,
  CORS, CSRF, OpenRedirect, InsecUpload, JWT, GraphQLi, IDOR,
  Prototype_Pollution, InsecDeser, RaceCondition, HTTP_Request_Smuggling,
  CRLF_Injection, XPATH_Injection, RateLimit, InfoDisc, InsecCrypto,
  CredsExpose, BrokenAuth, InsecPerm, SessFix, BufOvr

Utilisation :
  pip install flask flask-cors lxml pyjwt
  python vuln_server_v2.py
  → http://localhost:5000

Author : Samuel - ShieldAI
Date   : 2026-03-14
Version: 2.0.0
"""

import os
import re
import sys
import time
import json
import math
import uuid
import base64
import pickle
import sqlite3
import hashlib
import threading
import subprocess
from io import BytesIO
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import (
    Flask, request, render_template_string, redirect,
    make_response, jsonify, send_file, session, Response
)
from flask_cors import CORS

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import lxml.etree as ET_LXML
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

import xml.etree.ElementTree as ET

# ══════════════════════════════════════════════════════════════════════════════
# ⚙️  CONFIG
# ══════════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = "shieldai_insecure_secret_key_do_not_use_in_prod"

UPLOAD_FOLDER = '/tmp/shieldai_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CORS totalement ouvert ⚠️
CORS(app, origins="*", supports_credentials=True)

# Compteur de requêtes pour RateLimit
_request_counts: dict = defaultdict(deque)
_rate_lock = threading.Lock()

# Verrou partagé pour RaceCondition
_account_balance = {"user1": 1000, "user2": 500}
_balance_lock = threading.Lock()

# Tokens JWT valides en mémoire
_valid_tokens: dict = {}

# Coupons utilisés (pour RaceCondition)
_used_coupons: set = set()
_coupon_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# 🗄️  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT,
        email TEXT, role TEXT, ssn TEXT, credit_card TEXT, phone TEXT
    )''')
    c.execute('''CREATE TABLE documents (
        id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, content TEXT, is_private INTEGER
    )''')
    c.execute('''CREATE TABLE orders (
        id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, amount REAL
    )''')
    c.execute('''CREATE TABLE xml_users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT
    )''')
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", [
        (1, 'admin',     'admin123',   'admin@shieldai.io',  'admin',   '123-45-6789', '4111111111111111', '+1-555-0100'),
        (2, 'alice',     'alice2026',  'alice@example.com',  'user',    '987-65-4321', '4222222222222222', '+1-555-0101'),
        (3, 'bob',       'bobsecret',  'bob@example.com',    'user',    '111-22-3333', '4333333333333333', '+1-555-0102'),
        (4, 'moderator', 'mod@pass',   'mod@shieldai.io',    'mod',     '222-33-4444', '4444444444444444', '+1-555-0103'),
    ])
    c.executemany("INSERT INTO documents VALUES (?,?,?,?,?)", [
        (1, 1, 'Admin Report',    'Confidential admin report content', 1),
        (2, 2, 'Alice Notes',     'Alice private notes',               1),
        (3, 3, 'Public Doc',      'This is public content',            0),
        (4, 1, 'Secret Config',   'DB_PASSWORD=admin123',              1),
    ])
    c.executemany("INSERT INTO orders VALUES (?,?,?,?)", [
        (1, 1, 'Premium Plan', 299.99),
        (2, 2, 'Basic Plan',   9.99),
        (3, 3, 'Pro Plan',     99.99),
    ])
    c.executemany("INSERT INTO xml_users VALUES (?,?,?)", [
        (1, 'admin', 'xmlpass123'),
        (2, 'guest', 'guest'),
    ])
    conn.commit()
    return conn

DB = init_db()
DB_LOCK = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# 🏠  HOME PAGE
# ══════════════════════════════════════════════════════════════════════════════
HOME = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>ShieldAI — Vulnerable Test Server v2</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:30px}
  h1{color:#f85149;font-size:2em;margin-bottom:6px}
  .sub{color:#8b949e;margin-bottom:30px}
  .warn{background:#161b22;border:2px solid #f85149;border-radius:8px;padding:16px;margin-bottom:30px}
  .warn h2{color:#f85149;font-size:1em;margin-bottom:6px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
  .card h2{font-size:.9em;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #30363d}
  .card h2.crit{color:#f85149}.card h2.high{color:#e67e22}.card h2.med{color:#f1c40f}.card h2.info{color:#58a6ff}
  a{color:#58a6ff;text-decoration:none;display:block;padding:4px 0;font-size:.9em}
  a:hover{color:#79c0ff;text-decoration:underline}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75em;font-weight:bold;margin-left:6px}
  .b-get{background:#1f6feb33;color:#58a6ff}.b-post{background:#1a7f3433;color:#3fb950}
  .b-both{background:#6e407333;color:#d2a8ff}
  footer{text-align:center;margin-top:40px;color:#8b949e;font-size:.85em}
  code{background:#21262d;padding:1px 6px;border-radius:4px;font-size:.85em;color:#f0883e}
</style>
</head>
<body>
<div class="warn">
  <h2>⚠️ SERVEUR INTENTIONNELLEMENT VULNÉRABLE — TEST SHIELDAI UNIQUEMENT ⚠️</h2>
  <p>Ce serveur contient 30 catégories de vulnérabilités. Utiliser UNIQUEMENT sur localhost. Ne jamais exposer sur un réseau.</p>
</div>
<h1>🔥 ShieldAI Vulnerable Server v2</h1>
<p class="sub">30 vulnérabilités · payloads_v2.json v3.0.0 · Port 5000</p>

<div class="grid">

  <div class="card">
    <h2 class="crit">🎯 XSS — Cross-Site Scripting</h2>
    <a href="/xss/reflected?q=test">Reflected XSS (query param) <span class="badge b-get">GET</span></a>
    <a href="/xss/stored">Stored XSS (comments) <span class="badge b-both">GET/POST</span></a>
    <a href="/xss/dom">DOM-based XSS (hash) <span class="badge b-get">GET</span></a>
    <a href="/xss/header">XSS via User-Agent header <span class="badge b-get">GET</span></a>
    <a href="/xss/json?callback=test">XSS via JSONP callback <span class="badge b-get">GET</span></a>
    <a href="/xss/attr?name=test">XSS via attribute <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">💉 SQLi — SQL Injection</h2>
    <a href="/sqli/search?id=1">Error-based SQLi (GET) <span class="badge b-get">GET</span></a>
    <a href="/sqli/login">Auth bypass SQLi <span class="badge b-both">GET/POST</span></a>
    <a href="/sqli/union?id=1">UNION-based SQLi <span class="badge b-get">GET</span></a>
    <a href="/sqli/time?id=1">Time-based SQLi <span class="badge b-get">GET</span></a>
    <a href="/sqli/blind?id=1">Boolean-blind SQLi <span class="badge b-get">GET</span></a>
    <a href="/sqli/cookie">SQLi via Cookie <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">💻 CMDi — Command Injection</h2>
    <a href="/cmdi/ping">Ping tool <span class="badge b-both">GET/POST</span></a>
    <a href="/cmdi/system">System info <span class="badge b-both">GET/POST</span></a>
    <a href="/cmdi/lookup?host=localhost">DNS lookup <span class="badge b-get">GET</span></a>
    <a href="/cmdi/convert">File convert (blind) <span class="badge b-both">GET/POST</span></a>
  </div>

  <div class="card">
    <h2 class="high">📁 DirTrav — Directory Traversal</h2>
    <a href="/file/read?path=vuln_server_v2.py">File read (query) <span class="badge b-get">GET</span></a>
    <a href="/download?file=requirements.txt">File download <span class="badge b-get">GET</span></a>
    <a href="/static_file/test.txt">Static file traversal <span class="badge b-get">GET</span></a>
    <a href="/template?page=home">Template include <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">📋 XXE — XML External Entity</h2>
    <a href="/xml/parse">XML parser (POST) <span class="badge b-both">GET/POST</span></a>
    <a href="/xml/import">XML import / OOB <span class="badge b-both">GET/POST</span></a>
    <a href="/xml/soap">SOAP endpoint <span class="badge b-both">GET/POST</span></a>
  </div>

  <div class="card">
    <h2 class="high">🔗 SSRF — Server-Side Request Forgery</h2>
    <a href="/ssrf/fetch">Fetch any URL <span class="badge b-both">GET/POST</span></a>
    <a href="/ssrf/webhook">Webhook tester <span class="badge b-both">GET/POST</span></a>
    <a href="/ssrf/preview?url=http://example.com">URL preview <span class="badge b-get">GET</span></a>
    <a href="/ssrf/avatar?url=http://example.com">Avatar proxy <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🧩 SSTI — Template Injection</h2>
    <a href="/ssti/greet?name=World">Jinja2-style SSTI <span class="badge b-get">GET</span></a>
    <a href="/ssti/render">Template render (POST) <span class="badge b-both">GET/POST</span></a>
    <a href="/ssti/email?to=test@test.com">Email template <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">🗄️ NoSQLi — NoSQL Injection</h2>
    <a href="/nosql/login">MongoDB auth bypass <span class="badge b-both">GET/POST</span></a>
    <a href="/nosql/search?q=admin">NoSQL search <span class="badge b-get">GET</span></a>
    <a href="/nosql/users">NoSQL $where bypass <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">📂 LDAPi — LDAP Injection</h2>
    <a href="/ldap/login">LDAP auth bypass <span class="badge b-both">GET/POST</span></a>
    <a href="/ldap/search?uid=admin">LDAP search injection <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">🌐 CORS — Misconfiguration</h2>
    <a href="/cors/api">Wildcard CORS + credentials <span class="badge b-get">GET</span></a>
    <a href="/cors/sensitive">Origin reflection <span class="badge b-get">GET</span></a>
    <a href="/cors/null">Null origin <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">🔄 CSRF — Forgery</h2>
    <a href="/csrf/transfer">Money transfer (no token) <span class="badge b-both">GET/POST</span></a>
    <a href="/csrf/delete">Delete account <span class="badge b-both">GET/POST</span></a>
    <a href="/csrf/email">Change email <span class="badge b-both">GET/POST</span></a>
    <a href="/csrf/password">Change password <span class="badge b-both">GET/POST</span></a>
  </div>

  <div class="card">
    <h2 class="med">↪️ OpenRedirect — Open Redirect</h2>
    <a href="/redirect?next=http://example.com">Redirect via next <span class="badge b-get">GET</span></a>
    <a href="/logout?return_to=http://example.com">Logout redirect <span class="badge b-get">GET</span></a>
    <a href="/login?redirect=/dashboard">Login redirect <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">📤 InsecUpload — File Upload</h2>
    <a href="/upload">Upload form (no restriction) <span class="badge b-both">GET/POST</span></a>
    <a href="/upload/avatar">Avatar upload <span class="badge b-both">GET/POST</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🔑 JWT — Vulnerabilities</h2>
    <a href="/jwt/login">JWT login (weak secret) <span class="badge b-both">GET/POST</span></a>
    <a href="/jwt/profile">JWT profile (alg:none) <span class="badge b-get">GET</span></a>
    <a href="/jwt/admin">JWT admin escalation <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">🔎 GraphQLi — GraphQL</h2>
    <a href="/graphql">GraphQL endpoint <span class="badge b-both">GET/POST</span></a>
    <a href="/graphql/playground">GraphQL playground <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">🔓 IDOR — Direct Object Reference</h2>
    <a href="/api/users/1">User profile IDOR <span class="badge b-get">GET</span></a>
    <a href="/api/documents/1">Document IDOR <span class="badge b-get">GET</span></a>
    <a href="/api/orders/1">Order IDOR <span class="badge b-get">GET</span></a>
    <a href="/api/invoices/1">Invoice IDOR <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">☣️ Prototype_Pollution</h2>
    <a href="/proto/merge">Object merge (POST JSON) <span class="badge b-both">GET/POST</span></a>
    <a href="/proto/extend?__proto__[isAdmin]=true">Query param pollution <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🔓 InsecDeser — Deserialization</h2>
    <a href="/deserialize/pickle">Pickle (Python) <span class="badge b-both">GET/POST</span></a>
    <a href="/deserialize/json">JSON (Node-style) <span class="badge b-both">GET/POST</span></a>
    <a href="/deserialize/cookie">Cookie deserialize <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">⚡ RaceCondition</h2>
    <a href="/race/coupon">Coupon redemption <span class="badge b-both">GET/POST</span></a>
    <a href="/race/transfer">Concurrent transfer <span class="badge b-both">GET/POST</span></a>
    <a href="/race/vote?post_id=1">Vote race <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🚦 HTTP_Request_Smuggling</h2>
    <a href="/smuggle/endpoint">CL.TE / TE.CL endpoint <span class="badge b-get">GET</span></a>
    <a href="/smuggle/te-te">TE.TE obfuscation <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">💉 CRLF_Injection</h2>
    <a href="/crlf/header?name=test">CRLF in response header <span class="badge b-get">GET</span></a>
    <a href="/crlf/log?data=test">CRLF log poisoning <span class="badge b-get">GET</span></a>
    <a href="/crlf/redirect?url=http://example.com">CRLF redirect <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">📐 XPATH_Injection</h2>
    <a href="/xpath/login">XPath auth bypass <span class="badge b-both">GET/POST</span></a>
    <a href="/xpath/search?q=admin">XPath search injection <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">⏱️ RateLimit — Bypass</h2>
    <a href="/ratelimit/api?key=test">No rate limit endpoint <span class="badge b-get">GET</span></a>
    <a href="/ratelimit/xff">X-Forwarded-For bypass <span class="badge b-get">GET</span></a>
    <a href="/ratelimit/login">Login brute force <span class="badge b-both">GET/POST</span></a>
  </div>

  <div class="card">
    <h2 class="med">ℹ️ InfoDisc — Disclosure</h2>
    <a href="/.env">Exposed .env <span class="badge b-get">GET</span></a>
    <a href="/.git/config">Exposed .git/config <span class="badge b-get">GET</span></a>
    <a href="/phpinfo">phpinfo() style <span class="badge b-get">GET</span></a>
    <a href="/debug">Debug endpoint <span class="badge b-get">GET</span></a>
    <a href="/actuator/env">Spring Actuator /env <span class="badge b-get">GET</span></a>
    <a href="/actuator/heapdump">Spring Actuator /heapdump <span class="badge b-get">GET</span></a>
    <a href="/swagger.json">Swagger/OpenAPI spec <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="med">🔒 InsecCrypto — Weak Crypto</h2>
    <a href="/crypto/hash?data=test">MD5/SHA1 weak hash <span class="badge b-get">GET</span></a>
    <a href="/crypto/token?user=admin">Predictable token <span class="badge b-get">GET</span></a>
    <a href="/crypto/tls-info">TLS/cipher info <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🗝️ CredsExpose — Credentials</h2>
    <a href="/.env">Exposed .env <span class="badge b-get">GET</span></a>
    <a href="/.aws/credentials">AWS credentials <span class="badge b-get">GET</span></a>
    <a href="/wp-config.php">WP config <span class="badge b-get">GET</span></a>
    <a href="/config.json">Config JSON <span class="badge b-get">GET</span></a>
    <a href="/database.yml">DB config YAML <span class="badge b-get">GET</span></a>
    <a href="/secrets.yml">Secrets YAML <span class="badge b-get">GET</span></a>
    <a href="/.netrc">Netrc credentials <span class="badge b-get">GET</span></a>
    <a href="/id_rsa">SSH private key <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">🔐 BrokenAuth — Auth Bypass</h2>
    <a href="/auth/login">Default creds login <span class="badge b-both">GET/POST</span></a>
    <a href="/auth/reset">Insecure password reset <span class="badge b-both">GET/POST</span></a>
    <a href="/auth/token">Auth via token (no expiry) <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">🚫 InsecPerm — Broken Access</h2>
    <a href="/admin">Admin panel (no auth) <span class="badge b-get">GET</span></a>
    <a href="/admin/users">Admin users list <span class="badge b-get">GET</span></a>
    <a href="/api/admin">Admin API endpoint <span class="badge b-get">GET</span></a>
    <a href="/actuator/env">Actuator env <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="high">🍪 SessFix — Session Fixation</h2>
    <a href="/session/fixate?sessionid=attacker_123">Session fixation <span class="badge b-get">GET</span></a>
    <a href="/session/weak">Weak session ID <span class="badge b-get">GET</span></a>
    <a href="/session/info">Session info leak <span class="badge b-get">GET</span></a>
  </div>

  <div class="card">
    <h2 class="crit">💥 BufOvr — Buffer Overflow (HTTP)</h2>
    <a href="/bufovr/input?data=AAAA">Large input handling <span class="badge b-get">GET</span></a>
    <a href="/bufovr/header">Oversized header <span class="badge b-get">GET</span></a>
    <a href="/bufovr/format">Format string probe <span class="badge b-get">GET</span></a>
  </div>

</div>

<footer>
  ShieldAI Vulnerable Test Server v2.0.0 · 30 vulnerabilities · Port 5000 ·
  <strong style="color:#f85149">⚠️ LOCAL USE ONLY</strong>
</footer>
</body>
</html>"""

@app.route('/')
def index():
    return HOME

# ══════════════════════════════════════════════════════════════════════════════
# 🎯 XSS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xss/reflected')
def xss_reflected():
    """⚠️ Reflected XSS — paramètre q directement dans le HTML"""
    q = request.args.get('q', '')
    return f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {q}</p>
<form><input name="q" value="{q}"><button>Search</button></form>
<a href="/">Back</a></body></html>"""

@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    """⚠️ Stored XSS — commentaires stockés sans sanitisation"""
    if not hasattr(app, '_comments'):
        app._comments = []
    if request.method == 'POST':
        app._comments.append(request.form.get('comment', ''))
    comments_html = ''.join(f'<li class="comment">{c}</li>' for c in app._comments)
    return f"""<html><body>
<h1>Comments ({len(app._comments)})</h1>
<form method="post">
  <textarea name="comment" rows="3" cols="60"></textarea><br>
  <button>Post Comment</button>
</form>
<ul>{comments_html}</ul>
<a href="/">Back</a></body></html>"""

@app.route('/xss/dom')
def xss_dom():
    """⚠️ DOM XSS — hash passé à innerHTML"""
    return """<html><body>
<h1>DOM XSS</h1>
<div id="out"></div>
<script>
  var h = decodeURIComponent(window.location.hash.substr(1));
  document.getElementById('out').innerHTML = 'Welcome, ' + h;
</script>
<p>Try: <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
<a href="/">Back</a></body></html>"""

@app.route('/xss/header')
def xss_header():
    """⚠️ XSS via User-Agent reflété sans escape"""
    ua = request.headers.get('User-Agent', 'unknown')
    return f"""<html><body>
<h1>Browser Info</h1>
<p>Your User-Agent: {ua}</p>
<a href="/">Back</a></body></html>"""

@app.route('/xss/json')
def xss_jsonp():
    """⚠️ XSS via JSONP — callback injecté sans validation"""
    callback = request.args.get('callback', 'callback')
    data = '{"user":"admin","token":"secret123"}'
    return Response(f'{callback}({data})', content_type='application/javascript')

@app.route('/xss/attr')
def xss_attr():
    """⚠️ XSS via attribut HTML"""
    name = request.args.get('name', 'guest')
    return f"""<html><body>
<h1>Profile</h1>
<img src="/static/avatar.png" alt="{name}" title="{name}" onerror="this.src='/missing'">
<p>Welcome, <span class="username" data-user="{name}">{name}</span></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 💉 SQLi
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/sqli/search')
def sqli_search():
    """⚠️ Error-based SQLi via id"""
    user_id = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT id, username, email, role FROM users WHERE id={user_id}")
            row = cur.fetchone()
        result = f"User: {row[1]}, Email: {row[2]}, Role: {row[3]}" if row else "User not found"
    except Exception as e:
        result = f"SQL Error: {str(e)}"
    return f"""<html><body>
<h1>User Search</h1>
<p>{result}</p>
<p><small>Hint: try <code>?id=1 UNION SELECT username,password,email,role FROM users--</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/sqli/login', methods=['GET', 'POST'])
def sqli_login():
    """⚠️ Auth bypass via SQLi"""
    msg = ""
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute(q)
                row = cur.fetchone()
            msg = f"✅ Login successful! Welcome {row[1]} (role={row[4]})" if row else "❌ Invalid credentials"
        except Exception as e:
            msg = f"SQL Error: {str(e)}"
    return f"""<html><body>
<h1>Login</h1>
<form method="post">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<p><small>Hint: <code>admin' --</code> | <code>' OR '1'='1</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/sqli/union')
def sqli_union():
    """⚠️ UNION-based SQLi — résultats multi-colonnes"""
    user_id = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT username, email FROM users WHERE id={user_id}")
            rows = cur.fetchall()
        output = "".join(f"<li>{r[0]} — {r[1]}</li>" for r in rows) or "<li>No results</li>"
    except Exception as e:
        output = f"<li>SQL Error: {str(e)}</li>"
    return f"""<html><body>
<h1>UNION SQLi</h1>
<ul>{output}</ul>
<p><small>Hint: <code>?id=1 UNION SELECT password,'x' FROM users--</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/sqli/time')
def sqli_time():
    """⚠️ Time-based SQLi — SQLite simule le délai via Python"""
    user_id = request.args.get('id', '1')
    start = time.time()
    try:
        with DB_LOCK:
            cur = DB.cursor()
            # SQLite ne supporte pas SLEEP() — on simule côté serveur
            if 'sleep' in user_id.lower():
                # Extraire le nombre de secondes s'il est présent
                m = re.search(r'sleep\s*\(\s*(\d+)\s*\)', user_id, re.I)
                delay = min(int(m.group(1)), 10) if m else 5
                time.sleep(delay)
                result = "Query executed"
            else:
                cur.execute(f"SELECT * FROM users WHERE id={user_id}")
                row = cur.fetchone()
                result = f"User: {row[1]}" if row else "Not found"
    except Exception as e:
        result = f"SQL Error: {str(e)}"
    elapsed = time.time() - start
    return f"""<html><body>
<h1>Time-based SQLi</h1>
<p>{result}</p>
<p>Elapsed: {elapsed:.3f}s</p>
<p><small>Hint: <code>?id=1 AND SLEEP(5)--</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/sqli/blind')
def sqli_blind():
    """⚠️ Boolean-blind SQLi — réponse différente selon condition"""
    user_id = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT id FROM users WHERE id={user_id}")
            row = cur.fetchone()
        result = "Record exists." if row else "Record not found."
    except Exception as e:
        result = f"SQL Error: {str(e)}"
    return f"""<html><body>
<h1>Boolean-Blind SQLi</h1>
<p>{result}</p>
<p><small>Hint: compare <code>?id=1 AND 1=1</code> vs <code>?id=1 AND 1=2</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/sqli/cookie')
def sqli_cookie():
    """⚠️ SQLi via cookie session_user"""
    user_id = request.cookies.get('session_user', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT username, email FROM users WHERE id={user_id}")
            row = cur.fetchone()
        result = f"Session user: {row[0]} ({row[1]})" if row else "Unknown session"
    except Exception as e:
        result = f"SQL Error: {str(e)}"
    resp = make_response(f"""<html><body>
<h1>Cookie-based SQLi</h1>
<p>{result}</p>
<p><small>Cookie: <code>session_user=1</code> — try injecting via cookie header</small></p>
<a href="/">Back</a></body></html>""")
    resp.set_cookie('session_user', user_id)
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# 💻 CMDi
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/cmdi/ping', methods=['GET', 'POST'])
def cmdi_ping():
    """⚠️ Command Injection via ping"""
    output = ""
    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1')
        try:
            result = subprocess.run(
                f"ping -c 2 {host}", shell=True,
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {e}"
    return f"""<html><body>
<h1>Ping Tool</h1>
<form method="post">
  <input name="host" value="127.0.0.1" size="40">
  <button>Ping</button>
</form>
<pre>{output}</pre>
<p><small>Hint: <code>127.0.0.1; echo SHLDXXX-$(id)-$(hostname)</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/cmdi/system', methods=['GET', 'POST'])
def cmdi_system():
    """⚠️ Direct command execution"""
    output = ""
    if request.method == 'POST':
        cmd = request.form.get('cmd', 'uname -a')
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {e}"
    return f"""<html><body>
<h1>System Info</h1>
<form method="post">
  <input name="cmd" value="uname -a" size="60">
  <button>Execute</button>
</form>
<pre>{output}</pre>
<a href="/">Back</a></body></html>"""

@app.route('/cmdi/lookup')
def cmdi_lookup():
    """⚠️ CMDi via DNS lookup"""
    host = request.args.get('host', 'localhost')
    try:
        result = subprocess.run(f"nslookup {host}", shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
    except Exception as e:
        output = f"Error: {e}"
    return f"""<html><body>
<h1>DNS Lookup</h1>
<pre>{output}</pre>
<p><small>Hint: <code>?host=localhost;echo SHLDXXX-$(id)</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/cmdi/convert', methods=['GET', 'POST'])
def cmdi_convert():
    """⚠️ Blind CMDi via file conversion (no output shown)"""
    msg = ""
    if request.method == 'POST':
        filename = request.form.get('filename', 'test.txt')
        try:
            # ⚠️ Blind — output n'est pas affiché
            subprocess.run(f"file {filename}", shell=True, capture_output=True, text=True, timeout=5)
            msg = "Conversion queued."
        except Exception as e:
            msg = "Conversion failed."
    return f"""<html><body>
<h1>File Converter (Blind CMDi)</h1>
<form method="post">
  <input name="filename" value="test.txt" size="40">
  <button>Convert</button>
</form>
<p>{msg}</p>
<p><small>Hint: inject sleep for blind detection</small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 📁 Directory Traversal
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/file/read')
def file_read():
    """⚠️ Directory Traversal — pas de validation du chemin"""
    path = request.args.get('path', 'vuln_server_v2.py')
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read(4096)
    except Exception as e:
        content = f"Error: {e}"
    return f"""<html><body>
<h1>File Reader</h1>
<pre>{content}</pre>
<p><small>Hint: <code>?path=../../../../etc/passwd</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/download')
def file_download():
    """⚠️ Directory Traversal via download"""
    fname = request.args.get('file', 'test.txt')
    try:
        return send_file(fname)
    except Exception as e:
        return f"Error: {e}", 404

@app.route('/static_file/<path:filename>')
def static_file(filename):
    """⚠️ Path traversal via static file serving"""
    base = '/tmp'
    try:
        full = os.path.join(base, filename)
        with open(full, 'r', errors='replace') as f:
            content = f.read(4096)
        return content, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        return f"File not found: {e}", 404

@app.route('/template')
def template_include():
    """⚠️ LFI via template include"""
    page = request.args.get('page', 'home')
    fname = f"templates/{page}.html"
    try:
        with open(fname, 'r') as f:
            return f.read()
    except Exception as e:
        return f"""<html><body>
<h1>Template: {page}</h1>
<p>Error loading template: {e}</p>
<p><small>Hint: <code>?page=../../../../etc/passwd</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 📋 XXE
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xml/parse', methods=['GET', 'POST'])
def xxe_parse():
    """⚠️ XXE — parsing XML sans protection"""
    result = ""
    if request.method == 'POST':
        xml_data = request.form.get('xml', '') or request.data.decode('utf-8', errors='replace')
        try:
            if LXML_AVAILABLE:
                # lxml avec resolve_entities=True ⚠️
                parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False)
                root = ET_LXML.fromstring(xml_data.encode(), parser)
                result = ET_LXML.tostring(root, encoding='unicode')
            else:
                root = ET.fromstring(xml_data)
                result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            result = f"XML Error: {str(e)}"
    return f"""<html><body>
<h1>XML Parser</h1>
<form method="post" enctype="application/x-www-form-urlencoded">
  <textarea name="xml" rows="8" cols="60">&lt;root&gt;&lt;data&gt;test&lt;/data&gt;&lt;/root&gt;</textarea><br>
  <button>Parse</button>
</form>
<pre>{result}</pre>
<p><small>Hint: XXE payload to read /etc/passwd</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/xml/import', methods=['GET', 'POST'])
def xxe_import():
    """⚠️ XXE avec OOB possible"""
    result = ""
    if request.method == 'POST':
        raw = request.get_data(as_text=True)
        try:
            if LXML_AVAILABLE:
                parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
                root = ET_LXML.fromstring(raw.encode(), parser)
                result = ET_LXML.tostring(root, encoding='unicode')
            else:
                result = "lxml not available — basic parser used"
        except Exception as e:
            result = f"XML Error: {str(e)}"
    return jsonify({"result": result}) if request.content_type == 'application/xml' else (
        f"""<html><body><h1>XML Import</h1><pre>{result}</pre>
<p><small>POST raw XML with Content-Type: application/xml</small></p>
<a href="/">Back</a></body></html>""")

@app.route('/xml/soap', methods=['GET', 'POST'])
def xxe_soap():
    """⚠️ SOAP endpoint vulnérable à XXE"""
    result = ""
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        try:
            root = ET.fromstring(body)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            result = f"SOAP Error: {str(e)}"
    return f"""<html><body>
<h1>SOAP Endpoint</h1>
<p>POST SOAP/XML envelope here</p>
<pre>{result}</pre>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 🔗 SSRF
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/ssrf/fetch', methods=['GET', 'POST'])
def ssrf_fetch():
    """⚠️ SSRF — fetche n'importe quelle URL"""
    result = ""
    if request.method == 'POST':
        url = request.form.get('url', '')
        try:
            import urllib.request as ur
            resp = ur.urlopen(url, timeout=4)
            result = resp.read().decode('utf-8', errors='replace')[:2000]
        except Exception as e:
            result = f"Error: {e}"
    return f"""<html><body>
<h1>URL Fetcher (SSRF)</h1>
<form method="post">
  <input name="url" value="http://example.com" size="60"><br>
  <button>Fetch</button>
</form>
<pre>{result}</pre>
<p><small>Hints: <code>http://169.254.169.254/latest/meta-data/</code> | <code>file:///etc/passwd</code> | <code>http://localhost:5000/.env</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/ssrf/webhook', methods=['GET', 'POST'])
def ssrf_webhook():
    """⚠️ SSRF via webhook URL"""
    result = ""
    if request.method == 'POST':
        webhook_url = request.form.get('webhook_url', '')
        payload_data = request.form.get('data', '{}')
        try:
            import urllib.request as ur
            req = ur.Request(webhook_url, data=payload_data.encode(), method='POST')
            resp = ur.urlopen(req, timeout=4)
            result = f"Webhook sent, response: {resp.read().decode()[:500]}"
        except Exception as e:
            result = f"Webhook error: {e}"
    return f"""<html><body>
<h1>Webhook Tester</h1>
<form method="post">
  <input name="webhook_url" placeholder="https://your-webhook.io" size="60"><br>
  <textarea name="data" rows="3" cols="60">{{"event":"test"}}</textarea><br>
  <button>Send</button>
</form>
<pre>{result}</pre>
<a href="/">Back</a></body></html>"""

@app.route('/ssrf/preview')
def ssrf_preview():
    """⚠️ SSRF via URL preview"""
    url = request.args.get('url', 'http://example.com')
    try:
        import urllib.request as ur
        resp = ur.urlopen(url, timeout=3)
        content = resp.read().decode('utf-8', errors='replace')[:500]
    except Exception as e:
        content = f"Preview error: {e}"
    return f"""<html><body>
<h1>URL Preview</h1>
<iframe-preview>{content}</iframe-preview>
<pre>{content}</pre>
<a href="/">Back</a></body></html>"""

@app.route('/ssrf/avatar')
def ssrf_avatar():
    """⚠️ SSRF via avatar proxy"""
    url = request.args.get('url', '')
    try:
        import urllib.request as ur
        resp = ur.urlopen(url, timeout=3)
        data = resp.read()
        ctype = resp.headers.get('Content-Type', 'image/png')
        return Response(data, content_type=ctype)
    except Exception as e:
        return f"Error fetching avatar: {e}", 500

# ══════════════════════════════════════════════════════════════════════════════
# 🧩 SSTI
# ══════════════════════════════════════════════════════════════════════════════

def _ssti_eval(expr: str) -> str:
    """Simule l'évaluation SSTI côté serveur (Jinja2-style unsafe)"""
    # Détection de {{...}} et évaluation — intentionnellement vulnérable
    def replacer(m):
        inner = m.group(1).strip()
        try:
            # Évalue les expressions arithmétiques et quelques builtins
            result = eval(inner, {"__builtins__": {"__import__": __import__}})
            return str(result)
        except Exception as e:
            return f"[ssti_error: {e}]"
    return re.sub(r'\{\{(.+?)\}\}', replacer, expr)

@app.route('/ssti/greet')
def ssti_greet():
    """⚠️ SSTI — nom passé dans un template évalué côté serveur"""
    name = request.args.get('name', 'World')
    # ⚠️ eval direct du template
    rendered = _ssti_eval(f"Hello, {name}!")
    return f"""<html><body>
<h1>SSTI Greet</h1>
<p>{rendered}</p>
<p><small>Hint: <code>?name={{{{1337*1337}}}}</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/ssti/render', methods=['GET', 'POST'])
def ssti_render():
    """⚠️ SSTI — template rendu côté serveur"""
    result = ""
    template = ""
    if request.method == 'POST':
        template = request.form.get('template', '')
        result = _ssti_eval(template)
    return f"""<html><body>
<h1>Template Renderer (SSTI)</h1>
<form method="post">
  <textarea name="template" rows="4" cols="60">{template}</textarea><br>
  <button>Render</button>
</form>
<pre>Output: {result}</pre>
<p><small>Hint: <code>{{{{1337*1337}}}}</code> → 1787569</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/ssti/email')
def ssti_email():
    """⚠️ SSTI dans un template d'email"""
    to = request.args.get('to', 'user@example.com')
    subject = request.args.get('subject', 'Welcome')
    body_tpl = f"Dear {to},\n\nSubject: {subject}\n\nThank you for registering."
    rendered = _ssti_eval(body_tpl)
    return f"""<html><body>
<h1>Email Template</h1>
<pre>{rendered}</pre>
<p><small>Hint: inject SSTI in <code>to</code> or <code>subject</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 🗄️ NoSQLi
# ══════════════════════════════════════════════════════════════════════════════
_nosql_users = [
    {"_id": "1", "username": "admin",     "password": "admin123",  "role": "admin"},
    {"_id": "2", "username": "alice",     "password": "alice2026", "role": "user"},
    {"_id": "3", "username": "bob",       "password": "bobsecret", "role": "user"},
]

@app.route('/nosql/login', methods=['GET', 'POST'])
def nosql_login():
    """⚠️ NoSQL injection — simule MongoDB auth"""
    msg = ""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        username = data.get('username', request.form.get('username', ''))
        password = data.get('password', request.form.get('password', ''))
        # ⚠️ Opérateurs MongoDB simulés
        if isinstance(username, dict) and "$ne" in username:
            msg = "✅ NoSQL bypass! All users accessible. " + str([u['username'] for u in _nosql_users])
        elif isinstance(password, dict) and "$ne" in password:
            user = next((u for u in _nosql_users if u['username'] == username), None)
            msg = f"✅ Password bypassed! Welcome {user['username']}" if user else "❌ User not found"
        else:
            user = next((u for u in _nosql_users if u['username'] == username and u['password'] == password), None)
            msg = f"✅ Login as {user['username']}" if user else "❌ Invalid credentials"
    return f"""<html><body>
<h1>NoSQL Login</h1>
<form method="post">
  <input name="username" placeholder="username"><br>
  <input name="password" placeholder="password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<p><small>Hint: POST JSON with <code>{{"username":{{"$ne":null}},"password":{{"$ne":null}}}}</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/nosql/search')
def nosql_search():
    """⚠️ NoSQL search injection"""
    q = request.args.get('q', '')
    if '$ne' in q or '$gt' in q or '$regex' in q:
        result = "✅ NoSQL operator accepted! Users: " + str([u['username'] for u in _nosql_users])
    else:
        found = [u for u in _nosql_users if q.lower() in u['username'].lower()]
        result = str(found) if found else "No results"
    return f"""<html><body>
<h1>NoSQL Search</h1>
<p>{result}</p>
<p><small>Hint: <code>?q[$ne]=null</code> or <code>?q[$regex]=.*</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/nosql/users')
def nosql_users():
    """⚠️ NoSQL $where bypass"""
    where = request.args.get('where', '')
    if where and ('1==1' in where or 'true' in where.lower()):
        result = "✅ $where bypass! All users: " + json.dumps(_nosql_users)
    else:
        result = "No users matched"
    return f"""<html><body>
<h1>NoSQL $where</h1>
<p>{result}</p>
<p><small>Hint: <code>?where=1==1</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 📂 LDAPi
# ══════════════════════════════════════════════════════════════════════════════
_ldap_users = {"admin": "ldappass", "alice": "alice123", "bob": "bob456"}

def _ldap_query(uid_filter: str, pass_filter: str) -> str:
    """Simule une requête LDAP vulnérable"""
    # ⚠️ Filtres non sanitisés
    if '*' in uid_filter or '*)' in uid_filter or '|' in uid_filter:
        return "✅ LDAP wildcard bypass! All entries returned: " + str(list(_ldap_users.keys()))
    if uid_filter in _ldap_users:
        if pass_filter == _ldap_users[uid_filter] or '*' in pass_filter:
            return f"✅ LDAP auth OK for: {uid_filter}"
    return "❌ LDAP: Invalid credentials"

@app.route('/ldap/login', methods=['GET', 'POST'])
def ldap_login():
    """⚠️ LDAP injection — filtre construit par concaténation"""
    msg = ""
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        # ⚠️ Filtre LDAP: (&(uid=UID)(userPassword=PWD))
        msg = _ldap_query(uid, pwd)
    return f"""<html><body>
<h1>LDAP Login</h1>
<form method="post">
  <input name="uid" placeholder="UID"><br>
  <input name="password" placeholder="Password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<p><small>Hint: <code>uid=*)(|(uid=*</code> — bypass LDAP filter</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/ldap/search')
def ldap_search():
    """⚠️ LDAP search injection"""
    uid = request.args.get('uid', '')
    result = _ldap_query(uid, '*')
    return f"""<html><body>
<h1>LDAP Search</h1>
<p>Searching uid={uid}</p>
<p>{result}</p>
<p><small>Hint: <code>?uid=*)(objectClass=*</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 🌐 CORS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/cors/api')
def cors_api():
    """⚠️ CORS wildcard + credentials"""
    resp = make_response(jsonify({
        "user": "admin", "api_key": "sk-SHIELDAI-SECRET-123", "balance": 9999.99
    }))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

@app.route('/cors/sensitive')
def cors_sensitive():
    """⚠️ CORS origin reflection"""
    origin = request.headers.get('Origin', 'null')
    resp = make_response(jsonify({
        "secret": "SHIELDAI_SENSITIVE_DATA", "private_token": "tok_abc123"
    }))
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, PUT'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return resp

@app.route('/cors/null')
def cors_null():
    """⚠️ CORS null origin accepté"""
    resp = make_response(jsonify({"data": "sensitive", "token": "SHIELDAI_NULL_ORIGIN_TOKEN"}))
    resp.headers['Access-Control-Allow-Origin'] = 'null'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# 🔄 CSRF
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/csrf/transfer', methods=['GET', 'POST'])
def csrf_transfer():
    """⚠️ CSRF — pas de token de validation"""
    msg = ""
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '0')
        msg = f"✅ Transferred ${amount} to {to} — No CSRF token checked!"
    return f"""<html><body>
<h1>Money Transfer (No CSRF Protection)</h1>
<form method="post">
  <input name="to" placeholder="Recipient"><br>
  <input name="amount" placeholder="Amount"><br>
  <button>Transfer</button>
</form>
<p>{msg}</p>
<p><em>⚠️ No CSRF token required</em></p>
<a href="/">Back</a></body></html>"""

@app.route('/csrf/delete', methods=['GET', 'POST'])
def csrf_delete():
    """⚠️ CSRF — suppression de compte sans token"""
    msg = ""
    if request.method == 'POST':
        msg = "✅ Account deleted! (No CSRF token checked)"
    return f"""<html><body>
<h1>Delete Account</h1>
<form method="post"><button style="background:red;color:#fff;padding:10px">Delete Account</button></form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

@app.route('/csrf/email', methods=['GET', 'POST'])
def csrf_email():
    """⚠️ CSRF — changement d'email sans token"""
    msg = ""
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        msg = f"✅ Email changed to: {new_email} — No CSRF token!"
    return f"""<html><body>
<h1>Change Email (No CSRF)</h1>
<form method="post">
  <input name="email" placeholder="new@email.com"><br>
  <button>Change Email</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

@app.route('/csrf/password', methods=['GET', 'POST'])
def csrf_password():
    """⚠️ CSRF — changement de mot de passe sans token ni ancien mot de passe"""
    msg = ""
    if request.method == 'POST':
        new_pwd = request.form.get('password', '')
        msg = f"✅ Password changed! (old password not required, no CSRF token)"
    return f"""<html><body>
<h1>Change Password (No CSRF, No Old Pwd)</h1>
<form method="post">
  <input name="password" type="password" placeholder="New password"><br>
  <button>Change Password</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# ↪️ Open Redirect
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/redirect')
def open_redirect():
    """⚠️ Open Redirect — next non validé"""
    next_url = request.args.get('next', '/')
    return redirect(next_url)

@app.route('/logout')
def logout_redirect():
    """⚠️ Open Redirect via return_to après logout"""
    return_to = request.args.get('return_to', '/')
    session.clear()
    return redirect(return_to)

@app.route('/login')
def login_redirect():
    """⚠️ Open Redirect via redirect param au login"""
    redir = request.args.get('redirect', '/')
    return f"""<html><body>
<h1>Login (with redirect)</h1>
<form method="post" action="/auth/login">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <input type="hidden" name="redirect" value="{redir}">
  <button>Login</button>
</form>
<p><small>Redirect target: <code>{redir}</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 📤 File Upload
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """⚠️ Insecure File Upload — aucune vérification d'extension ni de contenu"""
    msg = ""
    if request.method == 'POST':
        f = request.files.get('file')
        if f and f.filename:
            filepath = os.path.join(UPLOAD_FOLDER, f.filename)
            f.save(filepath)
            msg = f"✅ File uploaded: {f.filename} → {filepath}"
    return f"""<html><body>
<h1>File Upload (No Validation)</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file"><br>
  <button>Upload</button>
</form>
<p>{msg}</p>
<p><small>Try: shell.php, shell.php.jpg, shell.phtml, .htaccess</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/upload/avatar', methods=['GET', 'POST'])
def upload_avatar():
    """⚠️ Avatar upload — accepte tout y compris PHP"""
    msg = ""
    if request.method == 'POST':
        f = request.files.get('avatar')
        if f:
            filepath = os.path.join(UPLOAD_FOLDER, 'avatar_' + f.filename)
            f.save(filepath)
            msg = f"✅ Avatar saved: {filepath}"
    return f"""<html><body>
<h1>Avatar Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="avatar"><br>
  <button>Upload Avatar</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 🔑 JWT
# ══════════════════════════════════════════════════════════════════════════════
JWT_SECRET = "shieldai_weak_secret"

@app.route('/jwt/login', methods=['GET', 'POST'])
def jwt_login():
    """⚠️ JWT avec secret faible"""
    msg = ""
    token = ""
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == 'admin' and p == 'admin':
            payload = {"user": u, "role": "admin", "isAdmin": False, "exp": time.time() + 3600}
            if JWT_AVAILABLE:
                token = pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')
            else:
                # Fallback: base64 non signé
                h = base64.urlsafe_b64encode(json.dumps({"alg":"HS256"}).encode()).decode().rstrip('=')
                p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                token = f"{h}.{p64}.fakesig"
            msg = f"✅ Token: <code>{token}</code>"
        else:
            msg = "❌ Invalid credentials"
    return f"""<html><body>
<h1>JWT Login</h1>
<form method="post">
  <input name="username" placeholder="Username (admin)"><br>
  <input name="password" type="password" placeholder="Password (admin)"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

@app.route('/jwt/profile')
def jwt_profile():
    """⚠️ JWT — accepte alg:none"""
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '') or request.args.get('token', '')
    result = {}
    if token:
        try:
            # ⚠️ Accepte alg:none
            parts = token.split('.')
            if len(parts) >= 2:
                padding = 4 - len(parts[1]) % 4
                payload_b64 = parts[1] + '=' * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                if header.get('alg', '').lower() == 'none':
                    result = {"status": "✅ alg:none accepted!", "payload": payload, "message": "Welcome, " + payload.get('user', 'unknown')}
                elif JWT_AVAILABLE:
                    result = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                else:
                    result = {"payload": payload}
        except Exception as e:
            result = {"error": str(e)}
    return jsonify(result or {"error": "No token provided"})

@app.route('/jwt/admin')
def jwt_admin():
    """⚠️ JWT — escalade de privilèges via isAdmin"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or request.args.get('token', '')
    if token:
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                padding = 4 - len(parts[1]) % 4
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * padding))
                if payload.get('isAdmin') or payload.get('role') == 'superadmin':
                    return jsonify({"status": "✅ Admin access granted!", "users": [u['username'] for u in _nosql_users], "isAdmin": True})
                return jsonify({"status": "❌ Not admin", "role": payload.get('role', 'user')}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "No token"}), 401

# ══════════════════════════════════════════════════════════════════════════════
# 🔎 GraphQL
# ══════════════════════════════════════════════════════════════════════════════
_gql_schema_response = {
    "__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "id"}, {"name": "username"}, {"name": "email"},
                {"name": "passwordHash"}, {"name": "role"}
            ]},
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user"}, {"name": "users"}, {"name": "documents"}
            ]},
            {"kind": "SCALAR", "name": "String"},
            {"kind": "SCALAR", "name": "Int"},
        ]
    }
}

@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    """⚠️ GraphQL — introspection activée, injection SQL dans resolvers"""
    if request.method == 'GET':
        return jsonify({"message": "GraphQL endpoint — POST a query"}), 200
    
    data = request.get_json(silent=True) or {}
    query = data.get('query', '')
    
    # Introspection
    if '__schema' in query or '__type' in query or 'IntrospectionQuery' in query:
        return jsonify({"data": _gql_schema_response})
    
    # Simulation de résolution avec SQLi possible
    if 'user(' in query.lower():
        m = re.search(r'user\s*\(\s*id\s*:\s*["\']?([^)"\']+)', query)
        if m:
            uid = m.group(1).strip()
            try:
                with DB_LOCK:
                    cur = DB.cursor()
                    cur.execute(f"SELECT id, username, email, role FROM users WHERE id={uid}")
                    row = cur.fetchone()
                if row:
                    return jsonify({"data": {"user": {"id": row[0], "username": row[1], "email": row[2], "passwordHash": "HASHED", "role": row[3]}}})
            except Exception as e:
                return jsonify({"errors": [{"message": str(e)}]})
    
    if 'users' in query.lower():
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email, role FROM users")
            rows = cur.fetchall()
        return jsonify({"data": {"users": [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]}})
    
    return jsonify({"errors": [{"message": f"Cannot query field: {query[:50]}"}]})

@app.route('/graphql/playground')
def graphql_playground():
    """⚠️ GraphQL Playground exposé"""
    return f"""<html><body>
<h1>GraphQL Playground</h1>
<p>Endpoint: <code>POST /graphql</code></p>
<p>Try introspection: <code>{{"query":"{{"__schema{{"queryType{{"name}}}}}}}}"}}</code></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# 🔓 IDOR
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/users/<int:uid>')
def idor_user(uid):
    """⚠️ IDOR — aucune vérification d'autorisation"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "username": row[1], "password": row[2],
                        "email": row[3], "role": row[4], "ssn": row[5],
                        "credit_card": row[6], "phone": row[7]})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/documents/<int:doc_id>')
def idor_document(doc_id):
    """⚠️ IDOR — documents privés accessibles sans auth"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM documents WHERE id=?", (doc_id,))
        row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "owner_id": row[1], "title": row[2],
                        "content": row[3], "is_private": row[4]})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/orders/<int:oid>')
def idor_order(oid):
    """⚠️ IDOR — commandes accessibles sans auth"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM orders WHERE id=?", (oid,))
        row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "user_id": row[1], "product": row[2], "amount": row[3]})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/invoices/<int:inv_id>')
def idor_invoice(inv_id):
    """⚠️ IDOR — factures"""
    return jsonify({"invoice_id": inv_id, "user_id": 1, "amount": inv_id * 99.99,
                    "account_number": f"ACC-{inv_id:04d}", "date_of_birth": "1990-01-01"})

# ══════════════════════════════════════════════════════════════════════════════
# ☣️ Prototype Pollution
# ══════════════════════════════════════════════════════════════════════════════
_proto_store: dict = {}

@app.route('/proto/merge', methods=['GET', 'POST'])
def proto_merge():
    """⚠️ Prototype Pollution — merge d'objet JSON sans filtrage de __proto__"""
    result = {}
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        # ⚠️ Merge sans filtrage des clés dangereuses
        for k, v in data.items():
            _proto_store[k] = v
        # Simuler l'effet de pollution
        is_admin = _proto_store.get('__proto__', {}).get('isAdmin', False) if isinstance(_proto_store.get('__proto__'), dict) else False
        result = {"merged": True, "isAdmin": is_admin, "store": dict(_proto_store)}
    return jsonify(result) if result else make_response("""<html><body>
<h1>Object Merge (Prototype Pollution)</h1>
<p>POST JSON: <code>{"__proto__": {"isAdmin": true, "marker": "SHLDXXX"}}</code></p>
<a href="/">Back</a></body></html>""")

@app.route('/proto/extend')
def proto_extend():
    """⚠️ Prototype Pollution via query params"""
    params = request.args.to_dict()
    is_admin = params.get('__proto__[isAdmin]', 'false').lower() == 'true'
    marker = params.get('__proto__[marker]', '')
    return jsonify({
        "params": params,
        "isAdmin": is_admin,
        "marker": marker,
        "message": "✅ Prototype polluted!" if is_admin else "Not polluted"
    })

# ══════════════════════════════════════════════════════════════════════════════
# 🔓 Insecure Deserialization
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/deserialize/pickle', methods=['GET', 'POST'])
def deser_pickle():
    """⚠️ Pickle deserialization"""
    result = ""
    if request.method == 'POST':
        data = request.form.get('data', '') or request.get_data(as_text=True)
        try:
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)  # ⚠️ VULNERABLE
            result = f"Deserialized: {obj}"
        except Exception as e:
            result = f"Error: {str(e)}"
    return f"""<html><body>
<h1>Pickle Deserializer</h1>
<form method="post">
  <textarea name="data" rows="4" cols="60" placeholder="Base64 pickle data"></textarea><br>
  <button>Deserialize</button>
</form>
<pre>{result}</pre>
<a href="/">Back</a></body></html>"""

@app.route('/deserialize/json', methods=['GET', 'POST'])
def deser_json():
    """⚠️ JSON deserialization avec eval côté serveur simulé"""
    result = ""
    if request.method == 'POST':
        raw = request.get_json(silent=True) or request.form.to_dict()
        rce_key = raw.get('rce', '') if isinstance(raw, dict) else ''
        if '_$$ND_FUNC$$_' in str(rce_key):
            # Simule l'évaluation node-serialize
            result = "⚠️ _$$ND_FUNC$$_ detected — RCE gadget triggered!"
            try:
                # Extraire et simuler l'exécution
                inner = re.search(r"exec\('(.+?)'\)", str(rce_key))
                if inner:
                    out = subprocess.run(inner.group(1), shell=True, capture_output=True, text=True, timeout=5)
                    result += f"\n{out.stdout}{out.stderr}"
            except Exception:
                pass
        else:
            result = f"Received: {json.dumps(raw, indent=2)}"
    return jsonify({"result": result}) if request.content_type == 'application/json' else (
        f"""<html><body>
<h1>JSON Deserializer</h1>
<form method="post" enctype="application/x-www-form-urlencoded">
  <textarea name="rce" rows="4" cols="60"></textarea><br>
  <button>Deserialize</button>
</form>
<pre>{result}</pre>
<a href="/">Back</a></body></html>""")

@app.route('/deserialize/cookie')
def deser_cookie():
    """⚠️ Cookie deserialize (pickle en base64)"""
    cookie_data = request.cookies.get('user_data', '')
    result = ""
    if cookie_data:
        try:
            obj = pickle.loads(base64.b64decode(cookie_data))  # ⚠️
            result = f"Cookie data: {obj}"
        except Exception as e:
            result = f"Error: {e}"
    else:
        result = "No user_data cookie set"
    resp = make_response(f"""<html><body>
<h1>Cookie Deserializer</h1>
<p>{result}</p>
<p><small>Set cookie <code>user_data</code> to base64-encoded pickle payload</small></p>
<a href="/">Back</a></body></html>""")
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# ⚡ Race Condition
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/race/coupon', methods=['GET', 'POST'])
def race_coupon():
    """⚠️ Race Condition — coupon utilisable plusieurs fois si race"""
    msg = ""
    if request.method == 'POST':
        code = request.form.get('code', '')
        # ⚠️ Pas de lock atomic — TOCTOU
        if code == 'SAVE50':
            time.sleep(0.05)  # Fenêtre de race artificielle
            if code in _used_coupons:
                msg = "❌ Coupon already redeemed"
            else:
                _used_coupons.add(code)
                msg = "✅ Coupon applied! -50% discount"
        else:
            msg = "❌ Invalid coupon"
    return f"""<html><body>
<h1>Coupon Redemption (Race Condition)</h1>
<form method="post">
  <input name="code" value="SAVE50"><br>
  <button>Apply Coupon</button>
</form>
<p>{msg}</p>
<p><small>Send many concurrent requests to apply the coupon multiple times!</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/race/transfer', methods=['GET', 'POST'])
def race_transfer():
    """⚠️ Race Condition — transfert avec race sur le solde"""
    msg = ""
    if request.method == 'POST':
        user = request.form.get('user', 'user1')
        amount = float(request.form.get('amount', 0))
        time.sleep(0.05)  # Fenêtre de race
        if _account_balance.get(user, 0) >= amount:
            _account_balance[user] -= amount
            msg = f"✅ Transferred {amount} from {user}. New balance: {_account_balance[user]}"
        else:
            msg = f"❌ Insufficient balance: {_account_balance.get(user, 0)}"
    return f"""<html><body>
<h1>Transfer (Race Condition)</h1>
<p>Balances: {_account_balance}</p>
<form method="post">
  <input name="user" value="user1"><br>
  <input name="amount" value="100"><br>
  <button>Transfer</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

@app.route('/race/vote')
def race_vote():
    """⚠️ Race Condition — double vote"""
    if not hasattr(app, '_votes'):
        app._votes = defaultdict(int)
        app._voters = defaultdict(set)
    post_id = request.args.get('post_id', '1')
    user_ip = request.remote_addr
    time.sleep(0.02)  # Fenêtre de race
    if user_ip not in app._voters[post_id]:
        app._voters[post_id].add(user_ip)
        app._votes[post_id] += 1
    return jsonify({"post_id": post_id, "votes": app._votes[post_id], "message": "Vote counted"})

# ══════════════════════════════════════════════════════════════════════════════
# 🚦 HTTP Request Smuggling
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/smuggle/endpoint', methods=['GET', 'POST', 'OPTIONS'])
def smuggle_endpoint():
    """⚠️ Endpoint qui illustre les conditions de smuggling CL.TE"""
    # Accepte les deux headers Transfer-Encoding et Content-Length sans conflit
    te = request.headers.get('Transfer-Encoding', '')
    cl = request.headers.get('Content-Length', '')
    x_shld = request.headers.get('X-SHLD', '')
    body = request.get_data(as_text=True)
    resp = make_response(jsonify({
        "Transfer-Encoding": te,
        "Content-Length": cl,
        "X-SHLD": x_shld,
        "body_received": body[:200],
        "note": "CL.TE smuggling test point"
    }))
    resp.headers['X-SHLD-Reflected'] = x_shld or "none"
    return resp

@app.route('/smuggle/te-te')
def smuggle_te_te():
    """⚠️ TE.TE obfuscation test"""
    te = request.headers.get('Transfer-Encoding', '')
    x_shld = request.headers.get('X-SHLD', '')
    return jsonify({
        "Transfer-Encoding": te,
        "X-SHLD": x_shld,
        "chunked_conflict": "identity" in te or "xchunked" in te,
        "note": "TE.TE obfuscation test point"
    })

# ══════════════════════════════════════════════════════════════════════════════
# 💉 CRLF Injection
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/crlf/header')
def crlf_header():
    """⚠️ CRLF — name injecté dans un header de réponse"""
    name = request.args.get('name', 'test')
    resp = make_response(f"""<html><body>
<h1>CRLF Header Injection</h1>
<p>Name: {name}</p>
<p><small>Hint: <code>?name=test%0d%0aX-SHLD:SHLDXXX</code></small></p>
<a href="/">Back</a></body></html>""")
    # ⚠️ Injection directe dans header
    try:
        resp.headers['X-User'] = name
    except Exception:
        pass
    return resp

@app.route('/crlf/log')
def crlf_log():
    """⚠️ CRLF log poisoning simulé"""
    data = request.args.get('data', 'test')
    # Simule l'écriture dans un log
    log_entry = f"[{datetime.now()}] User input: {data}"
    return f"""<html><body>
<h1>Log Entry</h1>
<pre>{log_entry}</pre>
<p><small>Hint: inject CRLF to forge log entries</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/crlf/redirect')
def crlf_redirect():
    """⚠️ CRLF dans le header Location"""
    url = request.args.get('url', 'http://example.com')
    resp = make_response("Redirecting...", 302)
    try:
        resp.headers['Location'] = url
    except Exception:
        pass
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# 📐 XPath Injection
# ══════════════════════════════════════════════════════════════════════════════
_xml_db = """<?xml version="1.0"?>
<users>
  <user><id>1</id><username>admin</username><password>xmlpass123</password><role>admin</role></user>
  <user><id>2</id><username>alice</username><password>alice123</password><role>user</role></user>
  <user><id>3</id><username>guest</username><password>guest</password><role>guest</role></user>
</users>"""

@app.route('/xpath/login', methods=['GET', 'POST'])
def xpath_login():
    """⚠️ XPath injection — filtre construit par concaténation"""
    msg = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            root = ET.fromstring(_xml_db)
            # ⚠️ XPath construit par concaténation
            xpath = f"//user[username='{username}' and password='{password}']"
            matches = root.findall(xpath.replace("//user[", ".//user/..").replace("]", ""))
            # Fallback simple simulation
            if "'" in username and ("or" in username.lower() or "1=1" in username):
                msg = f"✅ XPath bypass! All users: " + str([u.find('username').text for u in root.findall('.//user')])
            elif any(u.find('username').text == username and u.find('password').text == password for u in root.findall('.//user')):
                msg = f"✅ Login successful as {username}!"
            else:
                msg = "❌ Invalid credentials"
        except Exception as e:
            msg = f"XPath Error: {str(e)}"
    return f"""<html><body>
<h1>XPath Login</h1>
<form method="post">
  <input name="username" placeholder="Username"><br>
  <input name="password" placeholder="Password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<p><small>Hint: <code>username=' or '1'='1</code></small></p>
<a href="/">Back</a></body></html>"""

@app.route('/xpath/search')
def xpath_search():
    """⚠️ XPath search injection"""
    q = request.args.get('q', '')
    try:
        root = ET.fromstring(_xml_db)
        if "'" in q or '"' in q or 'or' in q.lower():
            results = [u.find('username').text for u in root.findall('.//user')]
            msg = f"✅ XPath injection! All users: {results}"
        else:
            found = [u for u in root.findall('.//user') if u.find('username').text == q]
            msg = f"Found: {[u.find('username').text for u in found]}" if found else "No results"
    except Exception as e:
        msg = f"XPath Error: {str(e)}"
    return f"""<html><body>
<h1>XPath Search</h1>
<p>{msg}</p>
<p><small>Hint: <code>?q=admin' or '1'='1</code></small></p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# ⏱️ Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/ratelimit/api')
def ratelimit_api():
    """⚠️ Pas de rate limiting — endpoint accessible à volonté"""
    key = request.args.get('key', '')
    if not hasattr(app, '_api_calls'):
        app._api_calls = 0
    app._api_calls += 1
    return jsonify({
        "status": "ok",
        "api_key": key,
        "calls_total": app._api_calls,
        "rate_limit": None,  # ⚠️ Pas de limite !
        "data": "Sensitive API data returned without rate limiting"
    })

@app.route('/ratelimit/xff')
def ratelimit_xff():
    """⚠️ Rate limit bypassable via X-Forwarded-For"""
    xff = request.headers.get('X-Forwarded-For', request.remote_addr)
    real_ip = request.headers.get('X-Real-IP', '')
    client_ip = request.headers.get('X-Client-IP', '')
    return jsonify({
        "X-Forwarded-For": xff,
        "X-Real-IP": real_ip,
        "X-Client-IP": client_ip,
        "trusted_ip": xff.split(',')[0].strip(),
        "note": "Rate limiting based on first XFF IP — easily bypassed"
    })

@app.route('/ratelimit/login', methods=['GET', 'POST'])
def ratelimit_login():
    """⚠️ Login sans rate limiting — brute force possible"""
    msg = ""
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        # ⚠️ Pas de compte de tentatives
        if u == 'admin' and p == 'admin':
            msg = "✅ Login successful! (No rate limiting — brute force possible)"
        else:
            msg = "❌ Invalid"
    return f"""<html><body>
<h1>Login (No Rate Limit)</h1>
<form method="post">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# ℹ️ Information Disclosure
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/.env')
@app.route('/credsexpose/env')
def exposed_env():
    """⚠️ .env exposé"""
    return """DB_HOST=localhost
DB_PORT=5432
DB_NAME=shieldai_prod
DB_USER=dbadmin
DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!
API_KEY=sk-shieldai-1234567890abcdef
API_SECRET=secret_api_key_very_long_value_here
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
JWT_SECRET=shieldai_jwt_secret_do_not_expose
STRIPE_SECRET_KEY=sk_live_shieldai_1234567890
SENDGRID_API_KEY=SG.shieldai.test123
REDIS_URL=redis://:redispassword@localhost:6379
APP_SECRET=my_very_insecure_app_secret
""", 200, {'Content-Type': 'text/plain'}

@app.route('/.git/config')
def exposed_git():
    """⚠️ .git/config exposé"""
    return """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://github.com/shieldai/vuln-server.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\temail = admin@shieldai.io
\tname = ShieldAI Admin
""", 200, {'Content-Type': 'text/plain'}

@app.route('/phpinfo')
def phpinfo():
    """⚠️ Info système exposée"""
    return jsonify({
        "PHP_VERSION": "8.1.3",
        "SERVER_SOFTWARE": "Apache/2.4.51 (Ubuntu)",
        "DOCUMENT_ROOT": "/var/www/html",
        "SERVER_ADDR": "192.168.1.100",
        "MYSQL_VERSION": "8.0.28",
        "LOADED_EXTENSIONS": ["mysqli", "pdo_mysql", "curl", "xml", "openssl"],
        "open_basedir": "",   # ⚠️ Pas de restriction
        "allow_url_include": "On",  # ⚠️
        "display_errors": "On",     # ⚠️
    })

@app.route('/debug')
def debug_info():
    """⚠️ Debug endpoint complet"""
    return jsonify({
        "environment": "production",
        "debug": True,
        "database": "postgresql://dbadmin:Sup3rS3cr3t@localhost:5432/shieldai",
        "redis": "redis://:redispassword@localhost:6379",
        "api_keys": {"stripe": "sk_live_1234", "sendgrid": "SG.1234abc"},
        "internal_ips": ["192.168.1.10", "10.0.0.5", "172.16.0.100"],
        "secret_key": "shieldai_insecure_secret_key_do_not_use_in_prod",
        "admin_password_hash": hashlib.md5(b"admin123").hexdigest(),  # ⚠️ MD5
    })

@app.route('/actuator/env')
def actuator_env():
    """⚠️ Spring Actuator /env simulé"""
    return jsonify({
        "activeProfiles": ["production"],
        "propertySources": [
            {"name": "systemEnvironment", "properties": {
                "DB_PASSWORD": {"value": "Sup3rS3cr3tP@ssw0rd!"},
                "JWT_SECRET": {"value": "shieldai_jwt_secret"},
                "AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
            }},
            {"name": "applicationConfig", "properties": {
                "spring.datasource.password": {"value": "dbpassword123"},
                "spring.security.user.password": {"value": "admin"}
            }}
        ]
    })

@app.route('/actuator/heapdump')
def actuator_heapdump():
    """⚠️ Heapdump simulé"""
    fake_heap = b"JAVA_HEAPDUMP\x00" + b"password=admin123\x00" + b"secret_key=shieldai_secret\x00" * 100
    return Response(fake_heap, content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=heapdump.hprof'})

@app.route('/swagger.json')
def swagger_spec():
    """⚠️ OpenAPI spec exposée avec endpoints sensibles"""
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "ShieldAI Internal API", "version": "1.0.0"},
        "paths": {
            "/api/admin/users": {"get": {"summary": "List all users (admin)"}},
            "/api/admin/delete": {"post": {"summary": "Delete user"}},
            "/internal/migrate": {"post": {"summary": "Run DB migrations"}},
            "/internal/backup": {"get": {"summary": "Download DB backup"}},
        }
    })

# ══════════════════════════════════════════════════════════════════════════════
# 🔒 Insecure Crypto
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/crypto/hash')
def crypto_hash():
    """⚠️ Hash MD5/SHA1 faibles"""
    data = request.args.get('data', 'test')
    return jsonify({
        "input": data,
        "md5": hashlib.md5(data.encode()).hexdigest(),          # ⚠️ Faible
        "sha1": hashlib.sha1(data.encode()).hexdigest(),        # ⚠️ Faible
        "sha256": hashlib.sha256(data.encode()).hexdigest(),    # OK pour démo
        "note": "MD5 and SHA1 used for password hashing — INSECURE"
    })

@app.route('/crypto/token')
def crypto_token():
    """⚠️ Token prévisible basé sur timestamp"""
    user = request.args.get('user', 'guest')
    timestamp = int(time.time())
    # ⚠️ Token prévisible : MD5(user + timestamp)
    token = hashlib.md5(f"{user}{timestamp}".encode()).hexdigest()
    return jsonify({
        "user": user,
        "token": token,
        "timestamp": timestamp,
        "note": "Token is MD5(username+timestamp) — predictable!"
    })

@app.route('/crypto/tls-info')
def crypto_tls_info():
    """⚠️ Informations TLS/cipher exposées"""
    return jsonify({
        "supported_ciphers": [
            "TLS_RSA_WITH_RC4_128_MD5",    # ⚠️ Faible
            "TLS_RSA_WITH_DES_CBC_SHA",    # ⚠️ Faible
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
        ],
        "min_tls_version": "TLSv1.0",     # ⚠️ Faible
        "certificate_hash": "MD5WithRSAEncryption",  # ⚠️
        "hsts_enabled": False,             # ⚠️
        "cert_expiry": "2020-01-01",       # ⚠️ Expiré
    })

# ══════════════════════════════════════════════════════════════════════════════
# 🗝️ Credentials Exposure (chemins supplémentaires)
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/.aws/credentials')
def aws_creds():
    return """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[shieldai-prod]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
""", 200, {'Content-Type': 'text/plain'}

@app.route('/wp-config.php')
def wp_config():
    return """<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'wp_S3cr3t_P@ss!');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'put_your_unique_phrase_here');
define('SECURE_AUTH_KEY', 'shieldai_auth_key_here');
$table_prefix = 'wp_';
""", 200, {'Content-Type': 'text/plain'}

@app.route('/config.json')
def config_json():
    return jsonify({
        "database": {"host": "localhost", "port": 5432, "user": "admin", "password": "db_password_exposed"},
        "redis": {"password": "redis_secret"},
        "jwt": {"secret": "jwt_insecure_secret"},
        "api_keys": {"internal": "int_key_shieldai_123", "external": "ext_key_abc_456"}
    })

@app.route('/database.yml')
def database_yml():
    return """production:
  adapter: postgresql
  host: db.internal
  database: shieldai_prod
  username: dbadmin
  password: "YamlPassword123!"
  pool: 5

staging:
  adapter: postgresql
  password: "StagingPass456!"
""", 200, {'Content-Type': 'text/plain'}

@app.route('/secrets.yml')
def secrets_yml():
    return """secret_key_base: shieldai_secret_key_base_very_long_and_secret
aws_access_key_id: AKIAIOSFODNN7EXAMPLE
aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
stripe_secret_key: sk_live_shieldai_1234567890
sendgrid_api_key: SG.shieldai.test.key
""", 200, {'Content-Type': 'text/plain'}

@app.route('/.netrc')
def netrc():
    return """machine github.com
  login shieldai-bot
  password ghp_ShieldAI1234567890abcdef

machine internal.shieldai.io
  login admin
  password admin_netrc_password
""", 200, {'Content-Type': 'text/plain'}

@app.route('/id_rsa')
def ssh_private_key():
    return """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA (FAKE KEY FOR TESTING ONLY)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END OPENSSH PRIVATE KEY-----
""", 200, {'Content-Type': 'text/plain'}

# ══════════════════════════════════════════════════════════════════════════════
# 🔐 Broken Authentication
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    """⚠️ Login avec credentials par défaut"""
    msg = ""
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        # ⚠️ Credentials par défaut
        if (u == 'admin' and p == 'admin') or u == p:
            msg = f"✅ Login successful as {u}! (Default/weak credentials)"
            resp = make_response(redirect('/admin'))
            resp.set_cookie('session', f'sess_{u}_authenticated', httponly=False)
            return resp
        else:
            msg = "❌ Invalid credentials"
    return f"""<html><body>
<h1>Login</h1>
<form method="post">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button>Login</button>
</form>
<p>{msg}</p>
<p><small>Hints: admin:admin | test:test | guest:guest | root:root</small></p>
<a href="/">Back</a></body></html>"""

@app.route('/auth/reset', methods=['GET', 'POST'])
def auth_reset():
    """⚠️ Reset de mot de passe sans vérification"""
    msg = ""
    if request.method == 'POST':
        email = request.form.get('email', '')
        new_pwd = request.form.get('password', '')
        # ⚠️ Pas de validation de propriété de compte
        msg = f"✅ Password reset for {email} without any verification!"
    return f"""<html><body>
<h1>Password Reset (Insecure)</h1>
<form method="post">
  <input name="email" placeholder="email"><br>
  <input name="password" placeholder="New password"><br>
  <button>Reset</button>
</form>
<p>{msg}</p>
<a href="/">Back</a></body></html>"""

@app.route('/auth/token')
def auth_token():
    """⚠️ Token sans expiration"""
    user = request.args.get('user', 'anonymous')
    token = hashlib.sha256(f"shieldai_{user}".encode()).hexdigest()
    resp = make_response(jsonify({
        "token": token, "user": user, "expires": None,  # ⚠️ Pas d'expiration
        "note": "Token never expires — no invalidation mechanism"
    }))
    resp.set_cookie('auth', token, httponly=False, secure=False, samesite=None)
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# 🚫 Insecure Permissions
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/admin')
def admin_panel():
    """⚠️ Admin panel sans authentification"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, username, email, role FROM users")
        users = cur.fetchall()
    rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in users)
    return f"""<html><body>
<h1>🔴 Admin Panel (No Auth Required)</h1>
<table border="1">
  <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
  {rows}
</table>
<p>Administration Console — WordPress Dashboard style</p>
<a href="/">Back</a></body></html>"""

@app.route('/admin/users')
def admin_users():
    """⚠️ Liste utilisateurs admin sans auth"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
    return jsonify([{"id": r[0], "username": r[1], "password": r[2], "email": r[3], "role": r[4]} for r in rows])

@app.route('/api/admin')
def api_admin():
    """⚠️ API admin sans authentification"""
    return jsonify({
        "admin": True,
        "users_count": 4,
        "system": {"os": sys.platform, "python": sys.version},
        "note": "Admin API endpoint accessible without authentication"
    })

# ══════════════════════════════════════════════════════════════════════════════
# 🍪 Session Fixation
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/session/fixate')
def session_fixate():
    """⚠️ Session fixation — accepte sessionid en GET"""
    session_id = request.args.get('sessionid', '')
    if session_id:
        session['id'] = session_id
        resp = make_response(f"""<html><body>
<h1>Session Fixation</h1>
<p>Session fixed to: <code>{session_id}</code></p>
<p>Set-Cookie header will contain the attacker-controlled session.</p>
<a href="/">Back</a></body></html>""")
        resp.set_cookie('PHPSESSID', session_id, httponly=False, samesite=None)
        resp.set_cookie('session_token', session_id, httponly=False)
        return resp
    return f"""<html><body>
<h1>Session Fixation</h1>
<p>Provide <code>?sessionid=attacker_session_123</code></p>
<a href="/">Back</a></body></html>"""

@app.route('/session/weak')
def session_weak():
    """⚠️ Session ID faible et prévisible"""
    timestamp = int(time.time())
    weak_id = f"{timestamp:x}"  # ⚠️ Timestamp hex = prévisible
    resp = make_response(jsonify({
        "session_id": weak_id,
        "timestamp": timestamp,
        "entropy_bits": 32,  # ⚠️ Trop faible
        "note": "Session ID is predictable timestamp-based"
    }))
    resp.set_cookie('PHPSESSID', weak_id, httponly=False, samesite=None)
    return resp

@app.route('/session/info')
def session_info():
    """⚠️ Infos de session exposées"""
    return jsonify({
        "session": dict(session),
        "cookies": dict(request.cookies),
        "note": "Session and cookies exposed"
    })

# ══════════════════════════════════════════════════════════════════════════════
# 💥 Buffer Overflow (HTTP-level)
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/bufovr/input')
def bufovr_input():
    """⚠️ Input de grande taille — tente de provoquer des comportements anormaux"""
    data = request.args.get('data', '')
    length = len(data)
    # Simule un traitement qui crasherait sur de grandes entrées
    if length > 50000:
        return "Internal Server Error: memory limit exceeded", 500
    if '%x' in data.lower() or '%s' in data.lower() or '%n' in data.lower():
        return f"Format string probe detected: {data[:100]}... uid=0(root)", 200
    return jsonify({
        "received_length": length,
        "truncated_preview": data[:100],
        "status": "processed"
    })

@app.route('/bufovr/header')
def bufovr_header():
    """⚠️ Header de grande taille"""
    ua = request.headers.get('User-Agent', '')
    custom = request.headers.get('X-Custom-Data', '')
    total = len(ua) + len(custom)
    if total > 8192:
        return "Request Header Fields Too Large", 431
    return jsonify({"ua_length": len(ua), "custom_length": len(custom), "total": total})

@app.route('/bufovr/format')
def bufovr_format():
    """⚠️ Format string simulation"""
    data = request.args.get('data', '')
    if re.search(r'%[0-9]*[xsndpu]', data):
        # Simule une fuite de format string
        return f"Format string output: {data} 0x7fff1234 uid=0(root) gid=0(root)", 200
    return f"Input processed: {data[:200]}", 200

# ══════════════════════════════════════════════════════════════════════════════
# 🚀 MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║        🔥 ShieldAI VULNERABLE TEST SERVER v2.0.0                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ⚠️  Ce serveur est INTENTIONNELLEMENT vulnérable                        ║
║  ⚠️  Utiliser UNIQUEMENT en local (localhost)                             ║
║  ⚠️  NE JAMAIS déployer en production ou réseau public !                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║  🌐  URL      : http://localhost:5000                                     ║
║  📊  Vulns    : 30 catégories / 80+ endpoints                            ║
║  🎯  Couvre   : payloads_v2.json v3.0.0 complet                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Dépendances : flask flask-cors lxml pyjwt                               ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    app.run(host='0.0.0.0', port=6000, debug=False, threaded=True)
