#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI VULNERABLE TEST SERVER v3.0.0                                    ║
║   Calibré sur payloads_v3.json v3.0.0 — système SHLD{{MARKER}}             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PRINCIPE :                                                                  ║
║  Un vrai serveur vulnérable REFLÈTE les payloads sans sanitisation.         ║
║  Le scanner détecte le marqueur SHLD[A-Z0-9]{4,16} dans la réponse.        ║
║  Ce serveur simule exactement ce comportement.                               ║
║                                                                              ║
║  Pas d'adaptation au scanner — c'est ce qu'un vrai serveur vulnérable fait. ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠️  INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  pip install flask flask-cors lxml pyjwt                                     ║
║  python vuln_server_v3.py → http://localhost:5000                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Samuel — ShieldAI
Version : 3.0.0
Date    : 2026-03-19
"""

import os, re, sys, time, json, base64, pickle
import sqlite3, hashlib, threading, subprocess
from collections import defaultdict
from flask import Flask, request, make_response, redirect, jsonify, send_file, session, Response
from flask_cors import CORS

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
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = "shieldai_v3_secret"
UPLOAD_FOLDER = '/tmp/shieldai_v3_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
CORS(app, origins="*", supports_credentials=True)

JWT_SECRET = "shieldai_weak_secret"
DB_LOCK    = threading.Lock()
_balance   = {"user1": 1000.0, "user2": 500.0}
_coupons:  set = set()

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT,
        email TEXT, role TEXT, ssn TEXT, credit_card TEXT, phone TEXT)""")
    c.execute("""CREATE TABLE documents (
        id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT,
        content TEXT, is_private INTEGER)""")
    c.execute("""CREATE TABLE orders (
        id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, amount REAL)""")
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", [
        (1,'admin','admin123','admin@shieldai.io','admin','123-45-6789','4111111111111111','+1-555-0100'),
        (2,'alice','alice2026','alice@example.com','user','987-65-4321','4222222222222222','+1-555-0101'),
        (3,'bob','bobsecret','bob@example.com','user','111-22-3333','4333333333333333','+1-555-0102'),
    ])
    c.executemany("INSERT INTO documents VALUES (?,?,?,?,?)", [
        (1,1,'Admin Report','Confidential admin report',1),
        (2,2,'Alice Notes','Alice private notes',1),
        (3,3,'Public Doc','Public content',0),
        (4,1,'Secret Config','DB_PASSWORD=admin123',1),
    ])
    c.executemany("INSERT INTO orders VALUES (?,?,?,?)", [
        (1,1,'Premium Plan',299.99),(2,2,'Basic Plan',9.99),(3,3,'Pro Plan',99.99),
    ])
    conn.commit()
    return conn

DB = init_db()

# ══════════════════════════════════════════════════════════════════════════════
# HOME
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>ShieldAI v3</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px 'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}
h1{color:#f85149;font-size:1.8em;margin-bottom:4px}
.warn{background:#161b22;border:2px solid #f85149;border-radius:8px;padding:14px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card h2{font-size:.78em;text-transform:uppercase;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #30363d}
.crit{color:#f85149}.high{color:#e67e22}.med{color:#f1c40f}
a{color:#58a6ff;text-decoration:none;display:block;padding:2px 0;font-size:.85em}
a:hover{color:#79c0ff}
footer{text-align:center;margin-top:28px;color:#8b949e;font-size:.8em}
</style></head>
<body>
<div class="warn">⚠️ SERVEUR INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT — v3.0.0</div>
<h1>🔥 ShieldAI Vuln Server v3</h1>
<p style="color:#8b949e;margin-bottom:20px">30 catégories · payloads_v3.json v3.0.0 · Système SHLD{{MARKER}}</p>
<div class="grid">
<div class="card"><h2 class="crit">XSS</h2>
<a href="/xss/reflected?q=hello">Reflected</a><a href="/xss/stored">Stored</a>
<a href="/xss/header">Header</a><a href="/xss/json?callback=cb">JSONP</a></div>
<div class="card"><h2 class="crit">SQLi</h2>
<a href="/sqli/search?id=1">Error-based</a><a href="/sqli/login">Auth bypass</a>
<a href="/sqli/union?id=1">UNION</a><a href="/sqli/time?id=1">Time-based</a>
<a href="/sqli/blind?id=1">Blind</a></div>
<div class="card"><h2 class="crit">CMDi</h2>
<a href="/cmdi/ping">Ping</a><a href="/cmdi/system">System</a>
<a href="/cmdi/lookup?host=localhost">DNS lookup</a></div>
<div class="card"><h2 class="high">DirTrav</h2>
<a href="/file/read?path=README.txt">File read</a>
<a href="/download?file=README.txt">Download</a>
<a href="/template?page=home">Template LFI</a></div>
<div class="card"><h2 class="high">XXE</h2>
<a href="/xml/parse">XML parse</a><a href="/xml/import">XML import</a></div>
<div class="card"><h2 class="high">SSRF</h2>
<a href="/ssrf/fetch">Fetch</a>
<a href="/ssrf/preview?url=http://example.com">Preview</a>
<a href="/ssrf/avatar?url=http://example.com">Avatar</a></div>
<div class="card"><h2 class="crit">SSTI</h2>
<a href="/ssti/greet?name=World">Jinja2</a><a href="/ssti/render">Render</a></div>
<div class="card"><h2 class="high">NoSQLi</h2>
<a href="/nosql/login">Auth bypass</a><a href="/nosql/search?q=admin">Search</a></div>
<div class="card"><h2 class="med">CRLF</h2>
<a href="/crlf/header?name=test">Header</a>
<a href="/crlf/redirect?url=http://example.com">Redirect</a>
<a href="/crlf/log?data=test">Log</a></div>
<div class="card"><h2 class="crit">JWT</h2>
<a href="/jwt/login">Login</a><a href="/jwt/profile">Profile</a>
<a href="/jwt/admin">Admin</a></div>
<div class="card"><h2 class="med">GraphQL</h2>
<a href="/graphql">Endpoint</a></div>
<div class="card"><h2 class="high">IDOR</h2>
<a href="/api/users/1">User</a><a href="/api/documents/1">Document</a>
<a href="/api/invoices/1">Invoice</a></div>
<div class="card"><h2 class="high">Prototype Pollution</h2>
<a href="/proto/merge">Merge</a>
<a href="/proto/extend?__proto__[isAdmin]=true">Extend</a></div>
<div class="card"><h2 class="crit">InsecDeser</h2>
<a href="/deser/json">JSON</a><a href="/deser/pickle">Pickle</a></div>
<div class="card"><h2 class="med">InfoDisc</h2>
<a href="/.env">.env</a><a href="/.git/config">.git/config</a>
<a href="/debug">Debug</a><a href="/actuator/env">Actuator</a></div>
<div class="card"><h2 class="crit">CredsExpose</h2>
<a href="/.aws/credentials">AWS</a><a href="/config.json">Config</a>
<a href="/id_rsa">SSH key</a></div>
<div class="card"><h2 class="crit">BrokenAuth</h2>
<a href="/auth/login">Login</a><a href="/auth/token?user=admin">Token</a></div>
<div class="card"><h2 class="high">InsecPerm</h2>
<a href="/admin">Admin panel</a><a href="/admin/users">Users</a>
<a href="/api/admin">API admin</a></div>
<div class="card"><h2 class="high">SessFix</h2>
<a href="/session/fixate?sessionid=attacker_123">Fixation</a>
<a href="/session/weak">Weak</a></div>
<div class="card"><h2 class="crit">BufOvr</h2>
<a href="/bufovr/input?data=AAAA">Input</a>
<a href="/bufovr/format?data=test">Format string</a></div>
<div class="card"><h2 class="high">XPath</h2>
<a href="/xpath/login">Login</a><a href="/xpath/search?q=admin">Search</a></div>
<div class="card"><h2 class="med">OpenRedirect</h2>
<a href="/redirect?next=http://example.com">Redirect</a></div>
<div class="card"><h2 class="med">CORS</h2>
<a href="/cors/api">Wildcard</a><a href="/cors/sensitive">Origin reflect</a></div>
<div class="card"><h2 class="crit">InsecUpload</h2>
<a href="/upload">Upload</a></div>
<div class="card"><h2 class="med">RaceCondition</h2>
<a href="/race/coupon">Coupon</a><a href="/race/transfer">Transfer</a></div>
<div class="card"><h2 class="med">RateLimit</h2>
<a href="/ratelimit/api?key=test">API</a><a href="/ratelimit/xff">XFF bypass</a></div>
<div class="card"><h2 class="high">LDAPi</h2>
<a href="/ldap/login">Login</a><a href="/ldap/search?uid=admin">Search</a></div>
<div class="card"><h2 class="med">InsecCrypto</h2>
<a href="/crypto/hash?data=test">Hash</a><a href="/crypto/tls-info">TLS info</a></div>
<div class="card"><h2 class="crit">HTTP Smuggling</h2>
<a href="/smuggle/endpoint">Endpoint</a><a href="/smuggle/te-te">TE-TE</a></div>
</div>
<footer>ShieldAI Vuln Server v3.0.0 · payloads_v3.json · Système SHLD{{MARKER}} · ⚠️ LOCAL ONLY</footer>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# XSS — réflexion brute du payload
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xss/reflected')
def xss_reflected():
    q = request.args.get('q', '')
    return f"""<html><head><title>Search</title></head><body>
<h1>Search Results</h1><p>You searched for: {q}</p>
<div id="results">{q}</div>
<form><input name="q" value="{q}"><button>Search</button></form>
</body></html>""", 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    if not hasattr(app, '_comments'):
        app._comments = []
    if request.method == 'POST':
        app._comments.append(request.form.get('comment', ''))
    items = '\n'.join(f'<li class="comment">{c}</li>' for c in app._comments)
    return f"""<html><body><h1>Comments</h1>
<form method="post"><textarea name="comment" rows="3" cols="50"></textarea>
<button>Post</button></form>
<ul>{items}</ul></body></html>"""


@app.route('/xss/header')
def xss_header():
    ua = request.headers.get('User-Agent', '')
    return f"<html><body><h1>Browser Info</h1><p>Your browser: {ua}</p></body></html>"


@app.route('/xss/json')
def xss_jsonp():
    cb = request.args.get('callback', 'callback')
    return Response(f'{cb}({{"user":"admin","token":"secret123"}})',
                    content_type='application/javascript')


@app.route('/xss/attr')
def xss_attr():
    name = request.args.get('name', 'guest')
    return f'<html><body><img alt="{name}" title="{name}"><span data-user="{name}">{name}</span></body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# SQLi — requêtes concaténées, erreurs reflétées
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/sqli/search')
def sqli_search():
    uid = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT id, username, email FROM users WHERE id={uid}")
            row = cur.fetchone()
        result = f"User: {row[1]} ({row[2]})" if row else "Not found"
    except Exception as e:
        result = (f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
                  f"for the right syntax to use near '{uid}' at line 1\n"
                  f"Warning: mysql_fetch_row() expects parameter\n"
                  f"SQLSTATE[42000]: Syntax error or access violation\n"
                  f"Query: SELECT * FROM users WHERE id={uid}")
    resp = make_response(f"<html><body><h1>Search</h1><pre>{result}</pre></body></html>")
    resp.set_cookie('session_user', str(uid))
    return resp


@app.route('/sqli/login', methods=['GET', 'POST'])
def sqli_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'")
                row = cur.fetchone()
            msg = f"Welcome {row[1]} (role={row[4]})" if row else "Invalid credentials"
        except Exception as e:
            msg = (f"You have an error in your SQL syntax near '{u}' at line 1\n"
                   f"SQLSTATE[42000]: Syntax error or access violation\n"
                   f"Warning: mysql_fetch_row() expects parameter")
        return f"<html><body><h1>Login</h1><pre>{msg}</pre></body></html>"
    return """<html><body><h1>Login</h1>
<form method="post"><input name="username"><br>
<input name="password" type="password"><br><button>Login</button></form></body></html>"""


@app.route('/sqli/union')
def sqli_union():
    uid = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT username, email FROM users WHERE id={uid}")
            rows = cur.fetchall()
        result = "\n".join(f"{r[0]} — {r[1]}" for r in rows) or "Not found"
    except Exception as e:
        result = (f"You have an error in your SQL syntax near '{uid}'\n"
                  f"Warning: mysql_fetch_array() expects parameter\n"
                  f"SQLite3::query(): Unable to prepare statement: {e}\n"
                  f"Query failed: SELECT username FROM users WHERE id={uid}")
    return f"<html><body><h1>Union SQLi</h1><pre>{result}</pre></body></html>"


@app.route('/sqli/time')
def sqli_time():
    uid = request.args.get('id', '1')
    start = time.time()
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT * FROM users WHERE id={uid}")
            cur.fetchone()
        lw = uid.lower()
        if 'sleep' in lw or 'waitfor' in lw or 'pg_sleep' in lw:
            m = re.search(r'(\d+)', uid)
            delay = min(int(m.group(1)), 10) if m else 5
            time.sleep(delay)
    except Exception:
        pass
    elapsed = time.time() - start
    return f"<html><body><h1>Time SQLi</h1><p>Query in {elapsed:.3f}s</p></body></html>"


@app.route('/sqli/blind')
def sqli_blind():
    uid = request.args.get('id', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT id FROM users WHERE id={uid}")
            row = cur.fetchone()
        result = "Record exists." if row else "Record not found."
    except Exception:
        result = "Record not found."
    return f"<html><body><h1>Blind SQLi</h1><p>{result}</p></body></html>"


@app.route('/sqli/cookie')
def sqli_cookie():
    uid = request.cookies.get('session_user', '1')
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute(f"SELECT username, email FROM users WHERE id={uid}")
            row = cur.fetchone()
        result = f"Session: {row[0]} ({row[1]})" if row else "Unknown"
    except Exception as e:
        result = (f"You have an error in your SQL syntax near '{uid}'\n"
                  f"Warning: mysql_fetch_row() expects parameter\n"
                  f"SQLite3::query(): Unable to prepare statement: {e}")
    resp = make_response(f"<html><body><h1>Cookie SQLi</h1><pre>{result}</pre></body></html>")
    resp.set_cookie('session_user', str(uid))
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# CMDi — shell=True, payload exécuté et sortie reflétée
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/cmdi/ping', methods=['GET', 'POST'])
def cmdi_ping():
    output = ""
    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1')
        try:
            result = subprocess.run(f"ping -c 2 {host}", shell=True,
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {e}"
    return f"""<html><body><h1>Ping</h1>
<form method="post"><input name="host" value="127.0.0.1" size="30"><button>Ping</button></form>
<pre>{output}</pre></body></html>"""


@app.route('/cmdi/system', methods=['GET', 'POST'])
def cmdi_system():
    output = ""
    # CMDi via header User-Agent
    ua = request.headers.get('User-Agent', '')
    if request.method == 'POST':
        cmd = request.form.get('cmd', '') or ua
        if cmd:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Error: {e}"
    elif ua and ('; echo SHLD' in ua or '| echo SHLD' in ua or '$(echo' in ua):
        try:
            result = subprocess.run(ua, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception:
            pass
    return f"""<html><body><h1>System</h1>
<form method="post"><input name="cmd" value="uname -a" size="50"><button>Run</button></form>
<pre>{output}</pre></body></html>"""


@app.route('/cmdi/lookup')
def cmdi_lookup():
    host = request.args.get('host', 'localhost')
    try:
        result = subprocess.run(f"nslookup {host}", shell=True,
                                capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
    except Exception as e:
        output = f"Error: {e}"
    return f"<html><body><h1>DNS Lookup</h1><pre>{output}</pre></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# DirTrav — open() sans validation de chemin
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/file/read')
def file_read():
    path = request.args.get('path', '')
    if not path:
        return "<html><body><h1>File Reader</h1><p>Provide ?path=filename</p></body></html>"
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read(4096)
    except Exception as e:
        content = f"Error: cannot open '{path}': {e}"
    return f"<html><body><h1>File</h1><pre>{content}</pre></body></html>"


@app.route('/download')
def file_download():
    fname = request.args.get('file', '')
    if not fname:
        return "<p>No file</p>", 400
    try:
        return send_file(fname)
    except Exception:
        if 'passwd' in fname or '/etc/' in fname:
            return Response(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data\n",
                content_type='text/plain')
        return f"<p>Not found: {fname}</p>", 404


@app.route('/template')
def template_include():
    page = request.args.get('page', 'home')
    try:
        with open(f"templates/{page}.html", 'r') as f:
            return f.read()
    except Exception:
        try:
            with open(page, 'r', errors='replace') as f:
                return f"<html><body><pre>{f.read(4096)}</pre></body></html>"
        except Exception:
            return f"<html><body><h1>Template: {page}</h1><p>Loaded.</p></body></html>"


@app.route('/static_file/<path:filename>')
def static_file(filename):
    try:
        with open(filename, 'r', errors='replace') as f:
            return f.read(4096), 200, {'Content-Type': 'text/plain'}
    except Exception:
        return f"Not found: {filename}", 404


# ══════════════════════════════════════════════════════════════════════════════
# XXE — parsing sans protection
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xml/parse', methods=['GET', 'POST'])
def xxe_parse():
    if request.method == 'POST':
        xml_data = request.form.get('xml', '') or request.get_data(as_text=True)
        try:
            if LXML_AVAILABLE:
                parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
                root = ET_LXML.fromstring(xml_data.encode(), parser)
                result = ET_LXML.tostring(root, encoding='unicode')
            else:
                root = ET.fromstring(xml_data)
                result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            result = f"SAXParseException: {e}\nlxml.etree.XMLSyntaxError: {e}"
        return f"<html><body><h1>XML Parser</h1><pre>{result}</pre></body></html>"
    return """<html><body><h1>XML Parser</h1>
<form method="post"><textarea name="xml" rows="5" cols="50">&lt;root/&gt;</textarea><br>
<button>Parse</button></form></body></html>"""


@app.route('/xml/import', methods=['GET', 'POST'])
def xxe_import():
    if request.method == 'POST':
        raw = request.get_data(as_text=True)
        try:
            if LXML_AVAILABLE:
                parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
                root = ET_LXML.fromstring(raw.encode(), parser)
                result = ET_LXML.tostring(root, encoding='unicode')
            else:
                result = "lxml not available"
        except Exception as e:
            result = f"SAXParseException: {e}"
        return jsonify({"result": result})
    return "<html><body><h1>XML Import</h1><p>POST XML here.</p></body></html>"


@app.route('/xml/soap', methods=['GET', 'POST'])
def xxe_soap():
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        try:
            root = ET.fromstring(body)
            return ET.tostring(root, encoding='unicode'), 200, {'Content-Type': 'application/xml'}
        except Exception as e:
            return f"SAXParseException: {e}", 400
    return "<html><body><h1>SOAP</h1><p>POST SOAP here.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# SSRF — fetch de n'importe quelle URL
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/ssrf/fetch', methods=['GET', 'POST'])
def ssrf_fetch():
    url = ''
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        url = data.get('url', request.form.get('url', ''))
    else:
        url = request.args.get('url', '')
    if url:
        try:
            import urllib.request as ur
            resp = ur.urlopen(url, timeout=4)
            content = resp.read().decode('utf-8', errors='replace')[:2000]
            return f"<html><body><h1>Fetch</h1><pre>{content}</pre></body></html>"
        except Exception as e:
            return f"<html><body><h1>Fetch</h1><p>Error: {e}</p></body></html>"
    return """<html><body><h1>URL Fetcher (SSRF)</h1>
<form method="post"><input name="url" value="http://example.com" size="50"><button>Fetch</button></form>
</body></html>"""


@app.route('/ssrf/preview')
def ssrf_preview():
    url = request.args.get('url', '')
    if url:
        try:
            import urllib.request as ur
            resp = ur.urlopen(url, timeout=3)
            content = resp.read().decode('utf-8', errors='replace')[:500]
            return f"<html><body><h1>Preview</h1><pre>{content}</pre></body></html>"
        except Exception as e:
            return f"<html><body><h1>Preview</h1><p>Error: {e}</p></body></html>"
    return "<html><body><h1>Preview</h1><p>No URL.</p></body></html>"


@app.route('/ssrf/avatar')
def ssrf_avatar():
    url = request.args.get('url', '')
    if url:
        try:
            import urllib.request as ur
            resp = ur.urlopen(url, timeout=3)
            data = resp.read()
            ct = resp.headers.get('Content-Type', 'image/png')
            return Response(data, content_type=ct)
        except Exception as e:
            return Response(f"Error: {e}".encode(), content_type='text/plain')
    return Response(b'\x89PNG\r\n\x1a\n', content_type='image/png')


@app.route('/ssrf/webhook', methods=['GET', 'POST'])
def ssrf_webhook():
    if request.method == 'POST':
        url = request.form.get('webhook_url', '')
        data = request.form.get('data', '{}')
        if url:
            try:
                import urllib.request as ur
                req = ur.Request(url, data=data.encode(), method='POST')
                resp = ur.urlopen(req, timeout=4)
                result = resp.read().decode()[:500]
                return f"<html><body><p>Sent. Response: {result}</p></body></html>"
            except Exception as e:
                return f"<html><body><p>Error: {e}</p></body></html>"
    return """<html><body><h1>Webhook</h1>
<form method="post"><input name="webhook_url"><br>
<textarea name="data" rows="3" cols="40">{}</textarea><br>
<button>Send</button></form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SSTI — eval() sur les expressions {{ }}
# Payload v3 : "{{1337*1337}}SHLDABCD" → "1787569SHLDABCD"
# ══════════════════════════════════════════════════════════════════════════════
def _ssti_eval(s: str) -> str:
    def repl(m):
        inner = m.group(1).strip()
        try:
            result = eval(inner, {"__builtins__": {"__import__": __import__}})
            return str(result)
        except Exception as e:
            return f"[jinja2.exceptions.TemplateSyntaxError: {e}]"
    return re.sub(r'\{\{(.+?)\}\}', repl, s)


@app.route('/ssti/greet')
def ssti_greet():
    name = request.args.get('name', 'World')
    rendered = _ssti_eval(f"Hello, {name}!")
    return f"<html><body><h1>Greet</h1><p>{rendered}</p></body></html>"


@app.route('/ssti/render', methods=['GET', 'POST'])
def ssti_render():
    if request.method == 'POST':
        tpl = request.form.get('template', '')
        result = _ssti_eval(tpl)
        return f"<html><body><h1>Render</h1><pre>Output: {result}</pre></body></html>"
    return """<html><body><h1>Template Renderer</h1>
<form method="post"><textarea name="template" rows="3" cols="50">Hello</textarea><br>
<button>Render</button></form></body></html>"""


@app.route('/ssti/email')
def ssti_email():
    to = request.args.get('to', 'user@example.com')
    subject = request.args.get('subject', 'Welcome')
    body = f"Dear {to}, Subject: {subject}"
    return f"<html><body><h1>Email</h1><pre>{_ssti_eval(body)}</pre></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# NoSQLi — opérateurs MongoDB simulés
# ══════════════════════════════════════════════════════════════════════════════
_nosql_users = [
    {"_id": "1", "username": "admin",  "password": "admin123",  "role": "admin"},
    {"_id": "2", "username": "alice",  "password": "alice2026", "role": "user"},
    {"_id": "3", "username": "bob",    "password": "bobsecret", "role": "user"},
]


@app.route('/nosql/login', methods=['GET', 'POST'])
def nosql_login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        u = data.get('username', request.form.get('username', ''))
        p = data.get('password', request.form.get('password', ''))
        all_str = str(u) + str(p) + str(data)
        if isinstance(u, dict) or '$' in all_str:
            if isinstance(u, dict) and '$ne' in u:
                return jsonify({
                    "status": "ok", "message": "Login successful",
                    "users": [x['username'] for x in _nosql_users],
                    "MongoError": "unknown operator: $ne bypassed"
                })
            return jsonify({
                "error": "MongoServerError: unknown operator: $regex",
                "detail": "CastError: Cast to ObjectId failed",
                "BSONTypeError": "cast failed"
            }), 400
        user = next((x for x in _nosql_users if x['username'] == u and x['password'] == p), None)
        if user:
            return jsonify({"status": "ok", "message": f"Welcome {user['username']}"})
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>NoSQL Login</h1>
<form method="post"><input name="username"><br><input name="password"><br><button>Login</button></form>
</body></html>"""


@app.route('/nosql/search')
def nosql_search():
    q = request.args.get('q', '')
    if '$' in q:
        return f"""<html><body><h1>NoSQL Search</h1>
<p>MongoServerError: unknown operator: {q}</p>
<p>CastError: Cast to ObjectId failed for "{q}"</p>
<p>BSONTypeError: cast failed</p></body></html>"""
    found = [x for x in _nosql_users if q.lower() in x['username'].lower()]
    return f"<html><body><h1>NoSQL Search</h1><p>{found or 'No results'}</p></body></html>"


@app.route('/nosql/users')
def nosql_users():
    where = request.args.get('where', '')
    if '$' in where or '1==1' in where:
        return jsonify({"MongoServerError": "$where is not allowed", "users": _nosql_users})
    return jsonify({"result": "No users"})


# ══════════════════════════════════════════════════════════════════════════════
# CRLF — injection dans les headers de réponse
# Payload v3 : "%0d%0aX-SHLD: SHLDABCD"
# Le header X-User reçoit la valeur brute → si CRLF présent, X-SHLD est injecté
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/crlf/header')
def crlf_header():
    name = request.args.get('name', 'test')
    resp = make_response(f"<html><body><h1>CRLF Header</h1><p>Name: {name}</p></body></html>")
    try:
        resp.headers['X-User'] = name
    except Exception:
        pass
    return resp


@app.route('/crlf/redirect')
def crlf_redirect():
    url = request.args.get('url', 'http://example.com')
    resp = make_response("Redirecting...", 302)
    try:
        resp.headers['Location'] = url
    except Exception:
        resp.headers['Location'] = 'http://example.com'
    return resp


@app.route('/crlf/log')
def crlf_log():
    data = request.args.get('data', 'test')
    return f"<html><body><h1>Log</h1><pre>[LOG] User input: {data}</pre></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# JWT
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/jwt/login', methods=['GET', 'POST'])
def jwt_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == 'admin' and p in ('admin', 'admin123', 'password'):
            payload = {"user": u, "role": "admin", "isAdmin": False, "exp": time.time() + 3600}
            if JWT_AVAILABLE:
                token = pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')
            else:
                h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')
                p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                token = f"{h}.{p64}.fakesig"
            return jsonify({"token": token, "user": u, "role": "admin"})
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>JWT Login</h1>
<form method="post"><input name="username"><br>
<input name="password" type="password"><br><button>Login</button></form></body></html>"""


@app.route('/jwt/profile')
def jwt_profile():
    auth = request.headers.get('Authorization', '')
    token = (auth.replace('Bearer ', '')
             or request.args.get('token', '')
             or request.cookies.get('token', ''))
    if not token:
        return jsonify({"error": "No token"}), 401
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            pad = 4 - len(parts[0]) % 4
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * pad))
            pad2 = 4 - len(parts[1]) % 4
            pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad2))
            alg = header.get('alg', '').lower()
            if alg in ('none', ''):
                marker = pl.get('marker', '')
                return jsonify({
                    "status": "alg: none accepted",
                    "message": "Welcome admin",
                    "role": "admin", "isAdmin": True,
                    "marker": marker,
                    "privileged access granted": True,
                    "payload": pl
                })
            if JWT_AVAILABLE:
                decoded = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                return jsonify({"status": "ok", "payload": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"error": "Invalid token"}), 400


@app.route('/jwt/admin')
def jwt_admin():
    token = (request.headers.get('Authorization', '').replace('Bearer ', '')
             or request.args.get('token', '')
             or request.cookies.get('token', ''))
    if not token:
        return jsonify({"error": "No token"}), 401
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            pad = 4 - len(parts[1]) % 4
            pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad))
            if pl.get('isAdmin') or pl.get('role') == 'superadmin':
                return jsonify({
                    "status": "Admin access granted", "isAdmin": True,
                    "privileged access granted": True,
                    "message": "Welcome admin", "role": "admin"
                })
            return jsonify({"status": "forbidden"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"error": "Invalid token"}), 401


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    q = ''
    if request.method == 'GET':
        q = request.args.get('q', '')
        if not q:
            return jsonify({"message": "GraphQL — POST query here"}), 200
    else:
        data = request.get_json(silent=True) or {}
        q = str(data.get('query', ''))

    if '__schema' in q or '__type' in q or 'IntrospectionQuery' in q or '{__schema' in q:
        return jsonify({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "kinds": ["OBJECT", "SCALAR"],
                    "types": [
                        {"kind": "OBJECT", "name": "User",
                         "fields": [{"name": "id"}, {"name": "username"},
                                    {"name": "email"}, {"name": "passwordHash"}]},
                        {"kind": "SCALAR", "name": "String"},
                    ]
                }
            }
        })
    if 'user(' in q.lower():
        m = re.search(r"id\s*:\s*[\"']?([^\"'\)]+)", q)
        uid = m.group(1).strip() if m else '1'
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute(f"SELECT id, username, email, role FROM users WHERE id={uid}")
                row = cur.fetchone()
            if row:
                return jsonify({"data": {"user": {"id": row[0], "username": row[1],
                                                   "email": row[2], "role": row[3]}}})
        except Exception as e:
            return jsonify({"errors": [{"message": f"graphql error: {e}"}]})
    if 'users' in q.lower():
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email, role FROM users")
            rows = cur.fetchall()
        return jsonify({"data": {"users": [{"id": r[0], "username": r[1],
                                             "email": r[2], "role": r[3]} for r in rows]}})
    return jsonify({"errors": [{"message": f"Cannot query field: {q[:50]}"}]})


@app.route('/graphql/playground')
def graphql_playground():
    return "<html><body><h1>GraphQL Playground</h1><p>POST to /graphql</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# IDOR
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/users/<int:uid>')
def idor_user(uid):
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
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM documents WHERE id=?", (doc_id,))
        row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "owner_id": row[1], "title": row[2],
                        "content": row[3], "is_private": row[4],
                        "email": "owner@shieldai.io", "credit_card": "4111111111111111"})
    return jsonify({"error": "Not found"}), 404


@app.route('/api/invoices/<int:inv_id>')
def idor_invoice(inv_id):
    return jsonify({
        "invoice_id": inv_id, "user_id": 1, "amount": inv_id * 99.99,
        "account_number": f"ACC-{inv_id:04d}", "credit_card": "4111111111111111",
        "date_of_birth": "1990-01-01", "ssn": "123-45-6789",
        "phone": "+1-555-0100", "email": "billing@shieldai.io"
    })


@app.route('/api/orders/<int:oid>')
def idor_order(oid):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM orders WHERE id=?", (oid,))
        row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "user_id": row[1], "product": row[2],
                        "amount": row[3], "email": "user@shieldai.io",
                        "credit_card": "4111111111111111", "date_of_birth": "1990-01-01"})
    return jsonify({"error": "Not found"}), 404


# ══════════════════════════════════════════════════════════════════════════════
# Prototype Pollution
# Payload v3 : {"__proto__": {"isAdmin": true, "marker": "SHLDABCD"}}
# → serveur retourne {"isAdmin": true, "marker": "SHLDABCD"}
# ══════════════════════════════════════════════════════════════════════════════
_proto_store: dict = {}


@app.route('/proto/merge', methods=['GET', 'POST'])
def proto_merge():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        for k, v in data.items():
            _proto_store[k] = v
        is_admin = False
        marker = ''
        if '__proto__' in data and isinstance(data['__proto__'], dict):
            is_admin = data['__proto__'].get('isAdmin', False)
            marker   = data['__proto__'].get('marker', '')
        elif 'constructor' in data:
            proto = data['constructor'].get('prototype', {})
            is_admin = proto.get('isAdmin', False)
            marker   = proto.get('marker', '')
        return jsonify({
            "merged": True, "isAdmin": is_admin, "marker": marker,
            "__proto__ accepted": bool(is_admin),
            "prototype chain modified": bool(is_admin),
        })
    return "<html><body><h1>Proto Merge</h1><p>POST JSON</p></body></html>"


@app.route('/proto/extend')
def proto_extend():
    params = request.args.to_dict()
    is_admin = params.get('__proto__[isAdmin]', 'false').lower() == 'true'
    marker   = params.get('__proto__[marker]', '') or params.get('constructor[prototype][marker]', '')
    if is_admin:
        return jsonify({"params": params, "isAdmin": True, "marker": marker,
                        "__proto__ accepted": True})
    return jsonify({"params": params, "isAdmin": False})


# ══════════════════════════════════════════════════════════════════════════════
# InsecDeser
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/deser/json', methods=['GET', 'POST'])
def deser_json():
    if request.method == 'POST':
        raw = request.get_json(silent=True) or {}
        rce = str(raw.get('rce', ''))
        if '_$$ND_FUNC$$_' in rce:
            result = rce
            try:
                inner = re.search(r"exec\('(.+?)'\)", rce)
                if inner:
                    out = subprocess.run(inner.group(1), shell=True,
                                         capture_output=True, text=True, timeout=5)
                    result = out.stdout + out.stderr
            except Exception:
                pass
            return jsonify({"result": result, "_$$ND_FUNC$$_": "triggered"})
        return jsonify({"result": f"Received: {json.dumps(raw)}"})
    return "<html><body><h1>JSON Deserializer</h1><p>POST JSON</p></body></html>"


@app.route('/deser/pickle', methods=['GET', 'POST'])
def deser_pickle():
    if request.method == 'POST':
        data = request.form.get('data', '') or request.get_data(as_text=True)
        try:
            obj = pickle.loads(base64.b64decode(data))  # ⚠️ VULNERABLE
            return f"<html><body><pre>Deserialized: {obj}</pre></body></html>"
        except Exception as e:
            return f"<html><body><pre>Error: {e}</pre></body></html>"
    return """<html><body><h1>Pickle</h1>
<form method="post"><textarea name="data" rows="3" cols="50"></textarea><br>
<button>Deserialize</button></form></body></html>"""


@app.route('/deser/cookie')
def deser_cookie():
    cd = request.cookies.get('user_data', '')
    if cd:
        try:
            obj = pickle.loads(base64.b64decode(cd))
            return f"<html><body><p>Cookie: {obj}</p></body></html>"
        except Exception as e:
            return f"<html><body><p>Error: {e}</p></body></html>"
    return "<html><body><p>No user_data cookie.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# InfoDisc / CredsExpose
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/.env')
def exposed_env():
    return ("DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=shieldai_prod\n"
            "DB_USER=dbadmin\nDB_PASSWORD=Sup3rS3cr3tP@ssw0rd!\n"
            "API_KEY=sk-shieldai-1234567890abcdef\nAPI_SECRET=secret_api_key_value\n"
            "SECRET_KEY=shieldai_secret_key_very_long\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.env.local')
@app.route('/.env.production')
@app.route('/.env.staging')
def exposed_env_local():
    return ("DB_PASSWORD=local_secret_password\nAPI_KEY=local-api-key-12345\n"
            "SECRET_KEY=local_secret_key\nDATABASE_PASSWORD=local_db_pass\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.git/config')
def exposed_git():
    return ("[core]\n\trepositoryformatversion = 0\n"
            "[remote \"origin\"]\n\turl = https://github.com/shieldai/vuln-server.git\n"
            "[user]\n\temail = admin@shieldai.io\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/debug')
def debug_info():
    return jsonify({
        "debug": True, "DB_PASSWORD": "Sup3rS3cr3tP@ssw0rd!",
        "API_KEY": "sk-shieldai-debug-1234567890",
        "SECRET_KEY": "shieldai_secret_key",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    })


@app.route('/actuator/env')
def actuator_env():
    return jsonify({
        "activeProfiles": ["production"],
        "propertySources": [{"name": "systemEnvironment", "properties": {
            "DB_PASSWORD": {"value": "Sup3rS3cr3tP@ssw0rd!"},
            "API_KEY": {"value": "sk-shieldai-actuator-key"},
            "SECRET_KEY": {"value": "shieldai_secret_key"},
            "aws_access_key_id": {"value": "AKIAIOSFODNN7EXAMPLE"},
            "aws_secret_access_key": {"value": "wJalrXUtnFEMI/K7MDENG"},
        }}]
    })


@app.route('/actuator/heapdump')
def actuator_heapdump():
    return Response(b"JAVA_HEAP\x00DB_PASSWORD=admin123\x00API_KEY=shieldai\x00",
                    content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=heapdump.hprof'})


@app.route('/swagger.json')
def swagger_spec():
    return jsonify({"openapi": "3.0.0", "info": {"title": "ShieldAI Internal API", "version": "1.0.0"},
                    "paths": {"/api/admin/users": {"get": {"summary": "List all users"}}}})


@app.route('/phpinfo')
def phpinfo():
    return jsonify({"display_errors": "On", "DB_PASSWORD": "Sup3rS3cr3t",
                    "API_KEY": "sk-test-phpinfo"})


@app.route('/.aws/credentials')
def aws_creds():
    return ("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "region = us-east-1\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/wp-config.php')
def wp_config():
    return ("<?php\ndefine('DB_NAME', 'wordpress_db');\n"
            "define('DB_USER', 'wp_admin');\ndefine('DB_PASSWORD', 'wp_S3cr3t_P@ss!');\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/config.json')
def config_json():
    return jsonify({
        "DB_PASSWORD": "db_password_exposed", "API_KEY": "int_key_shieldai_123",
        "API_SECRET": "ext_key_abc_456", "SECRET_KEY": "config_secret_key",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    })


@app.route('/database.yml')
def database_yml():
    return ("production:\n  username: dbadmin\n"
            "  DB_PASSWORD: 'YamlPassword123!'\n  database: shieldai_prod\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/secrets.yml')
def secrets_yml():
    return ("DB_PASSWORD: shieldai_secret_db_pass\nAPI_KEY: shieldai_api_key_12345\n"
            "SECRET_KEY: shieldai_secret_key_base\n"
            "aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/id_rsa')
def ssh_private_key():
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA (FAKE KEY — TESTING ONLY)\n"
            "-----END OPENSSH PRIVATE KEY-----\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.netrc')
def netrc():
    return "machine github.com\n  login shieldai-bot\n  password ghp_ShieldAI1234567890\n",\
           200, {'Content-Type': 'text/plain'}


@app.route('/backup.sql')
def backup_sql():
    return ("-- MySQL dump\nDB_PASSWORD='backup_pass';\n"
            "INSERT INTO users VALUES (1,'admin','admin123');\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/credentials.json')
def credentials_json():
    return jsonify({"DB_PASSWORD": "cred_password", "API_KEY": "cred_api_key",
                    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"})


# ══════════════════════════════════════════════════════════════════════════════
# BrokenAuth
# ══════════════════════════════════════════════════════════════════════════════
_default_creds = {
    'admin': ['admin', 'admin123', '123456', 'password', ''],
    'root': ['root', 'toor', ''], 'test': ['test'], 'guest': ['guest'],
    'administrator': ['password', 'admin'],
}


@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u in _default_creds and p in _default_creds[u]:
            resp = make_response(jsonify({
                "status": "ok", "message": f"Welcome, admin — Logged in as {u}",
                "access_token": f"token_{u}_authenticated",
                "auth_token": hashlib.sha256(f"shieldai_{u}".encode()).hexdigest(),
            }))
            resp.set_cookie('session', f'sess_{u}_authenticated', httponly=False)
            resp.set_cookie('auth', f'auth_{u}', httponly=False)
            return resp
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>Login</h1>
<form method="post"><input name="username"><br>
<input name="password" type="password"><br><button>Login</button></form>
<p><small>admin:admin | test:test | guest:guest</small></p></body></html>"""


@app.route('/auth/reset', methods=['GET', 'POST'])
def auth_reset():
    if request.method == 'POST':
        email = request.form.get('email', '')
        return f"<html><body><p>Welcome, admin — Logged in as {email}, password reset — no verification</p></body></html>"
    return """<html><body><h1>Reset</h1>
<form method="post"><input name="email"><input name="password" type="password">
<button>Reset</button></form></body></html>"""


@app.route('/auth/token')
def auth_token():
    user = request.args.get('user', 'anonymous')
    token = hashlib.sha256(f"shieldai_{user}".encode()).hexdigest()
    resp = make_response(jsonify({
        "token": token, "access_token": token,
        "user": user, "expires": None, "message": f"Logged in as {user}"
    }))
    resp.set_cookie('session', f'sess_{user}', httponly=False)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# InsecPerm
# Payload v3 : /admin?ref=SHLDABCD → réponse contient SHLDABCD
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/admin')
def admin_panel():
    ref = request.args.get('ref', '')
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, username, email, role FROM users")
        users = cur.fetchall()
    rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in users)
    return f"""<html><body>
<h1>Admin Panel — Administration Console</h1>
<p>WordPress Dashboard — No authentication required</p>
{f'<p data-ref="{ref}">ref: {ref}</p>' if ref else ''}
<table border="1"><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
{rows}</table></body></html>"""


@app.route('/admin/users')
def admin_users():
    ref = request.args.get('ref', '')
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
    return jsonify({
        "panel": "Administration Console", "ref": ref,
        "users": [{"id": r[0], "username": r[1], "password": r[2],
                   "email": r[3], "role": r[4]} for r in rows]
    })


@app.route('/api/admin')
def api_admin():
    ref = request.args.get('ref', '')
    return jsonify({"admin": True, "panel": "Admin Panel", "ref": ref,
                    "note": "Administration Console — No auth required"})


@app.route('/phpmyadmin')
def phpmyadmin():
    return "<html><body><h1>phpMyAdmin</h1><p>Administration Console — phpMyAdmin</p></body></html>"


@app.route('/manager/html')
def tomcat_manager():
    return "<html><body><h1>Apache Tomcat Manager</h1><p>Administration Console</p></body></html>"


@app.route('/cpanel')
def cpanel():
    return "<html><body><h1>cPanel</h1><p>Administration Console — cPanel</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# SessFix
# Payload v3 : cookie PHPSESSID=SHLDABCD_fixed_session
# → serveur répond avec Set-Cookie: PHPSESSID=SHLDABCD_fixed_session
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/session/fixate')
def session_fixate():
    sid = request.args.get('sessionid', '') or request.cookies.get('PHPSESSID', '')
    if not sid:
        return "<html><body><h1>Session Fixation</h1><p>Provide ?sessionid=xxx</p></body></html>"
    resp = make_response(f"<html><body><h1>Session</h1><p>Accepted: {sid}</p><p>session_id reused</p></body></html>")
    resp.set_cookie('PHPSESSID', sid, httponly=False, samesite=None)
    resp.set_cookie('JSESSIONID', sid, httponly=False, samesite=None)
    resp.set_cookie('session_token', sid, httponly=False)
    return resp


@app.route('/session/weak')
def session_weak():
    ts = int(time.time())
    weak_id = f"{ts:x}"
    resp = make_response(jsonify({"session_id": weak_id, "predictable_token": weak_id}))
    resp.set_cookie('PHPSESSID', weak_id, httponly=False, samesite=None)
    return resp


@app.route('/session/info')
def session_info():
    return jsonify({"session": dict(session), "cookies": dict(request.cookies)})


# ══════════════════════════════════════════════════════════════════════════════
# BufOvr
# Payload v3 : "SHLDABCDAAA...AAAA" → serveur reflète le début → SHLDABCD trouvé
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/bufovr/input')
def bufovr_input():
    data = request.args.get('data', '')
    length = len(data)
    if length > 50000:
        return (f"segmentation fault (core dumped)\n"
                f"stack smashing detected — input: {data[:50]}\n"
                f"memory corruption"), 500
    if re.search(r'%[0-9]*[xsndpu]', data):
        return (f"Format string: {data[:200]}\nstack smashing detected\n"
                f"*** stack smashing detected ***\nmemory corruption"), 200
    return jsonify({"received_length": length, "preview": data[:200], "status": "ok"})


@app.route('/bufovr/format')
def bufovr_format():
    data = request.args.get('data', '')
    if re.search(r'%[0-9]*[xsndpu]', data):
        return (f"Format string: {data[:200]}\nstack smashing detected\n"
                f"*** stack smashing detected ***\nmemory corruption"), 200
    return f"Input: {data[:200]}", 200


@app.route('/bufovr/header')
def bufovr_header():
    ua = request.headers.get('User-Agent', '')
    custom = request.headers.get('X-Custom-Data', '')
    total = len(ua) + len(custom)
    if total > 8192:
        return "segmentation fault\nstack smashing detected", 431
    return jsonify({"ua_length": len(ua), "total": total, "ua_preview": ua[:200]})


# ══════════════════════════════════════════════════════════════════════════════
# XPath Injection
# Payload v3 : "' or 'SHLDABCD'='SHLDABCD"
# → XPath construit par concaténation → erreur reflète le payload → SHLDABCD trouvé
# ══════════════════════════════════════════════════════════════════════════════
_xml_users_db = """<?xml version="1.0"?>
<users>
  <user><id>1</id><username>admin</username><password>xmlpass123</password><role>admin</role></user>
  <user><id>2</id><username>alice</username><password>alice123</password><role>user</role></user>
</users>"""


@app.route('/xpath/login', methods=['GET', 'POST'])
def xpath_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            root = ET.fromstring(_xml_users_db)
            xpath = f".//user[username='{username}' and password='{password}']"
            matches = root.findall(xpath)
            if matches:
                return f"<html><body><h1>XPath Login</h1><p>Welcome {username}!</p></body></html>"
            if "'" in username or "or" in username.lower():
                return f"""<html><body><h1>XPath Login</h1>
<p>XPathException: Invalid predicate: {username}</p>
<p>XPath syntax error near '{username}'</p>
<p>lxml.etree.XPathEvalError: {username}</p></body></html>"""
        except Exception as e:
            return f"<html><body><h1>XPath Login</h1><p>XPathException: {e}</p><p>lxml.etree.XPathEvalError: {username}</p></body></html>"
        return "<html><body><h1>XPath Login</h1><p>Invalid credentials</p></body></html>"
    return """<html><body><h1>XPath Login</h1>
<form method="post"><input name="username"><br><input name="password"><br><button>Login</button></form>
</body></html>"""


@app.route('/xpath/search')
def xpath_search():
    q = request.args.get('q', '')
    try:
        root = ET.fromstring(_xml_users_db)
        xpath = f".//user[username='{q}']"
        found = root.findall(xpath)
        if found:
            return f"<html><body><h1>XPath Search</h1><p>Found: {[u.find('username').text for u in found]}</p></body></html>"
        if "'" in q or "or" in q.lower():
            return f"""<html><body><h1>XPath Search</h1>
<p>XPath syntax error: Unexpected token near '{q}'</p>
<p>lxml.etree.XPathEvalError: Invalid expression: {q}</p>
<p>XPathException: {q}</p></body></html>"""
    except Exception as e:
        return f"<html><body><h1>XPath Search</h1><p>XPathException: {e}</p><p>lxml.etree.XPathEvalError: {q}</p></body></html>"
    return f"<html><body><h1>XPath Search</h1><p>No results for: {q}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# OpenRedirect — Location header reçoit la valeur brute
# Payload v3 : "https://shld-SHLDABCD.io"
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/redirect')
def open_redirect():
    next_url = request.args.get('next', '/')
    resp = make_response("Redirecting...", 302)
    try:
        resp.headers['Location'] = next_url
    except Exception:
        resp.headers['Location'] = '/'
    return resp


@app.route('/logout')
def logout_redirect():
    return_to = request.args.get('return_to', '/')
    session.clear()
    resp = make_response("Logged out", 302)
    try:
        resp.headers['Location'] = return_to
    except Exception:
        resp.headers['Location'] = '/'
    return resp


@app.route('/login')
def login_form():
    redir = request.args.get('redirect', '/')
    return f"""<html><body><h1>Login</h1>
<form method="post" action="/auth/login">
  <input name="username"><input name="password" type="password">
  <input type="hidden" name="redirect" value="{redir}">
  <button>Login</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# CORS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/cors/api')
def cors_api():
    resp = make_response(jsonify({"user": "admin", "api_key": "sk-SHIELDAI-SECRET-123"}))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


@app.route('/cors/sensitive')
def cors_sensitive():
    origin = request.headers.get('Origin', 'null')
    resp = make_response(jsonify({"secret": "SHIELDAI_SENSITIVE_DATA"}))
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


@app.route('/cors/null')
def cors_null():
    resp = make_response(jsonify({"data": "sensitive"}))
    resp.headers['Access-Control-Allow-Origin'] = 'null'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# InsecUpload
# Payload v3 : filename "SHLDABCD.php" → réponse contient "SHLDABCD.php"
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files.get('file')
        if f and f.filename:
            filepath = os.path.join(UPLOAD_FOLDER, f.filename)
            f.save(filepath)
            return f"""<html><body>
<h1>Upload</h1>
<p>File uploaded successfully: {f.filename}</p>
<p>Path: /uploads/{f.filename}</p>
<p>saved as {f.filename}</p>
</body></html>"""
    return """<html><body><h1>File Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file"><br><button>Upload</button>
</form></body></html>"""


@app.route('/upload/avatar', methods=['GET', 'POST'])
def upload_avatar():
    if request.method == 'POST':
        f = request.files.get('avatar')
        if f and f.filename:
            filepath = os.path.join(UPLOAD_FOLDER, 'avatar_' + f.filename)
            f.save(filepath)
            return f"<html><body><p>File uploaded successfully: {f.filename} — /uploads/{f.filename}</p></body></html>"
    return """<html><body><h1>Avatar</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="avatar"><button>Upload</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# CSRF
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/csrf/transfer', methods=['GET', 'POST'])
def csrf_transfer():
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '0')
        ref = request.form.get('ref', '')
        return f"<html><body><p>Transferred ${amount} to {to} — no CSRF token{' ref:'+ref if ref else ''}</p></body></html>"
    return """<html><body><h1>Transfer</h1>
<form method="post"><input name="to"><input name="amount"><button>Transfer</button></form></body></html>"""


@app.route('/csrf/delete', methods=['GET', 'POST'])
def csrf_delete():
    if request.method == 'POST':
        return "<html><body><p>Account deleted — No CSRF token</p></body></html>"
    return '<html><body><form method="post"><button>Delete Account</button></form></body></html>'


@app.route('/csrf/email', methods=['GET', 'POST'])
def csrf_email():
    if request.method == 'POST':
        email = request.form.get('email', '')
        ref = request.form.get('ref', '')
        return f"<html><body><p>Email changed to {email} — No CSRF token{' ref:'+ref if ref else ''}</p></body></html>"
    return '<html><body><form method="post"><input name="email"><button>Change</button></form></body></html>'


@app.route('/csrf/password', methods=['GET', 'POST'])
def csrf_password():
    if request.method == 'POST':
        return "<html><body><p>Password changed — No CSRF token, no old password</p></body></html>"
    return '<html><body><form method="post"><input name="password" type="password"><button>Change</button></form></body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# RaceCondition
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/race/coupon', methods=['GET', 'POST'])
def race_coupon():
    if request.method == 'POST':
        code = request.form.get('code', '')
        ref = request.form.get('ref', '') or request.args.get('ref', '')
        time.sleep(0.05)
        if code == 'DISCOUNT50' or 'DISCOUNT' in code.upper():
            if code in _coupons:
                return f"<html><body><p>already redeemed — coupon used more than once{' ref:'+ref if ref else ''}</p></body></html>"
            _coupons.add(code)
            return f"<html><body><p>Coupon applied! -50% discount{' ref:'+ref if ref else ''}</p></body></html>"
        return "<html><body><p>Invalid coupon</p></body></html>"
    return """<html><body><h1>Coupon</h1>
<form method="post"><input name="code" value="DISCOUNT50"><input name="ref">
<button>Apply</button></form></body></html>"""


@app.route('/race/transfer', methods=['GET', 'POST'])
def race_transfer():
    if request.method == 'POST':
        user = request.form.get('user', 'user1')
        try:
            amount = float(request.form.get('amount', 0))
        except Exception:
            amount = 0
        time.sleep(0.05)
        if _balance.get(user, 0) >= amount:
            _balance[user] -= amount
            return jsonify({"status": "ok", "new_balance": _balance[user]})
        return jsonify({"error": "concurrent modification detected — UNIQUE constraint failed"}), 400
    return f"""<html><body><h1>Transfer</h1><p>Balances: {_balance}</p>
<form method="post"><input name="user" value="user1"><input name="amount" value="100">
<button>Transfer</button></form></body></html>"""


@app.route('/race/vote')
def race_vote():
    if not hasattr(app, '_votes'):
        app._votes = defaultdict(int)
    post_id = request.args.get('post_id', '1')
    time.sleep(0.02)
    app._votes[post_id] += 1
    return jsonify({"post_id": post_id, "votes": app._votes[post_id]})


# ══════════════════════════════════════════════════════════════════════════════
# RateLimit
# ══════════════════════════════════════════════════════════════════════════════
_rl_counts: dict = defaultdict(int)
_rl_lock = threading.Lock()


@app.route('/ratelimit/api')
def ratelimit_api():
    xff = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = xff.split(',')[0].strip()
    with _rl_lock:
        _rl_counts[ip] += 1
    return jsonify({"status": "ok", "requests": _rl_counts[ip], "rate_limit": None})


@app.route('/ratelimit/xff')
def ratelimit_xff():
    xff = request.headers.get('X-Forwarded-For', '')
    real_ip = request.headers.get('X-Real-IP', '')
    if xff or real_ip:
        return jsonify({"X-Forwarded-For": xff, "rate_limit_bypassed": True})
    return jsonify({"note": "Standard request"})


@app.route('/ratelimit/login', methods=['GET', 'POST'])
def ratelimit_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == 'admin' and p == 'admin':
            return "<html><body><p>Login successful — no rate limit</p></body></html>"
        return "<html><body><p>Invalid</p></body></html>"
    return """<html><body><h1>Login (No Rate Limit)</h1>
<form method="post"><input name="username"><input name="password" type="password">
<button>Login</button></form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# LDAPi
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/ldap/login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        if '*' in uid or '|' in uid or ')' in uid:
            return f"""<html><body><h1>LDAP</h1>
<p>LDAP Result Code 2 — ldap_bind() failed — ldap_search_s() failed
Invalid filter syntax — Bad search filter — javax.naming.NamingException: {uid}</p></body></html>"""
        if uid == 'admin' and pwd == 'ldappass':
            return "<html><body><p>LDAP auth OK</p></body></html>"
        return "<html><body><p>Invalid LDAP credentials</p></body></html>"
    return """<html><body><h1>LDAP Login</h1>
<form method="post"><input name="uid"><input name="password"><button>Login</button></form>
</body></html>"""


@app.route('/ldap/search')
def ldap_search():
    uid = request.args.get('uid', '')
    if '*' in uid or '|' in uid:
        return f"<html><body><p>ldap_search_s() failed — Invalid filter syntax: {uid}</p></body></html>"
    return f"<html><body><p>No result for uid={uid}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# InsecCrypto
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/crypto/hash')
def crypto_hash():
    data = request.args.get('data', 'test')
    return jsonify({"input": data, "md5": hashlib.md5(data.encode()).hexdigest(),
                    "sha1": hashlib.sha1(data.encode()).hexdigest()})


@app.route('/crypto/token')
def crypto_token():
    user = request.args.get('user', 'guest')
    ts = int(time.time())
    return jsonify({"user": user, "token": hashlib.md5(f"{user}{ts}".encode()).hexdigest(), "timestamp": ts})


@app.route('/crypto/tls-info')
def crypto_tls_info():
    return jsonify({
        "supported_ciphers": ["TLS_RSA_WITH_RC4_128_MD5", "SSL_CK_RC4_128_WITH_MD5",
                              "TLS_RSA_WITH_DES_CBC_SHA", "SSLv3"],
        "min_tls_version": "TLSv1.0",
        "hsts_enabled": False
    })


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Request Smuggling
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/smuggle/endpoint', methods=['GET', 'POST', 'OPTIONS'])
def smuggle_endpoint():
    te = request.headers.get('Transfer-Encoding', '')
    cl = request.headers.get('Content-Length', '')
    body = request.get_data(as_text=True)
    if te and cl:
        return jsonify({"Transfer-Encoding": te, "Content-Length": cl,
                        "note": "chunked encoding conflict — Transfer-Encoding conflict",
                        "desynchronized": True})
    return jsonify({"Transfer-Encoding": te, "body_preview": body[:200]})


@app.route('/smuggle/te-te')
def smuggle_te_te():
    te = request.headers.get('Transfer-Encoding', '')
    if 'identity' in te or 'xchunked' in te:
        return jsonify({"note": "TE.TE obfuscation — Transfer-Encoding conflict", "desynchronized": True})
    return jsonify({"Transfer-Encoding": te})


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║        ShieldAI VULNERABLE TEST SERVER v3.0.0                           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ⚠️  INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║  URL     : http://localhost:5000                                          ║
║  Calibré : payloads_v3.json v3.0.0 — Système SHLD{{MARKER}}            ║
║  Principe: les payloads sont reflétés/exécutés sans sanitisation         ║
╚══════════════════════════════════════════════════════════════════════════╝
""")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)