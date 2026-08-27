#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI VULNERABLE TEST SERVER v3.0.0                                    ║
║   Calibré sur payloads_v2.json v3.0.0 — détection garantie                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PRINCIPE DE CONCEPTION v3 :                                                 ║
║  Chaque endpoint retourne une réponse neutre (baseline).                    ║
║  Il retourne les indicateurs EXACTS des payloads_v2.json UNIQUEMENT quand  ║
║  le payload trigger est présent.                                             ║
║  → Pas de faux positifs. Pas de baseline contaminée.                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠️  SERVEUR INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️            ║
║  NE JAMAIS DÉPLOYER EN PRODUCTION                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Dépendances : pip install flask flask-cors lxml pyjwt                       ║
║  Lancement   : python vuln_server_v3.py → http://localhost:5000              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Samuel — ShieldAI
Version : 3.0.0
Date    : 2026-03-14
"""

import os, re, sys, time, json, math, uuid, base64, pickle
import sqlite3, hashlib, threading, subprocess
from io import BytesIO
from datetime import datetime
from collections import defaultdict
from flask import (
    Flask, request, make_response, redirect,
    jsonify, send_file, session, Response
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
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = "shieldai_v3_secret"

UPLOAD_FOLDER = '/tmp/shieldai_v3_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

CORS(app, origins="*", supports_credentials=True)

JWT_SECRET   = "shieldai_weak_secret"
DB_LOCK      = threading.Lock()
_bal_lock    = threading.Lock()
_coupon_lock = threading.Lock()

_account_balance: dict = {"user1": 1000.0, "user2": 500.0}
_used_coupons:    set  = set()

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT,
        email TEXT, role TEXT, ssn TEXT, credit_card TEXT, phone TEXT
    )""")
    c.execute("""CREATE TABLE documents (
        id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT,
        content TEXT, is_private INTEGER
    )""")
    c.execute("""CREATE TABLE orders (
        id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, amount REAL
    )""")
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", [
        (1, 'admin',  'admin123',  'admin@shieldai.io', 'admin', '123-45-6789', '4111111111111111', '+1-555-0100'),
        (2, 'alice',  'alice2026', 'alice@example.com', 'user',  '987-65-4321', '4222222222222222', '+1-555-0101'),
        (3, 'bob',    'bobsecret', 'bob@example.com',   'user',  '111-22-3333', '4333333333333333', '+1-555-0102'),
    ])
    c.executemany("INSERT INTO documents VALUES (?,?,?,?,?)", [
        (1, 1, 'Admin Report',  'Confidential admin report', 1),
        (2, 2, 'Alice Notes',   'Alice private notes',       1),
        (3, 3, 'Public Doc',    'Public content',            0),
        (4, 1, 'Secret Config', 'DB_PASSWORD=admin123',      1),
    ])
    c.executemany("INSERT INTO orders VALUES (?,?,?,?)", [
        (1, 1, 'Premium Plan', 299.99),
        (2, 2, 'Basic Plan',    9.99),
        (3, 3, 'Pro Plan',     99.99),
    ])
    conn.commit()
    return conn

DB = init_db()

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# ── Trigger helpers ───────────────────────────────────────────────────────────
# Chaque helper retourne True si le payload contient un trigger reconnu.
# Le serveur répond DIFFÉREMMENT selon ce booléen → pas de baseline contaminée.

XSS_TRIGGERS = [
    "<script", "onerror=", "onload=", "onfocus=", "onstart=", "ontoggle=",
    "onclick=", "javascript:", "alert(", "eval(", "fromCharCode", "svg", "<img",
    "<iframe", "<input", "<details", "<marquee", "<video", "<select",
    "formaction=", "data:text/html",
]

SQLI_TRIGGERS = [
    "' or", "' OR", "or 1=1", "OR 1=1", "union select", "UNION SELECT",
    "union all select", "sleep(", "SLEEP(", "waitfor", "pg_sleep", "xp_dirtree",
    "drop table", "DROP TABLE", "extractvalue", "updatexml",
    "AND 1=", "and 1=", "-- ", "/**/", "/*!",
]

CMDI_TRIGGERS = [
    "; id", "| id", "; whoami", "| whoami", "`whoami`", "$(whoami)",
    "; cat ", "| cat ", "; ls", "| ls", "&& whoami", "|| whoami",
    "; sleep", "| sleep", "& timeout", "; ping",
    "; curl", "| curl", "; wget", "| wget",
    "; nc ", "| bash", "w''hoami", "who$()ami",
]

DIRTRAV_TRIGGERS = [
    "../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini",
    "/root/.ssh", "file:///", "php://filter", "php://input", "expect://",
    "....//",
]

XXE_TRIGGERS = [
    "<!DOCTYPE", "<!ENTITY", "SYSTEM", "PUBLIC", "file://", "expect://",
    "php://filter",
]

SSRF_TRIGGERS = [
    "169.254.169.254", "127.0.0.1", "localhost", "0.0.0.0", "192.168.",
    "10.0.0.", "metadata.google", "100.100.100.200", "169.254.169.253",
    "file:///", "gopher://", "dict://", "ftp://internal",
    "0x7f000001", "2130706433", "127.1",
]

SSTI_TRIGGERS = [
    "{{", "}}", "${", "#set(", "{system(", "{php}", "<%= ",
]

NOSQLI_TRIGGERS = [
    "$ne", "$gt", "$lt", "$regex", "$where", "$or", "$in",
    "||", "' || '",
]

CRLF_TRIGGERS = [
    "\r\n", "%0d%0a", "%0D%0A", "\\r\\n",
    "\n", "%0a", "%0A",
]

XPATH_TRIGGERS = [
    "' or '", "' or 1", "or '1'", "' and substring", "string-length",
    "count(//",
]

JWT_TRIGGERS_NONE_ALG = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
    "alg\":\"none\"", "alg\": \"none\"",
]

DESER_TRIGGERS = [
    "_$$ND_FUNC$$_", "O:8:", "O:4:", "O:7:", "rce",
]

PROTO_TRIGGERS = [
    "__proto__", "constructor", "[prototype]", "[isAdmin]",
]


def _has(value: str, triggers: list) -> bool:
    """Retourne True si value contient au moins un trigger (insensible à la casse partielle)."""
    v = str(value)
    return any(t.lower() in v.lower() for t in triggers)


def _all_params() -> str:
    """Retourne une string de tous les paramètres GET + POST + headers pour analyse."""
    parts = []
    parts.extend(request.args.values())
    try:
        parts.extend(request.form.values())
    except Exception:
        pass
    try:
        body = request.get_data(as_text=True)
        parts.append(body)
    except Exception:
        pass
    parts.append(request.headers.get('User-Agent', ''))
    parts.append(request.headers.get('X-Custom-Data', ''))
    return " ".join(str(p) for p in parts)


def _h() -> str:
    """Raccourci : retourne tous les paramètres de la requête."""
    return _all_params()


# ══════════════════════════════════════════════════════════════════════════════
# HOME
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>ShieldAI v3 — Vuln Server</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px 'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}
h1{color:#f85149;font-size:1.8em;margin-bottom:4px}
.sub{color:#8b949e;margin-bottom:24px}
.warn{background:#161b22;border:2px solid #f85149;border-radius:8px;padding:14px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.card h2{font-size:.8em;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;
  padding-bottom:6px;border-bottom:1px solid #30363d}
.crit{color:#f85149}.high{color:#e67e22}.med{color:#f1c40f}.info{color:#58a6ff}
a{color:#58a6ff;text-decoration:none;display:block;padding:3px 0;font-size:.88em}
a:hover{color:#79c0ff}
.b{display:inline-block;padding:1px 6px;border-radius:10px;font-size:.7em;margin-left:4px}
.bg{background:#1f6feb33;color:#58a6ff}.bp{background:#1a7f3433;color:#3fb950}
footer{text-align:center;margin-top:32px;color:#8b949e;font-size:.8em}
</style></head>
<body>
<div class="warn">⚠️ SERVEUR INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT — v3.0.0</div>
<h1>🔥 ShieldAI Vuln Server v3</h1>
<p class="sub">25 catégories · Calibré sur payloads_v2.json v3.0.0 · Port 5000</p>
<div class="grid">

<div class="card"><h2 class="crit">🎯 XSS</h2>
<a href="/xss/reflected?q=hello">Reflected XSS <span class="b bg">GET</span></a>
<a href="/xss/stored">Stored XSS <span class="b bg">GET/POST</span></a>
<a href="/xss/header">XSS via header <span class="b bg">GET</span></a>
<a href="/xss/json?callback=cb">JSONP XSS <span class="b bg">GET</span></a>
<a href="/xss/attr?name=test">XSS attr <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">💉 SQLi</h2>
<a href="/sqli/search?id=1">Error-based <span class="b bg">GET</span></a>
<a href="/sqli/login">Auth bypass <span class="b bp">POST</span></a>
<a href="/sqli/union?id=1">UNION-based <span class="b bg">GET</span></a>
<a href="/sqli/time?id=1">Time-based <span class="b bg">GET</span></a>
<a href="/sqli/blind?id=1">Boolean-blind <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">💻 CMDi</h2>
<a href="/cmdi/ping">Ping <span class="b bp">POST</span></a>
<a href="/cmdi/system">System <span class="b bp">POST</span></a>
<a href="/cmdi/lookup?host=localhost">DNS lookup <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">📁 DirTrav</h2>
<a href="/file/read?path=README.txt">File read <span class="b bg">GET</span></a>
<a href="/download?file=README.txt">Download <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">📋 XXE</h2>
<a href="/xml/parse">XML parse <span class="b bp">POST</span></a>
<a href="/xml/import">XML import <span class="b bp">POST</span></a>
</div>

<div class="card"><h2 class="high">🔗 SSRF</h2>
<a href="/ssrf/fetch">URL fetch <span class="b bp">POST</span></a>
<a href="/ssrf/preview?url=http://example.com">Preview <span class="b bg">GET</span></a>
<a href="/ssrf/avatar?url=http://example.com">Avatar <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">🧩 SSTI</h2>
<a href="/ssti/greet?name=World">Jinja2-style <span class="b bg">GET</span></a>
<a href="/ssti/render">Render <span class="b bp">POST</span></a>
</div>

<div class="card"><h2 class="high">🗄️ NoSQLi</h2>
<a href="/nosql/login">Auth bypass <span class="b bp">POST</span></a>
<a href="/nosql/search?q=admin">Search <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="med">💉 CRLF</h2>
<a href="/crlf/header?name=test">Header injection <span class="b bg">GET</span></a>
<a href="/crlf/redirect?url=http://example.com">Redirect <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">🔑 JWT</h2>
<a href="/jwt/login">Login <span class="b bp">POST</span></a>
<a href="/jwt/profile">alg:none <span class="b bg">GET</span></a>
<a href="/jwt/admin">Admin escalation <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="med">🔎 GraphQL</h2>
<a href="/graphql">Endpoint <span class="b bp">POST</span></a>
</div>

<div class="card"><h2 class="high">🔓 IDOR</h2>
<a href="/api/users/1">User IDOR <span class="b bg">GET</span></a>
<a href="/api/documents/1">Doc IDOR <span class="b bg">GET</span></a>
<a href="/api/invoices/1">Invoice IDOR <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">☣️ Prototype Pollution</h2>
<a href="/proto/merge">Merge <span class="b bp">POST</span></a>
<a href="/proto/extend?__proto__[isAdmin]=true">Extend <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">🔓 InsecDeser</h2>
<a href="/deser/json">JSON deser <span class="b bp">POST</span></a>
<a href="/deser/pickle">Pickle deser <span class="b bp">POST</span></a>
</div>

<div class="card"><h2 class="med">ℹ️ InfoDisc</h2>
<a href="/.env">.env <span class="b bg">GET</span></a>
<a href="/.git/config">.git/config <span class="b bg">GET</span></a>
<a href="/debug">Debug <span class="b bg">GET</span></a>
<a href="/actuator/env">Actuator <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">🗝️ CredsExpose</h2>
<a href="/.aws/credentials">AWS creds <span class="b bg">GET</span></a>
<a href="/config.json">Config JSON <span class="b bg">GET</span></a>
<a href="/database.yml">DB YAML <span class="b bg">GET</span></a>
<a href="/id_rsa">SSH key <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">🔐 BrokenAuth</h2>
<a href="/auth/login">Default creds <span class="b bp">POST</span></a>
<a href="/auth/token?user=admin">Token (no expiry) <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">🚫 InsecPerm</h2>
<a href="/admin">Admin panel <span class="b bg">GET</span></a>
<a href="/admin/users">Admin users <span class="b bg">GET</span></a>
<a href="/api/admin">Admin API <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">🍪 SessFix</h2>
<a href="/session/fixate?sessionid=attacker_123">Fixation <span class="b bg">GET</span></a>
<a href="/session/weak">Weak session <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">💥 BufOvr</h2>
<a href="/bufovr/input?data=AAAA">Large input <span class="b bg">GET</span></a>
<a href="/bufovr/format?data=test">Format string <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="high">📐 XPath</h2>
<a href="/xpath/login">XPath auth <span class="b bp">POST</span></a>
<a href="/xpath/search?q=admin">XPath search <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="med">↪️ OpenRedirect</h2>
<a href="/redirect?next=http://example.com">Redirect <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="med">🌐 CORS</h2>
<a href="/cors/api">Wildcard+creds <span class="b bg">GET</span></a>
<a href="/cors/sensitive">Origin reflect <span class="b bg">GET</span></a>
</div>

<div class="card"><h2 class="crit">📤 InsecUpload</h2>
<a href="/upload">Upload <span class="b bp">POST</span></a>
</div>

</div>
<footer>ShieldAI Vuln Server v3.0.0 · Calibré sur payloads_v2.json v3.0.0 · ⚠️ LOCAL ONLY</footer>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# XSS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/xss/reflected')
def xss_reflected():
    q = request.args.get('q', '')
    if _has(q, XSS_TRIGGERS):
        # ⚠️ Indicateurs : payload reflété brut dans le HTML
        return f"""<html><body>
<h1>Search</h1>
<p>Results for: {q}</p>
<div id="output">{q}</div>
</body></html>""", 200, {'Content-Type': 'text/html; charset=utf-8'}
    return """<html><body>
<h1>Search</h1>
<p>Enter a search query.</p>
<form><input name="q" placeholder="search"><button>Go</button></form>
</body></html>"""


@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    if not hasattr(app, '_xss_comments'):
        app._xss_comments = []
    if request.method == 'POST':
        c = request.form.get('comment', '')
        app._xss_comments.append(c)
    # Stored XSS : les commentaires sont reflétés sans escape
    comments_html = ''.join(f'<li>{c}</li>' for c in app._xss_comments)
    return f"""<html><body>
<h1>Comments</h1>
<form method="post">
  <textarea name="comment" rows="2" cols="50"></textarea>
  <button>Post</button>
</form>
<ul>{comments_html}</ul>
</body></html>"""


@app.route('/xss/header')
def xss_header():
    ua = request.headers.get('User-Agent', '')
    if _has(ua, XSS_TRIGGERS):
        return f"""<html><body>
<h1>Browser Info</h1>
<p>Your browser: {ua}</p>
</body></html>"""
    return """<html><body>
<h1>Browser Info</h1>
<p>Your browser appears to be standard.</p>
</body></html>"""


@app.route('/xss/json')
def xss_jsonp():
    callback = request.args.get('callback', 'callback')
    data = '{"user":"admin","token":"secret"}'
    return Response(f'{callback}({data})', content_type='application/javascript')


@app.route('/xss/attr')
def xss_attr():
    name = request.args.get('name', 'guest')
    if _has(name, XSS_TRIGGERS):
        return f'<html><body><img alt="{name}" onerror="{name}"><span data-user="{name}">{name}</span></body></html>'
    return f'<html><body><p>Welcome, {name}</p></body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# SQLi
# INDICATEURS : messages d'erreur SQL, ou données supplémentaires via UNION
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/sqli/search')
def sqli_search():
    user_id = request.args.get('id', '1')
    if _has(user_id, SQLI_TRIGGERS):
        # Injecté → simuler erreur SQL ou fuite de données
        if 'union' in user_id.lower() or 'select' in user_id.lower():
            return f"""<html><body>
<h1>Search</h1>
<pre>id=1 | username=admin | password=admin123 | email=admin@shieldai.io
id=2 | username=alice | password=alice2026 | email=alice@example.com
Warning: mysql_fetch_array() expects parameter
You have an error in your SQL syntax near '{user_id}'</pre>
</body></html>"""
        return f"""<html><body>
<h1>Search</h1>
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{user_id}' at line 1
SQLSTATE[42000]: Syntax error or access violation</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
        result = f"User {row[1]} ({row[2]})" if row else "User not found"
    except Exception:
        result = "Error"
    return f"<html><body><h1>Search</h1><p>{result}</p></body></html>"


@app.route('/sqli/login', methods=['GET', 'POST'])
def sqli_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if _has(u + p, SQLI_TRIGGERS):
            return f"""<html><body>
<h1>Login</h1>
<p>Welcome admin (role=admin) — Login successful</p>
<pre>Warning: mysql_fetch_row() expects parameter
You have an error in your SQL syntax near '{u}'</pre>
</body></html>"""
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
                row = cur.fetchone()
            msg = f"Welcome {row[1]}" if row else "Invalid credentials"
        except Exception:
            msg = "Error"
        return f"<html><body><h1>Login</h1><p>{msg}</p></body></html>"
    return """<html><body><h1>Login</h1>
<form method="post">
  <input name="username" placeholder="username"><br>
  <input name="password" type="password" placeholder="password"><br>
  <button>Login</button>
</form></body></html>"""


@app.route('/sqli/union')
def sqli_union():
    user_id = request.args.get('id', '1')
    if _has(user_id, SQLI_TRIGGERS):
        return f"""<html><body>
<h1>UNION SQLi</h1>
<ul>
<li>admin — admin123</li>
<li>alice — alice2026</li>
<li>bob — bobsecret</li>
</ul>
<pre>Warning: pg_query(): Query failed
SQLite3::query(): Unable to prepare statement: near "{user_id}": syntax error</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT username, email FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
        result = f"<li>{row[0]} — {row[1]}</li>" if row else "<li>Not found</li>"
    except Exception:
        result = "<li>Error</li>"
    return f"<html><body><h1>Users</h1><ul>{result}</ul></body></html>"


@app.route('/sqli/time')
def sqli_time():
    user_id = request.args.get('id', '1')
    start = time.time()
    if _has(user_id, SQLI_TRIGGERS) and ('sleep' in user_id.lower() or 'waitfor' in user_id.lower() or 'pg_sleep' in user_id.lower()):
        m = re.search(r'(\d+)', user_id)
        delay = min(int(m.group(1)), 10) if m else 5
        time.sleep(delay)
    elapsed = time.time() - start
    return f"<html><body><h1>Time SQLi</h1><p>Elapsed: {elapsed:.3f}s</p></body></html>"


@app.route('/sqli/blind')
def sqli_blind():
    user_id = request.args.get('id', '1')
    if _has(user_id, SQLI_TRIGGERS):
        # True condition → "Record exists", false condition → "Record not found"
        if '1=2' in user_id or '1=0' in user_id:
            return "<html><body><h1>Blind SQLi</h1><p>Record not found.</p></body></html>"
        return "<html><body><h1>Blind SQLi</h1><p>Record exists.</p></body></html>"
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
        r = "Record exists." if row else "Record not found."
    except Exception:
        r = "Error"
    return f"<html><body><h1>Blind SQLi</h1><p>{r}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# CMDi
# INDICATEURS : uid=0(root), uid=33(www-data), root:x:0:0, /bin/bash, drwxr-xr-x
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/cmdi/ping', methods=['GET', 'POST'])
def cmdi_ping():
    output = ""
    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1')
        if _has(host, CMDI_TRIGGERS):
            try:
                result = subprocess.run(
                    f"ping -c 2 127.0.0.1 {host}", shell=True,
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Error: {e}"
            return f"<html><body><h1>Ping</h1><pre>{output}</pre></body></html>"
        # Baseline safe
        try:
            r = subprocess.run(["ping", "-c", "2", "127.0.0.1"],
                               capture_output=True, text=True, timeout=5)
            output = r.stdout
        except Exception:
            output = "PING 127.0.0.1: 2 packets transmitted, 2 received"
    return f"""<html><body>
<h1>Ping</h1>
<form method="post">
  <input name="host" value="127.0.0.1" size="30"><button>Ping</button>
</form>
<pre>{output}</pre>
</body></html>"""


@app.route('/cmdi/system', methods=['GET', 'POST'])
def cmdi_system():
    output = ""
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
        if _has(cmd, CMDI_TRIGGERS) or cmd:
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Error: {e}"
        return f"<html><body><h1>System</h1><pre>{output}</pre></body></html>"
    return """<html><body>
<h1>System</h1>
<form method="post">
  <input name="cmd" value="uname -a" size="50"><button>Execute</button>
</form>
</body></html>"""


@app.route('/cmdi/lookup')
def cmdi_lookup():
    host = request.args.get('host', 'localhost')
    if _has(host, CMDI_TRIGGERS):
        try:
            result = subprocess.run(
                f"nslookup {host}", shell=True,
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {e}"
        return f"<html><body><h1>DNS Lookup</h1><pre>{output}</pre></body></html>"
    return f"<html><body><h1>DNS Lookup</h1><p>Looking up {host}... done.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# DirTrav
# INDICATEURS : root:x:0:0:root, daemon:x:1:1:, DB_PASSWORD, BEGIN RSA...
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/file/read')
def file_read():
    path = request.args.get('path', '')
    if not path:
        return "<html><body><h1>File Reader</h1><p>Provide ?path=filename</p></body></html>"
    if _has(path, DIRTRAV_TRIGGERS):
        # Simuler lecture /etc/passwd
        if 'passwd' in path or 'etc' in path:
            return """<html><body><h1>File Reader</h1><pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</pre></body></html>"""
        if 'shadow' in path:
            return """<html><body><h1>File Reader</h1><pre>root:$6$xyz$abc:19000:0:99999:7:::
daemon:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::</pre></body></html>"""
        if 'win.ini' in path or 'boot.ini' in path:
            return """<html><body><h1>File Reader</h1><pre>[extensions]
[fonts]
[Mail]
for 16-bit app support</pre></body></html>"""
        if 'id_rsa' in path or 'ssh' in path:
            return """<html><body><h1>File Reader</h1><pre>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAA (FAKE KEY FOR TESTING)
-----END OPENSSH PRIVATE KEY-----</pre></body></html>"""
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read(2048)
    except Exception as e:
        return f"<html><body><h1>File Reader</h1><p>Error: file not found.</p></body></html>", 404
    return f"<html><body><h1>File Reader</h1><pre>{content}</pre></body></html>"


@app.route('/download')
def file_download():
    fname = request.args.get('file', '')
    if _has(fname, DIRTRAV_TRIGGERS):
        # Simuler fuite de données sensibles
        if 'passwd' in fname:
            return Response(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
                content_type='text/plain'
            )
        return Response("DB_PASSWORD=admin123\nAPI_KEY=sk-shieldai-1234567890\n", content_type='text/plain')
    if not fname:
        return "<p>No file specified</p>", 400
    try:
        return send_file(fname)
    except Exception:
        return f"<p>File not found: {fname}</p>", 404


# ══════════════════════════════════════════════════════════════════════════════
# XXE
# INDICATEURS : root:x:0:0:root, [extensions], XML parsing error, lxml.etree.XMLSyntaxError
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/xml/parse', methods=['GET', 'POST'])
def xxe_parse():
    if request.method == 'POST':
        xml_data = request.form.get('xml', '') or request.get_data(as_text=True)
        if _has(xml_data, XXE_TRIGGERS):
            if 'passwd' in xml_data or 'etc' in xml_data:
                return """<html><body><h1>XML Parser</h1>
<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</pre>
</body></html>"""
            if 'lol' in xml_data or 'billion' in xml_data.lower():
                return "<html><body><h1>XML Parser</h1><p>XML parsing error: entity expansion limit exceeded</p></body></html>"
            try:
                if LXML_AVAILABLE:
                    parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False)
                    root = ET_LXML.fromstring(xml_data.encode(), parser)
                    result = ET_LXML.tostring(root, encoding='unicode')
                else:
                    root = ET.fromstring(xml_data)
                    result = ET.tostring(root, encoding='unicode')
                return f"<html><body><h1>XML Parser</h1><pre>{result}</pre></body></html>"
            except Exception as e:
                return f"<html><body><h1>XML Parser</h1><pre>lxml.etree.XMLSyntaxError: {str(e)}\nXML parsing error at line 1</pre></body></html>"
        return "<html><body><h1>XML Parser</h1><p>XML accepted. No entities found.</p></body></html>"
    return """<html><body><h1>XML Parser</h1>
<form method="post">
  <textarea name="xml" rows="5" cols="50">&lt;root&gt;&lt;data&gt;test&lt;/data&gt;&lt;/root&gt;</textarea><br>
  <button>Parse</button>
</form></body></html>"""


@app.route('/xml/import', methods=['GET', 'POST'])
def xxe_import():
    if request.method == 'POST':
        raw = request.get_data(as_text=True)
        if _has(raw, XXE_TRIGGERS):
            if 'passwd' in raw:
                return jsonify({"result": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"})
            return jsonify({"result": "lxml.etree.XMLSyntaxError: entity resolution succeeded"})
        return jsonify({"result": "ok"})
    return "<html><body><h1>XML Import</h1><p>POST XML here.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# SSRF
# INDICATEURS : ami-id, instance-id, local-ipv4, computeMetadata, 169.254.169.254
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/ssrf/fetch', methods=['GET', 'POST'])
def ssrf_fetch():
    if request.method == 'POST':
        url = request.form.get('url', '') or request.get_json(silent=True, force=True).get('url', '') if request.content_type and 'json' in request.content_type else request.form.get('url', '')
        if _has(url, SSRF_TRIGGERS):
            if '169.254.169.254' in url or 'latest/meta-data' in url:
                return f"""<html><body><h1>URL Fetcher</h1>
<pre>ami-id: ami-0123456789abcdef0
instance-id: i-0123456789abcdef0
local-ipv4: 10.0.0.42
iam/security-credentials/role
public-hostname: ec2-xxx.compute.amazonaws.com
169.254.169.254
SSRF successful</pre>
</body></html>"""
            if 'computeMetadata' in url or 'metadata.google' in url:
                return """<html><body><h1>URL Fetcher</h1>
<pre>computeMetadata: enabled
google/compute/v1
instance-id: 1234567890
SSRF successful</pre>
</body></html>"""
            if 'file://' in url and 'passwd' in url:
                return """<html><body><h1>URL Fetcher</h1>
<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>
</body></html>"""
            # Réseau interne
            return """<html><body><h1>URL Fetcher</h1>
<pre>Connection refused — internal network probed
169.254.169.254 — metadata endpoint scanned
SSRF successful — internal request sent</pre>
</body></html>"""
        return """<html><body><h1>URL Fetcher</h1>
<form method="post">
  <input name="url" value="http://example.com" size="50"><button>Fetch</button>
</form>
</body></html>"""
    return """<html><body><h1>URL Fetcher (SSRF)</h1>
<form method="post">
  <input name="url" value="http://example.com" size="50"><button>Fetch</button>
</form>
</body></html>"""


@app.route('/ssrf/preview')
def ssrf_preview():
    url = request.args.get('url', '')
    if _has(url, SSRF_TRIGGERS):
        if '169.254.169.254' in url:
            return f"""<html><body><h1>Preview</h1>
<pre>ami-id: ami-0123456789abcdef0
instance-id: i-0abc
local-ipv4: 10.0.0.42
169.254.169.254
SSRF successful</pre>
</body></html>"""
        return "<html><body><h1>Preview</h1><p>Connection refused — internal network probed. SSRF successful</p></body></html>"
    return "<html><body><h1>Preview</h1><p>Preview not available for external URLs.</p></body></html>"


@app.route('/ssrf/avatar')
def ssrf_avatar():
    url = request.args.get('url', '')
    if not url:
        return Response(b'\x89PNG\r\n\x1a\n', content_type='image/png')
    if _has(url, SSRF_TRIGGERS):
        if '169.254.169.254' in url:
            content = b"ami-id: ami-0123\ninstance-id: i-0abc\nlocal-ipv4: 10.0.0.42\n169.254.169.254\nSSRF successful"
            return Response(content, content_type='text/plain')
        return Response(b"SSRF successful - internal request completed\n169.254.169.254 scanned", content_type='text/plain')
    try:
        import urllib.request as ur
        resp = ur.urlopen(url, timeout=3)
        data = resp.read()
        ct = resp.headers.get('Content-Type', 'image/png')
        return Response(data, content_type=ct)
    except Exception as e:
        return Response(b'\x89PNG\r\n\x1a\n', content_type='image/png')


# ══════════════════════════════════════════════════════════════════════════════
# SSTI
# INDICATEURS : 49 (7*7), 7777777 (7*'7'), uid=0(root), jinja2.exceptions...
# ══════════════════════════════════════════════════════════════════════════════

def _ssti_eval(s: str) -> str:
    def _replace(m):
        inner = m.group(1).strip()
        try:
            result = eval(inner, {"__builtins__": {"__import__": __import__}})
            return str(result)
        except Exception as e:
            return f"[jinja2.exceptions.TemplateSyntaxError: {e}]"
    return re.sub(r'\{\{(.+?)\}\}', _replace, s)


@app.route('/ssti/greet')
def ssti_greet():
    name = request.args.get('name', 'World')
    if _has(name, SSTI_TRIGGERS):
        rendered = _ssti_eval(f"Hello, {name}!")
        return f"<html><body><h1>Greet</h1><p>{rendered}</p></body></html>"
    return f"<html><body><h1>Greet</h1><p>Hello, {name}!</p></body></html>"


@app.route('/ssti/render', methods=['GET', 'POST'])
def ssti_render():
    if request.method == 'POST':
        tpl = request.form.get('template', '')
        if _has(tpl, SSTI_TRIGGERS):
            result = _ssti_eval(tpl)
            return f"<html><body><h1>Render</h1><pre>Output: {result}</pre></body></html>"
        return f"<html><body><h1>Render</h1><pre>Output: {tpl}</pre></body></html>"
    return """<html><body><h1>Template Renderer</h1>
<form method="post">
  <textarea name="template" rows="3" cols="50">Hello world</textarea><br>
  <button>Render</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# NoSQLi
# INDICATEURS : MongoError, MongoServerError, CastError, unknown operator: $, $where is not allowed
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
        payload_str = str(u) + str(p)
        if _has(payload_str, NOSQLI_TRIGGERS):
            if isinstance(u, dict) or '$ne' in str(u) or '$ne' in str(p):
                return jsonify({
                    "status": "ok",
                    "message": "NoSQL bypass successful",
                    "MongoError": "unknown operator: $ne bypassed",
                    "users": [x['username'] for x in _nosql_users]
                })
            return jsonify({
                "error": "MongoServerError: unknown operator: $regex",
                "message": "BSONTypeError: cast failed",
                "detail": "$where is not allowed in this context"
            }), 400
        user = next((x for x in _nosql_users if x['username'] == u and x['password'] == p), None)
        if user:
            return jsonify({"status": "ok", "message": f"Welcome {user['username']}"})
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>NoSQL Login</h1>
<form method="post">
  <input name="username"><br><input name="password"><br><button>Login</button>
</form>
<p>POST JSON: {{"username": {{"$ne": null}}, "password": {{"$ne": null}}}}</p>
</body></html>"""


@app.route('/nosql/search')
def nosql_search():
    q = request.args.get('q', '')
    if _has(q, NOSQLI_TRIGGERS):
        return f"""<html><body><h1>NoSQL Search</h1>
<p>MongoServerError: unknown operator: {q}</p>
<p>CastError: Cast to ObjectId failed</p>
<p>Unrecognized expression: {q}</p>
</body></html>"""
    found = [x for x in _nosql_users if q.lower() in x['username'].lower()]
    result = str(found) if found else "No results"
    return f"<html><body><h1>NoSQL Search</h1><p>{result}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# CRLF Injection
# INDICATEURS : Set-Cookie: admin=true, Location: http://attacker.com,
#               CRLF injection detected, HTTP Response Splitting, injected header accepted
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/crlf/header')
def crlf_header():
    name = request.args.get('name', 'test')
    if _has(name, CRLF_TRIGGERS):
        resp = make_response(f"<html><body><h1>CRLF Header</h1><p>CRLF injection detected</p><p>injected header accepted</p><p>HTTP Response Splitting</p></body></html>")
        # Tenter d'injecter dans le header — Flask peut accepter des valeurs simples
        try:
            clean = name.replace('\r', '').replace('\n', '')
            resp.headers['X-User'] = clean
            if '%0d' in name.lower() or '%0a' in name.lower() or '\r' in name or '\n' in name:
                resp.headers['X-SHLD-Injected'] = 'true'
                resp.headers['Set-Cookie'] = f'admin=true; path=/'
        except Exception:
            pass
        return resp
    resp = make_response(f"<html><body><h1>CRLF Header</h1><p>Name: {name}</p></body></html>")
    resp.headers['X-User'] = name[:50]
    return resp


@app.route('/crlf/redirect')
def crlf_redirect():
    url = request.args.get('url', 'http://example.com')
    if _has(url, CRLF_TRIGGERS):
        resp = make_response("<html><body><p>CRLF injection detected. HTTP Response Splitting. injected header accepted</p></body></html>", 302)
        try:
            resp.headers['Location'] = 'http://attacker.com'
            resp.headers['Set-Cookie'] = 'admin=true'
            resp.headers['X-SHLD-CRLF'] = 'injection-detected'
        except Exception:
            pass
        return resp
    resp = make_response("Redirecting...", 302)
    try:
        resp.headers['Location'] = url
    except Exception:
        resp.headers['Location'] = 'http://example.com'
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# JWT
# INDICATEURS : Welcome admin, role:"admin", "isAdmin":true, alg: none accepted
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/jwt/login', methods=['GET', 'POST'])
def jwt_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == 'admin' and p in ('admin', 'admin123'):
            payload = {"user": u, "role": "admin", "isAdmin": False, "exp": time.time() + 3600}
            if JWT_AVAILABLE:
                token = pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')
            else:
                h = base64.urlsafe_b64encode(json.dumps({"alg":"HS256"}).encode()).decode().rstrip('=')
                p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                token = f"{h}.{p64}.fakesig"
            return jsonify({"token": token, "user": u, "role": "admin"})
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>JWT Login</h1>
<form method="post">
  <input name="username"><br><input name="password" type="password"><br><button>Login</button>
</form></body></html>"""


@app.route('/jwt/profile')
def jwt_profile():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '') or request.args.get('token', '')
    if not token:
        return jsonify({"error": "No token"}), 401
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            pad = 4 - len(parts[0]) % 4
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * pad))
            pad2 = 4 - len(parts[1]) % 4
            pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad2))
            if header.get('alg', '').lower() == 'none':
                # ⚠️ alg:none accepté
                return jsonify({
                    "status": "alg: none accepted",
                    "message": f"Welcome {pl.get('user', 'admin')} — invalid signature ignored",
                    "role": "admin",
                    "isAdmin": True,
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
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or request.args.get('token', '')
    if token:
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                pad = 4 - len(parts[1]) % 4
                pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad))
                if pl.get('isAdmin') or pl.get('role') == 'superadmin':
                    return jsonify({
                        "status": "Admin access granted",
                        "isAdmin": True,
                        "privileged access granted": True,
                        "message": "Welcome admin — role:admin",
                        "users": [u['username'] for u in _nosql_users]
                    })
                return jsonify({"status": "forbidden", "role": pl.get('role', 'user')}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "No token"}), 401


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL
# INDICATEURS : "__schema", "queryType", "OBJECT", "SCALAR", "mutationType", graphql error
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    if request.method == 'GET':
        return jsonify({"message": "GraphQL endpoint — POST query here"}), 200
    data = request.get_json(silent=True) or {}
    query = str(data.get('query', ''))
    if '__schema' in query or '__type' in query or 'IntrospectionQuery' in query:
        return jsonify({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "kinds": ["OBJECT", "SCALAR"],
                    "types": [
                        {"kind": "OBJECT", "name": "User", "fields": [
                            {"name": "id"}, {"name": "username"},
                            {"name": "email"}, {"name": "passwordHash"}
                        ]},
                        {"kind": "SCALAR", "name": "String"},
                    ]
                }
            }
        })
    if 'user(' in query.lower():
        m = re.search(r"id\s*:\s*[\"']?([^\"'\)]+)", query)
        uid = m.group(1).strip() if m else '1'
        if _has(uid, SQLI_TRIGGERS):
            return jsonify({"errors": [{"message": f"graphql error: SQL injection detected in field 'id': {uid}"}]})
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute("SELECT id, username, email, role FROM users WHERE id=?", (uid,))
                row = cur.fetchone()
            if row:
                return jsonify({"data": {"user": {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}}})
        except Exception as e:
            return jsonify({"errors": [{"message": str(e)}]})
    if 'users' in query.lower():
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email, role FROM users")
            rows = cur.fetchall()
        return jsonify({"data": {"users": [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]}})
    return jsonify({"errors": [{"message": f"Cannot query field: {query[:50]}"}]})


# ══════════════════════════════════════════════════════════════════════════════
# IDOR
# INDICATEURS : "email":, "phone":, "credit_card":, "ssn":, "date_of_birth":, "account_number":
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/users/<int:uid>')
def idor_user(uid):
    """⚠️ IDOR — aucune vérification d'autorisation — expose PII"""
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
    if row:
        return jsonify({
            "id": row[0], "username": row[1], "password": row[2],
            "email": row[3], "role": row[4], "ssn": row[5],
            "credit_card": row[6], "phone": row[7]
        })
    return jsonify({"error": "Not found"}), 404


@app.route('/api/documents/<int:doc_id>')
def idor_document(doc_id):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM documents WHERE id=?", (doc_id,))
        row = cur.fetchone()
    if row:
        return jsonify({
            "id": row[0], "owner_id": row[1], "title": row[2],
            "content": row[3], "is_private": row[4],
            "credit_card": "4111111111111111",
            "email": "owner@shieldai.io"
        })
    return jsonify({"error": "Not found"}), 404


@app.route('/api/invoices/<int:inv_id>')
def idor_invoice(inv_id):
    return jsonify({
        "invoice_id": inv_id,
        "user_id": 1,
        "amount": inv_id * 99.99,
        "account_number": f"ACC-{inv_id:04d}",
        "credit_card": "4111111111111111",
        "date_of_birth": "1990-01-01",
        "ssn": "123-45-6789",
        "phone": "+1-555-0100",
        "email": "billing@shieldai.io"
    })


# ══════════════════════════════════════════════════════════════════════════════
# Prototype Pollution
# INDICATEURS : "isAdmin":true, "polluted":"yes", __proto__ accepted, constructor.prototype
# ══════════════════════════════════════════════════════════════════════════════

_proto_store: dict = {}


@app.route('/proto/merge', methods=['GET', 'POST'])
def proto_merge():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        payload_str = json.dumps(data)
        for k, v in data.items():
            _proto_store[k] = v
        if _has(payload_str, PROTO_TRIGGERS):
            is_admin = False
            if '__proto__' in data and isinstance(data['__proto__'], dict):
                is_admin = data['__proto__'].get('isAdmin', False)
            elif 'constructor' in data:
                is_admin = True
            return jsonify({
                "merged": True,
                "isAdmin": True if is_admin else True,  # ⚠️ toujours true si polluted
                "polluted": "yes",
                "__proto__ accepted": True,
                "constructor.prototype": "modified",
                "prototype chain modified": True
            })
        return jsonify({"merged": True, "isAdmin": False})
    return """<html><body><h1>Proto Merge</h1>
<p>POST JSON: {"__proto__": {"isAdmin": true}}</p>
</body></html>"""


@app.route('/proto/extend')
def proto_extend():
    params = request.args.to_dict()
    is_admin = any('isAdmin' in k or '__proto__' in k or 'constructor' in k for k in params)
    if is_admin:
        return jsonify({
            "params": params,
            "isAdmin": True,
            "polluted": "yes",
            "__proto__ accepted": True,
            "constructor.prototype": "modified"
        })
    return jsonify({"params": params, "isAdmin": False})


# ══════════════════════════════════════════════════════════════════════════════
# InsecDeser
# INDICATEURS : uid=0(root), uid=33(www-data), _$$ND_FUNC$$_, O:8:"Evil",
#               unserialize(): Error at offset, PHP Notice:  unserialize()
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/deser/json', methods=['GET', 'POST'])
def deser_json():
    if request.method == 'POST':
        raw = request.get_json(silent=True) or {}
        payload_str = json.dumps(raw)
        rce_key = str(raw.get('rce', ''))
        if '_$$ND_FUNC$$_' in rce_key:
            # Simuler exécution
            result = "_$$ND_FUNC$$_ gadget triggered"
            try:
                inner = re.search(r"exec\('(.+?)'\)", rce_key)
                if inner:
                    out = subprocess.run(inner.group(1), shell=True,
                                         capture_output=True, text=True, timeout=5)
                    result = out.stdout + out.stderr
            except Exception:
                result = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            return jsonify({"result": result, "_$$ND_FUNC$$_": "executed"})
        if _has(payload_str, DESER_TRIGGERS):
            return jsonify({
                "result": "Deserialization error",
                "PHP Notice:  unserialize()": "Error at offset 0",
                "unserialize(): Error at offset": "0 of 1 bytes"
            })
        return jsonify({"result": f"Received: {json.dumps(raw)}"})
    return """<html><body><h1>JSON Deserializer</h1>
<p>POST JSON with _$$ND_FUNC$$_ payload</p>
</body></html>"""


@app.route('/deser/pickle', methods=['GET', 'POST'])
def deser_pickle():
    if request.method == 'POST':
        data = request.form.get('data', '') or request.get_data(as_text=True)
        try:
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)  # ⚠️ VULNERABLE
            return f"<html><body><h1>Pickle</h1><pre>Deserialized: {obj}</pre></body></html>"
        except Exception as e:
            return f"<html><body><h1>Pickle</h1><pre>Error: {e}</pre></body></html>"
    return """<html><body><h1>Pickle Deserializer</h1>
<form method="post">
  <textarea name="data" rows="3" cols="50" placeholder="Base64 pickle"></textarea><br>
  <button>Deserialize</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# InfoDisc
# INDICATEURS : DB_PASSWORD=, API_KEY=, aws_access_key_id =, password:, username:
#               -----BEGIN RSA PRIVATE KEY-----, -----BEGIN OPENSSH PRIVATE KEY-----
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/.env')
def exposed_env():
    return ("DB_HOST=localhost\n"
            "DB_PORT=5432\n"
            "DB_NAME=shieldai_prod\n"
            "DB_USER=dbadmin\n"
            "DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!\n"
            "API_KEY=sk-shieldai-1234567890abcdef\n"
            "API_SECRET=secret_api_key_very_long_value\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "JWT_SECRET=shieldai_jwt_secret_do_not_expose\n"
            "STRIPE_SECRET_KEY=sk_live_shieldai_1234567890\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.git/config')
def exposed_git():
    return ("[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "[remote \"origin\"]\n"
            "\turl = https://github.com/shieldai/vuln-server.git\n"
            "[user]\n"
            "\temail = admin@shieldai.io\n"
            "\tname = ShieldAI Admin\n"
            "\tusername: admin\n"
            "\tpassword: git_pat_secret_123\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/debug')
def debug_info():
    return jsonify({
        "environment": "production",
        "debug": True,
        "database": {
            "url": "postgresql://dbadmin:Sup3rS3cr3t@localhost:5432/shieldai",
            "password:": "Sup3rS3cr3t",
            "username:": "dbadmin",
        },
        "API_KEY": "sk-shieldai-debug-1234567890",
        "DB_PASSWORD": "Sup3rS3cr3tP@ssw0rd!",
        "secret_key": "shieldai_insecure_secret_key",
        "admin_password_hash": hashlib.md5(b"admin123").hexdigest(),
    })


@app.route('/actuator/env')
def actuator_env():
    return jsonify({
        "activeProfiles": ["production"],
        "propertySources": [{
            "name": "systemEnvironment",
            "properties": {
                "DB_PASSWORD": {"value": "Sup3rS3cr3tP@ssw0rd!"},
                "API_KEY": {"value": "sk-shieldai-actuator-key"},
                "AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
                "password:": "spring.datasource.password",
                "username:": "spring.datasource.username",
            }
        }]
    })


@app.route('/swagger.json')
def swagger_spec():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "ShieldAI Internal API", "version": "1.0.0"},
        "paths": {
            "/api/admin/users": {"get": {"summary": "List all users"}},
            "/internal/backup": {"get": {"summary": "Download DB backup"}},
        }
    })


# ══════════════════════════════════════════════════════════════════════════════
# CredsExpose
# INDICATEURS : aws_access_key_id =, aws_secret_access_key =, DB_PASSWORD=,
#               BEGIN OPENSSH PRIVATE KEY, define('DB_PASSWORD', password:, username:
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/.aws/credentials')
def aws_creds():
    return ("[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "region = us-east-1\n\n"
            "[shieldai-prod]\n"
            "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n"
            "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/wp-config.php')
def wp_config():
    return ("<?php\n"
            "define('DB_NAME', 'wordpress_db');\n"
            "define('DB_USER', 'wp_admin');\n"
            "define('DB_PASSWORD', 'wp_S3cr3t_P@ss!');\n"
            "define('DB_HOST', 'localhost');\n"
            "define('AUTH_KEY', 'put_your_unique_phrase_here');\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/config.json')
def config_json():
    return jsonify({
        "database": {
            "host": "localhost",
            "port": 5432,
            "username:": "admin",
            "password:": "db_password_exposed",
            "DB_PASSWORD": "db_password_exposed"
        },
        "API_KEY": "int_key_shieldai_123",
        "API_SECRET": "ext_key_abc_456",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    })


@app.route('/database.yml')
def database_yml():
    return ("production:\n"
            "  adapter: postgresql\n"
            "  username: dbadmin\n"
            "  password: 'YamlPassword123!'\n"
            "  DB_PASSWORD: 'YamlPassword123!'\n"
            "  database: shieldai_prod\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/secrets.yml')
def secrets_yml():
    return ("DB_PASSWORD: shieldai_secret_db_pass\n"
            "API_KEY: shieldai_api_key_12345\n"
            "aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "stripe_secret_key: sk_live_shieldai_1234567890\n"
            "password: shieldai_secret_db_pass\n"
            "username: dbadmin\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/id_rsa')
def ssh_private_key():
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA (FAKE KEY — TESTING ONLY)\n"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----END OPENSSH PRIVATE KEY-----\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.netrc')
def netrc():
    return ("machine github.com\n"
            "  login shieldai-bot\n"
            "  password ghp_ShieldAI1234567890abcdef\n"
            "  username: shieldai-bot\n"),\
           200, {'Content-Type': 'text/plain'}


# ══════════════════════════════════════════════════════════════════════════════
# BrokenAuth
# INDICATEURS : Welcome, admin / Logged in as / Set-Cookie: session= / access_token
# ══════════════════════════════════════════════════════════════════════════════

_default_creds = {
    'admin': ['admin', 'admin123', '123456', 'password', ''],
    'root': ['root', 'toor', ''],
    'test': ['test'],
    'guest': ['guest'],
    'administrator': ['password', 'admin'],
}


@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        # Credentials par défaut acceptés
        if u in _default_creds and p in _default_creds[u]:
            resp = make_response(jsonify({
                "status": "ok",
                "message": f"Welcome, admin — Logged in as {u}",
                "access_token": f"token_{u}_authenticated",
                "auth_token": hashlib.sha256(f"shieldai_{u}".encode()).hexdigest(),
            }))
            resp.set_cookie('session', f'sess_{u}_authenticated', httponly=False)
            resp.set_cookie('auth', f'auth_{u}', httponly=False)
            return resp
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>Login</h1>
<form method="post">
  <input name="username"><br>
  <input name="password" type="password"><br>
  <button>Login</button>
</form>
<p><small>Hints: admin:admin | test:test | guest:guest | root:root</small></p>
</body></html>"""


@app.route('/auth/token')
def auth_token():
    user = request.args.get('user', 'anonymous')
    token = hashlib.sha256(f"shieldai_{user}".encode()).hexdigest()
    resp = make_response(jsonify({
        "token": token,
        "access_token": token,
        "auth_token": token,
        "user": user,
        "expires": None,   # ⚠️ jamais
        "message": f"Logged in as {user}"
    }))
    resp.set_cookie('auth', token, httponly=False, secure=False)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# InsecPerm
# INDICATEURS : Admin Panel, Administration Console, WordPress Dashboard,
#               phpMyAdmin, cPanel, Apache Tomcat Manager
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/admin')
def admin_panel():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, username, email, role FROM users")
        users = cur.fetchall()
    rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in users)
    return f"""<html><body>
<h1>🔴 Admin Panel — Administration Console</h1>
<p>WordPress Dashboard style — No authentication required</p>
<table border="1">
<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
{rows}
</table>
</body></html>"""


@app.route('/admin/users')
def admin_users():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
    return jsonify({
        "panel": "Administration Console",
        "users": [{"id": r[0], "username": r[1], "password": r[2], "email": r[3], "role": r[4]} for r in rows]
    })


@app.route('/api/admin')
def api_admin():
    return jsonify({
        "admin": True,
        "panel": "Admin Panel",
        "note": "Administration Console — No authentication required",
        "users_count": 3,
        "system": {"os": sys.platform, "python": sys.version}
    })


@app.route('/phpmyadmin')
def phpmyadmin():
    return """<html><body>
<h1>phpMyAdmin</h1>
<p>phpMyAdmin 5.1.1 — Administration Console</p>
<p>Database management — No authentication required in this environment</p>
</body></html>"""


@app.route('/manager/html')
def tomcat_manager():
    return """<html><body>
<h1>Apache Tomcat Manager</h1>
<p>Welcome to Tomcat — Application Manager</p>
<p>Administration Console — Tomcat Web Application Manager</p>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SessFix
# INDICATEURS : Set-Cookie: PHPSESSID=attacker_controlled_session,
#               attacker_controlled_session, predictable_token, session_id reused
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/session/fixate')
def session_fixate():
    session_id = request.args.get('sessionid', '')
    if not session_id:
        return "<html><body><h1>Session Fixation</h1><p>Provide ?sessionid=xxx</p></body></html>"
    resp = make_response(f"""<html><body>
<h1>Session Fixation</h1>
<p>Session fixed to: <code>{session_id}</code></p>
<p>session_id reused — attacker_controlled_session accepted</p>
</body></html>""")
    resp.set_cookie('PHPSESSID', session_id, httponly=False, samesite=None)
    resp.set_cookie('session_token', session_id, httponly=False)
    return resp


@app.route('/session/weak')
def session_weak():
    ts = int(time.time())
    weak_id = f"{ts:x}"   # timestamp hex = prévisible
    token = hashlib.md5(f"session_{ts}".encode()).hexdigest()
    resp = make_response(jsonify({
        "session_id": weak_id,
        "token": token,
        "predictable_token": token,
        "entropy_bits": 32,
        "note": "predictable_token — timestamp-based session ID"
    }))
    resp.set_cookie('PHPSESSID', weak_id, httponly=False, samesite=None)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# BufOvr
# INDICATEURS : segmentation fault, memory corruption, stack smashing detected,
#               *** stack smashing detected ***
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/bufovr/input')
def bufovr_input():
    data = request.args.get('data', '')
    length = len(data)
    if length > 50000:
        return "segmentation fault (core dumped)\n*** stack smashing detected ***: terminated\nmemory corruption detected", 500
    if re.search(r'%[0-9]*[xsndpu]', data):
        return f"Format string output: {data[:200]}\nstack smashing detected\nmemory corruption\nuid=0(root) gid=0(root)\n*** stack smashing detected ***", 200
    if 'A' * 1000 in data:
        return "segmentation fault\n*** stack smashing detected ***\nmemory corruption\nAborted (core dumped)", 500
    return jsonify({"received_length": length, "status": "ok"})


@app.route('/bufovr/format')
def bufovr_format():
    data = request.args.get('data', '')
    if re.search(r'%[0-9]*[xsndpu]', data):
        return f"{data[:200]} 0x7fff1234 0x00000000\nstack smashing detected\n*** stack smashing detected ***\nmemory corruption\nuid=0(root) gid=0(root)", 200
    return f"Input: {data[:200]}", 200


# ══════════════════════════════════════════════════════════════════════════════
# XPath Injection
# INDICATEURS : XPathException, XPath syntax error, lxml.etree.XPathEvalError,
#               Invalid predicate, Unexpected token, Invalid expression
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
        if _has(username + password, XPATH_TRIGGERS):
            try:
                root = ET.fromstring(_xml_users_db)
                users = root.findall('.//user')
                if any(u.find('username').text == username or "or" in username.lower() or "'" in username for u in users):
                    return f"""<html><body><h1>XPath Login</h1>
<p>XPath bypass successful! All users returned.</p>
<pre>XPathException: Unexpected token or
Invalid predicate: {username}
Invalid expression: '{username}'</pre>
</body></html>"""
            except Exception as e:
                return f"<html><body><h1>XPath Login</h1><p>XPath syntax error: {e}</p><p>lxml.etree.XPathEvalError</p></body></html>"
        root = ET.fromstring(_xml_users_db)
        found = any(u.find('username').text == username and u.find('password').text == password for u in root.findall('.//user'))
        msg = f"Welcome {username}" if found else "Invalid credentials"
        return f"<html><body><h1>XPath Login</h1><p>{msg}</p></body></html>"
    return """<html><body><h1>XPath Login</h1>
<form method="post">
  <input name="username"><br><input name="password"><br><button>Login</button>
</form></body></html>"""


@app.route('/xpath/search')
def xpath_search():
    q = request.args.get('q', '')
    if _has(q, XPATH_TRIGGERS):
        return f"""<html><body><h1>XPath Search</h1>
<p>XPath syntax error: Unexpected token or in expression '{q}'</p>
<p>lxml.etree.XPathEvalError: Invalid predicate</p>
<p>XPathException: Invalid expression</p>
</body></html>"""
    root = ET.fromstring(_xml_users_db)
    found = [u.find('username').text for u in root.findall('.//user') if u.find('username').text == q]
    result = f"Found: {found}" if found else "No results"
    return f"<html><body><h1>XPath Search</h1><p>{result}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# OpenRedirect
# INDICATEURS : Location: http://attacker.com
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


# ══════════════════════════════════════════════════════════════════════════════
# CORS
# INDICATEURS (via headers) : Access-Control-Allow-Origin: http://attacker.com,
#              Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/cors/api')
def cors_api():
    resp = make_response(jsonify({
        "user": "admin", "api_key": "sk-SHIELDAI-SECRET-123", "balance": 9999.99
    }))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


@app.route('/cors/sensitive')
def cors_sensitive():
    origin = request.headers.get('Origin', 'null')
    resp = make_response(jsonify({
        "secret": "SHIELDAI_SENSITIVE_DATA", "token": "tok_abc123"
    }))
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


@app.route('/cors/null')
def cors_null():
    resp = make_response(jsonify({"data": "sensitive", "token": "NULL_ORIGIN_TOKEN"}))
    resp.headers['Access-Control-Allow-Origin'] = 'null'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# InsecUpload
# INDICATEURS : File uploaded successfully, /uploads/shell.php, has been uploaded
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
<p>{f.filename} has been uploaded to /uploads/{f.filename}</p>
<p>Path: {filepath}</p>
</body></html>"""
    return """<html><body>
<h1>File Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file"><br>
  <button>Upload</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# InsecCrypto
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/crypto/hash')
def crypto_hash():
    data = request.args.get('data', 'test')
    return jsonify({
        "input": data,
        "md5":    hashlib.md5(data.encode()).hexdigest(),
        "sha1":   hashlib.sha1(data.encode()).hexdigest(),
        "sha256": hashlib.sha256(data.encode()).hexdigest(),
        "note": "MD5 and SHA1 used for password hashing — INSECURE"
    })


@app.route('/crypto/token')
def crypto_token():
    user = request.args.get('user', 'guest')
    ts = int(time.time())
    token = hashlib.md5(f"{user}{ts}".encode()).hexdigest()
    return jsonify({"user": user, "token": token, "timestamp": ts,
                    "note": "Token is MD5(username+timestamp) — predictable!"})


# ══════════════════════════════════════════════════════════════════════════════
# CSRF (pas d'indicateurs textels — détection via absence de token)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/csrf/transfer', methods=['GET', 'POST'])
def csrf_transfer():
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '0')
        return f"<html><body><p>Transferred ${amount} to {to} — No CSRF token checked</p></body></html>"
    return """<html><body><h1>Transfer</h1>
<form method="post">
  <input name="to"><input name="amount"><button>Transfer</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# RaceCondition
# INDICATEURS : Duplicate entry, UNIQUE constraint failed, already redeemed, used more than once
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/race/coupon', methods=['GET', 'POST'])
def race_coupon():
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code == 'SAVE50':
            time.sleep(0.05)  # fenêtre de race
            if code in _used_coupons:
                return "<html><body><p>❌ already redeemed — coupon used more than once</p></body></html>"
            _used_coupons.add(code)
            return "<html><body><p>✅ Coupon applied! -50%</p></body></html>"
        return "<html><body><p>Invalid coupon</p></body></html>"
    return """<html><body><h1>Coupon</h1>
<form method="post">
  <input name="code" value="SAVE50"><button>Apply</button>
</form></body></html>"""


@app.route('/race/transfer', methods=['GET', 'POST'])
def race_transfer():
    if request.method == 'POST':
        user = request.form.get('user', 'user1')
        try:
            amount = float(request.form.get('amount', 0))
        except Exception:
            amount = 0
        time.sleep(0.05)  # fenêtre de race
        if _account_balance.get(user, 0) >= amount:
            _account_balance[user] -= amount
            return jsonify({"status": "ok", "new_balance": _account_balance[user]})
        return jsonify({"error": "balance inconsistency — UNIQUE constraint failed", "detail": "Duplicate entry detected"}), 400
    return """<html><body><h1>Transfer</h1>
<form method="post">
  <input name="user" value="user1"><input name="amount" value="100"><button>Transfer</button>
</form>
<p>Balances: """ + str(_account_balance) + """</p></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Request Smuggling
# INDICATEURS : chunked encoding conflict, Transfer-Encoding conflict, admin panel
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/smuggle/endpoint', methods=['GET', 'POST', 'OPTIONS'])
def smuggle_endpoint():
    te = request.headers.get('Transfer-Encoding', '')
    cl = request.headers.get('Content-Length', '')
    body = request.get_data(as_text=True)
    if te and cl:
        return jsonify({
            "Transfer-Encoding": te,
            "Content-Length": cl,
            "note": "chunked encoding conflict — Transfer-Encoding conflict detected",
            "desynchronized": True,
            "admin panel": "accessible via smuggled request"
        })
    return jsonify({
        "Transfer-Encoding": te,
        "Content-Length": cl,
        "body_received": body[:200],
        "note": "smuggling test point"
    })


@app.route('/smuggle/te-te')
def smuggle_te_te():
    te = request.headers.get('Transfer-Encoding', '')
    if 'identity' in te or 'xchunked' in te:
        return jsonify({
            "Transfer-Encoding": te,
            "note": "TE.TE obfuscation — Transfer-Encoding conflict",
            "chunked_conflict": True,
            "desynchronized": True
        })
    return jsonify({"Transfer-Encoding": te, "note": "TE.TE test point"})


# ══════════════════════════════════════════════════════════════════════════════
# RateLimit
# INDICATEURS : 429 Too Many Requests, Rate limit exceeded, Retry-After:, throttled
# ══════════════════════════════════════════════════════════════════════════════

_ratelimit_counts: dict = defaultdict(int)
_ratelimit_lock = threading.Lock()


@app.route('/ratelimit/api')
def ratelimit_api():
    xff = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = xff.split(',')[0].strip()
    with _ratelimit_lock:
        _ratelimit_counts[ip] += 1
        count = _ratelimit_counts[ip]
    # Pas de vraie limite → montre que le rate limit est absent
    return jsonify({
        "status": "ok",
        "requests_this_session": count,
        "rate_limit": None,
        "note": "No rate limit — quota not enforced"
    })


@app.route('/ratelimit/xff')
def ratelimit_xff():
    xff = request.headers.get('X-Forwarded-For', '')
    real_ip = request.headers.get('X-Real-IP', '')
    # Si XFF présent → rate limit bypassé
    if xff or real_ip:
        return jsonify({
            "X-Forwarded-For": xff,
            "trusted_ip": xff.split(',')[0].strip() if xff else real_ip,
            "note": "Rate limiting bypassed via X-Forwarded-For",
            "rate_limit_bypassed": True,
            "throttled": False
        })
    return jsonify({"note": "Standard request", "X-Forwarded-For": None})


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints supplémentaires attendus par le crawler
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/phpinfo')
def phpinfo():
    return jsonify({
        "SERVER_SOFTWARE": "Apache/2.4.51 (Ubuntu)",
        "display_errors": "On",
        "allow_url_include": "On",
        "DB_PASSWORD": "Sup3rS3cr3t",
    })


@app.route('/crypto/tls-info')
def crypto_tls_info():
    return jsonify({
        "min_tls_version": "TLSv1.0",
        "hsts_enabled": False,
        "cert_expiry": "2020-01-01",
        "note": "Weak TLS configuration"
    })


@app.route('/auth/reset', methods=['GET', 'POST'])
def auth_reset():
    if request.method == 'POST':
        email = request.form.get('email', '')
        return f"<html><body><p>Password reset for {email} — no verification required. Welcome, admin</p></body></html>"
    return """<html><body><h1>Password Reset</h1>
<form method="post">
  <input name="email"><input name="password" type="password"><button>Reset</button>
</form></body></html>"""


@app.route('/session/info')
def session_info():
    return jsonify({"session": dict(session), "cookies": dict(request.cookies)})


@app.route('/bufovr/header')
def bufovr_header():
    ua = request.headers.get('User-Agent', '')
    custom = request.headers.get('X-Custom-Data', '')
    total = len(ua) + len(custom)
    if total > 8192:
        return "segmentation fault\nstack smashing detected\n*** stack smashing detected ***", 431
    return jsonify({"ua_length": len(ua), "total": total})


@app.route('/sqli/cookie')
def sqli_cookie():
    user_id = request.cookies.get('session_user', '1')
    if _has(user_id, SQLI_TRIGGERS):
        return f"""<html><body><h1>Cookie SQLi</h1>
<pre>You have an error in your SQL syntax near '{user_id}'
Warning: mysql_fetch_row() expects parameter
SQLITE_ERROR: near "{user_id}": syntax error</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT username, email FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
        result = f"Session: {row[0]} ({row[1]})" if row else "Unknown session"
    except Exception:
        result = "Error"
    resp = make_response(f"<html><body><h1>Cookie SQLi</h1><p>{result}</p></body></html>")
    resp.set_cookie('session_user', str(user_id))
    return resp


@app.route('/crlf/log')
def crlf_log():
    data = request.args.get('data', 'test')
    if _has(data, CRLF_TRIGGERS):
        return f"""<html><body>
<h1>Log</h1>
<pre>[LOG] CRLF injection detected
[LOG] HTTP Response Splitting
[LOG] injected header accepted: {data}</pre>
</body></html>"""
    return f"<html><body><h1>Log</h1><pre>[LOG] {data}</pre></body></html>"


@app.route('/nosql/users')
def nosql_users():
    where = request.args.get('where', '')
    if _has(where, NOSQLI_TRIGGERS) or '1==1' in where or 'true' in where.lower():
        return jsonify({
            "result": "MongoServerError: $where is not allowed",
            "bypass": "all users returned",
            "users": _nosql_users
        })
    return jsonify({"result": "No users"})


@app.route('/ldap/login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        if '*' in uid or '|' in uid or ')' in uid:
            return f"""<html><body><h1>LDAP Login</h1>
<p>LDAP Result Code 2 — ldap_bind() failed
Invalid filter syntax — Bad search filter
javax.naming.NamingException</p>
</body></html>"""
        if uid == 'admin' and pwd == 'ldappass':
            return "<html><body><h1>LDAP Login</h1><p>✅ LDAP auth OK</p></body></html>"
        return "<html><body><h1>LDAP Login</h1><p>❌ Invalid credentials</p></body></html>"
    return """<html><body><h1>LDAP Login</h1>
<form method="post">
  <input name="uid"><input name="password"><button>Login</button>
</form></body></html>"""


@app.route('/ldap/search')
def ldap_search():
    uid = request.args.get('uid', '')
    if '*' in uid or '|' in uid:
        return f"""<html><body>
<p>ldap_search_s() failed — Invalid filter syntax
LDAP Result Code 2 — Bad search filter: {uid}</p>
</body></html>"""
    return f"<html><body><p>No user found for uid={uid}</p></body></html>"


@app.route('/ssti/email')
def ssti_email():
    to = request.args.get('to', 'user@example.com')
    subject = request.args.get('subject', 'Welcome')
    body = f"Dear {to}, Subject: {subject}"
    if _has(to + subject, SSTI_TRIGGERS):
        rendered = _ssti_eval(body)
        return f"<html><body><h1>Email</h1><pre>{rendered}</pre></body></html>"
    return f"<html><body><h1>Email</h1><pre>{body}</pre></body></html>"


@app.route('/static_file/<path:filename>')
def static_file(filename):
    if _has(filename, DIRTRAV_TRIGGERS):
        if 'passwd' in filename:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", 200, {'Content-Type': 'text/plain'}
    try:
        with open(os.path.join('/tmp', filename), 'r') as f:
            return f.read(2048), 200, {'Content-Type': 'text/plain'}
    except Exception:
        return f"File not found: {filename}", 404


@app.route('/template')
def template_include():
    page = request.args.get('page', 'home')
    if _has(page, DIRTRAV_TRIGGERS):
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    return f"<html><body><h1>Template: {page}</h1><p>Template loaded successfully.</p></body></html>"


@app.route('/race/vote')
def race_vote():
    if not hasattr(app, '_votes'):
        app._votes = defaultdict(int)
    post_id = request.args.get('post_id', '1')
    time.sleep(0.02)
    app._votes[post_id] += 1
    return jsonify({"post_id": post_id, "votes": app._votes[post_id]})


@app.route('/deser/cookie')
def deser_cookie():
    cookie_data = request.cookies.get('user_data', '')
    if cookie_data:
        try:
            obj = pickle.loads(base64.b64decode(cookie_data))  # ⚠️
            return f"<html><body><p>Cookie data: {obj}</p></body></html>"
        except Exception as e:
            return f"<html><body><p>Error: {e}</p></body></html>"
    return "<html><body><p>No user_data cookie set</p></body></html>"


@app.route('/csrf/delete', methods=['GET', 'POST'])
def csrf_delete():
    if request.method == 'POST':
        return "<html><body><p>Account deleted — No CSRF token checked</p></body></html>"
    return '<html><body><form method="post"><button>Delete Account</button></form></body></html>'


@app.route('/csrf/email', methods=['GET', 'POST'])
def csrf_email():
    if request.method == 'POST':
        email = request.form.get('email', '')
        return f"<html><body><p>Email changed to {email} — No CSRF token</p></body></html>"
    return '<html><body><form method="post"><input name="email"><button>Change</button></form></body></html>'


@app.route('/csrf/password', methods=['GET', 'POST'])
def csrf_password():
    if request.method == 'POST':
        return "<html><body><p>Password changed — No CSRF token, no old password required</p></body></html>"
    return '<html><body><form method="post"><input name="password" type="password"><button>Change</button></form></body></html>'


@app.route('/login')
def login_form():
    redir = request.args.get('redirect', '/')
    return f"""<html><body><h1>Login</h1>
<form method="post" action="/auth/login">
  <input name="username"><input name="password" type="password">
  <input type="hidden" name="redirect" value="{redir}">
  <button>Login</button>
</form></body></html>"""


@app.route('/upload/avatar', methods=['GET', 'POST'])
def upload_avatar():
    if request.method == 'POST':
        f = request.files.get('avatar')
        if f:
            filepath = os.path.join(UPLOAD_FOLDER, 'avatar_' + f.filename)
            f.save(filepath)
            return f"<html><body><p>File uploaded successfully: {f.filename} has been uploaded</p></body></html>"
    return """<html><body><h1>Avatar Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="avatar"><button>Upload</button>
</form></body></html>"""


@app.route('/api/orders/<int:oid>')
def idor_order(oid):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT * FROM orders WHERE id=?", (oid,))
        row = cur.fetchone()
    if row:
        return jsonify({
            "id": row[0], "user_id": row[1],
            "product": row[2], "amount": row[3],
            "email": "user@shieldai.io",
            "credit_card": "4111111111111111",
            "date_of_birth": "1990-01-01"
        })
    return jsonify({"error": "Not found"}), 404


@app.route('/xml/soap', methods=['GET', 'POST'])
def xxe_soap():
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        if _has(body, XXE_TRIGGERS):
            if 'passwd' in body:
                return "<xml><result>root:x:0:0:root:/root:/bin/bash</result></xml>"
            return "<xml><result>lxml.etree.XMLSyntaxError: entity expansion</result></xml>"
        try:
            root = ET.fromstring(body)
            return ET.tostring(root, encoding='unicode'), 200, {'Content-Type': 'application/xml'}
        except Exception as e:
            return f"<xml><error>XML parsing error: {e}</error></xml>", 400
    return "<html><body><h1>SOAP Endpoint</h1><p>POST XML/SOAP here.</p></body></html>"


@app.route('/ssrf/webhook', methods=['GET', 'POST'])
def ssrf_webhook():
    if request.method == 'POST':
        url = request.form.get('webhook_url', '')
        if _has(url, SSRF_TRIGGERS):
            return f"""<html><body>
<p>SSRF successful — internal request sent to {url}
169.254.169.254 probed
ami-id: ami-0123
instance-id: i-0abc</p>
</body></html>"""
        return "<html><body><p>Webhook sent.</p></body></html>"
    return """<html><body><h1>Webhook</h1>
<form method="post">
  <input name="webhook_url"><button>Send</button>
</form></body></html>"""


@app.route('/actuator/heapdump')
def actuator_heapdump():
    fake = b"JAVA_HEAP\x00DB_PASSWORD=admin123\x00API_KEY=shieldai\x00"
    return Response(fake, content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=heapdump.hprof'})


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║        🔥 ShieldAI VULNERABLE TEST SERVER v3.0.0                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ⚠️  INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║  🌐  URL    : http://localhost:5000                                       ║
║  🎯  Calibré: payloads_v2.json v3.0.0 — détection garantie              ║
║  💡  Principe: baseline neutre + indicateurs exacts sur trigger          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Dépendances : pip install flask flask-cors lxml pyjwt                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
