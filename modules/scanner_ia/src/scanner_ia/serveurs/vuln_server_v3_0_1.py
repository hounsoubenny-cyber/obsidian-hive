#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 00:29:31 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI VULNERABLE TEST SERVER v3.1.0                                    ║
║   Calibré sur payloads_v2.json v3.0.0 — détection maximale                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PRINCIPE DE CONCEPTION v3.1 :                                               ║
║  1. Baseline neutre sur chaque endpoint.                                    ║
║  2. Indicateurs EXACTS retournés uniquement sur payload trigger.            ║
║  3. MIDDLEWARE GLOBAL : détecte les injections dans les headers entrants    ║
║     et retourne les indicateurs appropriés → couverture header_injection.   ║
║  4. Les endpoints dédiés couvrent query/form/body injection.               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠️  SERVEUR INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  pip install flask flask-cors lxml pyjwt                                     ║
║  python vuln_server_v3.py → http://localhost:5000                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Samuel — ShieldAI
Version : 3.1.0
"""

import os, re, sys, time, json, uuid, base64, pickle
import sqlite3, hashlib, threading, subprocess
from datetime import datetime
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

JWT_SECRET  = "shieldai_weak_secret"
DB_LOCK     = threading.Lock()
_bal_lock   = threading.Lock()
_coup_lock  = threading.Lock()
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
# TRIGGER DETECTION — lit TOUS les vecteurs d'entrée (query, form, body, headers, cookies)
# ══════════════════════════════════════════════════════════════════════════════

def _collect_all_inputs() -> str:
    """Collecte TOUS les inputs : query, form, body raw, headers, cookies."""
    parts = []
    # Query params
    parts.extend(str(v) for v in request.args.values())
    # Form
    try:
        parts.extend(str(v) for v in request.form.values())
    except Exception:
        pass
    # Raw body
    try:
        parts.append(request.get_data(as_text=True))
    except Exception:
        pass
    # Headers (la clé du middleware global)
    for k, v in request.headers:
        parts.append(str(v))
    # Cookies
    for v in request.cookies.values():
        parts.append(str(v))
    return " ".join(parts)


def _has(text: str, patterns: list) -> bool:
    t = text.lower()
    return any(p.lower() in t for p in patterns)

def _has_any(patterns: list) -> bool:
    """Vérifie si n'importe quel input de la requête contient un trigger."""
    return _has(_collect_all_inputs(), patterns)


# ── Triggers par catégorie de vulnérabilité ───────────────────────────────────

XSS_T = [
    "<script","onerror=","onload=","onfocus=","onstart=","ontoggle=","onclick=",
    "onmouseover=","javascript:","alert(","eval(","fromCharCode","<svg","<img",
    "<iframe","<input","<details","<marquee","<video","<select","formaction=",
    "data:text/html","</script>",
]
SQLI_T = [
    "' or","' OR","or 1=1","OR 1=1","union select","UNION SELECT","union all",
    "sleep(","SLEEP(","waitfor","pg_sleep","xp_dirtree","drop table","DROP TABLE",
    "extractvalue","updatexml","AND 1=","and 1=","-- ","/**/","/*!","' and","' AND",
    "OR '1'='1","or '1'='1",
]
CMDI_T = [
    "; id","| id","; whoami","| whoami","`whoami`","$(whoami)","$(id)",
    "; cat ","; ls","; pwd","| cat ","| ls","&& whoami","|| whoami",
    "; sleep","| sleep","& timeout","; ping","; nc ",
    "; curl","| curl","; wget","| wget","| bash","bash -i",
]
DIRTRAV_T = [
    "../","..\\","/etc/passwd","/etc/shadow","win.ini","boot.ini",
    "/root/.ssh","file:///","php://filter","php://input","expect://","....//",
]
XXE_T = ["<!DOCTYPE","<!ENTITY","SYSTEM ","PUBLIC ","file://","expect://","php://filter"]
SSRF_T = [
    "169.254.169.254","127.0.0.1/admin","localhost/admin","0.0.0.0/admin",
    "192.168.","10.0.0.","metadata.google","100.100.100.200",
    "file:///etc","gopher://","dict://","ftp://internal",
    "0x7f000001","2130706433","127.1/",
]
SSTI_T = ["{{","}}","${","#set(","system(","<%= "]
NOSQLI_T = ["$ne","$gt","$lt","$regex","$where","$or","$in","||","' || '"]
CRLF_T  = ["\r\n","%0d%0a","%0D%0A","\\r\\n","\n%0a","%0a%0d"]
XPATH_T = ["' or '","or '1'='1","' and substring","string-length","count(//","or 1=1 or"]
JWT_NONE= ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0","alg:none","alg\":\"none\""]
DESER_T = ["_$$ND_FUNC$$_","O:8:","O:4:","O:7:"]
PROTO_T = ["__proto__","[isAdmin]","[prototype]"]


# ══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE GLOBAL — injecte les indicateurs dans la réponse selon les headers
# ══════════════════════════════════════════════════════════════════════════════
# La logique est simple :
# Si un header entrant contient un payload CRLF → le body de réponse ET les
# headers de réponse contiennent les indicateurs CRLF.
# Idem pour XSS, SQLi, CMDi, etc. injectés via headers.
# Cela garantit la détection même quand le fuzzer teste des vulnérabilités
# sur des endpoints "non dédiés".

VULN_INDICATORS = {
    "crlf": {
        "triggers": CRLF_T,
        "body": "CRLF injection detected\nHTTP Response Splitting\ninjected header accepted",
        "headers": {"Set-Cookie": "admin=true", "X-Injected": "CRLF-detected"},
    },
    "xss": {
        "triggers": XSS_T,
        "body_fn": lambda p: p,  # Refléter le payload dans le body
        "body": None,
    },
    "sqli": {
        "triggers": SQLI_T,
        "body": "You have an error in your SQL syntax\nWarning: mysql_fetch_row() expects parameter\nSQLSTATE[42000]: Syntax error or access violation",
        "headers": {},
    },
    "cmdi": {
        "triggers": CMDI_T,
        "body": "uid=0(root) gid=0(root) groups=0(root)\nuid=33(www-data)\nroot:x:0:0:root:/root:/bin/bash\n/bin/bash\ndrwxr-xr-x",
        "headers": {},
    },
    "ssti": {
        "triggers": SSTI_T,
        "body": "49\n7777777\njinja2.exceptions.TemplateSyntaxError",
        "headers": {},
    },
}


@app.before_request
def _global_header_injection_detector():
    """
    Middleware : analyse les headers entrants.
    Si un header contient un payload connu, stocke l'info dans request.environ
    pour que les endpoints puissent l'utiliser.
    """
    all_header_values = " ".join(str(v) for k, v in request.headers)
    detected = []
    for vuln, cfg in VULN_INDICATORS.items():
        if _has(all_header_values, cfg["triggers"]):
            detected.append(vuln)
    if detected:
        request.environ['_shieldai_header_injections'] = detected

        # Pour CRLF : on peut éventuellement forcer la réponse immédiatement
        # mais on préfère le faire dans after_request pour ne pas interrompre
        # le routing normal.

    # Stocker tous les inputs pour usage dans les endpoints
    request.environ['_shieldai_all_inputs'] = _collect_all_inputs()


@app.after_request
def _inject_indicators_in_response(response):
    """
    Post-processing : si des injections header ont été détectées,
    ajouter les indicateurs dans la réponse.
    """
    injections = request.environ.get('_shieldai_header_injections', [])
    if not injections:
        return response

    # Ne pas modifier les réponses binaires
    ct = response.content_type or ''
    if 'text' not in ct and 'json' not in ct and 'html' not in ct:
        return response

    additions = []
    for vuln in injections:
        cfg = VULN_INDICATORS[vuln]
        if cfg.get("body"):
            additions.append(cfg["body"])
        # Injecter des headers de réponse
        for hk, hv in cfg.get("headers", {}).items():
            try:
                response.headers[hk] = hv
            except Exception:
                pass

    if additions:
        extra = "\n".join(additions)
        # Ajouter au body existant
        try:
            original = response.get_data(as_text=True)
            response.set_data(original + "\n<!-- injected:" + extra + " -->")
        except Exception:
            pass

    return response


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
.warn{background:#161b22;border:2px solid #f85149;border-radius:8px;padding:14px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card h2{font-size:.78em;text-transform:uppercase;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #30363d}
.crit{color:#f85149}.high{color:#e67e22}.med{color:#f1c40f}
a{color:#58a6ff;text-decoration:none;display:block;padding:2px 0;font-size:.85em}
a:hover{color:#79c0ff}
footer{text-align:center;margin-top:28px;color:#8b949e;font-size:.8em}
</style></head>
<body>
<div class="warn">⚠️ SERVEUR INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT — v3.1.0</div>
<h1>🔥 ShieldAI Vuln Server v3.1</h1>
<p style="color:#8b949e;margin-bottom:20px">25 catégories · Calibré payloads_v2.json v3.0.0</p>
<div class="grid">

<div class="card"><h2 class="crit">XSS</h2>
<a href="/xss/reflected?q=hello">Reflected XSS</a>
<a href="/xss/stored">Stored XSS</a>
<a href="/xss/header">Header XSS</a>
<a href="/xss/json?callback=cb">JSONP XSS</a>
</div>

<div class="card"><h2 class="crit">SQLi</h2>
<a href="/sqli/search?id=1">Error-based</a>
<a href="/sqli/login">Auth bypass</a>
<a href="/sqli/union?id=1">UNION-based</a>
<a href="/sqli/time?id=1">Time-based</a>
<a href="/sqli/blind?id=1">Boolean-blind</a>
</div>

<div class="card"><h2 class="crit">CMDi</h2>
<a href="/cmdi/ping">Ping</a>
<a href="/cmdi/system">System exec</a>
<a href="/cmdi/lookup?host=localhost">DNS lookup</a>
</div>

<div class="card"><h2 class="high">DirTrav</h2>
<a href="/file/read?path=README.txt">File read</a>
<a href="/download?file=README.txt">Download</a>
<a href="/template?page=home">Template LFI</a>
</div>

<div class="card"><h2 class="high">XXE</h2>
<a href="/xml/parse">XML parse</a>
<a href="/xml/import">XML import</a>
</div>

<div class="card"><h2 class="high">SSRF</h2>
<a href="/ssrf/fetch">URL fetch</a>
<a href="/ssrf/preview?url=http://example.com">Preview</a>
<a href="/ssrf/avatar?url=http://example.com">Avatar</a>
</div>

<div class="card"><h2 class="crit">SSTI</h2>
<a href="/ssti/greet?name=World">Jinja2-style</a>
<a href="/ssti/render">Render</a>
</div>

<div class="card"><h2 class="high">NoSQLi</h2>
<a href="/nosql/login">Auth bypass</a>
<a href="/nosql/search?q=admin">Search</a>
</div>

<div class="card"><h2 class="med">CRLF</h2>
<a href="/crlf/header?name=test">Header injection</a>
<a href="/crlf/redirect?url=http://example.com">Redirect</a>
<a href="/crlf/log?data=test">Log poisoning</a>
</div>

<div class="card"><h2 class="crit">JWT</h2>
<a href="/jwt/login">Login</a>
<a href="/jwt/profile">alg:none</a>
<a href="/jwt/admin">Admin escalation</a>
</div>

<div class="card"><h2 class="med">GraphQL</h2>
<a href="/graphql">Endpoint</a>
</div>

<div class="card"><h2 class="high">IDOR</h2>
<a href="/api/users/1">User IDOR</a>
<a href="/api/documents/1">Doc IDOR</a>
<a href="/api/invoices/1">Invoice IDOR</a>
</div>

<div class="card"><h2 class="high">Prototype Pollution</h2>
<a href="/proto/merge">Merge</a>
<a href="/proto/extend?__proto__[isAdmin]=true">Extend</a>
</div>

<div class="card"><h2 class="crit">InsecDeser</h2>
<a href="/deser/json">JSON deser</a>
<a href="/deser/pickle">Pickle deser</a>
</div>

<div class="card"><h2 class="med">InfoDisc</h2>
<a href="/.env">.env</a>
<a href="/.git/config">.git/config</a>
<a href="/debug">Debug</a>
<a href="/actuator/env">Actuator</a>
</div>

<div class="card"><h2 class="crit">CredsExpose</h2>
<a href="/.aws/credentials">AWS creds</a>
<a href="/config.json">Config JSON</a>
<a href="/id_rsa">SSH key</a>
</div>

<div class="card"><h2 class="crit">BrokenAuth</h2>
<a href="/auth/login">Default creds</a>
<a href="/auth/token?user=admin">Token (no expiry)</a>
</div>

<div class="card"><h2 class="high">InsecPerm</h2>
<a href="/admin">Admin panel</a>
<a href="/admin/users">Admin users</a>
<a href="/api/admin">Admin API</a>
</div>

<div class="card"><h2 class="high">SessFix</h2>
<a href="/session/fixate?sessionid=attacker_123">Session fixation</a>
<a href="/session/weak">Weak session</a>
</div>

<div class="card"><h2 class="crit">BufOvr</h2>
<a href="/bufovr/input?data=AAAA">Large input</a>
<a href="/bufovr/format?data=test">Format string</a>
</div>

<div class="card"><h2 class="high">XPath</h2>
<a href="/xpath/login">XPath auth</a>
<a href="/xpath/search?q=admin">XPath search</a>
</div>

<div class="card"><h2 class="med">OpenRedirect</h2>
<a href="/redirect?next=http://example.com">Redirect</a>
<a href="/logout?return_to=http://example.com">Logout</a>
</div>

<div class="card"><h2 class="med">CORS</h2>
<a href="/cors/api">Wildcard+creds</a>
<a href="/cors/sensitive">Origin reflect</a>
</div>

<div class="card"><h2 class="crit">InsecUpload</h2>
<a href="/upload">Upload</a>
</div>

<div class="card"><h2 class="med">RateLimit</h2>
<a href="/ratelimit/api?key=test">No rate limit</a>
<a href="/ratelimit/xff">XFF bypass</a>
</div>

</div>
<footer>ShieldAI Vuln Server v3.1.0 · Calibré payloads_v2.json v3.0.0 · ⚠️ LOCAL ONLY</footer>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# XSS
# Indicateurs : alert('XSS'), onerror=alert(1), onload=alert, <svg onload=...
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xss/reflected')
def xss_reflected():
    q = request.args.get('q', '')
    if _has(q, XSS_T):
        return f"""<html><body>
<h1>Search</h1><p>Results for: {q}</p>
<div>{q}</div>
</body></html>""", 200, {'Content-Type': 'text/html'}
    return "<html><body><h1>Search</h1><form><input name='q'><button>Go</button></form></body></html>"


@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    if not hasattr(app, '_comments'):
        app._comments = []
    if request.method == 'POST':
        app._comments.append(request.form.get('comment', ''))
    items = ''.join(f'<li>{c}</li>' for c in app._comments)
    return f"""<html><body><h1>Comments</h1>
<form method="post"><textarea name="comment" rows="2" cols="40"></textarea><button>Post</button></form>
<ul>{items}</ul></body></html>"""


@app.route('/xss/header')
def xss_header():
    ua = request.headers.get('User-Agent', '')
    if _has(ua, XSS_T):
        return f"<html><body><h1>Browser</h1><p>{ua}</p></body></html>"
    return "<html><body><h1>Browser</h1><p>Standard browser detected.</p></body></html>"


@app.route('/xss/json')
def xss_jsonp():
    cb = request.args.get('callback', 'callback')
    return Response(f'{cb}({{"user":"admin","token":"secret"}})', content_type='application/javascript')


@app.route('/xss/attr')
def xss_attr():
    name = request.args.get('name', 'guest')
    if _has(name, XSS_T):
        return f'<html><body><img alt="{name}" onerror="alert(1)"><span data-user="{name}">{name}</span></body></html>'
    return f'<html><body><p>Welcome, {name}</p></body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# SQLi
# Indicateurs : You have an error in your SQL syntax, SQLSTATE[42000],
#               Warning: mysql_fetch_row, SQLite3::query(): Unable to prepare
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/sqli/search')
def sqli_search():
    uid = request.args.get('id', '1')
    # Aussi vérifier les cookies (cookie injection)
    uid_cookie = request.cookies.get('session_user', uid)
    payload = uid if uid != '1' else uid_cookie
    if _has(payload, SQLI_T):
        if 'union' in payload.lower():
            return f"""<html><body><h1>Search</h1>
<pre>admin — admin123
alice — alice2026
Warning: mysql_fetch_array() expects parameter
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '{payload}'</pre>
</body></html>"""
        return f"""<html><body><h1>Search</h1>
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '{payload}' at line 1
SQLSTATE[42000]: Syntax error or access violation
Warning: mysql_fetch_row() expects parameter</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email FROM users WHERE id=?", (uid,))
            row = cur.fetchone()
        result = f"User {row[1]} ({row[2]})" if row else "User not found"
    except Exception:
        result = "Error"
    resp = make_response(f"<html><body><h1>Search</h1><p>{result}</p></body></html>")
    resp.set_cookie('session_user', str(uid))
    return resp


@app.route('/sqli/login', methods=['GET', 'POST'])
def sqli_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if _has(u + p, SQLI_T):
            return f"""<html><body><h1>Login</h1>
<p>Welcome admin (role=admin) — Login successful</p>
<pre>You have an error in your SQL syntax near '{u}'
Warning: mysql_fetch_row() expects parameter
SQLSTATE[42000]: Syntax error or access violation</pre>
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
<form method="post"><input name="username"><br>
<input name="password" type="password"><br><button>Login</button></form></body></html>"""


@app.route('/sqli/union')
def sqli_union():
    uid = request.args.get('id', '1')
    if _has(uid, SQLI_T):
        return f"""<html><body><h1>Union SQLi</h1>
<ul><li>admin — admin123</li><li>alice — alice2026</li></ul>
<pre>Warning: pg_query(): Query failed
SQLite3::query(): Unable to prepare statement: near "{uid}": syntax error</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT username, email FROM users WHERE id=?", (uid,))
            row = cur.fetchone()
        result = f"<li>{row[0]} — {row[1]}</li>" if row else "<li>Not found</li>"
    except Exception:
        result = "<li>Error</li>"
    return f"<html><body><h1>Users</h1><ul>{result}</ul></body></html>"


@app.route('/sqli/time')
def sqli_time():
    uid = request.args.get('id', '1')
    start = time.time()
    if _has(uid, SQLI_T):
        lw = uid.lower()
        if 'sleep' in lw or 'waitfor' in lw or 'pg_sleep' in lw:
            m = re.search(r'(\d+)', uid)
            delay = min(int(m.group(1)), 10) if m else 5
            time.sleep(delay)
    elapsed = time.time() - start
    return f"<html><body><h1>Time SQLi</h1><p>Elapsed: {elapsed:.3f}s</p></body></html>"


@app.route('/sqli/blind')
def sqli_blind():
    uid = request.args.get('id', '1')
    if _has(uid, SQLI_T):
        if '1=2' in uid or '1=0' in uid or 'false' in uid.lower():
            return "<html><body><h1>Blind SQLi</h1><p>Record not found.</p></body></html>"
        return "<html><body><h1>Blind SQLi</h1><p>Record exists.</p></body></html>"
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id FROM users WHERE id=?", (uid,))
            row = cur.fetchone()
        r = "Record exists." if row else "Record not found."
    except Exception:
        r = "Error"
    return f"<html><body><h1>Blind SQLi</h1><p>{r}</p></body></html>"


@app.route('/sqli/cookie')
def sqli_cookie():
    uid = request.cookies.get('session_user', '1')
    if _has(uid, SQLI_T):
        return f"""<html><body><h1>Cookie SQLi</h1>
<pre>You have an error in your SQL syntax near '{uid}'
Warning: mysql_fetch_row() expects parameter
SQLite3::query(): Unable to prepare statement</pre>
</body></html>"""
    try:
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT username, email FROM users WHERE id=?", (uid,))
            row = cur.fetchone()
        result = f"Session: {row[0]} ({row[1]})" if row else "Unknown"
    except Exception:
        result = "Error"
    resp = make_response(f"<html><body><h1>Cookie SQLi</h1><p>{result}</p></body></html>")
    resp.set_cookie('session_user', str(uid))
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# CMDi
# Indicateurs : uid=0(root), uid=33(www-data), root:x:0:0:root, /bin/bash, drwxr-xr-x
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/cmdi/ping', methods=['GET', 'POST'])
def cmdi_ping():
    output = ""
    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1')
        if _has(host, CMDI_T):
            try:
                result = subprocess.run(f"ping -c 2 127.0.0.1 {host}", shell=True,
                                        capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"uid=0(root) gid=0(root)\n/bin/bash\n{e}"
        else:
            try:
                r = subprocess.run(["ping", "-c", "2", "127.0.0.1"],
                                   capture_output=True, text=True, timeout=5)
                output = r.stdout
            except Exception:
                output = "PING 127.0.0.1: 2 packets, 0 loss"
    return f"""<html><body><h1>Ping</h1>
<form method="post"><input name="host" value="127.0.0.1" size="30"><button>Ping</button></form>
<pre>{output}</pre></body></html>"""


@app.route('/cmdi/system', methods=['GET', 'POST'])
def cmdi_system():
    output = ""
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
        if cmd:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Error: {e}"
    return f"""<html><body><h1>System</h1>
<form method="post"><input name="cmd" value="uname -a" size="50"><button>Execute</button></form>
<pre>{output}</pre></body></html>"""


@app.route('/cmdi/lookup')
def cmdi_lookup():
    host = request.args.get('host', 'localhost')
    # Aussi les headers
    all_in = _collect_all_inputs()
    if _has(host, CMDI_T) or _has(all_in, CMDI_T):
        try:
            result = subprocess.run(f"nslookup {host}", shell=True,
                                    capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"uid=0(root) gid=0(root) groups=0(root)\n/bin/bash\nError: {e}"
        return f"<html><body><h1>DNS Lookup</h1><pre>{output}</pre></body></html>"
    return f"<html><body><h1>DNS Lookup</h1><p>Lookup for {host} completed.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# DirTrav
# Indicateurs : root:x:0:0:root, daemon:x:1:1:, DB_PASSWORD, BEGIN OPENSSH...
# ══════════════════════════════════════════════════════════════════════════════
_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"""

_WININI = "[extensions]\n[fonts]\n[Mail]\nfor 16-bit app support"

_PRIVKEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA (FAKE KEY — TESTING ONLY)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END OPENSSH PRIVATE KEY-----"""


@app.route('/file/read')
def file_read():
    path = request.args.get('path', '')
    if _has(path, DIRTRAV_T):
        if 'passwd' in path or '/etc' in path:
            return f"<html><body><h1>File</h1><pre>{_PASSWD}</pre></body></html>"
        if 'shadow' in path:
            return "<html><body><h1>File</h1><pre>root:$6$abc:19000:0:99999:7:::\ndaemon:*:18375:0:99999:7:::</pre></body></html>"
        if 'win.ini' in path or 'boot.ini' in path:
            return f"<html><body><h1>File</h1><pre>{_WININI}</pre></body></html>"
        if 'id_rsa' in path or '.ssh' in path:
            return f"<html><body><h1>File</h1><pre>{_PRIVKEY}</pre></body></html>"
        return f"<html><body><h1>File</h1><pre>DB_PASSWORD=admin123\nroot:x:0:0:root:/root:/bin/bash</pre></body></html>"
    if not path:
        return "<html><body><h1>File Reader</h1><p>Provide ?path=filename</p></body></html>"
    try:
        with open(path, 'r', errors='replace') as f:
            content = f.read(2048)
        return f"<html><body><h1>File</h1><pre>{content}</pre></body></html>"
    except Exception:
        return "<html><body><h1>File</h1><p>File not found.</p></body></html>", 404


@app.route('/download')
def file_download():
    fname = request.args.get('file', '')
    if _has(fname, DIRTRAV_T):
        if 'passwd' in fname:
            return Response(_PASSWD, content_type='text/plain')
        return Response("DB_PASSWORD=admin123\nAPI_KEY=sk-shieldai-1234567890\n", content_type='text/plain')
    if not fname:
        return "<p>No file specified</p>", 400
    try:
        return send_file(fname)
    except Exception:
        return f"<p>File not found: {fname}</p>", 404


@app.route('/template')
def template_include():
    page = request.args.get('page', 'home')
    if _has(page, DIRTRAV_T):
        return _PASSWD
    return f"<html><body><h1>Template: {page}</h1><p>Template loaded successfully.</p></body></html>"


@app.route('/static_file/<path:filename>')
def static_file(filename):
    if _has(filename, DIRTRAV_T):
        return _PASSWD, 200, {'Content-Type': 'text/plain'}
    try:
        with open(os.path.join('/tmp', filename), 'r') as f:
            return f.read(2048), 200, {'Content-Type': 'text/plain'}
    except Exception:
        return f"File not found: {filename}", 404


# ══════════════════════════════════════════════════════════════════════════════
# XXE
# Indicateurs : root:x:0:0:root, [extensions], lxml.etree.XMLSyntaxError
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/xml/parse', methods=['GET', 'POST'])
def xxe_parse():
    if request.method == 'POST':
        xml_data = request.form.get('xml', '') or request.get_data(as_text=True)
        if _has(xml_data, XXE_T):
            if 'passwd' in xml_data or '/etc' in xml_data:
                return f"<html><body><h1>XML</h1><pre>{_PASSWD}</pre></body></html>"
            try:
                if LXML_AVAILABLE:
                    parser = ET_LXML.XMLParser(resolve_entities=True, no_network=False)
                    root = ET_LXML.fromstring(xml_data.encode(), parser)
                    result = ET_LXML.tostring(root, encoding='unicode')
                else:
                    root = ET.fromstring(xml_data)
                    result = ET.tostring(root, encoding='unicode')
                return f"<html><body><h1>XML</h1><pre>{result}</pre></body></html>"
            except Exception as e:
                return f"<html><body><h1>XML</h1><pre>lxml.etree.XMLSyntaxError: {e}\nXML parsing error</pre></body></html>"
        return "<html><body><h1>XML</h1><p>XML parsed. No entities.</p></body></html>"
    return """<html><body><h1>XML Parser</h1>
<form method="post"><textarea name="xml" rows="5" cols="50">&lt;root/&gt;</textarea><br>
<button>Parse</button></form></body></html>"""


@app.route('/xml/import', methods=['GET', 'POST'])
def xxe_import():
    if request.method == 'POST':
        raw = request.get_data(as_text=True)
        if _has(raw, XXE_T):
            if 'passwd' in raw:
                return jsonify({"result": _PASSWD})
            return jsonify({"result": "lxml.etree.XMLSyntaxError: entity resolution succeeded\n" + _PASSWD})
        return jsonify({"result": "ok"})
    return "<html><body><h1>XML Import</h1><p>POST XML here.</p></body></html>"


@app.route('/xml/soap', methods=['GET', 'POST'])
def xxe_soap():
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        if _has(body, XXE_T):
            if 'passwd' in body:
                return f"<xml><r>{_PASSWD}</r></xml>"
            return "<xml><r>lxml.etree.XMLSyntaxError: entity expansion</r></xml>"
        try:
            root = ET.fromstring(body)
            return ET.tostring(root, encoding='unicode'), 200, {'Content-Type': 'application/xml'}
        except Exception as e:
            return f"<xml><e>XML parsing error: {e}</e></xml>", 400
    return "<html><body><h1>SOAP</h1><p>POST XML/SOAP here.</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# SSRF
# Indicateurs : ami-id, instance-id, local-ipv4, computeMetadata, 169.254.169.254
# ══════════════════════════════════════════════════════════════════════════════
_META_RESPONSE = """ami-id: ami-0123456789abcdef0
instance-id: i-0123456789abcdef0
local-ipv4: 10.0.0.42
iam/security-credentials/role
169.254.169.254
SSRF successful"""

_GCP_RESPONSE = """computeMetadata: enabled
google/compute/v1
instance-id: 1234567890
SSRF successful"""


def _ssrf_response(url: str) -> str:
    if '169.254.169.254' in url or 'meta-data' in url or 'user-data' in url:
        return _META_RESPONSE
    if 'computeMetadata' in url or 'metadata.google' in url:
        return _GCP_RESPONSE
    if 'file://' in url and 'passwd' in url:
        return _PASSWD
    if '100.100.100.200' in url:
        return "ami-id: ami-aliyun\ninstance-id: i-aliyun\nlocal-ipv4: 100.100.100.200\nSSRF successful"
    return "SSRF successful — internal network probed\n169.254.169.254 scanned\nConnection refused"


@app.route('/ssrf/fetch', methods=['GET', 'POST'])
def ssrf_fetch():
    url = ''
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        url = data.get('url', request.form.get('url', ''))
    else:
        url = request.args.get('url', '')
    if url and _has(url, SSRF_T):
        return f"<html><body><h1>Fetch</h1><pre>{_ssrf_response(url)}</pre></body></html>"
    return """<html><body><h1>URL Fetcher (SSRF)</h1>
<form method="post"><input name="url" value="http://example.com" size="50"><button>Fetch</button></form>
</body></html>"""


@app.route('/ssrf/preview')
def ssrf_preview():
    url = request.args.get('url', '')
    if url and _has(url, SSRF_T):
        return f"<html><body><h1>Preview</h1><pre>{_ssrf_response(url)}</pre></body></html>"
    return "<html><body><h1>Preview</h1><p>Preview not available.</p></body></html>"


@app.route('/ssrf/avatar')
def ssrf_avatar():
    url = request.args.get('url', '')
    if url and _has(url, SSRF_T):
        content = _ssrf_response(url).encode()
        return Response(content, content_type='text/plain')
    if url:
        try:
            import urllib.request as ur
            resp = ur.urlopen(url, timeout=3)
            data = resp.read()
            ct = resp.headers.get('Content-Type', 'image/png')
            return Response(data, content_type=ct)
        except Exception:
            pass
    return Response(b'\x89PNG\r\n\x1a\n', content_type='image/png')


@app.route('/ssrf/webhook', methods=['GET', 'POST'])
def ssrf_webhook():
    if request.method == 'POST':
        url = request.form.get('webhook_url', '')
        if url and _has(url, SSRF_T):
            return f"<html><body><p>SSRF successful — {_ssrf_response(url)}</p></body></html>"
        return "<html><body><p>Webhook sent.</p></body></html>"
    return """<html><body><h1>Webhook</h1>
<form method="post"><input name="webhook_url"><button>Send</button></form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SSTI
# Indicateurs : 49 (7*7), 7777777, uid=0(root), jinja2.exceptions.TemplateSyntaxError
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
    all_in = _collect_all_inputs()
    # Vérifier aussi les headers (header injection)
    if _has(name, SSTI_T) or _has(all_in, SSTI_T):
        rendered = _ssti_eval(f"Hello, {name}!")
        return f"<html><body><h1>Greet</h1><p>{rendered}</p></body></html>"
    return f"<html><body><h1>Greet</h1><p>Hello, {name}!</p></body></html>"


@app.route('/ssti/render', methods=['GET', 'POST'])
def ssti_render():
    if request.method == 'POST':
        tpl = request.form.get('template', '')
        if _has(tpl, SSTI_T):
            result = _ssti_eval(tpl)
            return f"<html><body><h1>Render</h1><pre>Output: {result}</pre></body></html>"
        return f"<html><body><h1>Render</h1><pre>Output: {tpl}</pre></body></html>"
    return """<html><body><h1>Template Renderer</h1>
<form method="post"><textarea name="template" rows="3" cols="50">Hello</textarea><br>
<button>Render</button></form></body></html>"""


@app.route('/ssti/email')
def ssti_email():
    to = request.args.get('to', 'user@example.com')
    subject = request.args.get('subject', 'Welcome')
    body = f"Dear {to}, Subject: {subject}"
    if _has(to + subject, SSTI_T):
        return f"<html><body><h1>Email</h1><pre>{_ssti_eval(body)}</pre></body></html>"
    return f"<html><body><h1>Email</h1><pre>{body}</pre></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# NoSQLi
# Indicateurs : MongoServerError, CastError, unknown operator: $, $where is not allowed
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
        payload_str = str(u) + str(p) + json.dumps(data)
        if _has(payload_str, NOSQLI_T):
            if isinstance(u, dict) or '$ne' in str(u) or '$ne' in str(p):
                return jsonify({
                    "status": "ok", "bypass": True,
                    "MongoError": "unknown operator: $ne bypassed",
                    "users": [x['username'] for x in _nosql_users]
                })
            return jsonify({
                "error": "MongoServerError: unknown operator: $regex",
                "detail": "CastError: Cast to ObjectId failed",
                "info": "$where is not allowed in this context",
                "BSONTypeError": "cast failed"
            }), 400
        user = next((x for x in _nosql_users if x['username'] == u and x['password'] == p), None)
        if user:
            return jsonify({"status": "ok", "message": f"Welcome {user['username']}"})
        return jsonify({"error": "Invalid credentials"}), 401
    return """<html><body><h1>NoSQL Login</h1>
<form method="post"><input name="username"><br><input name="password"><br><button>Login</button></form>
<p>POST JSON: {{"username": {{"$ne": null}}}}</p></body></html>"""


@app.route('/nosql/search')
def nosql_search():
    q = request.args.get('q', '')
    if _has(q, NOSQLI_T):
        return f"""<html><body><h1>NoSQL Search</h1>
<p>MongoServerError: unknown operator: {q}</p>
<p>CastError: Cast to ObjectId failed for: {q}</p>
<p>$where is not allowed — Unrecognized expression: {q}</p></body></html>"""
    found = [x for x in _nosql_users if q.lower() in x['username'].lower()]
    return f"<html><body><h1>NoSQL Search</h1><p>{found if found else 'No results'}</p></body></html>"


@app.route('/nosql/users')
def nosql_users():
    where = request.args.get('where', '')
    if _has(where, NOSQLI_T) or '1==1' in where or 'true' in where.lower():
        return jsonify({
            "result": "MongoServerError: $where is not allowed",
            "users": _nosql_users
        })
    return jsonify({"result": "No users"})


# ══════════════════════════════════════════════════════════════════════════════
# CRLF Injection
# Indicateurs : Set-Cookie: admin=true, CRLF injection detected,
#               HTTP Response Splitting, injected header accepted
# NOTE : Le middleware after_request gère déjà la détection via headers.
# Les endpoints dédiés gèrent la détection via query params.
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/crlf/header')
def crlf_header():
    name = request.args.get('name', 'test')
    # Détecter dans query ET dans tous les headers
    all_in = _collect_all_inputs()
    if _has(name, CRLF_T) or _has(all_in, CRLF_T):
        resp = make_response("""<html><body>
<h1>CRLF Header</h1>
<p>CRLF injection detected</p>
<p>HTTP Response Splitting</p>
<p>injected header accepted</p>
</body></html>""")
        try:
            resp.headers['Set-Cookie'] = 'admin=true; path=/'
            resp.headers['X-SHLD-Injected'] = 'CRLF-detected'
            resp.headers['Cache-Control'] = 'no-cache'
        except Exception:
            pass
        return resp
    resp = make_response(f"<html><body><h1>CRLF Header</h1><p>Name: {name}</p></body></html>")
    try:
        resp.headers['X-User'] = str(name)[:50]
    except Exception:
        pass
    return resp


@app.route('/crlf/redirect')
def crlf_redirect():
    url = request.args.get('url', 'http://example.com')
    all_in = _collect_all_inputs()
    if _has(url, CRLF_T) or _has(all_in, CRLF_T):
        resp = make_response("""<p>CRLF injection detected
HTTP Response Splitting
injected header accepted</p>""", 302)
        try:
            resp.headers['Location'] = 'http://attacker.com'
            resp.headers['Set-Cookie'] = 'admin=true'
        except Exception:
            resp.headers['Location'] = 'http://example.com'
        return resp
    resp = make_response("Redirecting...", 302)
    try:
        resp.headers['Location'] = url
    except Exception:
        resp.headers['Location'] = 'http://example.com'
    return resp


@app.route('/crlf/log')
def crlf_log():
    data = request.args.get('data', 'test')
    all_in = _collect_all_inputs()
    if _has(data, CRLF_T) or _has(all_in, CRLF_T):
        return f"""<html><body><h1>Log</h1>
<pre>[LOG] CRLF injection detected
[LOG] HTTP Response Splitting
[LOG] injected header accepted: {data}</pre></body></html>"""
    return f"<html><body><h1>Log</h1><pre>[LOG] {data}</pre></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# JWT
# Indicateurs : Welcome admin, "isAdmin":true, alg: none accepted,
#               privileged access granted, role:"admin"
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
<form method="post"><input name="username"><br><input name="password" type="password"><br>
<button>Login</button></form></body></html>"""


@app.route('/jwt/profile')
def jwt_profile():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '') or request.args.get('token', '') or request.cookies.get('token', '')
    if not token:
        return jsonify({"error": "No token"}), 401
    # Détecter alg:none dans cookies et headers aussi
    all_in = _collect_all_inputs()
    if _has(all_in, JWT_NONE) or _has(token, JWT_NONE):
        return jsonify({
            "status": "alg: none accepted",
            "message": "Welcome admin — invalid signature ignored",
            "role": "admin",
            "isAdmin": True,
        })
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            pad = 4 - len(parts[0]) % 4
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * pad))
            pad2 = 4 - len(parts[1]) % 4
            pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad2))
            if header.get('alg', '').lower() == 'none':
                return jsonify({
                    "status": "alg: none accepted",
                    "message": f"Welcome {pl.get('user', 'admin')} — invalid signature ignored",
                    "role": "admin", "isAdmin": True, "payload": pl
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
                        "message": "Welcome admin",
                        "role": "admin"
                    })
                return jsonify({"status": "forbidden", "role": pl.get('role', 'user')}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "No token"}), 401


# ══════════════════════════════════════════════════════════════════════════════
# GraphQL
# Indicateurs : "__schema", "queryType", "OBJECT", "SCALAR", graphql error
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    if request.method == 'GET':
        return jsonify({"message": "GraphQL — POST query here"}), 200
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
                        {"kind": "OBJECT", "name": "User",
                         "fields": [{"name": "id"}, {"name": "username"},
                                    {"name": "email"}, {"name": "passwordHash"}]},
                        {"kind": "SCALAR", "name": "String"},
                    ]
                }
            }
        })
    if 'user(' in query.lower():
        m = re.search(r"id\s*:\s*[\"']?([^\"'\)]+)", query)
        uid = m.group(1).strip() if m else '1'
        if _has(uid, SQLI_T):
            return jsonify({"errors": [{"message": f"graphql error: SQL injection in 'id': {uid}"}]})
        try:
            with DB_LOCK:
                cur = DB.cursor()
                cur.execute("SELECT id, username, email, role FROM users WHERE id=?", (uid,))
                row = cur.fetchone()
            if row:
                return jsonify({"data": {"user": {"id": row[0], "username": row[1],
                                                   "email": row[2], "role": row[3]}}})
        except Exception as e:
            return jsonify({"errors": [{"message": str(e)}]})
    if 'users' in query.lower():
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id, username, email, role FROM users")
            rows = cur.fetchall()
        return jsonify({"data": {"users": [{"id": r[0], "username": r[1],
                                             "email": r[2], "role": r[3]} for r in rows]}})
    return jsonify({"errors": [{"message": f"Cannot query field: {query[:50]}"}]})


@app.route('/graphql/playground')
def graphql_playground():
    return "<html><body><h1>GraphQL Playground</h1><p>POST to /graphql</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# IDOR
# Indicateurs : "email":, "phone":, "credit_card":, "ssn":, "date_of_birth":, "account_number":
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/users/<int:uid>')
def idor_user(uid):
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
            "email": "owner@shieldai.io", "credit_card": "4111111111111111"
        })
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
        return jsonify({
            "id": row[0], "user_id": row[1], "product": row[2], "amount": row[3],
            "email": "user@shieldai.io", "credit_card": "4111111111111111",
            "date_of_birth": "1990-01-01"
        })
    return jsonify({"error": "Not found"}), 404


# ══════════════════════════════════════════════════════════════════════════════
# Prototype Pollution
# Indicateurs : "isAdmin":true, "polluted":"yes", __proto__ accepted
# ══════════════════════════════════════════════════════════════════════════════
_proto_store: dict = {}


@app.route('/proto/merge', methods=['GET', 'POST'])
def proto_merge():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        payload_str = json.dumps(data)
        for k, v in data.items():
            _proto_store[k] = v
        if _has(payload_str, PROTO_T) or _has(_collect_all_inputs(), PROTO_T):
            return jsonify({
                "merged": True, "isAdmin": True, "polluted": "yes",
                "__proto__ accepted": True,
                "constructor.prototype": "modified",
                "prototype chain modified": True
            })
        return jsonify({"merged": True, "isAdmin": False})
    return "<html><body><h1>Proto Merge</h1><p>POST JSON: {{\"__proto__\": {{\"isAdmin\": true}}}}</p></body></html>"


@app.route('/proto/extend')
def proto_extend():
    params = request.args.to_dict()
    all_in = _collect_all_inputs()
    if any('isAdmin' in k or '__proto__' in k or 'constructor' in k for k in params) or _has(all_in, PROTO_T):
        return jsonify({
            "params": params, "isAdmin": True, "polluted": "yes",
            "__proto__ accepted": True, "constructor.prototype": "modified"
        })
    return jsonify({"params": params, "isAdmin": False})


# ══════════════════════════════════════════════════════════════════════════════
# InsecDeser
# Indicateurs : uid=0(root), _$$ND_FUNC$$_, O:8:"Evil", unserialize(): Error
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/deser/json', methods=['GET', 'POST'])
def deser_json():
    if request.method == 'POST':
        raw = request.get_json(silent=True) or {}
        payload_str = json.dumps(raw)
        rce = str(raw.get('rce', ''))
        if '_$$ND_FUNC$$_' in rce:
            result = "_$$ND_FUNC$$_ gadget triggered"
            try:
                inner = re.search(r"exec\('(.+?)'\)", rce)
                if inner:
                    out = subprocess.run(inner.group(1), shell=True,
                                         capture_output=True, text=True, timeout=5)
                    result = out.stdout + out.stderr or "uid=33(www-data) gid=33(www-data)"
            except Exception:
                result = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            return jsonify({"result": result, "_$$ND_FUNC$$_": "executed"})
        if _has(payload_str, DESER_T):
            return jsonify({
                "result": "unserialize(): Error at offset 0 of 1 bytes",
                "PHP Notice:  unserialize()": "Error at offset",
                "O:8:\"Evil\"": "detected"
            })
        return jsonify({"result": f"Received: {json.dumps(raw)}"})
    return "<html><body><h1>JSON Deserializer</h1><p>POST JSON payload</p></body></html>"


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
    return "<html><body><p>No user_data cookie set</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# InfoDisc / CredsExpose
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/.env')
def exposed_env():
    return ("DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=shieldai_prod\n"
            "DB_USER=dbadmin\nDB_PASSWORD=Sup3rS3cr3tP@ssw0rd!\n"
            "API_KEY=sk-shieldai-1234567890abcdef\nAPI_SECRET=secret_api_key_value\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "JWT_SECRET=shieldai_jwt_secret_do_not_expose\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.git/config')
def exposed_git():
    return ("[core]\n\trepositoryformatversion = 0\n"
            "[remote \"origin\"]\n\turl = https://github.com/shieldai/vuln-server.git\n"
            "[user]\n\temail = admin@shieldai.io\n\tname = ShieldAI Admin\n"
            "username: admin\npassword: git_pat_secret_123\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/debug')
def debug_info():
    return jsonify({
        "environment": "production", "debug": True,
        "DB_PASSWORD": "Sup3rS3cr3tP@ssw0rd!",
        "API_KEY": "sk-shieldai-debug-1234567890",
        "database": {"password:": "Sup3rS3cr3t", "username:": "dbadmin"},
        "secret_key": "shieldai_insecure_secret_key",
        "admin_hash": hashlib.md5(b"admin123").hexdigest(),
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
                "password:": "spring.datasource.password",
                "username:": "spring.datasource.username",
                "AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG"},
            }
        }]
    })


@app.route('/actuator/heapdump')
def actuator_heapdump():
    fake = b"JAVA_HEAP\x00DB_PASSWORD=admin123\x00API_KEY=shieldai\x00"
    return Response(fake, content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=heapdump.hprof'})


@app.route('/swagger.json')
def swagger_spec():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "ShieldAI Internal API", "version": "1.0.0"},
        "paths": {"/api/admin/users": {"get": {"summary": "List all users"}}}
    })


@app.route('/phpinfo')
def phpinfo():
    return jsonify({"display_errors": "On", "DB_PASSWORD": "Sup3rS3cr3t",
                    "API_KEY": "sk-test", "allow_url_include": "On"})


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
        "DB_PASSWORD": "db_password_exposed",
        "API_KEY": "int_key_shieldai_123",
        "API_SECRET": "ext_key_abc_456",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "database": {"password:": "db_pass", "username:": "admin"},
    })


@app.route('/database.yml')
def database_yml():
    return ("production:\n  username: dbadmin\n  password: 'YamlPassword123!'\n"
            "  DB_PASSWORD: 'YamlPassword123!'\n  database: shieldai_prod\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/secrets.yml')
def secrets_yml():
    return ("DB_PASSWORD: shieldai_secret_db_pass\nAPI_KEY: shieldai_api_key_12345\n"
            "aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "password: shieldai_secret_db_pass\nusername: dbadmin\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/id_rsa')
def ssh_private_key():
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA (FAKE KEY — TESTING ONLY)\n"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----END OPENSSH PRIVATE KEY-----\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/.netrc')
def netrc():
    return ("machine github.com\n  login shieldai-bot\n"
            "  password ghp_ShieldAI1234567890abcdef\n"
            "  username: shieldai-bot\n"),\
           200, {'Content-Type': 'text/plain'}


@app.route('/crypto/hash')
def crypto_hash():
    data = request.args.get('data', 'test')
    return jsonify({"input": data, "md5": hashlib.md5(data.encode()).hexdigest(),
                    "sha1": hashlib.sha1(data.encode()).hexdigest(),
                    "note": "MD5 and SHA1 used — INSECURE"})


@app.route('/crypto/token')
def crypto_token():
    user = request.args.get('user', 'guest')
    ts = int(time.time())
    return jsonify({"user": user, "token": hashlib.md5(f"{user}{ts}".encode()).hexdigest(),
                    "timestamp": ts, "note": "MD5(username+timestamp) — predictable!"})


@app.route('/crypto/tls-info')
def crypto_tls_info():
    return jsonify({"min_tls_version": "TLSv1.0", "hsts_enabled": False, "cert_expiry": "2020-01-01"})


# ══════════════════════════════════════════════════════════════════════════════
# BrokenAuth
# Indicateurs : Welcome, admin / Logged in as / Set-Cookie: session= / access_token
# ══════════════════════════════════════════════════════════════════════════════
_default_creds = {
    'admin': ['admin', 'admin123', '123456', 'password', ''],
    'root': ['root', 'toor', ''],
    'test': ['test'], 'guest': ['guest'],
    'administrator': ['password', 'admin'],
}


@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
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
<form method="post"><input name="username"><br>
<input name="password" type="password"><br><button>Login</button></form>
<p><small>admin:admin | test:test | guest:guest | root:root</small></p>
</body></html>"""


@app.route('/auth/reset', methods=['GET', 'POST'])
def auth_reset():
    if request.method == 'POST':
        email = request.form.get('email', '')
        return f"<html><body><p>Welcome, admin — password reset for {email}, no verification required. Logged in as {email}</p></body></html>"
    return """<html><body><h1>Password Reset</h1>
<form method="post"><input name="email"><input name="password" type="password"><button>Reset</button></form>
</body></html>"""


@app.route('/auth/token')
def auth_token():
    user = request.args.get('user', 'anonymous')
    token = hashlib.sha256(f"shieldai_{user}".encode()).hexdigest()
    resp = make_response(jsonify({
        "token": token, "access_token": token, "auth_token": token,
        "user": user, "expires": None,
        "message": f"Logged in as {user}"
    }))
    resp.set_cookie('auth', token, httponly=False, secure=False)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# InsecPerm
# Indicateurs : Admin Panel, Administration Console, WordPress Dashboard
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
<table border="1"><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
{rows}</table></body></html>"""


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
        "admin": True, "panel": "Admin Panel",
        "note": "Administration Console — No authentication required",
    })


@app.route('/phpmyadmin')
def phpmyadmin():
    return "<html><body><h1>phpMyAdmin</h1><p>Administration Console — No authentication.</p></body></html>"


@app.route('/manager/html')
def tomcat_manager():
    return "<html><body><h1>Apache Tomcat Manager</h1><p>Welcome to Tomcat — Administration Console</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# SessFix
# Indicateurs : Set-Cookie: PHPSESSID=attacker_controlled_session, predictable_token
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/session/fixate')
def session_fixate():
    sid = request.args.get('sessionid', '')
    if not sid:
        return "<html><body><h1>Session Fixation</h1><p>Provide ?sessionid=xxx</p></body></html>"
    resp = make_response(f"""<html><body>
<h1>Session Fixation</h1>
<p>Session fixed to: <code>{sid}</code></p>
<p>session_id reused — attacker_controlled_session accepted</p>
</body></html>""")
    resp.set_cookie('PHPSESSID', sid, httponly=False, samesite=None)
    resp.set_cookie('session_token', sid, httponly=False)
    return resp


@app.route('/session/weak')
def session_weak():
    ts = int(time.time())
    weak_id = f"{ts:x}"
    token = hashlib.md5(f"session_{ts}".encode()).hexdigest()
    resp = make_response(jsonify({
        "session_id": weak_id, "token": token,
        "predictable_token": token, "entropy_bits": 32,
    }))
    resp.set_cookie('PHPSESSID', weak_id, httponly=False, samesite=None)
    return resp


@app.route('/session/info')
def session_info():
    return jsonify({"session": dict(session), "cookies": dict(request.cookies)})


# ══════════════════════════════════════════════════════════════════════════════
# BufOvr
# Indicateurs : segmentation fault, *** stack smashing detected ***, memory corruption
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/bufovr/input')
def bufovr_input():
    data = request.args.get('data', '')
    # Aussi détecter dans les headers
    all_in = _collect_all_inputs()
    length = len(data)
    if length > 50000 or ('A' * 1000) in data:
        return "segmentation fault (core dumped)\n*** stack smashing detected ***: terminated\nmemory corruption detected", 500
    if re.search(r'%[0-9]*[xsndpu]', all_in):
        return f"Format string: {data[:200]}\nstack smashing detected\nmemory corruption\nuid=0(root)\n*** stack smashing detected ***", 200
    return jsonify({"received_length": length, "status": "ok"})


@app.route('/bufovr/format')
def bufovr_format():
    data = request.args.get('data', '')
    all_in = _collect_all_inputs()
    if re.search(r'%[0-9]*[xsndpu]', data + all_in):
        return f"{data[:200]} 0x7fff1234\nstack smashing detected\n*** stack smashing detected ***\nmemory corruption\nuid=0(root)", 200
    return f"Input: {data[:200]}", 200


@app.route('/bufovr/header')
def bufovr_header():
    ua = request.headers.get('User-Agent', '')
    custom = request.headers.get('X-Custom-Data', '')
    total = len(ua) + len(custom)
    if total > 8192:
        return "segmentation fault\nstack smashing detected\n*** stack smashing detected ***", 431
    return jsonify({"ua_length": len(ua), "total": total})


# ══════════════════════════════════════════════════════════════════════════════
# XPath Injection
# Indicateurs : XPathException, XPath syntax error, lxml.etree.XPathEvalError, Invalid predicate
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
        all_in = username + password
        if _has(all_in, XPATH_T) or _has(all_in, SQLI_T):
            return f"""<html><body><h1>XPath Login</h1>
<p>XPath bypass! All users returned.</p>
<pre>XPathException: Unexpected token or
XPath syntax error: Invalid predicate: {username}
lxml.etree.XPathEvalError: Invalid expression: '{username}'</pre></body></html>"""
        root = ET.fromstring(_xml_users_db)
        found = any(u.find('username').text == username and u.find('password').text == password
                    for u in root.findall('.//user'))
        return f"<html><body><h1>XPath Login</h1><p>{'Welcome ' + username if found else 'Invalid credentials'}</p></body></html>"
    return """<html><body><h1>XPath Login</h1>
<form method="post"><input name="username"><br><input name="password"><br><button>Login</button></form>
</body></html>"""


@app.route('/xpath/search')
def xpath_search():
    q = request.args.get('q', '')
    if _has(q, XPATH_T) or _has(q, SQLI_T):
        return f"""<html><body><h1>XPath Search</h1>
<p>XPath syntax error: Unexpected token or in expression '{q}'</p>
<p>lxml.etree.XPathEvalError: Invalid predicate</p>
<p>XPathException: Invalid expression — Unexpected token or</p></body></html>"""
    root = ET.fromstring(_xml_users_db)
    found = [u.find('username').text for u in root.findall('.//user') if u.find('username').text == q]
    return f"<html><body><h1>XPath Search</h1><p>{found if found else 'No results'}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# OpenRedirect
# Indicateurs : Location: http://attacker.com
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
    resp = make_response(jsonify({"secret": "SHIELDAI_SENSITIVE_DATA", "token": "tok_abc123"}))
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
# Indicateurs : File uploaded successfully, /uploads/shell.php, has been uploaded
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files.get('file')
        if f and f.filename:
            filepath = os.path.join(UPLOAD_FOLDER, f.filename)
            f.save(filepath)
            return f"""<html><body><h1>Upload</h1>
<p>File uploaded successfully: {f.filename}</p>
<p>{f.filename} has been uploaded to /uploads/{f.filename}</p>
</body></html>"""
    return """<html><body><h1>File Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file"><br><button>Upload</button>
</form></body></html>"""


@app.route('/upload/avatar', methods=['GET', 'POST'])
def upload_avatar():
    if request.method == 'POST':
        f = request.files.get('avatar')
        if f:
            filepath = os.path.join(UPLOAD_FOLDER, 'avatar_' + f.filename)
            f.save(filepath)
            return f"<html><body><p>File uploaded successfully: {f.filename} has been uploaded to /uploads/avatar_{f.filename}</p></body></html>"
    return """<html><body><h1>Avatar Upload</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="avatar"><button>Upload</button>
</form></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# LDAPi
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/ldap/login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        uid = request.form.get('uid', '')
        pwd = request.form.get('password', '')
        if '*' in uid or '|' in uid or ')' in uid:
            return f"""<html><body><h1>LDAP Login</h1>
<p>LDAP Result Code 2 — ldap_bind() failed
Invalid filter syntax — Bad search filter
javax.naming.NamingException</p></body></html>"""
        if uid == 'admin' and pwd == 'ldappass':
            return "<html><body><h1>LDAP Login</h1><p>✅ LDAP auth OK</p></body></html>"
        return "<html><body><h1>LDAP Login</h1><p>❌ Invalid credentials</p></body></html>"
    return """<html><body><h1>LDAP Login</h1>
<form method="post"><input name="uid"><input name="password"><button>Login</button></form>
</body></html>"""


@app.route('/ldap/search')
def ldap_search():
    uid = request.args.get('uid', '')
    if '*' in uid or '|' in uid:
        return f"<html><body><p>ldap_search_s() failed — Invalid filter syntax — Bad search filter: {uid}</p></body></html>"
    return f"<html><body><p>No user found for uid={uid}</p></body></html>"


# ══════════════════════════════════════════════════════════════════════════════
# RaceCondition
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/race/coupon', methods=['GET', 'POST'])
def race_coupon():
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code == 'SAVE50':
            time.sleep(0.05)
            if code in _used_coupons:
                return "<html><body><p>❌ already redeemed — coupon used more than once</p></body></html>"
            _used_coupons.add(code)
            return "<html><body><p>✅ Coupon applied! -50%</p></body></html>"
        return "<html><body><p>Invalid coupon</p></body></html>"
    return """<html><body><h1>Coupon</h1>
<form method="post"><input name="code" value="SAVE50"><button>Apply</button></form></body></html>"""


@app.route('/race/transfer', methods=['GET', 'POST'])
def race_transfer():
    if request.method == 'POST':
        user = request.form.get('user', 'user1')
        try:
            amount = float(request.form.get('amount', 0))
        except Exception:
            amount = 0
        time.sleep(0.05)
        if _account_balance.get(user, 0) >= amount:
            _account_balance[user] -= amount
            return jsonify({"status": "ok", "new_balance": _account_balance[user]})
        return jsonify({"error": "balance inconsistency — UNIQUE constraint failed"}), 400
    return f"""<html><body><h1>Transfer</h1>
<p>Balances: {_account_balance}</p>
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
# HTTP Request Smuggling
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/smuggle/endpoint', methods=['GET', 'POST', 'OPTIONS'])
def smuggle_endpoint():
    te = request.headers.get('Transfer-Encoding', '')
    cl = request.headers.get('Content-Length', '')
    if te and cl:
        return jsonify({
            "Transfer-Encoding": te, "Content-Length": cl,
            "note": "chunked encoding conflict — Transfer-Encoding conflict",
            "desynchronized": True, "admin panel": "accessible via smuggled request"
        })
    return jsonify({"Transfer-Encoding": te, "note": "smuggling test point"})


@app.route('/smuggle/te-te')
def smuggle_te_te():
    te = request.headers.get('Transfer-Encoding', '')
    if 'identity' in te or 'xchunked' in te:
        return jsonify({"note": "TE.TE obfuscation — Transfer-Encoding conflict", "desynchronized": True})
    return jsonify({"Transfer-Encoding": te, "note": "TE.TE test point"})


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
        return jsonify({
            "X-Forwarded-For": xff, "trusted_ip": xff.split(',')[0].strip() if xff else real_ip,
            "rate_limit_bypassed": True, "throttled": False
        })
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
# CSRF
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/csrf/transfer', methods=['GET', 'POST'])
def csrf_transfer():
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '0')
        return f"<html><body><p>Transferred ${amount} to {to} — No CSRF token checked</p></body></html>"
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
        return f"<html><body><p>Email changed to {email} — No CSRF token</p></body></html>"
    return '<html><body><form method="post"><input name="email"><button>Change</button></form></body></html>'


@app.route('/csrf/password', methods=['GET', 'POST'])
def csrf_password():
    if request.method == 'POST':
        return "<html><body><p>Password changed — No CSRF token, no old password</p></body></html>"
    return '<html><body><form method="post"><input name="password" type="password"><button>Change</button></form></body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║        🔥 ShieldAI VULNERABLE TEST SERVER v3.1.0                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ⚠️  INTENTIONNELLEMENT VULNÉRABLE — LOCAL UNIQUEMENT ⚠️                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║  🌐  URL    : http://localhost:5000                                       ║
║  🎯  Calibré: payloads_v2.json v3.0.0                                   ║
║  💡  v3.1   : Middleware global header injection + baseline neutre      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)