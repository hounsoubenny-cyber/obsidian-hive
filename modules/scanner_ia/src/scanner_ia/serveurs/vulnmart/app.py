"""
VulnMart — boutique en ligne volontairement vulnérable.
Construite comme cible d'entraînement/test pour un scanner de sécurité.
Chaque vulnérabilité est documentée dans README.md. NE JAMAIS déployer
publiquement / sur un réseau non isolé.
"""
import os
import sqlite3
import hashlib
import subprocess
import pickle
import base64
import time
import secrets as pysecrets
import jwt  # PyJWT
import requests
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, g, make_response, send_from_directory, jsonify
)

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "vulnmart.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")

app = Flask(__name__)

# --- VULN #1: secrets hardcodés dans le code source / commentés comme "temporaire" ---
app.config["SECRET_KEY"] = "vulnmart-dev-secret-2024"  # TODO: move to env before prod (never happened)
JWT_SECRET = "sup3r-secret-jwt-key"
STRIPE_TEST_KEY = "sk_test_51Hxxxxxxxxxxxxxxxxxxxxxxxx"  # exposée volontairement (cf README)

# --- VULN #2: debug mode actif en "prod" ---
app.config["DEBUG"] = True


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


# ------------------------------------------------------------------
# Home / listing
# ------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products, user=current_user())


# ------------------------------------------------------------------
# VULN #3: SQL Injection (auth bypass) — login construit par concaténation
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # Requête vulnérable : concaténation directe, pas de paramètre bindé
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{md5(password)}'"
        try:
            user = db.execute(query).fetchone()
        except sqlite3.Error as e:
            # VULN #4: messages d'erreur verbeux (fuite d'infos sur le schéma)
            return render_template("login.html", error=f"Erreur SQL: {e} — requête: {query}")
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            resp = redirect(url_for("index"))
            # VULN #5: "remember me" via JWT signé avec un secret faible, alg confus possible
            token = jwt.encode({"uid": user["id"], "role": user["role"]}, JWT_SECRET, algorithm="HS256")
            resp.set_cookie("remember_token", token)
            return resp
        error = "Identifiants invalides."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("index"))
    resp.delete_cookie("remember_token")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        username = request.form.get("username", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        # Pas de politique de mot de passe, pas de vérif d'unicité gérée proprement,
        # hashing MD5 pour cohérence avec les comptes "legacy"
        db.execute(
            "INSERT INTO users (username,email,password_hash,hash_algo) VALUES (?,?,?,?)",
            (username, email, md5(password), "md5")
        )
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


# ------------------------------------------------------------------
# VULN #6: XSS réfléchi — recherche non échappée (rendue avec |safe côté template)
# ------------------------------------------------------------------
@app.route("/search")
def search():
    db = get_db()
    q = request.args.get("q", "")
    if q:
        results = db.execute(
            "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
            (f"%{q}%", f"%{q}%")
        ).fetchall()
    else:
        results = []
    return render_template("search.html", results=results, q=q, user=current_user())


# ------------------------------------------------------------------
# VULN #7: IDOR — accès produit/avis sans contrôle
# VULN #8: XSS stocké — avis client injecté tel quel
# ------------------------------------------------------------------
@app.route("/product/<int:pid>", methods=["GET", "POST"])
def product(pid):
    db = get_db()
    if request.method == "POST":
        body = request.form.get("review", "")
        user = current_user()
        author = user["username"] if user else "anonyme"
        db.execute("INSERT INTO reviews (product_id, username, body) VALUES (?,?,?)", (pid, author, body))
        db.commit()
    prod = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    reviews = db.execute("SELECT * FROM reviews WHERE product_id=?", (pid,)).fetchall()
    return render_template("product.html", product=prod, reviews=reviews, user=current_user())


# ------------------------------------------------------------------
# VULN #9: IDOR total — profil et commandes de N'IMPORTE QUEL utilisateur,
# aucune vérification que le viewer == propriétaire du profil.
# VULN #10: exposition de données sensibles (SSN, carte bancaire tronquée)
# ------------------------------------------------------------------
@app.route("/profile/<username>")
def profile(username):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        return "Utilisateur introuvable", 404
    orders = db.execute("SELECT * FROM orders WHERE user_id=?", (target["id"],)).fetchall()
    return render_template("profile.html", profile_user=target, orders=orders, user=current_user())


# API miroir de la même faille, encore plus directe
@app.route("/api/user/<int:uid>")
def api_user(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        return jsonify({"error": "not found"}), 404
    # Renvoie TOUT, y compris password_hash / ssn / credit_card
    return jsonify(dict(u))


# ------------------------------------------------------------------
# VULN #11: Broken Access Control — contrôle admin fait côté client uniquement
# (le serveur vérifie juste un cookie "is_admin" trivialement falsifiable)
# ------------------------------------------------------------------
@app.route("/admin")
def admin():
    if request.cookies.get("is_admin") != "true" and not (current_user() and current_user()["is_admin"]):
        return render_template("admin_denied.html"), 403
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


# ------------------------------------------------------------------
# VULN #12: Upload de fichier sans restriction (type, taille, contenu)
# -> possibilité d'uploader un .py/.php/.html exécutable selon la conf serveur,
# et le nom de fichier n'est pas sanitizé (path traversal potentiel).
# ------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    if request.method == "POST":
        f = request.files.get("avatar")
        if f and f.filename:
            # Pas de whitelist d'extension, pas de secure_filename
            dest = os.path.join(UPLOAD_DIR, f.filename)
            f.save(dest)
            user = current_user()
            if user:
                db = get_db()
                db.execute("UPDATE users SET avatar=? WHERE id=?", (f"/static/uploads/{f.filename}", user["id"]))
                db.commit()
            message = f"Fichier reçu : {f.filename}"
    return render_template("upload.html", message=message, user=current_user())


# ------------------------------------------------------------------
# VULN #13: Path Traversal / LFI — lecture de fichier arbitraire sur le serveur
# ------------------------------------------------------------------
@app.route("/file")
def file_view():
    name = request.args.get("name", "welcome.txt")
    path = os.path.join(BASE_DIR, "docs", name)  # pas de normalisation / vérif de préfixe
    try:
        with open(path, "r", errors="replace") as fh:
            content = fh.read()
    except Exception as e:
        content = f"Erreur: {e}"
    return render_template("file_view.html", name=name, content=content)


# ------------------------------------------------------------------
# VULN #14: Command Injection — outil "ping" qui passe l'entrée au shell
# ------------------------------------------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # shell=True + f-string => injection triviale via ; & | `` $()
        cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
        except Exception as e:
            output = str(e)
    return render_template("ping.html", output=output, host=host, user=current_user())


# ------------------------------------------------------------------
# VULN #15: SSRF — "importer une image produit depuis une URL" côté serveur
# ------------------------------------------------------------------
@app.route("/fetch-image", methods=["GET", "POST"])
def fetch_image():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # Aucune validation de schéma/host -> accès réseau interne possible
            # (127.0.0.1, 169.254.169.254 metadata cloud, etc.)
            r = requests.get(url, timeout=3)
            result = f"Status {r.status_code}, {len(r.content)} octets reçus"
        except Exception as e:
            result = f"Erreur: {e}"
    return render_template("fetch_image.html", result=result, url=url, user=current_user())


# ------------------------------------------------------------------
# VULN #16: Désérialisation non sûre — "importer mon panier" via pickle+base64
# ------------------------------------------------------------------
@app.route("/cart/import", methods=["GET", "POST"])
def cart_import():
    message = None
    if request.method == "POST":
        blob = request.form.get("cart_data", "")
        try:
            data = pickle.loads(base64.b64decode(blob))  # exécution de code arbitraire possible
            session["cart"] = data
            message = f"Panier importé : {data}"
        except Exception as e:
            message = f"Erreur: {e}"
    return render_template("cart_import.html", message=message, user=current_user())


# ------------------------------------------------------------------
# VULN #17: CSRF — pas de token, changement d'email accepté sur simple GET/POST
# depuis n'importe quelle origine
# ------------------------------------------------------------------
@app.route("/account/change-email", methods=["GET", "POST"])
def change_email():
    user = current_user()
    message = None
    if request.method == "POST" and user:
        new_email = request.form.get("email", "")
        db = get_db()
        db.execute("UPDATE users SET email=? WHERE id=?", (new_email, user["id"]))
        db.commit()
        message = "Email mis à jour."
    return render_template("change_email.html", message=message, user=user)


# ------------------------------------------------------------------
# VULN #18: Reset password — token prévisible (timestamp) + pas de rate limit
# + fuite d'info (confirme si l'email existe)
# ------------------------------------------------------------------
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    message = None
    if request.method == "POST":
        email = request.form.get("email", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u:
            token = str(int(time.time()))  # prévisible, pas de secrets.token_urlsafe
            db.execute("UPDATE users SET reset_token=? WHERE id=?", (token, u["id"]))
            db.commit()
            message = f"Lien envoyé. (debug: token={token})"  # fuite du token dans la réponse
        else:
            message = "Aucun compte trouvé avec cet email."  # confirme l'énumération
    return render_template("reset_password.html", message=message)


# ------------------------------------------------------------------
# VULN #19: Security misconfiguration — endpoint de debug qui expose la config
# ------------------------------------------------------------------
@app.route("/config")
def leak_config():
    return jsonify({
        "SECRET_KEY": app.config["SECRET_KEY"],
        "JWT_SECRET": JWT_SECRET,
        "STRIPE_KEY": STRIPE_TEST_KEY,
        "DB_PATH": DB_PATH,
        "DEBUG": app.config["DEBUG"],
    })


# ------------------------------------------------------------------
# VULN #20: pas de rate limiting sur le login -> brute force possible
# (aucun compteur, aucun verrouillage, pas de captcha)
# ------------------------------------------------------------------


@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonyme")
        body = request.form.get("body", "")
        db.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        db.commit()
    all_comments = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    return render_template("comments.html", comments=all_comments, user=current_user())


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import init_db
        init_db.main()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "docs"), exist_ok=True)
    welcome = os.path.join(BASE_DIR, "docs", "welcome.txt")
    if not os.path.exists(welcome):
        with open(welcome, "w") as f:
            f.write("Bienvenue sur VulnMart. Essayez ?name=../app.py sur /file 😉\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
