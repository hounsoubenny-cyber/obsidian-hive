"""
VulnLab - Niveau 1 (Facile)
Lance avec : python3 app.py
Port : 5001
"""
from flask import Flask, request, render_template_string, make_response
import sqlite3, os

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "lvl1.db")


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)")
    c.execute("INSERT INTO users VALUES (1,'admin','S7r0ngP@ss!',1)")
    c.execute("INSERT INTO users VALUES (2,'bob','bob123',0)")
    conn.commit()
    conn.close()


HOME = """
<h1>Mini-Blog</h1>
<form action="/search">
  <input name="q" placeholder="Rechercher un article...">
  <button type="submit">Chercher</button>
</form>
<p>Résultat : {{ result|safe }}</p>
<hr>
<a href="/login">Se connecter</a>
"""

LOGIN = """
<h1>Connexion</h1>
<form method="POST">
  <input name="username" placeholder="Utilisateur"><br>
  <input name="password" type="password" placeholder="Mot de passe"><br>
  <button type="submit">Connexion</button>
</form>
<p style="color:red">{{ error }}</p>
"""

ADMIN = """
<h1>Panneau admin</h1>
<p>Bienvenue {{ user }} !</p>
<p>FLAG: {{ flag }}</p>
"""


@app.route("/")
def home():
    return render_template_string(HOME, result="")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(HOME, result=q)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            c.execute(query)
            row = c.fetchone()
        except sqlite3.OperationalError as e:
            row = None
            error = f"Erreur SQL: {e}"
        conn.close()
        if row:
            resp = make_response(render_template_string(
                ADMIN, user=row[1],
                flag="FLAG{level1_sql1nj3ct10n_or_bru7ef0rce}" if row[3] else "accès limité, pas admin"
            ))
            return resp
        if not error:
            error = "Identifiants invalides."
    return render_template_string(LOGIN, error=error)


if __name__ == "__main__":
    init_db()
    print("[Level 1] http://127.0.0.1:5001")
    app.run(host="0.0.0.0", port=5001)
