"""
VulnLab - Niveau 2 (Moyen)
Lance avec : python3 app.py
Port : 5002
"""
from flask import Flask, request, render_template_string, session, redirect
import sqlite3, os, time

app = Flask(__name__)
app.secret_key = "dev-secret-not-for-prod"
DB = os.path.join(os.path.dirname(__file__), "lvl2.db")


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS invoices")
    c.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner TEXT, amount TEXT, secret TEXT)")
    c.execute("INSERT INTO invoices VALUES (1,'admin','99999','FLAG{level2_1d0r_0r_bl1nd_sqli}')")
    c.execute("INSERT INTO invoices VALUES (2,'bob','42','rien ici')")
    c.execute("INSERT INTO invoices VALUES (3,'alice','17','rien ici non plus')")
    conn.commit()
    conn.close()


LOGIN = """
<h1>Portail client</h1>
<form method="POST">
  <input name="username" placeholder="bob / alice"><br>
  <input name="password" placeholder="mot de passe (indice: identique au username + '123')" type="password"><br>
  <button type="submit">Connexion</button>
</form>
<p style="color:red">{{ error }}</p>
"""

DASH = """
<h1>Bonjour {{ user }}</h1>
<p>Ta facture : <a href="/invoice/{{ my_id }}">/invoice/{{ my_id }}</a></p>
<form action="/track">
  <input name="order" placeholder="Numéro de commande à tracker">
  <button type="submit">Tracker (réponse lente si existe)</button>
</form>
<p>{{ track_result }}</p>
"""

INVOICE = "<h1>Facture #{{ id }}</h1><p>Propriétaire: {{ owner }}</p><p>Montant: {{ amount }}</p>"

USERS = {"bob": ("bob123", 2), "alice": ("alice123", 3)}


@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in USERS and USERS[u][0] == p:
            session["user"] = u
            session["uid"] = USERS[u][1]
            return redirect("/dashboard")
        error = "Identifiants invalides."
    return render_template_string(LOGIN, error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template_string(DASH, user=session["user"], my_id=session["uid"], track_result="")


@app.route("/invoice/<int:inv_id>")
def invoice(inv_id):
    if "user" not in session:
        return redirect("/")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, owner, amount, secret FROM invoices WHERE id=?", (inv_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Facture introuvable", 404
    body = render_template_string(INVOICE, id=row[0], owner=row[1], amount=row[2])
    if row[1] == "admin":
        body += f"<p>{row[3]}</p>"
    return body


@app.route("/track")
def track():
    if "user" not in session:
        return redirect("/")
    order = request.args.get("order", "")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # vulnérable : requête construite par concaténation (injection SQL en aveugle possible)
    query = f"SELECT id FROM invoices WHERE id={order}"
    start = time.time()
    try:
        c.execute(query)
        row = c.fetchone()
        exists = bool(row)
    except sqlite3.OperationalError:
        exists = False
    conn.close()
    elapsed = time.time() - start
    msg = f"Commande trouvée (en {elapsed:.2f}s)" if exists else f"Introuvable (en {elapsed:.2f}s)"
    return render_template_string(DASH, user=session["user"], my_id=session["uid"], track_result=msg)


if __name__ == "__main__":
    init_db()
    print("[Level 2] http://127.0.0.1:5002")
    app.run(host="0.0.0.0", port=5002)
