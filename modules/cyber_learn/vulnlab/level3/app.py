"""
VulnLab - Niveau 3 (Difficile)
Lance avec : python3 app.py
Port : 5003
"""
from flask import Flask, request, render_template_string
import os, subprocess, base64, pickle

app = Flask(__name__)
FLAG_FILE = os.path.join(os.path.dirname(__file__), "flag.txt")

with open(FLAG_FILE, "w") as f:
    f.write("FLAG{level3_cmd1nj3ct10n_or_1nsecure_p1ckle}\n")
os.chmod(FLAG_FILE, 0o600)  # lisible seulement par le process qui tourne, pas en direct par toi

HOME = """
<h1>Outil diagnostic réseau</h1>
<form method="POST" action="/ping">
  <input name="host" placeholder="ex: 127.0.0.1" value="127.0.0.1">
  <button type="submit">Ping</button>
</form>
<pre>{{ output }}</pre>
<hr>
<h3>Charger un profil sauvegardé (base64)</h3>
<form method="POST" action="/load_profile">
  <input name="data" placeholder="données base64" style="width:400px">
  <button type="submit">Charger</button>
</form>
<pre>{{ profile_result }}</pre>
"""


@app.route("/")
def home():
    return render_template_string(HOME, output="", profile_result="")


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "127.0.0.1")
    # vulnérable : l'entrée utilisateur est injectée directement dans la commande shell
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
    except Exception as e:
        output = str(e)
    return render_template_string(HOME, output=output, profile_result="")


class Profile:
    def __init__(self, name):
        self.name = name


@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.form.get("data", "")
    result = ""
    try:
        raw = base64.b64decode(data)
        # vulnérable : désérialisation non sécurisée d'une entrée utilisateur
        obj = pickle.loads(raw)
        result = f"Profil chargé : {getattr(obj, 'name', obj)}"
    except Exception as e:
        result = f"Erreur: {e}"
    return render_template_string(HOME, output="", profile_result=result)


if __name__ == "__main__":
    print("[Level 3] http://127.0.0.1:5003")
    app.run(host="0.0.0.0", port=5003)
