"""
VulnLab - Niveau 5 (Expert) - combiné web + réseau + "privesc"
Lance avec : python3 app.py   (lance aussi automatiquement l'API interne et le faux cron)
Port web : 5005 | API interne : 127.0.0.1:6000 (non accessible depuis l'extérieur)
"""
from flask import Flask, request, send_file
import os, threading, time, http.server, socketserver, json, urllib.request

BASE = os.path.dirname(__file__)
SECRETS_DIR = os.path.join(BASE, "secrets")
REPORTS_DIR = os.path.join(BASE, "reports")
MAINT_DIR = os.path.join(BASE, "maintenance")
os.makedirs(REPORTS_DIR, exist_ok=True)

INTERNAL_TOKEN = "T0k3n_1nt3rn4l_9f82a1"
with open(os.path.join(SECRETS_DIR, "internal_token.txt"), "w") as f:
    f.write(INTERNAL_TOKEN + "\n")
with open(os.path.join(REPORTS_DIR, "report.txt"), "w") as f:
    f.write("Rapport public : tout va bien.\n")

app = Flask(__name__)

# ---------- API interne (accessible SEULEMENT depuis 127.0.0.1) ----------
class InternalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/admin/flag"):
            token = self.headers.get("X-Internal-Token", "")
            if not token and "token=" in self.path:
                token = self.path.split("token=", 1)[1]
            if token == INTERNAL_TOKEN:
                body = json.dumps({"flag": "FLAG{level5_ssrf_path_tr4versal_chain}"}).encode()
                self.send_response(200)
            else:
                body = b'{"error":"token invalide"}'
                self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


def run_internal_api():
    srv = socketserver.TCPServer(("127.0.0.1", 6000), InternalHandler)
    srv.serve_forever()


# ---------- Simulation "cron root" qui exécute un script modifiable ----------
def run_fake_cron():
    script = os.path.join(MAINT_DIR, "cleanup.sh")
    if not os.path.exists(script):
        with open(script, "w") as f:
            f.write("#!/bin/sh\n# Nettoyage temporaire (exécuté périodiquement par un process privilégié simulé)\n")
        os.chmod(script, 0o777)  # volontairement trop permissif
    while True:
        time.sleep(10)
        try:
            marker = os.path.join(MAINT_DIR, "pwned.txt")
            os.system(f"sh {script} > {os.path.join(MAINT_DIR, 'cron.log')} 2>&1")
            if os.path.exists(marker):
                with open(marker, "a") as f:
                    f.write("\nFLAG{level5_privesc_writable_cron}\n")
        except Exception:
            pass


# ---------- App web publique ----------
HOME = """
<h1>Générateur de rapports</h1>
<p>Télécharger un rapport : <a href="/download?file=report.txt">/download?file=report.txt</a></p>
<form action="/preview">
  <input name="url" placeholder="URL à prévisualiser" style="width:300px" value="http://example.com">
  <button type="submit">Prévisualiser</button>
</form>
"""


@app.route("/")
def home():
    return HOME


@app.route("/download")
def download():
    fname = request.args.get("file", "report.txt")
    # vulnérable : pas de validation du chemin -> path traversal possible
    path = os.path.join(REPORTS_DIR, fname)
    if not os.path.exists(path):
        return "Fichier introuvable", 404
    return send_file(path)


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    # vulnérable : SSRF, le serveur va chercher n'importe quelle URL fournie par l'utilisateur,
    # y compris des services internes non exposés publiquement (127.0.0.1:6000)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnLab-Previewer"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read(2000).decode(errors="replace")
    except Exception as e:
        content = f"Erreur: {e}"
    return f"<pre>{content}</pre><p><a href='/'>Retour</a></p>"


if __name__ == "__main__":
    threading.Thread(target=run_internal_api, daemon=True).start()
    threading.Thread(target=run_fake_cron, daemon=True).start()
    print("[Level 5] http://127.0.0.1:5005  (API interne cachée sur 127.0.0.1:6000)")
    app.run(host="0.0.0.0", port=5005)
