"""
Serveur volontairement vulnérable — point d'entrée.

Usage:
    python app.py

Génère 10 000+ routes vulnérables (mono + multi), démarre le serveur Flask
sur le port 5000, et écrit manifest.json (route -> vulns) à la racine.

⚠️ Voir README.md pour les avertissements de sécurité avant de lancer.
"""
import json
from generator import build_app

app, manifest = build_app()

with open("manifest.json", "w") as f:
    json.dump({"total_routes": len(manifest), "routes": manifest}, f, indent=2)

if __name__ == "__main__":
    mono = sum(1 for r in manifest if r["page_type"] == "mono")
    multi = sum(1 for r in manifest if r["page_type"] == "multi")
    print(f"[vulnserver] {len(manifest)} routes générées ({mono} mono / {multi} multi)")
    print("[vulnserver] manifest.json écrit à la racine du projet")
    print("[vulnserver] démarrage sur http://0.0.0.0:5050 ...")
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
