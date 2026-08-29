"""
Serveur SAFE — contre-partie sécurisée du vulnserver.

Même structure de routes exacte (10 170), mais chaque page implémente le
comportement sécurisé correspondant. Sert de labels négatifs (vulns=[])
pour équilibrer le dataset d'entraînement.

Usage:
    python app.py
"""
import json
from generator import build_app

app, manifest = build_app()

with open("manifest.json", "w") as f:
    json.dump({"total_routes": len(manifest), "routes": manifest}, f, indent=2)

if __name__ == "__main__":
    mono = sum(1 for r in manifest if r["page_type"] == "mono")
    multi = sum(1 for r in manifest if r["page_type"] == "multi")
    print(f"[safeserver] {len(manifest)} routes générées ({mono} mono / {multi} multi)")
    print("[safeserver] toutes les routes ont vulns=[] (labels négatifs)")
    print("[safeserver] démarrage sur http://0.0.0.0:5051 ...")
    app.run(host="0.0.0.0", port=5051, debug=False)
