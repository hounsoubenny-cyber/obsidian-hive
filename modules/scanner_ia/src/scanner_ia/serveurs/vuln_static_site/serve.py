#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur HTTP statique de test — ShieldAI
⚠️ Site 100% statique (aucune logique serveur), utilisé pour tester la partie
   PASSIVE / CODE ANALYZER du scanner (headers, secrets dans le code source,
   XSS DOM, dépendances obsolètes) SANS fuzzer actif ni ML.

Usage : python3 serve.py [port]
Défaut : port 8090, sert le dossier ./site
"""
import sys
import http.server
import socketserver

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
DIRECTORY = "site"


class WeakSecurityHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # ⚠️ VULNÉRABLE : volontairement AUCUN header de sécurité
        # (pas de CSP, pas de X-Frame-Options, pas de HSTS, pas de X-Content-Type-Options)
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")  # ⚠️ fingerprinting facile
        self.send_header("Access-Control-Allow-Origin", "*")  # ⚠️ CORS trop permissif
        self.send_header("Access-Control-Allow-Credentials", "true")
        super().end_headers()


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), WeakSecurityHandler) as httpd:
        print(f"🔥 Site statique vulnérable servi sur http://localhost:{PORT}")
        print(f"⚠️  Headers de sécurité volontairement absents/faibles — usage local uniquement !")
        httpd.serve_forever()
