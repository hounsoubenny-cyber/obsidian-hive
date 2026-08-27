#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug 16 18:25:30 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
"""
Mini scanner — construit à des fins de comparaison avec ShieldAI.
Objectif : rester simple et lisible, pas exhaustif. Couvre les classes de
vulns les plus faciles à détecter fiablement via HTTP : SQLi (auth bypass +
erreur), XSS réfléchi/stocké, IDOR, command injection, path traversal, SSRF,
désérialisation insécurisée, CSRF manquant, headers de sécurité manquants,
secrets/tokens exposés, mauvais hashing.
"""
import re
import time
import base64
import pickle
import argparse
import requests
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field


@dataclass
class Finding:
    vuln: str
    severity: str
    url: str
    evidence: str
    detail: str = ""


class MiniScanner:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.timeout = timeout
        self.visited = set()
        self.to_visit = [self.base_url + "/"]
        self.findings: list[Finding] = []

    # ---------------------------------------------------------- crawl
    def crawl(self, max_pages: int = 50):
        while self.to_visit and len(self.visited) < max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                r = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue
            self._check_headers(url, r)
            self._check_secrets(url, r.text)
            for href in re.findall(r'href=["\']([^"\']+)["\']', r.text):
                full = urljoin(url, href)
                if self._same_site(full) and full not in self.visited:
                    self.to_visit.append(full)
            for action in re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', r.text):
                full = urljoin(url, action) if action else url
                if self._same_site(full) and full not in self.visited:
                    self.to_visit.append(full)
        return self.visited

    def _same_site(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    # ---------------------------------------------------------- passive checks
    def _check_headers(self, url, r):
        missing = []
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        for h in ("strict-transport-security", "x-content-type-options",
                  "x-frame-options", "content-security-policy"):
            if h not in headers_lower:
                missing.append(h)
        if missing:
            self.findings.append(Finding(
                "missing_security_headers", "moyen", url,
                f"Headers absents: {', '.join(missing)}"
            ))
        for c in r.cookies:
            if not c.secure:
                self.findings.append(Finding(
                    "insecure_cookie", "élevé", url,
                    f"Cookie '{c.name}' sans flag Secure"
                ))
            if not c.has_nonstandard_attr("HttpOnly") and "httponly" not in str(c._rest).lower():
                self.findings.append(Finding(
                    "insecure_cookie", "moyen", url,
                    f"Cookie '{c.name}' possiblement sans HttpOnly"
                ))

    def _check_secrets(self, url, body):
        patterns = {
            "hardcoded_secret_key": r"SECRET_KEY[\"'\s]*[:=][\"'\s]*[\w\-]{8,}",
            "hardcoded_jwt_secret": r"JWT_SECRET[\"'\s]*[:=][\"'\s]*[\w\-]{8,}",
            "stripe_test_key": r"sk_(test|live)_[A-Za-z0-9]{10,}",
            "md5_hash_exposed": r"\b[a-f0-9]{32}\b",
        }
        for name, pat in patterns.items():
            m = re.search(pat, body)
            if m:
                self.findings.append(Finding(
                    name, "élevé", url, m.group(0)[:60]
                ))

    # ---------------------------------------------------------- active checks
    def test_sqli_login(self, login_path="/login"):
        url = urljoin(self.base_url + "/", login_path.lstrip("/"))
        payloads = ["admin' OR '1'='1' --", "' OR '1'='1' -- "]
        for user_payload in payloads:
            try:
                r = self.session.post(url, data={
                    "username": user_payload, "password": "whatever"
                }, timeout=self.timeout, allow_redirects=False)
            except requests.RequestException:
                continue
            # Signal fort : redirection (connexion réussie) ou cookie de session posé
            if r.status_code in (301, 302, 303) or "session" in r.headers.get("Set-Cookie", "").lower():
                self.findings.append(Finding(
                    "sqli_auth_bypass", "critique", url,
                    f"payload={user_payload!r} -> status={r.status_code}, "
                    f"Set-Cookie présent" if "Set-Cookie" in r.headers else f"status={r.status_code}"
                ))
                return
            if re.search(r"(sql|sqlite3\.|syntax error|erreur sql)", r.text, re.I):
                self.findings.append(Finding(
                    "sqli_error_based", "élevé", url,
                    f"payload={user_payload!r} -> message d'erreur SQL reflété"
                ))
                return

    def test_xss_reflected(self, search_path="/search"):
        url = urljoin(self.base_url + "/", search_path.lstrip("/"))
        marker = "MINISCAN_XSS_9f31"
        payload = f"<script>/*{marker}*/</script>"
        try:
            r = self.session.get(url, params={"q": payload}, timeout=self.timeout)
        except requests.RequestException:
            return
        if payload in r.text:
            self.findings.append(Finding(
                "xss_reflected", "élevé", url,
                f"Payload reflété tel quel (non échappé) via ?q="
            ))

    def test_idor_profile(self, profile_path="/profile/", usernames=("admin", "alice", "bob")):
        base = urljoin(self.base_url + "/", profile_path.lstrip("/"))
        for u in usernames:
            url = base.rstrip("/") + "/" + u
            try:
                r = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue
            if r.status_code == 200 and re.search(r"ssn|carte|card|password_hash|password hash", r.text, re.I):
                self.findings.append(Finding(
                    "idor_sensitive_data", "critique", url,
                    f"Profil '{u}' accessible sans authentification, données sensibles visibles"
                ))

    def test_command_injection(self, ping_path="/ping"):
        url = urljoin(self.base_url + "/", ping_path.lstrip("/"))
        marker = "MINISCANCMD9f31"
        payload = f"127.0.0.1; echo {marker}"
        try:
            r = self.session.post(url, data={"host": payload}, timeout=self.timeout)
            if r.status_code == 405:
                r = self.session.get(url, params={"host": payload}, timeout=self.timeout)
        except requests.RequestException:
            return
        if marker in r.text:
            self.findings.append(Finding(
                "command_injection", "critique", url,
                f"Marqueur '{marker}' exécuté et reflété -> RCE confirmée"
            ))

    def test_path_traversal(self, file_path="/file"):
        url = urljoin(self.base_url + "/", file_path.lstrip("/"))
        # Plusieurs profondeurs de ../ car on ne connaît pas la profondeur
        # réelle du répertoire de base côté serveur
        for depth in (4, 6, 8, 10):
            payload = "../" * depth + "etc/passwd"
            try:
                r = self.session.get(url, params={"name": payload}, timeout=self.timeout)
            except requests.RequestException:
                continue
            if "root:x:0:0" in r.text:
                self.findings.append(Finding(
                    "path_traversal", "critique", url,
                    f"Contenu de /etc/passwd lu via traversal (profondeur={depth})"
                ))
                return

    def test_ssrf(self, fetch_path="/fetch-image"):
        url = urljoin(self.base_url + "/", fetch_path.lstrip("/"))
        # Cible interne factice : le scanner lui-même sur un port improbable,
        # on regarde juste si le serveur tente réellement la requête (délai / erreur réseau spécifique)
        internal_target = "http://127.0.0.1:1/"
        t0 = time.time()
        try:
            r = self.session.post(url, data={"url": internal_target}, timeout=self.timeout)
        except requests.RequestException:
            return
        elapsed = time.time() - t0
        if re.search(r"connection refused|connectionerror|refused", r.text, re.I):
            self.findings.append(Finding(
                "ssrf", "critique", url,
                f"Le serveur a tenté de contacter '{internal_target}' (erreur réseau reflétée -> requête sortante confirmée)"
            ))

    def test_insecure_deserialization(self, cart_path="/cart/import"):
        url = urljoin(self.base_url + "/", cart_path.lstrip("/"))
        marker = "MINISCAN_PICKLE_OK"

        class Probe:
            def __reduce__(self):
                return (print, (marker,))

        payload_b64 = base64.b64encode(pickle.dumps(Probe())).decode()
        try:
            r = self.session.post(url, data={"cart_data": payload_b64}, timeout=self.timeout)
        except requests.RequestException:
            return
        # On ne peut pas observer le print() côté serveur directement, donc on
        # se contente de vérifier que l'endpoint ACCEPTE un blob pickle sans
        # le rejeter -> signal faible mais utile (à corroborer manuellement).
        if r.status_code == 200 and "erreur" not in r.text.lower() and "error" not in r.text.lower():
            self.findings.append(Finding(
                "insecure_deserialization_suspected", "élevé", url,
                "Endpoint accepte un blob pickle base64 sans le rejeter (signal faible, à valider manuellement)"
            ))

    def test_csrf_missing(self):
        for url in list(self.visited):
            try:
                r = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue
            for form in re.findall(r"<form[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>", r.text, re.I | re.S):
                if not re.search(r"csrf|token|authenticity|nonce", form, re.I):
                    self.findings.append(Finding(
                        "missing_csrf_protection", "élevé", url,
                        "Formulaire POST sans champ token détecté"
                    ))

    def test_common_paths(self, paths=("/config", "/admin/config", "/debug", "/.env")):
        for p in paths:
            url = urljoin(self.base_url + "/", p.lstrip("/"))
            try:
                r = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue
            if r.status_code == 200 and re.search(r"SECRET_KEY|JWT_SECRET|sk_(test|live)_", r.text):
                self.findings.append(Finding(
                    "exposed_config_secrets", "critique", url,
                    "Endpoint accessible exposant des secrets en clair"
                ))

    # ---------------------------------------------------------- run
    def run(self):
        print(f"[*] Crawl de {self.base_url} ...")
        self.crawl()
        print(f"[*] {len(self.visited)} pages découvertes")
        print("[*] Tests actifs...")
        self.test_sqli_login()
        self.test_xss_reflected()
        self.test_idor_profile()
        self.test_command_injection()
        self.test_path_traversal()
        self.test_ssrf()
        self.test_insecure_deserialization()
        self.test_common_paths()
        self.test_csrf_missing()
        return self.findings


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    args = ap.parse_args()
    scanner = MiniScanner(args.url)
    findings = scanner.run()
    print(f"\n=== {len(findings)} findings ===")
    for f in findings:
        print(f"[{f.severity:8s}] {f.vuln:30s} {f.url}\n    -> {f.evidence}")