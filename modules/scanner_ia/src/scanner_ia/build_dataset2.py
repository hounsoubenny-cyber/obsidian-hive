#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 19 21:16:54 2026

@author: hounsousamuel
"""

"""
build_dataset.py — Construit le dataset d'entraînement ScannerIA à partir de
TOUTES les sources non-redondantes disponibles (v1, bWAPP/Juice Shop → v1.1).

Sources retenues (voir PORTS.md pour le détail et les sources écartées) :
  - vulnmart              (Flask maison, vulnérable)   port 5000
  - vuln_server_v3_0_2    (Flask maison, vulnérable, 110 routes -
                            superset vérifié de v1/v2/v3/v3_0_1)  port 5001
  - vuln_static_site      (HTML statique, vulnérable)  port 8090
  - DVWA                  (Docker, vulnérable)          port 8081
  - test_site             (HTML statique, SAFE)         port 8080
  - train_server_for_tfidf(Flask maison, SAFE)          port 7000

Principe : on réutilise EXACTEMENT le même pipeline que
features_extractor.test_features() (AnalyzerHelper -> CodeAnalyzer ->
PassiveCodeAnalyzer -> Fuzzer -> FeatureExtractor), avec un label CONNU À
L'AVANCE (code source / doc / manifest lus et vérifiés un par un, jamais
deviné) pour chaque URL. "SAFE" n'est plus une classe : page saine = [].

⚠️ MAX_DEEPTH=0 : on scanne UNE SEULE page par URL fournie.
⚠️ N'utilise ça QUE sur des instances que tu héberges toi-même.
⚠️ Ne JAMAIS scanner un site tiers (google.com etc.) sans autorisation —
   c'est illégal même pour un scan passif. Toutes les cibles ci-dessous
   sont des serveurs que tu héberges localement.

Auth : système `helpers` maison (auth_helpers.py / helpers_registry.py /
resolve_helpers.py) — `analyse_and_parse_all(..., helpers=[...])` accepte
une liste de dict `{"name": ..., "kwargs": {...}}`, résolue et exécutée en
interne avant le crawl.
"""

import asyncio
import aiohttp
import pandas as pd

from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.fuzzer.active_fuzzer import Fuzzer
from scanner_ia.ml_model.features_extractor import FeatureExtractor
from scanner_ia.scanner_utils.logger import get_logger

logger = get_logger()

# ─────────────────────────────────────────────────────────────────────────
# 1. VULNMART — tiré de vulnmart/README.md (fiable à 100%).
# ─────────────────────────────────────────────────────────────────────────

VULNMART_BASE = "http://localhost:5000"

HELPERS_VULNMART = [
    {"name": "form_login", "kwargs": {
        "login_url": f"{VULNMART_BASE}/login",
        "username_field": "username", "password_field": "password",
        "username": "admin", "password": "admin123",
    }},
    {"name": "inject_cookies", "kwargs": {"cookies": {"is_admin": "true"}}},
]

LABELS_VULNMART = {
    f"{VULNMART_BASE}/":                    [],
    f"{VULNMART_BASE}/login":                ["SQLi", "InfoDisc", "BrokenAuth", "JWT", "RateLimit"],
    f"{VULNMART_BASE}/search?q=test":        ["XSS"],
    f"{VULNMART_BASE}/product/1":            ["IDOR", "XSS"],
    f"{VULNMART_BASE}/profile/alice":         ["IDOR", "InfoDisc"],
    f"{VULNMART_BASE}/api/user/1":            ["IDOR", "InfoDisc"],
    f"{VULNMART_BASE}/admin":                 ["InsecPerm"],
    f"{VULNMART_BASE}/upload":                ["InsecUpload"],
    f"{VULNMART_BASE}/file?name=README.md":   ["DirTrav"],
    f"{VULNMART_BASE}/ping":                  ["CMDi"],
    f"{VULNMART_BASE}/fetch-image":           ["SSRF"],
    f"{VULNMART_BASE}/cart/import":           ["InsecDeser"],
    f"{VULNMART_BASE}/account/change-email":  ["CSRF"],
    f"{VULNMART_BASE}/reset-password":        ["BrokenAuth"],
    f"{VULNMART_BASE}/config":                ["InfoDisc", "CredsExpose"],
    f"{VULNMART_BASE}/comments":               ["XSS"],
}

# ─────────────────────────────────────────────────────────────────────────
# 2. VULN_SERVER_V3_0_2 — le plus complet (110 routes), superset vérifié de
#    v1/v2/v3/v3_0_1. Labels croisés route par route avec le vrai code
#    source (98% de correspondance directe, le reste = routes paramétrées
#    remplies avec un ID concret ci-dessous). Port 5001 — voir PORTS.md
#    pour pourquoi (collision avec vulnmart sur 5000 sinon).
# ─────────────────────────────────────────────────────────────────────────

VS_BASE = "http://localhost:5001"
HELPERS_VULN_SERVER = []  # pas d'auth sur ce serveur

LABELS_VULN_SERVER = {
    f"{VS_BASE}/":                        [],
    # XSS
    f"{VS_BASE}/xss/reflected":           ["XSS"],
    f"{VS_BASE}/xss/stored":              ["XSS"],
    f"{VS_BASE}/xss/header":              ["XSS"],
    f"{VS_BASE}/xss/json":                ["XSS"],
    f"{VS_BASE}/xss/attr":                ["XSS"],
    # SQLi
    f"{VS_BASE}/sqli/search":             ["SQLi"],
    f"{VS_BASE}/sqli/login":              ["SQLi"],
    f"{VS_BASE}/sqli/union":              ["SQLi"],
    f"{VS_BASE}/sqli/time":               ["SQLi"],
    f"{VS_BASE}/sqli/blind":              ["SQLi"],
    f"{VS_BASE}/sqli/cookie":             ["SQLi"],
    # CMDi
    f"{VS_BASE}/cmdi/ping":               ["CMDi"],
    f"{VS_BASE}/cmdi/system":             ["CMDi"],
    f"{VS_BASE}/cmdi/lookup":             ["CMDi"],
    # DirTrav (payload encodé pour éviter la normalisation client des "..")
    f"{VS_BASE}/file/read":               ["DirTrav"],
    f"{VS_BASE}/download":                ["DirTrav"],
    f"{VS_BASE}/template":                ["DirTrav"],
    f"{VS_BASE}/static_file/..%2f..%2f..%2fetc%2fpasswd": ["DirTrav"],
    # XXE
    f"{VS_BASE}/xml/parse":               ["XXE"],
    f"{VS_BASE}/xml/import":              ["XXE"],
    f"{VS_BASE}/xml/soap":                ["XXE"],
    # SSRF
    f"{VS_BASE}/ssrf/fetch":              ["SSRF"],
    f"{VS_BASE}/ssrf/preview":            ["SSRF"],
    f"{VS_BASE}/ssrf/avatar":             ["SSRF"],
    f"{VS_BASE}/ssrf/webhook":            ["SSRF"],
    # SSTI
    f"{VS_BASE}/ssti/greet":              ["SSTI"],
    f"{VS_BASE}/ssti/render":             ["SSTI"],
    f"{VS_BASE}/ssti/email":              ["SSTI"],
    # NoSQLi
    f"{VS_BASE}/nosql/login":             ["NoSQLi"],
    f"{VS_BASE}/nosql/search":            ["NoSQLi"],
    f"{VS_BASE}/nosql/users":             ["NoSQLi"],
    # CRLF
    f"{VS_BASE}/crlf/header":             ["CRLF_Injection"],
    f"{VS_BASE}/crlf/redirect":           ["CRLF_Injection"],
    f"{VS_BASE}/crlf/log":                ["CRLF_Injection"],
    # JWT
    f"{VS_BASE}/jwt/login":               ["JWT"],
    f"{VS_BASE}/jwt/profile":             ["JWT"],
    f"{VS_BASE}/jwt/admin":               ["JWT"],
    # GraphQL
    f"{VS_BASE}/graphql":                 ["GraphQLi"],
    f"{VS_BASE}/graphql/playground":      ["GraphQLi"],
    # IDOR (routes paramétrées -> ID concret = 1)
    f"{VS_BASE}/api/users/1":             ["IDOR"],
    f"{VS_BASE}/api/documents/1":         ["IDOR"],
    f"{VS_BASE}/api/invoices/1":          ["IDOR"],
    f"{VS_BASE}/api/orders/1":            ["IDOR"],
    # Prototype Pollution
    f"{VS_BASE}/proto/merge":             ["Prototype_Pollution"],
    f"{VS_BASE}/proto/extend":            ["Prototype_Pollution"],
    # InsecDeser (renommé /deserialize/* -> /deser/* dans v3_0_2)
    f"{VS_BASE}/deser/json":              ["InsecDeser"],
    f"{VS_BASE}/deser/pickle":            ["InsecDeser"],
    f"{VS_BASE}/deser/cookie":            ["InsecDeser"],
    # InfoDisc
    f"{VS_BASE}/.env":                    ["InfoDisc"],
    f"{VS_BASE}/.env.local":              ["InfoDisc"],
    f"{VS_BASE}/.env.staging":            ["InfoDisc"],
    f"{VS_BASE}/.env.production":         ["InfoDisc"],
    f"{VS_BASE}/.git/config":             ["InfoDisc"],
    f"{VS_BASE}/debug":                   ["InfoDisc"],
    f"{VS_BASE}/actuator/env":            ["InfoDisc", "CredsExpose"],
    f"{VS_BASE}/actuator/heapdump":       ["InfoDisc"],
    f"{VS_BASE}/swagger.json":            ["InfoDisc"],
    f"{VS_BASE}/phpinfo":                 ["InfoDisc"],
    # CredsExpose
    f"{VS_BASE}/.aws/credentials":        ["CredsExpose"],
    f"{VS_BASE}/config.json":             ["CredsExpose"],
    f"{VS_BASE}/id_rsa":                  ["CredsExpose"],
    f"{VS_BASE}/database.yml":            ["CredsExpose"],
    f"{VS_BASE}/secrets.yml":             ["CredsExpose"],
    f"{VS_BASE}/wp-config.php":           ["CredsExpose"],
    f"{VS_BASE}/.netrc":                  ["CredsExpose"],
    f"{VS_BASE}/backup.sql":              ["CredsExpose"],
    f"{VS_BASE}/credentials.json":        ["CredsExpose"],
    # BrokenAuth
    f"{VS_BASE}/auth/login":              ["BrokenAuth"],
    f"{VS_BASE}/auth/reset":              ["BrokenAuth"],
    f"{VS_BASE}/auth/token":              ["BrokenAuth"],
    # InsecPerm
    f"{VS_BASE}/admin":                   ["InsecPerm"],
    f"{VS_BASE}/admin/users":             ["InsecPerm"],
    f"{VS_BASE}/api/admin":               ["InsecPerm"],
    f"{VS_BASE}/phpmyadmin":              ["InsecPerm"],
    f"{VS_BASE}/manager/html":            ["InsecPerm"],
    f"{VS_BASE}/cpanel":                  ["InsecPerm"],
    # SessFix
    f"{VS_BASE}/session/fixate":          ["SessFix"],
    f"{VS_BASE}/session/weak":            ["SessFix"],
    f"{VS_BASE}/session/info":            ["SessFix"],
    # BufOvr
    f"{VS_BASE}/bufovr/input":            ["BufOvr"],
    f"{VS_BASE}/bufovr/format":           ["BufOvr"],
    f"{VS_BASE}/bufovr/header":           ["BufOvr"],
    # XPath
    f"{VS_BASE}/xpath/login":             ["XPATH_Injection"],
    f"{VS_BASE}/xpath/search":            ["XPATH_Injection"],
    # OpenRedirect
    f"{VS_BASE}/redirect":                ["OpenRedirect"],
    f"{VS_BASE}/logout":                  ["OpenRedirect"],
    # CORS
    f"{VS_BASE}/cors/api":                ["CORS"],
    f"{VS_BASE}/cors/sensitive":          ["CORS"],
    f"{VS_BASE}/cors/null":               ["CORS"],
    # InsecUpload
    f"{VS_BASE}/upload":                  ["InsecUpload"],
    f"{VS_BASE}/upload/avatar":           ["InsecUpload"],
    # RaceCondition
    f"{VS_BASE}/race/coupon":             ["RaceCondition"],
    f"{VS_BASE}/race/transfer":           ["RaceCondition"],
    f"{VS_BASE}/race/vote":               ["RaceCondition"],
    # RateLimit
    f"{VS_BASE}/ratelimit/api":           ["RateLimit"],
    f"{VS_BASE}/ratelimit/xff":           ["RateLimit"],
    f"{VS_BASE}/ratelimit/login":         ["RateLimit", "BrokenAuth"],
    # LDAPi
    f"{VS_BASE}/ldap/login":              ["LDAPi"],
    f"{VS_BASE}/ldap/search":             ["LDAPi"],
    # HTTP Smuggling
    f"{VS_BASE}/smuggle/endpoint":        ["HTTP_Request_Smuggling"],
    f"{VS_BASE}/smuggle/te-te":           ["HTTP_Request_Smuggling"],
    # InsecCrypto
    f"{VS_BASE}/crypto/hash":             ["InsecCrypto"],
    f"{VS_BASE}/crypto/token":            ["InsecCrypto"],
    f"{VS_BASE}/crypto/tls-info":         ["InsecCrypto"],
    # CSRF
    f"{VS_BASE}/csrf/transfer":           ["CSRF"],
    f"{VS_BASE}/csrf/delete":             ["CSRF"],
    f"{VS_BASE}/csrf/email":              ["CSRF"],
    f"{VS_BASE}/csrf/password":           ["CSRF"],
}

# ─────────────────────────────────────────────────────────────────────────
# 3. VULN_STATIC_SITE — repris de manifest.json, ["SAFE"] -> [].
# ─────────────────────────────────────────────────────────────────────────

STATIC_BASE = "http://localhost:8090"
HELPERS_STATIC = []

LABELS_STATIC_SITE = {
    f"{STATIC_BASE}/index.html":               ["InfoDisc"],
    f"{STATIC_BASE}/page_xss_dom.html":        ["XSS"],
    f"{STATIC_BASE}/page_secrets.html":        ["CredsExpose"],
    f"{STATIC_BASE}/page_outdated_lib.html":   ["XSS", "InsecCrypto"],
    f"{STATIC_BASE}/page_form_csrf.html":      ["CSRF"],
    f"{STATIC_BASE}/page_clickjack.html":      ["InfoDisc"],
    f"{STATIC_BASE}/page_info_disclosure.html":["InfoDisc", "CredsExpose"],
    f"{STATIC_BASE}/page_safe.html":           [],
    f"{STATIC_BASE}/.env":                     ["CredsExpose", "InfoDisc"],
}

# ─────────────────────────────────────────────────────────────────────────
# 4. DVWA — auth via ton helper dédié dvwa_auth.
# ─────────────────────────────────────────────────────────────────────────

DVWA_BASE = "http://localhost:8081"
HELPERS_DVWA = [
    {"name": "dvwa_auth", "kwargs": {
        "base_url": DVWA_BASE, "username": "admin", "password": "password",
        "security_level": "low",
    }},
]

LABELS_DVWA = {
    f"{DVWA_BASE}/vulnerabilities/sqli/":        ["SQLi"],
    f"{DVWA_BASE}/vulnerabilities/sqli_blind/":  ["SQLi"],
    f"{DVWA_BASE}/vulnerabilities/xss_r/":       ["XSS"],
    f"{DVWA_BASE}/vulnerabilities/xss_s/":       ["XSS"],
    f"{DVWA_BASE}/vulnerabilities/xss_d/":       ["XSS"],
    f"{DVWA_BASE}/vulnerabilities/exec/":        ["CMDi"],
    f"{DVWA_BASE}/vulnerabilities/csrf/":        ["CSRF"],
    f"{DVWA_BASE}/vulnerabilities/fi/":          ["DirTrav"],
    f"{DVWA_BASE}/vulnerabilities/upload/":      ["InsecUpload"],
    f"{DVWA_BASE}/vulnerabilities/brute/":       ["BrokenAuth"],
    f"{DVWA_BASE}/vulnerabilities/weak_id/":     ["SessFix"],
    f"{DVWA_BASE}/login.php":                    [],
    f"{DVWA_BASE}/index.php":                    [],
}

# ─────────────────────────────────────────────────────────────────────────
# 5. SAFE — test_site (statique, 100% safe, servi directement — pas besoin
#    de local_serveur.py qui génère exactement le même contenu) + 
#    train_server_for_tfidf (e-commerce/blog simulé, safe, vérifié sans
#    eval/exec/os.system/pickle.loads).
#    Échantillonnage de test_site (10/51 pages) plutôt que tout scanner :
#    les 51 pages sont structurellement quasi-identiques (générées par le
#    même template), pas besoin de toutes les passer pour la diversité.
# ─────────────────────────────────────────────────────────────────────────

TESTSITE_BASE = "http://localhost:8080"
HELPERS_TESTSITE = []

LABELS_TESTSITE = {
    f"{TESTSITE_BASE}/":                    [],
    f"{TESTSITE_BASE}/level1/page0.html":  [],
    f"{TESTSITE_BASE}/level1/page5.html":  [],
    f"{TESTSITE_BASE}/level2/page0.html":  [],
    f"{TESTSITE_BASE}/level2/page5.html":  [],
    f"{TESTSITE_BASE}/level3/page0.html":  [],
    f"{TESTSITE_BASE}/level3/page5.html":  [],
    f"{TESTSITE_BASE}/level4/page0.html":  [],
    f"{TESTSITE_BASE}/level5/page0.html":  [],
    f"{TESTSITE_BASE}/level5/page9.html":  [],
}

TRAINSERVER_BASE = "http://localhost:7000"
HELPERS_TRAINSERVER = []

LABELS_TRAINSERVER = {
    f"{TRAINSERVER_BASE}/":                        [],
    f"{TRAINSERVER_BASE}/about":                    [],
    f"{TRAINSERVER_BASE}/contact":                  [],
    f"{TRAINSERVER_BASE}/faq":                      [],
    f"{TRAINSERVER_BASE}/privacy":                  [],
    f"{TRAINSERVER_BASE}/terms":                    [],
    f"{TRAINSERVER_BASE}/shop":                     [],
    f"{TRAINSERVER_BASE}/shop/product/1":           [],
    f"{TRAINSERVER_BASE}/shop/cart":                [],
    f"{TRAINSERVER_BASE}/shop/checkout":            [],
    f"{TRAINSERVER_BASE}/blog":                     [],
    f"{TRAINSERVER_BASE}/blog/1":                   [],
    f"{TRAINSERVER_BASE}/login":                    [],
    f"{TRAINSERVER_BASE}/register":                 [],
    f"{TRAINSERVER_BASE}/dashboard":                [],
    f"{TRAINSERVER_BASE}/search?q=test":            [],
    f"{TRAINSERVER_BASE}/api/v1/products":          [],
    f"{TRAINSERVER_BASE}/api/v1/products/1":        [],
    f"{TRAINSERVER_BASE}/api/v1/users":              [],
    f"{TRAINSERVER_BASE}/api/v1/health":             [],
    f"{TRAINSERVER_BASE}/api/v1/categories":         [],
    f"{TRAINSERVER_BASE}/api/v1/stats":              [],
    f"{TRAINSERVER_BASE}/feed.rss":                  [],
    f"{TRAINSERVER_BASE}/sitemap.xml":               [],
}

# ─────────────────────────────────────────────────────────────────────────
# 6. bWAPP / Juice Shop — v1.1 (voir décision de scope du 19/08). Auth déjà
#    prête (bwapp_auth, juice_shop_auth), labels à faire quand on y passe.
# ─────────────────────────────────────────────────────────────────────────

BWAPP_BASE = "http://localhost:8082"
HELPERS_BWAPP = [{"name": "bwapp_auth", "kwargs": {"base_url": BWAPP_BASE}}]
LABELS_BWAPP = {}

JUICESHOP_BASE = "http://localhost:3000"
HELPERS_JUICESHOP = [{"name": "juice_shop_auth", "kwargs": {"base_url": JUICESHOP_BASE}}]
LABELS_JUICESHOP = {}

# ─────────────────────────────────────────────────────────────────────────
# 7. Assemblage
# ─────────────────────────────────────────────────────────────────────────

GROUPS = [
    (LABELS_VULNMART,     False, HELPERS_VULNMART),
    (LABELS_VULN_SERVER,  False, HELPERS_VULN_SERVER),
    (LABELS_STATIC_SITE,  False, HELPERS_STATIC),
    (LABELS_DVWA,         False, HELPERS_DVWA),
    (LABELS_TESTSITE,     False, HELPERS_TESTSITE),
    (LABELS_TRAINSERVER,  False, HELPERS_TRAINSERVER),
    (LABELS_BWAPP,        False, HELPERS_BWAPP),       # vide pour l'instant (v1.1)
    (LABELS_JUICESHOP,    True,  HELPERS_JUICESHOP),    # vide pour l'instant (v1.1)
]

ALL_TARGETS = [
    (url, vulns, is_spa, helpers)
    for labels, is_spa, helpers in GROUPS
    for url, vulns in labels.items()
]


# ─────────────────────────────────────────────────────────────────────────
# 8. PIPELINE
# ─────────────────────────────────────────────────────────────────────────

async def build_dataset(targets: list, max_test: int = 100, out_path: str = "./dataset_mvp"):
    rows = []
    async with aiohttp.ClientSession() as session:
        an = AnalyzerHelper(session=session, use_cache=False, MAX_DEEPTH=2)
        ca = CodeAnalyzer(True)
        pa = PassiveCodeAnalyzer()
        fuzzer = Fuzzer(session=session)
        fuzzer.config.MAX_TEST = max_test
        fe = FeatureExtractor()

        total = len(targets)
        for i, (url, vulns, is_spa, helpers) in enumerate(targets, 1):
            names = [h["name"] for h in helpers] if helpers else []
            logger.info(f"[{i}/{total}] {url} -> {vulns or 'SAFE'} (is_spa={is_spa}, helpers={names})")
            try:
                analyzer_response = await an.analyse_and_parse_all(
                    url, verify_reachability=True, restore=False, silent=True,
                    is_spa=is_spa, helpers=helpers or None,
                )
                if not analyzer_response.elements:
                    logger.warning(f"  ⚠️  Aucune page récupérée pour {url}, skip")
                    continue

                ca_result = ca.analyse(analyzer_response)
                pa_result = pa.analyse(analyzer_response)
                fuzzer_result = await fuzzer.fuzz(url, analyzer_response, dynamic_timeout=True)

                features_df = await fe.extract(analyzer_response, pa_result, ca_result, fuzzer_result)

                if "url" in features_df.columns:
                    matching = features_df[features_df["url"] == url]
                    row_df = matching if not matching.empty else features_df.iloc[[0]]
                else:
                    row_df = features_df.iloc[[0]]

                row = row_df.iloc[0].to_dict()
                row["url"] = url
                row["labels"] = vulns
                rows.append(row)

            except Exception as e:
                logger.error(f"  ❌ Erreur sur {url} : {e}")
                continue

    dataset = pd.DataFrame(rows)
    logger.info(f"Dataset construit : {dataset.shape[0]} lignes, {dataset.shape[1]} colonnes")

    if not dataset.empty:
        FeatureExtractor.save_dataset(dataset, out_path)
        from collections import Counter
        counts = Counter(v for vulns in dataset["labels"] for v in vulns)
        counts["SAFE (labels=[])"] = sum(1 for vulns in dataset["labels"] if not vulns)
        logger.info("Répartition des classes :")
        for k, v in sorted(counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {k}: {v}")

    return dataset


if __name__ == "__main__":
    # v1 : tout sauf bWAPP / Juice Shop (labels vides -> aucune requête générée
    # de toute façon, mais on filtre explicitement par clarté).
    v1_targets = [
        t for t in ALL_TARGETS
        if not t[0].startswith(BWAPP_BASE) and not t[0].startswith(JUICESHOP_BASE)
    ]
    asyncio.run(build_dataset(v1_targets, max_test=100, out_path="./dataset_mvp"))