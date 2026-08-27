#!/usr/bin/env python3
"""
ShieldAI — Dataset Generator (unified)
Génère un dataset labellisé à partir des 4 serveurs de test.
Usage : python generate_dataset.py
"""

import os, sys, json, time, subprocess, asyncio, aiohttp
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

# ── Config chemins ───────────────────────────────────────────────────────────
PROJECT_ROOT    = Path(__file__).resolve().parent
SCANNER_DIR     = PROJECT_ROOT / "scanner_ia"
SERVEURS_DIR    = SCANNER_DIR / "serveurs"
VULN_SERVER_V3  = SERVEURS_DIR / "vuln_server_v3.py"
VULN_SERVER_V2  = SERVEURS_DIR / "vuln_server_v2.py"
LOCAL_SERVER    = SERVEURS_DIR / "local_serveur.py"
SAFE_SERVER     = SERVEURS_DIR / "train_server_for_tfidf.py"
OUTPUT_DIR      = PROJECT_ROOT / "dataset"
OUTPUT_CSV      = OUTPUT_DIR / "shieldai_dataset.csv"
OUTPUT_META     = OUTPUT_DIR / "shieldai_dataset_meta.json"

sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

# ── Imports ShieldAI ─────────────────────────────────────────────────────────
from scanner_ia.core.analyzer_helper         import AnalyzerHelper
from scanner_ia.analyzers.passive_analyzer   import PassiveCodeAnalyzer
from scanner_ia.analyzers.code_analyzer      import CodeAnalyzer
from scanner_ia.fuzzer.active_fuzzer         import Fuzzer
from scanner_ia.ml_model.features_extractor  import FeatureExtractor
from scanner_ia.ml_model.config              import VULNS, FEATURES_LIST

# ── Configuration ─────────────────────────────────────────────────────────────
VULN_SERVER_V3_PORT  = 5000
VULN_SERVER_V2_PORT  = 6000
LOCAL_SERVER_PORT    = 8080
SAFE_SERVER_PORT     = 7000
CONCURRENCY          = 2
FUZZER_LIMIT_VULN    = None       # None = toutes, ou 3-5 pour test rapide

# ── Mapping endpoint → labels (vuln_server_v3) ───────────────────────────────
VULN_SERVER_V3_LABELS = {
    # XSS
    "/xss/reflected":          ["XSS"],
    "/xss/stored":             ["XSS"],
    "/xss/header":             ["XSS"],
    "/xss/json":               ["XSS"],
    "/xss/attr":               ["XSS"],
    # SQLi
    "/sqli/search":            ["SQLi"],
    "/sqli/login":             ["SQLi"],
    "/sqli/union":             ["SQLi"],
    "/sqli/time":              ["SQLi"],
    "/sqli/blind":             ["SQLi"],
    "/sqli/cookie":            ["SQLi"],
    # CMDi
    "/cmdi/ping":              ["CMDi"],
    "/cmdi/system":            ["CMDi"],
    "/cmdi/lookup":            ["CMDi"],
    # DirTrav
    "/file/read":              ["DirTrav"],
    "/download":               ["DirTrav"],
    "/template":               ["DirTrav"],
    "/static_file/../etc/passwd": ["DirTrav"],
    # XXE
    "/xml/parse":              ["XXE"],
    "/xml/import":             ["XXE"],
    "/xml/soap":               ["XXE"],
    # SSRF
    "/ssrf/fetch":             ["SSRF"],
    "/ssrf/preview":           ["SSRF"],
    "/ssrf/avatar":            ["SSRF"],
    "/ssrf/webhook":           ["SSRF"],
    # SSTI
    "/ssti/greet":             ["SSTI"],
    "/ssti/render":            ["SSTI"],
    "/ssti/email":             ["SSTI"],
    # NoSQLi
    "/nosql/login":            ["NoSQLi"],
    "/nosql/search":           ["NoSQLi"],
    "/nosql/users":            ["NoSQLi"],
    # CRLF
    "/crlf/header":            ["CRLF_Injection"],
    "/crlf/redirect":          ["CRLF_Injection"],
    "/crlf/log":               ["CRLF_Injection"],
    # JWT
    "/jwt/login":              ["JWT"],
    "/jwt/profile":            ["JWT"],
    "/jwt/admin":              ["JWT"],
    # GraphQL
    "/graphql":                ["GraphQLi"],
    "/graphql/playground":     ["GraphQLi"],
    # IDOR
    "/api/users/1":            ["IDOR"],
    "/api/documents/1":        ["IDOR"],
    "/api/invoices/1":         ["IDOR"],
    "/api/orders/1":           ["IDOR"],
    # Prototype Pollution
    "/proto/merge":            ["Prototype_Pollution"],
    "/proto/extend":           ["Prototype_Pollution"],
    # InsecDeser
    "/deser/json":             ["InsecDeser"],
    "/deser/pickle":           ["InsecDeser"],
    "/deser/cookie":           ["InsecDeser"],
    # InfoDisc
    "/.env":                   ["InfoDisc"],
    "/.git/config":            ["InfoDisc"],
    "/debug":                  ["InfoDisc"],
    "/actuator/env":           ["InfoDisc", "CredsExpose"],
    "/actuator/heapdump":      ["InfoDisc"],
    "/swagger.json":           ["InfoDisc"],
    "/phpinfo":                ["InfoDisc"],
    # CredsExpose
    "/.aws/credentials":       ["CredsExpose"],
    "/config.json":            ["CredsExpose"],
    "/id_rsa":                 ["CredsExpose"],
    "/database.yml":           ["CredsExpose"],
    "/secrets.yml":            ["CredsExpose"],
    "/wp-config.php":          ["CredsExpose"],
    "/.netrc":                 ["CredsExpose"],
    "/backup.sql":             ["CredsExpose"],
    "/credentials.json":       ["CredsExpose"],
    # BrokenAuth
    "/auth/login":             ["BrokenAuth"],
    "/auth/reset":             ["BrokenAuth"],
    "/auth/token":             ["BrokenAuth"],
    # InsecPerm
    "/admin":                  ["InsecPerm"],
    "/admin/users":            ["InsecPerm"],
    "/api/admin":              ["InsecPerm"],
    "/phpmyadmin":             ["InsecPerm"],
    "/manager/html":           ["InsecPerm"],
    "/cpanel":                 ["InsecPerm"],
    # SessFix
    "/session/fixate":         ["SessFix"],
    "/session/weak":           ["SessFix"],
    "/session/info":           ["SessFix"],
    # BufOvr
    "/bufovr/input":           ["BufOvr"],
    "/bufovr/format":          ["BufOvr"],
    "/bufovr/header":          ["BufOvr"],
    # XPath
    "/xpath/login":            ["XPATH_Injection"],
    "/xpath/search":           ["XPATH_Injection"],
    # OpenRedirect
    "/redirect":               ["OpenRedirect"],
    "/logout":                 ["OpenRedirect"],
    "/login":                  ["OpenRedirect"],
    # CORS
    "/cors/api":               ["CORS"],
    "/cors/sensitive":         ["CORS"],
    "/cors/null":              ["CORS"],
    # InsecUpload
    "/upload":                 ["InsecUpload"],
    "/upload/avatar":          ["InsecUpload"],
    # RaceCondition
    "/race/coupon":            ["RaceCondition"],
    "/race/transfer":          ["RaceCondition"],
    "/race/vote":              ["RaceCondition"],
    # RateLimit
    "/ratelimit/api":          ["RateLimit"],
    "/ratelimit/xff":          ["RateLimit"],
    "/ratelimit/login":        ["RateLimit", "BrokenAuth"],
    # LDAPi
    "/ldap/login":             ["LDAPi"],
    "/ldap/search":            ["LDAPi"],
    # HTTP Smuggling
    "/smuggle/endpoint":       ["HTTP_Request_Smuggling"],
    "/smuggle/te-te":          ["HTTP_Request_Smuggling"],
    # InsecCrypto
    "/crypto/hash":            ["InsecCrypto"],
    "/crypto/token":           ["InsecCrypto"],
    "/crypto/tls-info":        ["InsecCrypto"],
    # CSRF
    "/csrf/transfer":          ["CSRF"],
    "/csrf/delete":            ["CSRF"],
    "/csrf/email":             ["CSRF"],
    "/csrf/password":          ["CSRF"],
    # Safe pages (vuln server)
    "/":                       [],
}

# ── Mapping endpoint → labels (vuln_server_v2) ───────────────────────────────
VULN_SERVER_V2_LABELS = {
    "/sqli/search":            ["SQLi"],
    "/sqli/login":             ["SQLi"],
    "/sqli/union":             ["SQLi"],
    "/sqli/time":              ["SQLi"],
    "/sqli/blind":             ["SQLi"],
    "/sqli/cookie":            ["SQLi"],
    "/xss/reflected":          ["XSS"],
    "/xss/stored":             ["XSS"],
    "/xss/dom":                ["XSS"],
    "/xss/header":             ["XSS"],
    "/xss/json":               ["XSS"],
    "/xss/attr":               ["XSS"],
    "/cmdi/ping":              ["CMDi"],
    "/cmdi/system":            ["CMDi"],
    "/cmdi/lookup":            ["CMDi"],
    "/cmdi/convert":           ["CMDi"],
    "/file/read":              ["DirTrav"],
    "/download":               ["DirTrav"],
    "/static_file/test.txt":   ["DirTrav"],
    "/template":               ["DirTrav"],
    "/xml/parse":              ["XXE"],
    "/xml/import":             ["XXE"],
    "/xml/soap":               ["XXE"],
    "/ssrf/fetch":             ["SSRF"],
    "/ssrf/preview":           ["SSRF"],
    "/ssrf/avatar":            ["SSRF"],
    "/ssrf/webhook":           ["SSRF"],
    "/ssti/greet":             ["SSTI"],
    "/ssti/render":            ["SSTI"],
    "/ssti/email":             ["SSTI"],
    "/nosql/login":            ["NoSQLi"],
    "/nosql/search":           ["NoSQLi"],
    "/nosql/users":            ["NoSQLi"],
    "/crlf/header":            ["CRLF_Injection"],
    "/crlf/redirect":          ["CRLF_Injection"],
    "/crlf/log":               ["CRLF_Injection"],
    "/jwt/login":              ["JWT"],
    "/jwt/profile":            ["JWT"],
    "/jwt/admin":              ["JWT"],
    "/graphql":                ["GraphQLi"],
    "/graphql/playground":     ["GraphQLi"],
    "/api/users/1":            ["IDOR"],
    "/api/documents/1":        ["IDOR"],
    "/api/orders/1":           ["IDOR"],
    "/api/invoices/1":         ["IDOR"],
    "/proto/merge":            ["Prototype_Pollution"],
    "/proto/extend":           ["Prototype_Pollution"],
    "/deserialize/pickle":     ["InsecDeser"],
    "/deserialize/json":       ["InsecDeser"],
    "/deserialize/cookie":     ["InsecDeser"],
    "/.env":                   ["InfoDisc", "CredsExpose"],
    "/.git/config":            ["InfoDisc"],
    "/phpinfo":                ["InfoDisc"],
    "/debug":                  ["InfoDisc"],
    "/actuator/env":           ["InfoDisc", "CredsExpose"],
    "/actuator/heapdump":       ["InfoDisc"],
    "/swagger.json":           ["InfoDisc"],
    "/.aws/credentials":       ["CredsExpose"],
    "/wp-config.php":          ["CredsExpose"],
    "/config.json":            ["CredsExpose"],
    "/database.yml":           ["CredsExpose"],
    "/secrets.yml":            ["CredsExpose"],
    "/.netrc":                 ["CredsExpose"],
    "/id_rsa":                 ["CredsExpose"],
    "/auth/login":             ["BrokenAuth"],
    "/auth/reset":             ["BrokenAuth"],
    "/auth/token":             ["BrokenAuth"],
    "/admin":                  ["InsecPerm"],
    "/admin/users":            ["InsecPerm"],
    "/api/admin":              ["InsecPerm"],
    "/session/fixate":         ["SessFix"],
    "/session/weak":           ["SessFix"],
    "/session/info":           ["SessFix"],
    "/bufovr/input":           ["BufOvr"],
    "/bufovr/format":          ["BufOvr"],
    "/bufovr/header":          ["BufOvr"],
    "/xpath/login":            ["XPATH_Injection"],
    "/xpath/search":           ["XPATH_Injection"],
    "/redirect":               ["OpenRedirect"],
    "/logout":                 ["OpenRedirect"],
    "/login":                  ["OpenRedirect"],
    "/cors/api":               ["CORS"],
    "/cors/sensitive":         ["CORS"],
    "/cors/null":              ["CORS"],
    "/upload":                 ["InsecUpload"],
    "/upload/avatar":          ["InsecUpload"],
    "/race/coupon":            ["RaceCondition"],
    "/race/transfer":          ["RaceCondition"],
    "/race/vote":              ["RaceCondition"],
    "/ratelimit/api":          ["RateLimit"],
    "/ratelimit/xff":          ["RateLimit"],
    "/ratelimit/login":        ["RateLimit", "BrokenAuth"],
    "/ldap/login":             ["LDAPi"],
    "/ldap/search":            ["LDAPi"],
    "/csrf/transfer":          ["CSRF"],
    "/csrf/delete":            ["CSRF"],
    "/csrf/email":             ["CSRF"],
    "/csrf/password":          ["CSRF"],
    "/smuggle/endpoint":       ["HTTP_Request_Smuggling"],
    "/smuggle/te-te":          ["HTTP_Request_Smuggling"],
    "/crypto/hash":            ["InsecCrypto"],
    "/crypto/token":           ["InsecCrypto"],
    "/crypto/tls-info":        ["InsecCrypto"],
    "/":                       [],
}

# ── Chemins SAFE ─────────────────────────────────────────────────────────────

# local_serveur.py (port 8080) — pages HTML générées aléatoirement
LOCAL_SERVER_PATHS = [
    "/",
    "/level1/page0.html", "/level1/page1.html", "/level1/page2.html",
    "/level2/page0.html", "/level2/page1.html", "/level2/page2.html",
    "/level3/page0.html", "/level3/page1.html",
    "/about.html", "/contact.html", "/privacy.html", "/terms.html",
    "/sitemap.xml",
]

# train_server_for_tfidf.py (port 7000) — e-commerce/blog simulé
SAFE_SERVER_PATHS = [
    "/", "/about", "/contact", "/privacy", "/terms", "/faq",
    "/shop", "/shop?category=electronics", "/shop?category=books",
    "/shop/product/1", "/shop/product/2", "/shop/product/3",
    "/shop/product/4", "/shop/product/5",
    "/shop/cart", "/shop/checkout",
    "/blog", "/blog?tag=security", "/blog/1", "/blog/2", "/blog/3",
    "/login", "/register", "/dashboard", "/forgot-password",
    "/search?q=test",
    "/api/v1/products", "/api/v1/users", "/api/v1/articles",
    "/api/v1/health", "/api/v1/categories", "/api/v1/stats",
    "/feed.rss", "/sitemap.xml",
    "/api/v1/export/products.xml",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def start_server(script_path: str, port: int) -> subprocess.Popen:
    """Lance un serveur Flask en arrière-plan."""
    proc = subprocess.Popen(
        [sys.executable, str(script_path)],
        env={**os.environ, "FLASK_RUN_PORT": str(port)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    return proc


def stop_server(proc: subprocess.Popen):
    """Arrête un serveur."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


# ── Core : extraction features ───────────────────────────────────────────────

async def extract_features_for_url(
    url: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    fuzzer: Fuzzer = None,
) -> dict | None:
    async with semaphore:
        try:
            ah = AnalyzerHelper(session=session, use_cache=False)
            pa = PassiveCodeAnalyzer()
            ca = CodeAnalyzer(debug=False)
            fe = FeatureExtractor()

            ah_result = await ah.analyse_and_parse_all(
                url=url, verify_reachability=False,
                restore=False, fetch=True, silent=True
            )

            if not ah_result.elements:
                return None

            passive_result = pa.analyse(ah_result)
            code_result = ca.analyse(ah_result)

            fuzzer_result = None
            if fuzzer:
                fuzzer_result = await fuzzer.fuzz(
                    base_url=url,
                    analyzer_helper_result=ah_result,
                    limit_vuln=FUZZER_LIMIT_VULN,
                    time_between=0.01,
                    dynamic_timeout=True,
                )

            df = await fe.extract(
                analyzer_helper_result=ah_result,
                passive_analyzer_result=passive_result,
                code_analyzer_result=code_result,
                fuzzer_result=fuzzer_result or _empty_fuzzer_result(),
            )

            if df is None or len(df) == 0:
                return None

            row = df.iloc[0].to_dict()
            row["url"] = url
            return row

        except Exception as e:
            print(f"  ⚠️ Échec {url}: {type(e).__name__} — {e}")
            return None


def _empty_fuzzer_result():
    from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
    return FuzzerResult()


# ── Traitement d'une source ──────────────────────────────────────────────────

async def process_source(
    name: str,
    base_url: str,
    paths_labels: dict | list,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    fuzzer: Fuzzer = None,
) -> list[dict]:
    rows = []
    if isinstance(paths_labels, dict):
        items = list(paths_labels.items())
    else:
        items = [(p, []) for p in paths_labels]
    total = len(items)

    print(f"\n{'─'*55}")
    print(f"  📡 {name} ({total} URLs)")
    print(f"{'─'*55}")

    for i, (path, labels) in enumerate(items, 1):
        url = build_url(base_url, path)
        print(f"  [{i:3d}/{total}] {path[:60]}", end="\r")

        row = await extract_features_for_url(url, session, semaphore, fuzzer)
        if row is None:
            continue

        row["source"] = name
        for v in VULNS:
            row[f"label_{v}"] = 1 if v in labels else 0
        row["labels"] = json.dumps(labels if labels else ["SAFE"])
        row["is_safe"] = int(len(labels) == 0)
        row["n_labels"] = len(labels)

        rows.append(row)

        if i % 10 == 0:
            print(f"  [{i:3d}/{total}] {path[:60]} — {len(rows)} ok")

    print(f"  ✅ {name} : {len(rows)}/{total} extractions réussies")
    return rows


# ── Sauvegarde ────────────────────────────────────────────────────────────────

def save_dataset(all_rows: list[dict]):
    OUTPUT_DIR.mkdir(exist_ok=True)
    df = pd.DataFrame(all_rows)

    meta_cols  = ["url", "source", "labels", "is_safe", "n_labels"]
    label_cols = [c for c in df.columns if c.startswith("label_")]
    feat_cols  = [c for c in df.columns if c not in meta_cols + label_cols]
    col_order  = [c for c in meta_cols + feat_cols + label_cols if c in df.columns]
    df = df[col_order]

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n💾 Dataset : {OUTPUT_CSV} ({len(df)} lignes, {len(feat_cols)} features)")

    vuln_stats = {lc.replace("label_", ""): int(df[lc].sum()) for lc in label_cols}
    source_stats = df["source"].value_counts().to_dict() if "source" in df.columns else {}
    safe_count = int(df["is_safe"].sum()) if "is_safe" in df.columns else 0

    meta = {
        "generated_at": datetime.now().isoformat(),
        "total_samples": len(df),
        "safe_samples": safe_count,
        "vuln_samples": len(df) - safe_count,
        "sources": source_stats,
        "vulns_coverage": vuln_stats,
        "vulns_covered": [v for v, c in vuln_stats.items() if c > 0],
        "vulns_missing": [v for v, c in vuln_stats.items() if c == 0],
        "features": feat_cols,
        "n_features": len(feat_cols),
    }
    with open(OUTPUT_META, "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"📄 Métadonnées : {OUTPUT_META}")

    print(f"\n{'='*55}")
    print(f"  Total   : {len(df)} échantillons")
    print(f"  SAFE    : {safe_count}")
    print(f"  Vuln    : {len(df) - safe_count}")
    print(f"  Features: {len(feat_cols)}")
    print(f"{'='*55}")
    for vn, cnt in sorted(vuln_stats.items(), key=lambda x: -x[1])[:12]:
        print(f"  {vn:<25} {'█' * min(cnt//2, 25)} {cnt}")
    if missing := meta["vulns_missing"]:
        print(f"\n  ⚠️  Vulns sans données : {missing}")


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    print("=" * 55)
    print("🚀 ShieldAI — Dataset Generator (4 serveurs)")
    print("=" * 55)

    # 1. Démarrer les serveurs
    print("\n📡 Démarrage des serveurs...")
    procs = {
        "vuln_v3": start_server(VULN_SERVER_V3, VULN_SERVER_V3_PORT),
        "vuln_v2": start_server(VULN_SERVER_V2, VULN_SERVER_V2_PORT),
        "local":   start_server(LOCAL_SERVER, LOCAL_SERVER_PORT),
        "safe":    start_server(SAFE_SERVER, SAFE_SERVER_PORT),
    }
    for name, port in [("vuln_v3", 5000), ("vuln_v2", 6000), ("local", 8080), ("safe", 7000)]:
        print(f"   ✅ {name:8} → http://localhost:{port}")

    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    session   = aiohttp.ClientSession(connector=connector)
    semaphore = asyncio.Semaphore(CONCURRENCY)
    fuzzer    = Fuzzer(session=session, debug=False, use_semantic=False)

    all_rows = []
    t_start  = time.time()

    try:
        # Source 1 : vuln_server_v3
        rows = await process_source("vuln_server_v3",
            f"http://localhost:{VULN_SERVER_V3_PORT}", VULN_SERVER_V3_LABELS,
            session, semaphore, fuzzer)
        all_rows.extend(rows)

        # Source 2 : vuln_server_v2
        rows = await process_source("vuln_server_v2",
            f"http://localhost:{VULN_SERVER_V2_PORT}", VULN_SERVER_V2_LABELS,
            session, semaphore, fuzzer)
        all_rows.extend(rows)

        # Source 3 : local_serveur (SAFE)
        rows = await process_source("local_serveur",
            f"http://localhost:{LOCAL_SERVER_PORT}", LOCAL_SERVER_PATHS,
            session, semaphore, fuzzer=None)
        all_rows.extend(rows)

        # Source 4 : train_server_for_tfidf (SAFE)
        rows = await process_source("safe_server",
            f"http://localhost:{SAFE_SERVER_PORT}", SAFE_SERVER_PATHS,
            session, semaphore, fuzzer=None)
        all_rows.extend(rows)

    except KeyboardInterrupt:
        print("\n⚠️ Interrompu — sauvegarde en cours...")
    except Exception as e:
        print(f"\n❌ Erreur : {e}")
        import traceback
        traceback.print_exc()
    finally:
        await session.close()
        for proc in procs.values():
            stop_server(proc)

    elapsed = time.time() - t_start
    print(f"\n⏱️  Temps total : {elapsed:.1f}s")

    if all_rows:
        save_dataset(all_rows)
    else:
        print("\n❌ Aucune donnée extraite.")


if __name__ == "__main__":
    asyncio.run(main())