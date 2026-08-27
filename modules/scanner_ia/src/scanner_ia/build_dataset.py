#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 19 11:06:09 2026

@author: hounsousamuel
"""

"""
build_dataset.py — Construit le dataset d'entraînement ScannerIA à partir
des cibles déjà prêtes : vulnmart (Flask maison), vuln_static_site (manifest
déjà écrit), DVWA, bWAPP, Juice Shop.

Principe : on réutilise EXACTEMENT le même pipeline que
features_extractor.test_features() (AnalyzerHelper -> CodeAnalyzer ->
PassiveCodeAnalyzer -> Fuzzer -> FeatureExtractor), mais on associe à chaque
URL un label CONNU À L'AVANCE (doc/README/manifest), au lieu de laisser le
fuzzer "deviner". "SAFE" n'est plus une classe (cf. scanner_ia_v2.py) : une
page saine = labels [] (liste vide), jamais ["SAFE"].

⚠️ MAX_DEEPTH=0 sur l'AnalyzerHelper : on scanne UNE SEULE page par URL
   fournie, sinon le label ne correspond plus forcément à la page analysée.
⚠️ N'utilise ça QUE sur des instances que tu héberges toi-même (Docker local).

Auth : on utilise directement le système `helpers` maison (auth_helpers.py /
helpers_registry.py / resolve_helpers.py) — `analyse_and_parse_all(..., helpers=[...])`
accepte une liste de dict `{"name": ..., "kwargs": {...}}`, résolue et
exécutée en interne AVANT le crawl. Plus de bricolage manuel de cookie_jar.
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
# 1. VULNMART — mapping tiré directement de vulnmart/README.md (fiable à
#    100%, pas de devinette de ma part). Auth via form_login + inject_cookies
#    (pas de helper dédié "vulnmart_auth" chez toi -> on compose avec les
#    briques génériques déjà là).
# ─────────────────────────────────────────────────────────────────────────

VULNMART_BASE = "http://localhost:5000"  # adapte le port à ton instance

HELPERS_VULNMART = [
    {"name": "form_login", "kwargs": {
        "login_url": f"{VULNMART_BASE}/login",
        "username_field": "username", "password_field": "password",
        "username": "admin", "password": "admin123",
    }},
    # cookie is_admin=true : la faille #12 (contrôle admin trivialement
    # falsifiable côté client) -> sans ça, /admin reste sur admin_denied.html
    # et fausserait le label.
    {"name": "inject_cookies", "kwargs": {"cookies": {"is_admin": "true"}}},
]

LABELS_VULNMART = {
    f"{VULNMART_BASE}/":                              [],
    f"{VULNMART_BASE}/login":                          ["SQLi", "InfoDisc", "BrokenAuth", "JWT", "RateLimit"],
    f"{VULNMART_BASE}/search?q=test":                  ["XSS"],
    f"{VULNMART_BASE}/product/1":                      ["IDOR", "XSS"],
    f"{VULNMART_BASE}/profile/alice":                   ["IDOR", "InfoDisc"],
    f"{VULNMART_BASE}/api/user/1":                      ["IDOR", "InfoDisc"],
    f"{VULNMART_BASE}/admin":                           ["InsecPerm"],
    f"{VULNMART_BASE}/upload":                          ["InsecUpload"],
    f"{VULNMART_BASE}/file?name=README.md":             ["DirTrav"],
    f"{VULNMART_BASE}/ping":                            ["CMDi"],
    f"{VULNMART_BASE}/fetch-image":                     ["SSRF"],
    f"{VULNMART_BASE}/cart/import":                     ["InsecDeser"],
    f"{VULNMART_BASE}/account/change-email":            ["CSRF"],
    f"{VULNMART_BASE}/reset-password":                  ["BrokenAuth"],
    f"{VULNMART_BASE}/config":                          ["InfoDisc", "CredsExpose"],
    f"{VULNMART_BASE}/comments":                        ["XSS"],
}

# ─────────────────────────────────────────────────────────────────────────
# 2. VULN_STATIC_SITE — repris directement de manifest.json, ["SAFE"]
#    converti en [] (SAFE n'est plus une classe entraînée). Pas d'auth requise.
# ─────────────────────────────────────────────────────────────────────────

STATIC_BASE = "http://localhost:8090"
HELPERS_STATIC = []  # site 100% statique, aucune auth

LABELS_STATIC_SITE = {
    f"{STATIC_BASE}/index.html":               ["InfoDisc"],
    f"{STATIC_BASE}/page_xss_dom.html":        ["XSS"],
    f"{STATIC_BASE}/page_secrets.html":        ["CredsExpose"],
    f"{STATIC_BASE}/page_outdated_lib.html":   ["XSS", "InsecCrypto"],
    f"{STATIC_BASE}/page_form_csrf.html":      ["CSRF"],
    f"{STATIC_BASE}/page_clickjack.html":      ["InfoDisc"],
    f"{STATIC_BASE}/page_info_disclosure.html":["InfoDisc", "CredsExpose"],
    f"{STATIC_BASE}/page_safe.html":           [],  # témoin négatif — corrigé depuis ["SAFE"] du manifest.json
    f"{STATIC_BASE}/.env":                     ["CredsExpose", "InfoDisc"],
}

# ─────────────────────────────────────────────────────────────────────────
# 3. DVWA — auth via ton helper dédié `dvwa_auth` (login + security level
#    en un seul appel, plus besoin de gérer ça à la main).
# ─────────────────────────────────────────────────────────────────────────

DVWA_BASE = "http://localhost:8081"  # adapte le port à ton instance

HELPERS_DVWA = [
    {"name": "dvwa_auth", "kwargs": {
        "base_url": DVWA_BASE, "username": "admin", "password": "password",
        "security_level": "low",  # "low" = vulns pleinement exploitables, meilleur signal pour le training
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
# 4. bWAPP / Juice Shop — REPORTÉS EN v1.1 (décision de scope prise avec Sam
#    le 19/08). L'auth est prête (bwapp_auth: bee/bug par défaut,
#    juice_shop_auth: admin@juice-sh.op/admin123 via JWT), mais je préfère
#    encore vérifier les vrais noms de page avant de labelliser quoi que ce
#    soit — pas la peine tant que ce n'est pas dans le scope MVP.
# ─────────────────────────────────────────────────────────────────────────

BWAPP_BASE = "http://localhost:8082"
HELPERS_BWAPP = [{"name": "bwapp_auth", "kwargs": {"base_url": BWAPP_BASE}}]
LABELS_BWAPP = {
    # f"{BWAPP_BASE}/sqli_1.php":   ["SQLi"],
}

JUICESHOP_BASE = "http://localhost:3000"
HELPERS_JUICESHOP = [{"name": "juice_shop_auth", "kwargs": {"base_url": JUICESHOP_BASE}}]
LABELS_JUICESHOP = {
    # f"{JUICESHOP_BASE}/#/": [],  # SPA -> is_spa=True obligatoire
}

# ─────────────────────────────────────────────────────────────────────────
# 5. Assemblage — (url, vulns, is_spa, helpers) par groupe
# ─────────────────────────────────────────────────────────────────────────

GROUPS = [
    (LABELS_VULNMART, False, HELPERS_VULNMART),
    (LABELS_STATIC_SITE, False, HELPERS_STATIC),
    (LABELS_DVWA, False, HELPERS_DVWA),
    (LABELS_BWAPP, False, HELPERS_BWAPP),
    (LABELS_JUICESHOP, True, HELPERS_JUICESHOP),
]

ALL_TARGETS = [
    (url, vulns, is_spa, helpers)
    for labels, is_spa, helpers in GROUPS
    for url, vulns in labels.items()
]


# ─────────────────────────────────────────────────────────────────────────
# 6. PIPELINE
# ─────────────────────────────────────────────────────────────────────────

async def build_dataset(targets: list, max_test: int = 100, out_path: str = "./dataset_mvp"):
    rows = []
    async with aiohttp.ClientSession() as session:
        an = AnalyzerHelper(session=session, MAX_DEEPTH=0, use_cache=False)
        ca = CodeAnalyzer(True)
        pa = PassiveCodeAnalyzer()
        fuzzer = Fuzzer(session=session)
        fuzzer.config.MAX_TEST = max_test
        fe = FeatureExtractor()

        total = len(targets)
        for i, (url, vulns, is_spa, helpers) in enumerate(targets, 1):
            logger.info(f"[{i}/{total}] {url} -> {vulns or 'SAFE'} (is_spa={is_spa}, helpers={[h['name'] for h in helpers]})")
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
    # v1 : vulnmart + vuln_static_site + DVWA uniquement.
    # bWAPP / Juice Shop -> v1.1 (voir section 4 ci-dessus).
    v1_targets = [
        t for t in ALL_TARGETS
        if not t[0].startswith(BWAPP_BASE) and not t[0].startswith(JUICESHOP_BASE)
    ]
    asyncio.run(build_dataset(v1_targets, max_test=100, out_path="./dataset_mvp"))