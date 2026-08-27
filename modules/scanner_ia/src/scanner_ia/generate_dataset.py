#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — generate_dataset.py                                             ║
║   Génère un dataset labellisé pour entraîner le ScannerIA                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Sources :                                                                   ║
║    - DVWA          (vulnerables/web-dvwa)  → port 8080                       ║
║    - Juice Shop    (bkimminich/juice-shop) → port 3000                       ║
║    - bWAPP         (raesene/bwapp)         → port 8081                       ║
║    - vuln_server_v3 (python local)         → port 5000                       ║
║                                                                              ║
║  Output :                                                                    ║
║    dataset/shieldai_dataset.csv            (features + labels)               ║
║    dataset/shieldai_dataset_meta.json      (stats + mapping URL→labels)      ║
║                                                                              ║
║  Usage :                                                                     ║
║    python generate_dataset.py                          # tout                ║
║    python generate_dataset.py --sources dvwa juice     # sources choisies    ║
║    python generate_dataset.py --no-docker              # sans gestion Docker ║
╚══════════════════════════════════════════════════════════════════════════════╝
Author : Samuel — ShieldAI
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import asyncio
import aiohttp
import argparse
import json
import time
import traceback
import pandas as pd
import numpy  as np
from datetime import datetime
from pathlib  import Path
from typing   import Dict, List, Optional, Tuple

from loguru import logger
logger.remove()
logger.add(sys.stdout,
    format="<yellow>{time:HH:mm:ss}</yellow> | <level>{level:<8}</level> | <cyan>{function}</cyan>\n└─ <level>{message}</level>",
    level="INFO", colorize=True)

# ── Imports ShieldAI ──────────────────────────────────────────────────────────
from scanner_ia.core.analyzer_helper         import AnalyzerHelper
from scanner_ia.analyzers.passive_analyzer   import PassiveCodeAnalyzer
from scanner_ia.analyzers.code_analyzer      import CodeAnalyzer
from scanner_ia.fuzzer.active_fuzzer         import Fuzzer
from scanner_ia.ml_model.features_extractor  import FeatureExtractor
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult
from scanner_ia.base_class.code_analyse_base_class     import CodeAnalyzerResult
from scanner_ia.ml_model.config import VULNS

# ══════════════════════════════════════════════════════════════════════════════
# MAPPING COMPLET URL → LABELS
# Chaque URL est associée aux vulnérabilités qu'elle expose.
# Label vide [] = page SAFE.
# ══════════════════════════════════════════════════════════════════════════════

DVWA_LABELS: Dict[str, List[str]] = {
    # SQLi
    "/vulnerabilities/sqli/":              ["SQLi"],
    "/vulnerabilities/sqli_blind/":        ["SQLi"],
    # XSS
    "/vulnerabilities/xss_r/":            ["XSS"],
    "/vulnerabilities/xss_s/":            ["XSS"],
    "/vulnerabilities/xss_d/":            ["XSS"],
    # CSRF
    "/vulnerabilities/csrf/":             ["CSRF"],
    # CMDi
    "/vulnerabilities/exec/":             ["CMDi"],
    # DirTrav / File inclusion
    "/vulnerabilities/fi/":               ["DirTrav"],
    "/vulnerabilities/fi/?page=../../../../../../etc/passwd": ["DirTrav"],
    # InsecUpload
    "/vulnerabilities/upload/":           ["InsecUpload"],
    # BruteForce / BrokenAuth
    "/vulnerabilities/brute/":            ["BrokenAuth"],
    # IDOR
    "/vulnerabilities/idor/":             ["IDOR"],
    # RateLimiting absent
    "/vulnerabilities/weak_id/":          ["IDOR", "InsecCrypto"],
    # Captcha (safe mostly)
    "/vulnerabilities/captcha/":          [],
    # Pages safe
    "/":                                   [],
    "/login.php":                          [],
    "/about.php":                          [],
    "/phpinfo.php":                        ["InfoDisc"],
    "/setup.php":                          ["InfoDisc"],
}

JUICESHOP_LABELS: Dict[str, List[str]] = {
    # SQLi
    "/rest/user/login":                    ["SQLi", "BrokenAuth"],
    "/rest/products/search?q=':":          ["SQLi"],
    # XSS
    "/search?q=<script>alert(1)</script>": ["XSS"],
    "/#/search?q=<img src=x onerror=alert(1)>": ["XSS"],
    # NoSQLi
    "/rest/basket/1":                      ["IDOR", "NoSQLi"],
    # SSRF
    "/rest/saveLoginIp":                   ["SSRF"],
    # InsecUpload
    "/rest/products/1/reviews":            [],
    "/#/complaint":                        ["InsecUpload"],
    # JWT
    "/rest/user/whoami":                   ["JWT"],
    "/rest/user/change-password":          ["JWT", "BrokenAuth"],
    # IDOR
    "/rest/basket/2":                      ["IDOR"],
    "/rest/user/2":                        ["IDOR"],
    # OpenRedirect
    "/redirect?to=https://evil.com":       ["OpenRedirect"],
    # InfoDisc
    "/api-docs":                           ["InfoDisc"],
    "/ftp/":                               ["InfoDisc", "DirTrav"],
    "/ftp/acquisitions.md":                ["InfoDisc"],
    "/.well-known/security.txt":           [],
    "/robots.txt":                         ["InfoDisc"],
    # CredsExpose
    "/ftp/eastere.gg":                     ["InfoDisc"],
    "/metrics":                            ["InfoDisc"],
    # Prototype pollution
    "/socket.io/?EIO=4&transport=polling": ["Prototype_Pollution"],
    # CORS
    "/rest/products/1":                    ["CORS"],
    # Pages safe
    "/#/":                                 [],
    "/#/about":                            [],
    "/#/contact":                          [],
    "/#/register":                         [],
    "/#/login":                            [],
}

BWAPP_LABELS: Dict[str, List[str]] = {
    # SQLi
    "/sqli_1.php":                         ["SQLi"],
    "/sqli_2.php":                         ["SQLi"],
    "/sqli_blind_boolean.php":             ["SQLi"],
    "/sqli_blind_time.php":                ["SQLi"],
    "/sqli_stored.php":                    ["SQLi"],
    # XSS
    "/xss_get.php":                        ["XSS"],
    "/xss_post.php":                       ["XSS"],
    "/xss_stored_1.php":                   ["XSS"],
    "/xss_json.php":                       ["XSS"],
    # CMDi
    "/commandi.php":                       ["CMDi"],
    "/commandi_blind.php":                 ["CMDi"],
    # SSRF
    "/ssrf_1.php":                         ["SSRF"],
    "/ssrf_2.php":                         ["SSRF"],
    # XXE
    "/xxe_1.php":                          ["XXE"],
    "/xxe_2.php":                          ["XXE"],
    # LDAPi
    "/ldapi.php":                          ["LDAPi"],
    # CSRF
    "/csrf_0.php":                         ["CSRF"],
    "/csrf_1.php":                         ["CSRF"],
    # DirTrav
    "/directory_traversal_1.php":          ["DirTrav"],
    "/directory_traversal_2.php":          ["DirTrav"],
    # InsecUpload
    "/unrestricted_file_upload.php":       ["InsecUpload"],
    # SSTI
    "/ssti_1.php":                         ["SSTI"],
    # XPath injection
    "/xpath.php":                          ["XPATH_Injection"],
    # InsecDeser
    "/insecure_deserialization.php":       ["InsecDeser"],
    # IDOR
    "/idor_1.php":                         ["IDOR"],
    # InfoDisc
    "/info_disclosure_1.php":             ["InfoDisc"],
    "/robots.txt":                         ["InfoDisc"],
    "/phpinfo.php":                        ["InfoDisc"],
    # CORS
    "/cors.php":                           ["CORS"],
    # OpenRedirect
    "/open_redirect_1.php":               ["OpenRedirect"],
    "/open_redirect_2.php":               ["OpenRedirect"],
    # CRLF
    "/crlf_injection.php":                ["CRLF_Injection"],
    # BrokenAuth
    "/ba_broken_auth.php":                 ["BrokenAuth"],
    "/ba_insecure_login.php":              ["BrokenAuth", "InsecCrypto"],
    # Safe
    "/":                                   [],
    "/login.php":                          [],
    "/portal.php":                         [],
}

VULN_SERVER_LABELS: Dict[str, List[str]] = {
    # SQLi
    "/sqli/error":                         ["SQLi"],
    "/sqli/blind":                         ["SQLi"],
    "/sqli/union":                         ["SQLi"],
    # XSS
    "/xss/reflected":                      ["XSS"],
    "/xss/stored":                         ["XSS"],
    "/xss/dom":                            ["XSS"],
    # CMDi
    "/cmdi/basic":                         ["CMDi"],
    "/cmdi/blind":                         ["CMDi"],
    # SSRF
    "/ssrf/basic":                         ["SSRF"],
    "/ssrf/metadata":                      ["SSRF"],
    # SSTI
    "/ssti/jinja2":                        ["SSTI"],
    "/ssti/mako":                          ["SSTI"],
    # DirTrav
    "/traversal/basic":                    ["DirTrav"],
    "/traversal/encoded":                  ["DirTrav"],
    # XXE
    "/xxe/basic":                          ["XXE"],
    # NoSQLi
    "/nosqli/basic":                       ["NoSQLi"],
    # InsecDeser
    "/deserial/pickle":                    ["InsecDeser"],
    # CORS
    "/cors/wildcard":                      ["CORS"],
    "/cors/credentials":                   ["CORS"],
    # CredsExpose
    "/creds/env":                          ["CredsExpose"],
    "/creds/git":                          ["CredsExpose"],
    # InfoDisc
    "/info/stacktrace":                    ["InfoDisc"],
    "/info/debug":                         ["InfoDisc"],
    # JWT
    "/jwt/none":                           ["JWT"],
    "/jwt/weak":                           ["JWT"],
    # CSRF
    "/csrf/basic":                         ["CSRF"],
    # InsecUpload
    "/upload/basic":                       ["InsecUpload"],
    # IDOR
    "/idor/basic":                         ["IDOR"],
    # CRLF
    "/crlf/header":                        ["CRLF_Injection"],
    # Prototype Pollution
    "/prototype/merge":                    ["Prototype_Pollution"],
    # GraphQL
    "/graphql/introspection":              ["GraphQLi"],
    # OpenRedirect
    "/redirect/basic":                     ["OpenRedirect"],
    # InsecPerm
    "/perm/admin":                         ["InsecPerm"],
    "/perm/api":                           ["InsecPerm"],
    # BrokenAuth
    "/auth/bruteforce":                    ["BrokenAuth"],
    # Safe pages
    "/":                                   [],
    "/health":                             [],
    "/static/css/main.css":               [],
    "/api/products":                       [],
    "/api/users":                          [],
    "/contact":                            [],
    "/about":                              [],
}

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG DOCKER
# ══════════════════════════════════════════════════════════════════════════════

SOURCES_CONFIG = {
    "dvwa": {
        "image":        "vulnerables/web-dvwa:latest",
        "container":    "shieldai_dvwa",
        "port":         8080,
        "base_url":     "http://localhost:8080",
        "labels_map":   DVWA_LABELS,
        "startup_wait": 15,
        "env":          {},
        "extra_cmd":    None,
    },
    "juice": {
        "image":        "bkimminich/juice-shop:latest",
        "container":    "shieldai_juice",
        "port":         3000,
        "base_url":     "http://localhost:3000",
        "labels_map":   JUICESHOP_LABELS,
        "startup_wait": 20,
        "env":          {},
        "extra_cmd":    None,
    },
    "bwapp": {
        "image":        "raesene/bwapp:latest",
        "container":    "shieldai_bwapp",
        "port":         8081,
        "base_url":     "http://localhost:8081",
        "labels_map":   BWAPP_LABELS,
        "startup_wait": 20,
        "env":          {"BWAPP_PASSWORD": "bug"},
        "extra_cmd":    None,
    },
    "vulnserver": {
        "image":        None,   # local python, pas Docker
        "container":    None,
        "port":         5000,
        "base_url":     "http://localhost:5000",
        "labels_map":   VULN_SERVER_LABELS,
        "startup_wait": 3,
        "env":          {},
        "extra_cmd":    None,
    },
}

OUTPUT_DIR  = Path(__file__).parent / "dataset"
OUTPUT_CSV  = OUTPUT_DIR / "shieldai_dataset.csv"
OUTPUT_META = OUTPUT_DIR / "shieldai_dataset_meta.json"
CONFIG_PATH = Path(__file__).parent / "shieldai_scanner.config.json5"


# ══════════════════════════════════════════════════════════════════════════════
# DOCKER MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class DockerManager:
    """Gère le démarrage/arrêt des containers Docker."""

    def __init__(self):
        try:
            import docker
            self.client = docker.client.DockerClient()
            self.available = True
            logger.success("Docker disponible")
        except Exception as e:
            logger.warning(f"Docker non disponible : {e}")
            self.available = False

    def is_running(self, container_name: str) -> bool:
        if not self.available:
            return False
        try:
            c = self.client.containers.get(container_name)
            return c.status == "running"
        except Exception:
            return False

    def start(self, source_name: str, cfg: dict) -> bool:
        """Démarre le container si non déjà lancé."""
        if not self.available or cfg.get("image") is None:
            return True  # local process, skip

        name  = cfg["container"]
        image = cfg["image"]
        port  = cfg["port"]
        
        try:
            self.client.containers.prune()
        except Exception:
            pass
        
        if self.is_running(name):
            logger.info(f"[{source_name}] Container déjà en cours ({name})")
            return True

        # Supprimer si existant mais arrêté
        try:
            old = self.client.containers.get(name)
            old.remove(force=True)
            logger.info(f"[{source_name}] Ancien container supprimé")
        except Exception:
            pass

        logger.info(f"[{source_name}] Démarrage {image} → port {port}...")
        try:
            # self.client.containers.model.start(
            #     image,
            #     name       = name,
            #     detach     = True,
            #     ports      = {f"80/tcp": port, f"{port}/tcp": port},
            #     environment= cfg.get("env", {}),
            #     remove     = False,
            #     )
            self.client.containers.run(
                image,
                name       = name,
                detach     = True,
                ports      = {"80/tcp": port} if "dvwa" in image or "bwapp" in image else {f"{port}/tcp": port },
                environment= cfg.get("env", {}),
                remove     = False,
            )
            # Attendre que le service soit prêt
            wait = cfg.get("startup_wait", 10)
            logger.info(f"[{source_name}] Attente {wait}s démarrage...")
            time.sleep(wait)
            logger.success(f"[{source_name}] Container prêt")
            return True
        except Exception as e:
            logger.error(f"[{source_name}] Échec démarrage : {e}")
            return False

    def stop(self, container_name: str):
        if not self.available:
            return
        try:
            c = self.client.containers.get(container_name)
            c.stop(timeout=5)
            c.remove()
            logger.info(f"Container arrêté : {container_name}")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# VÉRIFICATION URL
# ══════════════════════════════════════════════════════════════════════════════

async def _is_url_alive(url: str, timeout: int = 8) -> bool:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                             allow_redirects=True, ssl=False) as r:
                return r.status < 500
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# EXTRACTION FEATURES POUR UNE URL
# ══════════════════════════════════════════════════════════════════════════════

async def extract_features_for_url(
    url:              str,
    session:          aiohttp.ClientSession,
    analyzer_helper:  AnalyzerHelper,
    passive_analyzer: PassiveCodeAnalyzer,
    code_analyzer:    CodeAnalyzer,
    fuzzer:           Fuzzer,
    feature_extractor:FeatureExtractor,
    allowed_domains:  List[str],
) -> Optional[Dict]:
    """
    Extrait les 96 features pour une URL donnée.
    Retourne None si l'extraction échoue.
    """
    try:
        # Phase 1 — Crawl + Parse (1 seule page, pas de crawl profond)
        ah_result: AnalyzerHelperResult = await analyzer_helper.analyse_and_parse_all(
            url=url, verify_reachability=False,
            restore=False, fetch=True, silent=True
        )

        # Phase 2 — Analyse passive
        passive_result: PassiveAnalyzerResult = passive_analyzer.analyse(
            analyzer_helper_result=ah_result
        )

        # Phase 3 — Analyse code
        code_result: CodeAnalyzerResult = code_analyzer.analyse(
            analyzer_helper_result=ah_result
        )

        # Phase 4 — Fuzzer actif
        fuzzer_result: FuzzerResult = await fuzzer.fuzz(
            base_url=url,
            analyzer_helper_result=ah_result,
            limit_vuln=None,
            time_between=0.05,
            dynamic_timeout=False,
            allowed_domains=allowed_domains,
        )

        # Phase 5 — Extraction features
        df = await feature_extractor.extract(
            analyzer_helper_result=ah_result,
            passive_analyzer_result=passive_result,
            code_analyzer_result=code_result,
            fuzzer_result=fuzzer_result,
        )

        if df is None or len(df) == 0:
            return None

        # Prendre la première ligne (= l'URL cible)
        row = df.iloc[0].to_dict()
        return row

    except Exception as e:
        logger.warning(f"Extraction échouée pour {url} : {type(e).__name__} — {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# TRAITEMENT D'UNE SOURCE
# ══════════════════════════════════════════════════════════════════════════════

async def process_source(
    source_name: str,
    cfg:         dict,
    session:     aiohttp.ClientSession,
    semaphore:   asyncio.Semaphore,
    use_fuzzer:  bool = True,
) -> List[Dict]:
    """Extrait les features pour toutes les URLs d'une source."""

    base_url     = cfg["base_url"]
    labels_map   = cfg["labels_map"]
    allowed      = [base_url]

    logger.info(f"[{source_name}] Initialisation des composants...")

    # Instancier les composants pour cette source
    analyzer_helper   = AnalyzerHelper(session=session, use_cache=False,
                                        RESTRAIN_FOR_THIS_DOMAIN=True)
    passive_analyzer  = PassiveCodeAnalyzer()
    code_analyzer     = CodeAnalyzer(debug=False)
    feature_extractor = FeatureExtractor()

    fuzzer = None
    if use_fuzzer:
        try:
            fuzzer = Fuzzer(session=session, debug=False,
                            use_semantic=True, limit=None, FUZZ_TIMEOUT=600)
        except Exception as e:
            logger.warning(f"[{source_name}] Fuzzer non disponible : {e}")

    rows    = []
    total   = len(labels_map)
    success = 0
    failed  = 0

    logger.info(f"[{source_name}] {total} URLs à traiter")

    async def process_one(path: str, labels: List[str]) -> Optional[Dict]:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        async with semaphore:
            logger.debug(f"[{source_name}] → {path}")
            feats = await extract_features_for_url(
                url=url,
                session=session,
                analyzer_helper=analyzer_helper,
                passive_analyzer=passive_analyzer,
                code_analyzer=code_analyzer,
                fuzzer=fuzzer if use_fuzzer and fuzzer else _make_empty_fuzzer(),
                feature_extractor=feature_extractor,
                allowed_domains=allowed,
            )
            if feats is None:
                return None

            # Ajouter URL, source, labels
            feats["url"]    = url
            feats["source"] = source_name

            # Labels multi-label : une colonne par vuln (0/1)
            for v in VULNS:
                feats[f"label_{v}"] = 1 if v in labels else 0

            # Label agrégé lisible
            feats["labels"]    = json.dumps(labels if labels else ["SAFE"])
            feats["is_safe"]   = int(len(labels) == 0)
            feats["n_labels"]  = len(labels)

            return feats

    # Lancer en parallèle (limité par semaphore)
    tasks = [process_one(path, labels) for path, labels in labels_map.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            logger.warning(f"[{source_name}] Erreur : {r}")
            failed += 1
        elif r is not None:
            rows.append(r)
            success += 1
        else:
            failed += 1

    logger.success(f"[{source_name}] ✅ {success}/{total} URLs extraites ({failed} échecs)")
    return rows


def _make_empty_fuzzer():
    """Retourne un FuzzerResult vide si le vrai fuzzer est indisponible."""
    return FuzzerResult()


# ══════════════════════════════════════════════════════════════════════════════
# SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════════════

def save_dataset(all_rows: List[Dict], existing_csv: Optional[Path] = None):
    """Sauvegarde le dataset en CSV et génère les métadonnées."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    df = pd.DataFrame(all_rows)

    # Réorganiser : url, source, labels en premier, features au milieu
    meta_cols  = ["url", "source", "labels", "is_safe", "n_labels"]
    label_cols = [c for c in df.columns if c.startswith("label_")]
    feat_cols  = [c for c in df.columns if c not in meta_cols + label_cols]

    col_order = meta_cols + feat_cols + label_cols
    col_order = [c for c in col_order if c in df.columns]
    df = df[col_order]

    # Fusionner avec dataset existant si présent
    if existing_csv and existing_csv.exists():
        old = pd.read_csv(existing_csv)
        df  = pd.concat([old, df], ignore_index=True)
        # Dédupliquer sur (url, source)
        df  = df.drop_duplicates(subset=["url", "source"], keep="last")
        logger.info(f"Fusion avec dataset existant : {len(old)} → {len(df)} lignes")

    df.to_csv(OUTPUT_CSV, index=False)
    logger.success(f"Dataset sauvegardé : {OUTPUT_CSV} ({len(df)} lignes)")

    # ── Métadonnées ──────────────────────────────────────────────────────────
    label_cols_actual = [c for c in df.columns if c.startswith("label_")]
    vuln_stats = {}
    for lc in label_cols_actual:
        vname = lc.replace("label_", "")
        count = int(df[lc].sum())
        vuln_stats[vname] = count

    source_stats = df["source"].value_counts().to_dict() if "source" in df.columns else {}
    safe_count   = int(df["is_safe"].sum()) if "is_safe" in df.columns else 0

    meta = {
        "generated_at":    datetime.now().isoformat(),
        "total_samples":   len(df),
        "safe_samples":    safe_count,
        "vuln_samples":    len(df) - safe_count,
        "sources":         source_stats,
        "vulns_coverage":  vuln_stats,
        "vulns_covered":   [v for v, c in vuln_stats.items() if c > 0],
        "vulns_missing":   [v for v, c in vuln_stats.items() if c == 0],
        "features":        feat_cols,
        "n_features":      len(feat_cols),
        "label_cols":      label_cols_actual,
    }

    with open(OUTPUT_META, "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    logger.success(f"Métadonnées : {OUTPUT_META}")

    # ── Résumé affiché ────────────────────────────────────────────────────────
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   DATASET GÉNÉRÉ                                         ║
╠══════════════════════════════════════════════════════════╣
║  Total samples  : {len(df):<38}║
║  Safe (SAFE)    : {safe_count:<38}║
║  Vulnérables    : {len(df) - safe_count:<38}║
║  Features       : {len(feat_cols):<38}║
╠══════════════════════════════════════════════════════════╣""")
    for src, cnt in sorted(source_stats.items()):
        print(f"║  {src:<15} : {cnt:<40}║")
    print(f"╠══════════════════════════════════════════════════════════╣")
    top_vulns = sorted(vuln_stats.items(), key=lambda x: -x[1])[:10]
    for vn, cnt in top_vulns:
        bar = "█" * min(cnt, 30)
        print(f"║  {vn:<22} {bar:<20} {cnt:>3}  ║")
    missing = meta["vulns_missing"]
    if missing:
        print(f"║  ⚠ Vulns sans données : {', '.join(missing[:5])}{'...' if len(missing)>5 else '':<10}║")
    print(f"╚══════════════════════════════════════════════════════════╝")

    return df


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main_async(args):
    docker_mgr = DockerManager() if not args.no_docker else None

    # Sources sélectionnées
    sources_to_run = args.sources if args.sources else list(SOURCES_CONFIG.keys())
    logger.info(f"Sources : {sources_to_run}")

    # Démarrer les containers Docker
    active_sources = []
    for src in sources_to_run:
        cfg = SOURCES_CONFIG.get(src)
        if cfg is None:
            logger.warning(f"Source inconnue ignorée : {src}")
            continue

        # Démarrer Docker si nécessaire
        if docker_mgr and cfg.get("image"):
            ok = docker_mgr.start(src, cfg)
            if not ok:
                logger.warning(f"[{src}] Skipping — container non démarré")
                continue

        # Vérifier que le service répond
        alive = await _is_url_alive(cfg["base_url"])
        if not alive:
            logger.warning(f"[{src}] Service inaccessible : {cfg['base_url']} — skipping")
            continue

        logger.success(f"[{src}] Service en ligne ✅")
        active_sources.append(src)

    if not active_sources:
        logger.error("Aucune source disponible. Vérifier les containers Docker.")
        return

    # Créer une session HTTP partagée
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    session   = aiohttp.ClientSession(connector=connector)
    semaphore = asyncio.Semaphore(args.concurrency)

    all_rows = []
    t_start  = time.time()

    try:
        for src in active_sources:
            cfg = SOURCES_CONFIG[src]
            logger.info(f"\n{'═'*60}")
            logger.info(f"Traitement source : {src.upper()}")
            logger.info(f"{'═'*60}")

            try:
                rows = await process_source(
                    source_name = src,
                    cfg         = cfg,
                    session     = session,
                    semaphore   = semaphore,
                    use_fuzzer  = not args.no_fuzzer,
                )
                all_rows.extend(rows)
            except Exception as e:
                logger.error(f"[{src}] Erreur : {e}")
                logger.error(traceback.format_exc())

    finally:
        await session.close()

    elapsed = time.time() - t_start
    logger.info(f"Extraction terminée en {elapsed:.1f}s")

    if not all_rows:
        logger.error("Aucune donnée extraite.")
        return

    # Sauvegarder
    existing = OUTPUT_CSV if (not args.no_merge and OUTPUT_CSV.exists()) else None
    save_dataset(all_rows, existing_csv=existing)

    # Arrêter les containers si on les a démarrés
    if docker_mgr and not args.keep_containers:
        for src in active_sources:
            cfg = SOURCES_CONFIG.get(src, {})
            if cfg.get("container"):
                docker_mgr.stop(cfg["container"])


def main():
    parser = argparse.ArgumentParser(
        description="ShieldAI — Génération dataset d'entraînement"
    )
    parser.add_argument(
        "--sources", nargs="+",
        choices=list(SOURCES_CONFIG.keys()),
        help="Sources à utiliser (défaut: toutes)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=3,
        help="Nb de requêtes parallèles par source (défaut: 3)"
    )
    parser.add_argument(
        "--no-docker", action="store_true",
        help="Ne pas gérer Docker (containers déjà lancés)"
    )
    parser.add_argument(
        "--no-fuzzer", action="store_true",
        help="Désactiver le fuzzer actif (plus rapide, features fuzzer à 0)"
    )
    parser.add_argument(
        "--no-merge", action="store_true",
        help="Ne pas fusionner avec un dataset existant"
    )
    parser.add_argument(
        "--keep-containers", action="store_true",
        help="Ne pas arrêter les containers après extraction"
    )
    args = parser.parse_args()

    from nest_asyncio import apply
    apply()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
