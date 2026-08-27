#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Résolveur de query params pour _inject_payloads_in_query.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import json5
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from scanner_utils.logger import get_logger
logger = get_logger()

# ─── Fallback générique ──────────────────────────────────────────────────────
DEFAULT_QUERY_PARAMS = {
    "q": "test",
    "search": "test",
    "id": "1",
    "name": "test",
    "input": "test",
    "debug": "1",
    "page": "1",
    "file": "index.php",
    "url": "http://example.com",
}

# ─── Cache Arjun ─────────────────────────────────────────────────────────────
_ARJUN_CACHE = {}
_KNOWN_PARAMS_FILE = None


def set_known_params_dir(dirname: str):
    """Définit le dossier où chercher known_params.json"""
    global _KNOWN_PARAMS_FILE
    _KNOWN_PARAMS_FILE = Path(dirname) / "known_params.json"
    logger.debug(f"known_params.json cherché dans: {_KNOWN_PARAMS_FILE}")


def load_known_params(url: str) -> dict[str, list[str]] | None:
    """Cherche les query params connus pour cette URL dans known_params.json"""
    if _KNOWN_PARAMS_FILE is None:
        return None
    
    if not _KNOWN_PARAMS_FILE.exists():
        return None

    try:
        with open(_KNOWN_PARAMS_FILE, "r", encoding="utf-8") as f:
            known: dict = json5.load(f)
    except (ValueError, OSError) as e:
        logger.warning(f"known_params.json illisible : {e}")
        return None

    # Match exact
    if url in known:
        logger.debug(f"known_params: match exact pour {url[:80]}...")
        return {k: v if isinstance(v, list) else [v] for k, v in known[url].items()}

    # Match par base URL
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    for key, params in known.items():
        key_parsed = urlparse(key)
        key_base = f"{key_parsed.scheme}://{key_parsed.netloc}{key_parsed.path}".rstrip("/")
        if key_base == base:
            logger.debug(f"known_params: match base path pour {base}")
            return {k: v if isinstance(v, list) else [v] for k, v in params.items()}

    return None


def discover_params_arjun(
    url: str,
    timeout: int = 30,
    wordlist: str | None = None,
) -> dict[str, list[str]] | None:
    """Lance Arjun pour découvrir les query params"""
    if url in _ARJUN_CACHE:
        return {k: list(v) for k, v in _ARJUN_CACHE[url].items()}

    cmd = ["arjun", "-u", url, "--stable", "-oJ", "/tmp/arjun_result.json"]
    if wordlist:
        cmd += ["-w", wordlist]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.debug("Arjun non trouvé")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Arjun timeout sur {url[:80]}...")
        return None
    except Exception as e:
        logger.warning(f"Arjun erreur : {e}")
        return None

    params = {}
    for line in result.stdout.splitlines():
        if "[+]" in line or "Found" in line:
            matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{1,30})\b', line)
            for m in matches:
                if m not in ("Found", "GET", "POST", "the", "in", "at"):
                    params[m] = ["test"]

    if params:
        logger.success(f"Arjun a trouvé: {list(params.keys())}")
        _ARJUN_CACHE[url] = params

    return params if params else None


def resolve_query_params(
    url: str,
    use_arjun: bool = False,
    arjun_timeout: int = 30,
) -> dict[str, list[str]]:
    """
    Résout les query params à injecter pour une URL donnée.
    """
    parsed = urlparse(url)

    # Déjà dans l'URL
    if parsed.query:
        return parse_qs(parsed.query)
    
    # known_params.json
    known = load_known_params(url)
    if known:
        return known

    # Arjun
    if use_arjun:
        discovered = discover_params_arjun(url, timeout=arjun_timeout)
        if discovered:
            return discovered

    # Fallback
    logger.debug(f"Fallback params pour {url[:60]}")
    return {k: [v] for k, v in DEFAULT_QUERY_PARAMS.items()}