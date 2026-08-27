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
import tempfile
from uuid import uuid4
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from cachetools import TTLCache
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
_ARJUN_CACHE = TTLCache(maxsize=2048, ttl=4 * 3600)
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

    # Fichier de sortie unique par appel : évite que deux scans parallèles
    # n'écrasent/ne lisent le même fichier /tmp partagé.
    out_path = Path(tempfile.gettempdir()) / f"arjun_{uuid4().hex}.json"

    cmd = ["arjun", "-u", url, "--stable", "-oJ", str(out_path)]
    if wordlist:
        cmd += ["-w", wordlist]

    try:
        subprocess.run(
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
    try:
        if out_path.exists():
            with open(out_path, "r", encoding="utf-8") as f:
                arjun_data = json.load(f)
            # Structure réelle d'Arjun (vérifiée dans arjun/core/exporter.py) :
            # {"http://url...": {"method": "GET", "params": [...], "headers": {...}}}
            entry = arjun_data.get(url) or next(iter(arjun_data.values()), {})
            found = entry.get("params", [])
            params = {p: ["test"] for p in found}
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Lecture résultat Arjun impossible : {e}")
    finally:
        out_path.unlink(missing_ok=True)

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