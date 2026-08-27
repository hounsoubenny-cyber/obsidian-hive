#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 19 12:34:04 2026

@author: hounsousamuel
"""

"""
ShieldAI — HTTP Request Normalizer
Construit et anonymise une représentation textuelle d'une requête HTTP
pour l'entraînement d'un autoencodeur / classifier.

Format de sortie :
    [METHOD] GET [URL] /search?q=[INT]&page=[INT]
    [HOST] example.com
    [HEADERS] Accept: text/html | Accept-Language: [LANG] | ...
    [COOKIES] session=[HASH] | theme=dark
    [BODY] -
    [STATUS] 200
    [RES_HEADERS] Content-Type: text/html | Content-Length: [INT]
    [RES_BODY] <html><head>...
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, unquote


# ══════════════════════════════════════════════════════════════════════ #
#  Dataclass d'entrée                                                    #
# ══════════════════════════════════════════════════════════════════════ #

@dataclass
class RawRequest:
    """Représente une requête HTTP + sa réponse, telle que capturée."""

    # ── Requête ──────────────────────────────────────────
    method: str                                # GET, POST, PUT...
    url: str                                   # URL complète
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None                 # body brut (POST form, JSON...)

    # ── Réponse ──────────────────────────────────────────
    status_code: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None        # snippet (pas forcément complet)

    # ── Méta ─────────────────────────────────────────────
    label: Optional[str] = None                # "NORMAL" | "SQLI" | "XSS" | ...


# ══════════════════════════════════════════════════════════════════════ #
#  Patterns d'anonymisation                                              #
# ══════════════════════════════════════════════════════════════════════ #

# Ordre important : du plus spécifique au plus général

_PATTERNS: list[tuple[re.Pattern, str]] = [

    # ── Tokens opaques (avant INT pour éviter collision) ──
    (re.compile(
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        re.IGNORECASE
    ), "[UUID]"),

    (re.compile(
        r'\b[A-Za-z0-9+/]{20,}={0,2}\b'   # base64-like
    ), "[B64]"),

    (re.compile(
        r'\b[0-9a-f]{32,}\b',              # hex hash (MD5, SHA...)
        re.IGNORECASE
    ), "[HASH]"),

    # ── Temporel ──────────────────────────────────────────
    (re.compile(
        r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})?\b'
    ), "[DATETIME]"),

    (re.compile(
        r'\b\d{4}-\d{2}-\d{2}\b'
    ), "[DATE]"),

    (re.compile(
        r'\b\d{2}:\d{2}(:\d{2})?\b'
    ), "[TIME]"),

    # ── Réseau ────────────────────────────────────────────
    (re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ), "[IP]"),

    (re.compile(
        r'\b([0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b',
        re.IGNORECASE
    ), "[IPv6]"),

    # ── Identifiants personnels ───────────────────────────
    (re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b',
        re.IGNORECASE
    ), "[EMAIL]"),

    (re.compile(
        r'\b(?:\+?[\d\s\-().]{7,15})\b'   # numéro de téléphone approximatif
    ), "[PHONE]"),

    # ── Numérique générique (en dernier) ─────────────────
    (re.compile(r'\b\d+\b'), "[INT]"),
]

# Headers dont la valeur porte peu de signal sémantique → on garde le nom
# mais on anonymise la valeur selon son type
_OPAQUE_HEADERS = {
    "authorization", "cookie", "set-cookie",
    "x-auth-token", "x-api-key", "x-csrf-token",
    "x-request-id", "x-correlation-id",
    "if-none-match", "etag",
}

# Headers à supprimer complètement (bruit pur)
_DROP_HEADERS = {
    "accept-encoding",   # toujours gzip,deflate,br
    "connection",        # keep-alive
    "pragma",
    "cache-control",     # trop variable, peu de signal
}

# Valeurs de headers qu'on garde telles quelles (peu de variance, sémantique utile)
_KEEP_HEADER_VALUES = {
    "content-type", "accept", "accept-language",
    "x-requested-with", "origin", "referer",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
}


# ══════════════════════════════════════════════════════════════════════ #
#  Fonctions d'anonymisation                                             #
# ══════════════════════════════════════════════════════════════════════ #

def anonymize(text: str) -> str:
    """Applique tous les patterns de remplacement sur une chaîne."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _anon_header_value(name: str, value: str) -> str:
    """
    Anonymise la valeur d'un header selon sa sémantique.
    - Headers opaques → [HASH] ou [TOKEN]
    - Headers à valeur sémantique → on garde (Accept, Content-Type...)
    - Reste → anonymize() générique
    """
    name_lower = name.lower()

    if name_lower in _OPAQUE_HEADERS:
        # Token de sécurité : on garde juste une empreinte structurelle
        return f"[TOKEN:{_short_hash(value)}]"

    if name_lower in _KEEP_HEADER_VALUES:
        # Content-Type: application/json → on garde
        # Accept-Language: fr-FR,fr;q=0.9,en;q=0.8 → on simplifie
        if name_lower == "accept-language":
            langs = re.findall(r'[a-z]{2}(?:-[A-Z]{2})?', value)
            return f"[LANG:{','.join(langs[:2])}]" if langs else "[LANG]"
        return value

    return anonymize(value)


def _anon_cookie_value(value: str) -> str:
    """
    Si la valeur ressemble à un token opaque → [TOKEN:xxxx].
    Sinon valeur courte et lisible → on garde.
    """
    if len(value) > 12 or re.search(r'[0-9a-f]{8,}', value, re.IGNORECASE):
        return f"[TOKEN:{_short_hash(value)}]"
    return value


def _anon_url(url: str) -> str:
    """
    Anonymise une URL :
    - Chemin : segments numériques → [INT], UUIDs → [UUID]
    - Query params : on garde les noms, on anonymise les valeurs
    """
    parsed = urlparse(unquote(url))

    # ── Path ──────────────────────────────────────────────
    segments = parsed.path.split("/")
    anon_segments = []
    for seg in segments:
        if re.fullmatch(r'\d+', seg):
            anon_segments.append("[INT]")
        elif re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            seg, re.IGNORECASE
        ):
            anon_segments.append("[UUID]")
        elif re.fullmatch(r'[0-9a-f]{16,}', seg, re.IGNORECASE):
            anon_segments.append("[HASH]")
        else:
            anon_segments.append(seg)
    anon_path = "/".join(anon_segments)

    # ── Query params ──────────────────────────────────────
    params = parse_qs(parsed.query, keep_blank_values=True)
    anon_params: dict[str, list[str]] = {}
    for k, vals in params.items():
        anon_params[k] = [anonymize(v) for v in vals]
    anon_query = urlencode(anon_params, doseq=True)

    # ── Fragment ──────────────────────────────────────────
    fragment = anonymize(parsed.fragment) if parsed.fragment else ""

    reconstructed = parsed._replace(
        path=anon_path,
        query=anon_query,
        fragment=fragment,
    )
    return reconstructed.geturl()


def _anon_body(body: str, content_type: str = "") -> str:
    """
    Anonymise le body selon le Content-Type.
    - form-urlencoded : on garde les noms de params
    - JSON : on anonymise les valeurs, on garde les clés
    - autre : anonymize() générique + troncature
    """
    if not body.strip():
        return "-"

    ct = content_type.lower()

    if "application/x-www-form-urlencoded" in ct:
        params = parse_qs(body, keep_blank_values=True)
        anon = {k: [anonymize(v) for v in vals] for k, vals in params.items()}
        return urlencode(anon, doseq=True)

    if "application/json" in ct:
        return _anon_json_str(body)

    # Fallback : anonymize + tronque
    return anonymize(body)[:512]


def _anon_json_str(json_str: str) -> str:
    """
    Anonymise les valeurs d'un JSON sans parser (robuste aux JSON malformés).
    On remplace les valeurs string et number en gardant les clés.
    """
    # Valeurs string
    json_str = re.sub(
        r'("(?:[^"\\]|\\.)*"\s*:\s*)"(?:[^"\\]|\\.)*"',
        lambda m: m.group(1) + '"[STR]"',
        json_str,
    )
    # Valeurs numériques
    json_str = re.sub(
        r'("(?:[^"\\]|\\.)*"\s*:\s*)(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)',
        lambda m: m.group(1) + "[INT]",
        json_str,
    )
    return json_str[:512]


def _anon_response_body(body: str) -> str:
    """
    Pour le body de réponse on veut surtout la structure,
    pas les données. Troncature + anonymisation légère.
    """
    if not body:
        return "-"
    snippet = body[:300]
    # Retire les valeurs dans les attributs HTML type value="..."
    snippet = re.sub(r'value="[^"]{8,}"', 'value="[VAL]"', snippet)
    snippet = re.sub(r"value='[^']{8,}'", "value='[VAL]'", snippet)
    return anonymize(snippet)


def _short_hash(value: str) -> str:
    """Hash court pour différencier les tokens entre eux sans exposer la valeur."""
    return hashlib.sha256(value.encode()).hexdigest()[:6]


# ══════════════════════════════════════════════════════════════════════ #
#  Fonction principale                                                   #
# ══════════════════════════════════════════════════════════════════════ #

def build_normalized_sequence(req: RawRequest) -> str:
    """
    Construit la chaîne normalisée et anonymisée prête pour le tokenizer.

    Retourne une string multi-ligne de la forme :
        [METHOD] GET [URL] /search?q=[INT]
        [HOST] example.com
        [HEADERS] Accept: text/html | Content-Type: application/json
        [COOKIES] session=[TOKEN:a3f1c2] | remember=true
        [BODY] username=[STR]&password=[TOKEN:b2e4f1]
        [STATUS] 200
        [RES_HEADERS] Content-Type: text/html | Content-Length: [INT]
        [RES_BODY] <html><head><title>...
    """
    lines: list[str] = []

    # ── [METHOD] + [URL] ──────────────────────────────────
    parsed_url = urlparse(req.url)
    host = parsed_url.netloc
    path_and_query = _anon_url(req.url)
    # On retire le scheme://host pour garder juste le path+query
    path_only = urlparse(path_and_query).path
    query_only = urlparse(path_and_query).query
    relative = path_only + (f"?{query_only}" if query_only else "")

    lines.append(f"[METHOD] {req.method.upper()} [URL] {relative}")

    # ── [HOST] ────────────────────────────────────────────
    # On garde le host tel quel (pas de donnée sensible)
    lines.append(f"[HOST] {host}")

    # ── [HEADERS] ─────────────────────────────────────────
    req_headers_parts: list[str] = []
    for name, value in req.headers.items():
        name_lower = name.lower()
        if name_lower in _DROP_HEADERS:
            continue
        if name_lower == "host":
            continue  # déjà dans [HOST]
        if name_lower == "cookie":
            continue  # déjà dans [COOKIES]
        anon_val = _anon_header_value(name, value)
        req_headers_parts.append(f"{name}: {anon_val}")

    lines.append("[HEADERS] " + (" | ".join(req_headers_parts) if req_headers_parts else "-"))

    # ── [COOKIES] ─────────────────────────────────────────
    cookie_parts: list[str] = []
    for name, value in req.cookies.items():
        anon_val = _anon_cookie_value(value)
        cookie_parts.append(f"{name}={anon_val}")

    lines.append("[COOKIES] " + (" | ".join(cookie_parts) if cookie_parts else "-"))

    # ── [BODY] ────────────────────────────────────────────
    content_type = req.headers.get("Content-Type", req.headers.get("content-type", ""))
    lines.append("[BODY] " + _anon_body(req.body or "", content_type))

    # ── [STATUS] ──────────────────────────────────────────
    lines.append(f"[STATUS] {req.status_code if req.status_code is not None else '-'}")

    # ── [RES_HEADERS] ─────────────────────────────────────
    res_headers_parts: list[str] = []
    for name, value in req.response_headers.items():
        name_lower = name.lower()
        if name_lower in _DROP_HEADERS:
            continue
        anon_val = _anon_header_value(name, value)
        res_headers_parts.append(f"{name}: {anon_val}")

    lines.append("[RES_HEADERS] " + (" | ".join(res_headers_parts) if res_headers_parts else "-"))

    # ── [RES_BODY] ────────────────────────────────────────
    lines.append("[RES_BODY] " + _anon_response_body(req.response_body or ""))

    return "\n".join(lines)