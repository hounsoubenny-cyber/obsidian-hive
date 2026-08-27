#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 01:00:11 2026

@author: hounsousamuel
"""

USER_AGENT= "ScannerBot/1.0 (+https://tonsite.exemple) Mozilla/5.0 (compatible; Python aiohttp)"

EXTENSIONS_BY_CATEGORY = {
    "html": [
        ".html", ".htm", ".shtml", ".xhtml",
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".jsp", ".jspx",
        ".cfm", ".cgi", ".pl", ".do"
    ],
    "document": [
        ".pdf", ".doc", ".docx", ".rtf", ".odt",
        ".xls", ".xlsx", ".ods",
        ".ppt", ".pptx", ".odp"
    ],
    "text": [
        ".txt", ".log", ".md"
    ],
    "image": [
        ".jpg", ".jpeg", ".png", ".gif", ".webp",
        ".bmp", ".svg", ".svgz", ".ico"
    ],
    "icon": [
        ".ico"
    ],
    "audio": [
        ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac"
    ],
    "video": [
        ".mp4", ".webm", ".ogv", ".ogg", ".mov", ".avi", ".mkv"
    ],
    "script": [
        ".js", ".mjs", ".ts"
    ],
    "style": [
        ".css", ".less", ".scss"
    ],
    "json": [
        ".json", ".ndjson"
    ],
    "xml": [
        ".xml"
    ],
    "feed": [
        ".rss", ".atom"
    ],
    "data": [
        ".csv", ".tsv"
    ],
    "archive": [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"
    ],
    "binary": [
        ".exe", ".msi", ".bin", ".apk", ".dmg", ".iso"
    ],
    "wasm": [
        ".wasm"
    ],
    "font": [
        ".woff", ".woff2", ".ttf", ".otf", ".eot"
    ],
    "manifest": [
        ".webmanifest", ".manifest", ".appcache"
    ],
    "source_map": [
        ".map"
    ],
    "calendar": [
        ".ics"
    ],
    "config": [
        ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml"
    ],
    "backup": [
        ".bak", ".old", ".swp", ".tmp"
    ],

}

    # --- Dictionnaire Content-Type par catégorie ---
CONTENT_TYPE_BY_CATEGORY = {
    "html": [
        "text/html",
        "application/xhtml+xml"
    ],
    "image": [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml"
    ],
    "video": [
        "video/mp4",
        "video/webm",
        "video/ogg",
        "video/quicktime"
    ],
    "audio": [
        "audio/mpeg",
        "audio/ogg",
        "audio/wav",
        "audio/webm"
    ],
    "document": [
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/rtf",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation"
    ],
    "script": [
        "application/javascript",
        "text/javascript"
    ],
    "style": [
        "text/css"
    ],
    "json": [
        "application/json"
    ],
    "text": [
        "text/plain"
    ],
    "archive": [
        "application/zip",
        "application/x-tar",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/gzip"
    ],
    "xml": [
        "application/xml",
        "text/xml"
    ],
    "feed": [
        "application/rss+xml",
        "application/atom+xml"
    ],
    "binary": [
        "application/octet-stream",
        "application/x-msdownload"
    ],
    "font": [
        "font/woff",
        "font/woff2",
        "font/ttf",
        "font/otf",
        "application/vnd.ms-fontobject"
    ],
    "manifest": [
        "application/manifest+json",
        "text/cache-manifest"
    ],
    "calendar": [
        "text/calendar"
    ]

}

TESTS_NORMALIZE = [ 
    # ===== CAS DE BASE =====
    ("https://example.com", "page.html", "https://example.com/page.html"),
    ("https://example.com/dir/", "page.html", "https://example.com/dir/page.html"),
    
    # ===== ANCRES ET FRAGMENTS =====
    ("https://example.com/page#section", "#top", "https://example.com/page"),
    ("https://example.com/page?q=test#section", "#", "https://example.com/page?q=test"),
    ("https://example.com/page", "#", "https://example.com/page"),
    
    # ===== CHEMINS RELATIFS COMPLEXES =====
    ("https://example.com/a/b/c/", "../../d/e/f", "https://example.com/a/d/e/f"),
    ("https://example.com/a/b/c/", "../../../d", "https://example.com/d"),
    ("https://example.com/a/b/", "./c/d/../e", "https://example.com/a/b/c/e"),
    ("https://example.com/a//b///c/", "d", "https://example.com/a/b/c/d"),  # Doubles slashes
    
    # ===== URLS ABSOLUES =====
    ("https://example.com", "http://autre-site.com", "http://autre-site.com"),
    ("https://example.com", "https://autre-site.com:8080/path", "https://autre-site.com:8080/path"),
    
    # ===== PROTOCOLE-RELATIF =====
    ("http://example.com", "//cdn.com/image.jpg", "http://cdn.com/image.jpg"),
    ("https://example.com", "//cdn.com/image.jpg", "https://cdn.com/image.jpg"),
    ("ftp://example.com", "//cdn.com/image.jpg", "ftp://cdn.com/image.jpg"),  # Protocole bizarre
    
    # ===== PARAMÈTRES DE REQUÊTE =====
    ("https://example.com", "search?q=test", "https://example.com/search?q=test"),
    ("https://example.com/dir/", "page?x=1&y=2", "https://example.com/dir/page?x=1&y=2"),
    ("https://example.com/page?existing=1", "?new=2", "https://example.com/page?new=2"),
    
    # ===== PARAMÈTRES AVEC ANCRES =====
    ("https://example.com", "page?q=test#section", "https://example.com/page?q=test"),
    ("https://example.com/page?q=test#section", "?new=1#newsec", "https://example.com/page?new=1"),
    
    # ===== CAS LIMITES DES PROTOCLES =====
    ("https://example.com", "mailto:test@example.com", None),
    ("https://example.com", "data:text/plain,Hello", None),
    ("https://example.com", "blob:https://example.com", None),
    ("https://example.com", "tel:+123456789", None),
    ("https://example.com", "javascript:void(0)", None),
    
    # ===== URLS DÉJÀ NORMALISÉES =====
    ("https://example.com", "https://example.com", "https://example.com"),
    ("https://example.com/", "https://example.com/", "https://example.com/"),
    
    # ===== CHEMINS RACINE =====
    ("https://example.com/dir/page.html", "/", "https://example.com/"),
    ("https://example.com/dir/page.html", "/root", "https://example.com/root"),
    
    # ===== POINTS DE SUSPENSION EXCESSIFS =====
    ("https://example.com/a/b/", "../../../../../../etc/passwd", "https://example.com/etc/passwd"),
    
    # ===== ENCODAGE =====
    ("https://example.com", "café", "https://example.com/caf%C3%A9"),  # Caractères spéciaux
    ("https://example.com", "page with spaces", "https://example.com/page%20with%20spaces"),
    
    # ===== CAS D'ERREUR =====
    ("", "page.html", None),  # Base vide
    ("https://example.com", "", None),  # Lien vide
    ("https://example.com", "   ", None),  # Lien avec seulement des espaces
    (None, "page.html", None),  # Base None
    ("https://example.com", None, None),  # Lien None
    
    # ===== URLS RELATIVES SPÉCIALES =====
    ("https://example.com/dir/", "?query=1", "https://example.com/dir/?query=1"),
    ("https://example.com/dir/", "&query=1", "https://example.com/dir/&query=1"),  # Cas bizarre
    ("https://example.com/dir/", ";param=1", "https://example.com/dir/;param=1"),  # Path params
    
    # ===== PORTS =====
    ("https://example.com:8080", "/page", "https://example.com:8080/page"),
    ("https://example.com:8080", "//autre.com", "https://autre.com"),  # Perd le port
    
    # ===== MAJUSCULES/MINUSCULES =====
    ("https://EXAMPLE.com", "/Page", "https://example.com/Page"),
    ("HTTP://example.com", "/page", "http://example.com/page"),
    
    # ===== FRAGMENTS IGNORÉS =====
    ("https://example.com#old", "new#frag", "https://example.com/new"),
    
    # ===== MÉLANGE COMPLEXE =====
    ("https://user:pass@example.com:8080/dir/page?x=1#sec", 
     "../../other/./././../final?y=2#new", 
     "https://user:pass@example.com:8080/final?y=2"),
    
    # ===== URLS RELATIVES AVEC BACKTRACKING =====
    ("https://example.com/a/b/c/d/e/f/", "../../../../g", "https://example.com/a/b/g"),
]
