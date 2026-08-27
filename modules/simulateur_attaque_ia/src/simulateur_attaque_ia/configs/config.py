#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:14:55 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from dotenv import load_dotenv
load_dotenv()

from simulateur_attaque_ia.configs.utils import _get_api_keys, _get_llm_env

NOT_BEFORE = 0.1
EXP = 60 * 8
LIMITE = 30
IP = "0.0.0.0"
PORT = 8080
STATIC_DIR = "."
BUILD_DIR = "."
INDEX_FILE = "."
REACT_EXISTS = False
STATIC_URL = "/static"
BUILD_URL = "/build"

API_IP = "127.0.0.1"
ALLOWED_ORIGINS = [
    "*",
    # f"http://{API_IP}:{PORT}",
    # f"http://localhost:{PORT}",
    # f"http://{IP}:{PORT}",
    # "http://localhost:3000",
    # "http://127.0.0.1:3000",
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))
REPORT_DIR = os.path.join(BASEDIR, "..", "sim_report")

CACHE_DIR = os.path.join(BASEDIR, "..", "var", "cache")
CACHE_EXP = None

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

SIM_MAX_CONCURRENT = 3
SIM_KEEP_DELAY = 1800
CLONE_KEEP_DELAY = 30

SIM_BUFFER_CLEAR_DELAY = 1800
SIM_BUFFER_MAX_MESSAGES = 2000


CONT_INACTIVE_TIMEOUT = 30 * 60

# ─── LLM ─────────────────────────────────────────────────────────────────────

LLAMA_SERVER_PATH    = _get_llm_env("LLAMA_SERVER_PATH", ...)
LLAMA_SERVER_PORT    = _get_llm_env("LLAMA_SERVER_PORT", 9000, cast_to=int)
LLAMA_SERVER_HOST    = _get_llm_env("LLAMA_SERVER_HOST", "127.0.0.1")
LLAMA_MODELS_PRESET  = _get_llm_env("LLAMA_MODELS_PRESET", ...)

DEFAULT_API_KEYS = _get_api_keys(
    "API_KEYS",
    default=[("qwen2.5-3b", "local-fake-key")],
)

# ─── Validation au démarrage ─────────────────────────────────────────────────

if not os.path.exists(LLAMA_SERVER_PATH):
    raise RuntimeError(
        f"[config] llama-server introuvable : {LLAMA_SERVER_PATH}\n"
        f"→ Définis SIMATK_LLAMA_SERVER_PATH dans ton .env"
    )

if not os.path.exists(LLAMA_MODELS_PRESET):
    raise RuntimeError(
        f"[config] models_preset introuvable : {LLAMA_MODELS_PRESET}\n"
        f"→ Définis SIMATK_LLAMA_MODELS_PRESET dans ton .env"
    )

# Validation que le .ini est un preset llama valide
# (au moins une section autre que [*], avec une clé 'model')

def validate_model_ini(path, api_keys):
    import configparser
    _cfg = configparser.ConfigParser()
    _cfg.read(path)
    _model_sections = [s for s in _cfg.sections() if s != "*"]
    
    if not _model_sections:
        raise RuntimeError(
            f"[config] {LLAMA_MODELS_PRESET} ne contient aucune section de modèle.\n"
            f"→ Ajoute au moins une section [nom_modele] avec model=/chemin/vers/fichier.gguf"
        )
    _missing = [s for s in _model_sections if not _cfg.has_option(s, "model")]
    if _missing:
        raise RuntimeError(
            f"[config] Sections sans clé 'model' dans {LLAMA_MODELS_PRESET} : {_missing}\n"
            f"→ Chaque section doit avoir model=/chemin/vers/fichier.gguf"
        )
    _missing_files = [
        _cfg[s]["model"] for s in _model_sections
        if not os.path.exists(_cfg[s]["model"])
    ]
    
    if _missing_files:
        raise RuntimeError(
            "[config] Fichiers .gguf introuvables :\n"
            + "\n".join(f"  - {p}" for p in _missing_files)
            + "\n→ Vérifie les chemins dans ton models.ini"
        )
    
    if not api_keys:
        raise RuntimeError(
            "[config] Aucune clé API configurée.\n"
            "→ Définis au moins SIMATK_API_KEYS_1=model_name,api_key dans ton .env"
        )

validate_model_ini(LLAMA_MODELS_PRESET, DEFAULT_API_KEYS)