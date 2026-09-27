#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 23:34:01 2026

@author: hounsousamuel
"""

import os
from obsidian_hive.config.config import _get_config_manager
from dotenv import load_dotenv
load_dotenv()

START_ALL_KEY = "START_ALL"
START_ALL = os.environ.get(START_ALL_KEY, "0").strip().lower() in ("1", "true")
BASEDIR = os.path.abspath(os.path.dirname(__file__))
API_HOST = "0.0.0.0"
API_PORT = _get_config_manager().api_config.api_port
ALERT_THRESHOLD = _get_config_manager().global_config.alert_threshold
LIMITE = 25
PORT = 8000
API_IP = "127.0.0.1"
SCHEME = "http"
BASE_URL = f"{SCHEME}://{API_IP}:{API_PORT}" if API_PORT is not None else  f"{SCHEME}://{API_IP}"
ALLOWED_ORIGINS = [
    # BASE_URL,
    # f"{SCHEME}://localhost:{API_PORT}" if API_PORT is not None else f"{SCHEME}://localhost",
    # "{SCHEME}://localhost:3000",
    # "{SCHEME}://127.0.0.1:3000",
    
    "*"
]
NOT_BEFORE = 0.1
EXP = 60 * 5
FRONTEND_DIST_FOLDER = "OBSIDIAN_FRONTEND"
FAVICON_FOLDER = "favicon"
FAVICON_IMAGE_NAME = "obsidian_hive.svg"
BUILD_FOLDER = "dist"

BUILD_DIR = os.path.abspath(os.path.join(BASEDIR, "..", FRONTEND_DIST_FOLDER, BUILD_FOLDER))
STATIC_DIR = os.path.abspath(os.path.join(BUILD_DIR, "assets"))
INDEX_FILE = os.path.join(BUILD_DIR, "index.html")
FAVICON_FILE = os.path.abspath(os.path.join(BASEDIR, "..", FRONTEND_DIST_FOLDER, FAVICON_FOLDER, FAVICON_IMAGE_NAME))

REACT_EXISTS = all(
    os.path.exists(path)
    for path in [
        BUILD_DIR, STATIC_DIR, INDEX_FILE
    ]
)
STATIC_URL = "/assets"
BUILD_URL = "/dist"

# ENV
USER_ENV_KEY = "OBSIDIAN_ADMIN_USER"
PASSWD_ENV_KEY = "OBSIDIAN_ADMIN_PASSWORD"
SECRET_KEY_ENV_KEY = "OBSIDIAN_JWT_SECRET"

IDS_IPS_PY_VENV = "OBSIDIAN_IDS_IPS_PY_VENV"
CHECK_PROMPT_KEY = "OBSIDIAN_CHECK_PROMPT"

# Asset Config
ASSETS_CONFIG_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "assets_config"
)
os.makedirs(ASSETS_CONFIG_DIR, exist_ok=True)

BINARY_DIR = os.path.abspath(os.path.join(BASEDIR, "..", "dist"))

TOOL_ENGINE_BINARY_PATH = os.path.join(BINARY_DIR, "tool_engine")
AGENT_CORE_BINARY_PATH = os.path.join(BINARY_DIR, "obsidian-agent")


# Checker les env keys
def _check_env(key: str, is_path: bool = False):
    load_dotenv()
    v = os.environ.get(key, None)
    if not v:
        raise RuntimeError(f"The env variable '{key}' is missing")
    
    if is_path and not os.path.exists(v):
        raise RuntimeError(f"The env variable '{key}' is a path but doesn't exists !")

_check_env(IDS_IPS_PY_VENV, is_path=True)