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

BASEDIR = os.path.abspath(os.path.dirname(__file__))
API_HOST = "0.0.0.0"
API_PORT = _get_config_manager().api_config.api_port
LIMITE = 25
PORT = 8000
API_IP = "127.0.0.1"
ALLOWED_ORIGINS = [
    f"http://{API_IP}:{API_PORT}",
    f"http://localhost:{API_PORT}",
    f"http://{API_HOST}:{API_PORT}",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
NOT_BEFORE = 0.1
EXP = 60 * 5
STATIC_DIR = "."
BUILD_DIR = "."
INDEX_FILE = "."
REACT_EXISTS = False
STATIC_URL = "/static"
BUILD_URL = "/build"

# ENV
USER_ENV_KEY = "OBSIDIAN_ADMIN_USER"
PASSWD_ENV_KEY = "OBSIDIAN_ADMIN_PASSWORD"
SECRET_KEY_ENV_KEY = "OBSIDIAN_JWT_SECRET"

IDS_IPS_PY_VENV = "OBSIDIAN_IDS_IPS_PY_VENV"

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