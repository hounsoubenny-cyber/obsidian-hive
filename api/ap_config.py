#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 23:34:01 2026

@author: hounsousamuel
"""

import os
from obsidian_hive.config.config import _get_config_manager

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
