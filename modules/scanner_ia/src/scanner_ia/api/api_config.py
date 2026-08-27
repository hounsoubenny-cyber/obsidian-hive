#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 09:05:03 2026

@author: hounsousamuel
"""

import os
IP = "0.0.0.0"
PORT = 9000
API_HOST_PUBLIC = "localhost"  
API_PORT = 9000
LIMITE = 10
ALLOWED_ORIGINS = ["*"]
NOT_BEFORE = 0.1
EXP = 60 * 3
MAX_CONFIG_SIZE = 20 * 1024  # 20KB
STATICDIR = "."
BUILD_DIR = "."
INDEX_FILE = "."
REACT_EXISTS = False
CONFIG_TEMP_DIR = "/tmp/shieldai_configs"
os.makedirs(CONFIG_TEMP_DIR, exist_ok=True)
BASEDIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCAN_PATH = os.path.abspath(os.path.join(BASEDIR, "..", "shieldai_scanner.config.json5"))
WS_DISCONNECT_TIMEOUT = 60  # secondes avant annulation après disconnect

DEFAULT_SCANNER_ARGS = {
    # Scan
    "active_scan":       False,        
    "use_cache":         True,
    "restore":           False,
    "debug":             False,       

    # Fetcher
    "semaphore":         50,

    # Analyse
    "headers_sev_map":   None,
    "use_semantic":      True,

    # Fuzzer
    "limit_payloads":    None,         
    "use_arjun":         False,
    "arjun_timeout":     30,
    "known_params_dir":  None,
    # UI
    "theme":             "multi",
}
