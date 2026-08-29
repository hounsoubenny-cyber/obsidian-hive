#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 21:48:54 2026

@author: hounsousamuel
"""

import os
import json
import joblib
from urllib.parse import urljoin

SAFESERVER_BASE = "http://localhost:5051"

MANIFEST_PATH = "~/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/serveurs/safeserver/manifest.json"
SAVE_PATH = "~/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/serveurs/safeserver/safeserver_labels.pkl"

MANIFEST_PATH = os.path.expanduser(MANIFEST_PATH)
SAVE_PATH = os.path.expanduser(SAVE_PATH)

DATA = {}
FORCE = False
if os.path.exists(SAVE_PATH):
    try:
        DATA = dict(joblib.load(SAVE_PATH))
    except Exception:
        pass

if not DATA or FORCE:
    with open(MANIFEST_PATH, "r") as f:
        data = dict(json.load(f))
        routes = data["routes"]
        for r in routes:
            url = urljoin(SAFESERVER_BASE, r["route"])
            DATA[url] = r["vulns"] or []
    joblib.dump(DATA, SAVE_PATH)

HELPER_SAFESERVER = []
        