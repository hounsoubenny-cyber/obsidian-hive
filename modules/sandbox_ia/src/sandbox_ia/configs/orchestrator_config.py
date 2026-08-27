#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 29 20:50:49 2026

@author: hounsousamuel
"""

import os
# =============================================================================
# CONSTANTES
# =============================================================================


DEFAULT_SANDBOX_IMAGE = "shieldai-sandbox:v2-light"
DEFAULT_EXECUTION_TIMEOUT = 30.0

DOCKER_DEFAULTS = {
    "network_disabled": True,
    "mem_limit": "256m",
    "cpu_quota": 50000,
    "cpu_period": 100000,
    "pids_limit": 64,
    "read_only": False,
    "user": "sandbox",
    "workdir": "/sandbox/work",
    "extra_env": None,
}

CACHE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "var",
        "sandbox_cache"
    )
)
os.makedirs(CACHE_DIR, exist_ok=True)

