#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 11:13:40 2026

@author: hounsousamuel
"""

import os

API_HOST = "0.0.0.0"
API_PORT = 8100
LIMITE = 10
ALLOWED_ORIGINS = ["*"]
NOT_BEFORE = 0.1
EXP = 60 * 3
STATIC_DIR = "."
BUILD_DIR = "."
INDEX_FILE = "."
REACT_EXISTS = False
DEFAULT_SANDBOX_CONFIG_OVERRIDES = {
    "mem_limit":         "256m",
    "exec_timeout":      30.0,
    "alert_threshold":   60,
    "enable_strace":     True,
    "enable_fs_monitor": True,
}