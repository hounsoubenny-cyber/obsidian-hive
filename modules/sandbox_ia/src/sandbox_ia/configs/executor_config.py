#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 09:49:25 2026

@author: hounsousamuel
"""


LANGUAGE_TIMEOUTS = {
    "python": 20,
    "bash": 15,
    "javascript": 20,
    "php": 20,
    "ruby": 20,
    "perl": 20,
    "go": 25,
    "rust": 40,      # compilation
    "java": 45,      # compilation
    "c": 35,         # compilation
    "cpp": 35,       # compilation
    "lua": 20,
    "r": 25,
    "powershell": 20,
}

DEFAULT_TIMEOUT = 30