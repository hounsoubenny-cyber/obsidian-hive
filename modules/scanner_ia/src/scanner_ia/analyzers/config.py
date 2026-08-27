#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar  8 14:38:23 2026

@author: hounsousamuel
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(os.path.join(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

HTML_SIGNATURE_FILE = os.path.join(DATA_DIR,"html_signatures.json" )
JS_SIGNATURE_FILE = os.path.join(DATA_DIR, "js_signatures.json")

if not os.path.exists(HTML_SIGNATURE_FILE):
    HTML_SIGNATURE_FILE = os.path.join(BACKUP_DIR, "html_signatures.json")
    
if not os.path.exists(JS_SIGNATURE_FILE):
    JS_SIGNATURE_FILE = os.path.join(BACKUP_DIR, "js_signatures.json")