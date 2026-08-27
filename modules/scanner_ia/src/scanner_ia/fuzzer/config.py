#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 20:23:29 2026

@author: hounsousamuel
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(os.path.join(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

PAYLOADS_FILE = os.path.join(DATA_DIR, "payloads_v3_1.json")
WEIGTHS_FILE = os.path.join(DATA_DIR, "weights_v3.json")
WEIGTHS_FILE_WITH_SEMANTIC = os.path.join(DATA_DIR, "weights_v3_v2_semantic_equilibre.json") #"weights_v3_v1_semantic_fort.json"

if not os.path.exists(PAYLOADS_FILE):
    PAYLOADS_FILE = os.path.join(BACKUP_DIR, "payloads_v3_1.json")
    
if not os.path.exists(WEIGTHS_FILE):
    WEIGTHS_FILE = os.path.join(BACKUP_DIR, "weights_v3.json")

if not os.path.exists(WEIGTHS_FILE_WITH_SEMANTIC):
    WEIGTHS_FILE_WITH_SEMANTIC = os.path.join(BACKUP_DIR, "weights_v3_v2_semantic_equilibre.json")
    
CRITICAL_HEADERS = {
    'content-type', 'server', 'x-powered-by', 'location', 'set-cookie',
    'access-control-allow-origin', 'access-control-allow-credentials',
    'x-shld', 'x-user', 'transfer-encoding'
}

DEFAULT_FORM_VALUES:dict[str, callable] = {
    "email": lambda marker: f"test+{marker}@example.com",
    "text": lambda marker: f"Test{marker}",
    "password": lambda marker: f"password{marker}",
    "number": lambda marker: "42",
    "tel": lambda marker: "0123456789",
    "search": lambda marker: "test",
    "url": lambda marker: f"https://example.com?id={marker}",
    "default": lambda marker: f"test{marker}"
}

SIMILARITY_MODEL_DIR = "model_similarity"
BERT_SIMILARITY_MODEL = "MODEL_BERT"
N_FEATURES_SIM = 1000