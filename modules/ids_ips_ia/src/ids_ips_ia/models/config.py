#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan  2 13:39:36 2026

@author: hounsousamuel
"""

import os, sys
from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX

BASEDIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(os.path.join(BASEDIR, "data", "models", INSTANCE_SUFFIX))

os.makedirs(BASEDIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

CONFIG_MODELS = {
    "fast": {
        "seq_latent": 128, # 64
        "seq_dropout": 0.1,
        "seq_if_estimators" : 500,
        "pkt_if_estimators" : 500,
        "pkt_hidden" : 128, # 64
        },
    'full': {
        "seq_latent": 256, # 128
        "seq_dropout": 0.2,
        "seq_if_estimators" : 800,
        "pkt_if_estimators" : 800,
        "pkt_hidden" : 256, # 128
        },
    }

CONFIG_CNN = {
    'fast': {
        "filters" : 128, # 64
        "seq_dropout" : 0.10,
        },
    'full': {
        "filters" : 256, # 128
        "seq_dropout" : 0.20,
        },
    }

