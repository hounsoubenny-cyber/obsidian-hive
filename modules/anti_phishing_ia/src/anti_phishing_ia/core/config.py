#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 14:44:58 2026

@author: hounsousamuel
"""

import os
AWAIT_TIME = 2 # 3
DB_PATH = os.path.join(
    os.path.abspath(
        os.path.dirname(
            __file__
        ),
    ),
    "legite_domain"
)
os.makedirs(DB_PATH, exist_ok=True)
DB_PATH = os.path.join(
    DB_PATH, "legitimate_domains_mega.db"
)

LEGIT_BATCH_SIZE = 50000
