#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 26 22:57:59 2026

@author: hounsousamuel
"""

import os
from dotenv import load_dotenv

load_dotenv()

INSTANCE_ID = os.environ.get("IDS_IPS_INSTANCE_ID", "default")
# Suffixe court et safe pour noms de fichiers/tables nft
INSTANCE_SUFFIX = INSTANCE_ID[-10:] if INSTANCE_ID != "default" else "default"