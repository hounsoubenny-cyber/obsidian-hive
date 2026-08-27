#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 22:54:15 2026

@author: hounsousamuel
"""

import os, sys
from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX

BASEDIR = os.path.dirname(os.path.abspath(__file__))
REFIT_DIR = os.path.join(BASEDIR, "data", INSTANCE_SUFFIX, "refit_data")
FILE_PREFIX = "refit_data"
os.makedirs(REFIT_DIR, exist_ok=True)