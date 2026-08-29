#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 22 19:57:55 2026

@author: hounsousamuel
"""

import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))

WEB_ASSET_SCAN_REPORT_DIR = os.path.abspath(os.path.join(
    BASEDIR, "..", "..", "web_asset_report_dir"
))

os.makedirs(WEB_ASSET_SCAN_REPORT_DIR, exist_ok=True)