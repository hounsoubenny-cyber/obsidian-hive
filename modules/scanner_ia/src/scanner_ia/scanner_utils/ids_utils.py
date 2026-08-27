#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 09:35:43 2026

@author: hounsousamuel
"""

import secrets


def create_scan_id():
    scan_id = secrets.token_hex()
    return f"sh_sc-{str(scan_id)}"
