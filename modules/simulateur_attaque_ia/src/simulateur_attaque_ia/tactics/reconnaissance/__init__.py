#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan  9 06:04:07 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from tactics.reconnaissance.port_scan_and_banner_grab import NetworkServiceDiscover

__all__ = [
    "NetworkServiceDiscover"
]