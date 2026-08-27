#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 13 15:37:31 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
from anti_phishing_ia.core.legitimate_db_manager import LegitDomainDBManager
LEGITIMATE_DOMAINS = None
def _get_legitimate_domain():
    global LEGITIMATE_DOMAINS
    if LEGITIMATE_DOMAINS is None:        
        LEGITIMATE_DOMAINS = LegitDomainDBManager()
    return LEGITIMATE_DOMAINS
