#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 11 09:49:27 2026

@author: hounsousamuel
"""

# =============================================================================
#  Brève decription du projet
# =============================================================================
__version__ = '2.0.0'
__autor__ = "HOUNSOU Samuel"
__user_name__ = 'hounsousamuel'
__email__ = 'hounsounbenny@gmail.com'
__projet_name__ = "AntiPhishing Based on IA and Static Analysis"


import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from anti_phishing_ia.ml_model.phishing_ia import features_name 
from anti_phishing_ia.config import *
