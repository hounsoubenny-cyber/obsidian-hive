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


from anti_phishing_ia.core.features_extractor import get_features_names
from anti_phishing_ia.config import * # noqa
features_name = get_features_names()