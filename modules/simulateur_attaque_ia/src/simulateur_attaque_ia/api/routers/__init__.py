#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:20:20 2026

@author: hounsousamuel
"""


import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from simulateur_attaque_ia.orchestrator.orchestrator_env import get_data

AUTH_DATA = get_data()
JWT_KEY = "jwt_key"