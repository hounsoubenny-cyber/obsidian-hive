#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 22:50:33 2026

@author: hounsousamuel
"""

# conftest.py dans le dossier tests
import sys

def pytest_configure(config):
    # Bloquer le plugin avant qu'il ne soit chargé
    config.pluginmanager.set_blocked('logfire')