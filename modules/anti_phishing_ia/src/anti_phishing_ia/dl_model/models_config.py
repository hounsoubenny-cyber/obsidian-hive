#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 13 16:56:25 2026

@author: hounsousamuel
"""

import os, sys
BASEDIR        = os.path.dirname(os.path.abspath(__file__))
MODELS_BASEDIR = os.path.abspath(os.path.join(BASEDIR,"..", "..", "..", "..", "MODEL_SHARED"))
MODELS_TEXT_DIR     = os.path.abspath(os.path.join(MODELS_BASEDIR, "text"))

TEXT_MODEL_PATHS = {
    "very_fast": os.path.join(MODELS_TEXT_DIR, "very_fast"),
    "fast"     : os.path.join(MODELS_TEXT_DIR, "fast"),
    "full"     : os.path.join(MODELS_TEXT_DIR, "full"),
}