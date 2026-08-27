#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 19 08:14:18 2026

@author: hounsousamuel
"""

import os

DIRNAME = os.path.dirname(os.path.abspath(__file__))
BASEDIR = os.path.abspath(os.path.join(DIRNAME, "..", "frontend"))

BUILD_DIR = os.path.join(BASEDIR, "build")
STATICDIR = os.path.join(BUILD_DIR, "static")
INDEX_FILE = os.path.join(BUILD_DIR, "index.html")
REACT_EXISTS = all(os.path.exists(path) for path in (BUILD_DIR, STATICDIR, INDEX_FILE))
BUILD_URL = "/build"
STATIC_URL = "/static"
