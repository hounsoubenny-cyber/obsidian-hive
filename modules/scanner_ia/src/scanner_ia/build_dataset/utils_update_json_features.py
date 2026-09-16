#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 15 11:10:58 2026

@author: hounsousamuel
"""

import os
import glob
from scanner_ia.build_dataset.build_dataset_data import V1_TARGETS 

DIRNAME = os.path.dirname(__file__)
CHUNK_DIR = os.path.join(DIRNAME, "dataset_chunks")
CHUNK_FILES = sorted(glob.glob(os.path.join(CHUNK_DIR, "chunk_*.csv")))
URLS = [_[0] for _ in V1_TARGETS]



