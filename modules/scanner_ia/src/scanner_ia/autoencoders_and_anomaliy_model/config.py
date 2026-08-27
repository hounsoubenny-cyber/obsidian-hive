#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 22 18:45:09 2026

@author: hounsousamuel
"""

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(BASE_DIR, exist_ok=True)
MODEL_AUTOENCODER_BODIES_DIR = os.path.join(BASE_DIR, "model_autoencoder_bodies")
MODEL_AUTOENCODER_X_DIR = os.path.join(BASE_DIR, "model_autoencoder_x_dir")
os.makedirs(MODEL_AUTOENCODER_BODIES_DIR, exist_ok=True)
os.makedirs(MODEL_AUTOENCODER_X_DIR, exist_ok=True)

MODEL_AUTOENCODER_BODIES_DIR_PATH = os.path.join(MODEL_AUTOENCODER_BODIES_DIR, "model.pt")
MODEL_AUTOENCODER_X_DIR_PATH = os.path.join(MODEL_AUTOENCODER_X_DIR, "model.pt")