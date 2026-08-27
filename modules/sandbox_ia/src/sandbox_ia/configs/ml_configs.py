#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 13 20:56:35 2026

@author: hounsousamuel
"""

import os
from os.path import exists

BASEDIR = os.path.abspath(os.path.dirname(__file__))

MODEL_DIR = os.path.abspath(os.path.join(BASEDIR, "..", "ml_model", "models"))
AE_DIR = os.path.join(MODEL_DIR, "ae")
CLASSIFIER_DIR = os.path.join(MODEL_DIR, "classifier")

THRESHOLD_PATH = os.path.join(MODEL_DIR, "threshold_v1.joblib")

SCALER_AE_EBD_PATH = os.path.join(AE_DIR, "scaler_ebd.joblib")
SCALER_AE_PATH = os.path.join(AE_DIR, "scaler.joblib")
AE_MODEL = os.path.join(AE_DIR, "autoencoder_v1.pt")

SCALER_CLASSIFIER_PATH = os.path.join(CLASSIFIER_DIR, "scaler.joblib")
CLASSIFIER_MODEL = os.path.join(CLASSIFIER_DIR, "classifier_v1.pt")

PATHS = [
    THRESHOLD_PATH,
    SCALER_AE_EBD_PATH,
    SCALER_AE_PATH,
    SCALER_CLASSIFIER_PATH,
    CLASSIFIER_MODEL,
    AE_MODEL,
]

PATH_DICT = {
    "ae_model_path": AE_MODEL,
    "classifier_model_path": CLASSIFIER_MODEL,
    "scaler_ae_path": SCALER_AE_PATH,
    "scaler_ae_ebd_path": SCALER_AE_EBD_PATH,
    "scaler_classifier_path": SCALER_CLASSIFIER_PATH,
    "threshold_path": THRESHOLD_PATH
}

ML_AVAILABLE = all(exists(p) for p in PATHS)