#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 13 21:14:50 2026

@author: hounsousamuel
"""

import joblib as jb
from sandbox_ia.ml_model.autoencoders import AutoEncoder, DEVICE
from sandbox_ia.ml_model.classifier import Classifier

def load_models(
    ae_model_path: str,
    classifier_model_path: str,
    scaler_ae_path: str,
    scaler_ae_ebd_path: str,
    scaler_classifier_path: str,
    threshold_path: str
):
    threshold_dict = dict(jb.load(threshold_path))
    ae = AutoEncoder(
        d_model=256, 
        num_heads=8,
        num_features=10,
    )
    classifier = Classifier(
        d_model=256, 
        num_heads=8,
        num_features=10,
        num_layer=1,
    )
    ae.load(ae_model_path)
    classifier.load(classifier_model_path)
    ae.eval()
    classifier.eval()
    ae.to(DEVICE)
    classifier.to(DEVICE)
    scaler_ae = jb.load(scaler_ae_path)
    scaler_ae_ebd = jb.load(scaler_ae_ebd_path)
    scaler_classsifier = jb.load(scaler_classifier_path)
    
    return {
        "threshold_dict": threshold_dict,
        "ae": ae,
        "classifier": classifier,
        "scaler_ae": scaler_ae,
        "scaler_ae_ebd": scaler_ae_ebd,
        "scaler_classsifier": scaler_classsifier,
    }