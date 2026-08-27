#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 20:56:10 2026

@author: hounsousamuel
"""

import os, sys
import dill
import numpy as np
from sklearn.utils.validation import check_is_fitted

KEYS = [
    'ae_seq',
    'cnn_seq',
    'if_seq',
    'lof_seq',
    'ae_pkt',
    'if_pkt',
    'lof_pkt',
    'scaler_pkt',
    'scaler_seq'
]

ESTIMATORS = [
    'if_seq',
    'lof_seq',
    'if_pkt',
    'lof_pkt',
    'scaler_pkt',
    'scaler_seq'
]


def validate_model_file(model_path_or_dict:str|dict):
    try:
        if isinstance(model_path_or_dict, dict):
            data = model_path_or_dict
        else:
            if isinstance(model_path_or_dict, str):
                if not os.path.exists(model_path_or_dict):
                    return False
            
            data = {}
            with open(model_path_or_dict, "rb") as f:
                data = dill.load(f)
                
        if not data or not isinstance(data, dict):
            return False
        
        if any(k not in data for k in KEYS):
            return False
        
        try:
            for k in ESTIMATORS:
                check_is_fitted(data[k])
        except Exception:
            return False
        
        return True
    except Exception as e:
        print("Erreur dans la validation du fichier :", str(e))
    