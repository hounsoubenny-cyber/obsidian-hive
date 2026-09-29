#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 20:56:10 2026

@author: hounsousamuel
"""

import os
import dill
from sklearn.utils.validation import check_is_fitted
from ids_ips_ia.core.features_extractor import FeatureExtractor

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


def _features_compatibles(data: dict) -> bool:
    """Le modèle a-t-il été entraîné avec le schéma de features actuel ?

    Un modèle entraîné avec un autre nombre de features (ex : avant le passage de `time` en
    time_sin/time_cos) ne peut plus prédire : chaque paquet lèverait une erreur. On le refuse
    ici pour que le fit soit relancé, plutôt que de laisser l'IDS aveugle sans le dire.
    En cas de doute (attribut absent, import impossible) on bloque."""
    try:
        n_pkt = len(FeatureExtractor.get_feature_name("pkt"))
        n_seq = len(FeatureExtractor.get_feature_name("seq"))
        got_pkt = getattr(data['scaler_pkt'], 'n_features_in_', n_pkt)
        got_seq = getattr(data['scaler_seq'], 'n_features_in_', n_seq)
        if got_pkt != n_pkt or got_seq != n_seq:
            print(
                f"Modèle incompatible : entraîné avec {got_pkt}/{got_seq} features "
                f"(paquet/séquence), le schéma actuel en demande {n_pkt}/{n_seq}."
              )
            return False
        return True
    except Exception as e:
        print(f"Erreur dans la vérification du nombre de features: {e!r}")
        return False
    
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
        except Exception as e:
            print(f"Erreur dans check_fitted pour un modèle: {e!r}")
            return False
        
        if not _features_compatibles(data):
            return False
        
        return True
    except Exception as e:
        print("Erreur dans la validation du fichier :", str(e))
    