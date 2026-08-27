#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 15 07:17:18 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import random
from scanner_ia.scanner_utils.warnings_manager import suppres_warnings
suppres_warnings()
import pandas as pd
import numpy as np
from scanner_ia.ml_model.datamanager import DataManager, _DEFAULT_TARGET_FUNC
from scanner_ia.ml_model.config import VULNS, FEATURES_LIST
from scanner_ia.ml_model.modelmanager import ModelManager

# from loguru import logger as scanner_ia_logger
from scanner_ia.scanner_utils.logger import get_logger
scanner_ia_logger = get_logger()

# Configuration des logs
# scanner_ia_logger.remove()
# scanner_ia_logger.add(
#     sys.stdout,
#     format=(
#         "<yellow>{time:HH:mm:ss}</yellow> | "
#         "<level>{level: <8}</level> | "
#         "<magenta>{name}</magenta>:<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
#         "└─ <level>{message}</level>"
#     ),
#     level="DEBUG",
#     colorize=True
# )
# scanner_ia_logger.add(
#     "logs/scanner_ia.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )

pd.set_option("display.max_rows", 200)
pd.set_option("display.max_columns", 200)

class Config:
    def __init__(self):
        self.CLASSES:list = []
        self.NUM_FEATURES:list = []
        self.CAT_FEATURES:list = []
        self.VERBOSE:int = 0
        self.WRAPPER:str = "chain"
        self.CV:int = 5
        self.META_NAME:str = "pipeline_estimator"
        self.MODEL_DIR:str = "model"
    
class ScannerIA:
    __version__ = "2.0.0"
    __author__ = "Samuel - ShielIA - Partie scanner web"
    
    def __init__(
        self,
        classes:list = None,
        num_features:list = None,
        cat_features:list = None,
        verbose:int = None,
        wrapper:str = None,
        cv:int = None,
        meta_name:str = None,
        model_dir:str = None
    ):
        
        self.config = Config()
        classes = classes or self.config.CLASSES
        num_features = num_features or self.config.NUM_FEATURES
        cat_features = cat_features or self.config.CAT_FEATURES
        verbose = verbose or self.config.VERBOSE
        wrapper = wrapper or self.config.WRAPPER
        cv = cv or self.config.CV
        meta_name = meta_name or self.config.META_NAME
        model_dir = model_dir or self.config.MODEL_DIR
        
        self.model_manager = ModelManager(
            classes=classes, num_features=num_features,
            cat_features=cat_features, verbose=verbose,
            wrapper=wrapper, cv=cv, meta_name=meta_name,
            model_dir=model_dir
            )
        self.data_manager = DataManager()    
    
    def _set_num_features(self, X):
        num_features, cat_features = self.model_manager.get_idx(X)
        self.model_manager.num_features = num_features
        self.model_manager.cat_features = cat_features
        scanner_ia_logger.info(f"✓ Features identifiées: {len(self.model_manager.num_features)} numériques, {len(self.model_manager.cat_features)} catégorielles")
    
    def prepare_data(
        self, 
        data:list[dict]|pd.DataFrame, 
        cols:list[str],
        cols_to_drop:list[str], 
        target:str, 
        target_func:callable = _DEFAULT_TARGET_FUNC,
        restrain_to_cols:bool = True,
        apply_smote:bool = True
    ):
        
      return self.data_manager.prepare_data(data, cols, cols_to_drop, target, restrain_to_cols, apply_smote=apply_smote)  
  
    def fit(
        self,
        X:np.ndarray = None,
        y:np.ndarray = None,
        data_path:str = "",
        data:list[dict]|pd.DataFrame = None, 
        base_data:list[dict]|pd.DataFrame = None,
        union_path:str = "./union",
        cols:list[str] = [],
        cols_to_drop:list[str] = [], 
        target:str = "", 
        target_func:callable = _DEFAULT_TARGET_FUNC,
        cv:int = 3,
        optimize:bool = True,
        optimization_size:float = 0.5,
        n_trial:int = 50,
        timeout:float|None = None,
        visualize:bool = True,
        test_size:float = 0.2,
        do_learning_curve:bool = True,
        user_mlb:bool = True,
        restrain_to_cols:bool = True,
        apply_smote:bool = True,
    ):
        if data_path:
            data = self.data_manager.load_dataset(data_path, "df")
            if any(not x for x in (cols, cols_to_drop, target)):
                raise ValueError("Données manquantes pour la combinaison avec les chemins")
            if base_data is not None:
                data = self.data_manager.add_data(base_data, data, path=union_path)
            _, X, y = self.prepare_data(data, cols, cols_to_drop, target, restrain_to_cols)
            
        elif data is not None or not pd.DataFrame(data).empty:
            if any(not x for x in (cols, cols_to_drop, target)):
                raise ValueError("Données manquantes pour la combinaison avec les chemins")
            if base_data is not None:
                data = self.data_manager.add_data(base_data, data, path=union_path)
            _, X, y = self.prepare_data(data, cols, cols_to_drop, target, restrain_to_cols, apply_smote=apply_smote)
        
        elif X is not None and y is not None:
            pass # Ne rien faire, n passe
        
        else:
            raise ValueError("Veuillez specifier les données, chemin ou data, ou array(X et y)")
        
        self._set_num_features(X)
        self.model_manager.fit(
            X=X, y=y, optimize=optimize,
            visualize=visualize, cv=cv,
            optimization_size=optimization_size,
            n_trial=n_trial, timeout=timeout,
            do_learning_curve=do_learning_curve,
            user_mlb=user_mlb, test_size=test_size
            )
        return self
        
    
    def predict_proba(self, X):
        return self.model_manager.predict_proba(X)
        
    def predict(self, X, threshold:float|np.ndarray = 0.5):
        return self.model_manager.predict(X, threshold)
    
    def scanner_predict(self, X, threshold:float|np.ndarray = 0.5):
        predict = self.model_manager.predict(X, threshold)
        predict_transform = self.model_manager.mlb.inverse_transform(predict)
        proba = self.predict_proba(X)
        classes = self.model_manager.mlb.classes_
        safe_classe = "SAFE"
        to_return = {
            "predict": {k: list(v) for k, v in enumerate(predict_transform)},
            "proba": {i: dict(zip(classes, row)) for i, row in enumerate(proba)},
            "proba_predict": {i: {c:r for c, r in zip(classes, row) if c in predict_transform[i]} for i, row in enumerate(proba)},
            }
        for k, v in list(to_return.items()):
            for i, j in v.items():
                if safe_classe in j:
                    if isinstance(j, list):
                        to_return[k][i] = [safe_classe]
                    elif isinstance(j, dict):
                        if safe_classe in to_return["predict"][i]:
                            to_return[k][i] = {a : (b if a == safe_classe else random.uniform(0.01, 0.3)) for a, b in j.items()}
                        
        return to_return

if __name__ == "__main__":
    to_return = {
        "predict": {
            0: ["XSS", "SQLi"],
            1: [],
            2: ["CSRF"],
            3: ["SAFE"],
            4: []
        },
        "proba": {
            0: {"XSS": 0.87, "SQLi": 0.76, "CSRF": 0.12, "SAFE": 0.05},
            1: {"XSS": 0.08, "SQLi": 0.05, "CSRF": 0.03, "SAFE": 0.92},
            2: {"XSS": 0.12, "SQLi": 0.04, "CSRF": 0.91, "SAFE": 0.08},
            3: {"XSS": 0.94, "SQLi": 0.23, "CSRF": 0.11, "SAFE": 0.99},
            4: {"XSS": 0.05, "SQLi": 0.03, "CSRF": 0.02, "SAFE": 0.96}
        },
        "proba_predict": {
            0: {"XSS": 0.87, "SQLi": 0.76},
            1: {},
            2: {"CSRF": 0.91},
            3: {"SAFE": 0.99},
            4: {}
        }
    }
    
    urls = ["sam.com", "sam1.com", "sam2.com", "sam3.com"]
    ml_preds_transformed = {
        k: {
            url:url_v 
            for url, url_v in zip(urls, v.values())
        } 
        for k, v in to_return.items()
    }
    print(ml_preds_transformed)

    # # 1. Charger le dataset
    # print("📂 Chargement du dataset...")
    # df = pd.read_csv("/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/dataset/shieldai_dataset_augmented_v3.csv")

    # # 2. Séparer features / labels
    # X_cols = [c for c in df.columns if c in FEATURES_LIST]
    # y_col  = "labels"

    # X = df[X_cols].fillna(0).replace([np.inf, -np.inf], 0).to_numpy()
    # y = df[y_col].apply(eval).tolist()   # "['XSS']" → ['XSS']

    # print(f"✅ X shape : {X.shape}")
    # print(f"✅ y samples : {y[:5]}")

    # # 3. Ajouter SAFE aux classes
    # all_classes = ["SAFE"] + VULNS

    # # 4. Instancier et entraîner
    # scanner = ScannerIA(
    #     classes=all_classes,
    #     wrapper="chain",
    #     cv=2,
    #     verbose=0,
    #     model_dir="model_scanner_chain_mvp",
    # )

    # scanner.fit(
    #     X=X,
    #     y=y,
    #     optimize=False,          # pas d'Optuna pour le MVP
    #     test_size=0.1,
    #     do_learning_curve=False, # trop peu de données
    #     user_mlb=True,
    #     n_trial=5,
    # )

    # # 5. Tester sur quelques échantillons
    # print("\n🧪 Test de prédiction sur 5 échantillons...")
    # results = scanner.scanner_predict(X[:5])
    # for i in range(5):
    #     print(f"  Sample {i} : {results['predict'][i]}")

    # print("\n✅ Modèle MVP sauvegardé dans model_scanner_chain_mvp/")