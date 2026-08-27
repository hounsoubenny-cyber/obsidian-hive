#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 15 07:17:18 2026

@author: hounsousamuel
"""

import random
from scanner_ia.scanner_utils.warnings_manager import suppres_warnings

suppres_warnings()

import pandas as pd
import numpy as np
from scanner_ia.ml_model.datamanager import DataManager, _DEFAULT_TARGET_FUNC
from scanner_ia.ml_model.modelmanager import ModelManager

# from loguru import logger as scanner_ia_logger
from scanner_ia.scanner_utils.logger import get_logger
scanner_ia_logger = get_logger()

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
        """
        NOTE : "SAFE" n'est plus une classe entraînée/prédite par le modèle
        (self.model_manager.mlb.classes_ ne contient QUE les vraies vulns :
        XSS, SQLi, CSRF, ...). "safe" est déduit après coup : une page est
        safe si aucune vuln n'a franchi le seuil. C'est donc structurellement
        impossible d'obtenir "safe" + une vuln en même temps — contrairement
        à l'ancienne approche où SAFE était un label comme un autre et où il
        fallait une rustine post-hoc pour rattraper les incohérences.
        """
        predict = self.model_manager.predict(X, threshold)
        predict_transform = self.model_manager.mlb.inverse_transform(predict)
        proba = self.predict_proba(X)
        classes = self.model_manager.mlb.classes_

        to_return = {
            "predict": {k: list(v) for k, v in enumerate(predict_transform)},
            "proba": {i: dict(zip(classes, row)) for i, row in enumerate(proba)},
            "proba_predict": {i: {c:r for c, r in zip(classes, row) if c in predict_transform[i]} for i, row in enumerate(proba)},
            }

        # Déduit, jamais prédit : une page est "safe" si aucune vuln n'est
        # retenue par le modèle (predict vide). Aucun seuil séparé sur un
        # label "safe" — ça évite justement la classe d'incohérence qu'on
        # cherche à éliminer.
        to_return["is_safe"] = {
            i: (len(labels) == 0) for i, labels in to_return["predict"].items()
        }

        return to_return

if __name__ == "__main__":
    from scanner_ia.ml_model.config import VULNS, FEATURES_LIST
    # Démo du nouveau format : "SAFE" n'existe plus nulle part. "is_safe"
    # est calculé automatiquement (predict vide) — impossible d'avoir une
    # page à la fois "safe" et détectée vulnérable.
    to_return = {
        "predict": {
            0: ["XSS", "SQLi"],
            1: [],
            2: ["CSRF"],
            3: ["XSS"],
            4: []
        },
        "proba": {
            0: {"XSS": 0.87, "SQLi": 0.76, "CSRF": 0.12},
            1: {"XSS": 0.08, "SQLi": 0.05, "CSRF": 0.03},
            2: {"XSS": 0.12, "SQLi": 0.04, "CSRF": 0.91},
            3: {"XSS": 0.94, "SQLi": 0.23, "CSRF": 0.11},
            4: {"XSS": 0.05, "SQLi": 0.03, "CSRF": 0.02}
        },
        "proba_predict": {
            0: {"XSS": 0.87, "SQLi": 0.76},
            1: {},
            2: {"CSRF": 0.91},
            3: {"XSS": 0.94},
            4: {}
        },
        "is_safe": {0: False, 1: True, 2: False, 3: False, 4: True},
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
    # y = df[y_col].apply(eval).tolist()   # "['XSS']" → ['XSS'], "['SAFE']" → []  (⚠️ voir note dataset ci-dessous)

    # print(f"✅ X shape : {X.shape}")
    # print(f"✅ y samples : {y[:5]}")

    # # 3. Classes = uniquement les vraies vulns, SAFE n'est plus une classe
    # # entraînée. Les pages saines doivent avoir un label vide [] dans le
    # # dataset, pas ["SAFE"] (sinon MultiLabelBinarizer lèvera une erreur
    # # car "SAFE" n'appartient plus à `classes`).
    # all_classes = VULNS

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