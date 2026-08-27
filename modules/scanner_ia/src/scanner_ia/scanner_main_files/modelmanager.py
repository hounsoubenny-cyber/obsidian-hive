#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 15 07:22:39 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
from scanner_utils.warnings_manager import suppres_warnings
suppres_warnings()
import optuna, json, io
import traceback
from matplotlib import pyplot as plt
from optuna.importance import get_param_importances
from optuna.visualization.matplotlib import (
    plot_optimization_history, plot_param_importances, 
    plot_parallel_coordinate, plot_terminator_improvement
)
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split, cross_val_score, cross_validate, learning_curve
from iterstrat.ml_stratifiers import MultilabelStratifiedKFold
from sklearn.compose import ColumnTransformer
from sklearn.multioutput import ClassifierChain
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer, RobustScaler, PolynomialFeatures, OneHotEncoder
from sklearn.datasets import make_classification, make_multilabel_classification
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    jaccard_score, accuracy_score, f1_score, 
    make_scorer, hamming_loss, classification_report, 
    multilabel_confusion_matrix, confusion_matrix
)
import zstandard as zstd
import skops.io as skio
from zipfile import ZIP_DEFLATED

# from loguru import logger as modelmanager_logger
from ml_model.mlsmote import MLSMOTE
from scanner_utils.logger import get_logger

# Configuration des logs
modelmanager_logger = get_logger()
# modelmanager_logger.remove()
# modelmanager_logger.add(
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
# modelmanager_logger.add(
#     "logs/modelmanager.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )

pd.set_option("display.max_row", 200)
pd.set_option("display.max_columns", 200)

_RANDOM_STATE = 42
_PLOT_FUNC = [
    plot_optimization_history, plot_param_importances, 
    plot_parallel_coordinate, plot_terminator_improvement
]
_JOBS = int(0.9 * os.cpu_count()) or 2
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(BASE_DIR, exist_ok=True)

class ModelManager:
    def __init__(
        self,
        classes:list = [],
        num_features:list = [],
        cat_features:list = [],
        verbose:int = 0,
        wrapper:str = "chain",
        cv:int = 5,
        meta_name:str = "pipeline_estimator",
        model_dir:str = "model"
    ):
        self.verbose = verbose
        self.wrapper = wrapper
        self.cv = cv 
        self.order = None
        self.mlb = MultiLabelBinarizer(classes=classes)
        self.num_features = []
        self.cat_features = []
        self.model = None
        self.meta_name = meta_name or "pipeline_estimator"
        self.model_dir = os.path.join(BASE_DIR, model_dir)
        os.makedirs(self.model_dir, exist_ok=True)
        modelmanager_logger.info(f"✅ ModelManager initialisé - wrapper: {wrapper}, meta_name: {meta_name}, model_dir: {model_dir}")
    
    def _get_order(self, y:np.ndarray) -> list:
        order = np.argsort(np.sum(y, axis=0)).tolist() if y.ndim > 1 else None
        modelmanager_logger.debug(f"Ordre des classes déterminé: {order}")
        return order
    
    def _create_base_models(self):
        modelmanager_logger.debug("Création des modèles de base...")
        return {
            "hgbc": HistGradientBoostingClassifier(
                early_stopping=True, n_iter_no_change=20, class_weight="balanced", 
                random_state=_RANDOM_STATE, verbose=self.verbose, validation_fraction=0.15
                ),
            "rf": RandomForestClassifier(n_jobs=-1, random_state=_RANDOM_STATE, verbose=self.verbose),
            # "log": LogisticRegression(
            #     n_jobs=-1, class_weight="balanced", solver="saga", penalty="elasticnet", 
            #     random_state=_RANDOM_STATE, verbose=self.verbose, max_iter=5000
            #     ),
            "xgb": XGBClassifier(n_jobs=-1, random_state=_RANDOM_STATE, verbosity=self.verbose, base_score=0.5),
            # "lgbm": LGBMClassifier(n_jobs=-1, random_state=_RANDOM_STATE, verbose=-1 if not self.verbose else self.verbose, silent=True),
            "mlp": MLPClassifier(
                random_state=_RANDOM_STATE, verbose=self.verbose, 
                validation_fraction=0.15, n_iter_no_change=20
                ),
            # "svm": SVC( 
            #     probability=True,  
            #     random_state=_RANDOM_STATE,
            #     class_weight='balanced',
            #     max_iter=5000,
            # ),
        }
    
    def _get_stacking(self, optimize:bool = True, cv:int = 3, stack_cv:int = 3, trial:optuna.Trial|None = None):
        modelmanager_logger.debug(f"Construction du modèle - optimize={optimize}, cv={cv}, stack_cv={stack_cv}")
        
        models = self._create_base_models()
        meta = Pipeline(
            [
                ("scaler", RobustScaler()),
                ("poly", PolynomialFeatures(degree=2, include_bias=False, interaction_only=False)),
                (self.meta_name, models["hgbc"])
            ], verbose=bool(self.verbose)
        )

        stack = StackingClassifier(
            estimators=list(models.items()),
            final_estimator=meta,
            cv=stack_cv,
            stack_method="predict_proba",
            passthrough=False,
            n_jobs=_JOBS, verbose=self.verbose
        )
        
        params_func = self._get_params_trial if optimize else self._get_params_dict
        meta_params = params_func(name="final_estimator", trial=trial, poly=True, meta_name=self.meta_name)
        params = {k: params_func(name=k, trial=trial) for k in models}
        params_list = list(params.values())
        params = params_list[0]
        for p in params_list[1:]:
            params.update(p)
        # print(params)
        params.update(meta_params)
        
        if self.wrapper == "chain":
            stack = ClassifierChain(
                base_estimator=stack,
                order=self.order,
                cv=cv,
                chain_method="predict_proba", verbose=bool(self.verbose)
            )
            modelmanager_logger.debug("Wrapper ClassifierChain appliqué")
        else:
            stack = OneVsRestClassifier(
                estimator=stack,
                n_jobs=_JOBS,
                verbose=self.verbose
            )
            modelmanager_logger.debug("Wrapper OneVsRestClassifier appliqué")
        # print(params)
        stack.set_params(**params)
        return stack
    
    def get_preprocessing(self, num_features:list, cat_features:list) -> ColumnTransformer:
        preprocessing = [
            (
                "num_preprocess",
                Pipeline(
                    [
                        ("imputer", IterativeImputer(max_iter=50)),
                        ("scaler", RobustScaler())
                    ], verbose=bool(self.verbose)
                ),
                num_features
            ),
            ("cat_preprocess", OneHotEncoder(handle_unknown="ignore"), cat_features)
        ]
        
        return ColumnTransformer(
            transformers=preprocessing,
            remainder="drop",
            n_jobs=_JOBS, verbose=self.verbose,
            verbose_feature_names_out=True
        )
    
    def create_models(
        self, num_features:list, cat_features:list,
        X:np.ndarray = np.array([]),
        y:np.ndarray = np.array([]),
        optimize:bool = True, cv:int = 3,
        n_trial:int = 50, timeout:float|None = None,
        visualize:bool = True,
    ):
        modelmanager_logger.info(f"🚀 Création des modèles - optimize={optimize}, n_trial={n_trial}, cv={cv}")
        
        y = np.asarray(y)
        X = np.asarray(X)
        if self.wrapper == "chain" and self.order is None:
            self.order = self._get_order(y)
            
        preprocessing = self.get_preprocessing(num_features, cat_features)
        stack = self._get_stacking(optimize=False, cv=self.cv, stack_cv=cv)
        if optimize:
            modelmanager_logger.info(f"🔍 Lancement de l'optimisation avec {n_trial} essais...")
            best_params = self.optimize(
                n_trials=n_trial, preprocessing=preprocessing,
                X=X, y=y, timeout=timeout,
                visualize=visualize, cv=self.cv 
            )
            modelmanager_logger.info(f"✅ Optimisation terminée - {len(best_params)} paramètres optimisés")
            modelmanager_logger.info(f"Params optimisé : \n {best_params}")
            
            stack.set_params(**best_params)
            
        model = Pipeline(
            steps=[
                ("preprocessing", preprocessing),
                ("estimator", stack)
            ], verbose=bool(self.verbose)
        )
        
        modelmanager_logger.success("✅ Modèle créé avec succès")
        return model
    
    def _get_params_trial(self, name:str, trial:optuna.Trial, poly:bool = True, meta_name:str = "pipeline_meta") -> dict:
        name = name.lower()
        base = "base_estimator" if self.wrapper == "chain" else "estimator"
        final_estimator_base = f"final_estimator__{meta_name}" if poly else "final_estimator"
        
        _PARAMS_DEF = {
            "rf": {
                f"{base}__rf__n_estimators": ("int", 500, 5000),
                f"{base}__rf__max_depth": ("categorical", [8, 12, 14, 16, None]),
                f"{base}__rf__max_features": ("categorical", ["sqrt", "log2", None]),
                f"{base}__rf__max_leaf_nodes": ("categorical", [31, 41, 51, None]),
            },
            "hgbc": {
                f"{base}__hgbc__max_iter": ("int", 1000, 10000),
                f"{base}__hgbc__max_depth": ("categorical", [8, 12, 14, 16, None]),
                f"{base}__hgbc__learning_rate": ("logfloat", 1e-5, 1e-3),
                f"{base}__hgbc__max_leaf_nodes": ("categorical", [31, 41, 51, None]),
            },
            "log": {
                f"{base}__log__C": ("logfloat", 1.0, 100.0),
                f"{base}__log__l1_ratio": ("float", 0.1, 0.99),
                f"{base}__log__tol": ("logfloat", 1e-8, 1e-4),
            },
            "svm": {  
                f"{base}__svm__C": ("logfloat", 1e-3, 100.),
                f"{base}__svm__gamma": ("logfloat", 1e-4, 1e-1),
                f"{base}__svm__kernel": ("categorical", ["rbf", "poly", "sigmoid"]),
            },
            "xgb": {
                f"{base}__xgb__n_estimators": ("int", 1000, 10000),
                f"{base}__xgb__learning_rate": ("logfloat", 1e-5, 1e-3),
                f"{base}__xgb__max_leaves": ("categorical", [31, 41, 51, 61]),
                f"{base}__xgb__max_bin": ("int", 64, 512)
            },
            "lgbm":{
                f"{base}__lgbm__max_iter": ("int", 1000, 10000),
                f"{base}__lgbm__max_leaves": ("categorical", [31, 41, 51, 61]),
                f"{base}__lgbm__learning_rate": ("logfloat", 1e-5, 1e-3),
            },
            "mlp":{
                f"{base}__mlp__learning_rate_init": ("logfloat", 1e-5, 1e-3),
                f"{base}__mlp__max_iter": ("int", 500, 2000),
                f"{base}__mlp__hidden_layer_sizes": ("categorical", [(100, 50,), (128, 64, 32,)]),
            },
            "final_estimator": {
                f"{base}__{final_estimator_base}__max_iter": ("int", 1000, 5000),
                f"{base}__{final_estimator_base}__max_depth": ("categorical", [8, 12, 14, 16]),
                f"{base}__{final_estimator_base}__learning_rate": ("logfloat", 1e-5, 1e-3),
                f"{base}__{final_estimator_base}__max_leaf_nodes": ("categorical", [31, 41, 51]),
            },
        }
        
        params_def = _PARAMS_DEF.get(name, _PARAMS_DEF[[k for k in _PARAMS_DEF.keys() if k in name][0]])
        params = {}
        
        for param_name, param_config in params_def.items():
            param_type = param_config[0]
            
            if param_type == "int":
                params[param_name] = trial.suggest_int(param_name, param_config[1], param_config[2])
            elif param_type == "float":
                params[param_name] = trial.suggest_float(param_name, param_config[1], param_config[2])
            elif param_type == "logfloat":
                params[param_name] = trial.suggest_float(param_name, param_config[1], param_config[2], log=True)
            elif param_type == "categorical":
                params[param_name] = trial.suggest_categorical(param_name, param_config[1])
        modelmanager_logger.debug(f"Paramètres Optuna générés pour {name}, {list(params.keys())}")
        return params

    def _get_params_dict(self, name:str, poly:bool = True, meta_name:str = "pipeline_meta", *args, **kwargs) -> dict:
        name = name.lower()
        base = "base_estimator" if self.wrapper == "chain" else "estimator"
        final_estimator_base = f"final_estimator__{meta_name}" if poly else "final_estimator"
        
        _PARAMS = {
            "rf": {
                f"{base}__rf__n_estimators": 1500,
                f"{base}__rf__max_depth": None,
                f"{base}__rf__max_features": "sqrt",
                f"{base}__rf__max_leaf_nodes": None,
            },
            "hgbc": {
                f"{base}__hgbc__max_iter": 5000,
                f"{base}__hgbc__max_depth": None,
                f"{base}__hgbc__learning_rate": 1e-3,
                f"{base}__hgbc__max_leaf_nodes": None,
            },
            "log": {
                f"{base}__log__C": 50,
                f"{base}__log__l1_ratio": 0.5,
                f"{base}__log__tol": 1e-4
            },
            "svm": { 
                f"{base}__svm__C": 1.0,
                f"{base}__svm__gamma": "scale",
                f"{base}__svm__kernel": "rbf",
            },
            "xgb": {
                f"{base}__xgb__n_estimators": 5000,
                f"{base}__xgb__learning_rate": 1e-3,
                f"{base}__xgb__max_leaves": 41,
                f"{base}__xgb__max_bin": 256
            },
            "lgbm":{
                f"{base}__lgbm__max_iter": 5000,
                f"{base}__lgbm__max_leaves": 41,
                f"{base}__lgbm__learning_rate": 1e-3,
            },
            "mlp":{
                f"{base}__mlp__learning_rate_init": 1e-3,
                f"{base}__mlp__max_iter": 1000,
                f"{base}__mlp__hidden_layer_sizes": (100, 50, )
            },
            "final_estimator": {
                f"{base}__{final_estimator_base}__max_iter": 3000,
                f"{base}__{final_estimator_base}__max_depth": 16,
                f"{base}__{final_estimator_base}__learning_rate": 1e-3,
                f"{base}__{final_estimator_base}__max_leaf_nodes": 41,
            },
        }
        
        params = _PARAMS.get(name, _PARAMS[[k for k in _PARAMS.keys() if k in name][0]])
        modelmanager_logger.debug(f"Paramètres fixes générés pour {name}")
        return params
    
    @staticmethod
    def get_scorer():
        scorers = {
            'f1_micro': make_scorer(f1_score, average='micro', zero_division=0),
            'f1_macro': make_scorer(f1_score, average='macro', zero_division=0),
            'f1_samples': make_scorer(f1_score, average='samples', zero_division=0),
            'f1_weighted': make_scorer(f1_score, average='weighted', zero_division=0),
            'jaccard_samples': make_scorer(jaccard_score, average='samples', zero_division=0),
            'jaccard_micro': make_scorer(jaccard_score, average='micro', zero_division=0),
            'hamming': make_scorer(hamming_loss, greater_is_better=True)
        }
        modelmanager_logger.debug(f"Scorers créés: {list(scorers.keys())}")
        return scorers
    
    @staticmethod
    def get_idx(X):
        X = np.array(X)
        num_idx = []
        cat_idx = []
        for i in range(X.shape[1]):
            if any(isinstance(x, (int, float, np.number)) for x in X[:, i]):
                if i not in num_idx:
                    num_idx.append(i)
            else:
                if i not in cat_idx:
                    cat_idx.append(i)
        return num_idx, cat_idx
    
    def objective_eval(self, model, X:np.ndarray, y:np.ndarray, cv:int = 3) -> float:
        modelmanager_logger.debug(f"Évaluation objective - cv={cv}")
        
        # cv_results = cross_validate(
        #     model, X, y,
        #     cv=cv,
        #     scoring=self.get_scorer(),
        #     n_jobs=_JOBS,
        #     return_train_score=True,
        #     verbose=1 #self.verbose
        # )
        # modelmanager_logger.info(f"Cross validation result : \n {pd.DataFrame(cv_results)}")
        # composite = (
        #     0.4 * cv_results["test_f1_micro"] +
        #     0.25 * cv_results["test_f1_samples"] +
        #     0.15 * cv_results["test_jaccard_samples"] +
        #     0.2 * (1 - cv_results["test_hamming"]) 
        # ).mean()
        X, X_test, y, y_test = train_test_split(X, y, test_size=0.2)
        model.fit(X, y)
        y_pred = model.predict(X_test)
        f1_macro = f1_score(y_test, y_pred, average="macro")
        f1_micro = f1_score(y_test, y_pred, average="micro")
        f1_samples = f1_score(y_test, y_pred, average="samples")
        jc_samples = jaccard_score(y_test, y_pred, average="samples")
        hm_loss = hamming_loss(y_test, y_pred)
        composite = sum((
            0.25 * f1_micro,
            0.25 * f1_macro,
            0.20 * f1_samples,
            0.20 * jc_samples,
            0.10 * (1 - hm_loss)
            ))
        modelmanager_logger.info(f"✓ F1 macro: {f1_macro:.4f}")
        modelmanager_logger.info(f"✓ F1 micro: {f1_micro:.4f}")
        modelmanager_logger.info(f"✓ F1 samples: {f1_samples:.4f}")
        modelmanager_logger.info(f"✓ Hamming Loss: {hm_loss:.4f}")
        modelmanager_logger.info(f"✓ Jaccard Score: {jc_samples:.4f}")
        modelmanager_logger.debug(f"Score composite calculé: {composite:.4f}")
        return composite

    def optimize(
        self, 
        preprocessing,
        X:np.ndarray, 
        y:np.ndarray, 
        cv:int = 3,
        timeout:float|None = None,
        n_trials:int = 50,
        visualize:bool = True
    ) -> dict:

        modelmanager_logger.info(f"🔍 Démarrage de l'optimisation Optuna - {n_trials} essais, timeout={timeout}")

        def objective(trial:optuna.Trial) -> float:
            stack = self._get_stacking(optimize=True, cv=self.cv, stack_cv=cv, trial=trial)
            model = Pipeline(
                steps=[
                    ("preprocessing", preprocessing),
                    ("estimator", stack)
                ], verbose=bool(self.verbose)
            )
            return self.objective_eval(model, X, y, cv)

        study = optuna.create_study(
            study_name=f"optimization_stacking_{self.wrapper}",
            direction="maximize",
        )

        study.optimize(
            objective, show_progress_bar=True,
            n_trials=n_trials, timeout=timeout, n_jobs=2,
        )
        
        modelmanager_logger.info("=" * 10 + " PARAMS IMPORTANCE " + "=" * 10)
        param_importances = get_param_importances(study)
        for param, importance in list(param_importances.items())[:10]:
            modelmanager_logger.info(f"  {param}: {importance:.3f}")
        modelmanager_logger.info("=" * 30)

        if visualize:
            base_dir = os.path.join(BASE_DIR, "results_optuna")
            os.makedirs(base_dir, exist_ok=True)
            for plot_func in _PLOT_FUNC:
                try:
                  plot_func(study).plot()
                  plt.tight_layout()
                  
                  # Sauvegarder
                  plot_name = plot_func.__name__.replace('plot_', '')
                  plot_path = os.path.join(base_dir, f"{plot_name}_{self.wrapper}.png")
                  plt.savefig(plot_path)
                  
                  # Afficher
                  plt.show(block=False)
                  
                  modelmanager_logger.debug(f"✅ Graphique {plot_func.__name__} sauvegardé dans {plot_path}")
                  
                except Exception as e:
                    modelmanager_logger.warning(f"Erreur lors de la génération du graphique {plot_func.__name__}: {e}")

        modelmanager_logger.success(f"✅ Optimisation terminée - Meilleur score: {study.best_value:.4f}")
        return study.best_params
    
    def save_model(self, model, dir:str):
        modelmanager_logger.info(f"💾 Sauvegarde du modèle dans {dir}")
        
        try:
            modelmanager_logger.debug("Sérialisation avec joblib.dump...")
            buffer = io.BytesIO()
            joblib.dump(model, buffer, compress=9)
            buffer.seek(0)
            dumps = buffer.read()
            joblib_size = len(dumps) / (1024 * 1024)
            modelmanager_logger.debug(f"✓ Taille après JobLib: {joblib_size:.2f} MB")
            
            os.makedirs(dir, exist_ok=True)
            
            modelmanager_logger.debug("Compression avec Zstandard (niveau 21)...")
            compressed = zstd.compress(dumps, level=21)
            
            model_path = os.path.join(dir, "model.joblib.zst")
            joblib.dump(compressed, model_path, compress=9)
            # with open(model_path, 'wb') as f:
            #     f.write(compressed)
            
            final_size = os.path.getsize(model_path) / (1024 * 1024)
            ratio = len(dumps) / len(compressed)
            
            modelmanager_logger.success(f"✓ Modèle sauvegardé: {model_path}")
            modelmanager_logger.info(f"   └─ Taille finale: {final_size:.2f} MB (ratio: {ratio:.2f}x)")
            
            metadata = {
                "mlb_classes": self.mlb.classes_.tolist() if hasattr(self.mlb, 'classes_') else [],
                "order": self.order,
                "wrapper": self.wrapper,
                "num_features": self.num_features,
                "cat_features": self.cat_features,
                "compression": {
                    "skops_level": 8,
                    "zstd_level": 20,
                    "original_size_mb": joblib_size,
                    "final_size_mb": final_size,
                    "ratio": ratio
                }
            }
            
            meta_path = os.path.join(dir, "metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            meta_size = os.path.getsize(meta_path) / 1024
            modelmanager_logger.success(f"✓ Métadonnées sauvegardées: {meta_path} ({meta_size:.2f} KB)")
            
        except Exception as e:
            modelmanager_logger.error(f"❌ Erreur de sauvegarde du modèle: {str(e)}")
            modelmanager_logger.error(traceback.format_exc())
            raise
    
    def load_model(self, dir:str):
        modelmanager_logger.info(f"📂 Chargement du modèle depuis {dir}")
        
        try:
            model_path = os.path.join(dir, "model.joblib.zst")
            meta_path = os.path.join(dir, "metadata.json")
            
            missing = []
            if not os.path.exists(model_path):
                missing.append("model.joblib.zst")
            if not os.path.exists(meta_path):
                missing.append("metadata.json")
                
            if missing:
                raise FileNotFoundError(f"Fichiers manquants: {', '.join(missing)}")
            
            modelmanager_logger.debug("Lecture du fichier compressé...")
            compressed = joblib.load(model_path)
            
            modelmanager_logger.debug("Décompression Zstandard...")
            decompressed = zstd.decompress(compressed)
            buffer = io.BytesIO(decompressed)
            
            modelmanager_logger.debug("Désérialisation JobLib...")
            self.model = joblib.load(buffer)
            
            modelmanager_logger.debug("Chargement des métadonnées...")
            with open(meta_path, "r") as f:
                metadata = json.load(f)
            
            if metadata.get("mlb_classes"):
                self.mlb = MultiLabelBinarizer(classes=metadata["mlb_classes"])
                self.mlb.fit([[]])
                
            self.order = metadata.get("order")
            self.wrapper = metadata.get("wrapper", self.wrapper)
            self.num_features = metadata.get("num_features", [])
            self.cat_features = metadata.get("cat_features", [])
            
            if "compression" in metadata:
                comp = metadata["compression"]
                modelmanager_logger.info(f"   └─ Compression: ratio {comp['ratio']:.2f}x ({comp['original_size_mb']:.1f} MB → {comp['final_size_mb']:.1f} MB)")
            
            modelmanager_logger.success("✅ Modèle chargé avec succès")
            
        except Exception as e:
            modelmanager_logger.error(f"❌ Erreur de chargement du modèle: {str(e)}")
            modelmanager_logger.error(traceback.format_exc())
            raise
            
    def fit(
        self,
        X:np.ndarray,
        y:np.ndarray,
        cv:int = 3,
        optimize:bool = True,
        optimization_size:float = 0.8,
        n_trial:int = 50,
        timeout:float|None = None,
        visualize:bool = True,
        test_size:float = 0.2,
        do_learning_curve:bool = True,
        user_mlb:bool = True
    ):
        modelmanager_logger.info("=" * 70)
        modelmanager_logger.info("🚀 DÉMARRAGE DU FIT")
        modelmanager_logger.info("=" * 70)
        
        X = np.array(X)
        try:
            self.mlb.classes_
        except Exception:
            modelmanager_logger.debug("Ajustement du MultiLabelBinarizer...")
            self.mlb.fit([])
        if user_mlb:
            y = self.mlb.transform(y)
            modelmanager_logger.info(f"✓ Labels transformés: {y.shape}")
        else:
            y = np.array(y)
        if self.wrapper == "chain" and self.order is None:
            self.order = self._get_order(y)
        
        if not self.num_features:            
            num_idx, cat_idx = self.get_idx(X[:3])
            self.num_features = num_idx
            self.cat_features = cat_idx
            modelmanager_logger.info(f"✓ Features identifiées: {len(self.num_features)} numériques, {len(self.cat_features)} catégorielles")
        
        if optimize:
            X_opt, X_rem, y_opt, y_rem = train_test_split(
                X, y, test_size=optimization_size, random_state=_RANDOM_STATE
            )
            modelmanager_logger.info(f"🔍 Optimisation sur {len(X_opt)} échantillons")
            
            self.model = self.create_models(
                optimize=True,
                X=X_opt, y=y_opt,
                num_features=self.num_features,
                cat_features=self.cat_features,
                cv=cv, n_trial=n_trial, visualize=visualize,
                timeout=timeout
            )
        else:
            modelmanager_logger.info("⚡ Fit sans optimisation")
            self.model = self.create_models(
                optimize=False,
                num_features=self.num_features,
                cat_features=self.cat_features
            )
        
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=_RANDOM_STATE, stratify=y
                )
            modelmanager_logger.info("Données splittés avec stratification !")
        except Exception:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=_RANDOM_STATE
                )
            
        modelmanager_logger.info(f"✓ Split: train={len(X_train)}, test={len(X_test)}")
        
        modelmanager_logger.info("🏋️ Entraînement du modèle final...")
        self.model.fit(X_train, y_train)
        modelmanager_logger.success("✓ Modèle entraîné avec succès")
        
        self.save_model(self.model, dir=self.model_dir)
        
        # Évaluation
        self.evaluate_model(self.model, X_test, y_test)
        
        if do_learning_curve:
            modelmanager_logger.info("Debut du learning_curve")
            self.plot_learning_curve(self.model, X_train, y_train, cv=cv)
        return self.model
    
    def verify_model(self):
        try:
            if not self.model:
                modelmanager_logger.debug("Modèle non trouvé en mémoire, tentative de chargement...")
                self.load_model(self.model_dir)
            if not self.model:
                raise ValueError("Model indisponible")
            modelmanager_logger.debug("✓ Modèle vérifié avec succès")
        except Exception as e:
            modelmanager_logger.error(f"❌ Erreur de vérification du modèle: {str(e)}")
            modelmanager_logger.error(traceback.format_exc())
            raise
            
    def predict_proba(self, X):
        self.verify_model()
        modelmanager_logger.debug(f"Prédiction des probabilités sur {len(X)} échantillons")
        return self.model.predict_proba(np.asarray(X))
    
    def predict(self, X, threshold:float|np.ndarray = 0.5):
        self.verify_model()
        modelmanager_logger.debug(f"Prédiction avec seuil {threshold} sur {len(X)} échantillons")
        return np.array(np.array(self.predict_proba(np.asarray(X))) > threshold).astype(int)
    
    def evaluate_model(self, model, X, y, threshold:float = 0.5):
        modelmanager_logger.info("📊 ÉVALUATION DU MODÈLE")
        
        y_true = np.asarray(y)
        y_pred = self.predict(X, threshold)
        
        hamming = hamming_loss(y_true, y_pred)
        jaccard = jaccard_score(y_true, y_pred, average='samples', zero_division=0)
        
        modelmanager_logger.info(f"✓ Hamming Loss: {hamming:.4f}")
        modelmanager_logger.info(f"✓ Jaccard Score: {jaccard:.4f}")
        
        cr = classification_report(y_true, y_pred, zero_division=0)
        modelmanager_logger.info("\n" + "=" * 50)
        modelmanager_logger.info("CLASSIFICATION REPORT")
        modelmanager_logger.info("=" * 50)
        modelmanager_logger.info(cr)
        
        cm_func = confusion_matrix if y_true.ndim == 1 else multilabel_confusion_matrix
        cm = cm_func(y_true, y_pred)
        modelmanager_logger.info("\n" + "=" * 50)
        modelmanager_logger.info("CONFUSION MATRIX")
        modelmanager_logger.info("=" * 50)
        modelmanager_logger.info(cm)
        try:
            modelmanager_logger.debug("Validation croisée en cours...")
            cv_results = cross_validate(
                model, X, y,
                cv=self.cv,
                scoring=self.get_scorer(),
                n_jobs=_JOBS,
                return_train_score=True,
            )
            df = pd.DataFrame(cv_results)
            modelmanager_logger.info("\n" + "=" * 50)
            modelmanager_logger.info("CROSS VALIDATION RESULTS")
            modelmanager_logger.info("=" * 50)
            modelmanager_logger.info(df)
            df.loc['mean'] = df.mean()
            path = os.path.abspath(os.path.join(BASE_DIR, "evaluation"))
            os.makedirs(path, exist_ok=True)
            df.to_csv(os.path.join(path, 'evaluation.csv'), index=False)
        except Exception as e:
            modelmanager_logger.error(f"Erreur lors de l'évaluation : {str(e)}")
        
        modelmanager_logger.success("✅ Évaluation terminée")
        return model
    
    def plot_learning_curve(self, model, X, y, cv:int = 3) -> None:
        """ Trace la courbe d'apprentissage en utilisant sklearn.learning_curve """
        try:
            train_sizes, train_scores, test_scores = learning_curve(
                estimator=model, X=X, y=y, cv=cv, scoring='f1_macro', 
                train_sizes=np.linspace(0.2, 1.0, 5), error_score='raise',
                verbose=self.verbose,
                random_state=_RANDOM_STATE
            )
        except Exception as e:
            modelmanager_logger.error(f"Erreur au niveau de leaning curve : {type(e).__name__} : {str(e)}")
            modelmanager_logger.error(f"Détails : \n {traceback.format_exc()}")
            return
        
        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        gap_values = train_scores_mean - test_scores_mean
        gap = train_scores_mean[-1] - test_scores_mean[-1]  #Pour prendre le dataset total (train_sizes=100%)
        plt.figure(figsize=(20, 10))
        plt.subplot(2, 2, 1)
        plt.title('Learning Curve')
        plt.plot(train_sizes, train_scores_mean, 'o-', color='r', label=f'Training score(final : {train_scores_mean[-1]})')
        plt.fill_between(train_sizes, train_scores_mean - train_scores_std, train_scores_mean + train_scores_std, alpha=0.1, color='r')
        plt.plot(train_sizes, test_scores_mean, 'o-', color='g', label='Cross-validation score')
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std, test_scores_mean + test_scores_std, alpha=0.1, color='g')
        plt.xlabel('Fragmentations trainset')
        plt.ylabel('Score(f1_samples)')
        plt.ylim(0, 1.1)
        plt.legend(loc='best')
        plt.grid(True)

        plt.subplot(2,2,2)
        plt.title('Ecart Train-Validation ')
        plt.plot(train_sizes, gap_values, 'o-', color='purple', label='Evolution du gap')
        plt.axhline(y=0.1,color='red',linestyle='--',label='Seuil overfitting(10%)')
        plt.axhline(y=0.05,color='orange',linestyle='--',label='Seuil acceptable(5%)')
        plt.xlabel('Fragmentations trainset')
        plt.ylabel('Gap(Train-Validation)')
        plt.ylim(0, 0.1001)
        plt.legend(loc='best')
        plt.grid(True)

        plt.subplot(2,2,3)
        plt.title('Resumé ')
        plt.plot(train_sizes, train_scores_mean, 'o-', color='r', label=f'Training score(final : {train_scores_mean[-1]})')
        plt.fill_between(train_sizes, train_scores_mean - train_scores_std, train_scores_mean + train_scores_std, alpha=0.1, color='r')
        plt.plot(train_sizes, test_scores_mean, 'o-', color='g', label='Cross-validation score')
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std, test_scores_mean + test_scores_std, alpha=0.1, color='g')
        plt.plot(train_sizes, gap_values, 'o-', color='purple', label='Evolution du gap')
        plt.axhline(y=0.1,color='red',linestyle='--',label='Seuil overfitting(10%)')
        plt.axhline(y=0.05,color='orange',linestyle='--',label='Seuil acceptable(5%)')
        plt.xlabel('Fragmentations trainset')
        plt.ylabel('Score et Gap ')
        plt.ylim(0, 1.1)
        plt.legend(loc='best')
        plt.grid(True)
        
        path = os.path.abspath(os.path.join(BASE_DIR, "learning_curve"))
        os.makedirs(path, exist_ok=True)
        modelmanager_logger.info('='*60)
        modelmanager_logger.info(f'Score train final : {train_scores_mean[-1]}')
        modelmanager_logger.info(f'Score val final : {test_scores_mean[-1]}')
        modelmanager_logger.info(f"Gap final : {gap} ({gap*100}%)")
        if gap > 0.1 :
            modelmanager_logger.warning("[ALERTE] Overfiting détecté ! \n Le modèle performe plus sur train que validation. Vous pouvez essayer de réduire la complxité du modèle.")
        elif gap > 0.05:
            modelmanager_logger.warning("Overfiting léger. Gap acceptable mais peut être amélioré")
        else :
            modelmanager_logger.info('Pas d\'overfitting détecté. Le modèle généralise bien !')
        
        try:
            plt_path = os.path.join(path, f'learning_curve_{os.path.basename(self.model_dir)}.png')
            plt.savefig(plt_path)
            modelmanager_logger.info(f'Learning curve saved to {plt_path}')
            
        except Exception as e:
            modelmanager_logger.warning(f"Sauvegarde de l'image échoué, {str(e)}, \npath={plt_path}")
        plt.tight_layout()
        plt.show(block=False)


if __name__ == "__main__":
    # ============================================================
    # TEST DE LA CLASSE ModelManager
    # ============================================================
    print("=" * 70)
    print("🔬 TEST DE ModelManager - CLASSIFICATION MULTI-LABELS")
    print("=" * 70)
    
    # 1. Génération de données multi-labels
    print("\n📊 Génération des données...")
    X, y = make_multilabel_classification(
        n_samples=5000,
        n_features=20,
        n_classes=5,
        n_labels=3,
        random_state=0,
        allow_unlabeled=True
    )
    
    # Convertir en DataFrame pour avoir des noms de colonnes
    X = pd.DataFrame(X, columns=[f"feat_{i}" for i in range(20)])
    # Ajouter quelques colonnes catégorielles pour tester le preprocessing
    X['cat_1'] = np.random.choice(['A', 'B', 'C'], size=len(X))
    X['cat_2'] = np.random.choice(['X', 'Y', 'Z'], size=len(X))
    
    print(f"✅ X shape: {X.shape}")
    print(f"✅ y shape: {y.shape}")
    print(f"✅ Features numériques: {[c for c in X.columns if 'feat' in c][:5]}...")
    print(f"✅ Features catégorielles: {[c for c in X.columns if 'cat' in c]}")
    
    # 2. Test avec wrapper='chain' (ClassifierChain)
    # print("\n" + "=" * 70)
    # print("🔗 TEST AVEC WRAPPER='chain' (ClassifierChain)")
    # print("=" * 70)
    
    # manager_chain = ModelManager(
    #     classes=np.unique(y),
    #     wrapper='chain',
    #     verbose=1,
    #     cv=2,
    #     meta_name="meta_estimator",
    #     model_dir="model_chain"
    # )
    
    # 3. Fit avec optimisation (réduite pour le test)
    # print("\n🚀 Lancement de l'optimisation (5 trials pour test rapide)...")
    # manager_chain.fit(
    #     X=X,
    #     y=y,
    #     cv=2,
    #     optimize=True,
    #     optimization_size=0.3,  # 30% des données pour l'optimisation
    #     n_trial=5,  # Petit nombre pour test rapide
    #     timeout=300,  # 5 minutes max
    #     visualize=True,
    #     test_size=0.2
    # )
    # manager_chain.load_model(manager_chain.model_dir)
    # manager_chain.evaluate_model(manager_chain.model, X, y)
    
    # 4. Test avec wrapper='ovr' (OneVsRestClassifier)
    print("\n" + "=" * 70)
    print("🔄 TEST AVEC WRAPPER='ovr' (OneVsRestClassifier)")
    print("=" * 70)
    
    manager_ovr = ModelManager(
        classes=np.unique(y),
        wrapper='ovr',
        verbose=0,
        cv=2,
        meta_name="meta_estimator",
        model_dir="model_ovr_with_lrc"
    )
    
    # Fit sans optimisation (test rapide)
    manager_ovr.fit(
        X=X,
        y=y,
        cv=3,
        optimize=True,
        visualize=True,
        test_size=0.2,
        do_learning_curve=True,
        user_mlb=False, n_trial=5
    )
    
    # 5. Test des prédictions
    # print("\n" + "=" * 70)
    # print("🎯 TEST DES PRÉDICTIONS")
    # print("=" * 70)
    
    # X_test_sample = X.iloc[:5]
    # y_true_sample = y[:5]
    
    # for name, manager in [("ClassifierChain", manager_chain), ("OneVsRest", manager_ovr)]:
    #     print(f"\n📌 {name}:")
    #     try:
    #         y_pred = manager.predict(X_test_sample)
    #         y_proba = manager.predict_proba(X_test_sample)
            
    #         print(f"  ✅ Prédictions shape: {y_pred.shape}")
    #         print(f"  ✅ Probabilités disponibles")
    #         print(f"  ✅ Exemple - Vrai: {y_true_sample[0]}, Prédit: {y_pred[0]}")
            
    #         # Test avec threshold personnalisé
    #         y_pred_strict = manager.predict(X_test_sample, threshold=0.7)
    #         print(f"  ✅ Avec threshold=0.7: {y_pred_strict[0]}")
            
    #     except Exception as e:
    #         print(f"  ❌ Erreur: {e}")
    
    # print("\n" + "=" * 70)
    # print("✅ TEST TERMINÉ AVEC SUCCÈS")
    # print("=" * 70)
    