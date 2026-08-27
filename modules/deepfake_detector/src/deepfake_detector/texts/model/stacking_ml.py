#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 11 2026
@author: hounsousamuel + Claude
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import io
import numpy as np
import zstandard as zstd
import joblib
import optuna
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    StackingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report
)
from deepfake_detector.deepfake_utils.logger import get_logger

logger = get_logger()

# Silencer optuna par défaut — on gère l'affichage nous-mêmes
optuna.logging.set_verbosity(optuna.logging.WARNING)


class StackingML:
    """
    Stacking ML pour la détection de texte/image IA.

    Architecture :
        Level 0 (base learners) :
            - XGBoost
            - RandomForest
            - ExtraTreesClassifier

        Level 1 (meta learner) :
            - LogisticRegression

    Input  : features [N, D] — embeddings + features handcraftées
             (le scaler est géré à l'extérieur)
    Output : pred_proba [N, n_classes], pred_label [N]

    Optuna : optimisation automatique des hyperparamètres si optimize=True
    """

    def __init__(
        self,
        n_classes:int = 2,
        n_estimators:int = 100,
        max_depth:int = 6,
        random_state:int = 42,
        n_jobs:int = -1,
        cv:int = 5,
    ):
        self._params = dict(
            n_classes=n_classes,
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=n_jobs,
            cv=cv,
        )
        self._best_params = {}  # rempli par Optuna si optimize=True
        self.is_fitted = False
        self.build(**self._params)

    def build(
        self,
        n_classes:int = 2,
        n_estimators:int = 100,
        max_depth:int = 6,
        random_state:int = 42,
        n_jobs:int = -1,
        cv:int = 5,
        # Paramètres Optuna — ignorés si pas d'optimisation
        xgb_lr:float = 0.1,
        xgb_subsample:float = 0.8,
        xgb_min_child_weight:int = 1,
        rf_min_samples_split:int = 2,
        rf_min_samples_leaf:int = 1,
        et_min_samples_split:int = 2,
        et_min_samples_leaf:int = 1,
        meta_C:float = 1.0,
        **kwargs  
    ):
        # ── Level 0 — Base learners ──────────────────────────────────────────
        xgb = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=xgb_lr,
            subsample=xgb_subsample,
            min_child_weight=xgb_min_child_weight,
            random_state=random_state,
            n_jobs=n_jobs,
            eval_metric="logloss",
            verbosity=0,
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
        )
        rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=rf_min_samples_split,
            min_samples_leaf=rf_min_samples_leaf,
            random_state=random_state,
            n_jobs=n_jobs,
        )
        et = ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=et_min_samples_split,
            min_samples_leaf=et_min_samples_leaf,
            random_state=random_state,
            n_jobs=n_jobs,
        )

        # ── Level 1 — Meta learner ───────────────────────────────────────────
        meta = LogisticRegression(
            C=meta_C,
            max_iter=1000,
            random_state=random_state,
            n_jobs=n_jobs,
        )

        # ── Stacking ─────────────────────────────────────────────────────────
        self.model = StackingClassifier(
            estimators=[
                ("xgb", xgb),
                ("rf",  rf),
                ("et",  et),
            ],
            final_estimator=meta,
            cv=cv,
            n_jobs=n_jobs,
            passthrough=False,
            stack_method="predict_proba",
        )
        self.is_fitted = False

    # ── Optuna — objectif ────────────────────────────────────────────────────
    def _objective(self, trial, X:np.ndarray, y:np.ndarray) -> float:
        """
        Fonction objectif pour Optuna.

        Pour chaque trial, Optuna propose des hyperparamètres,
        on construit un stacking temporaire, on l'évalue via
        cross_val_score, et on retourne le score moyen.

        Optuna maximise ce score en explorant l'espace des paramètres.
        """
        # ── XGBoost ──────────────────────────────────────────────────────────
        xgb_params = dict(
            n_estimators         = trial.suggest_int  ("xgb_n_estimators",      50,   300),
            max_depth            = trial.suggest_int  ("xgb_max_depth",           3,    10),
            xgb_lr               = trial.suggest_float("xgb_lr",               0.01,  0.3,  log=True),
            xgb_subsample        = trial.suggest_float("xgb_subsample",         0.6,  1.0),
            xgb_min_child_weight = trial.suggest_int  ("xgb_min_child_weight",   1,    10),
        )

        # ── RandomForest ─────────────────────────────────────────────────────
        rf_params = dict(
            n_estimators          = trial.suggest_int("rf_n_estimators",         50,  300),
            max_depth             = trial.suggest_int("rf_max_depth",              3,   20),
            rf_min_samples_split  = trial.suggest_int("rf_min_samples_split",     2,   10),
            rf_min_samples_leaf   = trial.suggest_int("rf_min_samples_leaf",      1,    5),
        )

        # ── ExtraTrees ───────────────────────────────────────────────────────
        et_params = dict(
            n_estimators         = trial.suggest_int("et_n_estimators",          50,  300),
            max_depth            = trial.suggest_int("et_max_depth",               3,   20),
            et_min_samples_split = trial.suggest_int("et_min_samples_split",      2,   10),
            et_min_samples_leaf  = trial.suggest_int("et_min_samples_leaf",       1,    5),
        )

        # ── Meta ─────────────────────────────────────────────────────────────
        meta_params = dict(
            meta_C = trial.suggest_float("meta_C", 0.01, 10.0, log=True),
        )

        # Fusionner tous les params et construire un modèle temporaire
        all_params = {
            **self._params,
            **xgb_params,
            **rf_params,
            **et_params,
            **meta_params,
        }

        # Construire temporairement pour évaluer — pas de self.model
        temp = StackingML.__new__(StackingML)
        temp._params = all_params
        temp._best_params = {}
        temp.build(**all_params)

        # Cross-validation stratifiée — plus robuste que simple split
        cv = StratifiedKFold(
            n_splits=self._params["cv"],
            shuffle=True,
            random_state=self._params["random_state"]
        )
        scores = cross_val_score(
            temp.model, X, y,
            cv=cv,
            scoring="f1_macro",
            n_jobs=self._params["n_jobs"]
        )
        return scores.mean()

    # ── Fit ─────────────────────────────────────────────────────────────────
    def fit(
        self,
        X:np.ndarray,
        y:np.ndarray,
        optimize:bool = False,
        n_trials:int = 50,
    ):
        """
        Entraîne le stacking sur X, y.

        X        : [N, D]  features (déjà scalées à l'extérieur)
        y        : [N]     labels entiers
        optimize : si True → Optuna cherche les meilleurs hyperparamètres
        n_trials : nombre d'essais Optuna (plus = meilleur mais plus long)
        """
        if optimize:
            logger.print(f"🔍 Optimisation Optuna — {n_trials} trials...")

            study = optuna.create_study(
                direction="maximize",
                sampler=optuna.samplers.TPESampler(seed=self._params["random_state"]),
            )
            study.optimize(
                lambda trial: self._objective(trial, X, y),
                n_trials=n_trials,
                show_progress_bar=True,
            )

            self._best_params = study.best_params
            best_score = study.best_value

            logger.print(f"✅ Meilleur F1 macro : {best_score:.4f}")
            logger.print(f"   Meilleurs params  : {self._best_params}")

            # Rebuilder avec les meilleurs params trouvés
            merged = {**self._params, **self._best_params}
            self.build(**merged)

        logger.print(f"Entraînement sur {X.shape[0]} samples, {X.shape[1]} features...")
        self.model.fit(X, y)
        self.is_fitted = True
        logger.print("✅ Stacking entraîné avec succès")
        return self

    # ── Predict ─────────────────────────────────────────────────────────────
    def predict_proba(self, X:np.ndarray) -> np.ndarray:
        """X : [N, D] → [N, n_classes]"""
        if not self.is_fitted:
            raise RuntimeError("Appeler fit() d'abord !")
        return self.model.predict_proba(X)

    def predict(self, X:np.ndarray) -> np.ndarray:
        """X : [N, D] → [N]"""
        if not self.is_fitted:
            raise RuntimeError("Appeler fit() d'abord !")
        return self.model.predict(X)

    def __call__(self, X:np.ndarray):
        """Raccourci → (proba [N, n_classes], pred [N])"""
        return self.predict_proba(X), self.predict(X)

    # ── Evaluate ────────────────────────────────────────────────────────────
    def evaluate(self, X:np.ndarray, y:np.ndarray) -> dict:
        """Évalue et affiche les métriques."""
        if not self.is_fitted:
            raise RuntimeError("Appeler fit() d'abord !")

        pred    = self.predict(X)
        average = "binary" if self._params["n_classes"] == 2 else "macro"

        results = {
            "accuracy"  : accuracy_score(y, pred),
            "f1"        : f1_score(y, pred, average=average),
            "precision" : precision_score(y, pred, average=average),
            "recall"    : recall_score(y, pred, average=average),
        }

        logger.print("\n" + "=" * 70)
        logger.print(f"{'📊 ÉVALUATION STACKING ML':^70}")
        logger.print("=" * 70)
        logger.print(f"  🔹 Samples       : {len(y)}")
        logger.print(f"  🔹 Accuracy      : {results['accuracy']:.4f}  {'✅' if results['accuracy'] > 0.9 else '⚠️'}")
        logger.print(f"  🔹 F1            : {results['f1']:.4f}  {'✅' if results['f1'] > 0.9 else '⚠️'}")
        logger.print(f"  🔹 Precision     : {results['precision']:.4f}")
        logger.print(f"  🔹 Recall        : {results['recall']:.4f}")

        if self._best_params:
            logger.print("\n  🎯 Optimisé avec Optuna")
            logger.print(f"     Meilleurs params : {self._best_params}")

        cm = confusion_matrix(y, pred)
        logger.print("\n  📊 MATRICE DE CONFUSION")
        cell_width = max(4, len(str(cm.max()))) + 1
        header = "     " + "".join([f"{j:>{cell_width}}" for j in range(cm.shape[1])])
        logger.print(header)
        for i, row in enumerate(cm):
            logger.print(f"  {i:>2} │" + "".join([f"{v:>{cell_width}}" for v in row]))

        logger.print("\n  📋 RAPPORT COMPLET")
        logger.print("\n", classification_report(y, pred, zero_division=0))
        logger.print("=" * 70 + "\n")

        return results

    # ── Save / Load — pattern joblib + zstd du projet ───────────────────────
    def save(self, path:str):
        try:
            to_save = {
                "model"       : self.model,
                "params"      : self._params,
                "best_params" : self._best_params,
                "is_fitted"   : self.is_fitted,
            }
            buffer = io.BytesIO()
            joblib.dump(to_save, buffer, compress=9)
            buffer.seek(0)
            raw = buffer.read()
            compressed = zstd.compress(raw, level=20)
            joblib.dump(compressed, path, compress=9)
            logger.print(f"Stacking sauvegardé avec succès dans {path} !")
        except Exception as e:
            logger.print("Erreur de sauvegarde du stacking :", str(e))

    def load(self, path:str):
        if os.path.exists(path):
            try:
                compressed     = joblib.load(path)
                raw            = zstd.decompress(compressed)
                buffer         = io.BytesIO(raw)
                loaded         = joblib.load(buffer)
                self._params      = loaded["params"]
                self._best_params = loaded.get("best_params", {})
                self.is_fitted    = loaded["is_fitted"]
                self.model        = loaded["model"]
                logger.print("Stacking chargé avec succès ✅")
                return
            except Exception as e:
                logger.print("Erreur lors du chargement du stacking :", str(e))
                return
        logger.print("Erreur : Chemin inexistant !")


if __name__ == "__main__":
    from sklearn.datasets import make_classification
    from sklearn.model_selection import train_test_split

    logger.print("=== Test StackingML ===\n")

    # Dataset synthétique
    X, y = make_classification(
        n_samples=300,
        n_features=20,
        n_informative=15,
        n_classes=2,
        random_state=42
    )
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # ── Test sans Optuna ──────────────────────────────────────────────────
    logger.print("── Sans Optuna ──")
    stacking = StackingML(n_classes=2, n_estimators=50, cv=3)
    stacking.fit(X_train, y_train, optimize=False)
    stacking.evaluate(X_test, y_test)

    # ── Test avec Optuna ──────────────────────────────────────────────────
    logger.print("── Avec Optuna (10 trials) ──")
    stacking_opt = StackingML(n_classes=2, n_estimators=50, cv=3)
    stacking_opt.fit(X_train, y_train, optimize=True, n_trials=10)
    stacking_opt.evaluate(X_test, y_test)

    # ── Predict ───────────────────────────────────────────────────────────
    proba, pred = stacking_opt(X_test[:3])
    logger.print(f"Proba 3 premiers : {proba}")
    logger.print(f"Pred  3 premiers : {pred}")

    # ── Save / Load ───────────────────────────────────────────────────────
    stacking_opt.save("/tmp/stacking_opt.zstd")
    stacking2 = StackingML()
    stacking2.load("/tmp/stacking_opt.zstd")
    results = stacking2.evaluate(X_test, y_test)
    logger.print(f"Accuracy après reload : {results['accuracy']:.4f}")