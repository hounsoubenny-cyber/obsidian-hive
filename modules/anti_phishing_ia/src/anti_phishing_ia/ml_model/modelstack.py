#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Construction de modèles de stacking pour la classification.

Ce module implémente la classe ModelStack qui permet de :
- Créer une collection de modèles de base (XGBoost, ExtraTrees, MLP, etc.)
- Optimiser leurs hyperparamètres avec BayesSearchCV
- Combiner les modèles dans un stacking classifier
- Gérer différents modes d'optimisation (normal, calibré, mémoire rapide)

Le stacking combine plusieurs classifieurs pour améliorer les performances
par rapport à un modèle unique.

Auteur: HOUNSOU Samuel
Date: Octobre 2025
Version: 1.0.0
"""

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Supprime les logs TensorFlow

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pandas as pd
pd.reset_option('display.max_row')
pd.reset_option('display.max_columns')

import numpy as np
import time
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

import warnings
warnings.filterwarnings('ignore')

from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import PolynomialFeatures, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.ensemble import (
    RandomForestClassifier, HistGradientBoostingClassifier,
    StackingClassifier, ExtraTreesClassifier,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from skopt import BayesSearchCV
from skopt.space import Real, Integer, Categorical
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from tqdm import tqdm
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input
from tensorflow.keras.models import Sequential
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
from scikeras.wrappers import KerasClassifier
import traceback

# Répertoire de base pour les données
dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(dir_, exist_ok=True)


class ModelStack:
    """
    Crée et optimise un stacking classifier pour la classification binaire.

    Cette classe permet de :
    1. Créer plusieurs modèles de base (XGBoost, ExtraTrees, MLP, etc.)
    2. Optimiser leurs hyperparamètres avec BayesSearchCV
    3. Combiner les modèles optimisés dans un StackingClassifier
    4. Gérer différents modes d'optimisation (normal, calibré, mémoire rapide)

    Attributes:
        X (np.ndarray): Features d'entraînement
        y (np.ndarray): Labels
        method (str): Méthode d'optimisation ('normal', 'calibrated')
        random_state (int): Seed pour la reproductibilité
        cv (StratifiedKFold): Cross-validation personnalisée
        stack (StackingClassifier): Modèle de stacking final
        n_features (int): Nombre de features
        learning_rate (float): Taux d'apprentissage

    Example:
        >>> from sklearn.datasets import make_classification
        >>> X, y = make_classification(n_samples=1000, n_features=20)
        >>> model_stack = ModelStack(X, y, n_features=20, method='normal')
        >>> stack = model_stack.run(mode='fast')
        >>> stack.predict(X[:5])
        array([0, 1, 0, 0, 1])
    """

    def __init__(self, X, y, n_features, method='normal', learning_rate=0.01, random_state=42, cv=None):
        """
        Initialise le ModelStack.

        Args:
            X (array-like): Features d'entraînement (shape: n_samples, n_features)
            y (array-like): Labels (shape: n_samples, ou n_samples, n_labels)
            n_features (int): Nombre de features dans X
            method (str): Méthode d'optimisation: 'normal' ou 'calibrated'
            learning_rate (float): Taux d'apprentissage pour les modèles
            random_state (int): Seed pour la reproductibilité
            cv (cross-validator, optional): Cross-validator personnalisé

        Raises:
            ValueError: Si X n'est pas 2D, y n'est pas 1D/2D, ou dimensions incompatibles
        """
        self.X = np.asarray(X)
        self.y = np.asarray(y)

        # Validation des dimensions
        if self.X.ndim != 2:
            raise ValueError(f"X doit être 2D, reçu shape {self.X.shape}")

        if self.y.ndim not in (1, 2):
            raise ValueError(f"y doit être 1D ou 2D, reçu shape {self.y.shape}")

        if self.X.shape[0] != self.y.shape[0]:
            raise ValueError(f"X ({self.X.shape[0]} samples) et y ({self.y.shape[0]} samples) "
                             "doivent avoir le même nombre d'échantillons")

        if self.X.shape[1] != n_features:
            raise ValueError(f"X a {self.X.shape[1]} features mais n_features={n_features}")

        self.method = method
        self.random_state = random_state
        self.cv = cv or StratifiedKFold(n_splits=3, shuffle=True, random_state=self.random_state)
        self.stack = None
        self.n_features = n_features or X.shape[1]
        self.learning_rate = learning_rate

        print("[INIT] ModelStack créé:")
        print(f"  - X shape: {self.X.shape}")
        print(f"  - y shape: {self.y.shape}")
        print(f"  - Méthode: {self.method}")
        print(f"  - Learning rate: {self.learning_rate}")

    def build_deep_model(self, meta):
        """
        Construit un modèle de deep learning avec Keras.

        Args:
            meta (dict): Métadonnées contenant 'n_features_in_' et 'n_classes_'

        Returns:
            Sequential: Modèle Keras compilé

        Note:
            Modèle actuellement commenté. À activer si nécessaire.
        """
        n_feat = meta.get('n_features_in_', self.n_features)
        n_classes = meta.get('n_classes_', 1)
        y_shape = meta.get('y_shape_', self.y.shape)

        model = Sequential()
        model.add(Input(shape=(n_feat,)))
        model.add(Dense(128, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))
        model.add(Dense(64, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))
        model.add(Dense(32, activation='swish'))
        model.add(BatchNormalization())
        model.add(Dropout(0.3))

        # Sortie binaire (phishing vs safe)
        n_output = 1
        activation = 'sigmoid'
        loss = 'binary_crossentropy'
        print("[DEBUG] Binary détecté")

        print(f"[DEBUG] → {n_feat} features, {n_output} sortie(s), {activation}, {loss}")

        model.add(Dense(n_output, activation=activation))
        model.compile(optimizer=Adam(learning_rate=self.learning_rate), loss=loss, metrics=['accuracy'])
        return model

    def create_models(self):
        """
        Crée les dictionnaires de modèles de base pour le stacking.

        Returns:
            dict: Dictionnaire des modèles avec leurs noms
                  Format: {'nom': (nom, instance_modèle)}

        Note:
            Les modèles commentés (LGBM, CatBoost, etc.) peuvent être
            réactivés selon les besoins et la mémoire disponible.
        """
        to_return = {}

        # Régression logistique (modèle simple mais efficace)
        LogReg = LogisticRegression(
            max_iter=5000, class_weight='balanced',
            tol=1e-8, solver='lbfgs',
            random_state=self.random_state, C=20
        )
        to_return['LogReg'] = ('LogReg', LogReg)

        # HistGradientBoosting (rapide et efficace)
        hist = HistGradientBoostingClassifier(
            max_iter=1500, learning_rate=self.learning_rate,
            loss='log_loss', n_iter_no_change=20,
            max_leaf_nodes=100,
            max_depth=None,
            early_stopping=True,
            validation_fraction=0.1, scoring='f1_macro',
            class_weight='balanced',
            random_state=self.random_state,
            min_samples_leaf=50, verbose=0
        )
        to_return['hgbc'] = ('hgbc', hist)

        # ExtraTrees (version plus aléatoire de RandomForest)
        extra = ExtraTreesClassifier(
            n_estimators=600,
            max_depth=None,
            class_weight='balanced',
            n_jobs=-1,
            max_features='sqrt',
            random_state=self.random_state, verbose=0
        )
        to_return['extra'] = ('extra', extra)

        # XGBoost (modèle puissant)
        xgb = XGBClassifier(
            n_estimators=1500,
            objective='binary:logistic',
            learning_rate=self.learning_rate,
            tree_method='hist',
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=self.random_state, verbose=0
        )
        to_return['xgb'] = ('xgb', xgb)

        # MLP (réseau de neurones simple)
        mlp = MLPClassifier(
            hidden_layer_sizes=(250, 150, 100, 50),
            max_iter=600,
            random_state=self.random_state,
            learning_rate='adaptive',
            n_iter_no_change=20,
            early_stopping=True,
            tol=1e-6, verbose=0,
            alpha=0.001, batch_size=64
        )
        pipeline_mlp = Pipeline([
            ('scaler', StandardScaler()),
            ('mlp', mlp)
        ])
        to_return['mlp'] = ('mlp', pipeline_mlp)

        print(f"[CREATION DES MODELS DANS MODELSTACK] {len(to_return)} models créés de noms {list(to_return.keys())}")

        return to_return

    def create_param_dict_one_label(self, name):
        """
        Crée l'espace de recherche d'hyperparamètres pour un modèle donné.

        Args:
            name (str): Nom du modèle ('xgb', 'extra', 'lgbm', 'hgbc', 'cat', 'bagcat')

        Returns:
            dict: Espace de recherche pour BayesSearchCV

        Note:
            Les espaces sont adaptés à chaque type de modèle.
        """
        name = name.lower()
        params = {
            'extra': {
                'n_estimators': Integer(300, 1000),
                'max_features': Categorical(['sqrt', 'log2', None]),
                'max_depth': Categorical([4, 6, 8, 10, 12, 14, None]),
                'min_samples_leaf': Integer(1, 10)
            },
            'xgb': {
                'n_estimators': Integer(700, 1500),
                'max_depth': Integer(6, 30),
                'learning_rate': Real(0.01, 0.2, prior='log-uniform'),
                'gamma': Real(0, 10)
            },
            'lgbm': {
                'n_estimators': Integer(1000, 2500),
                'learning_rate': Real(0.05, 0.3, prior='log-uniform'),
                'max_depth': Categorical([5, 6, 7, 8, 10, 12]),
                'num_leaves': Integer(30, 80),
            },
            'hgbc': {
                'max_iter': Integer(500, 2500),
                'learning_rate': Real(0.01, 0.1, prior='log-uniform'),
                'max_depth': Categorical([4, 6, 8, 10, 12, 14, 16, 18, None]),
                'max_bins': Integer(128, 255)
            },
            'cat': {
                'depth': Integer(6, 15),
                'iterations': Integer(700, 2000),
                'learning_rate': Real(0.01, 0.1),
                'rsm': Real(0.5, 1.0),
                'random_strength': Real(0.0, 2.0)
            },
            "bagcat": {
                "estimator__iterations": Integer(700, 2000),
                "estimator__learning_rate": Real(0.01, 0.1),
                "estimator__depth": Integer(6, 15),
                "estimator__random_strength": Real(0.0, 2.0)
            },
        }
        return params.get(name, {})

    def model_optimize(self, dict_of_models, n_iter=15):
        """
        Optimise les hyperparamètres des modèles avec BayesSearchCV.

        Args:
            dict_of_models (dict): Dictionnaire des modèles à optimiser
            n_iter (int): Nombre d'itérations pour BayesSearchCV

        Returns:
            dict: Dictionnaire des modèles optimisés
        """
        if not dict_of_models:
            raise ValueError("Aucun model (model_optimize_one_label)")

        best_models = {}
        X_copy = self.X.copy()
        y_copy = self.y.copy()

        # Modèles exclus de l'optimisation (trop lourds ou déjà optimisés)
        models = [m for m in dict_of_models.keys() if m not in ("keras", "mlp", "bagcat", 'LogReg', "extra")]

        for i in tqdm(range(len(models)), desc='FITTING séparé des models'):
            name, model = dict_of_models[models[i]]
            space = self.create_param_dict_one_label(name.lower())
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}")

            model_bayes = BayesSearchCV(
                estimator=model,
                search_spaces=space,
                scoring='f1_macro',
                cv=self.cv,
                n_iter=n_iter, n_jobs=-1,
                return_train_score=True,
                verbose=1,
            )

            start = time.time()
            model_bayes.fit(X_copy, y_copy)
            end = time.time()

            best_models[name] = (name, model_bayes.best_estimator_)
            print(f"\n Meilleur paramètres pour ce model : {dict(model_bayes.best_params_)} "
                  f"et \n Meilleur score CV : {model_bayes.best_score_}")
            print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)})")
            print(f"\n Fit terminé en {end - start:.3f} secondes")

        print("FIN de l'optimisation multi_label des models")

        # Ajout des modèles non optimisés
        if 'keras' in dict_of_models:
            best_models['keras'] = dict_of_models['keras']
        if "mlp" in dict_of_models:
            best_models['mlp'] = dict_of_models['mlp']
        if "bagcat" in dict_of_models:
            best_models['bagcat'] = dict_of_models['bagcat']
        if "LogReg" in dict_of_models:
            best_models['LogReg'] = dict_of_models['LogReg']
        if "extra" in dict_of_models:
            best_models['extra'] = dict_of_models['extra']

        return best_models

    def optimize_for_memory(self):
        """
        Optimisation mémoire pour éviter les problèmes de RAM.

        Utilise des modèles légers (HistGradientBoosting + LogisticRegression)
        pour le stacking.

        Returns:
            Pipeline: Pipeline avec PolynomialFeatures + LogisticRegression

        Note:
            Mode recommandé pour les machines avec peu de RAM (<= 8GB).
        """
        print('MODE OPTIMISATION MÉMOIRE RAPIDE')

        # Modèles légers
        light_models = {
            'hgbc': HistGradientBoostingClassifier(
                max_iter=100, max_depth=6,
                learning_rate=0.1
            ),
            'logreg': LogisticRegression(C=0.1, max_iter=1000)
        }

        estimators = list(light_models.items())

        final_estimator = Pipeline([
            ('poly', PolynomialFeatures(include_bias=False, degree=2)),
            ('LogReg', LogisticRegression(
                max_iter=4000, class_weight='balanced', tol=1e-8,
                solver='lbfgs', random_state=self.random_state, C=20
            ))
        ])

        # Stacking avec modèles légers
        stack = StackingClassifier(
            estimators=estimators,
            final_estimator=final_estimator,
            n_jobs=-1,
            passthrough=True,
            stack_method='predict_proba', verbose=1
        )

        return Pipeline([
            ('poly', PolynomialFeatures(include_bias=False, degree=2)),
            ('LogReg', LogisticRegression(
                max_iter=4000, class_weight='balanced', tol=1e-8,
                solver='lbfgs', random_state=self.random_state, C=20
            ))
        ])

    def create_stacking(self, dict_of_models):
        """
        Crée le stacking classifier final à partir des modèles optimisés.

        Args:
            dict_of_models (dict): Dictionnaire des modèles optimisés

        Returns:
            StackingClassifier: Classifieur de stacking configuré
        """
        if not dict_of_models:
            raise ValueError("Aucun model")

        estimators = []
        for name, model_wraped in dict_of_models.values():
            print(f"\n[create_stacking] {name} -> {type(model_wraped).__name__}")

            if name not in ('keras', 'mlp'):
                if self.method == 'calibrate':
                    model_wraped = CalibratedClassifierCV(model_wraped, cv=2, ensemble=True, n_jobs=-1)
                elif self.method == 'normal':
                    model_wraped = model_wraped

            estimators.append((name, model_wraped))

        print(f"\n[create_stacking] Total estimators: {len(estimators)}")

        # Méta-classifieur (combine les prédictions des modèles de base)
        meta = Pipeline([
            ('poly', PolynomialFeatures(include_bias=False, degree=2)),
            ('LogReg', LogisticRegression(
                max_iter=4000, class_weight='balanced', tol=1e-6,
                solver='lbfgs', random_state=self.random_state, C=15
            ))
        ])

        stack = StackingClassifier(
            estimators=estimators,
            final_estimator=meta,
            cv=self.cv,
            passthrough=True,
            n_jobs=-1,
            stack_method='predict_proba', verbose=1
        )

        list2 = [k[0] for k in estimators]
        print(f"[INFO] Stacking créé avec les modèles suivants : {list2}")
        return stack

    def run(self, n_iter=15, mode='fast'):
        """
        Exécute le pipeline complet de création du stacking.

        Args:
            n_iter (int): Nombre d'itérations pour BayesSearchCV
            mode (str): 'fast' pour optimisation mémoire, 'normal' pour stacking complet

        Returns:
            Pipeline or StackingClassifier: Modèle final entraîné

        Example:
            >>> model_stack = ModelStack(X_train, y_train, n_features=20)
            >>> model = model_stack.run(mode='fast')
        """
        if mode == 'fast':
            return self.optimize_for_memory()

        models = self.create_models()
        models = self.model_optimize(models, n_iter)
        return self.create_stacking(dict_of_models=models)


if __name__ == '__main__':
    from sklearn.datasets import make_classification
    from sklearn.preprocessing import StandardScaler as SC
    from sklearn.model_selection import train_test_split as tts
    from sklearn.metrics import recall_score, classification_report, multilabel_confusion_matrix
    import dill
    from anti_phishing_ia.ml_model.modeloptimize import ModelOptimization
    import warnings

    warnings.filterwarnings('ignore')
    np.random.seed(0)

    # Génération de données de test
    X, y = make_classification(n_samples=6000, n_features=25, random_state=42)
    X = SC().fit_transform(X)
    X_train, _, y_train, _ = tts(X, y, test_size=0.2, random_state=42)
    features_names = [f'features_{i}' for i in range(25)]

    # Création du model stack
    model = ModelStack(X_train, y_train, n_features=25, method='normal', learning_rate=0.001, cv=3)
    stack = model.run(n_iter=4)

    # Optimisation et évaluation
    Opt = ModelOptimization(
        model=stack, X=X, y=y, random_state=42, cv=2,
        save_dir="modelstack", features_name=features_names,
        scoring=["f1_macro", "accuracy"]
    )

    start = time.time()
    stack, X_test, y_test = Opt.run(threshold=None)
    end = time.time()
    print(f"\n Fit terminé en {end - start:.3f} secondes")

    # Évaluation
    y_pred = stack.predict(X_test)
    print('Score : ', stack.score(X_test, y_test))
    print('\n Recall score : ', recall_score(y_test, y_pred, average="macro"))
    print("\n Classification report : \n", classification_report(y_test, y_pred))
    print("\n MultiLabel Confusion Matrix report : \n", multilabel_confusion_matrix(y_test, y_pred))

    # Sauvegarde
    with open('model_stack_nouvelle_methode_multilabel_chain1_sam.pkl', 'wb') as f:
        dill.dump(stack, f)
    print('Modèle sauvegardé!')

    # Vérification des prédictions
    print()
    for name, est in stack.named_estimators_.items():
        print(f"\n{name} → {type(est).__name__}")
        try:
            proba = est.predict_proba(X_test)
            print(f"Shape: {np.shape(proba)}")
            print(proba, '\n')
        except Exception as e:
            print(f"Erreur pour {name}: {e}")

    print('\n COMPARAISON POUR VÉRIFICATION')
    print(y_pred[:3, :])
    print(stack.predict_proba(X_test[:3, :]))