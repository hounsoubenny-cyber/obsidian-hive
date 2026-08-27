#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modèle d'intelligence artificielle pour la détection de phishing.

Ce module implémente la classe PhishingIA qui gère :
- L'entraînement d'un modèle de stacking (XGBoost, RandomForest, ExtraTrees, MLP)
- La sauvegarde et le chargement du modèle
- L'extraction et la préparation des données
- La prédiction sur de nouvelles URLs

Le modèle utilise 33 caractéristiques extraites des URLs et peut être
ré-entraîné automatiquement sur de nouvelles données.

Auteur: HOUNSOU Samuel
Date: Octobre 2025
Version: 1.0.0
"""

import os
import sys
import numpy as np
import json
import gzip
import pandas as pd
import time
import joblib

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Supprime les logs TensorFlow

import tensorflow as tf
tf.get_logger().setLevel('ERROR')

import warnings
warnings.filterwarnings('ignore')

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from imblearn.over_sampling import SMOTE
from sklearn.ensemble import HistGradientBoostingRegressor, StackingClassifier
from xgboost import XGBClassifier
from skopt import BayesSearchCV
from skopt.space import Real, Integer, Categorical
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, confusion_matrix, multilabel_confusion_matrix,
    f1_score, accuracy_score, precision_score, recall_score
)
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
from sklearn.preprocessing import RobustScaler, LabelEncoder
from tqdm import tqdm
from anti_phishing_ia.ml_model.modeloptimize import ModelOptimization, compute_metrics_safe
from anti_phishing_ia.ml_model.modelstack import ModelStack
from anti_phishing_ia.core.features_extractor import get_features_names
import traceback

# Répertoire de base pour les données et modèles
dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(dir_, exist_ok=True)

# Classes possibles pour la classification
classes = ['phishing', 'safe']

# Noms des features (33 caractéristiques)
features_name = get_features_names()

# Espaces de recherche pour l'optimisation BayesSearchCV
PARAMS = {
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


def get_features_name(X):
    """
    Récupère les noms des features à partir d'un DataFrame ou d'un array.

    Args:
        X: DataFrame pandas ou array numpy contenant les features

    Returns:
        list: Liste des noms des colonnes (ou noms par défaut)

    Example:
        >>> df = pd.DataFrame({'url_length': [45], 'has_ip': [0]})
        >>> get_features_name(df)
        ['url_length', 'has_ip']
    """
    if isinstance(X, pd.DataFrame):
        features_name_ = X.columns.tolist()
    elif isinstance(X, np.ndarray):
        features_name_ = features_name
    return features_name_


class PhishingIA:
    """
    Intelligence Artificielle pour la détection de phishing.

    Cette classe implémente un modèle de stacking combinant plusieurs
    classifieurs (XGBoost, ExtraTrees, HistGradientBoosting, MLP) pour
    classifier les URLs comme 'safe' ou 'phishing'.

    Le modèle utilise un pipeline avec :
    - RobustScaler pour normaliser les features
    - Un stacking classifier avec optimisation BayesSearchCV

    Attributes:
        dataset_file (str): Chemin vers le fichier dataset
        model_file (str): Chemin vers le modèle sauvegardé
        scoring (list): Métriques d'évaluation
        random_state (int): Seed pour la reproductibilité
        save_dir (str): Dossier de sauvegarde des résultats
        learning_rate (float): Taux d'apprentissage
        df (pd.DataFrame): Dataset chargé
        auto_fill_missing (bool): Auto-remplissage des colonnes manquantes
        imputer (IterativeImputer): Pour imputer les valeurs manquantes
        scaler (RobustScaler): Normalisation robuste
        cv (StratifiedKFold): Cross-validation stratifiée
        smote (SMOTE): Sur-échantillonnage pour équilibrer les classes
        le (LabelEncoder): Encodeur pour les labels
        model (Pipeline): Modèle entraîné
        features_name (list): Noms des features
        n_features (int): Nombre de features
        model_optimize (ModelOptimization): Instance d'optimisation

    Example:
        >>> ph = PhishingIA(model_dir_='model1', model_file='model_phish.pkl')
        >>> ph.load_model('model_phish.pkl')
        >>> result = ph.predict([{'url_length': 45, 'has_ip': 0, ...}])
        >>> print(result['predict']['0'])
        'safe'
    """

    def __init__(
            self, model_dir_='model1',
            dataset_file='dataset.joblib',
            model_file='model.joblib',
            n_features=len(features_name),
            cv=5, scoring=[],
            random_state=42, learning_rate=0.01,
            save_dir='sam0',
            features_name=features_name,
            auto_fill_missing=True
    ):
        """
        Initialise l'instance PhishingIA.

        Args:
            model_dir_ (str): Dossier contenant le modèle
            dataset_file (str): Nom du fichier dataset
            model_file (str): Nom du fichier modèle
            n_features (int): Nombre de features
            cv (int): Nombre de folds pour la cross-validation
            scoring (list): Métriques d'évaluation
            random_state (int): Seed pour la reproductibilité
            learning_rate (float): Taux d'apprentissage
            save_dir (str): Dossier de sauvegarde
            features_name (list): Noms des features
            auto_fill_missing (bool): Remplir automatiquement les colonnes manquantes
        """
        self.dataset_file = os.path.join(dir_, 'datasets', dataset_file)
        self.model_file = os.path.join(dir_, 'models', model_dir_, model_file)

        self.scoring = scoring or ['f1_samples', 'accuracy', 'precision_samples', 'recall_samples']
        self.random_state = random_state
        self.save_dir = save_dir
        self.learning_rate = learning_rate
        self.df = pd.DataFrame({})
        self.auto_fill_missing = auto_fill_missing

        os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
        self.load_dataset(self.dataset_file)

        if features_name and n_features:
            self.features_name = features_name
            self.n_features = n_features
        else:
            if not self.df.empty and 'label' in self.df.columns:
                self.features_name = get_features_name(self.df.drop(['label'], axis=1))
                self.n_features = self.df.shape[1] - 1
            else:
                raise ValueError("Données manquantes !")

        # Initialisation des composants du pipeline
        self.imputer = IterativeImputer(
            random_state=self.random_state,
            estimator=HistGradientBoostingRegressor(max_iter=100, learning_rate=0.01, n_iter_no_change=20)
        )
        self.scaler = RobustScaler()
        self.cv = StratifiedKFold(n_splits=min(cv, 3), shuffle=True, random_state=self.random_state)
        self.smote = SMOTE(k_neighbors=10, random_state=self.random_state)
        self.le = LabelEncoder()
        self.le.fit(classes)
        self.model = None
        self.load_model(self.model_file)

        # Nettoyage des colonnes indésirables
        self.features_name = [i for i in self.features_name if i not in ('grade', 'score_total', 'url')]

        print(f"PhishingIA initialisé avec {self.n_features} features, "
              f"dataset dans {self.dataset_file}, model dans {self.model_file}")

    def load_dataset(self, filepath):
        """
        Charge le dataset depuis un fichier.

        Args:
            filepath (str): Chemin vers le fichier à charger

        Note:
            Le fichier doit contenir une colonne 'label'.
        """
        if os.path.exists(filepath):
            try:
                self.df = pd.DataFrame(pd.read_pickle(filepath))
                if 'label' not in self.df.columns:
                    raise ValueError("Le dataset doit contenir une colonne 'label'")
                if self.df.empty:
                    print(f" ⚠️ Attention : Le dataset chargé depuis {filepath} est vide.")
                else:
                    print(f" ✅ Dataset chargé depuis {filepath} avec "
                          f"{self.df.shape[0]} échantillons et {self.df.shape[1]-1} features.")
            except Exception as e:
                print(f" ❌ Erreur lors du chargement du dataset depuis {filepath} : \n"
                      f"{type(e).__name__} - {e} \n {traceback.format_exc()}")
                self.df = pd.DataFrame({})
        else:
            print(f" 📁 Aucun dataset trouvé à {filepath}, démarrage avec un dataset vide.")
            self.df = pd.DataFrame({})

    def save_dataset(self, filepath):
        """
        Sauvegarde le dataset dans un fichier.

        Args:
            filepath (str): Chemin où sauvegarder le dataset
        """
        try:
            joblib.dump(self.df.to_dict(orient="records"), filepath)
            print(f" 💾 Dataset sauvegardé dans {filepath} avec "
                  f"{self.df.shape[0]} échantillons et {self.df.shape[1]-1} features.")
        except Exception as e:
            print(f" ❌ Erreur lors de la sauvegarde du dataset dans {filepath} : \n"
                  f"{type(e).__name__} - {e} \n {traceback.format_exc()}")

    def save_model(self, model=None):
        """
        Sauvegarde le modèle dans un fichier.

        Args:
            model: Modèle à sauvegarder (si None, utilise self.model)
        """
        model = model or self.model
        if model is None:
            print("Aucun model à sauvegarder.")
            return

        for i in range(3):
            try:
                os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
                self.model = model
                features_name = self.features_name
                stack = self.model.named_steps['stack']
                sc = self.model.named_steps['scaler']
                prefit = True
                classes_ = stack.classes_
                stack_method_ = stack.stack_method_
                final_estimator_ = stack.final_estimator_
                named_estimators_ = stack.named_estimators_
                label_encoder = stack._label_encoder

                dic = {
                    "le": self.le,
                    "scaler": sc,
                    "classes_": classes_,
                    'features_name': features_name,
                    'final_estimator_': final_estimator_,
                    "named_estimators_": named_estimators_,
                    'prefit': int(prefit),
                    'stack_method_': stack_method_,
                    '_label_encoder': label_encoder
                }
                mod_file = self.model_file
                joblib.dump(dic, mod_file, compress=6)
                print(f" ✅ Model sauvegardé dans {self.model_file}.")
                break
            except Exception as e:
                print(f'Tentative de sauvegarde {i+1}/3')
                print(f" ❌ Erreur lors de la sauvegarde du model dans {self.model_file} : \n"
                      f"{type(e).__name__} - {e} \n {traceback.format_exc()}")

    def load_model(self, model_file):
        """
        Charge le modèle depuis un fichier.

        Args:
            model_file (str): Chemin vers le fichier du modèle

        Returns:
            Pipeline: Le modèle chargé, ou None en cas d'erreur
        """
        from sklearn.utils.validation import check_is_fitted, NotFittedError

        if os.path.exists(model_file):
            try:
                data = joblib.load(model_file)
                if not data:
                    return

                self.le = data.get('le', LabelEncoder())
                self.features_name = data.get('features_name', features_name)
                classes_ = data.get('classes_', [0, 1])
                final_estimator_ = data.get('final_estimator_')
                named_estimators_ = data.get("named_estimators_")
                stack_method_ = data.get('stack_method', ["predict_proba"] * len(named_estimators_))
                scaler = data.get('scaler')
                prefit = data.get('prefit', 1)
                _label_encoder = data.get('_label_encoder')

                if not all(c for c in (final_estimator_, named_estimators_, scaler, _label_encoder)):
                    raise ValueError('[LOAD_MODEL] Un élément est absent')

                estimators = [(k, v) for k, v in named_estimators_.items()]
                stack = StackingClassifier(
                    estimators=estimators,
                    final_estimator=final_estimator_,
                    stack_method=stack_method_[0] if isinstance(stack_method_, list) else stack_method_,
                    cv='prefit' if prefit else 2,
                    n_jobs=-1, passthrough=True
                )

                print("[INFO] Petite vérification ...")
                print("=" * 50)
                for es in list(named_estimators_.values()) + [final_estimator_]:
                    try:
                        check_is_fitted(es)
                        print(type(es).__name__, 'est fitté, cool!')
                    except NotFittedError:
                        print(type(es).__name__, "NON fitté, GRAVE !!!")
                print("=" * 50)

                setattr(stack, "named_estimators_", named_estimators_)
                setattr(stack, 'classes_', classes_)
                setattr(stack, "estimators_", list(named_estimators_.values()))
                setattr(stack, "final_estimator_", final_estimator_)
                setattr(stack, "stack_method_", stack_method_)
                setattr(stack, "_label_encoder", _label_encoder)

                pip = Pipeline([
                    ('scaler', scaler),
                    ('stack', stack)
                ])
                self.model = pip
                self.scaler = scaler
                print(f" ✅ Model chargé depuis {model_file}.")
                return pip

            except Exception as e:
                print(f" ❌ Erreur lors du chargement du model depuis {model_file} : \n"
                      f"{type(e).__name__} - {e} \n {traceback.format_exc()}")
                return None
        else:
            print(f" 📁 Aucun model trouvé à {model_file}.")
            return None

    def prepa_data(self, data, mode, smote=True):
        """
        Prépare les données pour l'entraînement ou la prédiction.

        Args:
            data: Données d'entrée (DataFrame, list, ou dict)
            mode (str): 'fit' pour entraînement, 'predict' pour prédiction
            smote (bool): Appliquer SMOTE pour équilibrer les classes

        Returns:
            tuple: (X, y) où y peut être None en mode 'predict'

        Raises:
            ValueError: Si les données sont vides ou si 'label' manque en mode 'fit'
        """
        if isinstance(data, (pd.DataFrame, np.ndarray, pd.Series)):
            if isinstance(data, pd.DataFrame) and data.empty:
                raise ValueError('Data vide')
        else:
            if not data:
                raise ValueError('Data vide')

        p = pd.DataFrame(data)

        if 'label' not in p.columns and mode == 'fit':
            raise ValueError("La colonne 'label' est requise en mode 'fit'")

        if 'label' in p.columns:
            p['label'] = p['label'].apply(lambda x: x if isinstance(x, str) else str(x[0]))

        missing_cols = [c for c in self.features_name if c not in p.columns and c != "label"]

        if missing_cols:
            print(f"⚠️ Colonnes manquantes détectées : {missing_cols}")
            if self.auto_fill_missing:
                print("✅ Auto-remplissage activé: création des colonnes manquantes avec valeur 0")
                for col in missing_cols:
                    p[col] = 0
            else:
                raise ValueError(f"Colonnes manquantes dans les données: {missing_cols}")

        if mode == 'fit':
            # Ajout des nouvelles données dans le dataset global
            if self.df.empty:
                self.df = p
            else:
                all_row_in = p.apply(lambda r: ((r == self.df).all(axis=1)).all(), axis=1).all()
                if all_row_in or self.df.equals(p):
                    print("⚠️ Les nouvelles données sont déjà présentes dans le dataset. "
                          "Aucune concaténation effectuée.")
                else:
                    self.df = pd.concat((self.df, p), axis=0, ignore_index=True)
                    self.df = self.df.drop_duplicates(subset=['url'], ignore_index=True)

            self.save_dataset(self.dataset_file.replace('.pkl', '_fitted.pkl'))
            print(self.df.head(3))
            print(self.df.shape)

            for col in ('grade', 'score_total', 'url'):
                if col in self.df.columns:
                    self.df = self.df.drop(col, axis=1)

            y = self.le.transform(
                self.df.loc[:, 'label'].apply(lambda x: x if isinstance(x, list) else [x]).to_list()
            )
            X = self.df.drop(['label'], axis=1)

            if X.isna().sum().sum() != 0:
                print("Imputation", X.isna().sum().sum())
                X_imputed = self.imputer.fit_transform(X=X)
            else:
                print('Imputation désactivée')
                X_imputed = X

            if smote:
                X_, y_ = self.smote.fit_resample(X_imputed, y)
            else:
                print('Smote désactivée')
                X_, y_ = X_imputed, y

            X_ = pd.DataFrame(X_)
            return X_, y_

        elif mode == 'predict':
            # En mode prédiction, 'label' peut être absent
            for col in ('grade', 'score_total', 'url'):
                if col in p.columns:
                    p = p.drop(col, axis=1)

            if 'label' in p.columns:
                y = self.le.transform(p['label'].tolist())
                X = p.drop(['label'], axis=1)
            else:
                y = None
                X = p

            return X, y

    def _validate_data_size(self, X, y):
        """
        Valide que le dataset est suffisamment grand pour l'entraînement.

        Args:
            X: Features
            y: Labels

        Returns:
            bool: True si valide

        Raises:
            ValueError: Si le dataset est trop petit
        """
        X, y = np.asarray(X), np.asarray(y)
        n_samples = len(X)
        n_classes = len(np.unique(y, axis=0))
        min_samples = n_classes * 5  # Au moins 5 échantillons par classe

        if n_samples < min_samples:
            raise ValueError(
                f"Dataset trop petit : {n_samples} échantillons pour {n_classes} classes. "
                f"Minimum requis : {min_samples} échantillons (5 par classe)."
            )
        return True

    def fit(self, data, smote=False, _all_=True):
        """
        Entraîne le modèle sur un dataset.

        Args:
            data: Dataset d'entraînement (DataFrame avec colonne 'label')
            smote (bool): Appliquer SMOTE pour équilibrer les classes
            _all_ (bool): Exécuter toutes les analyses (learning curve, etc.)

        Returns:
            None (le modèle est sauvegardé automatiquement)
        """
        try:
            X, y = self.prepa_data(data, 'fit', smote=smote)
            print("Shapes avant fit:", X.shape, y.shape)
            self._validate_data_size(X, y)
            X_train, y_train = X, y
        except Exception as e:
            print(f"Erreur lors de la préparation des données (FIT): \n"
                  f"{type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None

        print(X.columns)

        # Création du ModelStack
        model_stack = ModelStack(
            X=X_train, y=y_train, n_features=X.shape[1], method='normal',
            learning_rate=self.learning_rate, cv=self.cv, random_state=self.random_state
        )
        stack = model_stack.run(n_iter=10, mode='normal')

        # Pipeline complet
        pip = Pipeline(steps=[
            ('scaler', self.scaler),
            ('stack', stack)
        ])

        # Optimisation du modèle
        model_optimize = ModelOptimization(
            pip, X, y, scoring=self.scoring, save_dir=self.save_dir, cv=2,
            features_name=self.features_name, random_state=self.random_state
        )

        for _ in tqdm(range(1), desc='🔄 Entraînement du Pipeline'):
            model_fit, test_x, test_y = model_optimize.run(
                save_func={"fonction": self.save_model}, _all_=_all_
            )

        self.scaler = pip.named_steps['scaler']
        self.model_optimize = model_optimize
        self.model = model_fit
        self.save_model(self.model)
        self.evaluate_model(self.model, test_x, test_y)

    def fit_sample(self, data, smote=False, _all_=True):
        """
        Version simplifiée de fit utilisant uniquement XGBoost.

        Args:
            data: Dataset d'entraînement
            smote (bool): Appliquer SMOTE
            _all_ (bool): Exécuter toutes les analyses
        """
        try:
            X, y = self.prepa_data(data, 'fit', smote=smote)
            print("Shapes avant fit:", X.shape, y.shape)
            self._validate_data_size(X, y)
            X_train, y_train = X, y
        except Exception as e:
            print(f"Erreur lors de la préparation des données (FIT): \n"
                  f"{type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None

        print(X.columns)

        xgb = XGBClassifier(
            n_estimators=1000,
            objective='binary:logistic',
            learning_rate=self.learning_rate,
            tree_method='hist',
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=self.random_state, verbose=0
        )

        dict_of_models = {}
        best_models = {}
        dict_of_models['xgb'] = ('xgb', xgb)
        models = [m for m in dict_of_models.keys() if m not in ("keras", "mlp", "bagcat", 'LogReg', "extra")]

        for i in tqdm(range(len(models)), desc='FITTING séparé des models'):
            name, model = dict_of_models[models[i]]
            space = PARAMS[name.lower()]
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}")

            model_bayes = BayesSearchCV(
                estimator=model,
                search_spaces=space,
                scoring='f1_macro',
                cv=self.cv,
                n_iter=15, n_jobs=-1,
                return_train_score=True,
                verbose=1,
            )
            start = time.time()
            model_bayes.fit(X_train, y_train)
            end = time.time()
            best_models[name] = (name, model_bayes.best_estimator_)
            print(f"\n Meilleur paramètres pour ce model : {dict(model_bayes.best_params_)} "
                  f"et \n Meilleur score CV : {model_bayes.best_score_}")
            print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)}")
            print(f"\n Fit terminé en {end - start:.3f} secondes")

            pip = Pipeline(steps=[
                ('scaler', self.scaler),
                list(best_models.values())[0]
            ])

        model_optimize = ModelOptimization(
            pip, X, y, scoring=self.scoring, save_dir=self.save_dir, cv=2,
            features_name=self.features_name, random_state=self.random_state
        )

        for _ in tqdm(range(1), desc='🔄 Entraînement du Pipeline'):
            model_fit, test_x, test_y = model_optimize.run(
                save_func={"fonction": self.save_model}, _all_=_all_
            )

        self.model_optimize = model_optimize
        self.model = model_fit
        self.save_model(self.model)
        self.evaluate_model(self.model, test_x, test_y)

    def evaluate_model(self, model, X, y):
        """
        Évalue les performances du modèle sur un jeu de test.

        Args:
            model: Modèle à évaluer
            X: Features de test
            y: Labels réels

        Returns:
            tuple: (score, report, matrix, metrics_df)
        """
        X, y = np.asarray(X), np.asarray(y)
        y_pred = model.predict(X)
        label = 'PH_test'

        metrics = self.model_optimize._compute_detailed_metrics(y, y_pred, prefix='')
        score, report, matrix = self.model_optimize.matrix_and_report(
            model, X, y, from_='Matrix and Report sur X_test et y_test '
        )

        metrics_df = pd.DataFrame([metrics], index=['Test'])
        metrics_df.to_csv(
            os.path.join(self.model_optimize.save_dir, f'evaluation_detailed_{label}.csv'),
            index=True
        )
        print(f'Évaluation détaillée sauvegardée dans '
              f'{os.path.join(self.model_optimize.save_dir, f"evaluation_detailed_{label}.csv")}')
        print(f"Métriques détaillées : \n {metrics_df}")

        return score, report, matrix, metrics_df

    def predict(self, data):
        """
        Prédit le label d'une ou plusieurs URLs.

        Args:
            data: Données d'entrée (features extraites d'une URL)

        Returns:
            dict: Contenant les clés :
                - predict_proba (dict): Probabilités pour chaque classe
                - predict (dict): Labels prédits
                - true_labels (dict): Labels réels (si fournis)

        Example:
            >>> ph = PhishingIA()
            >>> ph.load_model('model_phish.pkl')
            >>> features = features_extractor_from_url('https://google.com')
            >>> result = ph.predict(features)
            >>> print(result['predict']['0'])
            'safe'
            >>> print(result['predict_proba']['0'])
            {'phishing': 0.01, 'safe': 0.99}
        """
        try:
            X, y_true = self.prepa_data(data, 'predict')
        except Exception as e:
            print(f" ❌ Erreur lors de la préparation des données (PREDICT): \n"
                  f"{type(e).__name__} - {e} \n {traceback.format_exc()}")
            return None

        if self.model is None:
            print(" ⚠️ Aucun modèle chargé pour la prédiction.")
            return None

        y_pred = np.array(self.model.predict(X))
        y_pred_proba = np.array(self.model.predict_proba(X)).astype(float)
        cols = self.le.classes_

        predict_proba = {str(i): dict(zip(cols, row)) for i, row in enumerate(y_pred_proba)}
        predict_labels = {str(i): label for i, label in enumerate(self.le.inverse_transform(y_pred))}
        true_labels = {str(i): label for i, label in enumerate(self.le.inverse_transform(y_true))} \
                      if y_true is not None else {}

        return {
            "predict_proba": predict_proba,
            "predict": predict_labels,
            "true_labels": true_labels
        }


if __name__ == '__main__':
    pd.set_option("display.max_row", 111)
    pd.set_option("display.max_columns", 111)

    ph = PhishingIA(
        features_name=features_name, n_features=len(features_name), cv=3,
        learning_rate=0.001, dataset_file='dataset0.pkl', model_file='model_phish.pkl',
        auto_fill_missing=True, model_dir_='model', save_dir='sam'
    )

    test_ = pd.DataFrame(joblib.load(os.path.join(dir_, 'datasets', 'dataset_test.pkl')))
    test = test_.to_dict(orient='records')
    if not isinstance(test, list):
        test = [test]
    test = test[:len(test)]

    mo = ModelOptimization(ph.model, X=[[], []], y=[], random_state=2)
    mo.matrix_and_report(ph.model, test_.drop(['label', 'url'], axis=1),
                         y_test=ph.le.fit_transform(test_['label']))

    print(pd.DataFrame(compute_metrics_safe(
        ph.le.fit_transform(test_['label']),
        ph.model.predict(test_.drop(['label', 'url'], axis=1)),
        ph.model.predict_proba(test_.drop(['label', 'url'], axis=1))
    ), index=['Test']))

    input()
    for r in test:
        if not isinstance(r, list):
            r = [r]
        print(json.dumps(ph.predict(r), indent=2, ensure_ascii=False))
        input()
    print(json.dumps(ph.predict(test), indent=2, ensure_ascii=False))