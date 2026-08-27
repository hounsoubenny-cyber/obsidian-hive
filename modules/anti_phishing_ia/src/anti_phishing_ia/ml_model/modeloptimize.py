#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Optimisation et évaluation de modèles de machine learning.

Ce module fournit des outils pour :
- Évaluer des modèles avec cross-validation
- Calculer des métriques détaillées (F1, précision, rappel, AUC-ROC)
- Tracer des courbes d'apprentissage
- Calculer l'importance des features par permutation
- Comparer plusieurs modèles

La classe ModelOptimization centralise ces fonctionnalités.

Auteur: HOUNSOU Samuel
Date: Octobre 2025
Version: 1.0.0
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sklearn.base import clone
from sklearn.model_selection import train_test_split, cross_validate, learning_curve
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    f1_score, accuracy_score, precision_score, recall_score, hamming_loss,
    jaccard_score, confusion_matrix, multilabel_confusion_matrix,
    classification_report, roc_auc_score
)
import numpy as np
import traceback
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
import joblib

warnings.filterwarnings('ignore')
pd.set_option("display.max_row", 111)
pd.set_option("display.max_columns", 111)

# Répertoire de base pour les résultats
dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(dir_, exist_ok=True)


def _compute_metrics(y_true, y_pred, y_pred_proba=None, prefix=''):
    """
    Calcule toutes les métriques détaillées de façon centralisée.

    Cette fonction gère les différents types de classification :
    - Binaire
    - Multiclasse
    - Multilabel

    Args:
        y_true (array-like): Labels réels
        y_pred (array-like): Labels prédits
        y_pred_proba (array-like, optional): Probabilités prédites
        prefix (str): Préfixe à ajouter aux noms des métriques

    Returns:
        dict: Dictionnaire contenant toutes les métriques calculées

    Note:
        Les métriques ROC-AUC ne sont calculées que si y_pred_proba est fourni.
        En cas d'erreur, les métriques sont mises à NaN.
    """
    metrics = {}

    try:
        # Conversion robuste des arrays
        y_true = np.asarray(y_true)
        y_pred = np.asarray(y_pred)

        # Vérification des dimensions cohérentes
        if y_true.shape != y_pred.shape:
            raise ValueError(f"Dimensions incohérentes: y_true {y_true.shape}, y_pred {y_pred.shape}")

        # Détection du type de problème
        is_multilabel = y_true.ndim == 2 and y_true.shape[1] > 1
        is_binary = not is_multilabel and len(np.unique(y_true)) == 2

        # ========== MÉTRIQUES F1-SCORE ==========
        try:
            metrics[f'{prefix}f1_weighted'] = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}f1_weighted'] = np.nan
            print(f"Erreur f1_weighted: {e}")

        try:
            metrics[f'{prefix}f1_micro'] = f1_score(y_true, y_pred, average='micro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}f1_micro'] = np.nan
            print(f"Erreur f1_micro: {e}")

        try:
            metrics[f'{prefix}f1_macro'] = f1_score(y_true, y_pred, average='macro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}f1_macro'] = np.nan
            print(f"Erreur f1_macro: {e}")

        # Métriques samples seulement pour multilabel
        try:
            if is_multilabel:
                metrics[f'{prefix}f1_samples'] = f1_score(y_true, y_pred, average='samples', zero_division=0)
            else:
                metrics[f'{prefix}f1_samples'] = np.nan
        except Exception as e:
            metrics[f'{prefix}f1_samples'] = np.nan
            print(f"Erreur f1_samples: {e}")

        # ========== MÉTRIQUES DE BASE ==========
        try:
            metrics[f'{prefix}accuracy_score'] = accuracy_score(y_true, y_pred)
        except Exception as e:
            metrics[f'{prefix}accuracy_score'] = np.nan
            print(f"Erreur accuracy_score: {e}")

        try:
            metrics[f'{prefix}precision_macro'] = precision_score(y_true, y_pred, average='macro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}precision_macro'] = np.nan
            print(f"Erreur precision_macro: {e}")

        try:
            metrics[f'{prefix}recall_macro'] = recall_score(y_true, y_pred, average='macro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}recall_macro'] = np.nan
            print(f"Erreur recall_macro: {e}")

        try:
            metrics[f'{prefix}recall_micro'] = recall_score(y_true, y_pred, average='micro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}recall_micro'] = np.nan
            print(f"Erreur recall_micro: {e}")

        # ========== MÉTRIQUES DE DISTANCE ==========
        try:
            metrics[f'{prefix}hamming_loss'] = hamming_loss(y_true, y_pred)
        except Exception as e:
            metrics[f'{prefix}hamming_loss'] = np.nan
            print(f"Erreur hamming_loss: {e}")

        # ========== MÉTRIQUES JACCARD ==========
        try:
            metrics[f'{prefix}jaccard_micro'] = jaccard_score(y_true, y_pred, average='micro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}jaccard_micro'] = np.nan
            print(f"Erreur jaccard_micro: {e}")

        try:
            metrics[f'{prefix}jaccard_macro'] = jaccard_score(y_true, y_pred, average='macro', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}jaccard_macro'] = np.nan
            print(f"Erreur jaccard_macro: {e}")

        try:
            metrics[f'{prefix}jaccard_weighted'] = jaccard_score(y_true, y_pred, average='weighted', zero_division=0)
        except Exception as e:
            metrics[f'{prefix}jaccard_weighted'] = np.nan
            print(f"Erreur jaccard_weighted: {e}")

        try:
            if is_multilabel:
                metrics[f'{prefix}jaccard_samples'] = jaccard_score(y_true, y_pred, average='samples', zero_division=0)
            else:
                metrics[f'{prefix}jaccard_samples'] = np.nan
        except Exception as e:
            metrics[f'{prefix}jaccard_samples'] = np.nan
            print(f"Erreur jaccard_samples: {e}")

        # ========== ROC-AUC SCORES ==========
        try:
            if y_pred_proba is not None:
                y_pred_proba = np.asarray(y_pred_proba)

                # ROC-AUC pour classification binaire
                if is_binary and y_pred_proba.ndim == 1:
                    metrics[f'{prefix}roc_auc'] = roc_auc_score(y_true, y_pred_proba)
                elif is_binary and y_pred_proba.ndim == 2 and y_pred_proba.shape[1] == 2:
                    metrics[f'{prefix}roc_auc'] = roc_auc_score(y_true, y_pred_proba[:, 1])
                # ROC-AUC pour multilabel
                elif is_multilabel:
                    try:
                        metrics[f'{prefix}roc_auc_micro'] = roc_auc_score(y_true, y_pred_proba, average='micro')
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_micro'] = np.nan
                        print(f"Erreur roc_auc_micro: {e}")

                    try:
                        metrics[f'{prefix}roc_auc_macro'] = roc_auc_score(y_true, y_pred_proba, average='macro')
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_macro'] = np.nan
                        print(f"Erreur roc_auc_macro: {e}")

                    try:
                        metrics[f'{prefix}roc_auc_weighted'] = roc_auc_score(y_true, y_pred_proba, average='weighted')
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_weighted'] = np.nan
                        print(f"Erreur roc_auc_weighted: {e}")

                # ROC-AUC multiclasse
                elif not is_multilabel and len(np.unique(y_true)) > 2:
                    try:
                        metrics[f'{prefix}roc_auc_ovr'] = roc_auc_score(
                            y_true, y_pred_proba, multi_class='ovr', average='macro'
                        )
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_ovr'] = np.nan
                        print(f"Erreur roc_auc_ovr: {e}")

                    try:
                        metrics[f'{prefix}roc_auc_ovo'] = roc_auc_score(
                            y_true, y_pred_proba, multi_class='ovo', average='macro'
                        )
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_ovo'] = np.nan
                        print(f"Erreur roc_auc_ovo: {e}")
            else:
                if is_binary:
                    try:
                        metrics[f'{prefix}roc_auc'] = roc_auc_score(y_true, y_pred)
                    except Exception as e:
                        metrics[f'{prefix}roc_auc'] = np.nan
                        print(f"Erreur roc_auc (binary fallback): {e}")
                else:
                    metrics[f'{prefix}roc_auc'] = np.nan

        except Exception as e:
            print(f"Erreur générale ROC-AUC: {e}")
            roc_metrics = ['roc_auc', 'roc_auc_micro', 'roc_auc_macro',
                           'roc_auc_weighted', 'roc_auc_ovr', 'roc_auc_ovo']
            for roc_metric in roc_metrics:
                metrics[f'{prefix}{roc_metric}'] = np.nan

    except Exception as e:
        print(f"Erreur critique dans _compute_metrics {prefix}: {e}")
        # Initialiser toutes les métriques à NaN en cas d'erreur critique
        base_metrics = [
            'f1_weighted', 'f1_micro', 'f1_macro', 'f1_samples',
            'accuracy_score', 'precision_macro', 'recall_macro', 'recall_micro',
            'hamming_loss', 'jaccard_micro', 'jaccard_macro',
            'jaccard_weighted', 'jaccard_samples'
        ]
        roc_metrics = ['roc_auc', 'roc_auc_micro', 'roc_auc_macro',
                       'roc_auc_weighted', 'roc_auc_ovr', 'roc_auc_ovo']

        for metric in base_metrics + roc_metrics:
            metrics[f'{prefix}{metric}'] = np.nan

    return metrics


def compute_metrics_safe(y_true, y_pred, y_pred_proba=None, prefix=''):
    """
    Version simplifiée avec gestion d'erreurs pour usage rapide.

    Args:
        y_true (array-like): Labels réels
        y_pred (array-like): Labels prédits
        y_pred_proba (array-like, optional): Probabilités prédites
        prefix (str): Préfixe optionnel

    Returns:
        dict: Métriques calculées ou dictionnaire d'erreur

    Example:
        >>> metrics = compute_metrics_safe(y_test, y_pred, y_proba)
        >>> print(metrics['accuracy_score'])
        0.95
    """
    try:
        return _compute_metrics(y_true, y_pred, y_pred_proba, prefix)
    except Exception as e:
        print(f"Erreur fatale dans compute_metrics_safe: {e}")
        return {f'{prefix}error': str(e)}


def split_data(X, y, random_state=42):
    """
    Effectue un split train/test avec stratification adaptative.

    Args:
        X (array-like): Features
        y (array-like): Labels
        random_state (int): Seed pour la reproductibilité

    Returns:
        tuple: (X_train, X_test, y_train, y_test)

    Raises:
        ValueError: Si les données sont vides
    """
    X, y = np.asarray(X), np.asarray(y)

    if X.any() and y.any():
        X, y = np.asarray(X), np.asarray(y)
        n_samples = len(X)
        n_classes = len(np.unique(y, axis=0))

        # Calcul du test_size minimum pour la stratification
        min_test_samples = n_classes
        min_test_size = min_test_samples / n_samples

        # Choix entre 0.2 et le minimum requis
        test_size = max(0.2, min_test_size + 0.05)

        # Désactivation de la stratification si dataset trop petit
        if test_size >= 0.5 or n_samples < 10:
            print(f"⚠️ Dataset trop petit ({n_samples} échantillons). Stratification désactivée.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=random_state
            )
        else:
            print(f"✅ Utilisation de test_size={test_size:.2f} pour {n_samples} échantillons.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )

        return X_train, X_test, y_train, y_test
    else:
        raise ValueError("Données vides (SPLIT_DATA)")


class ModelOptimization:
    """
    Optimisation et évaluation complète de modèles ML.

    Cette classe permet d'entraîner un modèle, d'évaluer ses performances,
    de tracer des courbes d'apprentissage, et d'analyser l'importance
    des features.

    Attributes:
        model: Modèle scikit-learn à optimiser
        X (np.ndarray): Features
        y (np.ndarray): Labels
        random_state (int): Seed
        features_names (list): Noms des features
        n_features (int): Nombre de features
        scoring (list): Métriques d'évaluation
        cv (int): Nombre de folds
        results (dict): Résultats des évaluations
        save_dir (str): Dossier de sauvegarde

    Example:
        >>> from sklearn.ensemble import RandomForestClassifier
        >>> model = RandomForestClassifier()
        >>> opt = ModelOptimization(model, X_train, y_train, random_state=42)
        >>> model_opt, X_test, y_test = opt.run()
        >>> print(f"Accuracy: {model_opt.score(X_test, y_test):.2%}")
    """

    def __init__(self, model, X, y, random_state, scoring=None, save_dir="results0",
                 features_name=None, dir_=dir_, cv=2):
        """
        Initialise l'optimisation du modèle.

        Args:
            model: Modèle scikit-learn à optimiser
            X (array-like): Features d'entraînement
            y (array-like): Labels
            random_state (int): Seed pour la reproductibilité
            scoring (list): Métriques d'évaluation
            save_dir (str): Dossier de sauvegarde des résultats
            features_name (list): Noms des features
            dir_ (str): Répertoire de base
            cv (int): Nombre de folds pour la cross-validation
        """
        features_name = features_name or []
        scoring = scoring or []
        self.model = model
        self.random_state = random_state
        self.X = np.asarray(X)
        self.y = np.asarray(y)
        self.model_ = None
        self.features_names = features_name
        self.n_features = self.X.shape[1]
        self.scoring = scoring or ['f1_macro', 'accuracy', 'precision', 'recall']
        self.cv = cv
        self.results = {}
        self.save_dir = os.path.join(dir_, "results_optimization", save_dir)
        os.makedirs(self.save_dir, exist_ok=True)
        print(f"ModelOptimization initialisée avec {self.n_features} features, "
              f"sauvegarde des resultats dans le dossier {self.save_dir}")

    def _apply_mask(self, X, mask):
        """
        Applique un masque de sélection de features.

        Args:
            X: Données (DataFrame ou ndarray)
            mask (array-like): Masque booléen

        Returns:
            array-like: Données filtrées
        """
        if mask is not None:
            if isinstance(X, pd.DataFrame):
                X = X.loc[:, mask]
            elif isinstance(X, np.ndarray):
                X = X[:, mask]
            else:
                raise ValueError("X doit être un DataFrame ou un ndarray")
        return X

    def fit(self, model, X, y):
        """
        Entraîne un modèle.

        Args:
            model: Modèle à entraîner
            X: Features
            y: Labels

        Returns:
            Modèle entraîné
        """
        model.fit(X, y)
        return model

    def matrix_and_report(self, model, X_test, y_test, from_='ModelOptimize sur Échantillon de X_train et y_train réel'):
        """
        Affiche et sauvegarde la matrice de confusion et le rapport de classification.

        Args:
            model: Modèle entraîné
            X_test: Features de test
            y_test: Labels réels
            from_ (str): Description de la source

        Returns:
            tuple: (score, classification_report, confusion_matrix)
        """
        to_print = 'Matrice de confusion multilabel et classification report'
        print('\n', '=' * 50)
        print(to_print)
        print(from_)
        print('=' * 50)

        X_test, y_test = np.asarray(X_test), np.asarray(y_test)
        y_pred = np.asarray(model.predict(X_test))
        sc = model.score(X_test, y_test)

        try:
            # Pour les problèmes multiclasses/multilabels complexes
            if y_test.ndim == 2 and y_test.shape[1] > 1:
                cm = multilabel_confusion_matrix(y_test, y_pred)
                n_labels = cm.shape[0]

                # Visualisation adaptée pour multilabel
                fig, axes = plt.subplots(1, min(n_labels, 4), figsize=(15, 4))
                if n_labels == 1:
                    axes = [axes]

                for i in range(min(n_labels, 4)):
                    sns.heatmap(cm[i], annot=True, fmt='d', cmap='Blues',
                                xticklabels=['Négatif', 'Positif'],
                                yticklabels=['Négatif', 'Positif'],
                                ax=axes[i])
                    axes[i].set_title(f'Label {i}')
                    axes[i].set_xlabel('Prédit')
                    axes[i].set_ylabel('Réel')

            else:
                # Pour les problèmes de classification binaire ou multiclasse simple
                cm = confusion_matrix(y_test, y_pred)
                plt.figure(figsize=(8, 6))
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                            xticklabels=['Négatif', 'Positif'],
                            yticklabels=['Négatif', 'Positif'])
                plt.title('Matrice de Confusion')
                plt.xlabel('Prédit')
                plt.ylabel('Réel')

            plt.tight_layout()
            plt.show(block=False)
            plt.savefig(os.path.join(self.save_dir, 'confusion_matrix.png'))
            print(f'Confusion matrix sauvegardée dans {os.path.join(self.save_dir, "confusion_matrix.png")}')

        except Exception as e:
            print(f"Erreur dans la visualisation de la matrice de confusion : {e}")
            cm = confusion_matrix(y_test, y_pred)  # Fallback simple

        cr = classification_report(y_test, y_pred)
        print(f"Score du modèle sur les données de test : {sc:.4f}")
        print("\nClassification report : \n", cr)
        print('Confusion matrix : \n', cm)

        return sc, cr, cm

    def _compute_detailed_metrics(self, y_true, y_pred, prefix=''):
        """
        Calcule toutes les métriques détaillées de façon centralisée.

        Args:
            y_true: Labels réels
            y_pred: Labels prédits
            prefix (str): Préfixe optionnel

        Returns:
            dict: Métriques calculées
        """
        return _compute_metrics(y_true, y_pred, prefix=prefix)

    def evaluate(self, model, X_train, y_train, X_val, y_val, label='initial'):
        """
        Évalue le modèle en utilisant cross_validate et calcule les métriques détaillées.

        Args:
            model: Modèle à évaluer
            X_train: Features d'entraînement
            y_train: Labels d'entraînement
            X_val: Features de validation
            y_val: Labels de validation
            label (str): Label pour l'évaluation (ex: 'initial', 'optimized')
        """
        print(f"Evaluations ({label}) ...")

        # Score simple
        try:
            print("Score du modèle sur les données de validation : ", model.score(X_val, y_val))
        except Exception:
            print("Score du modèle sur les données de validation : ", accuracy_score(y_val, model.predict(X_val)))

        # Cross-validation
        try:
            res = cross_validate(
                model, X_train, y_train,
                scoring=['f1_macro', "precision_macro", 'f1_micro', 'precision_micro'],
                cv=self.cv, n_jobs=2, return_train_score=True, error_score='raise'
            )
            df = pd.DataFrame(res)
            df.loc['mean'] = df.mean()
            df.to_csv(os.path.join(self.save_dir, f'evaluation_{label}.csv'), index=True)
            self.results[label] = df
            print(f'✅ Evaluation sauvegardée dans {os.path.join(self.save_dir, f"evaluation_{label}.csv")}')
            print('Dataframe des résultats de cross_validate : \n', df)
        except Exception as e:
            print(f"❌ Erreur lors de la cross-validation: {e}")
            print("Détails : \n ", traceback.format_exc())
            df = pd.DataFrame()
            self.results[label] = df

        # Métriques détaillées
        try:
            y_train_pred = model.predict(X_train)
            y_val_pred = model.predict(X_val)

            train_metrics = self._compute_detailed_metrics(y_train, y_train_pred, '')
            val_metrics = self._compute_detailed_metrics(y_val, y_val_pred, '')

            # DataFrame des métriques
            metrics_df = pd.DataFrame([train_metrics, val_metrics], index=['Train', 'Validation'])
            metrics_df.index.name = "Étape"
            metrics_df = metrics_df.dropna(axis=1)

            # Calcul du gap (différence Train - Validation)
            metrics_df.loc['gap'] = metrics_df.loc['Train'] - metrics_df.loc['Validation']

            def classify_gap(metric_name, gap_value):
                """Classe l'écart pour détecter l'overfitting."""
                if 'hamming_loss' in metric_name:
                    effective_gap = -gap_value  # Inversion pour hamming_loss
                else:
                    effective_gap = gap_value

                abs_gap = abs(effective_gap)
                if abs_gap > 0.1:
                    return '⚠️ Écart important'
                elif abs_gap > 0.05:
                    return '📊 Écart modéré'
                else:
                    return '✅ Bonne généralisation'

            gap_evaluation = {}
            for metric in metrics_df.columns:
                if metric in metrics_df.loc['gap']:
                    gap_value = metrics_df.loc['gap'][metric]
                    gap_evaluation[metric] = classify_gap(metric, gap_value)

            metrics_df.loc['évaluation_gap'] = gap_evaluation

            # Sauvegarde
            if not metrics_df.empty:
                metrics_df.to_csv(os.path.join(self.save_dir, f'evaluation_detailed_{label}.csv'), index=True)
                print(f'Évaluation détaillée sauvegardée dans '
                      f'{os.path.join(self.save_dir, f"evaluation_detailed_{label}.csv")}')
                print(f"Métriques détaillées : \n {metrics_df}")

            self.matrix_and_report(model, X_val, y_val)

            return df, metrics_df

        except Exception as e:
            print(f"Erreur dans le calcul approfondi des métriques d'évaluation : {e}")
            traceback.print_exc()
            return df, pd.DataFrame([])

    def plot_learning_curve(self, model, X, y, label='initial'):
        """
        Trace la courbe d'apprentissage du modèle.

        Args:
            model: Modèle à analyser
            X: Features
            y: Labels
            label (str): Label pour le titre
        """
        try:
            train_sizes, train_scores, test_scores = learning_curve(
                model, X, y, cv=2, scoring='f1_macro', n_jobs=2,
                train_sizes=np.linspace(0.2, 1.0, 5), error_score='raise'
            )
        except Exception as e:
            print(f"[plot_learning_curve] Erreur au niveau de learning curve : {type(e).__name__} : {e}")
            print("Détails : \n ", traceback.format_exc())
            return

        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        gap_values = train_scores_mean - test_scores_mean
        gap = train_scores_mean[-1] - test_scores_mean[-1]

        plt.figure(figsize=(20, 10))

        # Graphique 1: Courbe d'apprentissage
        plt.subplot(2, 2, 1)
        plt.title(f'Learning Curve ({label})')
        plt.plot(train_sizes, train_scores_mean, 'o-', color='r',
                 label=f'Training score (final: {train_scores_mean[-1]:.3f})')
        plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                         train_scores_mean + train_scores_std, alpha=0.1, color='r')
        plt.plot(train_sizes, test_scores_mean, 'o-', color='g', label='Cross-validation score')
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                         test_scores_mean + test_scores_std, alpha=0.1, color='g')
        plt.xlabel('Taille du jeu d\'entraînement')
        plt.ylabel('Score (f1_macro)')
        plt.ylim(0, 1.1)
        plt.legend(loc='best')
        plt.grid(True)

        # Graphique 2: Écart Train-Validation
        plt.subplot(2, 2, 2)
        plt.title('Écart Train-Validation')
        plt.plot(train_sizes, gap_values, 'o-', color='purple', label='Évolution du gap')
        plt.axhline(y=0.1, color='red', linestyle='--', label='Seuil overfitting (10%)')
        plt.axhline(y=0.05, color='orange', linestyle='--', label='Seuil acceptable (5%)')
        plt.xlabel('Taille du jeu d\'entraînement')
        plt.ylabel('Gap (Train - Validation)')
        plt.ylim(0, 0.1001)
        plt.legend(loc='best')
        plt.grid(True)

        # Graphique 3: Résumé
        plt.subplot(2, 2, 3)
        plt.title('Résumé')
        plt.plot(train_sizes, train_scores_mean, 'o-', color='r',
                 label=f'Training score (final: {train_scores_mean[-1]:.3f})')
        plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                         train_scores_mean + train_scores_std, alpha=0.1, color='r')
        plt.plot(train_sizes, test_scores_mean, 'o-', color='g',
                 label=f'CV score (final: {test_scores_mean[-1]:.3f})')
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                         test_scores_mean + test_scores_std, alpha=0.1, color='g')
        plt.plot(train_sizes, gap_values, 'o-', color='purple', label='Gap')
        plt.axhline(y=0.1, color='red', linestyle='--', label='Seuil overfitting (10%)')
        plt.axhline(y=0.05, color='orange', linestyle='--', label='Seuil acceptable (5%)')
        plt.xlabel('Taille du jeu d\'entraînement')
        plt.ylabel('Score et Gap')
        plt.ylim(0, 1.1)
        plt.legend(loc='best')
        plt.grid(True)

        plt.savefig(os.path.join(self.save_dir, f'learning_curve_{label}.png'))
        print(f'Learning curve sauvegardée dans {os.path.join(self.save_dir, f"learning_curve_{label}.png")}')
        print('=' * 60)
        print(f'Score train final : {train_scores_mean[-1]:.4f}')
        print(f'Score validation final : {test_scores_mean[-1]:.4f}')
        print(f"Gap final : {gap:.4f} ({gap * 100:.2f}%)")

        if gap > 0.1:
            print("[ALERTE] Overfitting détecté ! "
                  "Le modèle performe mieux sur train que validation. "
                  "Essayez de réduire la complexité du modèle.")
        elif gap > 0.05:
            print("Overfitting léger. Gap acceptable mais peut être amélioré.")
        else:
            print("Pas d'overfitting détecté. Le modèle généralise bien !")

        plt.tight_layout()
        plt.show(block=False)

    def feature_importance(self, model, X, y, label='initial', threshold=None):
        """
        Calcule l'importance des features par permutation.

        Args:
            model: Modèle entraîné
            X: Features
            y: Labels
            label (str): Label pour le graphique
            threshold (float, optional): Seuil de sélection

        Returns:
            pd.DataFrame: DataFrame avec les importances
        """
        original_idx = np.arange(self.n_features)

        print(f"Calcul des importances des features pour {label} ...")

        result = permutation_importance(model, X, y, n_repeats=10,
                                        random_state=self.random_state, n_jobs=-1)
        importances_mean = result.importances_mean
        importances_std = result.importances_std
        indices = np.argsort(importances_mean)[::-1]

        df = pd.DataFrame({
            'features': np.array(self.features_names)[original_idx],
            "indices": original_idx,
            "importances_mean": importances_mean,
            "importances_std": importances_std
        }).sort_values(by='importances_mean', ascending=False)

        mean_imp = df['importances_mean'].mean()
        std_imp = df["importances_std"].mean()
        quantile = df['importances_mean'].quantile(0.7)
        threshold = threshold or max(quantile, mean_imp + 0.5 * std_imp)

        print(f'Sélection des features avec un seuil de {threshold:.4f} ...')
        mask = df['importances_mean'].to_numpy() < threshold
        features_prob = df['features'].to_numpy()[mask]

        if features_prob.any():
            print("Features problématiques (importance faible) : ")
            for lab in features_prob:
                print("-", lab)

        df.to_csv(os.path.join(self.save_dir, f'feature_importance_{label}.csv'), index=False)
        print(f'Feature importances sauvegardées dans '
              f'{os.path.join(self.save_dir, f"feature_importance_{label}.csv")}')
        print(df)

        # Graphique
        plt.figure(figsize=(20, 10))
        plt.subplot(1, 2, 1)
        plt.title(f'Permutation Feature Importances ({label})')
        plt.plot(indices, importances_mean[indices], 'o', label='Importances Moyennes', color='r')
        plt.plot(indices, importances_std[indices], 'o', label='Importances Std', color='g')
        plt.xlabel('Indices des features')
        plt.ylabel('Importance')
        plt.legend()

        plt.subplot(1, 2, 2)
        plt.title(f'Permutation Feature Importances ({label})')
        plt.plot(indices, importances_mean[indices], 'o-', label='Importances Moyennes', color='r')
        plt.plot(indices, importances_std[indices], 'o-', label='Importances Std', color='g')
        plt.xlabel('Indices des features')
        plt.ylabel('Importance')
        plt.legend()

        plt.savefig(os.path.join(self.save_dir, f'feature_importance_{label}.png'))
        print(f'Feature importance plot sauvegardé dans '
              f'{os.path.join(self.save_dir, f"feature_importance_{label}.png")}')
        plt.show(block=False)

        return df

    def features_selection(self, df_importance):
        """
        Sélectionne les features en fonction d'un seuil d'importance.

        Args:
            df_importance (pd.DataFrame): DataFrame de feature_importance()

        Returns:
            np.ndarray: Masque booléen des features sélectionnées
        """
        mean_imp = df_importance['importances_mean'].mean()
        std_imp = df_importance["importances_std"].mean()
        quantile = df_importance['importances_mean'].quantile(0.7)
        threshold = max(quantile, mean_imp + 0.5 * std_imp)

        print(f'Sélection des features avec un seuil de {threshold:.4f} ...')
        mask = df_importance['importances_mean'] > threshold
        full_mask = np.zeros(self.n_features, dtype=bool)

        if not mask.any():
            print(f'Aucune feature ne dépasse le seuil, ajustement du seuil à {threshold:.4f}')
            indices_sorted = np.argsort(df_importance['importances_mean'].values)[::-1]
            top75 = max(int(len(indices_sorted) * 0.75), 1)
            top_indices = indices_sorted[:top75]
            full_mask[df_importance['indices'].values[top_indices]] = True
        else:
            print(f'Features sélectionnées : {mask.sum()} , avec seuil {threshold:.4f}')
            full_mask[df_importance['indices'].values] = mask.values

        print(f'Finalement {full_mask.sum()} features sélectionnées sur {self.n_features}')
        return full_mask

    def compare(self):
        """
        Compare les résultats des deux premières évaluations.

        Returns:
            pd.DataFrame: DataFrame de comparaison
        """
        keys = list(self.results.keys())[:2]
        if len(keys) < 2:
            print("Pas assez de résultats pour comparer.")
            return None

        df_0 = self.results[keys[0]].loc['mean']
        df_1 = self.results[keys[1]].loc['mean']

        comparison = pd.DataFrame({
            'Metric': df_0.index,
            keys[0]: df_0.values,
            keys[1]: df_1.values,
            'Difference': df_1.values - df_0.values
        })

        comparison.to_csv(os.path.join(self.save_dir, 'comparison_results.csv'), index=True)
        print(f'Résultats de comparaison sauvegardés dans {os.path.join(self.save_dir, "comparison_results.csv")}')
        print("Comparaison des deux premiers résultats des Évaluations \n", comparison)
        return comparison

    def run(self, threshold=None, save_func=None, already_fit=False, _all_=True, features=False):
        """
        Exécute l'optimisation complète du modèle.

        Args:
            threshold (float, optional): Seuil pour feature_importance
            save_func (dict): Fonction de sauvegarde {'fonction': func, 'filename': str}
            already_fit (bool): Si True, le modèle est déjà entraîné
            _all_ (bool): Exécute toutes les analyses (learning curve, etc.)
            features (bool): Calcule l'importance des features

        Returns:
            tuple: (modèle_entraîné, X_test, y_test)
        """
        print("Début de l'optimisation du modèle ...")
        from copy import deepcopy

        X_train, X_test, y_train, y_test = split_data(self.X, self.y, self.random_state)
        X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.1,
                                                          random_state=self.random_state)

        # Entraînement initial
        print("\n🔄 Entraînement du modèle ...")
        clone_ = deepcopy(self.model) or self.model

        try:
            if not already_fit:
                model_initial = self.fit(clone_, X_train, y_train)
            else:
                model_initial = self.model

            if save_func:
                func = save_func['fonction']
                if 'filename' in save_func:
                    file = save_func['filename']
                    func(model_initial, file)
                else:
                    func(model_initial)
        except Exception as e:
            print(f"[run] Erreur dans le fitting : {type(e).__name__} : {e}")
            print("Détails : \n ", traceback.format_exc())
            return

        self.model_ = model_initial

        # Évaluation
        print("\n📊 Évaluation du modèle ...")
        try:
            self.evaluate(model_initial, X_train, y_train, X_val, y_val, label='initial')
        except Exception as e:
            print(f"[run] Erreur dans l'évaluation du modèle : {type(e).__name__} : {e}")
            print("Détails : \n ", traceback.format_exc())
            return

        if _all_:
            # Courbe d'apprentissage
            print("\n📈 Courbe d'apprentissage...")
            try:
                self.plot_learning_curve(model_initial, X_train, y_train, label='initial')
            except Exception as e:
                print(f"[run] Erreur dans le learning curve : {type(e).__name__} : {e}")
                print("Détails : \n ", traceback.format_exc())

            # Importance des features
            if features:
                print("\n🔍 Calcul de l'importance des features...")
                try:
                    self.feature_importance(model_initial, X_train, y_train,
                                            label='initial', threshold=threshold)
                except Exception as e:
                    print(f"[run] Erreur dans le calcul de l'importance des features : "
                          f"{type(e).__name__} : {e}")
                    print("Détails : \n ", traceback.format_exc())

        return self.model_, X_test, y_test


if __name__ == '__main__':
    from sklearn.datasets import make_classification, make_multilabel_classification
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from anti_phishing_ia.ml_model.modelstack import ModelStack
    from sklearn.multioutput import MultiOutputClassifier as M
    from tqdm import tqdm

    sc = StandardScaler()
    X, y = make_classification(n_samples=10000, n_features=10, random_state=42)
    X = sc.fit_transform(X)
    fn = [f"feature_{i}" for i in range(10)]

    lg = LogisticRegression(max_iter=1000)
    rf = RandomForestClassifier(n_estimators=300, random_state=42)

    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    sys.path.append("/home/hounsousamuel/PROJET")

    model = ModelOptimization(model=lg, X=X, y=y, random_state=42,
                              scoring='accuracy', save_dir="test_result",
                              cv=2, features_name=fn)

    for i in tqdm(range(1), desc="Lancement essai..."):
        model_, x_, y_ = model.run(1e-5)

    import joblib
    joblib.dump(model_, 'model_test.joblib')
    print('\n Score du modèle sur données de test :\n ', model_.score(x_, y_))