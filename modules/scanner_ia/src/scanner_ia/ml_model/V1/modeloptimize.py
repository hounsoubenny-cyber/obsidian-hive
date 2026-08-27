#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov  4 15:49:41 2025

@author: hounsousamuel
"""


import os,sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from sklearn.base import clone
from sklearn.model_selection import train_test_split,cross_validate,learning_curve
from sklearn.inspection import permutation_importance
from sklearn.metrics import (f1_score,accuracy_score,precision_score,recall_score,hamming_loss,
                             jaccard_score,confusion_matrix,multilabel_confusion_matrix,
                             classification_report, roc_auc_score)
import numpy as np, traceback
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
pd.set_option("display.max_row",111)
pd.set_option("display.max_columns",111)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))

_dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(_dir_, exist_ok=True)


def _compute_metrics(y_true, y_pred, y_pred_proba=None, prefix=''):
    """Calcule toutes les métriques détaillées de façon centralisée avec gestion robuste des erreurs"""
    metrics = {}

    try:
        # Conversion robuste des arrays
        y_true = np.asarray(y_true)
        y_pred = np.asarray(y_pred)

        # Vérification des dimensions cohérentes
        if y_true.shape != y_pred.shape:
            raise ValueError(f"Dimensions incohérentes: y_true {y_true.shape}, y_pred {y_pred.shape}")

        # Éviter les métriques samples pour les problèmes non-multilabel
        is_multilabel = y_true.ndim == 2 and y_true.shape[1] > 1
        is_binary = not is_multilabel and len(np.unique(y_true)) == 2

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

        try:
            metrics[f'{prefix}hamming_loss'] = hamming_loss(y_true, y_pred)
        except Exception as e:
            metrics[f'{prefix}hamming_loss'] = np.nan
            print(f"Erreur hamming_loss: {e}")

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

        # ROC-AUC Scores - AVEC GESTION ROBUSTE
        try:
            if y_pred_proba is not None:
                y_pred_proba = np.asarray(y_pred_proba)

                # ROC-AUC pour classification binaire
                if is_binary and y_pred_proba.ndim == 1:
                    metrics[f'{prefix}roc_auc'] = roc_auc_score(y_true, y_pred_proba)
                # ROC-AUC pour classification binaire (format 2 colonnes)
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
                        metrics[f'{prefix}roc_auc_ovr'] = roc_auc_score(y_true, y_pred_proba, multi_class='ovr', average='macro')
                    except Exception as e:
                        metrics[f'{prefix}roc_auc_ovr'] = np.nan
                        print(f"Erreur roc_auc_ovr: {e}")

                    try:
                        metrics[f'{prefix}roc_auc_ovo'] = roc_auc_score(y_true, y_pred_proba, multi_class='ovo', average='macro')
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
            # S'assurer que toutes les métriques ROC-AUC sont NaN en cas d'erreur générale
            roc_metrics = ['roc_auc', 'roc_auc_micro', 'roc_auc_macro', 'roc_auc_weighted', 'roc_auc_ovr', 'roc_auc_ovo']
            for roc_metric in roc_metrics:
                metrics[f'{prefix}{roc_metric}'] = np.nan

    except Exception as e:
        print(f"Erreur critique dans _compute_metrics {prefix}: {e}")
        # Initialiser toutes les métriques à NaN en cas d'erreur critique
        base_metrics = [
            'f1_weighted', 'f1_micro', 'f1_macro', 'f1_samples',
            'accuracy_score', 'precision_macro', 'recall_macro', 'recall_micro',
            'hamming_loss', 'jaccard_micro', 'jaccard_macro', 'jaccard_weighted', 'jaccard_samples'
        ]
        roc_metrics = ['roc_auc', 'roc_auc_micro', 'roc_auc_macro', 'roc_auc_weighted', 'roc_auc_ovr', 'roc_auc_ovo']

        for metric in base_metrics + roc_metrics:
            metrics[f'{prefix}{metric}'] = np.nan

    return metrics


def compute_metrics_safe(y_true, y_pred, y_pred_proba=None, prefix=''):
    """Version simplifiée avec gestion d'erreurs pour usage rapide"""
    try:
        return _compute_metrics(y_true, y_pred, y_pred_proba, prefix)
    except Exception as e:
        print(f"Erreur fatale dans compute_metrics_safe: {e}")
        return {f'{prefix}error': str(e)}


def split_data(X,y,random_state=42):
    X,y = np.asarray(X),np.asarray(y)
    if X is not None and y is not None:
        X,y = np.asarray(X),np.asarray(y)
        n_samples = len(X)
        n_classes = len(np.unique(y, axis=0))

        # Calculer le test_size minimum pour la stratification
        min_test_samples = n_classes
        min_test_size = min_test_samples / n_samples

        # Choisir le plus grand entre 0.2 et le minimum requis
        test_size = max(0.2, min_test_size + 0.05)  # +0.05 pour une marge

        # Si le dataset est trop petit, désactiver la stratification
        if test_size >= 0.5 or n_samples < 10:
            print(f"⚠️ Dataset trop petit ({n_samples} échantillons). Stratification désactivée.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=random_state
                )
        else:
            print(f"✅ Utilisation de test_size={test_size:.2f} pour {n_samples} échantillons.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=random_state
            )

        return X_train, X_test, y_train, y_test
    else:
        print(X, y)
        # input()
        raise ValueError("Données vides(SPLIT_DATA)")



class ModelOptimization :
    def __init__(self,model,X,y,random_state,scoring=[],save_dir="results0",features_name=[],dir=_dir_,cv=2) :
        X, y = np.asarray(X), np.asarray(y)
        self.model = model
        self.random_state = random_state
        self.X = np.asarray(X)
        self.y = np.asarray(y)
        self.model_ = None
        self.features_names = features_name
        self.n_features = X.shape[1]
        self.scoring = scoring or ['f1_macro', 'accuracy','precision', 'recall']
        self.cv = cv
        self.results = {}
        self.save_dir = os.path.join(_dir_,"results_optimization",save_dir)
        os.makedirs(self.save_dir, exist_ok=True)
        print(f"ModelOptimization initialisée avec {self.n_features} features, sauvegarde des resultats dans le dossier {self.save_dir}")

    def _apply_mask(self,X,mask):
        if mask is not None :
            if isinstance(X,pd.DataFrame) :
                X = X.loc[:,mask]
            elif isinstance(X,np.ndarray):
                X = X[:,mask]
            else :
                raise ValueError("X doit etre un DataFrame ou un ndarray")
        return X

    def fit(self,model,X,y) :
        model.fit(X,y)
        return model

    def matrix_and_report(self,model,X_test,y_test,from_='ModelOptimize sur Échantillon de X_train et y_train réel'):
        to_print = 'Matrix de confusion multilabel et classification report'
        print('\n', '='*50)
        print(to_print)
        print(from_)
        print('='*50)
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
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',xticklabels=['Négatif', 'Positif'],yticklabels=['Négatif', 'Positif'])
                plt.title('Matrice de Confusion')
                plt.xlabel('Prédit')
                plt.ylabel('Réel')
            plt.tight_layout()
            plt.show(block=False)
            plt.savefig(os.path.join(self.save_dir,f'confusion_matrix.png'))
            print(f'confusion_matrix saved savegardeée dans {os.path.join(self.save_dir,f"confusion_matrix.png")}')

        except Exception as e:
            print(f"Erreur dans la visualisation de la matrice de confusion : {e}")
            cm = confusion_matrix(y_test, y_pred)  # Fallback simple

        cr = classification_report(y_test, y_pred)
        print(f"Score du modèle sur les données de test : {sc:.4f}")
        print("\nClassification report : \n", cr)
        print('Confusion matrix : \n', cm)

        return sc, cr, cm


    def _compute_detailed_metrics(self, y_true, y_pred, prefix=''):
        """Calcule toutes les métriques détaillées de façon centralisée"""
        return _compute_metrics(y_true, y_pred,prefix=prefix)



    def evaluate(self, model, X_train, y_train, X_val, y_val, label='initial'):
        """Evaluation du model en utilisant sklearn.cross_validate"""
        print(f"Evaluations ({label}) ...")
        try:
            print("Score du modèle sur les données de validation : ", model.score(X_val, y_val))
        except Exception:
            print("Score du modèle sur les données de validation : ", accuracy_score(y_val, model.predict(X_val)))
            pass

        try:
            res = cross_validate(model, X_train, y_train, scoring=self.scoring, cv=self.cv,
                                n_jobs=2, return_train_score=True,error_score='raise')
            df = pd.DataFrame(res)
            df.loc['mean'] = df.mean()
            df.to_csv(os.path.join(self.save_dir, f'evaluation_{label}.csv'), index=True)
            self.results[label] = df
            print(f'✅ Evaluation sauvegardée dans {os.path.join(self.save_dir, f"evaluation_{label}.csv")}')
            print('Dataframe des résultats de cross_validate : \n', df)
        except Exception as e:
            print(f"❌ Erreur lors de la cross-validation: {e}")
            print("Détails : \n ",traceback.format_exc())
            df = pd.DataFrame()
            self.results[label] = df

        try:
            y_train_pred = model.predict(X_train)
            y_val_pred = model.predict(X_val)

            train_metrics = self._compute_detailed_metrics(y_train, y_train_pred, '')
            val_metrics = self._compute_detailed_metrics(y_val, y_val_pred, '')

            #DataFrame
            metrics_df = pd.DataFrame([train_metrics, val_metrics], index=['Train', 'Validation'])
            metrics_df.index.name = "Étape"
            metrics_df = metrics_df.dropna(axis=1)
            # Calcul du gap
            metrics_df.loc['gap'] = metrics_df.loc['Train'] - metrics_df.loc['Validation']

            def classify_gap(metric_name, gap_value):
                # Pour hamming_loss, on inverse la logique
                if 'hamming_loss' in metric_name:
                    # Pour hamming_loss, on veut que le score soit bas
                    # Donc un gap négatif signifie que train est meilleur (plus bas)
                    effective_gap = -gap_value  # On inverse pour la classification
                else:
                    # Pour les autres métriques, on veut des scores hauts
                    effective_gap = gap_value

                # Classification basée sur la valeur absolue
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
            if  not metrics_df.empty :
                metrics_df.to_csv(os.path.join(self.save_dir, f'evaluation_detailed_{label}.csv'), index=True)
                print(f'Évaluation détaillée sauvegardée dans {os.path.join(self.save_dir, f"evaluation_detailed_{label}.csv")}')
                print(f"Métriques détaillées : \n {metrics_df}")

            self.matrix_and_report(model,X_val,y_val)

            return df, metrics_df

        except Exception as e:
            print(f"Erreur dans le calcul approfondi des métriques d'évaluation : {e}")
            traceback.print_exc()
            return df, pd.DataFrame([])


    def plot_learning_curve(self,model,X,y,label='initial') :
        """ Trace la courbe d'apprentissage en utilisant sklearn.learning_curve """
        try:
            train_sizes, train_scores, test_scores = learning_curve(model, X, y, cv=self.cv, scoring='f1_macro', n_jobs=2, train_sizes=np.linspace(0.2, 1.0, 5),error_score='raise')
        except Exception as e:
            print(f"[plot_learning_curve] Erreur au niveau de leaning curve : {type(e).__name__} : e")
            print("Détails : \n ",traceback.format_exc())
            return
        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        gap_values = train_scores_mean - test_scores_mean
        gap = train_scores_mean[-1] - test_scores_mean[-1]  #Pour prendre le dataset total (train_sizes=100%)
        plt.figure(figsize=(20, 10))
        plt.subplot(2,2,1)
        plt.title('Learning Curve ({label})')
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

        plt.savefig(os.path.join(self.save_dir,f'learning_curve_{label}.png'))
        print(f'Learning curve saved to {os.path.join(self.save_dir,f"learning_curve_{label}.png")}')
        print('='*60)
        print(f'Score train final : {train_scores_mean[-1]}')
        print(f'Score val final : {test_scores_mean[-1]}')
        print(f"Gap final : {gap} ({gap*100}%)")
        if gap > 0.1 :
            print("[ALERTE] Overfiting détecté ! \n Le modèle performe plus sur train que validation. Vous pouvez essayer de réduire la complxité du modèle.")
        elif gap > 0.05:
            print("Ovverfiting léger. Gap acceptable mais peut être amélioré")
        else :
            print('Pas d\'overfitting détecté. Le modèle généralise bien !')
        plt.tight_layout()
        plt.show(block=False)

    def feature_importance(self,model,X,y,label='initial',threshold=None) :
        """ Calcul des importances des features en utilisant la permutation importance de sklearn """

        original_idx = np.arange(self.n_features)

        print(f"Calcul des importances des features pour {label} ...")

        result = permutation_importance(model, X, y, n_repeats=10, random_state=self.random_state, n_jobs=-1)
        importances_mean = result.importances_mean
        importances_std = result.importances_std
        indices = np.argsort(importances_mean)[::-1]
        df = pd.DataFrame({
            'features' : np.array(self.features_names)[original_idx],
             "indices": original_idx,
            "importances_mean" : importances_mean,
            "importances_std" : importances_std
        }).sort_values(by='importances_mean',ascending=False)

        mean_imp = df['importances_mean'].mean()
        std_imp = df["importances_std"].mean()
        quantile = df['importances_mean'].quantile(0.7)
        threshold = threshold or max(quantile, mean_imp + 0.5 * std_imp)
        print(f'Selection des features avec un seuil de {threshold} ...')
        mask = df['importances_mean'].to_numpy() < threshold
        featues_prob = df['features'].to_numpy()[mask]
        if featues_prob.any():
            print("Features problématiques : ")
            for lab in featues_prob:
                print("-",lab)

        df.to_csv(os.path.join(self.save_dir,f'feature_importance_{label}.csv'),index=False)
        print(f'Feature importances sauvegarder dans {os.path.join(self.save_dir,f"feature_importance_{label}.csv")}')
        print(df)
        plt.figure(figsize=(20, 10))
        plt.subplot(1,2,1)
        plt.title(f'Permutation Feature Importances ({label})')
        plt.plot(indices, importances_mean[indices], 'o',label='Importances Moyennes',color='r')
        plt.plot(indices, importances_std[indices], 'o',label='Importances Std',color='g')
        plt.xlabel('Indices des features')
        plt.ylabel('Importance')
        plt.legend()

        plt.subplot(1,2,2)
        plt.title(f'Permutation Feature Importances ({label})')
        plt.plot(indices, importances_mean[indices], 'o-',label='Importances Moyennes',color='r')
        plt.plot(indices, importances_std[indices], 'o-',label='Importances Std',color='g')
        plt.xlabel('Indices des features')
        plt.ylabel('Importance')
        plt.legend()

        plt.savefig(os.path.join(self.save_dir,f'feature_importance_{label}.png'))
        print(f'Feature importance plot saved to {os.path.join(self.save_dir,f"feature_importance_{label}.png")}')
        plt.show(block=False)

        return df

    def features_selection(self,df_importance) :
        """ Selection des features en fonction d'un seuil d'importance. df_importance est le dataframe retourné par feature_importance """

        mean_imp = df_importance['importances_mean'].mean()
        std_imp = df_importance["importances_std"].mean()
        quantile = df_importance['importances_mean'].quantile(0.7)
        threshold = max(quantile, mean_imp + 0.5 * std_imp)
        print(f'Selection des features avec un seuil de {threshold} ...')
        mask = df_importance['importances_mean'] > threshold
        full_mask = np.zeros(self.n_features,dtype=bool)
        if not mask.any() :
            print(f'Aucune feature ne dépasse le seuil, ajustement du seuil à {threshold}')
            indices_sorted = np.argsort(df_importance['importances_mean'].values)[::-1]
            top75 = max(int(len(indices_sorted)*0.75),1)
            top_indices = indices_sorted[:top75]
            full_mask[df_importance['indices'].values[top_indices]] = True

        else :
            print(f'Features selectionnées : {mask.sum()} , avec  threshold {threshold}')
            full_mask[df_importance['indices'].values] = mask.values

        if full_mask.sum() < self.min_features :
            print(f'Nombre de features selectionnées {full_mask.sum()} inférieur au minimum requis {self.min_features}, ajustement du seuil.')
            sorted_indices = np.argsort(df_importance['importances_mean'].values)[::-1]
            selected_indices = sorted_indices[:self.min_features]
            full_mask = np.zeros(self.n_features,dtype=bool)
            full_mask[selected_indices] = True
            print(f'Features selectionnées ajustées : {full_mask.sum()}')
        print(f'Finalement {full_mask.sum()} features selectionnées sur {self.n_features}')
        return full_mask

    def compare(self) :
        """Produit un dataframe comparant les resultats des differentes evaluations"""
        keys = list(self.results.keys())[:2] # Comparer seulement les deux premiers
        if len(keys) < 2 :
            print("Pas assez de resultats pour comparer.")
            return None
        df_0 = self.results[keys[0]].loc['mean']
        df_1 = self.results[keys[1]].loc['mean']
        comparison = pd.DataFrame({
            'Metric' : df_0.index,
            keys[0] : df_0.values,
            keys[1] : df_1.values,
            'Difference' : df_1.values - df_0.values
        })
        comparison.to_csv(os.path.join(self.save_dir,'comparison_results.csv'),index=True)
        print(f'Résultats de comparaison sauvegardées dans {os.path.join(self.save_dir,"comparison_results.csv")}')
        print("Comparaison des deux premiers resultas des Evaluations \n",comparison)
        return comparison

    def run(self,threshold=None,save_func=None,already_fit=False, _all_=True, features_imp = False) :
        """ Execution de l'optimisation du model """
        print("Début de l'optimisation du model ...")
        from copy import deepcopy

        X_train, X_test, y_train, y_test = split_data(self.X,self.y,self.random_state)
        X_train,X_val,y_train,y_val = train_test_split(X_train,y_train,test_size=0.1,random_state=self.random_state)
        # Entraînement initial
        print("\n🔄 Entraînement du modèle ...")
        clone_ = deepcopy(self.model) or self.model
        try:
            if not already_fit:
                model_initial = self.fit(clone_, X_train, y_train)
            else :
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
            print("Détails : \n ",traceback.format_exc())
            return None, None, None
        self.model_ = model_initial

        print("\n📊 Évaluation du modèle ...")
        try:
            self.evaluate(model_initial, X_train, y_train,X_val,y_val,label='initial')
        except Exception as e:
            print(f"[run] Erreur dans l'évaluation du modèle : {type(e).__name__} : {e}")
            print("Détails : \n ",traceback.format_exc())
            return 
        if _all_:
            print("\n📈 Courbe d'apprentissage...")
            try:
                self.plot_learning_curve(model_initial, X_train, y_train, label='initial')
            except Exception as e:
                print(f"[run] Erreur dans le learning curve : {type(e).__name__} : {e}")
                print("Détails : \n ",traceback.format_exc())
                return

            if features_imp:
                print("\n🔍 Calcul de l'importance des features...")
                try:
                    self.feature_importance(model_initial, X_train, y_train, label='initial',threshold=threshold)
                except Exception as e:
                    print(f"[run] Erreur dans le calcul de l'importance des features : {type(e).__name__} : {e}")
                    print("Détails : \n ",traceback.format_exc())
                    return 

        return self.model_, X_test, y_test

if __name__ == '__main__':
    from sklearn.datasets import make_classification,make_multilabel_classification
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from scanner.ml_model.modelstack import ModelStack
    from sklearn.multioutput import MultiOutputClassifier as M
    from tqdm import tqdm
    
    sc = StandardScaler()
    X,y = make_classification(n_samples=10000,n_features=10,random_state=42)
    X = sc.fit_transform(X)
    fn = [f"feature_{i}" for i in range(10)]
    lg = LogisticRegression(max_iter=1000)
    rf= RandomForestClassifier(n_estimators=300,random_state=42)
    model = ModelOptimization(model=lg, X=X, y=y, random_state=42,scoring='accuracy',save_dir="test_result"
                              ,cv=2,features_name=fn)
    for i in tqdm(range(1),desc="Lancement essai..."):
        model_,x_,y_ = model.run(1e-5)
    import joblib
    joblib.dump(model_,'model_test.joblib')
    print('\n Score du model sur données de test :\n ',model_.score(x_,y_))


    
