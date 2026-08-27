#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct 12 18:15:01 2025

@author: hounsousamuel
"""
import os, sys
from sklearn.metrics import precision_score, recall_score, accuracy_score, precision_recall_curve
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
import matplotlib.pyplot as plt
from sklearn.utils.validation import check_is_fitted
import time
from scanner.ml_model.modeloptimize import _compute_metrics
import pandas as pd
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Supprime logs TensorFlow
import tensorflow as tf

# Supprime les logs et warnings
tf.get_logger().setLevel('ERROR')
import warnings
warnings.filterwarnings('ignore')
import json


dir_ = os.path.dirname(os.path.abspath(__file__))
dir_ = os.path.join(dir_,'seuils')
os.makedirs(dir_,exist_ok=True)

class ThresholdTunning :

    """
   Optimise automatiquement les seuils de décision pour chaque label

   Supporte :
   - Binary classification : ✅
   - Multi-class : ⚠️ Skip (argmax est déjà optimal)
   - Multi-label : ✅✅ (optimise chaque label indépendamment)
   """

    def __init__(
            self, model,
            X, y,
            recall_micro=0.25,
            recall_macro=0.3,
            precision_micro=0.2,
            precision_macro=0.25,
            space=(0.2,0.8,800)
        ):

        """
        Parameters
        ----------
        model : (ml/dl)
            Model entrainé.
        X : array
            DESCRIPTION.
        y : array
            DESCRIPTION.
        recall_micro : float, optional
            Importance du recall_micro. The default is 0.25.
        recall_macro : float, optional
            importance du recall_macro. The default is 0.3.
        precision_micro : float, optional
            Importance de la precision_micro. The default is 0.2.
        precision_macro : float, optional
            Importance de la precision_macro. The default is 0.25.
        space : tuple, optional
            Espace de recherche du seuil. The default is (0.2,0.8,800).

        Raises
        ------
        ValueError
            Si les données de validatins X et y sont vides(ne contiennent pas au moins un élément vrai.

        Returns
        -------
        None.

        """
        X = np.asarray(X)
        y = np.asarray(y)
        if not X.size > 0 or not y.size > 0 :
            raise ValueError('Données vides ')
        if any(i == 0 for i in (recall_micro,recall_macro,precision_macro,precision_micro)) :
            raise ValueError('Veuillez entrer des valeurs non nuls.')
        total = recall_micro + recall_macro + precision_micro + precision_macro
        self.recall_micro = recall_micro / total
        self.recall_macro = recall_macro / total
        self.precision_micro = precision_micro / total
        self.precision_macro = precision_macro / total
        self.space = space
        self.model = model
        self.X = X
        self.y = y
        self.optimal_score = []
        self.optimal_seuil = None
        self.default_seuil = 0.5
        self.metrics = {}

    def fit(self,verbose=False):
        """
        Parameters
        ----------
        verbose : bool, optional
            Paramètre pour suivre l'évolution. The default is False.

        Raises
        ------
        ValueError
            Si il y a des problèmes de mdimensions.

        Returns
        -------
        ThresholdTunning
            Modèle fitté.

        """
        print("[INFO]Recherche du meilleur seuil ...")
        X_copy,y_copy = self.X.copy(), self.y.copy()
        if not hasattr(self.model,"predict_proba"):
            print("[INFO] Votre modèle ne dispose pas de predict_proba(), utilisation de predict()")
            y_preds_proba = np.asarray(self.model.predict(X_copy).astype(float))
        else:
            y_preds_proba = np.asarray(self.model.predict_proba(X_copy))
        y_pred_def = np.asarray(self.model.predict(X_copy))
        if y_copy.ndim == 1:
            n_unique = np.unique(y_copy)
            if len(n_unique) == 2:
                print("[INFO] Problème BINAIRE détecté.")
                y_copy = y_copy.reshape(-1,1)
                y_pred_def = y_pred_def.reshape(-1,1)
                if y_preds_proba.ndim == 2 and y_preds_proba.shape[1] == 2:
                    y_preds_proba = y_preds_proba[:, 1].reshape(-1, 1)
                else:
                    y_preds_proba = y_preds_proba.reshape(-1, 1)

            elif len(n_unique) > 2:
                print("[INFO] Prblème MULTI-CLASSE détecté. On skip.")
                self.optimal_seuil = np.array([0.5] * len(n_unique))
                self.n_labels = 1
                self.metrics = {}
                return self
            else :
                raise ValueError(f"Problème avec y ({len(n_unique)}) classes")
        elif y_copy.ndim == 2:
            print("[INFO] Problème MULTI-LABEL détecté... ")
            if y_preds_proba.shape[1] != y_copy.shape[1]:
                raise ValueError(f"Imcompatibilité des dimensions entre y_probas et y ({y_preds_proba.shape[1]} vs {y_copy.shape[1]})")
        else:
            raise ValueError(f"y doit être 1D ou 2D, reçu shape {y_copy.shape}")

        self.n_labels = y_copy.shape[1]
        search_space = np.linspace(self.space[0], self.space[1],self.space[2])
        self.optimal_seuil = []
        for label_idx in range(self.n_labels):
            start = time.time()
            print(f"  \n Label {label_idx}...", end=" ")
            self.metrics[f"{int(label_idx)}"] = {'seuil' : [],'score':[]}
            best_score = -np.inf
            best_seuil = self.default_seuil
            best_metrics = {}
            for seuil in search_space:
                self.metrics[f"{int(label_idx)}"]['seuil'].append(seuil)
                rmio = recall_score(y_copy[:,label_idx], y_pred_def[:,label_idx], average='micro', zero_division=0)
                y_pred = (y_preds_proba[:,label_idx] >= seuil).astype(int)
                rmi = recall_score(y_copy[:,label_idx],y_pred,average='micro',zero_division=0)
                rma = recall_score(y_copy[:,label_idx],y_pred,average='macro',zero_division=0)
                pmi = precision_score(y_copy[:,label_idx],y_pred,average='micro',zero_division=0)
                pma = precision_score(y_copy[:,label_idx],y_pred,average='macro',zero_division=0)
                #score = (rmi*self.recall_micro) + (rma * self.recall_macro) + (pmi * self.precision_micro) + (pma * self.precision_macro)
                score = (rmi*self.recall_micro) + (rma * self.recall_macro)
                self.metrics[f"{int(label_idx)}"]['score'].append(score)
                if verbose :
                    print("Seuil : ",seuil)
                    print("\n Score : ",score)
                    print("\n Recall_macro : ",rma)
                    print("\n Recall_micro : ",rmi)
                    print("\n Precision_micro : ",pma)
                    print("\n Precision_macro : ",pmi)

                if score > best_score:
                    best_score = score
                    if rmi >= rmio:
                        print("OK")
                        print('Original : ',rmio,'Refité : ',rmi)
                        best_seuil = seuil
                    else:
                        print('Pas bon')
                        best_seuil = 0.5
                    print(best_seuil)
                    best_metrics = {
                        'recall_micro' : (rmi,self.recall_micro),
                        'recall_macro' : (rma,self.recall_macro),
                        'precision_macro' : (pma,self.precision_macro),
                        'precision_micro' : (pmi,self.precision_micro),
                        'score' : score
                        }
            elapsed = time.time() - start
            print(f"Fin pour label {label_idx} en {elapsed :.2f} secondes (score = {best_score} et un seuil de {best_seuil}).\n")
            print("Métrics : \n ")
            try :
                print(json.dumps(best_metrics,indent=2,ensure_ascii=False))
            except :
                print(best_metrics)
            print()
            self.optimal_seuil.append(best_seuil)
            self.optimal_score.append(best_score)
        self.optimal_seuil = np.array(self.optimal_seuil)
        print('\n ✅ Seuils optimisés : ',self.optimal_seuil.tolist())
        return self

    def fit_pareto(self, verbose=False):
        """
        Parameters
        ----------
        verbose : bool, optional
            Paramètre pour suivre l'évolution. The default is False.

        Raises
        ------
        ValueError
            Si il y a des problèmes de mdimensions.

        Returns
        -------
        ThresholdTunning
            Modèle fitté.

        """
        print("[INFO]Recherche du meilleur seuil(Pareto) ...")
        X_copy,y_copy = self.X.copy(), self.y.copy()
        if not hasattr(self.model,"predict_proba"):
            print("[INFO] Votre modèle ne dispose pas de predict_proba(), utilisation de predict()")
            y_preds_proba = np.asarray(self.model.predict(X_copy).astype(float))
        else:
            y_preds_proba = np.asarray(self.model.predict_proba(X_copy))
        y_pred_def = np.asarray(self.model.predict(X_copy))
        if y_copy.ndim == 1:
            n_unique = np.unique(y_copy)
            if len(n_unique) == 2:
                print("[INFO] Problème BINAIRE détecté.")
                y_copy = y_copy.reshape(-1,1)
                y_pred_def = y_pred_def.reshape(-1,1)
                if y_preds_proba.ndim == 2 and y_preds_proba.shape[1] == 2:
                    y_preds_proba = y_preds_proba[:, 1].reshape(-1, 1)
                else:
                    y_preds_proba = y_preds_proba.reshape(-1, 1)

            elif len(n_unique) > 2:
                print("[INFO] Prblème MULTI-CLASSE détecté. On skip.")
                self.optimal_seuil = np.array([0.5] * len(n_unique))
                self.n_labels = 1
                self.metrics = {}
                return self
            else :
                raise ValueError(f"Problème avec y ({len(n_unique)}) classes")
        elif y_copy.ndim == 2:
            print("[INFO] Problème MULTI-LABEL détecté... ")
            if y_preds_proba.shape[1] != y_copy.shape[1]:
                raise ValueError(f"Imcompatibilité des dimensions entre y_probas et y ({y_preds_proba.shape[1]} vs {y_copy.shape[1]})")
        else:
            raise ValueError(f"y doit être 1D ou 2D, reçu shape {y_copy.shape}")

        self.n_labels = y_copy.shape[1]
        search_space = np.linspace(self.space[0], self.space[1],self.space[2])
        self.optimal_seuil = []
        for label_idx in range(self.n_labels):
            start = time.time()
            print(f"  \n Label {label_idx}...", end=" ")
            self.metrics[f"{int(label_idx)}"] = {'seuil' : [],'score':[]}
            pareto_solutions = []
            for seuil in search_space:
                self.metrics[f"{int(label_idx)}"]['seuil'].append(seuil)
                rmio = recall_score(y_copy[:,label_idx], y_pred_def[:,label_idx], average='micro', zero_division=0)
                y_pred = (y_preds_proba[:,label_idx] >= seuil).astype(int)
                rma = recall_score(y_copy[:,label_idx],y_pred,average='macro',zero_division=0)
                pmi = precision_score(y_copy[:,label_idx],y_pred,average='micro',zero_division=0)
                score = (rma*self.recall_macro) + (pmi * self.precision_micro)
                self.metrics[f"{int(label_idx)}"]['score'].append(score)
                if verbose :
                    print("Seuil : ",seuil)
                    print("\n Score : ",score)
                    print("\n Recall_macro : ",rma)
                    print("\n Precision_macro : ",pmi)
                is_best = True
                for sol in pareto_solutions:
                    if (sol['recall_macro'] >= rma and sol['precision_micro'] >= pmi and
                        (sol['recall_macro'] > rma or sol['precision_micro'] > pmi)):
                        is_best = False
                        break
                if is_best :
                    #On retire toute les solution solutions dominées par la nouvelle
                    pareto_solutions = [ sol for sol in pareto_solutions if not (rma >= sol['recall_macro'] and
                                        pmi >= sol['precision_micro'] and (rma > sol['recall_macro'] or pmi > sol['precision_micro'] ))]
                    pareto_solutions.append({
                        'seuil' : seuil,
                        'recall_macro':rma,
                        'precision_micro': pmi,
                        'score' : score
                        })

            #Maintenant, si on a plusieurs solutons, trier selon une importance, ici le recall macro
            pareto_solutions = sorted(pareto_solutions, key=lambda x : x['recall_macro'], reverse=True)
            optimal_sol = pareto_solutions[0]
            self.optimal_seuil.append(optimal_sol['seuil'])
            self.optimal_score.append(optimal_sol["score"])
            elapsed = time.time() - start
            print(f"""Fin pour label {label_idx} en {elapsed :.2f}
                  secondes (score = {optimal_sol['score']} et un seuil de {optimal_sol['seuil']}).\n""")
        self.optimal_seuil = np.array(self.optimal_seuil)
        print('\n ✅ Seuils optimisés : ',self.optimal_seuil.tolist())
        return self


    def predict(self, X):
        """
        Prédictions avec les seuils optimisés.

        Parameters
        ----------
        X : array
            Donées de predictions.

        Raises
        ------
        ValueError
            Si le modèle n'est pas entriner au pealable(aucun appel à fit).

        Returns
        -------
        y_pred : array
            Résultasts de la prédictions.

        """
        if not hasattr(self.model, 'predict_proba'):
            y_proba = self.model.predict(X).astype(float)
        else:
            y_proba = self.model.predict_proba(X)
        is_binary = False
        # Gérer le cas binary avec predict_proba qui retourne (n, 2)
        if y_proba.ndim == 2 and y_proba.shape[1] == 2 and len(self.optimal_seuil) == 1:
            is_binary = True
            y_proba = y_proba[:, 1].reshape(-1, 1)

        y_pred = np.zeros_like(y_proba, dtype=int)
        for i, seuil in enumerate(self.optimal_seuil):
            y_pred[:, i] = (y_proba[:, i] >= seuil).astype(int)

        if is_binary :
            return y_pred.ravel()

        return y_pred

    def predict_proba(self, X):
        """
        Retourne les probabilités (pas affecté par les seuils).Dispo même sans aucun appel à fit.

        Parameters
        ----------
        X : array
            Données sur lequel prédire.

        Returns
        -------
        array
            Prédictions probabilistes.

        """
        if hasattr(self.model, 'predict_proba'):
            return self.model.predict_proba(X)
        else:
            return self.model.predict(X).astype(float)

    def score(self, X, y):
        """Score avec les seuils optimisés"""
        y_pred = self.predict(X)
        return accuracy_score(y, y_pred)

    def plot_seuil(self,save_path = 'seuils_optimals.png'):
        """
        Visualiser l'evolution du seuil avec matplotlib. Dispo uniquement si le modèle est déjà fitté(au moins un appel a fit)

        Parameters
        ----------
        save_path : str, optional
            Fichier de suavegarde du graphe. The default is 'seuils_optimals.png'.

        Raises
        ------
        ValueError
            Si aucun appel a fit .

        Returns
        -------
        La figure contenant les graphes.

        """
        if not self.metrics :
            raise ValueError("Appelez fit() d'abord pour trouver les seuils optimaux !")

        idxs = list(self.metrics.keys())
        n_labels = len(idxs)
        n_cols = 2
        n_rows = (n_labels + 1) // 2
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(10 * n_cols, 5 * n_rows))
        axes = axes.flatten()
        for i,idx in enumerate(idxs):
            ax = axes[i]
            ax.set_title(f'COURBES DEUS SEUILS POUR LE LABEL {idx}')
            seuils = self.metrics[f'{int(idx)}']['seuil']
            scores = self.metrics[f'{int(idx)}']['score']
            ax.plot(seuils,scores,color="blue")
            ax.scatter([self.optimal_seuil[int(idx)]], [self.optimal_score[int(idx)]],
                      color='red', s=150, zorder=5, marker='*',
                      label=f'Optimal: {self.optimal_seuil[int(idx)]:.3f}')
            ax.axvline(0.5, color='gray', linestyle='--', linewidth=1,
                      alpha=0.5, label='Défaut: 0.5')

            ax.set_title(f'Optimisation Seuil - Label {idx}',
                        fontsize=12, fontweight='bold')
            ax.set_xlabel('Seuils', fontsize=10)
            ax.set_ylabel('Score Pondéré', fontsize=10)
            ax.set_ylim(min(scores) - 0.01, max(scores) + 0.01)
            ax.legend(loc='best', fontsize=9)
            ax.grid(True, alpha=0.3)
            
        for j in range(n_labels, len(axes)):
            axes[j].axis('off')

        if save_path:
            plt.savefig(os.path.join(dir_,save_path))
            print(f"Figure sauvegardé dans {os.path.join(dir_,save_path)}")

        plt.tight_layout()
        plt.show(block=False)

        return fig


def apply_tunning(model,X_val,y_val,X_test,y_test):
    """
    Parameters
    ----------
    model : (ml/dl)
        Modelentrainé.
    X_val : array
        Pour validation du seuil.
    y_val : array
        Pour validation du seuil.
    X_test : array
        Pour comparaison des modèles.
    y_test : array
        Pour comparaison des modèles.

    Returns
    -------
    model,tunned_model.

    """
    try:
        check_is_fitted(model)
        print("Le modèle est effectivement entrainer")
    except Exception:
        print("Modèlee non fitté. Une exception sera lévée")
        raise ValueError("[apply_tunning]Modèle non fitté")

    for x in (X_val,y_val,X_test,y_test):
        x = np.asarray(x)
    if not all(x.size > 0 for x in (X_val,y_val,X_test,y_test)):
        raise ValueError("[apply_tunning]Données vides.")

    print(f"Ensemble de validation : {X_val.shape[0]} échantillons")
    tunned_model = ThresholdTunning(model, X_val, y_val,recall_macro=0.65,recall_micro=0.6,precision_macro=1e-15,precision_micro=1e-15)
    start = time.time()
    tunned_model.fit_pareto(False)
    dure = time.time() - start
    print(f"\n⏱️ Temps de tuning : {dure:.2f} secondes")
    print("\n" + "="*60)
    print("📊 COMPARAISON AVANT/APRÈS")
    print("="*60)
    y_pred_default = model.predict(X_test)
    y_pred_tunned = tunned_model.predict(X_test)
    default_metrics = _compute_metrics(y_true=y_test, y_pred=y_pred_default,prefix='')
    tunned_metrics = _compute_metrics(y_true=y_test, y_pred=y_pred_tunned,prefix='')
    data = pd.DataFrame([default_metrics,tunned_metrics],index=['Modèle initial','Modèle refité'])
    data.index.name = "Modèle"
    data.loc['Différence'] = data.loc['Modèle refité'] - data.loc["Modèle initial"]
    data.loc['Différence abosolu %'] = data.loc['Différence'].apply(lambda  x: f"{abs(x)*100 :.2f} %")
    print('DatFrame de comparaison AVANT/APRÈS : \n',data)

    try:
        tunned_model.plot_seuil('suivi_seuil.png')
    except Exception as e:
        print(f"   ⚠️ Erreur lors de la visualisation : {e}")
    print(tunned_model.optimal_seuil)

    return model,tunned_model

if __name__ == '__main__':
    from sklearn.datasets import make_multilabel_classification
    from sklearn.linear_model import LogisticRegression
    from sklearn.multiclass import OneVsRestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    pd.set_option("display.max_row",111)
    pd.set_option("display.max_columns",111)

    # Générer données multi-label
    X, y = make_multilabel_classification(
        n_samples=1000, n_features=10, n_classes=3, n_labels=2, random_state=42
    )
    X = StandardScaler().fit_transform(X)
    di = "/home/hounsousamuel/PROJET/scanner/ml_model/model_stack_nouvelle_methode_multilabel_chain1_sam.pkl"
    import dill
    with open(di,'rb') as f:
        model = dill.load(f)
    
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)
    
    print(model.predict_proba(X_train[:2,:]))
    print(model.predict(X_train[:2,:]))
    print(pd.DataFrame([_compute_metrics(y_train, model.predict(X_train)),_compute_metrics(y_test, model.predict(X_test)),_compute_metrics(y_val, model.predict(X_val))]
                       ,index=['Train','Test','Val']))
   
    tuned = ThresholdTunning(model, X_val, y_val,recall_micro=0.65,recall_macro=0.60,precision_micro=0.5,precision_macro=0.45 ,space=(0.3, 0.7, 1000))
    start = time.time()
    tuned.fit_pareto(False)
    print(f'Fine tunning terminé en : {time.time()-start:.2f}')
    # Comparer
    print("AVANT :", model.score(X_test, y_test))
    print("APRÈS :", tuned.score(X_test, y_test))
    print("SEUILS:", tuned.optimal_seuil)
    model,mt = apply_tunning(model, X_val, y_val, X_test, y_test)
    # Visualiser
    tuned.plot_seuil('mon_test.png')
    with open("model_stack_nouvelle_methode_multilabel_chain1_samtunned.pkl",'wb') as f:
        dill.dump(mt,f)
