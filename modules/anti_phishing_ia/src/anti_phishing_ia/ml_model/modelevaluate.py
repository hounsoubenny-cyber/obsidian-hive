#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Oct 28 09:10:03 2025

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from anti_phishing_ia.ml_model.modeloptimize import ModelOptimization
from anti_phishing_ia.ml_model.phishing_ia import PhishingIA
import numpy as np, pandas as pd
import warnings
warnings.filterwarnings('ignore')
pd.set_option("display.max_row",111)
pd.set_option("display.max_columns",111)

import os, traceback, joblib, dill
from sklearn.model_selection import train_test_split

class ModelEvaluate(ModelOptimization):
    def __init__(self,model,X,y,random_state,scoring=None,save_dir="results1",features_name=None,dir=dir,cv=2) :
        features_name = features_name or []
        scoring = scoring or []
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
        # os.makedirs(self.save_dir, exist_ok=True)
        self.ModelOptimization = ModelOptimization(model,X,y,random_state,scoring,save_dir,features_name,cv=cv)
        print(f"ModelEvaluate initialisée avec {self.n_features} features, sauvegarde des resultats dans le dossier {self.ModelOptimization.save_dir}")


    def run(self,threshold=None,save_func=None,already_fit=False) :
        """ Execution de l'optimisation du model """
        print("Début de l'évaluation du model ...")
        from copy import deepcopy

        X_train,X_val,y_train,y_val = train_test_split(self.X,self.y,test_size=0.1,random_state=self.random_state)
        # Entraînement initial
        print("\n🔄 Entraînement du modèle ...")
        clone_ = deepcopy(self.model) or self.model
        try:
            if not already_fit:
                model_initial = self.ModelOptimization.fit(clone_, X_train, y_train)
            else:
                model_initial =  clone_
            if save_func:
                func = save_func['fonction']
                if 'filename' in save_func:
                    file = save_func['filename']
                    func(model_initial,file)
                else:
                    func(model_initial)
        except Exception as e:
            print(f"[run] Erreur dans le fitting : {type(e).__name__} : {e}")
            print("Détails : \n ",traceback.format_exc())
            return
        self.model_ = model_initial

        print("\n📊 Évaluation du modèle ...")
        try:
            self.ModelOptimization.evaluate(model_initial, X_train, y_train,X_val,y_val,label='evaluation')
        except Exception as e:
            print(f"[run] Erreur dans l'évaluation du modèle : {type(e).__name__} : {e}")
            print("Détails : \n ",traceback.format_exc())
            return

        print("\n📈 Courbe d'apprentissage...")
        try:
            self.ModelOptimization.plot_learning_curve(model_initial, X_train, y_train, label='evaluation')
        except Exception as e:
            print(f"[run] Erreur dans le learning curve : {type(e).__name__} : {e}")
            print("Détails : \n ",traceback.format_exc())
            return

        print("\n🔍 Calcul de l'importance des features...")
        try:
            self.feature_importance(model_initial, X_train, y_train, label='initial',threshold=threshold)
        except Exception as e:
            print(f"[run] Erreur dans le calcul de l'importance des features : {type(e).__name__} : {e}")
            print("Détails : \n ",traceback.format_exc())
            return

        return self.model_

if __name__ == '__main__':
    dir_ = "/home/hounsousamuel/PROJET/anti_phishing/ml_model/data/datasets/dataset2.pkl"
    dir_2 = '//home/hounsousamuel/PROJET/anti_phishing/ml_model/dataset_test_df6.pkl'
    dir_1 = "/home/hounsousamuel/PROJET/anti_phishing/ml_model/data/models/model6/model_phish.pkl"
    # inp = input('Choississeze votre dir (dir_,dir_2) : ').strip()
    inp = dir_
    df = joblib.load(dir_) if inp == dir_ else joblib.load(dir_2)
    data = pd.DataFrame(df)
    X = data.drop(['url'],axis=1) if inp == dir_ else data
    print(X)
    X = X.drop(['label'],axis=1)
    y = data["label"]
    shape = X.shape
    batch = 10000 #if inp == dir_ else 100
    try:
        data_mod = PhishingIA()
        data_mod.load_model(dir_1)
        # print(data_mod)
        # input()
    except Exception:
        try:
            data_mod = joblib.load(dir_1)
            # print(data_mod)
            # input()
        except Exception:
            with open(dir_1,'rb') as f:
                data_mod = dill.load(f)
                # print(data_mod)
                # input()
    print(data_mod)
    input()
    model = data_mod.model
    le = data_mod.le
    names = data_mod.features_name
    print(names == list(X.columns))
    print(le, names, len(names))
    print([f for f in names if f not in X.columns])
    print(shape)
    input()
    for i in range(batch,shape[0],batch):
        print('='*60)
        X_, y_ = X.iloc[:i,:], le.transform(y.iloc[:i])
        eval_ = ModelEvaluate(model, X_, y_, random_state=42,features_name=names)
        eval_.run(already_fit=True)
        print('='*60)
        if i == batch:
            input()
