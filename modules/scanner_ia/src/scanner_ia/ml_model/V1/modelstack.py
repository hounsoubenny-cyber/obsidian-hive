#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov  4 15:49:41 2025

@author: hounsousamuel

"""

import os, sys, time
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import pandas as pd, numpy as np
import tensorflow as tf
pd.set_option("display.max_row",111)
pd.set_option("display.max_columns",111)

tf.get_logger().setLevel('ERROR')
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from iterstrat.ml_stratifiers import MultilabelStratifiedKFold
from sklearn.calibration import CalibratedClassifierCV as CCCV
from sklearn.linear_model import LogisticRegression
from sklearn.utils import check_random_state
from sklearn.utils.validation import check_is_fitted, NotFittedError
from sklearn.preprocessing import PolynomialFeatures, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelBinarizer
from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.ensemble import (RandomForestClassifier,
                              HistGradientBoostingClassifier, 
                              StackingClassifier, 
                              BaggingClassifier, 
                              ExtraTreesClassifier)
from sklearn.neural_network import MLPClassifier
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from skopt import BayesSearchCV
from skopt.space import Real, Integer,Categorical
from sklearn.multioutput import ClassifierChain as ClassifierChainBase
from sklearn.multiclass import OneVsRestClassifier as MOP
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier,early_stopping as ES
from catboost import CatBoostClassifier
from tqdm import tqdm
from tensorflow.keras.layers import Dense,Dropout,BatchNormalization,Input
from tensorflow.keras.models import Sequential,load_model as lm
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
from scikeras.wrappers import KerasClassifier
from sklearn.metrics import accuracy_score
import traceback, copy
from joblib import Parallel, delayed
# from deepforest.scripts import 

dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)),'data')
os.makedirs(dir_, exist_ok=True)

# if "rf" in dict_of_models:
#     rf_name, rf_model = dict_of_models['rf']
#     if self.output == 'chain':
#         rf_wrapped = ClassifierChain(rf_model, order=self.order, random_state=self.random_state, chain_method='predict_proba')
#     elif self.output == 'ovr':
#         rf_wrapped = MOP(rf_model, n_jobs=2)
#     else:
#         rf_wrapped = rf_model
#     best_models['rf'] = (rf_name, rf_wrapped)

class MultiLabelStackingClassifier(BaseEstimator, ClassifierMixin):
    def __init__(
            self, estimators, 
            final_estimator, 
            cv=3, 
            passthrough=False, 
            n_jobs=None, 
            n_labels=None,
            stack_method="predict_proba",
            verbose=0
        ):
        
        self.estimators = estimators
        self.final_estimator = final_estimator
        self.cv = cv
        self.passthrough = passthrough
        self.n_jobs = n_jobs
        self.n_labels = n_labels
        self.verbose=verbose
        self.estimators_ = []
        self.named_estimators_ = {k:v for k,v in estimators }
        self.stack_method = stack_method

    def fit(self, X, y):
        if self.n_labels is None:
            self.n_labels = np.asarray(y).shape[1] if np.asarray(y).ndim == 2 else len(np.unique(y))
        self.stack_ = StackingClassifier(
            estimators=self.estimators,
            final_estimator=self.final_estimator,
            cv=self.cv,
            stack_method=self.stack_method,
            passthrough=self.passthrough,
            n_jobs=self.n_jobs,
            verbose=self.verbose
        )
        self.stack_.fit(X, y)
        self.named_estimators_ = self.stack_.named_estimators_
        self.final_estimator_ = self.stack_.final_estimator_
        self.estimators_ = [(k,v) for k,v in self.stack_.named_estimators_.items()]
        self.stack_method_ = self.stack_.stack_method
        self._label_encoder = self.stack_._label_encoder
        if hasattr(self.stack_,'classes_'):
            self.classes_ = self.stack_.classes_
        if hasattr(self.stack_,'n_features_in_'):
            self.n_features_in_ = self.stack_.n_features_in_
        else :
            self.n_features_in_ = np.asarray(X).shape[1]

        return self

    def predict(self, X):
        if not hasattr(self, 'stack_'):
           raise ValueError("Le modèle n'est pas encore entraîné. Appelez fit() d'abord.")
        return (self.predict_proba(X)>0.5).astype(int)

    def predict_proba(self, X):
        predictions = []
        for name, estimator in self.estimators_:
            try:
                proba = np.asarray(estimator.predict_proba(X))
                if proba.ndim == 2 and proba.shape[1] == 1:
                    proba = np.concatenate((1 - proba, proba), axis=1)
                predictions.append(proba)
            except Exception as e:
                print(f"Erreur avec {name}: {e}")
                traceback.format_exc()
                raise

        stacked_proba = np.hstack(predictions)
        if self.passthrough:
            stacked_proba = np.hstack([stacked_proba, X])

        return self.stack_.final_estimator_.predict_proba(stacked_proba)

    def score(self, X, y):
        if not hasattr(self, 'stack_'):
            raise ValueError("Le modèle n'est pas encore entraîné. Appelez fit() d'abord.")
        try:
            y_pred = self.predict(X)
            sc = accuracy_score(y,y_pred)
        except Exception:
            y_pred = self.predict(X)
            sc = self.stack_.score(X,y)
        return sc

    def get_params(self, deep=True):
        return {
            'estimators': self.estimators,
            'final_estimator': self.final_estimator,
            'cv': self.cv,
            'passthrough': self.passthrough,
            'n_jobs': self.n_jobs,
            'n_labels': self.n_labels,
            'stack_method': self.stack_method
        }

    def set_params(self, **params):
        for key, value in params.items():
            setattr(self, key, value)
        return self

class CustomChain(ClassifierChainBase):
    def __init__(
            self, order=None,
            cv=None, 
            chain_method='predict', 
            random_state=None, 
            verbose=False, 
            estimator=None, 
            prefit_estimators=None
        ):
        
        base_estimator = RandomForestClassifier(
                n_estimators=50,
                random_state=random_state
            )
        super().__init__(
            estimator or base_estimator,
            order=order,
            random_state=random_state,
            verbose=verbose,
            chain_method=chain_method,
            cv=cv
            )
        self.prefit_estimators = prefit_estimators
        self.estimator = estimator or base_estimator
    
    def __sklearn_clone__(self):
        """Empêche le clonage des estimateurs pré-fittés"""
        # Crée une copie SANS cloner les estimateurs pré-fittés
        cloned = self.__class__(
            order=self.order,
            cv=self.cv,
            chain_method=self.chain_method,
            random_state=self.random_state,
            verbose=self.verbose,
            estimator=self.estimator,
            prefit_estimators=self.prefit_estimators  
        )
        return cloned
    
    def fit(self, X, Y, **fit_params):
        if self.prefit_estimators is not None:
            n_labels = Y.shape[1] if hasattr(Y,'shape') else len(self.estimators_)
            if n_labels != len(self.prefit_estimators):
                raise ValueError(f"Nombre d'estimateurs ({len(self.estimators_)})")
            for i, est in enumerate(self.prefit_estimators) :
                try:
                    check_is_fitted(est)
                except NotFittedError:
                    raise ValueError(f"Estimateur {i}(type(est).__name__) doit être fitté")
            self.estimators_ = self.prefit_estimators  
            random_state = check_random_state(self.random_state)
            self.order_ = self.order
            if self.order_ is None:
                self.order_ = np.array(range(n_labels))
            elif isinstance(self.order, str):
                if self.order_ == 'random':
                    self.order_ = random_state.permutation(n_labels)

            if not hasattr(self,'chain_method_'):
                self.chain_method_ = 'predict_proba'
            self.classes_ = [est.classes_ for est in self.estimators_]

            if all(hasattr(self,'n_features_in_') for est in self.estimators_) :
                self.n_features_in_ = self.estimators_[0].n_features_in_

            print('Utilisations d\'estimateurs pré-fittés, FIT skippé avec succès')
            return self
        else:
            raise ValueError(
                'Pour utiliser cette classe il faut initialisé l\' attribut "estimators_" avec setattr '
                "Example : Utilisez set_prefit_estimators() avant fit()."
                )
    
    def get_good(self, n_feat):
        for est in self.estimators_:
            if est.n_features_in_ == n_feat:
                return est
        return None # Aucun estimator ne correspond.
            
    def predict_proba(self, X):
        X = np.asarray(X)
        X_aug = X.copy()
        preds = []
        y = np.asarray([])
        for _, label_pos in enumerate(self.order_):
            est = self.estimators_[label_pos]
            try:
                pred = np.asarray(est.predict_proba(X_aug))
            except Exception :
                to_match = X_aug.shape[1]
                est_ = self.get_good(to_match)
                if est_:
                    est = est_
                    pred = np.asarray(est.predict_proba(X_aug))
                else:
                    raise
                    
            if pred.ndim == 2 and pred.shape[1] == 2:
                y = pred[:,1].reshape(-1, 1)
            else:
                y =  pred.reshape(-1, 1)
            preds.append(y)
            X_aug = np.concatenate((X_aug, y), axis=1)
            
        Y = np.concatenate(preds, axis=1)
        shape = Y.shape
        try:
            Y_copy = Y[:, self.order_]
            Y = Y_copy if Y.shape == shape else Y
        except Exception:
            pass
        return Y 
    
    def predict(self, X):
        return np.asarray(self.predict_proba(X) > 0.5).astype(int)
    
    def score(self, X, y):
        return accuracy_score(y, self.predict(X))
    
class CustomOneVsRestClassifier(MOP):
    def __init__(
            self, estimator=None,
            n_jobs=-1, 
            random_state=42, 
            prefit_estimators=None
        ):
        
        base_estimator = RandomForestClassifier(
                n_estimators=50,
                random_state=random_state
            )
        super().__init__(estimator or base_estimator, n_jobs=n_jobs)
    
        self.prefit_estimators = prefit_estimators
        self.estimator = estimator or base_estimator
    
    def __sklearn_clone__(self):
        """Empêche le clonage des estimateurs pré-fittés"""
        cloned = self.__class__(
            estimator=self.estimator,
            n_jobs=self.n_jobs,
            random_state=self.random_state,
            prefit_estimators=self.prefit_estimators 
        )
        return cloned

    def fit(self, X, y) :
        if self.prefit_estimators is not None:
            n_labels = y.shape[1] if hasattr(y,'shape') else len(self.estimators_)
            if n_labels != len(self.estimators_):
                raise ValueError(f"Nombre d'estimateurs ({len(self.estimators_)})")
            for i,est in enumerate(self.prefit_estimators) :
                if not hasattr(est,'classes_'):
                    raise ValueError(f"Estimateur {i} doit être fitté")

            self.label_binarizer_ = LabelBinarizer().fit(y)
            self.classes_ = [est.classes_ for est in self.prefit_estimators]
            self.estimators_ = self.prefit_estimators
            if all(hasattr(self,'n_features_in_') for est in self.estimators_) :
                self.n_features_in_ = self.estimators_[0].n_features_in_

            print('Utilisations d\'estimateurs pré-fittés, FIT skippé avec succès')
            return self
        
        else:
            raise ValueError(
                'Pour utiliser cette classe il faut initialisé l\' attribut "estimators_" avec setattr '
                "Example : Utilisez set_prefit_estimators() avant fit()."
                )
    
    def predict_proba(self, X):
        X = np.asarray(X)
        preds = []
        pred = [] 
        for i in range(len(self.estimators_)):
            est = self.estimators_[i]
            y = np.asarray(est.predict_proba(X))
            if y.ndim == 2 and y.shape[1] == 2:
                pred = y[:, 1].reshape(-1, 1)
            else:
                pred = y.reshape(-1, 1)
            preds.append(pred)
            
        return np.concatenate(preds, axis=1)
    
    def predict(self, X):
        return np.asarray(self.predict_proba(X) > 0.5).astype(int)
    
    def score(self, X, y):
        return accuracy_score(y, self.predict(X))
    
class ClassifierChain(ClassifierChainBase):
    def __init__(self, base_estimator, order=None, random_state=42, chain_method='predict_proba', verbose=False, cv=None):
        super().__init__(
            base_estimator, 
            order=order, 
            random_state=random_state, 
            cv=cv, 
            chain_method=chain_method, 
            verbose=verbose,
            )
        self.chain_method = chain_method
    
    def fit(self, X, Y, **fit_params):
        super().fit(X, Y, **fit_params)
        self.chain_method_ = self.chain_method
        return self
    
    def get_good(self, n_feat):
        for est in self.estimators_:
            if est.n_features_in_ == n_feat:
                return est
        return None # Aucun estimator ne correspond.
    
    def predict_proba(self, X):
        X = np.asarray(X)
        X_aug = X.copy()
        preds = []
        y = []
        order = self.order_ if hasattr(self, 'order_') else range(len(self.esttimator_))
        for i in order:
            est = self.estimators_[i]
            try:
                pred = np.asarray(est.predict_proba(X_aug))
            except Exception:
                est_ = self.get_good(X_aug.shape[1])
                if est_:
                    est = est_
                    pred = np.asarray(est.predict_proba(X_aug))
                else:
                    raise
                    
            if pred.ndim == 2 and pred.shape[1] == 2:
                y = pred[:,1].reshape(-1, 1)
            else:
                y =  pred.reshape(-1, 1)
            preds.append(y)
            X_aug = np.concatenate((X_aug, y), axis=1)
         
        Y = np.concatenate(preds, axis=1)
        shape = Y.shape
        try:
            Y_copy = Y[:, self.order_]
            Y = Y_copy if Y.shape == shape else Y
        except Exception:
            pass
        return Y 
    
    def predict(self, X):
        return np.asarray(self.predict_proba(X) > 0.5).astype(int)
    
    def score(self, X, y):
        return accuracy_score(y, self.predict(X))
        
class CustomKerasClassifier:
    def __init__(self, y, n_features, output="chain", learning_rate=0.001):
        self.y_shape = np.asarray(y).shape
        self.n_classes = y.shape[1] if y.ndim > 1 else len(np.unique(y))
        self.n_features = n_features
        self.learning_rate = learning_rate
        self.output = output
        
    
    def __call__(self, meta):
        n_feat = meta.get('n_features_in_', self.n_features)
        n_classes = meta.get('n_classes_',self.n_classes)
        y_shape = meta.get('y_shape_',self.y_shape)
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
        
        if self.output in ('chain', 'ovr'):
            n_output = n_classes
            activation = 'sigmoid'
            loss = 'binary_crossentropy'
            print(f"[DEBUG] Multi-label détecté (output={self.output})")
        elif n_classes > 2 and len(y_shape) == 1:
            n_output = n_classes
            activation = 'softmax'
            loss = 'sparse_categorical_crossentropy'
            print(f"[DEBUG] Multi-class détecté ({n_classes} classes)")
        else:
            n_output = 1
            activation = 'sigmoid'
            loss = 'binary_crossentropy'
            print("[DEBUG] Binary détecté")

        print(f"[DEBUG] → {n_feat} features, {n_output} sortie(s), {activation}, {loss}")

        model.add(Dense(n_output, activation=activation))
        model.compile(optimizer=Adam(learning_rate=self.learning_rate), loss=loss, metrics=['accuracy'])
        return model
    
class ModelStack:
    def __init__(self,X,y,n_features,method='one_label',output='chain',learning_rate=0.01,random_state=42,cv=None):
        self.X = np.asarray(X)
        self.y = np.asarray(y)

        if self.X.ndim != 2:
            raise ValueError(f"X doit être 2D, reçu shape {self.X.shape}")

        if method == 'multi_label':
            if output.lower() not in ('ovr', 'chain'):
                raise TypeError(f"Pour multi_label, output doit être 'chain' ou 'ovr', reçu '{output}'")
            if self.y.ndim != 2:
                raise ValueError(f"Pour multi_label, y doit être 2D (shape: (n_samples, n_labels)), "
                               f"reçu shape {self.y.shape}")


        if self.y.ndim not in (1, 2):
            raise ValueError(f"y doit être 1D ou 2D, reçu shape {self.y.shape}")

        if self.X.shape[0] != self.y.shape[0]:
            raise ValueError(f"X ({self.X.shape[0]} samples) et y ({self.y.shape[0]} samples) "
                           "doivent avoir le même nombre d'échantillons")

        if self.X.shape[1] != n_features:
            raise ValueError(f"X a {self.X.shape[1]} features mais n_features={n_features}")

        self.method = method
        self.random_state = random_state
        self.cv = cv or StratifiedShuffleSplit(n_splits=3, test_size=0.2, random_state=self.random_state)
        self.output = output.lower()
        self.stack = None
        self.n_features = n_features or X.shape[1]
        self.order = np.argsort(np.sum(self.y,axis=0)) if self.y.ndim > 1 else None
        self.learning_rate = learning_rate
        if self.y.ndim == 1 and (method == 'multi_label' or output.lower() in ('ovr', 'chain')):
            print("[WARNING] y est 1D, impossible de faire du multi-label.")
            print("          Basculement automatique : method='one_label', output=None")
            self.method = 'one_label'
            self.output = None

        print("[INIT] ModelStack créé:")
        print(f"  - X shape: {self.X.shape}")
        print(f"  - y shape: {self.y.shape}")
        print(f"  - Méthode: {self.method}")
        print(f"  - Output: {self.output}")
        print(f"  - Learning rate: {self.learning_rate}")

   
    def create_models(self) :
        to_return = {}

        # lgbm = LGBMClassifier(
        #     n_estimators=300,
        #     num_leaves=40,
        #     learning_rate=self.learning_rate,
        #     verbose=-1,
        #     max_depth=6,
        #     subsample=0.8,
        #     subsample_freq=1,
        #     min_child_samples=30,
        #     importance_type='gain',
        #     boosting_type="gbdt",
        #     colsample_bytree=0.8,
        #     objective="binary",
        #     n_jobs=2,
        #     random_state=self.random_state
        # )
        # to_return['lgbm'] = ('lgbm',lgbm)

        rf = RandomForestClassifier(
            n_estimators=600,
            class_weight='balanced',
            n_jobs=-1,
            max_depth=None,
            max_features="sqrt",verbose=0,
            random_state=self.random_state
        )
        to_return['rf'] = ('rf',rf)

        xgb = XGBClassifier(
            n_estimators=1500,
            objective='binary:logistic',
            learning_rate=self.learning_rate,
            tree_method='hist',
            n_jobs=-1,
            base_score=0.5,
            random_state=self.random_state
        )
        to_return['xgb'] = ('xgb',xgb)

        hist = HistGradientBoostingClassifier(
            max_iter=2000, learning_rate=self.learning_rate,
            loss='log_loss',n_iter_no_change=70,
            max_leaf_nodes=40,
            early_stopping=True,
            validation_fraction=0.1,scoring='f1_macro',
            class_weight='balanced',
            random_state=self.random_state,max_depth=None
        )
        to_return['hgbc'] = ('hgbc',hist)

        extra = ExtraTreesClassifier(
                    n_estimators=600,
                    max_depth=None,
                    class_weight='balanced',
                    n_jobs=-1,
                    max_features='sqrt',
                    random_state=self.random_state,verbose=0
                    )
        to_return['extra'] = ('extra',extra)

        mlp = MLPClassifier(hidden_layer_sizes=(256,128,64,),
                            max_iter=300,
                            random_state=self.random_state,
                            learning_rate='adaptive',
                            n_iter_no_change=20,
                            early_stopping=True,
                            tol=1e-6
                            )
        pipeline_mlp = Pipeline([
            ('scaler', StandardScaler()),
            ('mlp', mlp)
        ])
        to_return['mlp'] = ('mlp',pipeline_mlp)
        
        keras = CustomKerasClassifier(
            y=self.y,  
            output=self.output,
            n_features=self.n_features,
            learning_rate=self.learning_rate
        )   
        def func(meta):
            return keras(meta)
        
        deep_model = KerasClassifier(
            model=func,
            epochs=120,
            batch_size=32,
            verbose=0,
            random_state=self.random_state,
            validation_split=0.2,
            loss='binary_crossentropy',
            callbacks=[EarlyStopping(monitor='val_loss', patience=15)]
        )
        deep_model._estimator_type='classifier'
        to_return['keras'] = ('keras',deep_model)

        print(f"[CREATION DES MODELS DANS MODELSTACK] {len(to_return)} models crées de noms {list(to_return.keys())}")

        return to_return

    def create_param_dict_one_label(self,name):
        name = name.lower()
        params = {
            'rf': {
                'n_estimators': Integer(300, 700),
                'max_features': Categorical(['sqrt', 'log2',None]),
                'max_depth': Categorical([4, 6, 8, 10, 12,14, None]),
                'min_samples_leaf':Integer(1, 10)

            },
            'xgb': {
                'n_estimators': Integer(700, 1500),
                'max_depth': Integer(6, 30),
                'learning_rate': Real(0.01, 0.2, prior='log-uniform'),
                'gamma':Real(0,10)
            },
            'lgbm': {
                'n_estimators': Integer(1000, 2000),
                'learning_rate': Real(0.05, 0.3, prior='log-uniform'),
                'max_depth': Categorical([5,6,7,8]),
                'num_leaves': Integer(30, 80),
            },
            'hgbc': {
                'max_iter': Integer(500, 2500),
                'learning_rate': Real(0.01, 0.1, prior='log-uniform'),
                'max_depth': Categorical([4, 6, 8,10,12,14,16,18, None]),
                'max_bins' : Integer(128, 255)
            },
            'cat': {
                'depth':Integer(6,15),
                'iterations': Integer(700,2000),
                'learning_rate': Real(0.01,0.1),
                'rsm':Real(0.5,1.0),
                'random_strength':Real(0.0,2.0)
                },
            'svc':{
                'C':Categorical([1e-1,1e-2,1e-3,1,10]),
                'kernel':Categorical(['poly', 'rbf'])
                },
            'extra': {
                'n_estimators': Integer(300, 1000),
                'max_features': Categorical(['sqrt', 'log2',None]),
                'max_depth': Categorical([4, 6, 8, 10, 12,14, None]),
                'min_samples_leaf':Integer(1, 10)

            },
            'logreg':{
                "C" :Real(1e-5, 100),
                "max_iter" : Integer(100, 8000),
                'tol' : Real(1e-10, 1e-2),
                "solver":Categorical(['liblinear','lbfgs','saga'])
                },
            "mlp":{
                "hidden_layer_sizes" : Categorical([(256,128,64,32,), (128,64,),(256,64,),(128,32,),(128,64,32,),(64,32,)]),
                'learning_rate':Categorical(['constant','adaptive']),
                'max_iter':Integer(200,600),
                'learning_rate_init':Real(1e-3,1e-1)
                }
        }
        return params.get(name, {})

    def create_param_dict_multi_label(self,name):
        dic = self.create_param_dict_one_label(name=name.lower())
        if self.output == 'chain':
            return {'base_estimator__'+str(k):v for k,v in dic.items()}
        elif self.output == 'ovr':
            return {'estimator__'+str(k):v for k,v in dic.items()}
        else:
            return {}
        
    
    def helper(self, best_models, dict_of_models, list_models_name, specials):
        print(best_models.keys())
        print(dict_of_models.keys())
        print(list_models_name)
        print(type(best_models[list(best_models.keys())[0]][1]).__name__)
       
        for name in list_models_name:
            if not name in dict_of_models:
                continue
            else:
                if name in specials:
                    best_models[name] = dict_of_models[name]
                else:
                    name_, model = dict_of_models[name]
                    if self.output == 'chain':
                        wrapped = ClassifierChain(model, order=self.order, random_state=self.random_state, chain_method='predict_proba')
                    elif self.output == 'ovr':
                        wrapped = MOP(model, n_jobs=2)
                    else:
                        wrapped = model
                    best_models[name] = (name_, wrapped)
        return best_models
        
    def model_optimize_one_label(self,dict_of_models,n_iter=15):
        if not dict_of_models:
            raise ValueError("Aucun model (model_optimize_one_label)")
        excludes = ("keras","mlp","bagcat","extra", "rf")
        best_models = {}
        X_copy = self.X.copy()
        y_copy = self.y.copy()
        if y_copy.ndim > 1 :
            best_idx = np.argmax(np.sum(y_copy,axis=0))
            y_single = y_copy[:,best_idx]
            print(f" \n Label selectionné  : {best_idx}")
            print(f"Distribution : {y_single.mean()*100}% ")
        else :
            y_single = y_copy
        models = [m for m in dict_of_models.keys() if m not in excludes]
        for i in tqdm(range(len(models)),desc='FITTING séparé des models,(ONE_LABEL)'):
            name , model  = dict_of_models[models[i]]
            space = self.create_param_dict_one_label(name.lower())
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}(one label)")
            model_bayes = BayesSearchCV(
            estimator=model,
            search_spaces=space,
            scoring='f1_macro',
            cv=self.cv,
            return_train_score=True,
            n_iter=n_iter, n_jobs=1
            )
            start = time.time()
            model_bayes.fit(X_copy, y_single)
            end = time.time()
            best = model_bayes.best_estimator_
            if self.output == 'chain':
                best = ClassifierChain(best,order=self.order,random_state=self.random_state,chain_method='predict_proba')
            elif self.output == 'ovr':
                best = MOP(best,n_jobs=2)
            best_models[name] = (name,best)
            print(f"\n Meilleur paramètres pour ce model : {dict(model_bayes.best_params_)} et \n Meillleur score CV : {model_bayes.best_score_} ")
            print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)})")
            print(f" \n Fit terminé en {end - start:.3f} secondes")

        print("FIN de l'optimisation one_label des models")

        return self.helper(best_models, dict_of_models, list_models_name=excludes, specials=['mlp', 'keras'])

    def model_optimize_multi_label(self,dict_of_models,n_iter=15) :
        if not dict_of_models:
            raise ValueError("Aucun model (model_optimize_one_label)")
        excludes = ("keras","mlp","bagcat","extra", "rf")
        best_models = {}
        X_copy = self.X.copy()
        y_copy = self.y.copy()
        models = [m for m in dict_of_models.keys() if m not in excludes]
        for i in tqdm(range(len(models)),desc='FITTING séparé des models,(MULTI_LABEL) '):
            name , model  = dict_of_models[models[i]]
            space = self.create_param_dict_multi_label(name.lower())
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}(multi label)")
            if self.output == 'chain':
                model_wraped = ClassifierChain(model, cv=self.cv, random_state=self.random_state, order=self.order, chain_method='predict_proba')
            elif self.output == 'ovr':
                model_wraped = MOP(model,n_jobs=2)
            else :
                raise ValueError("Méthode incompatible avec output différent de chain ou ovr[model_optimize_multi_label]")
            model_bayes = BayesSearchCV(
                estimator=model_wraped,
                search_spaces=space,
                scoring='f1_macro',
                cv=self.cv,
                n_iter=n_iter, n_jobs=-1,
                return_train_score=True,
                verbose=0
            )
            start = time.time()
            model_bayes.fit(X_copy,y_copy)
            end = time.time()
            best_models[name] = (name,model_bayes.best_estimator_)
            print(f" \n Meilleur paramètres pour ce model : {dict(model_bayes.best_params_)} et \n Meillleur score CV : {model_bayes.best_score_} ")
            print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)})")
            print(f" \n Fit terminé en {end - start:.3f} secondes")

        print("FIN de l'optimisation multi_label des models")
        
        return self.helper(best_models, dict_of_models, list_models_name=excludes, specials=['mlp', 'keras'])

    def _manual_ovr(self,best_models,dict_of_models,models,n_iter,X,y) :
        if not models:
            raise ValueError("Pas de models")
        print('Opimisation manuelle façon OVR')
        for i in tqdm(range(len(models)),desc='FITTING séparé des models,(MULTI_LABEL) '):
            name , model  = dict_of_models[models[i]]
            space = self.create_param_dict_one_label(name.lower())
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}(multi_label)")
            estimators_ = []
            for j in range(len(self.order)) :
                print(f"Label de position {j} --> ({self.order[j]})")
                model_for_pos = clone(model)
                model_bayes = BayesSearchCV(
                    estimator=model_for_pos,
                    search_spaces=space,
                    scoring='f1_macro',
                    cv=self.cv,
                    n_iter=n_iter,n_jobs=-1,
                    return_train_score=True,
                    verbose=0
                )
                start = time.time()
                model_bayes.fit(X,y[:,j])
                end = time.time()
                print(f" \n Meilleur paramètres  : {dict(model_bayes.best_params_)} et \n Meillleur score CV : {model_bayes.best_score_} ")
                print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)})")
                print(f" \n Fit terminé en {end - start:.3f} secondes")
                estimators_.append(model_bayes.best_estimator_)
            for est_ in estimators_:
                try:
                    check_is_fitted(est_)
                except NotFittedError:
                    print(est_, 'no fitted')
                    input()
            est = CustomOneVsRestClassifier(estimator=estimators_[-1], prefit_estimators=estimators_)
            est.estimators_ = estimators_
            est.prefit_estimators = estimators_
            best_models[name] = (name, est)
            for i, est_i in enumerate(est.estimators_):
                try:
                    check_is_fitted(est_i)
                    print(f"  ✅ Après création: estimateur {i} toujours fitted")
                except NotFittedError:
                    print(f"  ❌ Après création: estimateur {i} PLUS fitted!")
    
            best_models[name] = (name,est)
        return best_models

    def _manual_chain(self, best_models, dict_of_models, models, n_iter, X, y) :
        if not models:
            raise ValueError("Pas de models")
        print('Opimisation manuelle façon CHAIN')
        for i in tqdm(range(len(models)),desc='FITTING séparé des models(MULTI_LABEL) '):
            name , model  = dict_of_models[models[i]]
            space = self.create_param_dict_one_label(name.lower())
            print(f"\n [{i+1}/{len(models)}] Optimisation {name.upper()}(multi_label)")
            estimators_ = []
            preds = np.array([])
            X_au = np.asarray(X)
            for j, k  in enumerate(self.order):
                print(f"Label de position {j} --> ({k})")
                model_for_pos = clone(model)
                if  preds.size > 0 :
                    X_au = np.concatenate((X_au, preds),axis=1)
                else :
                    X_au = X.copy()
                # print(X_au.shape)
                model_bayes = BayesSearchCV(
                    estimator=model_for_pos,
                    search_spaces=space,
                    scoring='f1_macro',
                    cv=self.cv,
                    n_iter=n_iter,n_jobs=-1,
                    return_train_score=True,
                    verbose=0
                )
                start = time.time()
                model_bayes.fit(X_au,y[:,k])
                end = time.time()
                model_bayes_ = model_bayes.best_estimator_
                preds_ = np.asarray(model_bayes_.predict_proba(X_au))
                if preds_.ndim == 2:
                    preds = preds_[:,1].reshape(-1,1)
                else :
                    print(X_au)
                    print(preds_, preds_.shape, preds_.ndim)
                    input()
                    preds = preds_.reshape(-1,1)
                estimators_.append(model_bayes_)
                print(f" \n Meilleur paramètres  : {dict(model_bayes.best_params_)} et \n Meillleur score CV : {model_bayes.best_score_} ")
                print(f"\n Score CV complet : \n {pd.DataFrame(model_bayes.cv_results_)})")
                print(f" \n Fit terminé en {end - start:.3f} secondes")
            for est_ in estimators_:
                try:
                    check_is_fitted(est_)
                except NotFittedError:
                    print(est_, 'no fitted')
                    input()
            est = CustomChain(order=self.order, random_state=self.random_state, chain_method='predict_proba', estimator=estimators_[-1], prefit_estimators=estimators_)
            est.prefit_estimators = estimators_
            best_models[name] = (name, est)
            for i, est_i in enumerate(est.prefit_estimators):
                try:
                    check_is_fitted(est_i)
                    print(f"  ✅ Après création: estimateur {i} toujours fitted")
                except NotFittedError:
                    print(f"  ❌ Après création: estimateur {i} PLUS fitted!")
            print('Test : \n')
            est.fit(X, y)
            p = est.predict_proba(X)
            print(p)
            
        return best_models
    
    def model_optimize_multi_label_manual(self,dict_of_models,n_iter=10) :
        if not dict_of_models:
            raise ValueError("Aucun model (model_optimize_one_label)")
        excludes = ("keras","mlp","bagcat","extra", "rf")
        best_models = {}
        X_copy = self.X.copy()
        y_copy = self.y.copy()
        models = [m for m in dict_of_models.keys() if m not in excludes]
        if self.output == 'ovr' :
            start = time.time()
            best_models = self._manual_ovr(best_models, dict_of_models, models, n_iter, X_copy, y_copy)
            print(f"Manual OVR terminé en {time.time()-start:.3f} secondes ")
        elif self.output == 'chain':
            start = time.time()
            best_models = self._manual_chain(best_models, dict_of_models, models, n_iter, X_copy, y_copy)
            print(f"Manual CHAIN terminé en {time.time()-start:.3f} secondes ")
            
        return self.helper(best_models, dict_of_models, list_models_name=excludes, specials=['mlp', 'keras'])

    def create_stacking(self, dict_of_models, n_classes):
        if not dict_of_models:
            raise ValueError("Aucun model")
        estimators = []
        for name, model in dict_of_models.values():
            print(f"\n[create_stacking] {name} -> {type(model).__name__}")
            estimators.append((name, model))

        print(f"\n[create_stacking] Total estimators: {len(estimators)}")
        
        mlp = MLPClassifier(hidden_layer_sizes=(256,128,64,),
                            max_iter=300,
                            random_state=self.random_state,
                            learning_rate='adaptive',
                            n_iter_no_change=20,
                            early_stopping=True,
                            tol=1e-6
                            )
        meta = Pipeline([
            ('scaler', StandardScaler()),
            ('mlp', mlp)
        ])
        print("Méta : ", meta)
        stack = MultiLabelStackingClassifier(
            estimators=estimators,
            final_estimator=meta,
            cv=self.cv,
            passthrough=True,
            n_jobs=-1,
            verbose=1,
            n_labels=n_classes,
            stack_method='predict_proba'
        )

        list2 = [k[0] for k in estimators]
        print(f"[INFO] Stacking crée avec le modèles suivants : {list2}")
        return stack

    def run(self,n_classes,n_iter=15,manual_label=False):
        models = self.create_models()
        if self.method == 'fast' :
            if not models:
                raise ValueError("Aucun model")
            estimators = {}
            for name, model in models.values():
                if name in ("mlp", 'keras'):
                    estimators[name] = (name, model)
                    continue
                if self.output == 'ovr':
                    model = MOP(model,n_jobs=-1)
                elif self.output == 'chain':
                    model = ClassifierChain(model, order=self.order, cv=self.cv, chain_method='predict_proba', random_state=self.random_state)
                else:
                    model = model
                estimators[name] = (name, model)
            return self.create_stacking(dict_of_models=estimators,n_classes=n_classes)
        elif self.method == 'one_label':
            return self.create_stacking(dict_of_models=self.model_optimize_one_label(models,n_iter=n_iter),
                                        n_classes=n_classes)
        elif self.method == 'multi_label':
            if not manual_label:
                return self.create_stacking(dict_of_models=self.model_optimize_multi_label(models,n_iter=n_iter),
                                            n_classes=n_classes)
            else :
                return self.create_stacking(dict_of_models=self.model_optimize_multi_label_manual(models,n_iter),
                                            n_classes=n_classes)
        else :
            raise ValueError("Methode invalide")

if __name__ == '__main__':
    from sklearn.datasets import make_multilabel_classification
    from sklearn.preprocessing import StandardScaler as SC
    from sklearn.model_selection import train_test_split as tts
    from sklearn.metrics import recall_score,classification_report,multilabel_confusion_matrix
    import dill
    from ml_model.modeloptimize import ModelOptimization
    import warnings
    warnings.filterwarnings('ignore')
    np.random.seed(0)

    X,y = make_multilabel_classification(n_samples=7000, n_features=44, n_classes=3, n_labels=2, allow_unlabeled=False, random_state=42)
    X = SC().fit_transform(X)
    X_train,_,y_train,_ = tts(X,y,test_size=0.2,random_state=42)
    features_names = [f'features_{i}' for i in range(44)]
    model = ModelStack(X_train, y_train, n_features=44, method='fast', output='chain', learning_rate=0.001, cv=3)
    stack = model.run(n_iter=10, manual_label=False, n_classes=3)
    Opt = ModelOptimization(model=stack, X=X ,y=y ,random_state=42, cv=2, save_dir="modelstack", features_name=features_names, scoring=["f1_macro","accuracy"])
    start = time.time()
    stack,X_test,y_test = Opt.run(threshold=None, _all_=True, features_imp=False)
    end = time.time()
    print(f" \n Fit terminé en {end - start:.3f} secondes")

    y_pred = stack.predict(X_test)
    print('Score : ',stack.score(X_test,y_test))
    print('\n Recall score : ',recall_score(y_test, y_pred,average="macro"))
    print("\n Classification report : \n",classification_report(y_test, y_pred))
    print("\n MultiLabel Confusion Matrix report : \n",multilabel_confusion_matrix(y_test, y_pred))

    with open('model_stack_nouvelle_methode_multilabel_chain1_sam.pkl', 'wb') as f:
        dill.dump(stack, f)
    print('Modèle sauvegardé!')
    # Chargement
    # with open('model_stack_onelabel.pkl', 'rb') as f:
    #     stack = dill.load(f)
    # print('Modèle chargé!')

    print()
    for name, est in stack.named_estimators_.items():
        print(f"\n{name} → {type(est).__name__}")
        try:
            proba = est.predict_proba(X_test)
            print(f"Shape: {np.shape(proba)}")
            print(proba,'\n')
        except Exception as e:
            print(f"Erreur pour {name}: {e}")
    print('\n COMPARAISON POUR VÉRIFICATION')
    print(y_pred[:3,:] )
    print(stack.predict_proba(X_test[:3,:]))
