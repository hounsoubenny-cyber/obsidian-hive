#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 28 21:39:14 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Oct 25 20:38:59 2025

@author: hounsousamuel
"""

# models.py
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import threading
import copy
import warnings
import optuna
import tensorflow as tf
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt
from sklearn.metrics import silhouette_score
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
from tensorflow.keras.layers import (
    Input, LSTM, Dense, TimeDistributed,
    RepeatVector, Dropout, 
    LayerNormalization, Attention,
    Conv1D, MaxPooling1D, UpSampling1D,
    MultiHeadAttention, Add, Concatenate,
)
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
from ids_ips_ia.config.config_ids import N_TRIAl
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

pd.set_option("display.max_row",111)
pd.set_option("display.max_columns",111)
tf.get_logger().setLevel('ERROR')
warnings.filterwarnings('ignore')

path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'courbe')
os.makedirs(path, exist_ok=True)

SEQ_WEIGTH = {
    'if': 0.5,
    'lof': 0.5
    }

PKT_WEIGTH = {
    'if': 0.5,
    'lof': 0.5
    }

class Models:
    def __init__(self, lock=None):
        self.mse_mean = 0.15
        self.verbose = 0
        self.n_trial = N_TRIAl
        self.lock = lock or threading.Lock()
        self.if_dec_func_max_pkt = None
        self.if_dec_func_min_pkt = None
        self.lof_dec_func_max_pkt = None
        self.lof_dec_func_min_pkt = None
        
        self.if_dec_func_max_seq = None
        self.if_dec_func_min_seq = None
        self.lof_dec_func_max_seq = None
        self.lof_dec_func_min_seq = None
    
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_seq_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        # self.mse_pkt_scaler = StandardScaler()
        
    def _build_LOF(self, mode='full'):
        mode = mode.strip().lower()
        if mode == "fast":
            n_neighbors = 20
            contamination = 0.05
        else :  #full par défaut
            n_neighbors = 30
            contamination = 0.1
        LOF = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=contamination,
            novelty=True,
            algorithm="auto",
            n_jobs=-1,
            metric='euclidean',
            leaf_size=20
            )
        return LOF
    
    def _build_cnn(self, n_pkt, n_seq_features, metrics, mode='full'):
        mode = mode.strip().lower()
        
        filters, seq_dropout = self._get_conf(mode, "cnn")
        
        inp = Input(shape=(n_pkt, n_seq_features))
        
        x = Conv1D(filters=filters, kernel_size=3, padding='same', activation='swish')(inp)
        x = MaxPooling1D(pool_size=2)(x)
        x = Dropout(seq_dropout)(x)
        
        x = Conv1D(filters=filters // 2, kernel_size=5, padding='same', activation='swish')(x)
        x = MaxPooling1D(pool_size=2)(x)
        x = Dropout(seq_dropout)(x)
        
        if mode == "full":
            x = Conv1D(filters=max(32, filters // 4), kernel_size=6, padding='same', activation='swish')(x)
            # x = MaxPooling1D(pool_size=2)(x)
            x = Dropout(seq_dropout)(x)
            
        x = Conv1D(filters=max(16, filters // 8), kernel_size=7, padding='same', activation='swish')(x)
        # x = MaxPooling1D(pool_size=2)(x)
        x = Dropout(seq_dropout)(x)
        
        dec = Conv1D(filters=max(16, filters // 8), kernel_size=7, padding='same', activation='swish')(x)
        # dec = UpSampling1D(size=2)(dec)
        dec = Dropout(seq_dropout)(dec)
        
        if mode == "full":
            dec = Conv1D(filters=filters // 4, kernel_size=5, padding='same', activation='swish')(dec)
            # dec = UpSampling1D(size=2)(dec)
            dec = Dropout(seq_dropout)(dec)
        
        dec = Conv1D(filters=filters // 2, kernel_size=5, padding='same', activation='swish')(dec)
        dec = UpSampling1D(size=2)(dec)
        dec = Dropout(seq_dropout)(dec)
        
        dec = Conv1D(filters=filters, kernel_size=3, padding='same', activation='swish')(dec)
        dec = UpSampling1D(size=2)(dec)
        dec = Dropout(seq_dropout)(dec)
        
        out = Conv1D(filters=n_seq_features, kernel_size=3, 
                     padding='same', activation='linear')(dec)
    
        cnn_seq = Model(inp, out)
        cnn_seq.compile(loss="mse", optimizer=Adam(0.0005),metrics=metrics)
        
        return cnn_seq
            

    def _get_metrics(self):
        def r_squared(y_true, y_pred):
            ss_res = tf.reduce_sum(tf.square(y_true - y_pred))
            ss_tot = tf.reduce_sum(tf.square(y_true - tf.reduce_mean(y_true)))
            return 1 - ss_res / (ss_tot + tf.keras.backend.epsilon())

        metrics = [
            tf.keras.metrics.MeanSquaredError(name='mse'),      # Gros erreurs pénalisées
            tf.keras.metrics.MeanAbsoluteError(name='mae'),  # Erreurs moyennes
            # r_squared,
            tf.keras.metrics.CosineSimilarity(name='cosine_sim'),
            #tf.keras.metrics.MeanAbsolutePercentageError(name='mape')  # Pourcentage d'erreur
        ]
        return metrics
    
    def _get_conf(self, mode="full", who="models"):
        if "models" in who:
            from ids_ips_ia.models.config import CONFIG_MODELS
            return list(CONFIG_MODELS.get(mode).values())
        else:
            from ids_ips_ia.models.config import CONFIG_CNN
            return list(CONFIG_CNN.get(mode).values())
    
    def _build_lstm(self, mode, seq_latent, seq_dropout, n_pkt, n_seq_features, metrics):        
        inp = Input(shape=(n_pkt, n_seq_features))
        x = (Dense(seq_latent, activation='swish'))(inp)
        x = LayerNormalization()(x)
        x = Dropout(seq_dropout)(x)

        x = Dense(seq_latent // 2, activation='swish')(x)
        x = LayerNormalization()(x)
        x = Dropout(seq_dropout)(x)
        
        if mode == "full":
            x = LSTM(max(32, seq_latent // 4), return_sequences=True)(x)
            x = LayerNormalization()(x)
            x = Dropout(seq_dropout)(x)

            attn = Attention()([x, x])
            x = Dense(max(16, seq_latent // 8), activation='swish')(attn)
            x = LayerNormalization()(x)
            x = Dropout(seq_dropout)(x)

            dec = Dense(max(16, seq_latent // 8), activation='swish')(x)
            dec = LayerNormalization()(dec)
            dec = Dropout(seq_dropout)(dec)

            dec = LSTM(max(32, seq_latent // 4), return_sequences=True)(dec)
            dec = LayerNormalization()(dec)
            dec = Dropout(seq_dropout)(dec)

        else:
            attn = Attention()([x, x])
            x = LSTM(max(16, seq_latent // 4), return_sequences=True)(attn)
            x = LayerNormalization()(x)
            x = Dropout(seq_dropout)(x)


            # dec = RepeatVector(n_pkt)(x)
            dec = Dense(max(16, seq_latent // 4), activation='swish')(x)
            dec = LayerNormalization()(dec)
            dec = Dropout(seq_dropout)(dec)


        dec = Dense(seq_latent // 2, activation='swish')(dec)
        dec = LayerNormalization()(dec)
        dec = Dropout(seq_dropout)(dec)

        dec = Dense(seq_latent, activation='swish')(dec)
        out = Dense(n_seq_features)(dec)

        model = Model(inp, out)
        model.compile(loss="mse", optimizer=Adam(0.0005),metrics=metrics)
        return model
        
    def _build_dense(self, mode, n_pkt_features, pkt_hidden, metrics):
        inp_p = Input(shape=(n_pkt_features,))
        p = Dense(pkt_hidden, activation="swish")(inp_p)
        p = Dropout(0.2)(p)
        p = LayerNormalization()(p)
        p = Dense(pkt_hidden // 2, activation="swish")(p)
        p = Dropout(0.2)(p)
        p = LayerNormalization()(p)
        if mode == 'full':
            p = Dense(pkt_hidden // 4, activation="swish")(p)
            p = Dropout(0.2)(p)
            p = LayerNormalization()(p)

            p = Dense(pkt_hidden // 8, activation="swish")(p)
            p = Dropout(0.2)(p)
            p = LayerNormalization()(p)

            p = Dense(pkt_hidden // 4, activation="swish")(p)
            p = Dropout(0.2)(p)
            p = LayerNormalization()(p)

        else:
            p = Dense(pkt_hidden // 4, activation="swish")(p)
            p = Dropout(0.2)(p)
            p = LayerNormalization()(p)

        p = Dense(pkt_hidden // 2, activation="swish")(p)
        p = Dropout(0.2)(p)
        p = LayerNormalization()(p)
        out_p = Dense(n_pkt_features, activation="linear")(p)


        model = Model(inp_p, out_p)
        model.compile(loss="mse", optimizer=Adam(0.001),metrics=metrics)

        return model
    
    def build_models(self, n_pkt, n_seq_features, n_pkt_features=None, mode="full"):
        """
        
        Parameters
        ----------
        n_pkt : int
            Nombre de packets dans une sequence.
        n_seq_features : int
            Nombre de features de chaque packet de la sequence.
        n_pkt_features : int, optional
            Nombre de features dans les packet. The default is None.
        mode : str, optional
            Le mode de construction(full pour puissant, fast pour rapide). The default is "full".

        Returns
        -------
        ae_seq : AutoEncoder
            AutoEncoder de séquence.
        cnn_seq : CNN
            CNN des séquences.
        if_seq : IsolationForest
            DESCRIPTION.
        lof_seq : LocalOutlierFactor
            LocalOutlierFactor des séquences.
        ae_pkt : AutoEncoder
            AutoEncoder Dense des packets.
        if_pkt : IsolationForest
            IsolationForest des packets.
        lof_pkt : LocalOutlierFactor
            LocalOutlierFactor des packets.

        """

        metrics = self._get_metrics()
        seq_latent, seq_dropout, seq_if_estimators,pkt_if_estimators, pkt_hidden = self._get_conf(mode, "models")
        if_seq = IsolationForest(
            n_estimators=seq_if_estimators,
            max_samples="auto",
            contamination=0.015,
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            random_state=42,
            verbose=self.verbose
        )
        
        if_pkt = IsolationForest(
            n_estimators=pkt_if_estimators,
            contamination=0.01,
            random_state=42,
            n_jobs=-1,
            verbose=self.verbose
        )
        
        lof_seq = self._build_LOF(mode=mode)
        
        lof_pkt = self._build_LOF()
        
        if n_pkt_features is None:
            n_pkt_features = n_seq_features

        ae_seq = self._build_lstm(
            mode=mode,
            seq_latent=seq_latent, 
            seq_dropout=seq_dropout, 
            n_pkt=n_pkt, 
            n_seq_features=n_seq_features, metrics=metrics
        )
        
        cnn_seq = self._build_cnn(
            n_pkt=n_pkt, 
            n_seq_features=n_seq_features, 
            metrics=metrics, 
            mode=mode
        )
        
        ae_pkt = self._build_dense(
            n_pkt_features=n_pkt_features, 
            pkt_hidden=pkt_hidden, 
            metrics=metrics,
            mode=mode
        )
       
        return ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt

    def get_opt_params_lof(self, trial):
        params_opt_one = {
                    'n_neighbors': trial.suggest_int('n_neighbors',15, 50),
                    'contamination': trial.suggest_float('contamination', 0.05,0.2),
                    'leaf_size': trial.suggest_int('leaf_size',20, 40),
                    'metric': trial.suggest_categorical('metric', ["euclidean", "minkowski", "manhattan"]),
                }

        return params_opt_one

    def get_opt_params_if(self, trial):
        params_opt_if = {
                'contamination': trial.suggest_float('contamination', 0.05, 0.2),
                'n_estimators': trial.suggest_int('n_estimators', 300, 2000),
                'bootstrap': trial.suggest_categorical('bootstrap', [True, False]),
                "max_samples":  trial.suggest_float('max_samples', 0.1, 1.0),
                "max_features":  trial.suggest_float('max_features', 0.5, 1.0),
            }
        return params_opt_if

    def optimize(self, X,  classe, name, n_trial=50, timeout=None, rs=None):
        """
        

        Parameters
        ----------
        X : np.array
            Donné de fitting.
        classe : class
            La classe du modèle.
        name : str
            Le nom du modèle.
        n_trial : int, optional
            Nombre d'itérations. The default is 50.
        timeout : float, optional
            Durée d'optimisation. The default is None.
        rs : int, optional
            random_state. The default is None.

        Returns
        -------
        dict
            Dictinnaire complet contenat le modèles les stats et les meilleurs params.

        """
        def _optimize(trial):
                params = self.get_opt_params_if(trial) if name == "IsolationForest" else self.get_opt_params_lof(trial)
                if name == "Local Outlier Factor":
                    model =  classe(**params, novelty=True, n_jobs=-1)
                    model.fit(X)
                else:
                    model = classe(**params) if not rs else classe(**params, random_state=rs)
                    model.fit(X, X)
                return np.mean(model.score_samples(X))
            
        s = time.time()
        study = optuna.create_study(direction='maximize')
        study.optimize(_optimize, n_trials=n_trial, timeout=timeout, n_jobs=-1, show_progress_bar=bool(self.verbose))
        t = time.time() - s
        logger.print('Optimisation terminé en ', t,' secondes')
        if name == 'Local Outlier Factor':
            best_model = classe(**study.best_params, novelty=True, n_jobs=-1)
        else:
            best_model = classe(**study.best_params) if not rs else classe(**study.best_params, random_state=rs)
            
        return {
            'best_model': best_model,
            'best_params' : study.best_params,
            'best_score': study.best_value,
            'df': study.trials_dataframe()
        }

    def fit_models(
        self,
        ae_seq,
        cnn_seq,
        if_seq,
        lof_seq,
        ae_pkt,
        if_pkt,
        lof_pkt,
        X_sequences,
        X_packets,
        epochs=50,
        batch_size=64,
        verbose=0
    ):
        """
        Entraîne :
          - les deux autoencoders en parallèle (threads) ;
          - puis les IF/LOF en parallèle sur les sorties des AE.
        Inputs :
          X_sequences : np.array shape (n_seq, seq_len, n_features)
          X_packets   : np.array shape (n_packets, n_features)
        Retourne les modèles entraînés.
        """
        X_sequences, X_packets = np.asarray(X_sequences), np.asarray(X_packets)
        es_seq = EarlyStopping(monitor="loss", patience=10, restore_best_weights=True)
        es_pkt = EarlyStopping(monitor="loss", patience=10, restore_best_weights=True)
        self.verbose = verbose
        X_sequences, X_seq_test = train_test_split(X_sequences, test_size=0.1)

        h = ae_seq.fit(
            X_sequences,
            X_sequences,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            callbacks=[es_seq],
            validation_split=0.1,
            verbose=verbose,
        )
        try:
            self.plot_history_and_evaluate(ae_seq, h, X_seq_test, plot=False,name='Autoencoder sequentiel')
            logger.print()
        except Exception as e:
            logger.print("Erreur pour ploting de ae_seq : ",e)
        
        h_cnn = cnn_seq.fit(
            X_sequences,
            X_sequences,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            callbacks=[es_seq],
            validation_split=0.1,
            verbose=verbose,
        )
        
        try:
            self.plot_history_and_evaluate(cnn_seq, h_cnn, X_seq_test, plot=False,name='CNN sequentiel')
            logger.print()
        except Exception as e:
            logger.print("Erreur pour ploting de CNN : ",e)

        X_packets, X_pkt_test = train_test_split(X_packets, test_size=0.1)
        h1 =  ae_pkt.fit(
            X_packets,
            X_packets,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            callbacks=[es_pkt],
            validation_split=0.1,
            verbose=verbose,
        )

        try:
            self.plot_history_and_evaluate(ae_pkt, h1, X_pkt_test, plot=False,name='Autoencoder packet')
            logger.print()
        except Exception as e:
            logger.print("Erreur pour ploting de ae_pkt : ",e)

        X_seq_pred = np.asarray(ae_seq.predict(X_sequences, verbose=verbose))
        X_seq_flat = X_seq_pred.reshape(X_seq_pred.shape[0], -1) # Maintenir le nombre d'element, la premiere dim et transformer en 2D
        X_seq_pred_cnn = np.asarray(cnn_seq.predict(X_sequences, verbose=verbose))
        X_seq_flat_cnn = X_seq_pred_cnn.reshape(X_seq_pred.shape[0], -1) # Maintenir le nombre d'element, la premiere dim et transformer en 2D
        
        # X_seq_cop_flat = X_sequences.reshape(X_sequences.shape[0], -1)
        diff = X_sequences - X_seq_pred
        mse_features = np.mean(diff ** 2, axis=(1, 2)).reshape(-1, 1)
        mae_features = np.mean(np.abs(diff), axis=(1, 2)).reshape(-1, 1)
        
        diff_cnn = X_sequences - X_seq_pred_cnn
        mse_features_cnn = np.mean(diff_cnn ** 2, axis=(1, 2)).reshape(-1, 1)
        mae_features_cnn = np.mean(np.abs(diff_cnn), axis=(1, 2)).reshape(-1, 1)
        
        X_seq_flat_to_fit = np.concatenate((X_seq_flat, X_seq_flat_cnn, mse_features, mae_features, mse_features_cnn, mae_features_cnn), axis=1) # Concatenation
        
        X_pkt_pred = ae_pkt.predict(X_packets, verbose=verbose)
        diff = X_packets - X_pkt_pred
        mse_features = np.mean(diff ** 2, axis=1).reshape(-1, 1)
        mae_features = np.mean(np.abs(diff), axis=1).reshape(-1, 1)
        X_pkt_to_fit = np.concatenate((X_pkt_pred, mse_features, mae_features), axis=1) #Concatenation
        
        
        pkt_pred_copy = copy.deepcopy(X_pkt_to_fit)
        seq_pred_cop = copy.deepcopy(X_seq_flat_to_fit)
        X_seq_flat, X_seq_flat_test = train_test_split(X_seq_flat_to_fit, test_size=0.1)
        X_pkt_pred, X_pkt_test = train_test_split(X_pkt_to_fit, test_size=0.1)

        if if_seq is not None:
            logger.print("Fit du IsolationForest Séquentiel ...")
            opt_if = self.optimize(X=X_seq_flat, n_trial=self.n_trial, classe=IsolationForest, rs=42, name='IsolationForest')
            if_seq = opt_if['best_model']
            if_seq.fit(X_seq_flat, X_seq_flat)
            logger.print('Meilleur score : ', opt_if['best_score'])
            logger.print('Meilleur params : ', opt_if['best_params'])
            logger.print('DataFrame Trial : \n', opt_if['df'])
            self.evaluate_sklearn(if_seq, X_seq_flat, name='Isolation Forest sequentiel (Train)')
            self.evaluate_sklearn(if_seq, X_seq_flat_test, name='Isolation Forest sequentiel (Test)')

        if lof_seq is not None:
            logger.print('Fit du Local Outlier Factor des séquences ...')
            opt_lof = self.optimize(X=X_seq_flat, n_trial=self.n_trial, classe=LocalOutlierFactor, name='Local Outlier Factor')
            lof_seq = opt_lof['best_model']
            lof_seq.fit(X_seq_flat, X_seq_flat)
            logger.print('Meilleur score : ', opt_lof['best_score'])
            logger.print('Meilleur params : ', opt_lof['best_params'])
            logger.print('DataFrame Trial : \n', opt_lof['df'])

            self.evaluate_sklearn(lof_seq, X_seq_flat, name='Local Outlier Factor sequentiel (Train)')
            self.evaluate_sklearn(lof_seq, X_seq_flat_test, name='Local Outlier Factor sequentiel (Test)')

        self.accord_models(if_seq, lof_seq, X_seq_flat, name1='Isolation Forest (Train)', name2='Local Outlier Factor (Train)')
        self.accord_models(if_seq, lof_seq, X_seq_flat_test, name1='Isolation Forest (Test)', name2='Local Outlier Factor (Test)')

        if if_pkt is not None:
            logger.print("Fit du IsolationForest des packets...")
            opt_if_pkt = self.optimize(X=X_seq_flat, n_trial=self.n_trial, classe=IsolationForest, rs=42, name='IsolationForest')
            if_pkt = opt_if_pkt['best_model'] #or IsolationForest(**opt_if_pkt['best_params'], random_state=42)
            logger.print('Meilleur score : ', opt_if_pkt['best_score'])
            logger.print('Meilleur params : ', opt_if_pkt['best_params'])
            logger.print('DataFrame Trial : \n', opt_if_pkt['df'])
            if_pkt.fit(X_pkt_pred, X_pkt_pred)
            self.evaluate_sklearn(if_pkt, X_pkt_pred, name='Isolation Forest packet (Train)')
            self.evaluate_sklearn(if_pkt, X_pkt_test, name='Isolation Forest packet (Test)')
        
        if lof_pkt is not None:
            logger.print("Fit du Local Outlier Factor des packets...")
            opt_lof_pkt = self.optimize(X=X_pkt_pred, n_trial=self.n_trial, classe=LocalOutlierFactor, name='Local Outlier Factor')
            lof_pkt = opt_lof_pkt['best_model']
            logger.print('Meilleur score : ', opt_lof_pkt['best_score'])
            logger.print('Meilleur params : ', opt_lof_pkt['best_params'])
            logger.print('DataFrame Trial : \n', opt_lof_pkt['df'])
            lof_pkt.fit(X_pkt_pred, X_pkt_pred)
            self.evaluate_sklearn(lof_pkt, X_pkt_pred, name='Local Outlier Factor packet (Train)')
            self.evaluate_sklearn(lof_pkt, X_pkt_test, name='Local Outlier Factor packet (Test)')
        
        with self.lock:
            if_pred_pkt = np.array(if_pkt.decision_function(pkt_pred_copy))
            lof_pred_pkt = np.array(lof_pkt.decision_function(pkt_pred_copy))
            if_pred_seq = np.array(if_seq.decision_function(seq_pred_cop))
            lof_pred_seq = np.array(lof_seq.decision_function(seq_pred_cop))
            
            # Stocker dans if_pkt et lof_pkt
            if_pkt.norm_min_ = np.min(if_pred_pkt)
            if_pkt.norm_max_ = np.max(if_pred_pkt)
            lof_pkt.norm_min_ = np.min(lof_pred_pkt)
            lof_pkt.norm_max_ = np.max(lof_pred_pkt)
            
            # Stocker dans if_seq et lof_seq  
            if_seq.norm_min_ = np.min(if_pred_seq)
            if_seq.norm_max_ = np.max(if_pred_seq)
            lof_seq.norm_min_ = np.min(lof_pred_seq)
            lof_seq.norm_max_ = np.max(lof_pred_seq)
            
            self.if_dec_func_min_pkt = if_pkt.norm_min_
            self.if_dec_func_max_pkt = if_pkt.norm_max_
            self.lof_dec_func_min_pkt = lof_pkt.norm_min_
            self.lof_dec_func_max_pkt = lof_pkt.norm_max_
            self.if_dec_func_min_seq = if_seq.norm_min_
            self.if_dec_func_max_seq = if_seq.norm_max_
            self.lof_dec_func_min_seq = lof_seq.norm_min_
            self.lof_dec_func_max_seq = lof_seq.norm_max_
    
        
        self.accord_models(if_pkt, lof_pkt, X_pkt_pred, name1='Isolation Forest (Train)', name2='Local Outlier Factor (Train)')
        self.accord_models(if_pkt, lof_pkt, X_pkt_test, name1='Isolation Forest (Test)', name2='Local Outlier Factor (Test)')
            
        return ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt

    def _normalize_decision_function(self, if_score: float, lof_score: float, who:str, if_model, lof_model):
        """
        Normalise les deux scores dans [-1, +1]

        Logique:
        1. Normaliser IF → [-1, +1]
        2. Normaliser LOF  → [-1, +1]
        3. Moyenne

        Returns: Score normalisé dans [-1, +1]
        """
        # Normaliser IF → [-1, +1]
        # Formule: (x - min) / (max - min) * 2 - 1
        min_attr = "norm_min_"
        max_attr = 'norm_max_'
        if hasattr(if_model, min_attr) and hasattr(if_model, max_attr):
            if_min = if_model.norm_min_
            if_max = if_model.norm_max_
            lof_min = lof_model.norm_min_
            lof_max = lof_model.norm_max_
        
        else:
            if who == 'pkt':
                if_min = self.if_dec_func_min_pkt if self.if_dec_func_min_pkt is not None else -1
                if_max = self.if_dec_func_max_pkt if self.if_dec_func_max_pkt is not None else 1
                lof_min = self.lof_dec_func_min_pkt if self.lof_dec_func_min_pkt is not None else -1
                lof_max = self.lof_dec_func_max_pkt if self.lof_dec_func_max_pkt is not None else 1
            else:  # 'seq'
                if_min = self.if_dec_func_min_seq if self.if_dec_func_min_seq is not None else -1
                if_max = self.if_dec_func_max_seq if self.if_dec_func_max_seq is not None else 1 
                lof_min = self.lof_dec_func_min_seq if self.lof_dec_func_min_seq is not None else -1
                lof_max = self.lof_dec_func_max_seq if self.lof_dec_func_max_seq is not None else 1
    
            
    
        if abs(if_max - if_min) == 0:
            if_max = if_min + 1e-8
        if abs(lof_max - lof_min) == 0:
            lof_max = lof_min + 1e-8
        
        if_normalized = ((if_score - (if_min)) / (if_max - (if_min))) * 2 - 1
        # if_normalized = np.clip(if_normalized, -1, 1)

        # Normaliser LOF  → [-1, +1]
        lof_normalized = ((lof_score - (lof_min)) / (lof_max - (lof_min))) * 2 - 1
        avg = 0.5 * if_normalized + 0.5 * lof_normalized
        
        return float(np.clip(avg, -1, 1))


    def _get_decision_confidence(self, norm_score: float):
        """
        Retourne le niveau de confiance (0-1) basé sur |score|

        Logique: Plus |score| est loin de 0, plus on est confident
        """
        abs_score = abs(norm_score)

        if abs_score >= 0.9:
            return "very_confident", 0.95
        elif abs_score >= 0.7:
            return "confident", 0.85
        elif abs_score >= 0.5:
            return "moderate", 0.70
        elif abs_score >= 0.3:
            return "low", 0.50
        else:
            return "uncertain", 0.30


    def predict_sequence(self, ae_seq, cnn_seq, if_seq, lof_seq, scaler, X_seq, method='predict', how='all'):
        """
        Parameters
        ----------
       ae_seq : AutoEncoder
           AutoEncoder de séquence.
       cnn_seq : CNN
           CNN des séquences.
       if_seq : IsolationForest
           DESCRIPTION.
       lof_seq : LocalOutlierFactor
           LocalOutlierFactor des séquences.
        scaler : StandardScaler
            Le scaler fitté.
        X_seq : list
            La liste des éléments de la séquence (n_pkt, n_features).
        method : str, optional
            Méthode de prédiction (predict, decisin_funcion, ...). The default is 'predict'.
        how : str, optional
            méthode de mise en relation des prédictions. The default is 'all'.

        Returns
        -------
        float or int
            La prediction.

        """
        try:
            how = how.lower().strip()
            self.seq_scaler = scaler
            X_scaled = scaler.transform(X_seq)
            new = X_scaled[np.newaxis, :, :]  # Ajouter une dimension, car (n_sequences(ici 1), n_pkt, n_features)
            X_pred = ae_seq.predict(new, verbose=self.verbose)
            X_pred_cnn = cnn_seq.predict(new, verbose=self.verbose)
            
            diff = new - X_pred
            mse_features = np.mean(diff ** 2, axis=(1, 2)).reshape(-1, 1)
            mae_features = np.mean(np.abs(diff), axis=(1, 2)).reshape(-1, 1)
            
            diff_cnn = new - X_pred_cnn
            mse_features_cnn = np.mean(diff_cnn ** 2, axis=(1, 2)).reshape(-1, 1)
            mae_features_cnn = np.mean(np.abs(diff_cnn), axis=(1, 2)).reshape(-1, 1)
            
            X_flat = X_pred.reshape(1, -1)
            X_flat_cnn = X_pred_cnn.reshape(1, -1)
            X_flat = np.concatenate((X_flat, X_flat_cnn, mse_features, mae_features, mse_features_cnn, mae_features_cnn), axis=1)
            if method == 'predict':
                preds = [if_seq.predict(X_flat)[0], lof_seq.predict(X_flat)[0]]
                if how == 'all':
                    r = -1 if np.all(np.array(preds) == -1) else 1
                else :
                    r = -1 if np.any(np.array(preds) == -1) else 1
                return r

            if method == 'decision_function':
                if_pred = if_seq.decision_function(X_flat)[0]
                lof_pred = lof_seq.decision_function(X_flat)[0]

                return self._normalize_decision_function(if_pred, lof_pred, who='seq', if_model=if_seq, lof_model=lof_seq)

            if method == 'score_sample':
                if_pred = if_seq.score_sample(X_flat)[0]
                lof_pred = lof_seq.score_sample(X_flat)[0]
                return float((if_pred + lof_pred) / 2)

            else:
               if how == 'all':
                   r = -1 if np.all(np.array(preds) == -1) else 1
               else :
                   r = -1 if np.any(np.array(preds) == -1) else 1
               return r

        except Exception as e:
            logger.print("Erreur predict_sequence:", e)
            return 1


    def predict_packet(self, ae_pkt, if_pkt, lof_pkt, scaler, pkt_features, method='predict', how='all'):
        try:
            if isinstance(pkt_features, dict):
                pkt_features = list(pkt_features.values())
            self.pkt_scaler = scaler
            X_scaled = scaler.transform([pkt_features])
            X_pred = ae_pkt.predict(X_scaled, verbose=self.verbose)
            diff = X_scaled - X_pred
            mse_features = np.mean(diff ** 2, axis=1).reshape(-1, 1)
            mae_features = np.mean(np.abs(diff), axis=1).reshape(-1, 1)
            X_pred = np.concatenate((X_pred, mse_features, mae_features), axis=1)
            if method == 'predict':
                pred = if_pkt.predict(X_pred)[0]
                lof_pred = lof_pkt.predict(X_pred)[0]
                preds = [pred, lof_pred]
                if how == 'all':
                    r = -1 if np.all(np.array(preds) == -1) else 1
                else :
                    r = -1 if np.any(np.array(preds) == -1) else 1
                return r

            if method == 'decision_function':
                decision = if_pkt.decision_function(X_pred)[0]
                decision_lof = lof_pkt.decision_function(X_pred)[0]
                # normalized = ((decision + 0.5) / 1.5)
                # # logger.print(normalized)
                # normalized = float(np.clip(normalized, -1, 1))
                # logger.print(normalized)
                return self._normalize_decision_function(decision, decision_lof, who="pkt", if_model=if_pkt, lof_model=lof_pkt)

            if method == 'score_sample':
                score = if_pkt.score_samples(X_pred)[0]
                score_lof = lof_pkt.score_samples(X_pred)[0]
                return float((score + score_lof) / 2)

            else:
                return -1 if np.any(np.array([if_pkt.predict(X_pred)[0], lof_pkt.predict(X_pred)[0]]) == -1) else 1

        except Exception as e:
            logger.print("Erreur predict_packet:", e)
            import traceback
            logger.print(traceback.format_exc())
            return 1

    def plot_history_and_evaluate(self, tf_model, history, X_test, name='Autoencoder', plot=False):

        shape = X_test.shape
        if len(shape) > 2:
            axis = (1,2)
        else:
            axis = 1
        recons = tf_model.predict(X_test)
        mse = np.square(X_test - recons)
        mse_mean = np.mean(mse, axis=axis)
        mse_mean1 = np.mean(mse)
        self.mse_mean = mse_mean1
        self.table_mse_mean = mse_mean

        logger.print('='*30, 'MSE du model ',name, '='*30)
        logger.print(f"MSE moyen global: {np.mean(mse_mean):.4f}")
        logger.print(f"MSE max: {np.max(mse_mean):.4f}")
        logger.print(f"MSE min: {np.min(mse_mean):.4f}")
        logger.print(f"Écart-type: {np.std(mse_mean):.4f}")

        if mse_mean1 <= 0.1:
            logger.print('Le modèle est excellent, il apprend bien !')
        elif 0.1 < mse_mean1 <= 0.5:
            logger.print('Le modèle est bon, il apprend bien !')
        elif 0.5 < mse_mean1 < 1:
            logger.print('Modèle acceptable.')
        else:
            logger.print('Le modèle n\'apprend pas bien !')

        keys = list(history.history.keys())
        val = [k for k in keys if str(k).startswith('val_') ]
        norm = [k for k in keys if k not in val]
        same = [(k,v) for k,v in zip(norm, val) if k in v]

        if plot:
            for k,tup in enumerate(same):
                plt.figure(figsize=(24,10))
                norm_val = history.history[tup[0] if 'val' not in tup[0] else tup[1]]
                val_val = history.history[tup[1] if 'val' in tup[1] else tup[1]]
                gap = []
                for i,n in zip(norm_val, val_val):gap.append(i - n)
                # gap = norm_val - val_val

                plt.subplot(2,2,1)
                plt.title(f'Visualisation {tup[0]}, {tup[1]}')
                plt.plot(norm_val,'-', color='r' ,label=f'Training {tup[0] if "val" not in tup[0] else tup[1]}')
                plt.plot(val_val,'-', color='g', label=f'Validation {tup[1] if "val" in tup[1] else tup[1]}')
                plt.legend(loc='best')
                plt.grid(True)

                plt.subplot(2,2,2)
                plt.title('GAP')
                plt.plot(gap,'-', color='purple', label='Evolution du gap')
                plt.axhline(y=0.1,color='red',linestyle='--',label='Seuil overfitting(10%)')
                plt.axhline(y=0.05,color='orange',linestyle='--',label='Seuil acceptable(5%)')
                plt.ylabel('Gap(Train-Validation)')
                plt.legend(loc='best')
                plt.grid(True)

                plt.subplot(2,2,3)
                plt.title('Résumé')
                plt.plot(norm_val,'-', color='r' ,label=f'Training {tup[0] if "val" not in tup[0] else tup[1]}')
                plt.plot(val_val,'-', color='g', label=f'Validation {tup[1] if "val" in tup[1] else tup[1]}')
                plt.plot(gap,'-', color='purple', label='Evolution du gap')
                plt.axhline(y=0.1,color='red',linestyle='--',label='Seuil overfitting(10%)')
                plt.axhline(y=0.05,color='orange',linestyle='--',label='Seuil acceptable(5%)')
                plt.ylabel('Gap(Train-Validation)')
                plt.legend(loc='best')
                plt.grid(True)

                plt.savefig(os.path.join(path,f'courbe_history_{name}_tf{k}.png'))
                logger.print(f'Courbe history saved to {os.path.join(path,f"courbe_history_tf_{name}{k}.png")}')
                logger.print()

                gap_mean = sum(gap) / len(gap)
                if gap_mean > 0.15 :
                    logger.print("[ALERTE] Overfiting détecté ! \n Le modèle performe plus sur train que validation. Vous pouvez essayer de réduire la complxité du modèle.")
                elif gap_mean > 0.1:
                    logger.print("Ovverfiting léger. Gap acceptable mais peut être amélioré")
                else :
                    logger.print('Pas d\'overfitting détecté. Le modèle généralise bien !')
                    logger.print()

                plt.tight_layout()
                plt.show(block=False)

        return mse, mse_mean

    def evaluate_sklearn(self, model, X_test, name):
        score = np.asarray(model.decision_function(X_test))
        mean, std = np.mean(score), np.std(score)
        logger.print('Evaluation pour ', name)
        logger.print(' NOTE : Pour un bon modèle, std doit être grand et mean proche de 0 !')
        logger.print(f"Moyenne: {mean:.3f}, Ecart-type: {std:.3f}")
        logger.print()

        scores_list = []
        for i in range(5):
            subset = X_test[np.random.choice(len(X_test), 100)]
            scores_list.append(model.decision_function(subset))
        stability = np.std([np.mean(s) for s in scores_list])

        logger.print('Stabilité du modele : ', stability, '(Doit être faible)')
        logger.print()

        kmeans = KMeans(n_clusters=3).fit(score.reshape(-1,1))
        silhouette = silhouette_score(score.reshape(-1,1), kmeans.labels_)
        good = silhouette > 0.5
        if good:
            logger.print('Bon score de silhouette, le modele sépare bien !')
        logger.print(f"Score de silhouette: {silhouette:.4f}")
        logger.print()

    def accord_models(self, model1, model2, X_test, name1, name2):

        score1 = model1.predict(X_test)
        score2 = model2.predict(X_test)

        anomalies1 = np.asarray(score1) == -1
        anomalies2 = np.asarray(score2) == -1

        safe1 = np.asarray(score1) == 1
        safe2 = np.asarray(score2) == 1

        logger.print(f"=== Comparaison {name1} vs {name2} ===")
        logger.print(f"Anomalies détectées par {name1}: {np.sum(anomalies1)}")
        logger.print(f"Normaux détectées par {name1}: {np.sum(safe1)}")
        logger.print()
        logger.print(f"Anomalies détectées par {name2}: {np.sum(anomalies2)}")
        logger.print(f"Normaux détectées par {name2}: {np.sum(safe2)}")
        logger.print()

        accord = np.mean(score1 == score2)
        logger.print('Accord total entre le deux modèles : ', accord)
        logger.print()

        accord = np.mean(anomalies1 == anomalies2)
        self.accord_sklearn_seq = accord
        logger.print('Accord anomalies entre le deux modèles : ', accord)
        logger.print()

        over = np.sum(anomalies1 & anomalies2)
        union = np.sum(anomalies1 | anomalies2)

        if union > 0:
            jaccard = over / union
            self.jaccard_sklearn_seq_ano = jaccard
            logger.print(f"Similarité de Jaccard entre les détections anomalies : {jaccard:.4f} \n")
            logger.print()

        over = np.sum(safe1 & safe2)
        union = np.sum(safe1 | safe2)

        if union > 0:
            jaccard = over / union
            self.jaccard_sklearn_seq_no = jaccard
            logger.print(f"Similarité de Jaccard entre les détections safe : {jaccard:.4f} \n")
            logger.print()
            logger.print()
