#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 10:12:52 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import dill
import joblib
import shutil
import numpy as np
import threading
import multiprocessing as mp
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split as tts
from ids_ips_ia.core.features_extractor import FeatureExtractor
from ids_ips_ia.config.config_ids import SEQ_LENGTH
from ids_ips_ia.refit_system.config import FILE_PREFIX, REFIT_DIR
from ids_ips_ia.models.models import Models
from ids_ips_ia.ids_ips_utils.logger import get_logger

logger = get_logger()

def _evaluate_model(model_dict: dict, X_sequences: np.ndarray, X_packets: np.ndarray) -> float:
    """
    Évalue un modèle de façon concise mais rigoureuse.
    Retourne un score entre 0 et 1.
    """
    ae_seq = model_dict['ae_seq']
    cnn_seq = model_dict['cnn_seq']
    ae_pkt = model_dict['ae_pkt']
    if_seq = model_dict['if_seq']
    lof_seq = model_dict['lof_seq']
    if_pkt = model_dict['if_pkt']
    lof_pkt = model_dict['lof_pkt']
    
    scores = []
    weights = []
    score_if = 0.0
    score_lof = 0.0
    score_ae = 0.0
    score_cnn = 0.0
    score_pkt = 0.0
    final_score = 0.0
    
    # 1. AUTOENCODER LSTM (reconstruction) - poids 20%
    X_seq_pred_ae = ae_seq.predict(X_sequences, verbose=0)
    mse_ae = np.mean((X_sequences - X_seq_pred_ae) ** 2)
    score_ae = max(0, 1.0 - mse_ae / 5.0)
    scores.append(score_ae)
    weights.append(0.20)
    
    # 2. CNN (reconstruction) - poids 20% (même importance que LSTM)
    X_seq_pred_cnn = cnn_seq.predict(X_sequences, verbose=0)
    mse_cnn = np.mean((X_sequences - X_seq_pred_cnn) ** 2)
    score_cnn = max(0, 1.0 - mse_cnn / 5.0)
    scores.append(score_cnn)
    weights.append(0.20)
    
    # 3. AUTOENCODER PAQUETS - poids 15%
    X_pkt_pred = ae_pkt.predict(X_packets, verbose=0)
    mse_pkt = np.mean((X_packets - X_pkt_pred) ** 2)
    score_pkt = max(0, 1.0 - mse_pkt / 5.0)
    scores.append(score_pkt)
    weights.append(0.15)
    
    # 4. Préparation features pour IF/LOF
    X_seq_ae_flat = X_seq_pred_ae.reshape(X_seq_pred_ae.shape[0], -1)
    X_seq_cnn_flat = X_seq_pred_cnn.reshape(X_seq_pred_cnn.shape[0], -1)
    diff_ae = np.mean((X_sequences - X_seq_pred_ae) ** 2, axis=(1, 2)).reshape(-1, 1)
    diff_cnn = np.mean((X_sequences - X_seq_pred_cnn) ** 2, axis=(1, 2)).reshape(-1, 1)
    X_seq_features = np.concatenate([X_seq_ae_flat, X_seq_cnn_flat, diff_ae, diff_cnn], axis=1)
    
    diff_pkt = np.mean((X_packets - X_pkt_pred) ** 2, axis=1).reshape(-1, 1)
    X_pkt_features = np.concatenate([X_pkt_pred, diff_pkt], axis=1)
    
    # 5. ISOLATION FOREST (pouvoir discriminant) - poids 15%
    if hasattr(if_seq, 'decision_function'):
        std_if_seq = np.std(if_seq.decision_function(X_seq_features))
        std_if_pkt = np.std(if_pkt.decision_function(X_pkt_features))
        score_if = min(1.0, (std_if_seq + std_if_pkt) / 2.0)
        scores.append(score_if)
        weights.append(0.15)
    
    # 6. LOF (pouvoir discriminant) - poids 15%
    if hasattr(lof_seq, 'decision_function'):
        std_lof_seq = np.std(lof_seq.decision_function(X_seq_features))
        std_lof_pkt = np.std(lof_pkt.decision_function(X_pkt_features))
        score_lof = min(1.0, (std_lof_seq + std_lof_pkt) / 2.0)
        scores.append(score_lof)
        weights.append(0.15)
    
    # 7. Score composite
    if scores:
        total_weight = sum(weights)
        final_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
    else:
        final_score = 0.5
    
    logger.print(f"   AE: {score_ae:.3f} | CNN: {score_cnn:.3f} | Pkt: {score_pkt:.3f} | IF: {score_if:.3f} | LOF: {score_lof:.3f}")
    logger.print(f"   → Score final: {final_score:.4f}")
    
    return final_score


class ModelRefitMonitor:
    def __init__(
        self, 
        capture_path:str,
        session_id:str,
        model_path:str,
        mode:str = "full",
        refit_delay:int|float = 7 * 24 * 3600,
        epochs:int = 1,
        batch_size:int = 32, 
        verbose:int = 1,
        min_new_packets:int = 1_000_000,
     ):
        self.mode = mode
        self.event = threading.Event()
        self.monitor_thread = None
        self.refit_delay = refit_delay
        self.last_refit_time = time.time()
        self.session_id = session_id
        self.capture_path = capture_path
        self.is_in_refit = False
        self.epochs = epochs
        self.batch_size = batch_size
        self.verbose = verbose
        self.min_new_packets = min_new_packets
        self.model_path = model_path
        self.new_model_available = mp.Event() #threading.Event()
        
    def get_filenames(self):
        filenames = [
            path for path in os.listdir(REFIT_DIR) 
            if os.path.isfile(os.path.join(REFIT_DIR, path)) and str(path).startswith(FILE_PREFIX) \
            and str(path).endswith(".pkl") and self.session_id in path
        ]
            
        return [os.path.join(REFIT_DIR, filename) for filename in filenames]
    
    def get_all_pkt_from_files(self, filenames:list):
        all_pkt = []
        for filename in filenames:
            if os.path.exists(filename):
                try:
                    all_pkt.extend(joblib.load(filename))
                except Exception:
                    pass
        
        if os.path.exists(self.capture_path):
            try:
                all_pkt.extend(joblib.load(self.capture_path))
            except Exception:
                pass
            
        return all_pkt
                
    def process_data(self, pkt_list:list):
        try:
            extractor = FeatureExtractor()
            X_packets = np.array([extractor.extract_pack_features(pkt) for pkt in pkt_list])
            n_seq = X_packets.shape[0] - SEQ_LENGTH + 1 # Comme nombre d'éléments, fin - debut + 1
            if n_seq <= 0:
                raise ValueError("Pas assez de paquets pour une séquence !")
            seq_pkt = [X_packets[i : i + SEQ_LENGTH] for i in range(n_seq)]
            seq_lis = []
            #Extraire les features de sequances
            for seq in seq_pkt:
                try:
                    seq_fea = extractor.extract_seq_features(seq)
                    seq_lis.append(seq_fea)
                except Exception as e:
                    logger.print("Erreur extraction sequence :", str(e))
                    
            X_sequences = np.array(seq_lis)
            logger.print("[DEBUG] Avant nettoyage:")
            logger.print(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")
            logger.print(f"  Inf dans séquences: {np.isinf(X_sequences).sum()}")
            logger.print(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")
        
            # Nettoyer
            X_sequences = np.nan_to_num(X_sequences, nan=0.0, posinf=1.0, neginf=-1.0)
            X_packets = np.nan_to_num(X_packets, nan=0.0, posinf=1.0, neginf=-1.0)
        
            logger.print("[DEBUG] Après nettoyage:")
            logger.print(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")  # Doit être 0
            logger.print(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")
            
            scaler_pkt = StandardScaler()
            scaler_seq = StandardScaler()
            X_flat_seq = X_sequences.reshape(-1, X_sequences.shape[2]) #-1, 2 car la dim 2 = nombre de features de sequences
            X_packets_scaled = scaler_pkt.fit_transform(X_packets)
            scaler_seq.fit(X_flat_seq)
            X_sequences_scaled = np.array([scaler_seq.transform(seq) for seq in X_sequences])
            
            logger.print("[DEBUG] Après normalisation :")
            logger.print(f"  NaN dans séquences: {np.isnan(X_sequences_scaled).sum()}")
            logger.print(f"  Inf dans séquences: {np.isinf(X_sequences_scaled).sum()}")
            logger.print(f"  Min/Max: {X_sequences_scaled.min():.2f} / {X_sequences_scaled.max():.2f}")
        
            return X_sequences_scaled, scaler_seq, scaler_pkt, X_packets_scaled
        
        except Exception as e:
            logger.print("Erreur globale process_data :", str(e))
            return None, None, None, None
    
    def compare_models(self, old_model: dict, new_model: dict, X_seq: np.ndarray, X_pkt: np.ndarray) -> tuple[bool, dict]:
        """
        Compare deux modèles et décide lequel garder.
        """
        logger.print("\n" + "="*60)
        logger.print("🔬 COMPARAISON ANCIEN vs NOUVEAU MODÈLE")
        logger.print("="*60)
        
        logger.print("\n📊 ANCIEN MODÈLE :")
        old_score = _evaluate_model(old_model, X_seq, X_pkt)
        
        logger.print("\n📊 NOUVEAU MODÈLE :")
        new_score = _evaluate_model(new_model, X_seq, X_pkt)
        
        improvement = (new_score - old_score) / old_score if old_score > 0 else 0
        
        # Décision : garder le nouveau si amélioration > 2%
        keep_new = improvement >= 0.02
        
        logger.print("\n" + "="*60)
        logger.print("⚖️ DÉCISION")
        logger.print("="*60)
        logger.print(f"   Ancien score : {old_score:.4f}")
        logger.print(f"   Nouveau score : {new_score:.4f}")
        logger.print(f"   Amélioration : {improvement*100:.1f}%")
        logger.print(f"""   → {"🟢 CONSERVER LE NOUVEAU" if keep_new else "🔴 GARDER L'ANCIEN"}""")
        
        return keep_new, {'old_score': old_score, 'new_score': new_score, 'improvement': improvement}
    
    def _perform_refit(self, pkt_list:list):
        try:
            X_sequences, scaler_seq, scaler_pkt, X_packets = self.process_data(pkt_list)
            if any(x is None for x in [X_sequences, scaler_seq, scaler_pkt, X_packets]):
                return None
            
            X_sequences, X_seq_test = tts(X_sequences, test_size=0.2)
            X_packets, X_pkt_test = tts(X_packets, test_size=0.2)
            n_seq, seq_len, n_seq_features = X_sequences.shape
            n_pkt_features = X_packets.shape[1]
            logger.print("\n📊 Dimensions des données :")
            logger.print(f"   Séquences : {X_sequences.shape}")
            logger.print(f"   Paquets : {X_packets.shape}")

            # Construction et entraînement des modèles
            models = Models()
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.build_models(
                n_pkt=seq_len, n_seq_features=n_seq_features,
                n_pkt_features=n_pkt_features, mode=self.mode
            )
            self.is_in_refit = True
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.fit_models(
                ae_seq=ae_seq, cnn_seq=cnn_seq, if_seq=if_seq, lof_seq=lof_seq,
                ae_pkt=ae_pkt, if_pkt=if_pkt, lof_pkt=lof_pkt,
                X_sequences=X_sequences, X_packets=X_packets,
                epochs=self.epochs, batch_size=self.batch_size, verbose=self.verbose
            )
            new_model_dict = {
                'ae_seq': ae_seq, 'cnn_seq': cnn_seq,
                'if_seq': if_seq, 'lof_seq': lof_seq,
                'ae_pkt': ae_pkt, 'if_pkt': if_pkt, 'lof_pkt': lof_pkt,
                'scaler_seq': scaler_seq, 'scaler_pkt': scaler_pkt
            }
            try:
                old_model_dict = {}
                with open(self.model_path, "rb") as f:
                    old_model_dict = dill.load(f)
            except Exception as e:
                logger.print(f"Erreur chargement modèle : {e}")
                return
            
            keep_new, data = self.compare_models(old_model_dict, new_model_dict, X_seq_test, X_pkt_test)
            if keep_new:
                self.save_and_backup(new_model_dict)
                self.new_model_available.set()
            self.is_in_refit = False
            
        except Exception as e:
            logger.print("Erreur globale _perform_refit :", str(e))
            pass
        
    def save_and_backup(self, model_dict:dict):
        try:
            backup_path = self.model_path.replace(".pkl", "backup.pkl")
            shutil.copy2(self.model_path, backup_path)
            with open(self.model_path, "wb") as f:
                dill.dump(model_dict, f)
            return True
        except Exception:
            return False
        
    def _refit(self):
        while not self.event.is_set():
            if time.time() - self.last_refit_time > self.refit_delay:
                all_pkt = self.get_all_pkt_from_files(self.get_filenames())
                num_pkt = len(all_pkt)
                if not num_pkt > self.min_new_packets:
                    self.last_refit_time = time.time()
                    continue
                
                self._perform_refit(all_pkt)
                self.last_refit_time = time.time()
                
        
    def refit(self):
        self.monitor_thread = threading.Thread(
                target=self._refit, args=tuple(),
                daemon=True
            )
        self.monitor_thread.start()
    
    def start(self):
        self.refit()
        
    def stop(self):
        if self.is_in_refit:
            while self.is_in_refit:
                time.sleep(1)
                
        self.event.set()
        self.monitor_thread.join(1)
        