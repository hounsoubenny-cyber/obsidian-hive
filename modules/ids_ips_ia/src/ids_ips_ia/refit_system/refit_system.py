#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 10:12:52 2026

@author: hounsousamuel

Corrections par rapport à l'ancienne version (voir aussi les commentaires "CORRECTION") :

 1. LE REFIT NE TOURNAIT JAMAIS : _run_refit_manager appelait start(), qui lance un thread
    DAEMON puis retourne. Le processus se terminait aussitôt et tuait le thread.
    -> run(stop_event) BLOQUE dans le processus jusqu'à ce que l'événement soit levé.
 2. _refit() tournait en boucle sans aucune pause (100 % d'un cœur) : maintenant _wait().
 3. is_in_refit restait à True si le refit échouait, donc stop() bloquait pour toujours :
    maintenant try/finally.
 4. L'ancien modèle est chargé AVANT d'entraîner (avant : on entraînait pendant des heures,
    puis on découvrait qu'il ne se chargeait pas).
 5. Comparaison ancien / nouveau : chaque modèle est évalué avec SES propres scalers
    (avant : l'ancien modèle recevait des données normalisées avec les scalers du nouveau).
 6. Les séquences se chevauchent : le split aléatoire mettait dans le test des fenêtres
    qui chevauchent celles de l'entraînement (le nouveau modèle les avait "déjà vues").
    -> split chronologique avec un trou, et scalers ajustés sur l'entraînement seulement.
 7. Sauvegarde du modèle atomique (tmp + os.replace) ; l'événement new_model_available
    n'est levé que si la sauvegarde a réussi.
 8. Les fichiers sont lus UNE fois (avant : deux fois, une pour compter, une pour charger),
    triés par date de modification.
"""

import os
import math
import time
import dill
import shutil
import traceback
import threading
import numpy as np
import multiprocessing as mp
from ids_ips_ia.models.models import Models
from sklearn.preprocessing import StandardScaler
from ids_ips_ia.core.capture import load_pkt_file
from ids_ips_ia.ids_ips_utils.logger import get_logger
from sklearn.model_selection import train_test_split as tts
from ids_ips_ia.core.features_extractor import FeatureExtractor
from ids_ips_ia.config.config_ids import SEQ_LENGTH, SEQ_STRIDE_FIT, n_windows
from ids_ips_ia.refit_system.config import FILE_PREFIX, REFIT_DIR

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
    
    logger.info(f"   AE: {score_ae:.3f} | CNN: {score_cnn:.3f} | Pkt: {score_pkt:.3f} | IF: {score_if:.3f} | LOF: {score_lof:.3f}")
    logger.info(f"   → Score final: {final_score:.4f}")
    
    return final_score


def _scale_seq(scaler: StandardScaler, X_sequences: np.ndarray) -> np.ndarray:
    """Applique un scaler 2D à des séquences (n, longueur, features) d'un seul coup."""
    n_features = X_sequences.shape[-1]
    flat = X_sequences.reshape(-1, n_features)
    return scaler.transform(flat).reshape(X_sequences.shape)


class ModelRefitMonitor:
    def __init__(
        self, 
        capture_path: str,
        session_id: str,
        model_path: str,
        mode: str = "full",
        refit_delay: int | float = 7 * 24 * 3600,
        epochs: int = 1,
        batch_size: int = 32, 
        verbose: int = 1,
        min_new_packets: int = 1_000_000,
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
        self._stop_mp = None          # événement d'arrêt venant de l'orchestrator (mode processus)
    
    # ------------------------------------------------------------------ arrêt
    def _should_stop(self) -> bool:
        return self.event.is_set() or (self._stop_mp is not None and self._stop_mp.is_set())
    
    def _wait(self, seconds: float) -> bool:
        """Attend `seconds` (par pas de 1 s) sans consommer de CPU.
        Renvoie True si on doit s'arrêter. (CORRECTION : l'ancienne boucle n'attendait pas.)"""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self._should_stop():
                return True
            self.event.wait(min(1.0, max(0.0, end - time.monotonic())))
        return self._should_stop()
    
    # ---------------------------------------------------------------- fichiers
    def get_filenames(self):
        filenames = [
            os.path.join(REFIT_DIR, path) for path in os.listdir(REFIT_DIR) 
            if os.path.isfile(os.path.join(REFIT_DIR, path)) and str(path).startswith(FILE_PREFIX) \
            and str(path).endswith(".pkl") and self.session_id in path
        ]
        # du plus ancien au plus récent (os.listdir ne donne aucun ordre)
        return sorted(filenames, key=os.path.getmtime)
    
    @staticmethod
    def _read_packets_from(path: str, out: list):
        """Ajoute à `out` tous les paquets d'un fichier (un fichier abîmé ne bloque pas les autres)."""
        if not os.path.exists(path):
            return
        try:
            for chunk in load_pkt_file(path):
                out.extend(chunk)
        except Exception as e:
            logger.error(f"Fichier illisible ou tronqué ({path}) : {e!r}")
    
    def _collect_packets(self) -> list:
        """Lit les paquets UNE seule fois. Ordre : fichier capture_path d'abord (supposé
        plus ancien), puis les fichiers de la session du plus ancien au plus récent."""
        all_pkt = []
        self._read_packets_from(self.capture_path, all_pkt)
        for filename in self.get_filenames():
            self._read_packets_from(filename, all_pkt)
        return all_pkt
    
    def get_all_pkt_from_files(self, filenames: list, len_only: bool = True):
        """Gardée pour compatibilité (même comportement qu'avant)."""
        all_pkt = []
        for filename in filenames:
            self._read_packets_from(filename, all_pkt)
        self._read_packets_from(self.capture_path, all_pkt)
        return len(all_pkt) if len_only else all_pkt
    
    # -------------------------------------------------------------- features
    def extract_features(self, pkt_list: list):
        """Features NON normalisées : (X_sequences, X_packets), ou (None, None) si échec."""
        try:
            extractor = FeatureExtractor()
            X_packets = np.array([extractor.extract_pack_features(pkt) for pkt in pkt_list])
            n_seq = n_windows(X_packets.shape[0], SEQ_LENGTH, SEQ_STRIDE_FIT)  # (N - L) // stride + 1
            if n_seq <= 0:
                raise ValueError("Pas assez de paquets pour une séquence !")
            seq_pkt = [X_packets[k * SEQ_STRIDE_FIT : k * SEQ_STRIDE_FIT + SEQ_LENGTH] for k in range(n_seq)]
            seq_lis = []
            # Extraire les features de séquences
            for seq in seq_pkt:
                try:
                    seq_fea = extractor.extract_seq_features(seq)
                    seq_lis.append(seq_fea)
                except Exception as e:
                    logger.error("Erreur extraction sequence :", str(e))
                    
            X_sequences = np.array(seq_lis)
            logger.info("[DEBUG] Avant nettoyage:")
            logger.info(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")
            logger.info(f"  Inf dans séquences: {np.isinf(X_sequences).sum()}")
            logger.info(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")
        
            # Nettoyer
            X_sequences = np.nan_to_num(X_sequences, nan=0.0, posinf=1.0, neginf=-1.0)
            X_packets = np.nan_to_num(X_packets, nan=0.0, posinf=1.0, neginf=-1.0)
        
            logger.info("[DEBUG] Après nettoyage:")
            logger.info(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")  # Doit être 0
            logger.info(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")
            return X_sequences, X_packets
        
        except Exception as e:
            logger.error("Erreur globale extract_features :", str(e))
            return None, None
    
    @staticmethod
    def _split_sequences(X_sequences: np.ndarray, test_size: float = 0.2):
        """CORRECTION : split CHRONOLOGIQUE (le test = les séquences les plus récentes) avec
        un trou. Les fenêtres i et j se chevauchent si |i - j| * stride < longueur : on
        retire de l'entraînement celles qui chevauchent la première fenêtre de test."""
        n = len(X_sequences)
        n_test = max(1, int(n * test_size))
        gap = math.ceil(SEQ_LENGTH / SEQ_STRIDE_FIT)       # écart minimal sans chevauchement
        first_test = n - n_test
        n_train = first_test - gap + 1
        if n_train < 1:
            raise ValueError(f"Pas assez de séquences pour séparer entraînement et test ({n})")
        return X_sequences[:n_train], X_sequences[first_test:]
    
    # ------------------------------------------------------------ comparaison
    def compare_models(self, old_model: dict, new_model: dict, X_seq_raw: np.ndarray, X_pkt_raw: np.ndarray) -> tuple[bool, dict]:
        """
        Compare deux modèles et décide lequel garder.
        X_seq_raw / X_pkt_raw : données de test NON normalisées. Chaque modèle les reçoit
        normalisées avec SES scalers (CORRECTION).
        """
        logger.info("\n" + "="*60)
        logger.info("🔬 COMPARAISON ANCIEN vs NOUVEAU MODÈLE")
        logger.info("="*60)
        
        new_seq = _scale_seq(new_model['scaler_seq'], X_seq_raw)
        new_pkt = new_model['scaler_pkt'].transform(X_pkt_raw)
        if 'scaler_seq' in old_model and 'scaler_pkt' in old_model:
            old_seq = _scale_seq(old_model['scaler_seq'], X_seq_raw)
            old_pkt = old_model['scaler_pkt'].transform(X_pkt_raw)
        else:
            logger.info("⚠️ L'ancien modèle n'a pas ses scalers : comparaison avec ceux du nouveau")
            old_seq, old_pkt = new_seq, new_pkt
        
        logger.info("\n📊 ANCIEN MODÈLE :")
        old_score = _evaluate_model(old_model, old_seq, old_pkt)
        
        logger.info("\n📊 NOUVEAU MODÈLE :")
        new_score = _evaluate_model(new_model, new_seq, new_pkt)
        
        improvement = (new_score - old_score) / old_score if old_score > 0 else 0
        
        # Décision : garder le nouveau si amélioration > 2%
        keep_new = improvement >= 0.02
        
        logger.info("\n" + "="*60)
        logger.info("⚖️ DÉCISION")
        logger.info("="*60)
        logger.info(f"   Ancien score : {old_score:.4f}")
        logger.info(f"   Nouveau score : {new_score:.4f}")
        logger.info(f"   Amélioration : {improvement*100:.1f}%")
        logger.info(f"""   → {"🟢 CONSERVER LE NOUVEAU" if keep_new else "🔴 GARDER L'ANCIEN"}""")
        
        return keep_new, {'old_score': old_score, 'new_score': new_score, 'improvement': improvement}
    
    # ----------------------------------------------------------------- refit
    def _load_model(self):
        try:
            with open(self.model_path, "rb") as f:
                return dill.load(f)
        except Exception as e:
            logger.error(f"Erreur chargement modèle : {e}")
            return None
    
    def _perform_refit(self, pkt_list: list) -> bool:
        """Entraîne un nouveau modèle et le compare à l'ancien. True = le nouveau est installé."""
        self.is_in_refit = True
        try:
            # CORRECTION : on vérifie l'ancien modèle AVANT de perdre des heures à entraîner
            old_model_dict = self._load_model()
            if old_model_dict is None:
                return False
            
            X_seq_raw, X_pkt_raw = self.extract_features(pkt_list)
            if X_seq_raw is None or X_pkt_raw is None:
                return False
            
            # Séquences : split chronologique avec trou. Paquets : lignes indépendantes, split aléatoire.
            X_seq_train_raw, X_seq_test_raw = self._split_sequences(X_seq_raw)
            X_pkt_train_raw, X_pkt_test_raw = tts(X_pkt_raw, test_size=0.2)
            
            # Scalers ajustés sur l'ENTRAÎNEMENT seulement
            scaler_seq = StandardScaler().fit(X_seq_train_raw.reshape(-1, X_seq_train_raw.shape[2]))
            scaler_pkt = StandardScaler().fit(X_pkt_train_raw)
            X_sequences = _scale_seq(scaler_seq, X_seq_train_raw)
            X_packets = scaler_pkt.transform(X_pkt_train_raw)
            
            n_seq, seq_len, n_seq_features = X_sequences.shape
            n_pkt_features = X_packets.shape[1]
            logger.info("\n📊 Dimensions des données :")
            logger.info(f"   Séquences : {X_sequences.shape} (test : {X_seq_test_raw.shape})")
            logger.info(f"   Paquets : {X_packets.shape} (test : {X_pkt_test_raw.shape})")

            # Construction et entraînement des modèles
            models = Models()
            ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.build_models(
                n_pkt=seq_len, n_seq_features=n_seq_features,
                n_pkt_features=n_pkt_features, mode=self.mode
            )
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
            
            keep_new, data = self.compare_models(
                old_model_dict, new_model_dict, X_seq_test_raw, X_pkt_test_raw
            )
            if keep_new:
                if self.save_and_backup(new_model_dict):
                    self.new_model_available.set()
                    return True
                logger.info("⚠️ Le nouveau modèle est meilleur mais n'a pas pu être sauvegardé")
            return False
            
        except Exception as e:
            logger.error("Erreur globale _perform_refit :", str(e))
            logger.error(traceback.format_exc())
            return False
        finally:
            self.is_in_refit = False     # CORRECTION : toujours remis à False, même en cas d'échec
    
    def save_and_backup(self, model_dict: dict) -> bool:
        """Sauvegarde ATOMIQUE : le détecteur ne lit jamais un modèle à moitié écrit."""
        tmp = f"{self.model_path}.tmp"
        try:
            root, ext = os.path.splitext(self.model_path)
            backup_path = f"{root}backup{ext}"
            shutil.copy2(self.model_path, backup_path)
            with open(tmp, "wb") as f:
                dill.dump(model_dict, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.model_path)
            return True
        except Exception as e:
            logger.error("Erreur sauvegarde modèle :", str(e))
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            return False
    
    def _refit(self):
        while not self._should_stop():
            if time.time() - self.last_refit_time > self.refit_delay:
                all_pkt = self._collect_packets()          # CORRECTION : une seule lecture
                n_pkt = len(all_pkt)
                if n_pkt > self.min_new_packets:
                    self._perform_refit(all_pkt)
                else:
                    logger.info(f"Refit ignoré : {n_pkt} paquets (minimum {self.min_new_packets})")
                del all_pkt
                self.last_refit_time = time.time()
            self._wait(120)
    
    # ------------------------------------------------------------ démarrage
    def run(self, stop_event=None):
        """MODE PROCESSUS : à appeler dans le processus de refit. BLOQUE jusqu'à ce que
        `stop_event` (un mp.Event) soit levé.
        CORRECTION : start() lance un thread daemon et retourne, donc le processus se
        terminait aussitôt et le refit ne tournait jamais."""
        self._stop_mp = stop_event
        self._refit()
    
    def refit(self):
        self.monitor_thread = threading.Thread(
                target=self._refit, args=tuple(),
                daemon=True
            )
        self.monitor_thread.start()
    
    def start(self):
        """MODE THREAD : lance la boucle dans un thread (le processus doit rester vivant)."""
        self.refit()
        
    def stop(self, timeout: float | None = None):
        """MODE THREAD : demande l'arrêt, puis attend (au plus `timeout` s, None = sans
        limite) la fin d'un refit en cours. Dans le MODE PROCESSUS, c'est stop_event qu'on lève."""
        self.event.set()
        if self.monitor_thread:
            t0 = time.time()
            while self.is_in_refit and (timeout is None or time.time() - t0 < timeout):
                time.sleep(1)
            try:
                self.monitor_thread.join(1)
            except Exception:
                pass