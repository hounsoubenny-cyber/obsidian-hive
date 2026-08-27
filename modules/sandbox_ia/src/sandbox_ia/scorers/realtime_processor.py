#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 6 2026

@author: hounsousamuel

Processor temps réel pour la détection comportementale du Sandbox ShieldAI V2.

Reçoit les events un par un depuis la queue du sandbox et produit un score
de menace ML en temps réel. Fusionne le score séquentiel (AE + Classifier)
avec le score ponctuel (threat_score manuel) pour un score final 0-100.

Flow :
    event → FeatureExtractor → buffer
    Si buffer >= seq_len :
        → AE.is_anomaly()       → anomaly_score
        → Classifier.predict()  → prob_malware
        → score_séquentiel = 0.5 × anomaly_score + 0.5 × prob_malware
    score_final = 0.6 × score_séquentiel + 0.4 × threat_score_ponctuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import numpy as np
import torch
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from sklearn.preprocessing import RobustScaler

from sandbox_ia.tracers.fs_monitor import FSEvent
from sandbox_ia.tracers.syscall_tracer import SyscallEvent
from sandbox_ia.ml_model.features_extractor_v2 import FeatureExtractor
from sandbox_ia.ml_model.vocab import encode
from sandbox_ia.ml_model.autoencoders import AutoEncoder
from sandbox_ia.ml_model.classifier import Classifier
from sandbox_ia.sandbox_utils.logger import get_logger

logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ─────────────────────────────────────────────────────────────────────────────
# DATACLASS — Résultat de prédiction
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PredictionResult:
    """
    Résultat de prédiction pour un event.

    Attributes
    ----------
    timestamp : datetime
        Horodatage de la prédiction.
    threat_score_manual : int
        Score manuel du BehaviorScorer (0-100).
    anomaly_score : float | None
        Score d'anomalie AE (0-1). None si buffer pas encore plein.
    prob_malware : float | None
        Probabilité malware du Classifier (0-1). None si buffer pas plein.
    score_sequential : float | None
        Score séquentiel fusionné AE + Classifier (0-100). None si buffer vide.
    score_final : float
        Score final fusionné manuel + séquentiel (0-100).
    ml_active : bool
        True si le buffer est plein et les modèles ML sont actifs.
    """
    timestamp: datetime
    threat_score_manual: int
    anomaly_score: float | None
    prob_malware: float | None
    score_sequential: float | None
    score_final: float
    ml_active: bool
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "threat_score_manual": self.threat_score_manual,
            "anomaly_score": self.anomaly_score,
            "prob_malware": self.prob_malware,
            "score_sequential": self.score_sequential,
            "score_final": self.score_final,
            "ml_active": self.ml_active,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "PredictionResult":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            threat_score_manual=data["threat_score_manual"],
            anomaly_score=data["anomaly_score"],
            prob_malware=data["prob_malware"],
            score_sequential=data["score_sequential"],
            score_final=data["score_final"],
            ml_active=data["ml_active"],
        )


# ─────────────────────────────────────────────────────────────────────────────
# REALTIME PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class RealtimeProcessor:
    """
    Processor temps réel pour la détection comportementale ML.

    Maintient un buffer glissant des events et déclenche les modèles ML
    dès que le buffer est plein. Fusionne le score ML avec le score manuel
    du BehaviorScorer pour un score final robuste.

    Attributes
    ----------
    ae : AutoEncoder
        Modèle AutoEncoder pour la détection d'anomalie.
    classifier : Classifier
        Modèle Classifier pour la prédiction binaire.
    extractor : FeatureExtractor
        Extracteur de features stateful.
    scaler : RobustScaler
        Scaler fitted sur les données d'entraînement.
    seq_len : int
        Taille du buffer / longueur de séquence.
    weight_sequential : float
        Poids du score séquentiel dans la fusion finale.
    weight_manual : float
        Poids du score manuel dans la fusion finale.
    _buffer : deque
        Buffer glissant des features extraites.
    _ebd_buffer : deque
        Buffer glissant des indices syscall.
    _n_events : int
        Compteur total d'events traités.
    """

    def __init__(
        self,
        ae: AutoEncoder,
        classifier: Classifier,
        extractor: FeatureExtractor,
        scaler_classifier: RobustScaler,
        scaler_ae: RobustScaler,
        scaler_ebd_ae: RobustScaler,
        seq_len: int = 100,
        weight_sequential: float = 0.6,
        weight_manual: float = 0.4,
        anomaly_threshold: float | None = None
    ):
        self.ae = ae
        self.classifier = classifier
        self.extractor = extractor
        self.scaler_classifier = scaler_classifier
        self.scaler_ebd_ae = scaler_ebd_ae
        self.scaler_ae = scaler_ae
        self.seq_len = seq_len
        self.weight_sequential = weight_sequential
        self.weight_manual = weight_manual
        self.anomaly_threshold = anomaly_threshold

        self._buffer: deque = deque(maxlen=seq_len)
        self._ebd_buffer: deque = deque(maxlen=seq_len)
        self._n_events: int = 0
        
        self.ae.eval()
        self.classifier.eval()

        feature_names = self.extractor.get_feature_names()
        self._feature_names = [f for f in feature_names if f != "syscall"]
        self._n_features    = len(self._feature_names)

    # ─────────────────────────────────────────────────────────────────────
    # PROCESS
    # ─────────────────────────────────────────────────────────────────────

    def process(
        self,
        event: FSEvent | SyscallEvent,
        threat_score_manual: int,
    ) -> PredictionResult:
        """
        Traite un event et retourne un score de menace.

        Parameters
        ----------
        event : FSEvent | SyscallEvent
            Event courant à analyser.
        threat_score_manual : int
            Score manuel du BehaviorScorer pour cet event (0-100).

        Returns
        -------
        PredictionResult
            Résultat de prédiction avec score final fusionné.
        """
        self._n_events += 1

        features = self.extractor.extract(event)

        syscall_idx = encode(features["syscall"])
        feature_vec = np.array(
            [features[f] for f in self._feature_names],
            dtype=np.float32
        )
        feature_vec = np.nan_to_num(feature_vec, neginf=0)

        self._buffer.append(feature_vec)
        self._ebd_buffer.append(syscall_idx)

        ml_active = len(self._buffer) >= self.seq_len
        anomaly_score = None
        prob_malware = None
        score_sequential = None

        if ml_active:
            anomaly_score, prob_malware = self._predict_sequence()
            score_sequential = (0.5 * anomaly_score + 0.5 * prob_malware) * 100

        if score_sequential is not None:
            score_final = (
                self.weight_sequential * score_sequential
                + self.weight_manual   * threat_score_manual
            )
        else:
            score_final = float(threat_score_manual)

        score_final = min(max(score_final, 0.0), 100.0)

        return PredictionResult(
            timestamp           = datetime.utcnow(),
            threat_score_manual = threat_score_manual,
            anomaly_score       = anomaly_score,
            prob_malware        = prob_malware,
            score_sequential    = score_sequential,
            score_final         = score_final,
            ml_active           = ml_active,
        )

    def _predict_sequence(self) -> tuple[float, float]:
        """
        Prédit sur la séquence courante du buffer.

        Returns
        -------
        tuple[float, float]
            (anomaly_score, prob_malware) tous deux entre 0 et 1.
        """
        X = np.array(list(self._buffer), dtype=np.float32)   # (seq_len, n_features)
        X_ebd = np.array(list(self._ebd_buffer), dtype=np.int32) # (seq_len,)

        X_scaled = self.scaler_classifier.transform(X).astype(np.float32)   # (seq_len, n_features)

        with torch.inference_mode():
            if self.anomaly_threshold is not None:
                
                X_scaled_ae = self.scaler_ae.transform(X).astype(np.float32)   # (seq_len, n_features)
                X_ebd_scaled_ae = self.scaler_ebd_ae.transform(X).astype(np.float32)   # (seq_len,)
                # Ajouter dimension batch → (1, seq_len, n_features), (1, seq_len)
                X_tensor_ae     = torch.tensor(X_scaled_ae).unsqueeze(0).to(DEVICE)
                X_ebd_tensor_ae = torch.tensor(X_ebd_scaled_ae).unsqueeze(0).to(DEVICE)
                initial_x = torch.concat(
                    (X_tensor_ae, X_ebd_tensor_ae.unsqueeze(-1)),
                    dim=-1
                )
                mse, mae = self.ae.predict(initial_x=initial_x, x=X_tensor_ae, x_ebd=X_ebd_tensor_ae)
                error = mse + mae + torch.sqrt(mse)
                anomaly_score = min(error / self.anomaly_threshold, 1.0)
            else:
                anomaly_score = 0.0
            
            # Ajouter dimension batch → (1, seq_len, n_features), (1, seq_len)
            X_tensor     = torch.tensor(X_scaled).unsqueeze(0).to(DEVICE)
            X_ebd_tensor = torch.tensor(X_ebd).unsqueeze(0).to(DEVICE)
            prob, _ = self.classifier.predict(X_ebd_tensor, X_tensor)
            # prob shape : (1, 2) → prendre prob classe 1 (malveillant)
            if prob.shape[-1] == 2:
                prob_malware = float(prob[0, 1].cpu())
            else:
                prob_malware = float(prob[0].cpu())

        return anomaly_score, prob_malware

    # ─────────────────────────────────────────────────────────────────────
    # RESET
    # ─────────────────────────────────────────────────────────────────────

    def reset(self) -> None:
        """
        Remet le processor à zéro pour une nouvelle session.

        Vide le buffer et remet le FeatureExtractor à zéro.
        À appeler entre deux sessions sandbox.
        """
        self._buffer.clear()
        self._ebd_buffer.clear()
        self._n_events = 0
        self.extractor.reset()
        logger.print("🔄 RealtimeProcessor réinitialisé")

    # ─────────────────────────────────────────────────────────────────────
    # STATS
    # ─────────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        """Retourne les statistiques du processor."""
        return {
            "n_events":      self._n_events,
            "buffer_size":   len(self._buffer),
            "buffer_full":   len(self._buffer) >= self.seq_len,
            "ml_active":     len(self._buffer) >= self.seq_len,
            "ae_threshold":  self.ae.anomaly_threshold,
        }