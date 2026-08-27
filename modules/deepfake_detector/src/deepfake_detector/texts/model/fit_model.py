#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 14 14:14:38 2026

@author: hounsousamuel
"""

import pandas as pd
from sklearn.model_selection import train_test_split as tts
from deepfake_detector.texts.model.deepfake_text_pipeline import (
    DeepFakeDetectorTextTrain, DeepFakeDetectorTextPredict, logger
)

logger.print("=== Test Pipeline TrustSignal Text ===\n")
path = "/run/media/hounsousamuel/Windows/Utilitaire_windows/DEEPFAKE/TEXT/datasets/COMBINED/dataset_val.csv"
df = pd.DataFrame(pd.read_csv(path))
df.loc[:, "label"] = df.loc[:, "label"].apply(lambda x: 1 if x == "ai" else 0)
train_df, val_df = tts(df, test_size=0.99)
train_df = train_df.reset_index(drop=True)
val_df = val_df.reset_index(drop=True)
# ── Train ─────────────────────────────────────────────────────────────────
trainer = DeepFakeDetectorTextTrain(
    model_type = "fast",
    save_dir   = "/home/hounsousamuel/PROJETS/deepfake_detector/texts/model/models",
)

# Juste le ML pour tester rapidement sans GPU
trainer.fit_all(train_df, val_df) # ← décommenter pour full pipeline
trainer.save()
# Charger le modèle sauvegardé
predictor = DeepFakeDetectorTextPredict.from_directory(
    directory="/home/hounsousamuel/PROJETS/deepfake_detector/texts/model/models",
    model_type="fast"
)

# Tester
result = predictor("L'intelligence artificielle révolutionne le monde.")
print(result)  # → {'label': 'AI', 'confidence': ..., 'score': ...}

result = predictor("Je suis allé au marché ce matin.")
print(result)  # → {'label': 'Human', 'confidence': ..., 'score': ...}

# trainer.fit_model(train_df, val_df)

logger.print("Pipeline initialisé avec succès ✅")
logger.print("Décommenter fit_all() pour lancer l'entraînement complet.")