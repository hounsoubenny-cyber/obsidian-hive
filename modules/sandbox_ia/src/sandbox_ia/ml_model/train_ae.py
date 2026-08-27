#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 13 11:33:42 2026

@author: hounsousamuel
"""

import os
import sys
import numpy as np
import joblib as jb
import torch
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sandbox_ia.ml_model.autoencoders import AELoss, AutoEncoder
from sandbox_ia.ml_model.autoencoders_trainer import Trainer as AETrainer, compute_threshold, compute_reconstruction_errors
from sandbox_ia.ml_model.callbacks import EarlyStopping
from sandbox_ia.ml_model.model_dataset import SandBoxDataset
from torch.utils.data import DataLoader

BASEDIR = os.path.abspath(os.path.dirname(__file__))
DATASET_DIR = os.path.join(BASEDIR, "datasets")
DATASET_DIR_AE = os.path.join(DATASET_DIR, "ae")
DATASET_DIR_C = os.path.join(DATASET_DIR, "classifier")

MODEL_DIR = os.path.join(BASEDIR, "models")
AE_DIR = os.path.join(MODEL_DIR, "ae")
CLASSIFIER_DIR = os.path.join(MODEL_DIR, "classifier")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(AE_DIR, exist_ok=True)
os.makedirs(CLASSIFIER_DIR, exist_ok=True)
os.makedirs(DATASET_DIR_AE, exist_ok=True)
os.makedirs(DATASET_DIR_C, exist_ok=True)

X_train_path = os.path.join(DATASET_DIR_AE, "X_train.npy")
X_test_path = os.path.join(DATASET_DIR_AE, "X_test.npy")
X_val_path = os.path.join(DATASET_DIR_AE, "X_val.npy")
X_ebd_train_path = os.path.join(DATASET_DIR_AE, "X_ebd_train.npy")
X_ebd_test_path = os.path.join(DATASET_DIR_AE, "X_ebd_test.npy")
X_ebd_val_path = os.path.join(DATASET_DIR_AE, "X_ebd_val.npy")
scaler_path: str = os.path.join(AE_DIR, "scaler.joblib")
scaler_ebd_path: str = os.path.join(AE_DIR, "scaler_ebd.joblib")


X_train: np.ndarray = np.load(X_train_path)
X_test: np.ndarray = np.load(X_test_path)
X_val: np.ndarray = np.load(X_val_path)
X_ebd_train: np.ndarray = np.load(X_ebd_train_path)
X_ebd_test: np.ndarray = np.load(X_ebd_test_path)
X_ebd_val: np.ndarray = np.load(X_ebd_val_path)
scaler: StandardScaler = jb.load(scaler_path) # Déja fit
scaler_ebd: StandardScaler = jb.load(scaler_ebd_path) # Déja fit


# # Paramètres
# TEST_SIZE = 0.1
# VAL_SIZE = 0.1
# D_MODEL = 256
# NUM_HEADS = 8
# NUM_FEATURES = X_train.shape[-1] + 1  # Feature de X + 1 (1 pour ebd)
# FEED_FORWARD_FACTOR = 4
# DROPOUT = 0.2
# NUM_LAYER_PER_ENCODER_TRANSFORMER = 2
# NUM_LAYER_FOR_ENCODER_AND_DECODER = 4
# NUM_EMBEDDINGS = 100
# MAX_SEQ_LEN = 100

# PARAMS = dict(
#     num_features=NUM_FEATURES,
#     d_model=D_MODEL,
#     num_heads=NUM_HEADS,
#     feed_forward_factor=FEED_FORWARD_FACTOR,
#     dropout=DROPOUT,
#     num_layer_per_encoder_transformer=NUM_LAYER_PER_ENCODER_TRANSFORMER,
#     num_layer_for_encoder_and_decoder=NUM_LAYER_FOR_ENCODER_AND_DECODER,
#     num_embeddings=NUM_EMBEDDINGS,
#     max_seq_len=MAX_SEQ_LEN,
# )

# Paramètres
TEST_SIZE = 0.1
VAL_SIZE = 0.1
D_MODEL = 256 * 2
NUM_HEADS = 8
NUM_FEATURES = X_train.shape[-1] + 1  # Feature de X + 1 (1 pour ebd)
FEED_FORWARD_FACTOR = 4
DROPOUT = 0.2
NUM_LAYER_PER_ENCODER_TRANSFORMER = 4
NUM_LAYER_FOR_ENCODER_AND_DECODER = 4
NUM_EMBEDDINGS = 256
MAX_SEQ_LEN = 256

PARAMS = dict(
    num_features=NUM_FEATURES,
    d_model=D_MODEL,
    num_heads=NUM_HEADS,
    feed_forward_factor=FEED_FORWARD_FACTOR,
    dropout=DROPOUT,
    num_layer_per_encoder_transformer=NUM_LAYER_PER_ENCODER_TRANSFORMER,
    num_layer_for_encoder_and_decoder=NUM_LAYER_FOR_ENCODER_AND_DECODER,
    num_embeddings=NUM_EMBEDDINGS,
    max_seq_len=MAX_SEQ_LEN,
)

# =============================================================================
# Datasets & Dataloaders
# =============================================================================

# Pour un autoencodeur, la cible y = l'entrée X(X + X_ebd) elle-même (on reconstruit l'input)

def transform(scaler, X: np.ndarray):
    return scaler.transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)

X_train_scaled = transform(scaler, X_train)
X_test_scaled = transform(scaler, X_test)
X_val_scaled = transform(scaler, X_val)

X_ebd_train_scaled = scaler_ebd.transform(X_ebd_train)
X_ebd_test_scaled = scaler_ebd.transform(X_ebd_test)
X_ebd_val_scaled = scaler_ebd.transform(X_ebd_val)

X_final_train = np.concatenate([X_train_scaled, X_ebd_train_scaled[:, :, None]], axis=-1) # Dim des features, les donné scalés
X_final_val = np.concatenate([X_val_scaled, X_ebd_val_scaled[:, :, None]], axis=-1)
X_final_test = np.concatenate([X_test_scaled, X_ebd_test_scaled[:, :, None]], axis=-1)

train_dataset = SandBoxDataset(X=X_train_scaled, y=X_final_train, X_ebd=X_ebd_train)
val_dataset = SandBoxDataset(X=X_val_scaled, y=X_final_val, X_ebd=X_ebd_val)
test_dataset = SandBoxDataset(X=X_test_scaled, y=X_final_test, X_ebd=X_ebd_test)

BATCH_SIZE = 64
train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)


# ------------------------------------------------------------------
# Modèle, loss, optimizer, scheduler
# ------------------------------------------------------------------
model = AutoEncoder(**PARAMS)
loss_fn = AELoss()

EPOCHS = 20
LR = 5e-4
optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-5)
scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

early_stopping = EarlyStopping(patience=5, mode="min")

trainer = AETrainer(
    model=model,
    loss=loss_fn,
    optimizer=optimizer,
    scheduler=scheduler,
    each_epochs=True,
    compile_model=False,
    compile_loss=False,
)

# ------------------------------------------------------------------
# Entraînement
# ------------------------------------------------------------------
history = trainer.fit(
    dataloader=train_loader,
    valloader=val_loader,
    epochs=EPOCHS,
    plot_history=True,
    early_stopping=early_stopping,
)

# ------------------------------------------------------------------
# Évaluation finale sur le test set
# ------------------------------------------------------------------
print("\n🧪 Évaluation sur le test set :")
trainer.evaluate(test_loader)

# ------------------------------------------------------------------
# Sauvegarde du modèle
# ------------------------------------------------------------------
model_path = os.path.join(AE_DIR, "autoencoder_v2.pt")
model.save(model_path)

# Save history
jb.dump(history, os.path.join(AE_DIR, "history_v2.joblib"))

# Threashold

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

errors = compute_reconstruction_errors(trainer.model, val_loader, device)
thresholds = compute_threshold(errors)
jb.dump(thresholds, os.path.join(MODEL_DIR, "threshold_v2.joblib"))