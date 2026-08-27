#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 13 17:42:45 2026

@author: hounsousamuel
"""

import os
import sys
import numpy as np
import joblib as jb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


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

X_path = os.path.join(DATASET_DIR, "X_seq.npy")
y_path = os.path.join(DATASET_DIR, "y.npy")
X_ebd_path = os.path.join(DATASET_DIR, "X_ebd.npy")


X: np.ndarray = np.load(X_path)
y: np.ndarray = np.load(y_path)
X_ebd: np.ndarray = np.load(X_ebd_path)


# Paramètres
TEST_SIZE = 0.1
VAL_SIZE = 0.1
D_MODEL = 256
NUM_HEADS = 8
NUM_FEATURES = X.shape[-1] + 1  # Feature de X + 1 (1 pour ebd)
FEED_FORWARD_FACTOR = 4
DROPOUT = 0.2
NUM_LAYER_PER_ENCODER_TRANSFORMER = 2
NUM_LAYER_FOR_ENCODER_AND_DECODER = 4
NUM_EMBEDDINGS = 100
MAX_SEQ_LEN = 100

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

# ------------------------------------------------------------------
# Split train / val / test 
# ------------------------------------------------------------------

# CLASSIFIER
# Avec mm random state, mm résultat sur mm données !

X_train, X_test = train_test_split(X, test_size=TEST_SIZE, random_state=42)
X_train, X_val = train_test_split(X_train, test_size=VAL_SIZE, random_state=42)

X_ebd_train, X_ebd_test = train_test_split(X_ebd, test_size=TEST_SIZE, random_state=42)
X_ebd_train, X_ebd_val = train_test_split(X_ebd_train, test_size=VAL_SIZE, random_state=42)
y_train, y_test = train_test_split(y, test_size=TEST_SIZE, random_state=42)
y_train, y_val = train_test_split(y_train, test_size=VAL_SIZE, random_state=42)

np.save(os.path.join(DATASET_DIR_C, "X_train.npy"), X_train)
np.save(os.path.join(DATASET_DIR_C, "X_test.npy"), X_test)
np.save(os.path.join(DATASET_DIR_C, "X_val.npy"), X_val)
np.save(os.path.join(DATASET_DIR_C, "X_ebd_train.npy"), X_ebd_train)
np.save(os.path.join(DATASET_DIR_C, "X_ebd_test.npy"), X_ebd_test)
np.save(os.path.join(DATASET_DIR_C, "X_ebd_val.npy"), X_ebd_val)
np.save(os.path.join(DATASET_DIR_C, "y_train.npy"), y_train)
np.save(os.path.join(DATASET_DIR_C, "y_test.npy"), y_test)
np.save(os.path.join(DATASET_DIR_C, "y_val.npy"), y_val)

print(f"📊 Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")



# Les scaler, (remettre les trucs en ordre)
new_scaler = StandardScaler()  # Scaler global (pour le classifier)
X_train_scaled = new_scaler.fit_transform(X_train.reshape(-1, X_train.shape[-1])).reshape(X_train.shape)

# save
jb.dump(new_scaler, os.path.join(CLASSIFIER_DIR, "scaler.joblib"))



# AE
# Filtrer pour garder juste safe (0 = safe) -> l'AE n'apprend QUE le comportement "normal"
safe_mask = y == 0
X: np.ndarray = X[safe_mask]
X_ebd: np.ndarray = X_ebd[safe_mask]

X_train, X_test = train_test_split(X, test_size=TEST_SIZE, random_state=42)
X_train, X_val = train_test_split(X_train, test_size=VAL_SIZE, random_state=42)

X_ebd_train, X_ebd_test = train_test_split(X_ebd, test_size=TEST_SIZE, random_state=42)
X_ebd_train, X_ebd_val = train_test_split(X_ebd_train, test_size=VAL_SIZE, random_state=42)

new_scaler_ae = StandardScaler()  # Scaler global (pour le ae)
X_train_scaled = new_scaler_ae.fit_transform(X_train.reshape(-1, X_train.shape[-1])).reshape(X_train.shape)
new_scaler_ebd_ae = StandardScaler()  # Scaler ebd (pour le ae)
X_ebd_train_scaled = new_scaler_ebd_ae.fit_transform(X_ebd_train)

np.save(os.path.join(DATASET_DIR_AE, "X_train.npy"), X_train)
np.save(os.path.join(DATASET_DIR_AE, "X_test.npy"), X_test)
np.save(os.path.join(DATASET_DIR_AE, "X_val.npy"), X_val)
np.save(os.path.join(DATASET_DIR_AE, "X_ebd_train.npy"), X_ebd_train)
np.save(os.path.join(DATASET_DIR_AE, "X_ebd_test.npy"), X_ebd_test)
np.save(os.path.join(DATASET_DIR_AE, "X_ebd_val.npy"), X_ebd_val)


# save
jb.dump(new_scaler_ae, os.path.join(AE_DIR, "scaler.joblib"))
jb.dump(new_scaler_ebd_ae, os.path.join(AE_DIR, "scaler_ebd.joblib"))
