#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 10 05:47:43 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
"""
ShieldAI — Test rapide OVR vs ClassifierChain
Compare les deux wrappers sur des données fictives multi-label.
"""

import numpy as np
import pandas as pd
from sklearn.datasets import make_multilabel_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import ClassifierChain
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import f1_score, hamming_loss, jaccard_score, classification_report

# ── 1. Données fictives ──────────────────────────────────────────────────────
np.random.seed(42)

N_SAMPLES  = 500
N_FEATURES = 20
N_CLASSES  = 5
CLASS_NAMES = ["XSS", "SQLi", "CSRF", "CMDi", "InfoDisc"]

X, y = make_multilabel_classification(
    n_samples=N_SAMPLES,
    n_features=N_FEATURES,
    n_classes=N_CLASSES,
    n_labels=2,                # ~2 labels par échantillon
    random_state=42,
    allow_unlabeled=False,
)

print(f"X : {X.shape}")
print(f"y : {y.shape}")
print(f"Labels par sample (moy) : {y.sum(axis=1).mean():.1f}")
print(f"Samples multi-label : {(y.sum(axis=1) > 1).sum()}/{N_SAMPLES}")

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ── 2. Base estimator ────────────────────────────────────────────────────────
base = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)

# ── 3. OVR ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("OneVsRestClassifier")
print("=" * 50)

ovr = OneVsRestClassifier(base, n_jobs=-1)
ovr.fit(X_train, y_train)
y_pred_ovr = ovr.predict(X_test)
y_proba_ovr = ovr.predict_proba(X_test)

print(f"F1 micro  : {f1_score(y_test, y_pred_ovr, average='micro'):.4f}")
print(f"F1 macro  : {f1_score(y_test, y_pred_ovr, average='macro'):.4f}")
print(f"Hamming   : {hamming_loss(y_test, y_pred_ovr):.4f}")
print(f"Jaccard   : {jaccard_score(y_test, y_pred_ovr, average='samples'):.4f}")

# Afficher les 5 premières prédictions
print("\n5 premières prédictions OVR :")
for i in range(5):
    true_labels = [CLASS_NAMES[j] for j in range(N_CLASSES) if y_test[i][j]]
    pred_labels = [CLASS_NAMES[j] for j in range(N_CLASSES) if y_pred_ovr[i][j]]
    print(f"  Vrai: {true_labels or ['SAFE']}")
    print(f"  Prédit: {pred_labels or ['SAFE']}")
    probs = {CLASS_NAMES[j]: f"{y_proba_ovr[i][j]:.3f}" for j in range(N_CLASSES)}
    print(f"  Probas: {probs}")
    print()

# ── 4. ClassifierChain ───────────────────────────────────────────────────────
print("=" * 50)
print("ClassifierChain")
print("=" * 50)

chain = ClassifierChain(base, order="random", random_state=42)
chain.fit(X_train, y_train)
y_pred_chain = chain.predict(X_test)

print(f"F1 micro  : {f1_score(y_test, y_pred_chain, average='micro'):.4f}")
print(f"F1 macro  : {f1_score(y_test, y_pred_chain, average='macro'):.4f}")
print(f"Hamming   : {hamming_loss(y_test, y_pred_chain):.4f}")
print(f"Jaccard   : {jaccard_score(y_test, y_pred_chain, average='samples'):.4f}")

print("\n5 premières prédictions Chain :")
for i in range(5):
    true_labels = [CLASS_NAMES[j] for j in range(N_CLASSES) if y_test[i][j]]
    pred_labels = [CLASS_NAMES[j] for j in range(N_CLASSES) if y_pred_chain[i][j]]
    print(f"  Vrai: {true_labels or ['SAFE']}")
    print(f"  Prédit: {pred_labels or ['SAFE']}")
    print()

# ── 5. Comparatif ────────────────────────────────────────────────────────────
print("=" * 50)
print("COMPARATIF")
print("=" * 50)
print(f"{'Métrique':<15} {'OVR':<10} {'Chain':<10}")
print("-" * 35)
for metric_name, metric_fn in [
    ("F1 micro", lambda yt, yp: f1_score(yt, yp, average='micro')),
    ("F1 macro", lambda yt, yp: f1_score(yt, yp, average='macro')),
    ("Hamming", hamming_loss),
    ("Jaccard", lambda yt, yp: jaccard_score(yt, yp, average='samples')),
]:
    v_ovr = metric_fn(y_test, y_pred_ovr)
    v_chain = metric_fn(y_test, y_pred_chain)
    winner = "OVR" if v_ovr > v_chain else "Chain"
    print(f"{metric_name:<15} {v_ovr:<10.4f} {v_chain:<10.4f} → {winner}")