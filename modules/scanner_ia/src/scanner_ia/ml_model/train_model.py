#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 14 06:02:30 2026

@author: hounsousamuel
"""

"""
train_model.py — Pipeline d'entraînement scanner_ia (ShieldAI / ObsidianHive)

Étapes :
  1. Charger le dataset (CSV)
  2. Construire X (features numériques) et y (liste de labels, "SAFE" -> [])
  3. Split stratifié multi-label (MultilabelStratifiedShuffleSplit) — AVANT tout
     upsampling, pour ne jamais laisser de synthétiques contaminer le test
  4. Binariser les labels (MultiLabelBinarizer, classes=VULNS)
  5. Upsampling MLSOL sur le TRAIN uniquement (mlsol.py)
  6. Instancier ScannerIA, fit
  7. Évaluer sur le TEST ORIGINAL (jamais vu, jamais upsamplé) avec toutes
     les métriques multi-label
  8. Générer un rapport (JSON + texte lisible + matrices de confusion)

Usage:
    python train_model.py --data ./dataset/dataset.csv
    python train_model.py --data ./dataset/dataset.csv --optimize --n-trial 30
"""

import argparse
import ast
import json
import os
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import (
    f1_score, hamming_loss, jaccard_score,
    classification_report, multilabel_confusion_matrix,
)
from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit

from mlsol import mlsol_resample

from scanner_ia.ml_model.scanner_ia_v2 import ScannerIA
from scanner_ia.ml_model.config import VULNS, FEATURES_LIST


def load_xy(path: str):
    """Charge le CSV et construit X (numérique) et y (liste de labels, SAFE -> [])."""
    df = pd.read_csv(path)

    X_cols = [c for c in df.columns if c in FEATURES_LIST]
    X = df[X_cols].fillna(0).replace([np.inf, -np.inf], 0).to_numpy()

    def parse_labels(raw):
        labels = ast.literal_eval(raw) if isinstance(raw, str) else raw
        labels = (lambda x: [x] if isinstance(x, (str, int, float)) else x)(labels)
        return [l for l in labels if l != "SAFE"]  # SAFE déduit, jamais un label

    y_list = df["labels"].apply(parse_labels).tolist()
    return X, y_list, X_cols


def stratified_split(X: np.ndarray, Y_bin: np.ndarray, test_size: float, random_state: int):
    splitter = MultilabelStratifiedShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_idx, test_idx = next(splitter.split(X, Y_bin))
    return train_idx, test_idx


def build_report(y_true: np.ndarray, y_pred: np.ndarray, class_names: list) -> dict:
    return {
        "generated_at": datetime.now().isoformat(),
        "n_test_samples": int(len(y_true)),
        "f1_micro": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_samples": float(f1_score(y_true, y_pred, average="samples", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "hamming_loss": float(hamming_loss(y_true, y_pred)),
        "jaccard_samples": float(jaccard_score(y_true, y_pred, average="samples", zero_division=0)),
        "per_class_report": classification_report(
            y_true, y_pred, target_names=class_names, zero_division=0, output_dict=True
        ),
    }


def save_report(report: dict, y_true: np.ndarray, y_pred: np.ndarray, class_names: list, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(out_dir, f"report_{stamp}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    txt_path = os.path.join(out_dir, f"report_{stamp}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("RAPPORT D'ÉVALUATION — scanner_ia\n")
        f.write("=" * 70 + "\n")
        f.write(f"Généré le    : {report['generated_at']}\n")
        f.write(f"Échantillons de test : {report['n_test_samples']} (jamais upsamplés)\n\n")
        f.write(f"F1 micro        : {report['f1_micro']:.4f}\n")
        f.write(f"F1 macro        : {report['f1_macro']:.4f}\n")
        f.write(f"F1 samples      : {report['f1_samples']:.4f}\n")
        f.write(f"F1 weighted     : {report['f1_weighted']:.4f}\n")
        f.write(f"Hamming loss    : {report['hamming_loss']:.4f}\n")
        f.write(f"Jaccard(samples): {report['jaccard_samples']:.4f}\n\n")
        f.write("-" * 70 + "\n")
        f.write("RAPPORT PAR CLASSE\n")
        f.write("-" * 70 + "\n")
        f.write(classification_report(y_true, y_pred, target_names=class_names, zero_division=0))

    cm = multilabel_confusion_matrix(y_true, y_pred)
    cm_path = os.path.join(out_dir, f"confusion_matrices_{stamp}.npy")
    np.save(cm_path, cm)

    print(f"\n📄 Rapport texte : {txt_path}")
    print(f"📄 Rapport JSON  : {json_path}")
    print(f"📄 Matrices de confusion (par label) : {cm_path}")


def main_parse_arg():
    parser = argparse.ArgumentParser(description="Pipeline d'entraînement scanner_ia")
    parser.add_argument("--data", required=True, help="Chemin vers le dataset CSV")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--k", type=int, default=5, help="k voisins pour MLSOL")
    parser.add_argument("--rho", type=float, default=0.5, help="Facteur de saturation MLSOL (0-1)")
    parser.add_argument("--wrapper", default="chain", choices=["chain", "ovr"])
    parser.add_argument("--cv", type=int, default=3)
    parser.add_argument("--optimize", action="store_true", help="Active l'optimisation Optuna (plus lent)")
    parser.add_argument("--n-trial", type=int, default=30)
    parser.add_argument("--no-learning-curve", action="store_true")
    parser.add_argument("--model-dir", default="model_scanner_v2")
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    print("📂 Chargement du dataset...")
    X, y_list, feature_cols = load_xy(args.data)
    print(f"✅ X shape: {X.shape} | {len(y_list)} échantillons | {len(feature_cols)} features")

    mlb = MultiLabelBinarizer(classes=VULNS)
    Y_bin = mlb.fit_transform(y_list)
    print(f"✅ Y shape: {Y_bin.shape} | {len(VULNS)} classes (SAFE exclu, déduit à la prédiction)")

    print("\n✂️  Split stratifié multi-label (avant tout upsampling)...")
    train_idx, test_idx = stratified_split(X, Y_bin, test_size=args.test_size, random_state=args.random_state)
    X_train, Y_train = X[train_idx], Y_bin[train_idx]
    X_test, Y_test = X[test_idx], Y_bin[test_idx]
    print(f"✅ Train: {X_train.shape[0]} | Test: {X_test.shape[0]} (isolé, jamais retouché)")

    print(f"\n🧪 Upsampling MLSOL sur le train uniquement (k={args.k}, rho={args.rho})...")
    X_train_res, Y_train_res = mlsol_resample(X_train, Y_train, k=args.k, rho=args.rho)

    print("\n🚀 Instanciation et entraînement du modèle...")
    scanner = ScannerIA(
        classes=VULNS,
        wrapper=args.wrapper,
        cv=args.cv,
        model_dir=args.model_dir,
    )
    scanner.fit(
        X=X_train_res,
        y=Y_train_res,
        optimize=args.optimize,
        n_trial=args.n_trial,
        cv=args.cv,
        use_mlb=False,  # Y déjà binaire, classes déjà alignées sur VULNS
        do_learning_curve=not args.no_learning_curve,
    )

    print("\n📊 Évaluation finale sur le TEST ORIGINAL (jamais vu, jamais upsamplé)...")
    Y_pred = scanner.predict(X_test, threshold=0.5)
    report = build_report(Y_test, Y_pred, class_names=VULNS)
    save_report(report, Y_test, Y_pred, class_names=VULNS, out_dir=args.report_dir)

    print("\n" + "=" * 70)
    print("RÉSUMÉ (test réel, non upsamplé)")
    print("=" * 70)
    print(f"F1 macro   : {report['f1_macro']:.4f}  (traite chaque classe équitablement)")
    print(f"F1 micro   : {report['f1_micro']:.4f}  (vue globale)")
    print(f"Hamming    : {report['hamming_loss']:.4f}")
    print(f"Jaccard    : {report['jaccard_samples']:.4f}")
    print("=" * 70)


# ============================================================
# CONFIG — modifie directement ces variables au lieu d'argparse
# ============================================================
DATA_PATH = "/home/hounsousamuel/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/build_dataset/dataset/dataset.csv"
TEST_SIZE = 0.2
K_NEIGHBORS = 5            # k voisins pour MLSOL
RHO = 0.5                  # facteur de saturation MLSOL (0-1)
WRAPPER = "chain"          # "chain" ou "ovr"
CV = 3
OPTIMIZE = False           # True = active l'optimisation Optuna (plus lent)
N_TRIAL = 30
DO_LEARNING_CURVE = True
MODEL_DIR = "model_scanner_v2"
REPORT_DIR = "reports"
RANDOM_STATE = 42
# ============================================================


def main():
    print("📂 Chargement du dataset...")
    X, y_list, feature_cols = load_xy(DATA_PATH)
    print(f"✅ X shape: {X.shape} | {len(y_list)} échantillons | {len(feature_cols)} features")

    mlb = MultiLabelBinarizer(classes=VULNS)
    Y_bin = mlb.fit_transform(y_list)
    print(f"✅ Y shape: {Y_bin.shape} | {len(VULNS)} classes (SAFE exclu, déduit à la prédiction)")

    print("\n✂️  Split stratifié multi-label (avant tout upsampling)...")
    train_idx, test_idx = stratified_split(X, Y_bin, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    X_train, Y_train = X[train_idx], Y_bin[train_idx]
    X_test, Y_test = X[test_idx], Y_bin[test_idx]
    print(f"✅ Train: {X_train.shape[0]} | Test: {X_test.shape[0]} (isolé, jamais retouché)")

    print(f"\n🧪 Upsampling MLSOL sur le train uniquement (k={K_NEIGHBORS}, rho={RHO})...")
    X_train_res, Y_train_res = mlsol_resample(X_train, Y_train, k=K_NEIGHBORS, rho=RHO)

    print("\n🚀 Instanciation et entraînement du modèle...")
    scanner = ScannerIA(
        classes=VULNS,
        wrapper=WRAPPER,
        cv=CV,
        model_dir=MODEL_DIR,
    )
    scanner.model_manager.verify_model()
    # scanner.fit(
    #     X=X_train_res,
    #     y=Y_train_res,
    #     optimize=OPTIMIZE,
    #     n_trial=N_TRIAL,
    #     cv=CV,
    #     use_mlb=False,  # Y déjà binaire, classes déjà alignées sur VULNS
    #     do_learning_curve=DO_LEARNING_CURVE,
    #     test_size=0.1
    # )

    print("\n📊 Évaluation finale sur le TEST ORIGINAL (jamais vu, jamais upsamplé)...")
    Y_pred = scanner.predict(X_test, threshold=0.5)
    report = build_report(Y_test, Y_pred, class_names=VULNS)
    save_report(report, Y_test, Y_pred, class_names=VULNS, out_dir=REPORT_DIR)

    print("\n" + "=" * 70)
    print("RÉSUMÉ (test réel, non upsamplé)")
    print("=" * 70)
    print(f"F1 macro   : {report['f1_macro']:.4f}  (traite chaque classe équitablement)")
    print(f"F1 micro   : {report['f1_micro']:.4f}  (vue globale)")
    print(f"Hamming    : {report['hamming_loss']:.4f}")
    print(f"Jaccard    : {report['jaccard_samples']:.4f}")
    print("=" * 70)


if __name__ == "__main__":
    main()