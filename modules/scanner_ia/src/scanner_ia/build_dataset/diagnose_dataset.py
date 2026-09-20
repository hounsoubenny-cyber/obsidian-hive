#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 14 11:33:42 2026

@author: hounsousamuel
"""

"""
diagnose_dataset.py — Diagnostic de fuite de données (leakage) et de
pauvreté des features pour le dataset multi-label scanner_ia.

Aucun entraînement ici — juste de l'analyse statistique (quelques
secondes), pour répondre à 2 questions avant de retoucher l'algo ou
l'architecture du modèle :

  1. Fuite : les colonnes fuzzer_<Label> sont-elles quasi-identiques
     au label correspondant (le modèle "triche" dessus) ?
  2. Pauvreté : combien de features numériques sont à variance quasi
     nulle (donc inutiles), et pour chaque label, quelle est la
     meilleure feature disponible pour le distinguer ?

Usage:
    python diagnose_dataset.py
"""

import ast

import numpy as np
import pandas as pd

DATA_PATH = "/home/hounsousamuel/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/build_dataset/dataset/dataset.csv"
NEAR_ZERO_STD_THRESHOLD = 1e-6
LEAK_CORR_THRESHOLD = 0.7
WEAK_SIGNAL_THRESHOLD = 0.2


def load_data(path: str):
    df = pd.read_csv(path)

    def parse_labels(raw):
        labels = ast.literal_eval(raw) if isinstance(raw, str) else raw
        return [l for l in labels if l != "SAFE"]

    df["_label_list"] = df["labels"].apply(parse_labels)
    all_labels = sorted({l for row in df["_label_list"] for l in row})
    for label in all_labels:
        df[f"_y_{label}"] = df["_label_list"].apply(lambda row, l=label: int(l in row))
    return df, all_labels


def get_feature_columns(df: pd.DataFrame, all_labels: list) -> list:
    excluded = {"url", "labels", "_label_list"} | {f"_y_{l}" for l in all_labels}
    return [
        c for c in df.columns
        if c not in excluded and pd.api.types.is_numeric_dtype(df[c])
    ]


def analyze_variance(df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    stds = df[feature_cols].std()
    variance_df = pd.DataFrame({"feature": stds.index, "std": stds.values})
    variance_df["near_zero"] = variance_df["std"] < NEAR_ZERO_STD_THRESHOLD
    return variance_df.sort_values("std")


def analyze_leakage(df: pd.DataFrame, all_labels: list) -> pd.DataFrame:
    rows = []
    for label in all_labels:
        fuzzer_col = f"fuzzer_{label}"
        y_col = f"_y_{label}"
        if fuzzer_col not in df.columns:
            rows.append({
                "label": label, "fuzzer_col": None, "correlation": np.nan,
                "fuzzer_col_std": np.nan, "status": "pas de colonne fuzzer_* correspondante",
            })
            continue

        fuzzer_std = df[fuzzer_col].std()
        if fuzzer_std < NEAR_ZERO_STD_THRESHOLD:
            status = "colonne fuzzer constante -> pas de fuite possible, mais inutile aussi"
            corr = np.nan
        else:
            corr = df[fuzzer_col].corr(df[y_col])
            status = "⚠️ FUITE SUSPECTÉE" if abs(corr) >= LEAK_CORR_THRESHOLD else "corrélation faible/modérée"

        rows.append({
            "label": label, "fuzzer_col": fuzzer_col, "correlation": corr,
            "fuzzer_col_std": fuzzer_std, "status": status,
        })

    return pd.DataFrame(rows).sort_values("correlation", ascending=False, na_position="last")


def best_signal_per_label(df: pd.DataFrame, all_labels: list, feature_cols: list) -> pd.DataFrame:
    rows = []
    for label in all_labels:
        y_col = f"_y_{label}"
        corrs = df[feature_cols].corrwith(df[y_col]).abs().sort_values(ascending=False)
        corrs = corrs.dropna()
        if corrs.empty:
            rows.append({"label": label, "best_feature": None, "best_abs_corr": 0.0})
        else:
            rows.append({
                "label": label,
                "best_feature": corrs.index[0],
                "best_abs_corr": corrs.iloc[0],
            })
    return pd.DataFrame(rows).sort_values("best_abs_corr")


def main():
    print("📂 Chargement du dataset...")
    df, all_labels = load_data(DATA_PATH)
    feature_cols = get_feature_columns(df, all_labels)
    print(f"✅ {len(df)} échantillons | {len(all_labels)} labels | {len(feature_cols)} features numériques\n")
    print("Toutes les cols:", list(pd.read_csv(DATA_PATH).columns))
    print("=" * 70)
    print("1️⃣  VARIANCE DES FEATURES (colonnes à std ~0 = inutiles)")
    print("=" * 70)
    variance_df = analyze_variance(df, feature_cols)
    n_near_zero = int(variance_df["near_zero"].sum())
    print(f"⚠️  {n_near_zero}/{len(feature_cols)} features à variance quasi nulle "
          f"(std < {NEAR_ZERO_STD_THRESHOLD})\n")
    print("Colonnes concernées :")
    print(variance_df[variance_df["near_zero"]]["feature"].to_list())
    print()
    print("Top 10 features avec le PLUS de variance (les plus informatives a priori) :")
    print(variance_df.sort_values("std", ascending=False).head(10).to_string(index=False))

    print("\n" + "=" * 70)
    print("2️⃣  FUITE POTENTIELLE : label vs colonne fuzzer_<Label>")
    print("=" * 70)
    leakage_df = analyze_leakage(df, all_labels)
    print(leakage_df.to_string(index=False))
    n_leak = int((leakage_df["status"] == "⚠️ FUITE SUSPECTÉE").sum())
    print(f"\n⚠️  {n_leak} label(s) avec fuite suspectée (|corrélation| >= {LEAK_CORR_THRESHOLD})")

    print("\n" + "=" * 70)
    print("3️⃣  MEILLEUR SIGNAL DISPONIBLE PAR LABEL (hors fuite)")
    print("=" * 70)
    signal_df = best_signal_per_label(df, all_labels, feature_cols)
    print(signal_df.to_string(index=False))
    n_weak = int((signal_df["best_abs_corr"] < WEAK_SIGNAL_THRESHOLD).sum())
    print(f"\n⚠️  {n_weak} label(s) sans AUCUNE feature correctement corrélée "
          f"(best |corr| < {WEAK_SIGNAL_THRESHOLD}) -> structurellement difficiles "
          f"à apprendre avec ce dataset, quel que soit l'algo d'upsampling ou le modèle")

    print("\n" + "=" * 70)
    print("RÉSUMÉ")
    print("=" * 70)
    print(f"Features inutiles (variance nulle) : {n_near_zero}/{len(feature_cols)}")
    print(f"Labels avec fuite suspectée         : {n_leak}/{len(all_labels)}")
    print(f"Labels sans signal exploitable       : {n_weak}/{len(all_labels)}")


if __name__ == "__main__":
    main()