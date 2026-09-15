#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 14 05:43:24 2026

@author: hounsousamuel
"""

"""
explore_dataset.py — Exploration rapide d'un dataset multi-label (scanner_ia)

Usage:
    python explore_dataset.py /chemin/vers/dataset.csv
    python explore_dataset.py /chemin/vers/dataset.parquet

Formats supportés: .csv, .parquet/.pq, .json, .pkl/.pickle, .npz
"""

import sys
import ast
from pathlib import Path

import pandas as pd
import numpy as np

# Labels connus (utilisé si le dataset stocke les labels sous forme de colonnes binaires)
KNOWN_LABELS = [
    "SAFE", "InfoDisc", "BrokenAuth", "SQLi", "XSS", "CredsExpose",
    "CSRF", "IDOR", "InsecPerm", "JWT", "SSRF", "OpenRedirect",
    "DirTrav", "InsecCrypto", "RateLimit", "XXE", "CMDi", "NoSQLi",
    "SSTI", "CORS", "InsecDeser", "InsecUpload", "BufOvr",
    "XPATH_Injection", "HTTP_Request_Smuggling", "CRLF_Injection",
    "RaceCondition", "Prototype_Pollution", "GraphQLi", "LDAPi", "SessFix",
]


def load_dataset(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in (".parquet", ".pq"):
        return pd.read_parquet(path)
    if suffix == ".json":
        return pd.read_json(path)
    if suffix in (".pkl", ".pickle"):
        return pd.read_pickle(path)
    if suffix == ".npz":
        data = np.load(path, allow_pickle=True)
        return pd.DataFrame({k: list(data[k]) for k in data.files})
    raise ValueError(f"Format non supporté: {suffix}")


def detect_label_columns(df: pd.DataFrame):
    """Retourne ('single', 'labels') si une colonne 'labels' existe (liste/str),
    ('multi_hot', [colonnes]) si des colonnes binaires connues sont présentes,
    ou (None, None) si rien n'est détecté."""
    if "labels" in df.columns:
        return "single", "labels"
    binary_cols = [c for c in KNOWN_LABELS if c in df.columns]
    if binary_cols:
        return "multi_hot", binary_cols
    return None, None


def summarize(df: pd.DataFrame, path: Path):
    print("=" * 70)
    print(f"📊 DATASET: {path.name}  ({path.stat().st_size / 1024:.1f} Ko)")
    print("=" * 70)
    print(f"Shape            : {df.shape[0]} lignes x {df.shape[1]} colonnes")
    print(f"Mémoire (pandas) : {df.memory_usage(deep=True).sum() / 1024**2:.2f} Mo")
    print()

    print("— Colonnes & dtypes —")
    print(df.dtypes.to_string())
    print()

    n_missing = df.isna().sum()
    n_missing = n_missing[n_missing > 0]
    if len(n_missing):
        print("— Valeurs manquantes —")
        print(n_missing.to_string())
    else:
        print("✅ Aucune valeur manquante détectée.")
    print()

    mode, cols = detect_label_columns(df)

    if mode == "multi_hot":
        print(f"— Distribution des labels ({len(cols)} colonnes binaires) —")
        counts = df[cols].sum().sort_values(ascending=False)
        for label, c in counts.items():
            pct = 100 * c / len(df)
            print(f"  {label:<25} {int(c):>6}  ({pct:5.1f}%)")
        n_labels_per_row = df[cols].sum(axis=1)
        print()
        print("— Nb labels actifs par ligne —")
        print(n_labels_per_row.value_counts().sort_index().to_string())
        feature_cols = [c for c in df.columns if c not in cols]

    elif mode == "single":
        print("— Distribution des labels (colonne 'labels') —")

        def to_list(x):
            if isinstance(x, list):
                return x
            if isinstance(x, str) and x.strip().startswith("["):
                return ast.literal_eval(x)
            return [x]

        exploded = df["labels"].apply(to_list)
        flat = pd.Series([l for row in exploded for l in (row if row else ["SAFE"])])
        counts = flat.value_counts()
        for label, c in counts.items():
            pct = 100 * c / len(df)
            print(f"  {label:<25} {int(c):>6}  ({pct:5.1f}%)")
        print()
        n_labels_per_row = exploded.apply(len)
        print("— Nb labels actifs par ligne —")
        print(n_labels_per_row.value_counts().sort_index().to_string())
        feature_cols = [c for c in df.columns if c != "labels"]

    else:
        print("⚠️  Impossible de détecter automatiquement les colonnes de labels.")
        print("    Colonnes disponibles:", list(df.columns))
        feature_cols = list(df.columns)

    print()
    numeric_cols = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
    non_numeric_cols = [c for c in feature_cols if c not in numeric_cols]

    if numeric_cols:
        print(f"— Stats features numériques ({len(numeric_cols)} colonnes) —")
        print(df[numeric_cols].describe().T[["mean", "std", "min", "max"]].to_string())
    if non_numeric_cols:
        print()
        print(f"— Colonnes non-numériques hors labels ({len(non_numeric_cols)}) —")
        print(non_numeric_cols)

    print()
    print("— Aperçu (5 premières lignes) —")
    print(df.head().to_string())
    print("=" * 70)


def main():
    if len(sys.argv) != 2:
        print("Usage: python explore_dataset.py /chemin/vers/dataset.<csv|parquet|json|pkl|npz>")
        sys.exit(1)

    path = Path(sys.argv[1]).expanduser().resolve()
    if not path.exists():
        print(f"❌ Fichier introuvable: {path}")
        sys.exit(1)

    df = load_dataset(path)
    summarize(df, path)


if __name__ == "__main__":
    main()