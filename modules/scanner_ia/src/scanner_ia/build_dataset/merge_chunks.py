#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug 29 21:51:32 2026

@author: hounsousamuel
"""

"""
ShieldAI — fusion des lots (chunks) produits par build_dataset_chunked()
en un seul dataset .pkl + .csv.

Usage :
    python merge_chunks.py ./dataset_chunks --out ./dataset/shieldai_merged_v4
"""

import os
import glob
import pickle
import argparse
import pandas as pd


def merge(chunk_dir: str, out_path: str) -> pd.DataFrame:
    chunk_files = sorted(glob.glob(os.path.join(chunk_dir, "chunk_*.pkl")))
    if not chunk_files:
        raise FileNotFoundError(f"Aucun chunk_*.pkl trouvé dans {chunk_dir}")

    all_rows = []
    for path in chunk_files:
        with open(path, "rb") as f:
            obj = pickle.load(f)
        # Le format réel produit par FeatureExtractor.save_dataset est une
        # liste de dicts (un par ligne), malgré le message de log qui parle
        # de "pkl(dict)" — vérifié empiriquement sur v4_001.
        rows = obj if isinstance(obj, list) else list(obj.values())
        all_rows.extend(rows)
        print(f"  • {os.path.basename(path)} : +{len(rows)} lignes")

    df = pd.DataFrame(all_rows)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    pkl_path = f"{out_path}.pkl"
    csv_path = f"{out_path}.csv"

    with open(pkl_path, "wb") as f:
        pickle.dump(all_rows, f)
    df.to_csv(csv_path, index=False)

    print(f"\n✅ Fusion terminée : {len(chunk_files)} lots -> {len(df)} lignes")
    print(f"   {pkl_path}")
    print(f"   {csv_path}")

    if "labels" in df.columns:
        from collections import Counter
        counts = Counter(v for labels in df["labels"] for v in labels)
        counts["SAFE (labels=[])"] = sum(1 for labels in df["labels"] if not labels)
        print("\n📊 Répartition des classes après fusion :")
        for vuln_name, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  • {vuln_name:<25} : {count}")

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fusionne les lots de dataset ShieldAI")
    parser.add_argument("chunk_dir", help="Dossier contenant les chunk_*.pkl")
    parser.add_argument("--out", default="./dataset/shieldai_merged", help="Chemin de sortie sans extension")
    args = parser.parse_args()

    merge(args.chunk_dir, args.out)