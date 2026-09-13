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
import ast
import glob
import pickle
import argparse
import pandas as pd


def _normalize_vulns(vulns) -> list:
    """Même logique que `_normalize_vulns` dans build_dataset.py — force
    `vulns` en vraie liste de strings, que la source soit une string simple,
    le repr d'une liste, ou déjà une vraie liste. Dupliquée ici (pas de
    module partagé) pour permettre de réparer un dataset déjà fusionné sans
    dépendre du reste du pipeline de scan."""
    if vulns is None:
        return []
    if isinstance(vulns, (list, tuple, set)):
        return [str(v) for v in vulns]
    if isinstance(vulns, str):
        s = vulns.strip()
        if not s:
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, (list, tuple, set)):
                    return [str(v) for v in parsed]
            except (ValueError, SyntaxError):
                pass
        return [s]
    return [str(vulns)]


def relabel_from_targets(df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
    """Répare la colonne `labels` déjà présente dans `df` en la re-dérivant
    depuis `V1_TARGETS` (source de vérité) par correspondance d'URL, au lieu
    de faire confiance à ce qui a été écrit dans les .pkl — utile pour
    corriger un dataset déjà fusionné dont les labels ont été corrompus par
    un `vulns` mal typé (string au lieu de liste) au moment du scan, sans
    avoir à tout rescanner.

    Nécessite d'être lancé dans l'environnement du projet (le module
    `scanner_ia.build_dataset.build_dataset_data` doit être importable).
    """
    from scanner_ia.build_dataset.build_dataset_data import V1_TARGETS

    # Format de V1_TARGETS : (url, vulns, is_spa, helpers) — voir build_dataset.py
    url_to_labels = {t[0]: _normalize_vulns(t[1]) for t in V1_TARGETS}

    missing = set(df[url_col]) - set(url_to_labels)
    if missing:
        preview = list(missing)[:5]
        print(
            f"⚠️  {len(missing)} URL du dataset fusionné introuvable(s) dans "
            f"V1_TARGETS (ex: {preview}) — leurs labels ne sont pas touchés."
        )

    df = df.copy()
    # Pour les URL trouvées dans V1_TARGETS : labels re-dérivés (la vérité).
    # Pour les URL absentes (cas `missing` déjà signalé ci-dessus) : on garde
    # la valeur déjà présente dans `df` plutôt que de la perdre.
    df["labels"] = [
        url_to_labels[u] if u in url_to_labels else old
        for u, old in zip(df[url_col], df["labels"])
    ]

    print(f"✅ Labels re-dérivés depuis V1_TARGETS pour {len(df) - len(missing)} lignes.")
    return df


def merge(
    chunk_dir: str,
    out_path: str,
    dedup_col: str = "url",
    relabel: bool = False,
) -> pd.DataFrame:
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
    n_before = len(df)
    if dedup_col in df.columns:
        dup_mask = df.duplicated(subset=[dedup_col], keep="first")
        n_dup = int(dup_mask.sum())
        if n_dup:
            dup_values = df.loc[dup_mask, dedup_col].value_counts()
            print(
                f"\n⚠️  {n_dup} doublon(s) détecté(s) sur la colonne "
                f"'{dedup_col}' — probablement un chevauchement entre lots "
                f"(ex: relance avec un mauvais offset). On garde la première "
                f"occurrence rencontrée (ordre des fichiers triés) et on jette "
                f"le reste."
            )
            preview = dup_values.head(10)
            for val, count in preview.items():
                print(f"    - {val!r} : {count + 1} occurrences")
            if len(dup_values) > 10:
                print(f"    ... et {len(dup_values) - 10} autre(s) valeur(s) dupliquée(s)")
            df = df.loc[~dup_mask].reset_index(drop=True)
        else:
            print(f"\n✅ Aucun doublon sur '{dedup_col}'.")
    else:
        print(
            f"\n⚠️  Colonne '{dedup_col}' absente du dataset fusionné — "
            f"dédup ignorée. Colonnes disponibles : {list(df.columns)}"
        )

    if relabel:
        if "labels" not in df.columns:
            print("⚠️  --relabel demandé mais pas de colonne 'labels' à réparer.")
        else:
            print("\n🔧 Re-dérivation des labels depuis V1_TARGETS (source de vérité)...")
            df = relabel_from_targets(df, url_col=dedup_col if dedup_col in df.columns else "url")

    n_after = len(df)
    all_rows = df.to_dict(orient="records")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    pkl_path = f"{out_path}.pkl"
    csv_path = f"{out_path}.csv"

    with open(pkl_path, "wb") as f:
        pickle.dump(all_rows, f)
    df.to_csv(csv_path, index=False)

    print(
        f"\n✅ Fusion terminée : {len(chunk_files)} lots -> {n_before} lignes brutes "
        f"-> {n_after} lignes après dédup"
    )
    print(f"   {pkl_path}")
    print(f"   {csv_path}")

    if "labels" in df.columns:
        from collections import Counter
        counts = Counter(v for labels in df.loc[:, "labels"] for v in _normalize_vulns(labels))
        counts["SAFE (labels=[])"] = sum(1 for labels in df["labels"] if not labels)
        print("\n📊 Répartition des classes après fusion :")
        for vuln_name, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  • {vuln_name:<25} : {count}")

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fusionne les lots de dataset ShieldAI")
    parser.add_argument("chunk_dir", help="Dossier contenant les chunk_*.pkl")
    parser.add_argument("--out", default="./dataset/shieldai_merged", help="Chemin de sortie sans extension")
    parser.add_argument(
        "--dedup-col",
        default="url",
        help="Colonne utilisée pour dédupliquer les lignes fusionnées (défaut: url)",
    )
    parser.add_argument(
        "--relabel",
        action="store_true",
        help=(
            "Re-dérive la colonne 'labels' depuis V1_TARGETS par correspondance "
            "d'URL au lieu de faire confiance à ce qui est stocké dans les .pkl "
            "— répare les labels corrompus par un vulns mal typé sans rescanner. "
            "Nécessite d'être lancé dans l'environnement du projet."
        ),
    )
    args = parser.parse_args()

    merge(args.chunk_dir, args.out, dedup_col=args.dedup_col, relabel=args.relabel)