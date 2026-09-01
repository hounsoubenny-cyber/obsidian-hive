#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — split train/test multi-label + upsampling correct.

Règles suivies (voir discussion) :
  1. Le split train/test se fait TOUJOURS avant tout upsampling — jamais
     l'inverse, sous peine de fuite de données entre train et test.
  2. Le dataset est multi-label (labels = liste, ex: ['SQLi', 'XSS']).
     Chaque COMBINAISON unique de labels est traitée comme sa propre classe
     pour SMOTENC, afin de ne pas casser les cas multi-label existants.
  3. Une combinaison n'est synthétisée QUE si elle a assez d'échantillons en
     train (>= min_samples_for_smote). En dessous, aucune vraie diversité
     n'est possible par interpolation — la combinaison est seulement
     rapportée, jamais synthétisée silencieusement.
  4. Les colonnes catégorielles sont détectées par PRÉFIXE/NOM (pas par les
     valeurs observées) : sur un petit dataset, une colonne réellement
     continue (ex: js_code_entropy, num_links) peut n'afficher que des 0/1
     par coïncidence d'échantillonnage — la classer comme catégorielle sur
     cette base casserait tout dès que le dataset grossit.

Usage :
    python upsample_dataset.py chemin/vers/dataset.pkl --out-dir ./dataset_split
"""

import os
import json
import argparse
import pickle
from collections import Counter
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import MultiLabelBinarizer
from imblearn.over_sampling import SMOTENC
from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit

# Taxonomie fixe des classes — doit rester synchro avec VULNS de build_dataset_data.py
VULNS = [
    'SQLi', 'CMDi', 'InsecDeser', 'InsecUpload', 'BufOvr', 'CredsExpose',
    'BrokenAuth', 'XSS', 'DirTrav', 'XXE', 'NoSQLi', 'LDAPi', 'InsecPerm',
    'IDOR', 'SessFix', 'SSRF', 'SSTI', 'Prototype_Pollution',
    'HTTP_Request_Smuggling', 'XPATH_Injection', 'GraphQLi',
    'CORS', 'CSRF', 'RateLimit', 'InfoDisc', 'InsecCrypto',
    'OpenRedirect', 'JWT', 'CRLF_Injection', 'RaceCondition',
]

NON_FEATURE_COLS = {"url", "labels"}

# Colonnes catégorielles détectées par PRÉFIXE / nom exact — édite cette liste
# si tu ajoutes de nouvelles features un jour.
CATEGORICAL_PREFIXES = ("has_", "tech_", "fuzzer_")
CATEGORICAL_EXACT = {
    "status_code",
    "strict_transport_security", "x_frame_options", "x_content_type_options",
    "content_security_policy", "x_xss_protection", "referrer_policy",
    "permissions_policy",
}
# fuzzer_ratio_* / fuzzer_ration_* / fuzzer_max_score sont continues, pas
# catégorielles, malgré le préfixe fuzzer_ — exclues explicitement.
CATEGORICAL_PREFIX_EXCLUDE = ("fuzzer_ratio", "fuzzer_ration", "fuzzer_max_score")


def is_categorical(col: str) -> bool:
    if col in CATEGORICAL_EXACT:
        return True
    if any(col.startswith(p) for p in CATEGORICAL_PREFIX_EXCLUDE):
        return False
    return any(col.startswith(p) for p in CATEGORICAL_PREFIXES)


def load_dataset(path: str) -> pd.DataFrame:
    with open(path, "rb") as f:
        obj = pickle.load(f)
    df = pd.DataFrame(obj)
    if "labels" not in df.columns:
        raise ValueError("Colonne 'labels' absente du dataset.")
    unknown = {v for labels in df["labels"] for v in labels if v not in VULNS}
    if unknown:
        raise ValueError(
            f"Labels hors taxonomie VULNS trouvés : {sorted(unknown)} — "
            f"corrige le dict de labels source avant de continuer."
        )
    return df


def multilabel_split(
    df: pd.DataFrame, test_size: float, random_state: int
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    mlb = MultiLabelBinarizer(classes=VULNS)
    Y = mlb.fit_transform(df["labels"])
    splitter = MultilabelStratifiedShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_idx, test_idx = next(splitter.split(df, Y))
    return df.iloc[train_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)


def combo_key(labels: list) -> str:
    """Représentation stable d'une combinaison de labels, ex: 'SQLi+XSS', 'SAFE'."""
    return "+".join(sorted(labels)) if labels else "SAFE"


def upsample_train(
    train_df: pd.DataFrame,
    min_samples_for_smote: int,
    k_neighbors: int,
    random_state: int,
) -> Tuple[pd.DataFrame, dict]:
    feature_cols = [c for c in train_df.columns if c not in NON_FEATURE_COLS]
    categorical_cols = [c for c in feature_cols if is_categorical(c)]
    cat_idx = [feature_cols.index(c) for c in categorical_cols]

    combos = train_df["labels"].apply(combo_key)
    counts = Counter(combos)

    report = {
        "min_samples_for_smote": min_samples_for_smote,
        "k_neighbors": k_neighbors,
        "n_categorical_features": len(categorical_cols),
        "n_continuous_features": len(feature_cols) - len(categorical_cols),
        "combos_before": dict(counts),
        "combos_synthesized": {},
        "combos_skipped_too_small": {},
    }

    # SMOTENC a besoin d'au moins 2 classes ; s'il n'y en a qu'une seule dans
    # tout le train, impossible d'appliquer SMOTE — on retourne tel quel.
    eligible = {c for c, n in counts.items() if n >= min_samples_for_smote}
    if len(eligible) < 2 or len(counts) < 2:
        report["combos_skipped_too_small"] = dict(counts)
        report["note"] = (
            "Pas assez de combinaisons éligibles (>= 2 requis) pour lancer "
            "SMOTENC — dataset retourné inchangé."
        )
        return train_df.copy(), report

    X = train_df[feature_cols].copy()
    y = combos.copy()

    # SMOTENC échantillonne TOUTES les classes vers la taille de la classe
    # majoritaire par défaut, ce qu'on ne veut pas ici (ça sur-gonflerait
    # massivement les petites combos éligibles). On cible plutôt la médiane
    # des combos éligibles, plafonnée pour rester raisonnable.
    eligible_counts = [counts[c] for c in eligible]
    target_n = int(np.median(eligible_counts + [min_samples_for_smote * 3]))
    sampling_strategy = {
        c: max(counts[c], target_n) for c in eligible
    }

    k = min(k_neighbors, min(counts[c] for c in eligible) - 1)
    k = max(k, 1)

    smote = SMOTENC(
        categorical_features=cat_idx,
        sampling_strategy=sampling_strategy,
        k_neighbors=k,
        random_state=random_state,
    )

    # SMOTENC ne gère qu'une classe cible à la fois de façon fiable sur des
    # ensembles où certaines classes sont sous le seuil : on filtre d'abord
    # aux lignes des combos éligibles, on SMOTE, puis on rajoute les combos
    # non éligibles tels quels (non synthétisés).
    mask_eligible = y.isin(eligible)
    X_elig, y_elig = X[mask_eligible], y[mask_eligible]
    X_res, y_res = smote.fit_resample(X_elig, y_elig)

    for c in eligible:
        n_before = counts[c]
        n_after = int((y_res == c).sum())
        report["combos_synthesized"][c] = {"before": n_before, "after": n_after}

    skipped = {c: n for c, n in counts.items() if c not in eligible}
    report["combos_skipped_too_small"] = skipped

    # Reconstruit un DataFrame complet : lignes synthétisées + lignes des
    # combos trop petites (jamais touchées) + url='SYNTHETIC' pour tracer.
    df_res = pd.DataFrame(X_res, columns=feature_cols)
    df_res["labels"] = y_res.apply(lambda c: [] if c == "SAFE" else c.split("+"))
    is_synthetic = np.arange(len(df_res)) >= mask_eligible.sum()
    # Les n_before premières lignes de chaque combo dans X_res sont les
    # originales (SMOTENC les conserve en tête) — approximation raisonnable
    # pour le marquage, à ne pas sur-interpréter.
    df_res["url"] = ["SYNTHETIC" if s else "ORIGINAL" for s in is_synthetic]

    skipped_rows = train_df[~train_df["labels"].apply(combo_key).isin(eligible)].copy()

    final = pd.concat([df_res, skipped_rows[feature_cols + ["labels", "url"]]], ignore_index=True)
    return final, report


def main():
    parser = argparse.ArgumentParser(description="Split + upsampling multi-label du dataset ShieldAI")
    parser.add_argument("dataset_path", help="Chemin vers le .pkl du dataset")
    parser.add_argument("--out-dir", default="./dataset_split", help="Dossier de sortie")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--min-samples-for-smote", type=int, default=6,
                         help="Combos avec moins d'échantillons en train ne sont PAS synthétisées")
    parser.add_argument("--k-neighbors", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    df = load_dataset(args.dataset_path)
    print(f"📥 Dataset chargé : {df.shape[0]} lignes, {df.shape[1]} colonnes")

    train_df, test_df = multilabel_split(df, args.test_size, args.random_state)
    print(f"✂️  Split : train={len(train_df)}, test={len(test_df)} (test_size={args.test_size})")

    train_upsampled, report = upsample_train(
        train_df,
        min_samples_for_smote=args.min_samples_for_smote,
        k_neighbors=args.k_neighbors,
        random_state=args.random_state,
    )

    train_path = os.path.join(args.out_dir, "train_upsampled.pkl")
    test_path = os.path.join(args.out_dir, "test.pkl")
    report_path = os.path.join(args.out_dir, "upsampling_report.json")

    train_upsampled.to_pickle(train_path)
    test_df.to_pickle(test_path)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n✅ Train upsamplé : {train_path} ({len(train_upsampled)} lignes)")
    print(f"✅ Test (intact)  : {test_path} ({len(test_df)} lignes)")
    print(f"📊 Rapport        : {report_path}")

    if report.get("combos_synthesized"):
        print("\nCombinaisons synthétisées (avant -> après) :")
        for c, v in sorted(report["combos_synthesized"].items(), key=lambda x: -x[1]["after"]):
            print(f"  • {c:<30} : {v['before']} -> {v['after']}")

    if report.get("combos_skipped_too_small"):
        print(f"\n⚠️  Combinaisons NON synthétisées (trop petites, < {args.min_samples_for_smote}) :")
        for c, n in sorted(report["combos_skipped_too_small"].items(), key=lambda x: -x[1]):
            print(f"  • {c:<30} : {n} échantillon(s) — inchangé")


if __name__ == "__main__":
    main()
