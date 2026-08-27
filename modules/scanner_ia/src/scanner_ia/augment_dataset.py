#!/usr/bin/env python3
"""
ShieldAI — Dataset Augmenter v3
Sortie garantie : FEATURES_LIST + label_* + [url, source, labels, is_safe, n_labels]
Colonnes parasites automatiquement supprimées, colonnes manquantes ajoutées à 0.
Usage : python augment_dataset_v3.py
"""

import json, random, sys
from pathlib import Path
from datetime import datetime
from collections import Counter
import numpy as np
import pandas as pd

# ── Config ──────────────────────────────────────────────────────────────────
REAL_CSV         = Path("dataset/shieldai_dataset.csv")
AUGMENTED_CSV    = Path("dataset/shieldai_dataset_augmented_v3.csv")
AUGMENTED_META   = Path("dataset/shieldai_dataset_augmented_v3_meta.json")

TARGET_SAMPLES   = 2000
SAMPLES_PER_VULN = 25
SAFE_TARGET      = 300
REPLICATE_REAL   = 2
NOISE_STD        = 0.06
RANDOM_SEED      = 42

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

sys.path.insert(0, str(Path(__file__).resolve().parent / "scanner_ia"))
from scanner_ia.ml_model.config import VULNS, FEATURES_LIST

LABEL_COLS = [f"label_{v}" for v in VULNS]
META_COLS  = ["url", "source", "labels", "is_safe", "n_labels"]
ALL_COLS   = FEATURES_LIST + LABEL_COLS + META_COLS

# ── Combos réalistes multi-label ───────────────────────────────────────────
REALISTIC_COMBOS = [
    (["XSS", "CSRF"], ""), (["SQLi", "BrokenAuth"], ""),
    (["InfoDisc", "CredsExpose"], ""), (["InfoDisc", "InsecPerm"], ""),
    (["CMDi", "DirTrav"], ""), (["XSS", "InfoDisc"], ""),
    (["SSRF", "InfoDisc"], ""), (["CORS", "InfoDisc"], ""),
    (["InsecUpload", "InsecDeser"], ""), (["NoSQLi", "BrokenAuth"], ""),
    (["XXE", "SSRF"], ""), (["SSTI", "DirTrav"], ""),
    (["JWT", "BrokenAuth"], ""), (["IDOR", "InsecPerm"], ""),
    (["CRLF_Injection", "OpenRedirect"], ""), (["Prototype_Pollution", "InsecDeser"], ""),
    (["XSS", "SQLi", "CSRF"], ""), (["InfoDisc", "CredsExpose", "InsecPerm"], ""),
    (["CMDi", "DirTrav", "InfoDisc"], ""),
    (["BrokenAuth", "InsecPerm", "InfoDisc", "SessFix"], ""),
]

# ── Chargement réel ─────────────────────────────────────────────────────────
df_real = pd.read_csv(REAL_CSV)
for c in FEATURES_LIST:
    if c not in df_real.columns:
        df_real[c] = 0.0
df_real[FEATURES_LIST] = df_real[FEATURES_LIST].fillna(0).replace([np.inf, -np.inf], 0)

X_real = df_real[FEATURES_LIST].copy()
feature_means = X_real.mean()
feature_stds  = X_real.std().fillna(0.1)

# ── Helpers ─────────────────────────────────────────────────────────────────
def _row(features, vulns_list, source, url):
    d = {c: features[i] for i, c in enumerate(FEATURES_LIST)}
    d.update({f"label_{v}": 1 if v in vulns_list else 0 for v in VULNS})
    d["labels"]  = json.dumps(vulns_list if vulns_list else ["SAFE"])
    d["is_safe"] = 1 if not vulns_list else 0
    d["n_labels"] = len(vulns_list)
    d["source"] = source
    d["url"]    = url
    return d

def _fuzzer_boost(sample, vuln):
    col = f"fuzzer_{vuln}"
    if col in FEATURES_LIST:
        sample[FEATURES_LIST.index(col)] = np.random.choice([0, 1], p=[0.3, 0.7])

# ── Génération ──────────────────────────────────────────────────────────────
def generate_safe(n, real_X):
    rows = []
    for i in range(n):
        a, b = real_X.sample(2).values
        alpha = np.random.uniform(0.2, 0.8)
        s = a * alpha + b * (1 - alpha)
        s += np.random.normal(0, NOISE_STD * 1.5, len(s)) * feature_stds.values
        s = np.clip(s, 0, None)
        for c in [c for c in FEATURES_LIST if c.startswith("fuzzer_")]:
            s[FEATURES_LIST.index(c)] = 0.0
        rows.append(_row(s, [], "synthetic_safe", f"synth_safe_{i}"))
    return pd.DataFrame(rows)

def generate_single(vuln, n, real_X_vuln):
    rows = []
    fcol = f"fuzzer_{vuln}"
    fidx = FEATURES_LIST.index(fcol) if fcol in FEATURES_LIST else None
    for i in range(n):
        if real_X_vuln is not None and len(real_X_vuln) >= 3:
            a, b = real_X_vuln.sample(2).values
            alpha = np.random.uniform(0.3, 0.7)
            s = a * alpha + b * (1 - alpha)
            s += np.random.normal(0, NOISE_STD, len(s)) * feature_stds.values
        else:
            s = feature_means.values.copy()
            if fidx is not None:
                s[fidx] = 1.0
            s += np.random.normal(0, NOISE_STD * 3, len(s)) * feature_stds.values
        s = np.clip(s, 0, None)
        if fidx is not None:
            s[fidx] = np.random.choice([0, 1], p=[0.3, 0.7])
        rows.append(_row(s, [vuln], f"synthetic_{vuln}", f"synth_{vuln}_{i}"))
    return pd.DataFrame(rows)

def generate_combo(combos, n=12):
    rows = []
    for vulns, _ in combos:
        for i in range(n):
            s = feature_means.values.copy()
            for v in vulns:
                _fuzzer_boost(s, v)
            matching = df_real[df_real["labels"].apply(lambda x: tuple(sorted(eval(x))) == tuple(sorted(vulns)))]
            if len(matching) >= 2:
                a = matching[FEATURES_LIST].sample(1).values[0]
                b = matching[FEATURES_LIST].sample(1).values[0]
                alpha = np.random.uniform(0.3, 0.7)
                s = a * alpha + b * (1 - alpha)
            else:
                s += np.random.normal(0, NOISE_STD * 2, len(s)) * feature_stds.values
            s = np.clip(s, 0, None)
            rows.append(_row(s, vulns, "synthetic_combo", f"synth_combo_{'-'.join(sorted(vulns))}_{i}"))
    return pd.DataFrame(rows)

def replicate(df, n=REPLICATE_REAL):
    rows = []
    for _, row in df.iterrows():
        base = row[FEATURES_LIST].values.copy()
        for k in range(n):
            s = base + np.random.normal(0, NOISE_STD * 0.5, len(base)) * feature_stds.values
            s = np.clip(s, 0, None)
            rows.append(_row(s, eval(row["labels"]), f"replicated_{row['source']}", f"{row['url']}_rep_{k}"))
    return pd.DataFrame(rows)

# ── Assemblage ──────────────────────────────────────────────────────────────
dfs = [df_real, replicate(df_real)]

safe_mask = df_real['is_safe'] == 1
real_safe_X = X_real[safe_mask] if safe_mask.sum() > 0 else X_real
n_safe_real = safe_mask.sum()
n_safe_synth = max(0, SAFE_TARGET - n_safe_real)
if n_safe_synth > 0:
    dfs.append(generate_safe(n_safe_synth, real_safe_X))

for vuln in VULNS:
    mask = df_real[f"label_{vuln}"] == 1
    n_real = mask.sum()
    n_synth = max(0, SAMPLES_PER_VULN - n_real)
    rX = X_real[mask] if mask.sum() >= 3 else None
    if n_synth > 0:
        dfs.append(generate_single(vuln, n_synth, rX))

dfs.append(generate_combo(REALISTIC_COMBOS, n=12))

df_aug = pd.concat(dfs, ignore_index=True)

# ── Rééquilibrage ───────────────────────────────────────────────────────────
short = TARGET_SAMPLES - len(df_aug)
if short > 0:
    third = short // 3
    dfs.append(generate_safe(third, real_safe_X))
    dfs.append(generate_combo(random.sample(REALISTIC_COMBOS, min(len(REALISTIC_COMBOS), max(1, third//12))), n=6))
    for _ in range(max(0, short - third - (third//12)*6)):
        dfs.append(generate_single(random.choice(VULNS), 1, None))
    df_aug = pd.concat(dfs, ignore_index=True)

# ── Nettoyage strict des colonnes ──────────────────────────────────────────
extra = set(df_aug.columns) - set(ALL_COLS)
if extra:
    print(f"⚠️ {len(extra)} colonnes parasites supprimées")
    df_aug = df_aug.drop(columns=list(extra))
missing = set(ALL_COLS) - set(df_aug.columns)
if missing:
    print(f"⚠️ {len(missing)} colonnes manquantes ajoutées")
    for c in missing:
        df_aug[c] = 0 if c in LABEL_COLS or c in FEATURES_LIST else ""

df_aug = df_aug[ALL_COLS]

# ── Sauvegarde ──────────────────────────────────────────────────────────────
df_aug.to_csv(AUGMENTED_CSV, index=False)
print(f"💾 {AUGMENTED_CSV}  |  {len(df_aug)} lignes  |  {len(df_aug.columns)} colonnes  |  SAFE={df_aug['is_safe'].sum()}")