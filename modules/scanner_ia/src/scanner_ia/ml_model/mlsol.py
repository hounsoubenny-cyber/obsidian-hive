#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 14 05:58:21 2026

@author: hounsousamuel
"""

"""
mlsol.py — Upsampling multi-label pour scanner_ia (ShieldAI / ObsidianHive)

Implémente MLSOL (Multi-Label Synthetic Oversampling based on Local label
imbalance — Liu, Blekas & Tsoumakas, 2022), enrichi de :
  - contrainte de co-occurrence : un labelset synthétique n'est accepté
    que s'il correspond à une combinaison réellement observée dans le
    dataset (on refuse d'halluciner des associations de vulnérabilités
    qui n'existent jamais en vrai, ex: [SQLi, XXE] si jamais vu ensemble)
  - cible de saturation par label : N_target = N_majority^rho * N_label^(1-rho)
    (pas d'égalisation brute à la classe majoritaire, ce qui éviterait
    de noyer le dataset sous du bruit synthétique)
  - clipping des features synthétiques au range observé (min/max réels)

Ce module NE FAIT QUE l'upsampling : pas de split, pas de fit, pas d'éval.
Le split (stratifié !) doit être fait AVANT d'appeler cette fonction, et
uniquement sur le train.

⚠️ Hypothèse sur Y : matrice binaire (n_samples, n_labels) qui NE CONTIENT
PAS de colonne "SAFE". Une ligne SAFE = un vecteur tout à zéro. Ces lignes
ne sont jamais choisies comme graines (elles n'ont aucun label positif) —
c'est voulu, SAFE est déjà la classe majoritaire.

Usage :
    from mlsol import mlsol_resample
    X_res, Y_res = mlsol_resample(X_train, Y_train, k=5, rho=0.5)
"""

import numpy as np
from sklearn.neighbors import NearestNeighbors


def _saturation_targets(Y: np.ndarray, rho: float) -> np.ndarray:
    """
    Nombre de synthétiques à générer par label.

    N_target_l = N_majority^rho * N_l^(1-rho)

    rho -> 1 : cible proche de la classe majoritaire (agressif)
    rho -> 0 : cible proche du compte actuel (quasi pas d'upsampling)
    """
    counts = Y.sum(axis=0).astype(float)
    n_majority = counts.max()
    counts_safe = np.where(counts == 0, 1, counts)
    targets = (n_majority ** rho) * (counts_safe ** (1 - rho))
    n_to_generate = np.maximum(0, np.round(targets - counts)).astype(int)
    return n_to_generate


def _known_labelsets(Y: np.ndarray) -> set:
    """Ensemble des combinaisons de labels réellement présentes dans le dataset."""
    return {tuple(np.where(row == 1)[0]) for row in Y}


def _is_plausible(y_candidate: np.ndarray, known_sets: set) -> bool:
    return tuple(np.where(y_candidate == 1)[0]) in known_sets


def _local_difficulty_weight(neighbor_labels_for_l: np.ndarray) -> float:
    """
    Poids MLSOL : plus les voisins d'une instance porteuse du label sont
    eux-mêmes négatifs pour ce label, plus l'instance est dans une zone
    "difficile" (borderline/rare/outlier) et mérite d'être priorisée
    comme graine de génération.
    Borné à 0.15 minimum pour qu'un outlier total garde une petite chance
    d'être choisi (sinon on ignore complètement les cas les plus isolés).
    """
    positive_ratio = neighbor_labels_for_l.mean()
    return max(1.0 - positive_ratio, 0.15)


def mlsol_resample(
    X: np.ndarray,
    Y: np.ndarray,
    k: int = 5,
    rho: float = 0.5,
    max_attempts_factor: int = 20,
    random_state: int = 42,
    verbose: bool = True,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Upsampling MLSOL + co-occurrence + saturation + clipping.

    Parameters
    ----------
    X : (n_samples, n_features) — features numériques uniquement (déjà nettoyées)
    Y : (n_samples, n_labels) — matrice binaire, sans colonne SAFE
    k : nombre de voisins pour le calcul de difficulté locale et l'interpolation
    rho : facteur de saturation, 0 < rho < 1 (0.5 = équilibrage modéré)
    max_attempts_factor : tentatives max par synthétique avant abandon
        (la contrainte de co-occurrence peut faire échouer une génération)
    random_state : graine aléatoire pour la reproductibilité
    verbose : affiche un résumé label par label

    Returns
    -------
    X_resampled, Y_resampled : dataset original + synthétiques ajoutés
    """
    rng = np.random.default_rng(random_state)
    X = np.asarray(X, dtype=float)
    Y = np.asarray(Y, dtype=int)
    n_samples, n_labels = Y.shape

    feature_min = X.min(axis=0)
    feature_max = X.max(axis=0)

    known_labelsets = _known_labelsets(Y)
    n_to_generate = _saturation_targets(Y, rho=rho)

    n_neighbors = min(k + 1, n_samples)
    nn_model = NearestNeighbors(n_neighbors=n_neighbors)
    nn_model.fit(X)
    _, neighbor_idx = nn_model.kneighbors(X)
    neighbor_idx = neighbor_idx[:, 1:]  # exclure l'instance elle-même

    synthetic_X, synthetic_Y = [], []

    for label in range(n_labels):
        n_gen = int(n_to_generate[label])
        if n_gen == 0:
            continue

        carriers = np.where(Y[:, label] == 1)[0]
        if len(carriers) == 0:
            continue

        weights = np.array([
            _local_difficulty_weight(Y[neighbor_idx[i], label])
            for i in carriers
        ])
        weights = weights / weights.sum()

        generated, attempts = 0, 0
        max_attempts = n_gen * max_attempts_factor

        while generated < n_gen and attempts < max_attempts:
            attempts += 1

            seed_idx = rng.choice(carriers, p=weights)
            ref_idx = rng.choice(neighbor_idx[seed_idx])

            x_seed, x_ref = X[seed_idx], X[ref_idx]
            y_seed, y_ref = Y[seed_idx], Y[ref_idx]

            # Safe-level interpolation : si le voisin partage le label, on
            # interpole librement ; sinon on reste proche de la source pour
            # ne pas générer un point qui franchit la frontière de classe.
            shares_label = y_ref[label] == 1
            lam_max = 1.0 if shares_label else 0.5
            lam = rng.uniform(0, lam_max)

            x_new = x_seed + lam * (x_ref - x_seed)
            x_new = np.clip(x_new, feature_min, feature_max)

            vote = (1 - lam) * y_seed + lam * y_ref
            y_new = (vote >= 0.5).astype(int)
            y_new[label] = 1  # le label ciblé est garanti présent

            if not _is_plausible(y_new, known_labelsets):
                continue

            synthetic_X.append(x_new)
            synthetic_Y.append(y_new)
            generated += 1

        if verbose:
            status = "✅" if generated == n_gen else "⚠️ "
            print(f"{status} Label {label:>2}: {generated}/{n_gen} synthétiques générés"
                  + ("" if generated == n_gen else " (contrainte de co-occurrence trop stricte)"))

    if synthetic_X:
        X_resampled = np.vstack([X, np.array(synthetic_X)])
        Y_resampled = np.vstack([Y, np.array(synthetic_Y)])
    else:
        X_resampled, Y_resampled = X.copy(), Y.copy()

    if verbose:
        print(f"\n📦 Dataset: {n_samples} → {X_resampled.shape[0]} lignes "
              f"(+{X_resampled.shape[0] - n_samples} synthétiques)")

    return X_resampled, Y_resampled