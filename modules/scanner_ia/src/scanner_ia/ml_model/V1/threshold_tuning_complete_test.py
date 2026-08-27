#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Complet de ThresholdTunning
Teste : Binary, Multi-Class, Multi-Label
"""

import numpy as np
import warnings
warnings.filterwarnings('ignore')
import os,sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append("/home/hounsousamuel/PROJET/scanner/ml_model")
from sklearn.datasets import make_classification, make_multilabel_classification
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier as MultiOutputClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, classification_report
import time
from seuiltunning import ThresholdTunning, apply_tunning
# Importer votre classe (ajustez le chemin si nécessaire)
# from votre_module import ThresholdTunning, apply_tunning


def test_binary_classification():
    """Test sur classification binaire"""
    print("\n" + "="*70)
    print("🔵 TEST 1 : CLASSIFICATION BINAIRE")
    print("="*70)

    # Générer données
    X, y = make_classification(
        n_samples=2000,
        n_features=20,
        n_informative=15,
        n_redundant=5,
        n_classes=2,
        weights=[0.6, 0.4],  # Déséquilibre léger
        random_state=42
    )

    # Normaliser
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    print(f"\n📊 Distribution des classes :")
    print(f"   Train : {np.bincount(y_train)} (total: {len(y_train)})")
    print(f"   Val   : {np.bincount(y_val)} (total: {len(y_val)})")
    print(f"   Test  : {np.bincount(y_test)} (total: {len(y_test)})")

    # Entraîner modèle simple et rapide
    print(f"\n🔄 Entraînement LogisticRegression...")
    start = time.time()
    model = LogisticRegression(max_iter=1500, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    train_time = time.time() - start
    print(f"   ✅ Entraîné en {train_time:.2f}s")

    # Score de base
    y_pred_base = model.predict(X_test)
    acc_base = accuracy_score(y_test, y_pred_base)
    f1_base = f1_score(y_test, y_pred_base, average='binary')

    print(f"\n📍 Performances AVANT threshold tuning :")
    print(f"   Accuracy : {acc_base:.4f}")
    print(f"   F1-Score : {f1_base:.4f}")

    # Appliquer threshold tuning
    print(f"\n🎯 Application du Threshold Tuning...")
    start = time.time()
    tuned = ThresholdTunning(
        model=model,
        X=X_val,
        y=y_val,
        recall_micro=0.3,
        recall_macro=0.3,
        precision_micro=0.2,
        precision_macro=0.2,
        space=(0.2, 0.8, 100)  # Moins de points pour être rapide
    )
    tuned.fit(verbose=False)
    tune_time = time.time() - start
    print(f"   ✅ Tuning terminé en {tune_time:.2f}s")

    # Score après tuning
    y_pred_tuned = tuned.predict(X_test)
    acc_tuned = accuracy_score(y_test, y_pred_tuned)
    f1_tuned = f1_score(y_test, y_pred_tuned, average='binary')

    print(f"\n🎯 Performances APRÈS threshold tuning :")
    print(f"   Accuracy : {acc_tuned:.4f} ({(acc_tuned-acc_base)*100:+.2f}% points)")
    print(f"   F1-Score : {f1_tuned:.4f} ({(f1_tuned-f1_base)*100:+.2f}% points)")
    print(f"   Seuil optimal : {tuned.optimal_seuil[0]:.3f} (défaut: 0.5)")

    # Rapport
    print(f"\n📋 Classification Report (avec tuning) :")
    print(classification_report(y_test, y_pred_tuned, target_names=['Classe 0', 'Classe 1']))

    # Visualiser
    try:
        tuned.plot_seuil(save_path='binary_thresholds.png')
        print(f"   📊 Graphique sauvegardé : binary_thresholds.png")
    except Exception as e:
        print(f"   ⚠️ Erreur visualisation : {e}")

    return model, tuned


def test_multiclass_classification():
    """Test sur classification multi-classe"""
    print("\n" + "="*70)
    print("🟡 TEST 2 : CLASSIFICATION MULTI-CLASSE (3 classes)")
    print("="*70)

    # Générer données
    X, y = make_classification(
        n_samples=2000,
        n_features=20,
        n_informative=15,
        n_redundant=5,
        n_classes=3,
        n_clusters_per_class=1,
        weights=[0.4, 0.35, 0.25],
        random_state=42
    )

    # Normaliser
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    print(f"\n📊 Distribution des classes :")
    print(f"   Train : {np.bincount(y_train)} (total: {len(y_train)})")
    print(f"   Val   : {np.bincount(y_val)} (total: {len(y_val)})")
    print(f"   Test  : {np.bincount(y_test)} (total: {len(y_test)})")

    # Entraîner
    print(f"\n🔄 Entraînement LogisticRegression (multi-class)...")
    start = time.time()
    model = LogisticRegression(
        max_iter=500,
        random_state=42,
        multi_class='multinomial',
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    train_time = time.time() - start
    print(f"   ✅ Entraîné en {train_time:.2f}s")

    # Score de base
    acc_base = model.score(X_test, y_test)
    y_pred_base = model.predict(X_test)
    f1_base = f1_score(y_test, y_pred_base, average='macro')

    print(f"\n📍 Performances (multi-class utilise argmax, pas de threshold) :")
    print(f"   Accuracy : {acc_base:.4f}")
    print(f"   F1-Score (macro) : {f1_base:.4f}")

    # Tester threshold tuning (devrait skip)
    print(f"\n🎯 Test du Threshold Tuning (devrait skipper)...")
    start = time.time()
    tuned = ThresholdTunning(
        model=model,
        X=X_val,
        y=y_val,
        space=(0.2, 0.8, 50)
    )
    tuned.fit(verbose=False)
    tune_time = time.time() - start
    print(f"   ✅ Traité en {tune_time:.2f}s")

    if tuned.optimal_seuil is not None and len(tuned.optimal_seuil) == 3:
        print(f"   ⚠️ Seuils par défaut utilisés : {tuned.optimal_seuil}")
        print(f"   → Normal pour multi-class (argmax est optimal)")

    # Rapport
    print(f"\n📋 Classification Report :")
    print(classification_report(y_test, y_pred_base, target_names=['Classe 0', 'Classe 1', 'Classe 2']))

    return model, tuned


def test_multilabel_classification():
    """Test sur classification multi-label"""
    print("\n" + "="*70)
    print("🟢 TEST 3 : CLASSIFICATION MULTI-LABEL (4 labels)")
    print("="*70)

    # Générer données
    X, y = make_multilabel_classification(
        n_samples=2000,
        n_features=20,
        n_classes=4,
        n_labels=2,  # En moyenne 2 labels actifs par échantillon
        allow_unlabeled=False,
        random_state=42
    )

    # Normaliser
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Split (attention : pas de stratify pour multilabel)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42
    )

    print(f"\n📊 Distribution des labels :")
    for i in range(y.shape[1]):
        print(f"   Label {i} : {np.sum(y_train[:, i])} positifs sur {len(y_train)} "
              f"({np.sum(y_train[:, i])/len(y_train)*100:.1f}%)")

    # Entraîner (IMPORTANT : MultiOutputClassifier pour multi-label)
    print(f"\n🔄 Entraînement MultiOutputClassifier(LogisticRegression)...")
    start = time.time()
    base_lr = LogisticRegression(max_iter=1500, random_state=42, class_weight='balanced')
    model = MultiOutputClassifier(base_lr, n_jobs=-1)
    model.fit(X_train, y_train)
    train_time = time.time() - start
    print(f"   ✅ Entraîné en {train_time:.2f}s")

    # Score de base
    y_pred_base = model.predict(X_test)
    acc_base = accuracy_score(y_test, y_pred_base)  # Exact match
    f1_base = f1_score(y_test, y_pred_base, average='samples')

    print(f"\n📍 Performances AVANT threshold tuning :")
    print(f"   Accuracy (exact match) : {acc_base:.4f}")
    print(f"   F1-Score (samples) : {f1_base:.4f}")

    # F1 par label
    for i in range(y.shape[1]):
        f1_label = f1_score(y_test[:, i], y_pred_base[:, i])
        print(f"   F1 Label {i} : {f1_label:.4f}")

    # Appliquer threshold tuning
    print(f"\n🎯 Application du Threshold Tuning...")
    start = time.time()
    tuned = ThresholdTunning(
        model=model,
        X=X_val,
        y=y_val,
        recall_micro=0.25,
        recall_macro=0.3,
        precision_micro=0.2,
        precision_macro=0.25,
        space=(0.2, 0.8, 1000)  # Plus de points car 4 labels
    )
    tuned.fit(verbose=False)
    tune_time = time.time() - start
    print(f"   ✅ Tuning terminé en {tune_time:.2f}s")

    # Score après tuning
    y_pred_tuned = tuned.predict(X_test)
    acc_tuned = accuracy_score(y_test, y_pred_tuned)
    f1_tuned = f1_score(y_test, y_pred_tuned, average='samples')

    print(f"\n🎯 Performances APRÈS threshold tuning :")
    print(f"   Accuracy (exact match) : {acc_tuned:.4f} ({(acc_tuned-acc_base)*100:+.2f}% points)")
    print(f"   F1-Score (samples) : {f1_tuned:.4f} ({(f1_tuned-f1_base)*100:+.2f}% points)")
    print(f"\n   Seuils optimaux :")
    for i, seuil in enumerate(tuned.optimal_seuil):
        print(f"      Label {i} : {seuil:.3f} (défaut: 0.5)")

    # F1 par label après tuning
    print(f"\n   F1 par label APRÈS tuning :")
    for i in range(y.shape[1]):
        f1_label_base = f1_score(y_test[:, i], y_pred_base[:, i])
        f1_label_tuned = f1_score(y_test[:, i], y_pred_tuned[:, i])
        gain = (f1_label_tuned - f1_label_base) * 100
        print(f"      Label {i} : {f1_label_tuned:.4f} ({gain:+.2f}% points)")

    # Rapport détaillé
    print(f"\n📋 Classification Report (avec tuning) :")
    print(classification_report(y_test, y_pred_tuned, target_names=[f'Label {i}' for i in range(4)]))

    # Visualiser
    try:
        tuned.plot_seuil(save_path='multilabel_thresholds.png')
        print(f"   📊 Graphique sauvegardé : multilabel_thresholds.png")
    except Exception as e:
        print(f"   ⚠️ Erreur visualisation : {e}")

    return model, tuned


def test_apply_tunning_function():
    """Test de la fonction apply_tunning() complète"""
    print("\n" + "="*70)
    print("🔧 TEST 4 : FONCTION apply_tunning() (Multi-Label)")
    print("="*70)

    # Générer données
    X, y = make_multilabel_classification(
        n_samples=1500,
        n_features=15,
        n_classes=3,
        n_labels=2,
        random_state=42
    )

    X = StandardScaler().fit_transform(X)

    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.4, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

    # Entraîner
    print(f"\n🔄 Entraînement du modèle...")
    base_lr = LogisticRegression(max_iter=1500, random_state=42)
    model = MultiOutputClassifier(base_lr, n_jobs=-1)
    model.fit(X_train, y_train)

    print(f"   ✅ Modèle entraîné")
    print(f"   Train : {len(X_train)} samples")
    print(f"   Val   : {len(X_val)} samples")
    print(f"   Test  : {len(X_test)} samples")

    # Appliquer la fonction complète
    try:
        print(f"\n🎯 Application de apply_tunning()...")
        model_original, model_tuned = apply_tunning(
            model=model,
            X_val=X_val,
            y_val=y_val,
            X_test=X_test,
            y_test=y_test
        )

        print(f"\n✅ apply_tunning() exécuté avec succès !")

    except Exception as e:
        print(f"\n❌ Erreur dans apply_tunning() : {e}")
        import traceback
        traceback.print_exc()

    return model


def run_all_tests():
    """Lance tous les tests"""
    print("\n" + "="*70)
    print("🚀 LANCEMENT DE TOUS LES TESTS")
    print("="*70)

    start_total = time.time()

    try:
        # Test 1 : Binary
        model_bin, tuned_bin = test_binary_classification()
        print(f"\n✅ Test Binary : RÉUSSI")
    except Exception as e:
        print(f"\n❌ Test Binary : ÉCHOUÉ")
        print(f"   Erreur : {e}")
        import traceback
        traceback.print_exc()

    try:
        # Test 2 : Multi-Class
        model_mc, tuned_mc = test_multiclass_classification()
        print(f"\n✅ Test Multi-Class : RÉUSSI")
    except Exception as e:
        print(f"\n❌ Test Multi-Class : ÉCHOUÉ")
        print(f"   Erreur : {e}")
        import traceback
        traceback.print_exc()

    try:
        # Test 3 : Multi-Label
        model_ml, tuned_ml = test_multilabel_classification()
        print(f"\n✅ Test Multi-Label : RÉUSSI")
    except Exception as e:
        print(f"\n❌ Test Multi-Label : ÉCHOUÉ")
        print(f"   Erreur : {e}")
        import traceback
        traceback.print_exc()

    try:
        # Test 4 : Fonction apply_tunning
        model_apply = test_apply_tunning_function()
        print(f"\n✅ Test apply_tunning : RÉUSSI")
    except Exception as e:
        print(f"\n❌ Test apply_tunning : ÉCHOUÉ")
        print(f"   Erreur : {e}")
        import traceback
        traceback.print_exc()

    total_time = time.time() - start_total

    print("\n" + "="*70)
    print("🏁 TOUS LES TESTS TERMINÉS")
    print("="*70)
    print(f"⏱️  Temps total : {total_time:.2f}s")
    print(f"📊 Fichiers générés :")
    print(f"   - binary_thresholds.png")
    print(f"   - multilabel_thresholds.png")
    print(f"   - suivi_seuil.png (depuis apply_tunning)")


# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🧪 TEST COMPLET DE ThresholdTunning")
    print("   Tests : Binary, Multi-Class, Multi-Label")
    print("   Modèle : LogisticRegression (rapide)")
    print("="*70)

    # Lancer tous les tests
    run_all_tests()

    print("\n" + "="*70)
    print("✅ SCRIPT TERMINÉ AVEC SUCCÈS")
    print("="*70)
