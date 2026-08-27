#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 25 09:13:57 2026

@author: hounsousamuel

Test pour AnomalyModelSklearn
"""


import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
from autoencoders.anomalie_model_sklearn import AnomalyModelSklearn

import numpy as np
import pandas as pd
from sklearn.datasets import make_blobs, make_classification
import matplotlib.pyplot as plt
import seaborn as sns

def test_anomaly_model():
    """
    Test complet du modèle de détection d'anomalies
    """
    print("=" * 70)
    print("🔬 TEST DU MODÈLE DE DÉTECTION D'ANOMALIES")
    print("=" * 70)
    
    # ============================================
    # 1. DONNÉES DE TEST
    # ============================================
    print("\n📊 1. GÉNÉRATION DES DONNÉES")
    print("-" * 50)
    
    # Créer des données normales (en cluster)
    X_normal, _ = make_blobs(n_samples=500, centers=1, n_features=10, 
                              cluster_std=0.5, random_state=42)
    
    # Créer des anomalies (loin du cluster)
    X_anomalies, _ = make_blobs(n_samples=50, centers=1, n_features=10,
                                 cluster_std=2.0, random_state=42)
    X_anomalies = X_anomalies + 5  # Décaler loin du cluster normal
    
    # Mélanger
    X = np.vstack([X_normal, X_anomalies])
    y_true = np.array([0] * 500 + [1] * 50)  # 0 = normal, 1 = anomalie
    
    print(f"   ├─ Données normales: {len(X_normal)}")
    print(f"   ├─ Anomalies: {len(X_anomalies)}")
    print(f"   └─ Total: {len(X)}")
    
    # ============================================
    # 2. CRÉATION ET ENTRAÎNEMENT
    # ============================================
    print("\n🏗️ 2. CRÉATION ET ENTRAÎNEMENT")
    print("-" * 50)
    
    model = AnomalyModelSklearn(
        model_dir="test_anomaly_model",
        weights=(0.4, 0.35, 0.25),
        verbose=0
    )
    
    print("   Entraînement du modèle...")
    model.fit(X, optimize=False)  # Désactiver optuna pour test rapide
    
    print("   ✅ Modèle entraîné")
    
    # ============================================
    # 3. PRÉDICTION
    # ============================================
    print("\n🎯 3. PRÉDICTION")
    print("-" * 50)
    
    # Scores sur les données d'entraînement
    scores = model.score(X)
    
    # Statistiques
    scores_normal = scores[:500]
    scores_anomaly = scores[500:]
    
    print(f"   Scores normaux: min={scores_normal.min():.4f}, "
          f"mean={scores_normal.mean():.4f}, max={scores_normal.max():.4f}")
    print(f"   Scores anomalies: min={scores_anomaly.min():.4f}, "
          f"mean={scores_anomaly.mean():.4f}, max={scores_anomaly.max():.4f}")
    
    # Trouver un seuil (percentile 95 des normaux)
    threshold = np.percentile(scores_normal, 95)
    print(f"\n   Seuil (95e percentile): {threshold:.4f}")
    
    # Prédictions binaires
    y_pred = (scores > threshold).astype(int)
    
    # Métriques
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    
    print(f"\n   Métriques sur données d'entraînement:")
    print(f"   ├─ Accuracy:  {acc:.4f}")
    print(f"   ├─ Precision: {prec:.4f}")
    print(f"   ├─ Recall:    {rec:.4f}")
    print(f"   └─ F1:        {f1:.4f}")
    
    # ============================================
    # 4. TEST SUR NOUVELLES DONNÉES
    # ============================================
    print("\n🧪 4. TEST SUR NOUVELLES DONNÉES")
    print("-" * 50)
    
    # Générer nouvelles données
    X_new_normal, _ = make_blobs(n_samples=100, centers=1, n_features=10,
                                  cluster_std=0.5, random_state=43)
    X_new_anomalies, _ = make_blobs(n_samples=30, centers=1, n_features=10,
                                     cluster_std=2.0, random_state=43)
    X_new_anomalies = X_new_anomalies + 5
    X_new = np.vstack([X_new_normal, X_new_anomalies])
    y_new_true = np.array([0] * 100 + [1] * 30)
    
    scores_new = model.score(X_new)
    y_new_pred = (scores_new > threshold).astype(int)
    
    acc_new = accuracy_score(y_new_true, y_new_pred)
    prec_new = precision_score(y_new_true, y_new_pred)
    rec_new = recall_score(y_new_true, y_new_pred)
    f1_new = f1_score(y_new_true, y_new_pred)
    
    print(f"   Accuracy:  {acc_new:.4f}")
    print(f"   Precision: {prec_new:.4f}")
    print(f"   Recall:    {rec_new:.4f}")
    print(f"   F1:        {f1_new:.4f}")
    
    # ============================================
    # 5. DÉTAIL POUR UN ÉCHANTILLON
    # ============================================
    print("\n🔍 5. DÉTAIL POUR UN ÉCHANTILLON")
    print("-" * 50)
    
    # Prendre un normal et une anomalie
    sample_normal = X_normal[0]
    sample_anomaly = X_anomalies[0]
    
    # Détail
    detail_normal = model.score_detail(sample_normal)
    detail_anomaly = model.score_detail(sample_anomaly)
    
    print("   Échantillon NORMAL:")
    print(f"   ├─ IF raw:    {detail_normal['if_raw']}")
    print(f"   ├─ LOF raw:   {detail_normal['lof_raw']}")
    print(f"   ├─ SVM raw:   {detail_normal['svm_raw']}")
    print(f"   ├─ IF norm:   {detail_normal['if_norm']}")
    print(f"   ├─ LOF norm:  {detail_normal['lof_norm']}")
    print(f"   ├─ SVM norm:  {detail_normal['svm_norm']}")
    print(f"   └─ Score final: {detail_normal['final']}")
    
    print("\n   Échantillon ANOMALIE:")
    print(f"   ├─ IF raw:    {detail_anomaly['if_raw']}")
    print(f"   ├─ LOF raw:   {detail_anomaly['lof_raw']}")
    print(f"   ├─ SVM raw:   {detail_anomaly['svm_raw']}")
    print(f"   ├─ IF norm:   {detail_anomaly['if_norm']}")
    print(f"   ├─ LOF norm:  {detail_anomaly['lof_norm']}")
    print(f"   ├─ SVM norm:  {detail_anomaly['svm_norm']}")
    print(f"   └─ Score final: {detail_anomaly['final']}")
    
    # ============================================
    # 6. SAUVEGARDE ET CHARGEMENT
    # ============================================
    print("\n💾 6. SAUVEGARDE ET CHARGEMENT")
    print("-" * 50)
    
    # Sauvegarder
    model.save_model(model.__dict__, model.model_dir)
    
    # Charger dans une nouvelle instance
    model2 = AnomalyModelSklearn(model_dir="test_anomaly_model")
    model2.load_model(model2.model_dir)
    
    # Vérifier que les prédictions sont identiques
    scores_original = model.score(X[:10])
    scores_loaded = model2.score(X[:10])
    
    if np.allclose(scores_original, scores_loaded, rtol=1e-5):
        print("   ✅ Sauvegarde/chargement OK - scores identiques")
    else:
        print("   ❌ Sauvegarde/chargement KO - scores différents")
        print(f"      Original: {scores_original[:3]}")
        print(f"      Chargé:   {scores_loaded[:3]}")
    
    # ============================================
    # 7. VISUALISATION
    # ============================================
    print("\n📊 7. VISUALISATION")
    print("-" * 50)
    
    plt.figure(figsize=(12, 8))
    
    # Distribution des scores
    plt.subplot(2, 2, 1)
    plt.hist(scores_normal, bins=30, alpha=0.5, label='Normaux', color='blue')
    plt.hist(scores_anomaly, bins=30, alpha=0.5, label='Anomalies', color='red')
    plt.axvline(threshold, color='black', linestyle='--', label=f'Seuil ({threshold:.2f})')
    plt.xlabel('Score d\'anomalie')
    plt.ylabel('Fréquence')
    plt.title('Distribution des scores')
    plt.legend()
    
    # Scores vs indices
    plt.subplot(2, 2, 2)
    plt.scatter(range(500), scores_normal, alpha=0.5, label='Normaux', color='blue', s=10)
    plt.scatter(range(500, 550), scores_anomaly, alpha=0.5, label='Anomalies', color='red', s=10)
    plt.axhline(threshold, color='black', linestyle='--', label=f'Seuil ({threshold:.2f})')
    plt.xlabel('Indice')
    plt.ylabel('Score')
    plt.title('Scores par échantillon')
    plt.legend()
    
    # ROC Curve
    plt.subplot(2, 2, 3)
    from sklearn.metrics import roc_curve, auc
    fpr, tpr, _ = roc_curve(y_true, scores)
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Courbe ROC')
    plt.legend()
    
    # Comparaison des 3 modèles (normalisés)
    plt.subplot(2, 2, 4)
    if_n = [detail['if_norm'] for detail in model.score_detail(X[:100])]
    lof_n = [detail['lof_norm'] for detail in model.score_detail(X[:100])]
    svm_n = [detail['svm_norm'] for detail in model.score_detail(X[:100])]
    
    plt.plot(if_n, label='IF', alpha=0.7)
    plt.plot(lof_n, label='LOF', alpha=0.7)
    plt.plot(svm_n, label='SVM', alpha=0.7)
    plt.axhline(0, color='black', linestyle='-', alpha=0.3)
    plt.xlabel('Échantillon')
    plt.ylabel('Score normalisé')
    plt.title('Scores des 3 modèles')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('anomaly_model_test.png', dpi=100)
    plt.show()
    
    print("\n   ✅ Graphiques sauvegardés dans 'anomaly_model_test.png'")
    
    # ============================================
    # 8. RÉSUMÉ
    # ============================================
    print("\n" + "=" * 70)
    print("📊 RÉSUMÉ DES TESTS")
    print("=" * 70)
    
    print(f"\n   📌 Entraînement:")
    print(f"      ├─ Données: {len(X)} échantillons")
    print(f"      ├─ Anomalies réelles: {sum(y_true)} ({sum(y_true)/len(y_true)*100:.1f}%)")
    print(f"      └─ Seuil: {threshold:.4f} (95e percentile)")
    
    print(f"\n   📌 Performance sur données d'entraînement:")
    print(f"      ├─ Accuracy:  {acc:.4f}")
    print(f"      ├─ Precision: {prec:.4f}")
    print(f"      ├─ Recall:    {rec:.4f}")
    print(f"      └─ F1:        {f1:.4f}")
    
    print(f"\n   📌 Performance sur nouvelles données:")
    print(f"      ├─ Accuracy:  {acc_new:.4f}")
    print(f"      ├─ Precision: {prec_new:.4f}")
    print(f"      ├─ Recall:    {rec_new:.4f}")
    print(f"      └─ F1:        {f1_new:.4f}")
    
    # Conclusion
    print(f"\n   🎯 Conclusion:")
    if f1_new > 0.8:
        print("      ✅ Modèle performant (F1 > 0.8)")
    elif f1_new > 0.6:
        print("      ⚠️ Modèle acceptable (F1 > 0.6), peut être amélioré")
    else:
        print("      ❌ Modèle à améliorer (F1 < 0.6)")
    
    print("\n" + "=" * 70)
    
    return model, {
        'train': {'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1},
        'test': {'acc': acc_new, 'prec': prec_new, 'rec': rec_new, 'f1': f1_new},
        'threshold': threshold,
        'auc': roc_auc
    }


if __name__ == "__main__":
    model, metrics = test_anomaly_model()
    
    print("\n🚀 Test terminé!")
    print(f"   Modèle sauvegardé dans: test_anomaly_model/")