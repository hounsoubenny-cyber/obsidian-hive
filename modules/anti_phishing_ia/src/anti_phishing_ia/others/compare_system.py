#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FONCTION COMPARE COMPLÈTE - Teste le système ENTIER (IA + Passive)
"""

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import numpy as np
import pandas as pd
from datetime import datetime
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
sys.path.append('/home/hounsousamuel/PROJET/anti-phishing')
sys.path.append('/home/hounsousamuel/PROJET/anti-phishing/core')
sys.path.append('/home/hounsousamuel/PROJET/anti-phishing/ml_model')
# ============================================================================
# STRATÉGIE 1: CASCADE (Whitelist → IA prioritaire → Passive si incertain)
# ============================================================================

def predict_url_cascade(antiphishing, url, features_extractor_func=None, check_blacklist=False):
    """
    Logique en cascade pour décision finale

    1. Whitelist → SAFE (confiance 100%)
    2. IA confiant (>95%) → Suit l'IA
    3. IA incertain → Utilise Passive pour trancher
    """
    from core.features_extractor import get_domain
    from core.generator import LEGITIMATE_DOMAINS

    domain = get_domain(url)
    # ÉTAPE 1: Whitelist
    if domain in LEGITIMATE_DOMAINS:
        return {
            'final_prediction': 'safe',
            'confidence': 1.0,
            'decision_source': 'whitelist'
        }

    # ÉTAPE 2: Prédictions
    ia_pred = antiphishing.predict_with_ia(url,features_extractor_func)
    passive_pred = antiphishing.predict_passive_analyze(url, check_blacklist)

    ia_label = ia_pred['predict']['0']
    ia_proba = ia_pred['predict_proba']['0']

    # ÉTAPE 3: Logique de décision
    if ia_proba['safe'] >= 0.95:
        # IA très confiant → SAFE
        return {
            'final_prediction': 'safe',
            'confidence': ia_proba['safe'],
            'decision_source': 'ia_high_confidence'
        }

    elif ia_proba['phishing'] >= 0.95:
        # IA très confiant → PHISHING
        return {
            'final_prediction': 'phishing',
            'confidence': ia_proba['phishing'],
            'decision_source': 'ia_high_confidence'
        }

    else:
        # IA incertain (80-95%) → Utilise Passive
        if passive_pred['risk_score'] >= 55:
            # Passive détecte risque élevé
            return {
                'final_prediction': 'phishing',
                'confidence': (ia_proba['phishing'] + passive_pred['risk_score']/100) / 2,
                'decision_source': 'passive_override'
            }
        else:
            # Passive confirme safe
            return {
                'final_prediction': ia_label,
                'confidence': max(ia_proba.values()),
                'decision_source': 'ia_with_passive_confirmation'
            }

# ============================================================================
# STRATÉGIE 2: WEIGHTED (Score pondéré IA + Passive)
# ============================================================================

def predict_url_weighted(antiphishing, url, features_extractor_func=None, check_blacklist=False, weight_ia=0.7, weight_passive=0.3):
    """
    Score final = weight_ia × IA + weight_passive × Passive

    Recommandé: weight_ia=0.7, weight_passive=0.3
    """
    from core.features_extractor import get_domain
    from core.generator import LEGITIMATE_DOMAINS

    domain = get_domain(url)

    if domain in LEGITIMATE_DOMAINS:
        return {
            'final_prediction': 'safe',
            'confidence': 1.0,
            'decision_source': 'whitelist'
        }

    # Prédictions
    ia_pred = antiphishing.predict_with_ia(url,features_extractor_func)
    passive_pred = antiphishing.predict_passive_analyze(url, check_blacklist)

    # Scores normalisés (0-1)
    ia_score_phishing = ia_pred['predict_proba']['0']['phishing']
    passive_score_phishing = passive_pred['risk_score'] / 100

    # Score final pondéré
    final_score_phishing = (
        weight_ia * ia_score_phishing +
        weight_passive * passive_score_phishing
    )

    # Décision
    if final_score_phishing >= 0.5:
        final = 'phishing'
    else:
        final = 'safe'

    return {
        'final_prediction': final,
        'final_score_phishing': final_score_phishing,
        'confidence': max(final_score_phishing, 1 - final_score_phishing),
        'decision_source': f'weighted_ia{weight_ia}_passive{weight_passive}'
    }

# ============================================================================
# STRATÉGIE 3: STRICT AND (Sécurité maximale)
# ============================================================================

def predict_url_strict(antiphishing, url, features_extractor_func=None, check_blacklist=False):
    """
    SAFE seulement si IA ET Passive disent tous les deux SAFE
    Dès qu'un dit PHISHING → PHISHING
    """
    from core.features_extractor import get_domain
    from core.generator import LEGITIMATE_DOMAINS

    domain = get_domain(url)

    if domain in LEGITIMATE_DOMAINS:
        return {
            'final_prediction': 'safe',
            'confidence': 1.0,
            'decision_source': 'whitelist'
        }

    ia_pred = antiphishing.predict_with_ia(url,features_extractor_func)
    passive_pred = antiphishing.predict_passive_analyze(url, check_blacklist)

    ia_label = ia_pred['predict']['0']
    passive_is_phishing = passive_pred['is_phishing']

    # Logique AND stricte
    if ia_label == 'phishing' or passive_is_phishing:
        return {
            'final_prediction': 'phishing',
            'confidence': 0.95,
            'decision_source': 'strict_and_detected'
        }
    else:
        return {
            'final_prediction': 'safe',
            'confidence': ia_pred['predict_proba']['0']['safe'],
            'decision_source': 'strict_and_both_safe'
        }

# ============================================================================
# FONCTION COMPARE COMPLÈTE (Teste le système ENTIER)
# ============================================================================

def compare_antiphishing_systems(
    system1,
    system2,
    test_urls_df,
    strategy='cascade',
    threshold=0.02,
    features_extractor_func1=None,
    features_extractor_func2=None
):
    """
    Compare DEUX systèmes AntiPhishing complets (IA + Passive)

    Parameters:
    -----------
    system1 : AntiPhishing
        Système actuel (avec PhishingIA model1)
    system2 : AntiPhishing
        Nouveau système (avec PhishingIA model2)
    test_urls_df : pd.DataFrame
        DataFrame avec colonnes 'url' et 'label'
    strategy : str
        'cascade', 'weighted', ou 'strict'
    threshold : float
        Amélioration minimale requise (ex: 0.02 = 2%)

    Returns:
    --------
    best_system : AntiPhishing
        Le meilleur système
    comparison_report : dict
        Rapport détaillé de la comparaison
    """

    print(f"🔍 Comparaison avec stratégie: {strategy}")
    print(f"📊 Test sur {len(test_urls_df)} URLs")

    # Sélectionner la fonction de prédiction
    if strategy == 'cascade':
        predict_fn = predict_url_cascade
    elif strategy == 'weighted':
        predict_fn = predict_url_weighted
    elif strategy == 'strict':
        predict_fn = predict_url_strict
    else:
        raise ValueError(f"Stratégie inconnue: {strategy}")

    # Tester système 1
    print("\n📊 Test système 1 (actuel)...")
    y_true = []
    y_pred1 = []
    confidences1 = []

    for _, row in test_urls_df.iterrows():
        url = row['url']
        true_label = row['label']

        result = predict_fn(system1, url,features_extractor_func1)

        y_true.append(true_label)
        y_pred1.append(result['final_prediction'])
        confidences1.append(result['confidence'])

    # Métriques système 1
    acc1 = accuracy_score(y_true, y_pred1)
    f1_1 = f1_score(y_true, y_pred1, pos_label='phishing', average='binary')
    precision1 = precision_score(y_true, y_pred1, pos_label='phishing', average='binary')
    recall1 = recall_score(y_true, y_pred1, pos_label='phishing', average='binary')
    score1 = 0.6 * f1_1 + 0.4 * acc1
    avg_confidence1 = np.mean(confidences1)

    print(f"   Accuracy: {acc1:.4f}")
    print(f"   F1-Score: {f1_1:.4f}")
    print(f"   Precision: {precision1:.4f}")
    print(f"   Recall: {recall1:.4f}")
    print(f"   Score composite: {score1:.4f}")
    print(f"   Confiance moyenne: {avg_confidence1:.4f}")

    # Tester système 2
    print("\n📊 Test système 2 (nouveau)...")
    y_pred2 = []
    confidences2 = []

    for _, row in test_urls_df.iterrows():
        url = row['url']
        result = predict_fn(system2, url,features_extractor_func2)

        y_pred2.append(result['final_prediction'])
        confidences2.append(result['confidence'])

    # Métriques système 2
    acc2 = accuracy_score(y_true, y_pred2)
    f1_2 = f1_score(y_true, y_pred2, pos_label='phishing', average='binary')
    precision2 = precision_score(y_true, y_pred2, pos_label='phishing', average='binary')
    recall2 = recall_score(y_true, y_pred2, pos_label='phishing', average='binary')
    score2 = 0.6 * f1_2 + 0.4 * acc2
    avg_confidence2 = np.mean(confidences2)

    print(f"   Accuracy: {acc2:.4f}")
    print(f"   F1-Score: {f1_2:.4f}")
    print(f"   Precision: {precision2:.4f}")
    print(f"   Recall: {recall2:.4f}")
    print(f"   Score composite: {score2:.4f}")
    print(f"   Confiance moyenne: {avg_confidence2:.4f}")

    # Calcul de l'amélioration
    improvement = score2 - score1

    # Rapport de comparaison
    comparison = {
        'strategy': strategy,
        'test_size': len(test_urls_df),
        'system1': {
            'accuracy': float(acc1),
            'f1_score': float(f1_1),
            'precision': float(precision1),
            'recall': float(recall1),
            'score_composite': float(score1),
            'avg_confidence': float(avg_confidence1)
        },
        'system2': {
            'accuracy': float(acc2),
            'f1_score': float(f1_2),
            'precision': float(precision2),
            'recall': float(recall2),
            'score_composite': float(score2),
            'avg_confidence': float(avg_confidence2)
        },
        'improvement': {
            'accuracy': float(acc2 - acc1),
            'f1_score': float(f1_2 - f1_1),
            'score_composite': float(improvement)
        },
        'threshold': threshold,
        'timestamp': datetime.now().isoformat()
    }

    # Décision
    print(f"\n⚖️  DÉCISION:")
    print(f"   Amélioration: {improvement*100:+.2f}%")
    print(f"   Seuil requis: {threshold*100:.2f}%")

    if improvement > threshold:
        print(f"   ✅ Système 2 adopté (amélioration > seuil)")
        comparison['winner'] = 'system2'
        comparison['decision'] = 'upgrade'
        return system2, comparison

    elif improvement < -threshold:
        print(f"   ⚠️  Système 1 conservé (régression détectée)")
        comparison['winner'] = 'system1'
        comparison['decision'] = 'keep_rollback'
        return system1, comparison

    else:
        print(f"   📊 Système 1 conservé (amélioration non significative)")
        comparison['winner'] = 'system1'
        comparison['decision'] = 'keep_insufficient'
        return system1, comparison


#  verify_ip_in_url, get_domain, get_domain_age, get_action,get_num_form, LEGITIMATE_DOMAINS,SUSPICIOUS_WORDS,SUSPICIOUS_TLDS, calculate_entropy
# from tldextract import extract
# from urllib.parse import urlparse, parse_qs
# import asyncio


# ============================================================================
# EXEMPLE D'UTILISATION
# ============================================================================

if __name__ == "__main__":
    # Exemple de test
    from main_phish import AntiPhishing, PhishingIA
    # from ml_model.phishing_ia import PhishingIA, names1 as NAMES, features_name as FEATURES_NAME
    from core.features_extractor import features_extractor_from_url_
    # Créer les systèmes
    system1 = AntiPhishing(
        model_path='model_phish.pkl',
        model_dir='model10',
        path_to_original_dataset='dataset.pkl',
    )
#     p = system1.PhishingIA.features_name
#     setattr(system1.PhishingIA,'features_name',FEATURES_NAME,)
#     setattr(system1.PhishingIA,'n_features',len(FEATURES_NAME))
#     p2 = system1.PhishingIA.features_name
#     print(p == p2)
#     input()
    system2 = AntiPhishing(
        model_path='model_phish.pkl',
        model_dir='model6',
        path_to_original_dataset='dataset.pkl',
        # features_name = NAMES,
        # n_features = len(NAMES)
    )

    # Charger les URLs de test
    test_urls = pd.DataFrame({
        'url': [
            'https://www.google.com/',
            'http://gooogle.com/login',
            'https://www.amazon.com/',
            'https://amaz0n.com/signin',
            # ... plus d'URLs
        ],
        'label': ['safe', 'phishing', 'safe', 'phishing']
    })

    # Tester les 3 stratégies
    for strategy in ['cascade', 'weighted', 'strict']:
        print(f"\n{'='*70}")
        print(f"TEST STRATÉGIE: {strategy.upper()}")
        print(f"{'='*70}")

        best_system, report = compare_antiphishing_systems(
            system1,
            system2,
            test_urls,
            strategy=strategy,
            threshold=0.02,
            features_extractor_func2=None #features_extractor_from_url_
        )

        print(f"\n📄 Gagnant: {report['winner']}")
        print(f"📄 Décision: {report['decision']}")
