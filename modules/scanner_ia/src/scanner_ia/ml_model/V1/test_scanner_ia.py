import os
import sys
import pprint
import pandas as pd
import numpy as np
import random
from sklearn.metrics import f1_score, accuracy_score

# Ajouter le chemin du projet
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner_ia import ScannerIA
from modeloptimize import ModelOptimization

def test_initialisation():
    """Test 1: Initialisation de la classe"""
    print("\n" + "="*80)
    print("TEST 1: INITIALISATION DE LA CLASSE")
    print("="*80)
    
    try:
        features = [f"feature_{i}" for i in range(5)]
        scanner = ScannerIA(
            classes=['A', 'B', 'C'],
            n_features=5,
            model_dir='demo_model',
            dataset_file='demo_dataset.joblib',
            model_file='demo_model.joblib',
            deep_file='demo_deep.keras',
            features_name=features,
            learning_rate=0.01
        )
        print("✅ Initialisation réussie")
        print(f"   - Nombre de features: {scanner.n_features}")
        print(f"   - Classes: {scanner.classes}")
        print(f"   - Features names: {scanner.features_name}")
        return scanner
    except Exception as e:
        print(f"❌ Erreur d'initialisation: {type(e).__name__} - {e}")
        return None

def test_entrainement(scanner):
    """Test 2: Entraînement du modèle"""
    print("\n" + "="*80)
    print("TEST 2: ENTRAINEMENT DU MODELE")
    print("="*80)
    
    if scanner is None:
        print("❌ Scanner non initialisé, test ignoré")
        return False
    
    try:
        np.random.seed(42)
        random.seed(42)  # Pour reproductibilité
        n_samples = 100
        feature_0 = np.random.uniform(0.1, 0.5, n_samples)
        feature_1 = np.random.uniform(0.6, 1.0, n_samples)
        feature_2 = np.random.uniform(5.0, 9.0, n_samples)
        feature_3 = np.random.choice([0, 1], n_samples)
        feature_4 = np.random.uniform(10, 50, n_samples)
        
        labels = []
        possible_labels = [['A'], ['B'], ['C'], ['A', 'B'], ['A', 'C'], ['B', 'C'], ['A', 'B', 'C']]
        for _ in range(n_samples):
            labels.append(random.choice(possible_labels))  # Utiliser random.choice
        
        data_train = {
            'feature_0': feature_0,
            'feature_1': feature_1,
            'feature_2': feature_2,
            'feature_3': feature_3,
            'feature_4': feature_4,
            'label': labels
        }
        
        print("📊 Données d'entraînement (100 échantillons):")
        df = pd.DataFrame(data_train)
        print(df.head(10).to_string())
        
        print("\n🔄 Démarrage de l'entraînement...")
        scanner.fit(data_train)
        print("✅ Entraînement terminé avec succès")
        print(f"   Meilleurs paramètres: {scanner.bayes.best_params_}")
        print(f"   Meilleur score F1 (weighted): {scanner.bayes.best_score_:.4f}")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de l'entraînement: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        return False

def test_prediction_avec_labels(scanner):
    """Test 3: Prédiction avec labels (évaluation)"""
    print("\n" + "="*80)
    print("TEST 3: PREDICTION AVEC LABELS (EVALUATION)")
    print("="*80)
    
    if scanner is None or scanner.model is None:
        print("❌ Modèle non entraîné, test ignoré")
        return
    
    try:
        data_test_with_labels = {
            'feature_0': [0.15, 0.35, 0.25],
            'feature_1': [0.95, 0.75, 0.85],
            'feature_2': [5.5, 7.5, 6.5],
            'feature_3': [1, 0, 1],
            'feature_4': [15, 35, 25],
            'label': [['A'], ['B'], ['A', 'B']]
        }
        
        print("📊 Données de test avec labels:")
        df = pd.DataFrame(data_test_with_labels)
        print(df.to_string())
        
        print("\n🔮 Prédiction en cours...")
        resultats = scanner.predict(data_test_with_labels)
        
        if resultats:
            print("\n✅ Prédictions réussies:")
            print("\n📈 Probabilités prédites:")
            pprint.pprint(resultats['predict_proba'])
            
            print("\n🎯 Labels prédits:")
            pprint.pprint(resultats['predict'])
            
            print("\n✔️ Labels vrais:")
            pprint.pprint(resultats['true_labels'])
            
            print("\n📊 Comparaison prédiction vs réalité:")
            for i in resultats['predict'].keys():
                pred = resultats['predict'][i]
                true = resultats['true_labels'].get(i, 'N/A')
                match = "✅" if pred == true else "❌"
                print(f"   Échantillon {i}: Prédit={pred}, Vrai={true} {match}")
            
            # Calculer les métriques
            y_true = scanner.mlb.transform(data_test_with_labels['label'])
            y_pred = scanner.mlb.transform([resultats['predict'][i] for i in range(len(resultats['predict']))])
            f1 = f1_score(y_true, y_pred, average='weighted')
            accuracy = accuracy_score(y_true, y_pred)
            print(f"\n✅ Métriques de performance:")
            print(f"   F1 Score (weighted): {f1:.4f}")
            print(f"   Accuracy: {accuracy:.4f}")
        else:
            print("❌ Aucun résultat retourné")
            
    except Exception as e:
        print(f"❌ Erreur lors de la prédiction: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()

def test_prediction_sans_labels(scanner):
    """Test 4: Prédiction sans labels (production)"""
    print("\n" + "="*80)
    print("TEST 4: PREDICTION SANS LABELS (PRODUCTION)")
    print("="*80)
    
    if scanner is None or scanner.model is None:
        print("❌ Modèle non entraîné, test ignoré")
        return
    
    try:
        data_test_no_labels = {
            'feature_0': [0.12, 0.42, 0.28],
            'feature_1': [0.88, 0.72, 0.85],
            'feature_2': [5.2, 8.1, 6.5],
            'feature_3': [0, 1, 1],
            'feature_4': [12, 42, 28]
        }
        
        print("📊 Données de test sans labels (cas réel):")
        df = pd.DataFrame(data_test_no_labels)
        print(df.to_string())
        
        print("\n🔮 Prédiction en cours...")
        resultats = scanner.predict(data_test_no_labels)
        
        if resultats:
            print("\n✅ Prédictions réussies:")
            print("\n📈 Probabilités prédites:")
            pprint.pprint(resultats['predict_proba'])
            
            print("\n🎯 Labels prédits:")
            pprint.pprint(resultats['predict'])
            
            print("\n✔️ Labels vrais:")
            print(f"   {resultats['true_labels']} (vide car pas de labels fournis)")
        else:
            print("❌ Aucun résultat retourné")
            
    except Exception as e:
        print(f"❌ Erreur lors de la prédiction: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()

def test_sauvegarde_chargement(scanner):
    """Test 5: Sauvegarde et rechargement du modèle"""
    print("\n" + "="*80)
    print("TEST 5: SAUVEGARDE ET RECHARGEMENT")
    print("="*80)
    
    if scanner is None or scanner.model is None:
        print("❌ Modèle non entraîné, test ignoré")
        return
    
    try:
        data_test = {
            'feature_0': [0.15],
            'feature_1': [0.95],
            'feature_2': [5.5],
            'feature_3': [1],
            'feature_4': [15]
        }
        
        print("🔮 Prédiction avant sauvegarde...")
        result_before = scanner.predict(data_test)
        pred_before = result_before['predict'][0]
        print(f"   Label prédit: {pred_before}")
        
        print("\n💾 Sauvegarde du modèle...")
        scanner.save_model()
        
        print("\n📂 Création d'une nouvelle instance...")
        features = [f"feature_{i}" for i in range(5)]
        scanner_new = ScannerIA(
            classes=['A', 'B', 'C'],
            n_features=5,
            model_dir='demo_model',
            dataset_file='demo_dataset.joblib',
            model_file='demo_model.joblib',
            deep_file='demo_deep.keras',
            features_name=features
        )
        
        print("\n🔮 Prédiction après rechargement...")
        result_after = scanner_new.predict(data_test)
        pred_after = result_after['predict'][0]
        print(f"   Label prédit: {pred_after}")
        
        if pred_before == pred_after:
            print("\n✅ Sauvegarde/Rechargement OK: prédictions identiques")
        else:
            print(f"\n⚠️ Attention: prédictions différentes!")
            print(f"   Avant: {pred_before}")
            print(f"   Après: {pred_after}")
            
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde/rechargement: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()

def test_model_optimization(scanner):
    """Test 6: Vérification de ModelOptimization"""
    print("\n" + "="*80)
    print("TEST 6: VÉRIFICATION DE MODEL OPTIMIZATION")
    print("="*80)
    
    if scanner is None:
        print("❌ Scanner non initialisé, test ignoré")
        return
    
    try:
        np.random.seed(42)
        random.seed(42)
        n_samples = 20
        X = pd.DataFrame({
            'feature_0': np.random.uniform(0.1, 0.5, n_samples),
            'feature_1': np.random.uniform(0.6, 1.0, n_samples),
            'feature_2': np.random.uniform(5.0, 9.0, n_samples),
            'feature_3': np.random.choice([0, 1], n_samples),
            'feature_4': np.random.uniform(10, 50, n_samples)
        })
        y = scanner.mlb.transform([random.choice([['A'], ['B'], ['C'], ['A', 'B'], ['A', 'C'], ['B', 'C'], ['A', 'B', 'C']]) for _ in range(n_samples)])
        
        model_optimize = ModelOptimization(
            scanner.bayes, X, y, random_state=scanner.random_state, 
            scoring='f1_weighted', save_dir=scanner.save_dir,
            min_gain=scanner.min_gain, min_features_ratio=scanner.min_features_ratio,
            cv=scanner.cv, features_name=scanner.features_name
        )
        
        print("\n🔄 Optimisation en cours...")
        bayes, mask, test_x, test_y = model_optimize.run()
        print("✅ Optimisation terminée")
        print(f"   Meilleurs paramètres: {bayes.best_params_}")
        print(f"   Meilleur score F1 (weighted): {bayes.best_score_:.4f}")
        
    except Exception as e:
        print(f"❌ Erreur lors de l'optimisation: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()

def test_performance(scanner):
    """Test 7: Évaluation des performances du modèle"""
    print("\n" + "="*80)
    print("TEST 7: ÉVALUATION DES PERFORMANCES")
    print("="*80)
    
    if scanner is None or scanner.model is None:
        print("❌ Modèle non entraîné, test ignoré")
        return
    
    try:
        np.random.seed(42)
        random.seed(42)
        data_test = {
            'feature_0': np.random.uniform(0.1, 0.5, 20),
            'feature_1': np.random.uniform(0.6, 1.0, 20),
            'feature_2': np.random.uniform(5.0, 9.0, 20),
            'feature_3': np.random.choice([0, 1], 20),
            'feature_4': np.random.uniform(10, 50, 20),
            'label': [random.choice([['A'], ['B'], ['C'], ['A', 'B'], ['A', 'C'], ['B', 'C'], ['A', 'B', 'C']]) for _ in range(20)]
        }
        
        print("📊 Données de test pour évaluation:")
        df = pd.DataFrame(data_test)
        print(df.head(5).to_string())
        
        print("\n🔮 Prédiction en cours...")
        resultats = scanner.predict(data_test)
        
        if resultats:
            y_true = scanner.mlb.transform(data_test['label'])
            y_pred = scanner.mlb.transform([resultats['predict'][i] for i in range(len(resultats['predict']))])
            f1 = f1_score(y_true, y_pred, average='weighted')
            accuracy = accuracy_score(y_true, y_pred)
            print(f"\n✅ Métriques de performance:")
            print(f"   F1 Score (weighted): {f1:.4f}")
            print(f"   Accuracy: {accuracy:.4f}")
        else:
            print("❌ Aucun résultat retourné")
            
    except Exception as e:
        print(f"❌ Erreur lors de l'évaluation: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()

def test_cas_limites():
    """Test 8: Cas limites et erreurs"""
    print("\n" + "="*80)
    print("TEST 8: CAS LIMITES ET GESTION D'ERREURS")
    print("="*80)
    
    features = [f"feature_{i}" for i in range(5)]
    scanner = ScannerIA(
        classes=['A', 'B', 'C'],
        n_features=5,
        model_dir='demo_model_test',
        dataset_file='demo_dataset_test.joblib',
        model_file='demo_model_test.joblib',
        deep_file='demo_deep_test.keras',
        features_name=features
    )
    
    print("\n📋 Test 8.1: Données avec colonnes manquantes")
    try:
        data_incomplete = {
            'feature_0': [0.1],
            'feature_1': [1.0],
            'feature_3': [0],
            'feature_4': [10],
            'label': [['A']]
        }
        scanner.fit(data_incomplete)
        print("❌ Devrait échouer mais a réussi")
    except (ValueError, KeyError) as e:
        print(f"✅ Erreur correctement levée: {e}")
    except Exception as e:
        print(f"⚠️ Erreur inattendue: {type(e).__name__} - {e}")
    
    print("\n📋 Test 8.2: Prédiction sans modèle entraîné")
    try:
        data_test = {
            'feature_0': [0.1],
            'feature_1': [1.0],
            'feature_2': [5],
            'feature_3': [0],
            'feature_4': [10]
        }
        result = scanner.predict(data_test)
        if result is None:
            print("✅ Retour None correct (pas de modèle)")
        else:
            print("❌ Devrait retourner None")
    except Exception as e:
        print(f"⚠️ Erreur inattendue: {type(e).__name__} - {e}")
    
    print("\n📋 Test 8.3: Données vides")
    try:
        scanner.fit({})
        print("❌ Devrait échouer mais a réussi")
    except ValueError as e:
        print(f"✅ Erreur correctement levée: {e}")
    except Exception as e:
        print(f"⚠️ Erreur inattendue: {type(e).__name__} - {e}")

def main():
    print("\n" + "🧪"*40)
    print("SUITE DE TESTS COMPLÈTE POUR ScannerIA")
    print("🧪"*40)
    
    # Supprimer le dataset existant pour éviter les conflits
    try:
        os.remove('/home/hounsousamuel/PROJET/scanner/ml_model/data/datasets/demo_dataset.joblib')
        print("✅ Dataset existant supprimé")
    except FileNotFoundError:
        print("ℹ️ Aucun dataset existant à supprimer")
    
    scanner = test_initialisation()
    training_success = test_entrainement(scanner)
    
    if training_success:
        test_prediction_avec_labels(scanner)
        test_prediction_sans_labels(scanner)
        test_sauvegarde_chargement(scanner)
        test_performance(scanner)
        test_model_optimization(scanner)
    
    test_cas_limites()
    
    print("\n" + "="*80)
    print("FIN DES TESTS")
    print("="*80)

if __name__ == "__main__":
    # Supprimer les fichiers de modèle existants
    try:
        os.remove('/home/hounsousamuel/PROJET/scanner/ml_model/data/models/demo_model/demo_deep.keras')
        os.remove('/home/hounsousamuel/PROJET/scanner/ml_model/data/models/demo_model/demo_model.joblib')
        print("✅ Fichiers de modèle existants supprimés")
    except FileNotFoundError:
        print("ℹ️ Aucun fichier de modèle existant à supprimer")
    main()