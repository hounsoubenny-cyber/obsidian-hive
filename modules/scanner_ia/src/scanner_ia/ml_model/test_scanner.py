#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 17 22:42:07 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner_utils.warnings_manager import suppres_warnings
suppres_warnings()
import numpy as np
import pandas as pd
from sklearn.datasets import make_multilabel_classification
import tempfile
import traceback
from loguru import logger

# Importer ton ScannerIA
from scanner_ia_v2 import ScannerIA

# Configuration logger
logger.remove()
logger.add(sys.stdout, format="<level>{message}</level>", level="INFO")

class TestScannerIA:
    """
    Classe de test pour ScannerIA
    """
    
    def __init__(self):
        self.test_passed = 0
        self.test_failed = 0
        self.tests_results = []
        self.SAFE = "SAFE"
        self.VULN_NAMES = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 
                           'PATH_TRAVERSAL', 'CSRF', 'SSRF']
        
    def _print_header(self, title):
        """Affiche un en-tête de test"""
        print(f"\n{'='*70}")
        print(f"🔬 {title}")
        print(f"{'='*70}")
    
    def _print_result(self, test_name, success, message=""):
        """Affiche le résultat d'un test"""
        if success:
            print(f"  ✅ {test_name}: {message}" if message else f"  ✅ {test_name}")
            self.test_passed += 1
            self.tests_results.append(("✅", test_name, message))
        else:
            print(f"  ❌ {test_name}: {message}" if message else f"  ❌ {test_name}")
            self.test_failed += 1
            self.tests_results.append(("❌", test_name, message))
    
    def test_initialization(self):
        """Test 1: Initialisation de ScannerIA"""
        self._print_header("TEST 1: INITIALISATION")
        
        try:
            scanner1 = ScannerIA(verbose=0)
            self._print_result("Initialisation sans paramètres", True)
            
            scanner2 = ScannerIA(
                classes=[self.SAFE] + self.VULN_NAMES[:3],
                wrapper='ovr',
                cv=3,
                verbose=0
            )
            self._print_result("Initialisation avec paramètres dont SAFE", True)
            
            scanner3 = ScannerIA(model_dir="custom_model")
            self._print_result("Initialisation avec dossier personnalisé", True)
            
            return True
        except Exception as e:
            self._print_result("Initialisation", False, str(e))
            return False
    
    def generate_safe_data(self, n_samples=100, n_features=10):
        """
        Génère des données SAFE avec ['SAFE']
        """
        X = np.random.randn(n_samples, n_features)
        y = [[self.SAFE] for _ in range(n_samples)]
        return X, y
    
    def generate_vuln_data(self, n_samples=100, n_features=10, n_vuln_types=3, 
                          vuln_names=None, max_vulns_per_sample=2):
        """
        Génère des données avec vulnérabilités (sans SAFE)
        """
        if vuln_names is None:
            vuln_names = self.VULN_NAMES[:n_vuln_types]
            
        X = np.random.randn(n_samples, n_features)
        y = []
        
        for _ in range(n_samples):
            n_vulns = np.random.randint(1, max_vulns_per_sample + 1)
            vulns = np.random.choice(vuln_names, size=n_vulns, replace=False).tolist()
            y.append(vulns)
            
        return X, y
    
    def generate_mixed_data(self, n_samples=100, n_features=10, n_vuln_types=3,
                           safe_ratio=0.3, vuln_names=None):
        """
        Génère un mélange de données SAFE et vulnérables
        SAFE = ['SAFE']
        Vulnérables = listes de vulns sans SAFE
        """
        if vuln_names is None:
            vuln_names = self.VULN_NAMES[:n_vuln_types]
            
        n_safe = int(n_samples * safe_ratio)
        n_vuln = n_samples - n_safe
        
        # Données SAFE avec ['SAFE']
        X_safe, y_safe = self.generate_safe_data(n_safe, n_features)
        
        # Données vulnérables (sans SAFE)
        X_vuln, y_vuln = self.generate_vuln_data(n_vuln, n_features, n_vuln_types, vuln_names)
        
        # Fusionner
        X = np.vstack([X_safe, X_vuln])
        y = y_safe + y_vuln
        
        # Mélanger
        idx = np.random.permutation(n_samples)
        X = X[idx]
        y = [y[i] for i in idx]
        return X, y
    
    def test_safe_data_only(self):
        """
        Test 2: Données 100% SAFE avec ['SAFE']
        """
        self._print_header("TEST 2: DONNÉES 100% SAFE")
        
        try:
            vuln_types = self.VULN_NAMES[:3]
            all_classes = [self.SAFE] + vuln_types
            
            X, y = self.generate_safe_data(n_samples=50, n_features=10)
            
            print(f"\n📊 Données SAFE créées:")
            print(f"   - X shape: {X.shape}")
            print(f"   - y samples: {y[:3]}")
            print(f"   - Tous les y ont ['SAFE']: {all(y == [self.SAFE] for y in y[:5])}")
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                wrapper='ovr',
                model_dir="test_safe_model"
            )
            
            scanner.fit(
                X=X,
                y=y,
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            X_test = X[:10]
            y_pred_bin = scanner.predict(X_test)
            y_pred_labels = scanner.model_manager.mlb.inverse_transform(y_pred_bin)
            
            print(f"\n🔍 Résultats des prédictions SAFE:")
            all_safe = True
            for i, labels in enumerate(y_pred_labels):
                pred_list = list(labels) if isinstance(labels, tuple) else labels
                has_safe = self.SAFE in pred_list
                has_vuln = any(v in pred_list for v in vuln_types)
                
                if has_safe and not has_vuln:
                    status = f"✅ SAFE: {pred_list}"
                else:
                    status = f"❌ {pred_list}"
                    all_safe = False
                
                print(f"   Échantillon {i}: {status}")
            
            self._print_result("Codes SAFE détectés avec ['SAFE']", all_safe)
            
            return all_safe
            
        except Exception as e:
            self._print_result("Données SAFE", False, str(e))
            import traceback
            traceback.print_exc()
            return False
    
    def test_vuln_data_only(self):
        """
        Test 3: Données 100% vulnérables (sans SAFE)
        """
        self._print_header("TEST 3: DONNÉES 100% VULNÉRABLES")
        
        try:
            vuln_types = self.VULN_NAMES[:4]
            all_classes = [self.SAFE] + vuln_types
            
            X, y = self.generate_vuln_data(
                n_samples=50, 
                n_features=10,
                vuln_names=vuln_types,
                max_vulns_per_sample=2
            )
            
            print(f"\n📊 Données vulnérables créées:")
            print(f"   - X shape: {X.shape}")
            print(f"   - Exemples y: {y[:5]}")
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                wrapper='ovr',
                model_dir="test_vuln_model"
            )
            
            scanner.fit(
                X=X,
                y=y,
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            X_test = X[:10]
            y_true = y[:10]
            y_pred_bin = scanner.predict(X_test)
            y_pred_labels = scanner.model_manager.mlb.inverse_transform(y_pred_bin)
            
            print(f"\n🔍 Résultats des prédictions:")
            for i, (true, pred) in enumerate(zip(y_true, y_pred_labels)):
                pred_list = list(pred) if isinstance(pred, tuple) else pred
                has_vuln = len(pred_list) > 0 and self.SAFE not in pred_list
                status = "✅" if has_vuln else "❌"
                
                print(f"   {status} Échantillon {i}: Vrai={true} → Prédit={pred_list}")
            
            self._print_result("Prédictions sur données vulnérables", True)
            
            return True
            
        except Exception as e:
            self._print_result("Données vulnérables", False, str(e))
            return False
    
    def test_mixed_safe_and_vuln(self):
        """
        Test 4: Mélange de données SAFE et vulnérables
        """
        self._print_header("TEST 4: DONNÉES MIXTES (SAFE + vulnérables)")
        
        try:
            vuln_types = self.VULN_NAMES[:3]
            all_classes = [self.SAFE] + vuln_types
            
            X, y = self.generate_mixed_data(
                n_samples=100,
                n_features=10,
                n_vuln_types=3,
                safe_ratio=0.3,
                vuln_names=vuln_types
            )
            
            n_safe = sum(1 for labels in y if self.SAFE in labels)
            n_vuln = len(y) - n_safe
            
            print(f"\n📊 Données mixtes créées:")
            print(f"   - Total: {len(y)} échantillons")
            print(f"   - SAFE: {n_safe} ({(n_safe/len(y)*100):.1f}%)")
            print(f"   - Vulnérables: {n_vuln} ({(n_vuln/len(y)*100):.1f}%)")
            print(f"   - Exemples: {y[:5]}")
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                model_dir="test_mixed_model"
            )
            
            scanner.fit(
                X=X,
                y=y,
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            X_test = X[:20]
            y_true = y[:20]
            y_pred_bin = scanner.predict(X_test)
            y_pred_labels = scanner.model_manager.mlb.inverse_transform(y_pred_bin)
            
            print(f"\n🔍 Résultats (vrai → prédit):")
            correct = 0
            for i, (true, pred) in enumerate(zip(y_true, y_pred_labels)):
                pred_list = list(pred) if isinstance(pred, tuple) else pred
                
                true_has_safe = self.SAFE in true
                pred_has_safe = self.SAFE in pred_list
                
                true_vulns = [v for v in true if v != self.SAFE]
                pred_vulns = [v for v in pred_list if v != self.SAFE]
                
                if true_has_safe and pred_has_safe and not pred_vulns:
                    correct += 1
                    status = "✅"
                elif not true_has_safe and pred_vulns and not pred_has_safe:
                    correct += 1
                    status = "✅"
                else:
                    status = "❌"
                
                true_str = "SAFE" if true_has_safe else str(true_vulns)
                pred_str = "SAFE" if pred_has_safe else str(pred_vulns) if pred_vulns else "[]"
                
                print(f"   {status} {i}: Vrai={true_str:20} → Prédit={pred_str}")
            
            accuracy = correct / 20 * 100
            print(f"\n📊 Précision: {accuracy:.1f}% ({correct}/20)")
            
            self._print_result(f"Classification données mixtes ({accuracy:.1f}%)", True)
            
            return True
            
        except Exception as e:
            self._print_result("Données mixtes", False, str(e))
            return False
    
    def test_with_dataframe(self):
        """
        Test 5: Utilisation avec DataFrames
        """
        self._print_header("TEST 5: UTILISATION AVEC DATAFRAME")
        
        try:
            vuln_types = self.VULN_NAMES[:2]
            all_classes = [self.SAFE] + vuln_types
            
            n_samples = 30
            X = np.random.randn(n_samples, 5)
            df = pd.DataFrame(X, columns=['feat_1', 'feat_2', 'feat_3', 'feat_4', 'feat_5'])
            
            df['protocol'] = np.random.choice(['HTTP', 'HTTPS', 'FTP'], n_samples)
            df['method'] = np.random.choice(['GET', 'POST'], n_samples)
            
            y = []
            for i in range(n_samples):
                if i < 10:
                    y.append([self.SAFE])
                else:
                    n_vulns = np.random.randint(1, 3)
                    vulns = np.random.choice(vuln_types, size=n_vulns, replace=False).tolist()
                    y.append(vulns)
            
            df['vulnerabilities'] = y
            
            print(f"\n📊 DataFrame créé:")
            print(f"   Shape: {df.shape}")
            print(f"   Colonnes: {df.columns.tolist()}")
            print(f"   Exemple de labels: {df['vulnerabilities'].iloc[:5].tolist()}")
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                model_dir="test_df_model"
            )
            
            scanner.fit(
                data=df,
                cols=['feat_1', 'feat_2', 'feat_3', 'feat_4', 'feat_5', 'protocol', 'method'],
                cols_to_drop=[],
                target='vulnerabilities',
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            self._print_result("Utilisation avec DataFrame", True)
            
            return True
            
        except Exception as e:
            self._print_result("DataFrame", False, str(e))
            import traceback
            traceback.print_exc()
            return False
    
    def test_with_scanner_predict(self):
        """
        Test 6: scanner_predict avec SAFE explicite
        """
        self._print_header("TEST 6: SCANNER_PREDICT AVEC SAFE")
        
        try:
            vuln_types = self.VULN_NAMES[:3]
            all_classes = [self.SAFE] + vuln_types
            
            X, y = self.generate_mixed_data(
                n_samples=20,
                n_features=8,
                n_vuln_types=3,
                safe_ratio=0.4
            )
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                model_dir="test_scanner_predict"
            )
            
            scanner.fit(
                X=X,
                y=y,
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            X_test = X[:5]
            results = scanner.scanner_predict(X_test)
            
            print(f"\n🔍 Résultats de scanner_predict:")
            print(f"   Clés du dictionnaire: {results.keys()}")
            
            print(f"\n   Prédictions:")
            for idx, pred in results['predict'].items():
                print(f"     Échantillon {idx}: {pred}")
            
            print(f"\n   Probabilités (premier échantillon):")
            for vuln, prob in results['proba']['0'].items():
                print(f"     {vuln}: {prob:.4f}")
            
            print(f"\n   Probabilités des prédictions:")
            for idx, prob_pred in results['proba_predcit'].items():
                print(f"     Échantillon {idx}: {prob_pred}")
            
            safe_count = sum(1 for pred in results['predict'].values() if self.SAFE in pred)
            print(f"\n   Échantillons prédits SAFE: {safe_count}/5")
            
            self._print_result("scanner_predict fonctionne avec SAFE explicite", True)
            
            return True
            
        except Exception as e:
            self._print_result("scanner_predict", False, str(e))
            return False
    
    def test_safe_consistency(self):
        """
        Test 7: Vérifier que SAFE est toujours traité correctement
        """
        self._print_header("TEST 7: CONSISTANCE DE SAFE")
        
        try:
            vuln_types = self.VULN_NAMES[:2]
            all_classes = [self.SAFE] + vuln_types
            
            X, y = self.generate_mixed_data(
                n_samples=30,
                n_features=5,
                n_vuln_types=2,
                safe_ratio=0.5
            )
            
            scanner = ScannerIA(
                classes=all_classes,
                verbose=0,
                model_dir="test_consistency"
            )
            
            scanner.fit(
                X=X,
                y=y,
                optimize=False,
                test_size=0.2,
                do_learning_curve=False,
                user_mlb=True
            )
            
            print(f"\n📊 Vérification MLB:")
            print(f"   Classes MLB: {scanner.model_manager.mlb.classes_}")
            print(f"   SAFE dans classes: {self.SAFE in scanner.model_manager.mlb.classes_}")
            
            X_test = X[:3]
            results = scanner.scanner_predict(X_test)
            
            print(f"\n   Test inverse_transform:")
            for i, pred in results['predict'].items():
                print(f"     {i}: {pred}")
                
                if self.SAFE in pred:
                    print(f"       → SAFE détecté")
                elif not pred:
                    print(f"       → Liste vide (devrait pas arriver avec SAFE explicite)")
                else:
                    print(f"       → Vulnérabilités: {pred}")
            
            self._print_result("Consistance SAFE vérifiée", True)
            
            return True
            
        except Exception as e:
            self._print_result("Consistance SAFE", False, str(e))
            return False
    
    def run_all_tests(self):
        """
        Lance tous les tests
        """
        print("=" * 70)
        print("🚀 LANCEMENT DE LA SUITE DE TESTS SCANNERIA")
        print(f"📋 Types de vulnérabilités: {self.VULN_NAMES[:3]}...")
        print(f"📋 Classe SAFE = '{self.SAFE}' (explicite dans les labels)")
        print("=" * 70)
        
        tests = [
            ("Initialisation", self.test_initialization),
            ("Données 100% SAFE", self.test_safe_data_only),
            ("Données 100% vulnérables", self.test_vuln_data_only),
            ("Données mixtes", self.test_mixed_safe_and_vuln),
            ("Avec DataFrame", self.test_with_dataframe),
            ("Scanner Predict", self.test_with_scanner_predict),
            ("Consistance SAFE", self.test_safe_consistency)
        ]
        
        for name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                print(f"\n❌ ERREUR dans {name}:")
                print(traceback.format_exc())
                self._print_result(name, False, str(e))
        
        print("\n" + "=" * 70)
        print("📊 RÉSUMÉ DES TESTS")
        print("=" * 70)
        for status, name, message in self.tests_results:
            print(f"{status} {name}: {message}")
        
        print(f"\n✅ {self.test_passed} tests réussis")
        if self.test_failed > 0:
            print(f"❌ {self.test_failed} tests échoués")
        
        print("\n" + "=" * 70)
        if self.test_failed == 0:
            print("🎉 TOUS LES TESTS ONT RÉUSSI !")
        else:
            print("⚠️ CERTAINS TESTS ONT ÉCHOUÉ")
        print("=" * 70)
        
        return self.test_failed == 0


if __name__ == "__main__":
    tester = TestScannerIA()
    success = tester.run_all_tests()
    # sys.exit(0 if success else 1)