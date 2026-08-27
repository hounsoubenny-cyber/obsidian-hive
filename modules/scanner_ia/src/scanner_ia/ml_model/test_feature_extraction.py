#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 14:27:26 2026

@author: hounsousamuel
"""

"""
Fonction de test pour FeatureExtractor avec vrais serveurs
À placer dans le même dossier que feature_extractor.py
"""

import sys
import asyncio
import aiohttp
import pandas as pd
import numpy as np
from datetime import datetime
from loguru import logger
import json
import time

# Importer les composants nécessaires
from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.fuzzer.active_fuzzer import Fuzzer
from analyzers.passive_analyzer import PassiveCodeAnalyzer
from analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.ml_model.features_extractor import FeatureExtractor, FEATURES_LIST
from scanner_ia.ml_model.config import VULNS

# Configuration logger
logger.remove()
logger.add(sys.stdout, format="<level>{message}</level>", level="INFO")

# ============================================
# LISTE DES SERVEURS DE TEST PAR DÉFAUT
# ============================================
DEFAULT_TEST_URLS = [
    # Serveurs locaux de test
    "http://localhost:8080",           # Serveur de test local
    "http://localhost:5000",           # Flask/FastAPI local
    # "http://127.0.0.1:8080",           # Alternative localhost
    # "http://localhost:3000",           # Node.js/React dev server
    
#     # Sites d'entraînement sécurisés
#     "https://httpbin.org",              # API de test HTTP
#     "https://httpbin.org/html",         # Page HTML simple
#     "https://httpbin.org/forms/post",   # Formulaire de test
#     "https://httpbin.org/cookies",      # Test cookies
    
#     # Sites vulnérables pour entraînement
#     "http://testphp.vulnweb.com",       # Acunetix test site (PHP vulnérable)
#     "http://testasp.vulnweb.com",       # Acunetix test site (ASP vulnérable)
#     "https://juice-shop.herokuapp.com", # OWASP Juice Shop
#     "http://dvwa.local",                 # Damn Vulnerable Web App (si en local)
#     "https://portswigger.net/web-security", # PortSwigger labs
    
#     # Sites e-commerce pour tests variés
#     "https://books.toscrape.com",        # Catalogue de livres
#     "https://quotes.toscrape.com",       # Citations
#     "https://demo.saleor.io",            # Démo e-commerce
    
#     # APIs de test
#     "https://jsonplaceholder.typicode.com", # Fake API
#     "https://reqres.in/api/users",        # Test API
    
#     # Sites statiques
#     "http://example.com",
#     "https://www.example.org",
]

class RealFeatureExtractorTest:
    """
    Testeur réel du FeatureExtractor sur vrais serveurs
    """
    
    def __init__(self, urls=None, output_dir="test_output"):
        """
        Args:
            urls: Liste d'URLs à tester (si None, utilise DEFAULT_TEST_URLS)
            output_dir: Dossier de sortie pour les résultats
        """
        self.urls = urls if urls is not None else DEFAULT_TEST_URLS
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.feature_extractor = FeatureExtractor()
        self.test_results = []
        self.stats = {
            'total_urls': len(self.urls),
            'successful': 0,
            'failed': 0,
            'total_features': 0,
            'start_time': None,
            'end_time': None,
            'url_stats': {}
        }
        
    def _print_header(self, title):
        """Affiche un en-tête de test"""
        print(f"\n{'='*70}")
        print(f"🔬 {title}")
        print(f"{'='*70}")
    
    def _print_result(self, test_name, success, message=""):
        """Affiche le résultat d'un test"""
        if success:
            print(f"  ✅ {test_name}: {message}" if message else f"  ✅ {test_name}")
        else:
            print(f"  ❌ {test_name}: {message}" if message else f"  ❌ {test_name}")
    
    async def scan_single_url(self, session, url, index, total):
        """
        Scanne une URL unique et extrait ses features
        """
        print(f"\n  📌 [{index}/{total}] Analyse de: {url}")
        print(f"  {'─'*50}")
        
        url_stats = {
            'url': url,
            'status': 'pending',
            'analyzer_time': 0,
            'passive_time': 0,
            'code_time': 0,
            'fuzzer_time': 0,
            'extract_time': 0,
            'total_time': 0,
            'features_shape': None,
            'error': None
        }
        
        try:
            # Initialiser les composants
            analyzer_helper = AnalyzerHelper(session=session, use_cache=True)
            passive_analyzer = PassiveCodeAnalyzer()
            code_analyzer = CodeAnalyzer(debug=False)
            fuzzer = Fuzzer(session=session, debug=False)
            
            # ===== 1. ANALYZER HELPER (Crawl + Parse) =====
            print(f"    ⏳ Crawl et parsing...")
            start = time.time()
            analyzer_result = await analyzer_helper.analyse_and_parse_all(
                url=url,
                verify_reachability=True,
                restore=False,
                fetch=True,
                silent=True
            )
            analyzer_time = time.time() - start
            
            if not analyzer_result.elements:
                raise Exception("Aucune page trouvée")
            
            print(f"    ✅ {len(analyzer_result.elements)} pages trouvées ({analyzer_time:.2f}s)")
            url_stats['analyzer_time'] = analyzer_time
            
            # ===== 2. ANALYSE PASSIVE =====
            print(f"    ⏳ Analyse passive...")
            start = time.time()
            passive_result = passive_analyzer.analyse(analyzer_result)
            passive_time = time.time() - start
            print(f"    ✅ {passive_result.total_vulns} vulns passives ({passive_time:.2f}s)")
            url_stats['passive_time'] = passive_time
            
            # ===== 3. ANALYSE CODE =====
            print(f"    ⏳ Analyse code statique...")
            start = time.time()
            code_result = code_analyzer.analyse(analyzer_result)
            code_time = time.time() - start
            total_code_vulns = sum(
                len(r.get('body', {}).vulns) + 
                sum(s.vulns for s in r.get('balises_script', {}).values())
                for r in code_result.results.values()
            )
            print(f"    ✅ {total_code_vulns} vulns code ({code_time:.2f}s)")
            url_stats['code_time'] = code_time
            
            # ===== 4. FUZZING ACTIF =====
            print(f"    ⏳ Fuzzing actif...")
            start = time.time()
            
            # Limiter le fuzzing pour les tests (optionnel)
            original_max_test = fuzzer.config.MAX_TEST
            fuzzer.config.MAX_TEST = 20  # Limiter à 20 payloads par URL pour test
            
            fuzzer_result = await fuzzer.fuzz(
                base_url=url,
                analyzer_helper_result=analyzer_result,
                limit_vuln=None,  # Tester toutes les vulnérabilités
                time_between=0.001,
                dynamic_timeout=False
            )
            
            # Restaurer la config
            fuzzer.config.MAX_TEST = original_max_test
            
            fuzzer_time = time.time() - start
            print(f"    ✅ {fuzzer_result.stats.get('total_tests', 0)} tests, "
                  f"{fuzzer_result.stats.get('total_vulns', 0)} vulns actives ({fuzzer_time:.2f}s)")
            url_stats['fuzzer_time'] = fuzzer_time
            
            # ===== 5. EXTRACTION FEATURES =====
            print(f"    ⏳ Extraction des features...")
            start = time.time()
            
            df = await self.feature_extractor.extract(
                analyzer_helper_result=analyzer_result,
                passive_analyzer_result=passive_result,
                code_analyzer_result=code_result,
                fuzzer_result=fuzzer_result
            )
            
            extract_time = time.time() - start
            print(f"    ✅ Features extraites: {df.shape} ({extract_time:.2f}s)")
            url_stats['extract_time'] = extract_time
            url_stats['features_shape'] = str(df.shape)
            
            # ===== 6. STATISTIQUES GLOBALES =====
            total_time = analyzer_time + passive_time + code_time + fuzzer_time + extract_time
            url_stats['total_time'] = total_time
            url_stats['status'] = 'success'
            self.stats['successful'] += 1
            
            print(f"    {'─'*50}")
            print(f"    ✅ TOTAL: {total_time:.2f}s | Features: {df.shape}")
            
            # Sauvegarder les features pour cette URL
            output_file = os.path.join(
                self.output_dir, 
                f"features_{url.replace('://', '_').replace('/', '_')}.csv"
            )
            df.to_csv(output_file, index=False)
            print(f"    💾 Sauvegardé: {output_file}")
            
            # Ajouter les vulnérabilités trouvées aux stats
            url_stats['vulns'] = {
                'passive': passive_result.total_vulns,
                'code': total_code_vulns,
                'active': fuzzer_result.stats.get('total_vulns', 0),
                'by_type': fuzzer_result.stats.get('vuln_count', {})
            }
            
            return url_stats, df
            
        except Exception as e:
            print(f"    ❌ ERREUR: {str(e)}")
            url_stats['status'] = 'failed'
            url_stats['error'] = str(e)
            self.stats['failed'] += 1
            return url_stats, None
        
        finally:
            # Nettoyage
            await analyzer_helper.close()
    
    async def run_test(self, limit=None, save_all=True):
        """
        Lance les tests sur toutes les URLs
        
        Args:
            limit: Nombre maximum d'URLs à tester (None = toutes)
            save_all: Sauvegarder toutes les features dans un fichier global
        """
        self._print_header(f"TEST RÉEL DU FEATURE EXTRACTOR")
        
        urls_to_test = self.urls[:limit] if limit else self.urls
        print(f"\n📋 {len(urls_to_test)} URLs à tester:")
        for i, url in enumerate(urls_to_test, 1):
            print(f"  {i}. {url}")
        
        self.stats['start_time'] = datetime.now().isoformat()
        start_global = time.time()
        
        async with aiohttp.ClientSession() as session:
            # Scanner chaque URL
            all_features = []
            
            for i, url in enumerate(urls_to_test, 1):
                url_stats, df = await self.scan_single_url(session, url, i, len(urls_to_test))
                self.stats['url_stats'][url] = url_stats
                
                if df is not None:
                    all_features.append(df)
                
                # Pause entre les scans pour éviter de surcharger
                if i < len(urls_to_test):
                    print(f"\n  ⏱️  Pause de 2 secondes avant la prochaine URL...")
                    await asyncio.sleep(2)
            
            # Fusionner toutes les features
            if all_features and save_all:
                print(f"\n📊 Fusion de toutes les features...")
                combined_df = pd.concat(all_features, ignore_index=True)
                
                # Sauvegarder
                combined_file = os.path.join(self.output_dir, "all_features_combined.csv")
                combined_df.to_csv(combined_file, index=False)
                
                # Statistiques globales
                self.stats['total_features'] = combined_df.shape[1]
                self.stats['total_samples'] = combined_df.shape[0]
                
                print(f"   ✅ Shape final: {combined_df.shape}")
                print(f"   💾 Sauvegardé: {combined_file}")
                
                # Analyse des valeurs manquantes
                missing = combined_df.isna().sum().sum()
                if missing > 0:
                    print(f"   ⚠️  Valeurs manquantes: {missing}")
                    
                    # Remplacer par 0 si nécessaire
                    combined_df = combined_df.fillna(0)
                    combined_df.to_csv(combined_file.replace('.csv', '_clean.csv'), index=False)
                    print(f"   💾 Version clean: {combined_file.replace('.csv', '_clean.csv')}")
        
        # Statistiques finales
        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['total_time'] = time.time() - start_global
        
        self._print_results()
        
        return self.stats, combined_df if all_features else None
    
    def _print_results(self):
        """Affiche les résultats détaillés"""
        print("\n" + "="*70)
        print("📊 RÉSULTATS DU TEST")
        print("="*70)
        
        print(f"\n📈 STATISTIQUES GLOBALES:")
        print(f"  ├─ URLs testées: {self.stats['total_urls']}")
        print(f"  ├─ Succès: {self.stats['successful']}")
        print(f"  ├─ Échecs: {self.stats['failed']}")
        print(f"  ├─ Taux de succès: {(self.stats['successful']/self.stats['total_urls']*100):.1f}%")
        print(f"  ├─ Temps total: {self.stats['total_time']:.2f}s")
        if self.stats.get('total_samples'):
            print(f"  ├─ Échantillons totaux: {self.stats['total_samples']}")
            print(f"  └─ Features totales: {self.stats['total_features']}")
        
        print(f"\n📋 DÉTAIL PAR URL:")
        for url, stats in self.stats['url_stats'].items():
            status_icon = "✅" if stats['status'] == 'success' else "❌"
            print(f"\n  {status_icon} {url}")
            
            if stats['status'] == 'success':
                print(f"     ├─ Analyzer: {stats['analyzer_time']:.2f}s")
                print(f"     ├─ Passive: {stats['passive_time']:.2f}s")
                print(f"     ├─ Code: {stats['code_time']:.2f}s")
                print(f"     ├─ Fuzzer: {stats['fuzzer_time']:.2f}s")
                print(f"     ├─ Extract: {stats['extract_time']:.2f}s")
                print(f"     ├─ Total: {stats['total_time']:.2f}s")
                print(f"     ├─ Features: {stats['features_shape']}")
                
                if 'vulns' in stats:
                    v = stats['vulns']
                    print(f"     └─ Vulnérabilités:")
                    print(f"        ├─ Passives: {v['passive']}")
                    print(f"        ├─ Code: {v['code']}")
                    print(f"        └─ Actives: {v['active']}")
                    
                    if v['by_type']:
                        print(f"           └─ Par type: {dict(list(v['by_type'].items())[:3])}...")
            else:
                print(f"     └─ Erreur: {stats['error']}")
        
        print("\n" + "="*70)
        if self.stats['failed'] == 0:
            print("🎉 TOUS LES TESTS ONT RÉUSSI !")
        else:
            print(f"⚠️  {self.stats['failed']} ÉCHEC(S) - Vérifier les logs")
        print("="*70)


# ============================================
# FONCTION PRINCIPALE
# ============================================
async def test_feature_extractor(urls=None, limit=None, output_dir="test_output"):
    """
    Fonction principale de test
    
    Args:
        urls: Liste d'URLs à tester (si None, utilise DEFAULT_TEST_URLS)
        limit: Nombre maximum d'URLs à tester
        output_dir: Dossier de sortie
    
    Returns:
        stats, dataframe combiné
    """
    tester = RealFeatureExtractorTest(urls=urls, output_dir=output_dir)
    return await tester.run_test(limit=limit)


def main(limit, urls, output="test_output"):
    """Point d'entrée principal"""
    # import argparse
    
    # parser = argparse.ArgumentParser(description="Test FeatureExtractor sur vrais serveurs")
    # parser.add_argument('--urls', nargs='+', help='URLs à tester')
    # parser.add_argument('--limit', type=int, help='Nombre max d\'URLs à tester')
    # parser.add_argument('--output', default='test_output', help='Dossier de sortie')
    # parser.add_argument('--list-default', action='store_true', help='Afficher les URLs par défaut')
    
    # args = parser.parse_args()
    
    # if args.list_default:
    #     print("\n📋 URLs de test par défaut:")
    #     for i, url in enumerate(DEFAULT_TEST_URLS, 1):
    #         print(f"  {i}. {url}")
    #     return
    
    # Lancer les tests
    asyncio.run(test_feature_extractor(
        urls=urls,
        limit=limit,
        output_dir=output
    ))


if __name__ == "__main__":
    main(3, None)