#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 09:13:49 2026

@author: hounsousamuel
"""

"""
Test complet du crawler avec gestion robots.txt
"""


import sys
import asyncio
import aiohttp
import time
from loguru import logger

# Importer ton crawler
from scanner_ia.core.crawler import Crawler
from scanner_ia.core.parser import Parser

logger.remove()
logger.add(sys.stdout, format="<level>{message}</level>", level="INFO")

class CrawlerTester:
    """Testeur complet du crawler"""
    
    def __init__(self):
        self.results = []
        
    def _print_header(self, title):
        print("\n" + "="*70)
        print(f"🔬 {title}")
        print("="*70)
    
    def _print_result(self, test_name, success, message=""):
        status = "✅" if success else "❌"
        print(f"  {status} {test_name}: {message}" if message else f"  {status} {test_name}")
        return success
    
    async def test_robot_allow_cache(self, crawler):
        """Test 1: Vérifier que le cache robots.txt fonctionne"""
        self._print_header("TEST 1: CACHE ROBOTS.TXT")
        
        urls = [
            "https://www.google.com/robots.txt",
            "https://www.google.com/search",
            "https://www.google.com/images",
        ]
        
        print(f"\n📊 Test avec {len(urls)} URLs du même domaine")
        
        start = time.time()
        results = []
        
        for url in urls:
            allowed = await crawler.parser.robot_allow(url)
            results.append(allowed)
            print(f"  {url[:50]}... → {allowed}")
        
        elapsed = time.time() - start
        print(f"\n⏱️  Temps total: {elapsed:.2f}s")
        
        # Vérifier que le cache a été utilisé
        cache = crawler.parser._robot_global_lock
        success = elapsed < 2.0  # Moins de 2s = cache OK
        self._print_result("Cache robots.txt", success, f"{elapsed:.2f}s")
        
        return success
    
    async def test_robot_allow_multiple_domains(self, crawler):
        """Test 2: Robots.txt pour plusieurs domaines différents"""
        self._print_header("TEST 2: MULTIPLES DOMAINES")
        
        urls = [
            "https://www.google.com/search",
            "https://www.github.com/",
            "https://www.python.org/",
            "https://stackoverflow.com/",
        ]
        
        print(f"\n📊 Test avec {len(urls)} domaines différents")
        
        start = time.time()
        
        for url in urls:
            allowed = await crawler.parser.robot_allow(url)
            print(f"  {url[:40]}... → {allowed}")
        
        elapsed = time.time() - start
        print(f"\n⏱️  Temps total: {elapsed:.2f}s")
        
        # Chaque domaine = une requête, donc > 1s normal
        success = elapsed > 1.0  # Au moins 1s pour 4 requêtes
        self._print_result("Multi-domaines", success, f"{elapsed:.2f}s")
        
        return success
    
    async def test_concurrent_robot_requests(self, crawler):
        """Test 3: Requêtes concurrentes vers le même domaine"""
        self._print_header("TEST 3: CONCURRENCE MÊME DOMAINE")
        
        domain = "https://www.google.com"
        n_workers = 10
        
        print(f"\n📊 {n_workers} workers simultanés pour {domain}")
        
        async def worker(url, worker_id):
            start = time.time()
            allowed = await crawler.parser.robot_allow(url)
            elapsed = time.time() - start
            return worker_id, allowed, elapsed
        
        urls = [f"{domain}/page{i}" for i in range(n_workers)]
        
        start = time.time()
        tasks = [asyncio.create_task(worker(url, i)) for i, url in enumerate(urls)]
        results = await asyncio.gather(*tasks)
        total_elapsed = time.time() - start
        
        print(f"\n  Résultats:")
        for worker_id, allowed, elapsed in results:
            print(f"    Worker {worker_id}: {elapsed:.2f}s → {allowed}")
        
        print(f"\n  Temps total: {total_elapsed:.2f}s")
        
        # Vérifier qu'un seul worker a fait la requête (les autres ont pris le cache)
        # Les temps devraient être très variables (un lent, les autres rapides)
        times = [e for _, _, e in results]
        max_time = max(times)
        min_time = min(times)
        
        success = max_time > 0.5 and min_time < 0.1  # Un lent, les autres rapides
        self._print_result("Concurrence même domaine", success, 
                          f"max={max_time:.2f}s, min={min_time:.2f}s")
        
        return success
    
    async def test_localhost_crawling(self, crawler):
        """Test 4: Crawl de localhost (pas de robots.txt)"""
        self._print_header("TEST 4: CRAWL LOCALHOST")
        
        url = "http://localhost:8080"
        
        print(f"\n📊 Crawl de {url}")
        
        try:
            start = time.time()
            result = await crawler.crawl(url, restore=False)
            elapsed = time.time() - start
            
            print(f"  ✅ Pages trouvées: {len(result.result)}")
            print(f"  ✅ Erreurs: {result.error or 'Aucune'}")
            print(f"  ⏱️  Temps: {elapsed:.2f}s")
            
            # Afficher les premières URLs trouvées
            if result.result:
                print(f"\n  📄 Premières URLs:")
                for r in result.result[:5]:
                    print(f"    - {r.url[:80]} (depth: {r.deep})")
            
            success = len(result.result) > 0
            self._print_result("Crawl localhost", success)
            return success
            
        except Exception as e:
            self._print_result("Crawl localhost", False, str(e))
            return False
    
    async def test_cancel_signal(self, crawler):
        """Test 5: Annulation avec Ctrl+C (simulé)"""
        self._print_header("TEST 5: ANNULATION")
        
        url = "https://httpbin.org"
        
        print(f"\n📊 Lancement du crawl sur {url} (sera annulé après 2s)")
        
        # Créer une tâche de crawl
        task = asyncio.create_task(crawler.crawl(url, restore=False))
        
        # Attendre 2 secondes puis annuler
        await asyncio.sleep(2)
        task.cancel()
        
        try:
            result = await task
            print(f"  ✅ Crawl terminé normalement")
            success = True
        except asyncio.CancelledError:
            print(f"  ✅ Crawl annulé comme attendu")
            success = True
        except Exception as e:
            print(f"  ❌ Erreur: {e}")
            success = False
        
        self._print_result("Annulation Ctrl+C", success)
        return success
    
    async def test_robots_txt_real(self, crawler):
        """Test 6: Vérifier robots.txt sur des sites réels"""
        self._print_header("TEST 6: ROBOTS.TXT SUR SITES RÉELS")
        
        test_cases = [
            ("https://www.google.com/", "Google"),
            ("https://github.com/", "GitHub"),
            ("https://www.python.org/", "Python.org"),
            ("https://stackoverflow.com/", "StackOverflow"),
        ]
        
        print(f"\n📊 Test de {len(test_cases)} sites")
        
        results = []
        for url, name in test_cases:
            start = time.time()
            allowed = await crawler.parser.robot_allow(url)
            elapsed = time.time() - start
            
            print(f"  {name:15} → {allowed} ({elapsed:.2f}s)")
            results.append((name, allowed, elapsed))
        
        # Vérifier que tous les sites ont répondu
        success = all(r[1] is not None for r in results)
        self._print_result("Robots.txt sites réels", success)
        
        return success
    
    async def run_all_tests(self):
        """Lance tous les tests"""
        print("\n" + "🔥"*70)
        print("🔥 TEST COMPLET DU CRAWLER")
        print("🔥"*70)
        
        
        # Créer session et crawler
        connector = aiohttp.TCPConnector(limit=10)
        session = aiohttp.ClientSession(connector=connector)
        crawler = Crawler(session)
        # Configurer pour les tests
        crawler.config.DEBUG = False
        crawler.config.MAX_PAGES = 5
        crawler.config.MAX_DEEPTH = 1
        crawler.config.GET_TIMEOUT = 1
        crawler.config.JOIN_TIMEOUT = 10
        
        tests = [
            ("Cache robots.txt", self.test_robot_allow_cache),
            ("Multi-domaines", self.test_robot_allow_multiple_domains),
            ("Concurrence même domaine", self.test_concurrent_robot_requests),
            ("Crawl localhost", self.test_localhost_crawling),
            ("Annulation Ctrl+C", self.test_cancel_signal),
            ("Robots.txt sites réels", self.test_robots_txt_real),
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in tests:
            try:
                success = await test_func(crawler)
                if success:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"  ❌ Exception: {e}")
                failed += 1
        
        # Nettoyage
        await crawler.close()
        await session.close()
        
        # Résumé
        print("\n" + "="*70)
        print("📊 RÉSUMÉ DES TESTS")
        print("="*70)
        print(f"✅ Passés: {passed}/{len(tests)}")
        print(f"❌ Échoués: {failed}/{len(tests)}")
        
        if failed == 0:
            print("\n🎉 TOUS LES TESTS ONT RÉUSSI !")
        else:
            print(f"\n⚠️ {failed} TEST(S) ÉCHOUÉ(S)")
        
        return failed == 0


async def quick_test():
    """Test rapide pour valider le fonctionnement de base"""
    print("\n🚀 TEST RAPIDE")
    print("-"*40)
    
    
    connector = aiohttp.TCPConnector(limit=5)
    session = aiohttp.ClientSession(connector=connector)
    crawler = Crawler(session)
    
    # Config minimaliste
    crawler.config.DEBUG = False
    crawler.config.MAX_PAGES = 3
    crawler.config.MAX_DEEPTH = 1
    
    # Tester une URL simple
    url = "http://localhost:8080"
    print(f"\n📌 Crawl de {url}")
    
    try:
        result = await crawler.crawl(url, restore=False)
        print(f"  ✅ Pages trouvées: {len(result.result)}")
        print(f"  ✅ Erreurs: {result.error or 'Aucune'}")
        
        # Tester robot_allow sur Google
        print(f"\n📌 Test robots.txt sur google.com")
        allowed = await crawler.parser.robot_allow("https://www.google.com/search")
        print(f"  ✅ Résultat: {allowed}")
        
    except Exception as e:
        print(f"  ❌ Erreur: {e}")
    
    await crawler.close()
    await session.close()
    
    print("\n✅ Test rapide terminé")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test du crawler")
    parser.add_argument("--quick", action="store_true", help="Test rapide uniquement")
    parser.add_argument("--url", type=str, help="URL spécifique à tester")
    
    args = parser.parse_args()
    
    if args.url:
        # Tester une URL spécifique
        async def test_single():
            connector = aiohttp.TCPConnector()
            session = aiohttp.ClientSession(connector=connector)
            crawler = Crawler(session)
            crawler.config.MAX_PAGES = 10
            
            print(f"\n🔍 Crawl de {args.url}")
            result = await crawler.crawl(args.url)
            print(f"  Pages: {len(result.result)}")
            print(f"  Erreur: {result.error}")
            
            await crawler.close()
            await session.close()
        
        asyncio.run(test_single())
    elif args.quick:
        asyncio.run(quick_test())
    else:
        # Lancer tous les tests
        tester = CrawlerTester()
        success = asyncio.run(tester.run_all_tests())
        sys.exit(0 if success else 1)