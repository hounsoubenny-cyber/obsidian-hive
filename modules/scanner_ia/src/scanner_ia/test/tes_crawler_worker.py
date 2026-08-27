#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 09:18:40 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test complet du crawler avec 10 workers simultanés sur Wikipedia
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import asyncio
import aiohttp
import time
import random
from loguru import logger
from collections import Counter

# Importer ton crawler
from core.crawler import Crawler, Config
from core.parser import Parser

logger.remove()
logger.add(sys.stdout, format="<level>{message}</level>", level="INFO")

class CrawlerTester:
    """Testeur complet du crawler avec workers"""
    
    def __init__(self):
        self.results = []
        self.stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'domains': Counter()
        }
        
    def _print_header(self, title):
        print("\n" + "="*70)
        print(f"🔬 {title}")
        print("="*70)
    
    def _print_result(self, test_name, success, message=""):
        status = "✅" if success else "❌"
        print(f"  {status} {test_name}: {message}" if message else f"  {status} {test_name}")
        return success
    
    async def worker_robot_checker(self, crawler, url, worker_id, stop_event, stats):
        """
        Worker qui vérifie constamment les robots.txt
        """
        local_count = 0
        cache_hits_local = 0
        
        while not stop_event.is_set():
            try:
                start = time.time()
                allowed = await crawler.parser.robot_allow(url)
                elapsed = time.time() - start
                
                local_count += 1
                
                # Vérifier si c'était un cache hit (très rapide)
                if elapsed < 0.05:
                    cache_hits_local += 1
                
                stats['total_requests'] += 1
                stats['domains'][crawler.parser.get_domain(url)] += 1
                
                if local_count % 5 == 0:
                    print(f"  [{worker_id}] {local_count} requêtes → {allowed} ({elapsed:.3f}s)")
                
                # Pause aléatoire pour simuler une vraie charge
                await asyncio.sleep(random.uniform(0.1, 0.5))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                stats['errors'] += 1
                print(f"  [{worker_id}] Erreur: {e}")
        
        stats[f'worker_{worker_id}_total'] = local_count
        stats[f'worker_{worker_id}_cache_hits'] = cache_hits_local
        
        return local_count, cache_hits_local
    
    async def test_10_workers_wikipedia(self):
        """
        Test avec 10 workers qui vérifient constamment robots.txt de Wikipedia
        """
        self._print_header("TEST: 10 WORKERS SUR WIKIPEDIA")
        
        
        # URLs Wikipedia à tester
        wikipedia_urls = [
            "https://en.wikipedia.org/wiki/Main_Page",
            "https://en.wikipedia.org/wiki/Python_(programming_language)",
            "https://en.wikipedia.org/wiki/Artificial_intelligence",
            "https://en.wikipedia.org/wiki/Machine_learning",
            "https://en.wikipedia.org/wiki/Deep_learning",
            "https://en.wikipedia.org/wiki/Computer_science",
            "https://en.wikipedia.org/wiki/Algorithm",
            "https://en.wikipedia.org/wiki/Data_structure",
            "https://en.wikipedia.org/wiki/Web_scraping",
            "https://en.wikipedia.org/wiki/Asynchronous_I/O",
        ]
        
        print(f"\n📊 {len(wikipedia_urls)} URLs Wikipedia différentes")
        print(f"📊 {len(wikipedia_urls)} workers simultanés")
        print()
        
        # Créer session et crawler
        connector = aiohttp.TCPConnector(limit=20)
        session = aiohttp.ClientSession(connector=connector)
        crawler = Crawler(session)
        
        # Vider le cache avant le test
        crawler.parser._robot_domain_cache = {}
        crawler.parser._robot_url_cache = {}
        crawler.config.DEBUG = False
        crawler.config.GET_TIMEOUT = 1
        
        # Stop event pour arrêter les workers
        stop_event = asyncio.Event()
        stats = self.stats.copy()
        stats['total_requests'] = 0
        stats['cache_hits'] = 0
        stats['cache_misses'] = 0
        stats['errors'] = 0
        stats['domains'] = Counter()
        
        # Lancer les workers
        start_time = time.time()
        
        tasks = []
        for i, url in enumerate(wikipedia_urls):
            task = asyncio.create_task(
                self.worker_robot_checker(crawler, url, f"Worker-{i:02d}", stop_event, stats)
            )
            tasks.append(task)
        
        print(f"🚀 {len(tasks)} workers lancés sur {len(wikipedia_urls)} URLs différentes")
        print("⏳ Test en cours pendant 15 secondes...")
        print()
        
        # Laisser tourner pendant 15 secondes
        await asyncio.sleep(15)
        
        # Arrêter tous les workers
        print("\n🛑 Arrêt des workers...")
        stop_event.set()
        
        # Attendre que tous les workers terminent
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        elapsed = time.time() - start_time
        
        # Nettoyer
        await crawler.close()
        await session.close()
        
        # Analyser les résultats
        print("\n" + "="*70)
        print("📊 STATISTIQUES DU TEST")
        print("="*70)
        
        total_requests = stats['total_requests']
        total_errors = stats['errors']
        
        # Compter les cache hits par worker
        cache_hits_total = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"  Worker-{i:02d}: Exception - {result}")
            else:
                local_count, local_hits = result
                cache_hits_total += local_hits
                print(f"  Worker-{i:02d}: {local_count} requêtes, {local_hits} cache hits")
        
        print(f"\n📈 RÉCAPITULATIF:")
        print(f"  ├─ Temps total: {elapsed:.2f}s")
        print(f"  ├─ Requêtes totales: {total_requests}")
        print(f"  ├─ Cache hits: {cache_hits_total} ({cache_hits_total/total_requests*100:.1f}%)")
        print(f"  ├─ Erreurs: {total_errors}")
        print(f"  └─ Requêtes par seconde: {total_requests/elapsed:.1f}")
        
        print(f"\n🌐 DOMAINES VISITÉS:")
        for domain, count in stats['domains'].most_common(5):
            print(f"  ├─ {domain}: {count} requêtes")
        
        # Vérifier que les cache hits sont significatifs
        # Après le premier worker, les autres devraient utiliser le cache
        success = cache_hits_total > (total_requests * 0.7)  # Au moins 70% de cache hits
        
        self._print_result("Performance cache", success, 
                          f"{cache_hits_total/total_requests*100:.1f}% cache hits")
        
        # Vérifier que le lock a fonctionné (temps total < somme des temps)
        # On estime chaque requête à ~0.1s
        estimated_without_lock = total_requests * 0.1
        print(f"\n📊 COMPARAISON LOCK:")
        print(f"  ├─ Temps réel: {elapsed:.2f}s")
        print(f"  ├─ Temps estimé sans lock: {estimated_without_lock:.2f}s")
        print(f"  └─ Gain: {estimated_without_lock/elapsed:.1f}x")
        
        lock_success = elapsed < estimated_without_lock * 0.3  # Au moins 70% plus rapide
        self._print_result("Lock efficace", lock_success, 
                          f"{estimated_without_lock/elapsed:.1f}x plus rapide")
        
        return success and lock_success
    
    async def test_10_workers_same_domain(self):
        """
        Test avec 10 workers sur le MÊME domaine Wikipedia
        """
        self._print_header("TEST: 10 WORKERS MÊME DOMAINE")
        
        
        # Même domaine
        domain = "https://en.wikipedia.org"
        urls = [f"{domain}/wiki/Page_{i}" for i in range(10)]
        
        print(f"\n📊 {len(urls)} workers sur le MÊME domaine: {domain}")
        print()
        
        # Créer session et crawler
        connector = aiohttp.TCPConnector(limit=20)
        session = aiohttp.ClientSession(connector=connector)
        crawler = Crawler(session)
        crawler.config.DEBUG = False
        # Vider le cache
        crawler.parser._robot_domain_cache = {}
        crawler.parser._robot_url_cache = {}
        
        stop_event = asyncio.Event()
        stats = self.stats.copy()
        stats['total_requests'] = 0
        stats['cache_hits'] = 0
        
        # Lancer les workers
        start_time = time.time()
        
        tasks = []
        for i, url in enumerate(urls):
            task = asyncio.create_task(
                self.worker_robot_checker(crawler, url, f"Worker-{i:02d}", stop_event, stats)
            )
            tasks.append(task)
        
        print(f"🚀 {len(tasks)} workers lancés sur le MÊME domaine")
        print("⏳ Test en cours pendant 10 secondes...")
        print()
        
        # Laisser tourner pendant 10 secondes
        await asyncio.sleep(10)
        
        # Arrêter
        stop_event.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        elapsed = time.time() - start_time
        
        # Nettoyer
        await crawler.close()
        await session.close()
        
        # Analyser
        print("\n" + "="*70)
        print("📊 STATISTIQUES MÊME DOMAINE")
        print("="*70)
        
        total_requests = stats['total_requests']
        
        cache_hits_total = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"  Worker-{i:02d}: Exception - {result}")
            else:
                local_count, local_hits = result
                cache_hits_total += local_hits
                print(f"  Worker-{i:02d}: {local_count} req, {local_hits} cache hits")
        
        print(f"\n📈 RÉSULTATS:")
        print(f"  ├─ Temps: {elapsed:.2f}s")
        print(f"  ├─ Requêtes: {total_requests}")
        print(f"  ├─ Cache hits: {cache_hits_total} ({cache_hits_total/total_requests*100:.1f}%)")
        
        # Avec lock, le cache hit rate devrait être très élevé (>80%)
        success = cache_hits_total / total_requests > 0.8
        
        self._print_result("Cache hit rate", success, 
                          f"{cache_hits_total/total_requests*100:.1f}%")
        
        return success
    
    async def test_mixed_workers(self):
        """
        Test avec workers mélangeant différents domaines
        """
        self._print_header("TEST: WORKERS MULTI-DOMAINES")
        
        
        # Différents domaines
        urls = [
            "https://en.wikipedia.org/wiki/Python",
            "https://www.google.com/search",
            "https://github.com/",
            "https://stackoverflow.com/questions",
            "https://www.python.org/doc/",
        ]
        
        n_workers = 15  # 15 workers sur 5 domaines différents
        
        print(f"\n📊 {n_workers} workers sur {len(urls)} domaines différents")
        print(f"  Domaines: {[self._get_domain(u) for u in urls]}")
        print()
        
        # Créer session et crawler
        connector = aiohttp.TCPConnector(limit=30)
        session = aiohttp.ClientSession(connector=connector)
        crawler = Crawler(session)
        crawler.config.DEBUG = False
        # Vider le cache
        crawler.parser._robot_domain_cache = {}
        crawler.parser._robot_url_cache = {}
        
        stop_event = asyncio.Event()
        stats = self.stats.copy()
        stats['total_requests'] = 0
        stats['domains'] = Counter()
        
        # Assigner les URLs aux workers (round-robin)
        tasks = []
        for i in range(n_workers):
            url = urls[i % len(urls)]
            task = asyncio.create_task(
                self.worker_robot_checker(crawler, url, f"Worker-{i:02d}", stop_event, stats)
            )
            tasks.append(task)
        
        print(f"🚀 {n_workers} workers lancés")
        print("⏳ Test en cours pendant 12 secondes...")
        print()
        
        await asyncio.sleep(12)
        
        stop_event.set()
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        elapsed = time.time() - start_time
        
        await crawler.close()
        await session.close()
        
        # Analyser
        print("\n" + "="*70)
        print("📊 STATISTIQUES MULTI-DOMAINES")
        print("="*70)
        
        total_requests = stats['total_requests']
        
        print(f"\n📈 RÉSULTATS:")
        print(f"  ├─ Temps: {elapsed:.2f}s")
        print(f"  ├─ Requêtes totales: {total_requests}")
        print(f"  └─ Requêtes/s: {total_requests/elapsed:.1f}")
        
        print(f"\n🌐 RÉPARTITION PAR DOMAINE:")
        for domain, count in stats['domains'].most_common():
            print(f"  ├─ {domain}: {count} requêtes")
        
        # Vérifier qu'on a des requêtes pour chaque domaine
        unique_domains = len(stats['domains'])
        success = unique_domains >= len(urls)  # Au moins les 5 domaines
        
        self._print_result("Multi-domaines explorés", success, 
                          f"{unique_domains} domaines uniques")
        
        return success
    
    def _get_domain(self, url):
        from urllib.parse import urlparse
        return urlparse(url).netloc
    
    async def run_all_tests(self):
        """Lance tous les tests"""
        print("\n" + "🔥"*70)
        print("🔥 TEST COMPLET DU CRAWLER AVEC 10 WORKERS")
        print("🔥"*70)
        
        tests = [
            ("10 workers sur URLs différentes", self.test_10_workers_wikipedia),
            ("10 workers sur même domaine", self.test_10_workers_same_domain),
            ("15 workers multi-domaines", self.test_mixed_workers),
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in tests:
            try:
                print(f"\n{'─'*70}")
                print(f"📌 {name}")
                print(f"{'─'*70}")
                success = await test_func()
                if success:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"  ❌ Exception: {e}")
                import traceback
                traceback.print_exc()
                failed += 1
        
        # Résumé
        print("\n" + "="*70)
        print("📊 RÉSUMÉ FINAL")
        print("="*70)
        print(f"✅ Passés: {passed}/{len(tests)}")
        print(f"❌ Échoués: {failed}/{len(tests)}")
        
        if failed == 0:
            print("\n🎉 TOUS LES TESTS ONT RÉUSSI !")
            print("✅ Cache robots.txt fonctionne parfaitement")
            print("✅ Lock par domaine empêche les requêtes en double")
            print("✅ Workers parallèles bien gérés")
        else:
            print(f"\n⚠️ {failed} TEST(S) ÉCHOUÉ(S)")
        
        return failed == 0


async def quick_worker_test():
    """Test rapide avec 3 workers pour vérifier le fonctionnement"""
    print("\n🚀 TEST RAPIDE - 3 WORKERS")
    print("-"*50)
    
    connector = aiohttp.TCPConnector(limit=10)
    session = aiohttp.ClientSession(connector=connector)
    crawler = Crawler(session)
    crawler.config.DEBUG = False
    # Vider cache
    crawler.parser._robot_domain_cache = {}
    crawler.parser._robot_url_cache = {}
    
    urls = [
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://en.wikipedia.org/wiki/Python",
        "https://www.google.com/",
    ]
    
    stop_event = asyncio.Event()
    stats = {'total_requests': 0}
    
    async def quick_worker(url, wid):
        count = 0
        while not stop_event.is_set() and count < 5:
            allowed = await crawler.parser.robot_allow(url)
            count += 1
            stats['total_requests'] += 1
            print(f"  [{wid}] {url[:50]}... → {allowed}")
            await asyncio.sleep(0.5)
        return count
    
    tasks = [asyncio.create_task(quick_worker(url, f"W{i}")) for i, url in enumerate(urls)]
    
    await asyncio.sleep(6)
    stop_event.set()
    
    results = await asyncio.gather(*tasks)
    
    print(f"\n📊 Total requêtes: {stats['total_requests']}")
    
    await crawler.close()
    await session.close()
    
    print("\n✅ Test rapide terminé")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test du crawler avec workers")
    parser.add_argument("--quick", action="store_true", help="Test rapide uniquement")
    
    args = parser.parse_args()
    
    if args.quick:
        asyncio.run(quick_worker_test())
    else:
        tester = CrawlerTester()
        success = asyncio.run(tester.run_all_tests())
        sys.exit(0 if success else 1)