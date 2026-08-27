#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BENCHMARK ULTIMATE - Version FINALE
Crawler personnalisé vs Scrapy (Scrapy dans processus séparé)
Auteur: Expert
Date: 2026-03-10
"""

import os
import sys
import time
import asyncio
import json
import psutil
import tracemalloc
import multiprocessing as mp
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import warnings
warnings.filterwarnings('ignore')

# Import du crawler personnalisé
from scanner_ia.core.crawler import Crawler, Config as CustomConfig

# Imports Scrapy
try:
    import scrapy
    from scrapy.crawler import CrawlerProcess, CrawlerRunner
    from scrapy.utils.project import get_project_settings
    SCRAPY_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Scrapy non disponible: {e}")
    SCRAPY_AVAILABLE = False

# Configuration des logs
from loguru import logger
logger.remove()
logger.add(sys.stdout, 
           format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>", 
           level="INFO",
           colorize=True)
logger.add("benchmark_detailed.log", rotation="50 MB", level="DEBUG", encoding="utf-8")

# ==================== CONFIGURATION ====================

@dataclass
class BenchmarkConfig:
    """Configuration complète du benchmark"""
    urls: List[str]
    max_pages: int = 50
    max_depth: int = 3
    iterations: int = 3
    timeout_per_crawl: int = 60
    concurrent_requests: int = 16
    respect_robots: bool = False
    delay_between_requests: float = 0.0
    user_agent: str = "Mozilla/5.0 (Benchmark Bot)"
    
@dataclass
class BenchmarkResult:
    """Stockage des résultats de benchmark"""
    crawler_name: str
    url: str
    iteration: int
    success: bool
    pages_crawled: int
    duration: float
    memory_peak_mb: float
    memory_final_mb: float
    cpu_percent: float
    errors: List[str] = field(default_factory=list)
    links_found: int = 0
    avg_speed_pps: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return asdict(self)

# ==================== SPIDER SCRAY POUR PROCESSUS SÉPARÉ ====================

class BenchmarkSpider(scrapy.Spider):
    """Spider Scrapy pour benchmark (utilisé dans processus séparé)"""
    name = 'benchmark_spider'
    
    def __init__(self, start_urls=None, max_pages=50, max_depth=3, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = start_urls or []
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.pages_crawled = 0
        self.errors = []
        self.links_found = 0
        self.start_time = None
        
    def parse(self, response):
        if self.start_time is None:
            self.start_time = time.time()
            
        # Vérifier la limite de pages
        self.pages_crawled += 1
        if self.pages_crawled >= self.max_pages:
            return
            
        # Extraire les liens
        links = response.css('a::attr(href)').getall()
        self.links_found += len(links)
        
        # Suivre les liens (limité pour éviter explosion)
        followed = 0
        for link in links[:10]:
            if followed >= 5:
                break
            try:
                yield response.follow(
                    link, 
                    callback=self.parse, 
                    errback=self.errback
                )
                followed += 1
            except Exception as e:
                self.errors.append(f"Follow error: {str(e)[:50]}")
    
    def errback(self, failure):
        self.errors.append(str(failure.value)[:100])

# ==================== WRAPPER SCRAY DANS PROCESSUS SÉPARÉ ====================

class ScrapyProcessRunner:
    """Exécute Scrapy dans un processus séparé pour éviter les problèmes de threads"""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.result_queue = mp.Queue()
        
    def _run_spider_process(self, url: str, queue: mp.Queue):
        """Cette fonction s'exécute dans un processus séparé"""
        try:
            # Configuration Scrapy
            settings = {
               'CONCURRENT_REQUESTS': self.config.concurrent_requests,
               'CONCURRENT_REQUESTS_PER_DOMAIN': self.config.concurrent_requests,
               'DOWNLOAD_DELAY': self.config.delay_between_requests,
               'LOG_LEVEL': 'ERROR',
               'LOG_ENABLED': False,
               'ROBOTSTXT_OBEY': self.config.respect_robots,
               'USER_AGENT': self.config.user_agent,
               'DEPTH_LIMIT': self.config.max_depth,
               'CLOSESPIDER_PAGECOUNT': self.config.max_pages,
               'DNSCACHE_ENABLED': True,
               'DOWNLOAD_TIMEOUT': 15,
               'RETRY_ENABLED': True,
               'RETRY_TIMES': 3,
               'RETRY_HTTP_CODES': [500, 502, 503, 504, 408, 429, 403, 404],
               # AJOUTE CES LIGNES :
               'HTTPERROR_ALLOW_ALL': True,  # Accepte toutes les réponses HTTP
               'HTTPERROR_ALLOWED_CODES': [200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
                                           300, 301, 302, 303, 304, 305, 306, 307, 308,
                                           400, 401, 402, 403, 404, 405, 406, 407, 408, 409],
               'TELNETCONSOLE_ENABLED': False,
           }
            # Ajustements pour localhost
            if 'localhost' in url or '127.0.0.1' in url:
                settings.update({
                    'DNS_TIMEOUT': 5,
                    'URLLENGTH_LIMIT': 2083,
                })
            
            # Conteneur pour les résultats
            results = {
                'success': False,
                'pages': 0,
                'links_found': 0,
                'errors': [],
                'error_msg': None
            }
            
            # Créer un spider personnalisé avec collecte des résultats
            class LocalBenchmarkSpider(BenchmarkSpider):
                def closed(self, reason):
                    results['pages'] = self.pages_crawled
                    results['links_found'] = self.links_found
                    results['errors'] = self.errors[:10]
                    results['success'] = len(self.errors) == 0
                    queue.put(results)
            
            # Lancer le crawl
            process = CrawlerProcess(settings)
            process.crawl(
                LocalBenchmarkSpider,
                start_urls=[url],
                max_pages=self.config.max_pages,
                max_depth=self.config.max_depth
            )
            process.start()  # Bloquant
            
        except Exception as e:
            queue.put({
                'success': False,
                'pages': 0,
                'links_found': 0,
                'errors': [str(e)[:200]],
                'error_msg': str(e)[:200]
            })
    
    def crawl(self, url: str, iteration: int) -> Dict[str, Any]:
        """Lance Scrapy dans un processus séparé et attend le résultat"""
        if not SCRAPY_AVAILABLE:
            return {
                'success': False,
                'pages': 0,
                'error': 'Scrapy non installé',
                'links_found': 0,
                'errors': ['Scrapy non installé']
            }
        
        # Vider la queue
        while not self.result_queue.empty():
            try:
                self.result_queue.get_nowait()
            except Exception:
                pass
        
        # Créer et démarrer le processus
        process = mp.Process(
            target=self._run_spider_process,
            args=(url, self.result_queue)
        )
        process.start()
        
        # Attendre avec timeout
        process.join(timeout=self.config.timeout_per_crawl)
        
        # Si le processus tourne encore, le tuer
        if process.is_alive():
            process.terminate()
            process.join()
            return {
                'success': False,
                'pages': 0,
                'error': f'Timeout après {self.config.timeout_per_crawl}s',
                'links_found': 0,
                'errors': [f'Timeout après {self.config.timeout_per_crawl}s']
            }
        
        # Récupérer les résultats
        try:
            results = self.result_queue.get_nowait()
            return {
                'success': results.get('success', False),
                'pages': results.get('pages', 0),
                'error': results.get('error_msg'),
                'links_found': results.get('links_found', 0),
                'errors': results.get('errors', [])
            }
        except Exception as e:
            return {
                'success': False,
                'pages': 0,
                'error': f'Erreur récupération résultats: {str(e)[:100]}',
                'links_found': 0,
                'errors': [f'Erreur récupération: {str(e)[:100]}']
            }

# ==================== WRAPPER CRAWLER PERSONNALISÉ ====================

class RobustCustomCrawler:
    """Wrapper pour le crawler personnalisé"""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self._configure_crawler()
        
    def _configure_crawler(self):
        """Configure le crawler personnalisé"""
        conf = CustomConfig
        conf.MAX_PAGES = self.config.max_pages
        conf.MAX_DEEPTH = self.config.max_depth
        conf.Semaphore = self.config.concurrent_requests
        conf.MAX_WORKERS = max(2, self.config.concurrent_requests // 4)
        conf.DEBUG = False
        conf.GET_TIMEOUT = 0.1
        conf.JOIN_TIMEOUT = self.config.timeout_per_crawl
        conf.RETRIES = 2
        conf.DELAY = self.config.delay_between_requests
        return conf
        
    async def crawl(self, url: str, iteration: int) -> Dict[str, Any]:
        """Exécute un crawl avec le crawler personnalisé"""
        import aiohttp
        from aiohttp import ClientTimeout, TCPConnector
        
        connector = TCPConnector(
            limit=self.config.concurrent_requests,
            limit_per_host=self.config.concurrent_requests,
            ttl_dns_cache=300,
            force_close=True
        )
        
        timeout = ClientTimeout(total=self.config.timeout_per_crawl)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent}
        )
        
        crawler = Crawler(session)
        crawler.config = self._configure_crawler()
        
        try:
            result = await crawler.crawl(url, restore=True)
            
            # Compter les liens
            links_found = 0
            for worker_result in result.result:
                links_found += len(worker_result.html_links)
                links_found += len(worker_result.other_links)
            
            return {
                'success': result.error is None,
                'pages': len(result.result),
                'error': result.error,
                'links_found': links_found,
                'stats': result.stats if hasattr(result, 'stats') else {}
            }
            
        except asyncio.TimeoutError:
            return {
                'success': False,
                'pages': 0,
                'error': 'Timeout',
                'links_found': 0
            }
        except Exception as e:
            return {
                'success': False,
                'pages': 0,
                'error': str(e)[:200],
                'links_found': 0
            }
        finally:
            try:
                await crawler.close()
                await session.close()
            except Exception:
                pass

# ==================== MONITEUR DE PERFORMANCE ====================

class PerformanceMonitor:
    """Moniteur de performance"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.memory_samples = []
        self.cpu_samples = []
        self.start_time = None
        
    def start(self):
        """Démarrer la surveillance"""
        self.start_time = time.time()
        self.memory_samples = []
        self.cpu_samples = []
        tracemalloc.start()
        
    def sample(self):
        """Prendre un échantillon"""
        try:
            self.memory_samples.append(self.process.memory_info().rss / 1024 / 1024)
            self.cpu_samples.append(self.process.cpu_percent())
        except Exception:
            pass
        
    def stop(self) -> Dict[str, float]:
        """Arrêter et retourner les statistiques"""
        memory_peak = max(self.memory_samples) if self.memory_samples else 0
        memory_final = self.memory_samples[-1] if self.memory_samples else 0
        cpu_avg = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0
        
        try:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        except Exception:
            peak = 0
        
        return {
            'memory_peak_mb': memory_peak,
            'memory_final_mb': memory_final,
            'cpu_percent': cpu_avg,
            'tracemalloc_peak_mb': peak / 1024 / 1024
        }

# ==================== EXÉCUTEUR DE BENCHMARK ====================

class BenchmarkExecutor:
    """Exécute les benchmarks"""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.results: List[BenchmarkResult] = []
        self.custom_crawler = RobustCustomCrawler(config)
        self.scrapy_runner = ScrapyProcessRunner(config) if SCRAPY_AVAILABLE else None
        
    async def run_single_benchmark(self, url: str, iteration: int, crawler_type: str) -> BenchmarkResult:
        """Exécute un benchmark pour un crawler spécifique"""
        
        monitor = PerformanceMonitor()
        monitor.start()
        
        # Boucle d'échantillonnage
        async def sample_loop():
            while True:
                monitor.sample()
                await asyncio.sleep(0.1)
        
        sampler = asyncio.create_task(sample_loop())
        start_time = time.time()
        
        try:
            if crawler_type == 'custom':
                result = await self.custom_crawler.crawl(url, iteration)
            else:  # scrapy
                if not self.scrapy_runner:
                    raise Exception("Scrapy non disponible")
                # Exécuter Scrapy dans un processus séparé (bloquant mais dans un thread)
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, 
                    self.scrapy_runner.crawl, 
                    url, iteration
                )
            
            duration = time.time() - start_time
            sampler.cancel()
            stats = monitor.stop()
            
            # Calculer la vitesse
            speed = result['pages'] / duration if duration > 0 and result['pages'] > 0 else 0
            
            return BenchmarkResult(
                crawler_name=crawler_type.capitalize(),
                url=url,
                iteration=iteration,
                success=result['success'],
                pages_crawled=result['pages'],
                duration=duration,
                memory_peak_mb=stats['memory_peak_mb'],
                memory_final_mb=stats['memory_final_mb'],
                cpu_percent=stats['cpu_percent'],
                errors=result.get('errors', []) if not result['success'] else [],
                links_found=result.get('links_found', 0),
                avg_speed_pps=speed
            )
            
        except Exception as e:
            sampler.cancel()
            stats = monitor.stop()
            return BenchmarkResult(
                crawler_name=crawler_type.capitalize(),
                url=url,
                iteration=iteration,
                success=False,
                pages_crawled=0,
                duration=time.time() - start_time,
                memory_peak_mb=stats['memory_peak_mb'],
                memory_final_mb=stats['memory_final_mb'],
                cpu_percent=stats['cpu_percent'],
                errors=[str(e)[:200]],
                links_found=0,
                avg_speed_pps=0
            )
    
    async def run_benchmark(self) -> List[BenchmarkResult]:
        """Exécute tous les benchmarks"""
        
        logger.info("="*80)
        logger.info("🚀 BENCHMARK ULTIMATE - Crawler vs Scrapy")
        logger.info("="*80)
        logger.info(f"URLs: {len(self.config.urls)}")
        logger.info(f"Iterations: {self.config.iterations}")
        logger.info(f"Max pages: {self.config.max_pages}")
        logger.info(f"Max depth: {self.config.max_depth}")
        logger.info(f"Concurrent requests: {self.config.concurrent_requests}")
        logger.info(f"Scrapy disponible: {SCRAPY_AVAILABLE}")
        logger.info("="*80)
        
        all_results = []
        
        for url in self.config.urls:
            logger.info(f"\n📌 Testing: {url}")
            
            for iteration in range(1, self.config.iterations + 1):
                logger.info(f"  Iteration {iteration}/{self.config.iterations}")
                
                # Test Custom Crawler
                logger.info("    ↳ Custom Crawler...")
                custom_result = await self.run_single_benchmark(url, iteration, 'custom')
                all_results.append(custom_result)
                status = "✓" if custom_result.success else "✗"
                logger.info(f"      {status} {custom_result.pages_crawled} pages en {custom_result.duration:.2f}s ({custom_result.avg_speed_pps:.1f} p/s)")
                
                # Test Scrapy
                logger.info("    ↳ Scrapy...")
                scrapy_result = await self.run_single_benchmark(url, iteration, 'scrapy')
                all_results.append(scrapy_result)
                status = "✓" if scrapy_result.success else "✗"
                logger.info(f"      {status} {scrapy_result.pages_crawled} pages en {scrapy_result.duration:.2f}s ({scrapy_result.avg_speed_pps:.1f} p/s)")
                
                # Pause entre les itérations
                if iteration < self.config.iterations:
                    await asyncio.sleep(1)
        
        self.results = all_results
        return all_results

# ==================== ANALYSEUR DE RÉSULTATS ====================

class BenchmarkAnalyzer:
    """Analyse et visualise les résultats"""
    
    def __init__(self, results: List[BenchmarkResult]):
        self.results = results
        
    def print_summary(self):
        """Affiche un résumé détaillé"""
        
        logger.info("\n" + "📊"*40)
        logger.info("📊 RÉSULTATS DU BENCHMARK")
        logger.info("📊"*40)
        
        # Grouper par crawler
        crawlers = {}
        for r in self.results:
            if r.crawler_name not in crawlers:
                crawlers[r.crawler_name] = []
            crawlers[r.crawler_name].append(r)
        
        # Afficher les stats par crawler
        for crawler_name, results in crawlers.items():
            successes = [r for r in results if r.success]
            pages = [r.pages_crawled for r in successes]
            durations = [r.duration for r in successes]
            memories = [r.memory_peak_mb for r in successes]
            speeds = [r.avg_speed_pps for r in successes if r.avg_speed_pps > 0]
            
            logger.info(f"\n📌 {crawler_name.upper()}:")
            logger.info(f"  Tests: {len(results)}")
            logger.info(f"  Succès: {len(successes)}/{len(results)} ({len(successes)/len(results)*100:.1f}%)")
            
            if successes:
                logger.info(f"  Pages moyennes: {sum(pages)/len(pages):.1f}")
                logger.info(f"  Durée moyenne: {sum(durations)/len(durations):.2f}s")
                logger.info(f"  Mémoire pic moyenne: {sum(memories)/len(memories):.1f} MB")
                if speeds:
                    logger.info(f"  Vitesse moyenne: {sum(speeds)/len(speeds):.2f} p/s")
            
            # Afficher les erreurs
            errors = [r for r in results if not r.success]
            if errors:
                logger.info(f"  Erreurs ({len(errors)}):")
                for e in errors[:3]:
                    for err in e.errors[:2]:
                        logger.info(f"    - {err[:100]}")
    
    def export_results(self, filepath: str = "benchmark_results.json"):
        """Exporte les résultats en JSON"""
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'results': [r.to_dict() for r in self.results]
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"💾 Résultats exportés: {filepath}")
        except Exception as e:
            logger.warning(f"⚠️ Erreur export: {e}")

# ==================== FONCTION PRINCIPALE ====================

async def main():
    """Fonction principale"""
    
    # Configuration du benchmark
    config = BenchmarkConfig(
        urls=[
            "http://localhost:8080",  # Ton site local
            # "https://quotes.toscrape.com/",
            # "https://books.toscrape.com/",
        ],
        max_pages=300,
        max_depth=4,
        iterations=5,
        timeout_per_crawl=300,
        concurrent_requests=3,
        respect_robots=False,
        user_agent="Mozilla/5.0 (Benchmark Bot)"
    )
    
    try:
        # Exécution
        executor = BenchmarkExecutor(config)
        results = await executor.run_benchmark()
        
        # Analyse
        analyzer = BenchmarkAnalyzer(results)
        analyzer.print_summary()
        analyzer.export_results()
        
        # Rapport final
        logger.info("\n" + "★"*80)
        logger.info("★ BENCHMARK TERMINÉ AVEC SUCCÈS ★")
        logger.info("★"*80)
        
        return results
        
    except KeyboardInterrupt:
        logger.warning("\n⚠️ Benchmark interrompu")
    except Exception as e:
        logger.error(f"\n❌ Erreur fatale: {e}")
        import traceback
        logger.error(traceback.format_exc())

def run_benchmark():
    """Wrapper pour exécuter le benchmark"""
    try:
        asyncio.run(main())
    except RuntimeError as e:
        if "already running" in str(e):
            logger.info("📌 Exécution dans Jupyter...")
            loop = asyncio.get_event_loop()
            loop.create_task(main())
        else:
            raise

if __name__ == "__main__":
    # Configuration multiprocessing pour éviter les problèmes
    mp.set_start_method('spawn', force=True)
    run_benchmark()