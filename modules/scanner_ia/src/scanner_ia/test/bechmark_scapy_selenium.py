#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark Crawler custom vs Scrapy (version corrigée - mars 2026)
Testé pour éviter les erreurs de chemin et de création de projet
"""

import os
import sys
import json
import shutil
from rich.console import Console
from rich.table import Table
import matplotlib.pyplot as plt
import asyncio
import time
import psutil
import subprocess
import threading
import statistics
import csv
from urllib.parse import urlparse
from collections import defaultdict
from loguru import logger

# Imports de ton crawler (ajuste si besoin selon ta structure exacte)
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
from core.crawler import Crawler, Config
from base_class.crawler_base_class import CrawlerResult, WorkerResult
from core.parser import Parser

logger.remove()
logger.add(sys.stdout, level="INFO")
logger.add("benchmark_logs.log", rotation="10 MB", level="DEBUG")

class CrawlerBenchmark:
    def __init__(self, test_urls=None, num_runs=2, selenium_test=False):
        self.test_scenarios = [
            {
                "name": "Small Static Site",
                "urls": ["https://quotes.toscrape.com/"],
                "max_depth": 2,
                "max_pages": 50,
                "concurrency": 10,
                "description": "Simple static site with few links"
            },
            # Décommente quand tu veux tester d'autres sites
            # {
            #     "name": "Local Test",
            #     "urls": ["http://localhost:8080"],
            #     "max_depth": 3,
            #     "max_pages": 100,
            #     "concurrency": 15,
            #     "description": "Ton serveur local"
            # },
        ]
        self.num_runs = num_runs
        self.selenium_test = selenium_test
        if test_urls:
            self.test_scenarios[0]["urls"] = test_urls

    class ResourceMonitor:
        def __init__(self, pid):
            self.process = psutil.Process(pid)
            self.running = True
            self.metrics = {
                'cpu_percent': [],
                'memory_rss': [],
                'io_read': [],
                'io_write': [],
                'request_times': [],
            }

        def monitor(self):
            while self.running:
                try:
                    self.metrics['cpu_percent'].append(self.process.cpu_percent())
                    self.metrics['memory_rss'].append(self.process.memory_info().rss / (1024 * 1024))
                    io = self.process.io_counters()
                    self.metrics['io_read'].append(io.read_bytes / (1024 * 1024))
                    self.metrics['io_write'].append(io.write_bytes / (1024 * 1024))
                except Exception:
                    pass
                time.sleep(0.1)

        def stop(self):
            self.running = False

        def get_stats(self):
            rt = self.metrics['request_times']
            return {
                'peak_memory_mb': max(self.metrics['memory_rss']) if self.metrics['memory_rss'] else 0,
                'avg_cpu_percent': statistics.mean(self.metrics['cpu_percent']) if self.metrics['cpu_percent'] else 0,
                'total_io_read_mb': max(self.metrics['io_read']) if self.metrics['io_read'] else 0,
                'total_io_write_mb': max(self.metrics['io_write']) if self.metrics['io_write'] else 0,
                'min_request_time': min(rt) if rt else 0,
                'max_request_time': max(rt) if rt else 0,
                'avg_request_time': statistics.mean(rt) if rt else 0,
            }

    async def run_custom_crawler(self, url, max_depth, max_pages, concurrency, restore=False):
        import aiohttp
        session = aiohttp.ClientSession()
        crawler = Crawler(session)
        crawler.config.MAX_DEEPTH = max_depth
        crawler.config.MAX_PAGES = max_pages
        crawler.config.Semaphore = concurrency
        crawler.config.MAX_WORKERS = max(2, concurrency // 5)

        request_times = []

        original_get_all_links = crawler.parser.get_all_links
        async def timed_get_all_links(*args, **kwargs):
            start = time.perf_counter()
            result = await original_get_all_links(*args, **kwargs)
            elapsed = time.perf_counter() - start
            request_times.append(elapsed)
            return result
        crawler.parser.get_all_links = timed_get_all_links

        pid = os.getpid()
        monitor = self.ResourceMonitor(pid)
        monitor_thread = threading.Thread(target=monitor.monitor)
        monitor_thread.start()

        start_time = time.perf_counter()
        result = await crawler.crawl(url, restore=restore)
        elapsed = time.perf_counter() - start_time

        monitor.stop()
        monitor_thread.join()
        resource_stats = monitor.get_stats()
        resource_stats['request_times'] = request_times
        resource_stats['min_request_time'] = min(request_times) if request_times else 0
        resource_stats['max_request_time'] = max(request_times) if request_times else 0
        resource_stats['avg_request_time'] = statistics.mean(request_times) if request_times else 0

        await crawler.close()
        await session.close()

        pages_crawled = len([r for r in result.result if r.status_code == 200 or not r.error])
        total_requests = len(result.result)
        errors = total_requests - pages_crawled
        success_rate = (pages_crawled / total_requests * 100) if total_requests > 0 else 0
        total_links = sum(r.nbr_html_links + r.nbr_other_links for r in result.result)
        speed = total_requests / elapsed if elapsed > 0 else 0

        return {
            'time': elapsed,
            'requests_per_sec': speed,
            'pages': pages_crawled,
            'total_requests': total_requests,
            'errors': errors,
            'success_rate': success_rate,
            'links': total_links,
            'min_req_time': resource_stats['min_request_time'],
            'max_req_time': resource_stats['max_request_time'],
            'avg_req_time': resource_stats['avg_request_time'],
            'peak_memory_mb': resource_stats['peak_memory_mb'],
            'avg_cpu_percent': resource_stats['avg_cpu_percent'],
            'total_io_read_mb': resource_stats['total_io_read_mb'],
            'total_io_write_mb': resource_stats['total_io_write_mb'],
            'error_msg': result.error or None,
        }

    def run_scrapy(self, url, max_depth, max_pages, concurrency):
        PROJECT_NAME = "bench_temp"
        BASE_DIR = f"./{PROJECT_NAME}"
        SPIDERS_DIR = os.path.join(BASE_DIR, "spiders")
        SPIDER_FILE = os.path.join(SPIDERS_DIR, "benchmark_spider.py")

        # Nettoyage complet si existe déjà
        if os.path.exists(BASE_DIR):
            logger.info(f"Nettoyage ancien projet : {BASE_DIR}")
            shutil.rmtree(BASE_DIR, ignore_errors=True)

        logger.info(f"Création projet Scrapy : {BASE_DIR}")
        result = subprocess.run(
            ["scrapy", "startproject", PROJECT_NAME, BASE_DIR],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"Échec création projet Scrapy :\nstdout: {result.stdout}\nstderr: {result.stderr}")
            return {
                'time': 0, 'requests_per_sec': 0, 'pages': 0, 'total_requests': 0,
                'errors': 1, 'success_rate': 0, 'links': 0,
                'min_req_time': 0, 'max_req_time': 0, 'avg_req_time': 0,
                'peak_memory_mb': 0, 'avg_cpu_percent': 0,
                'total_io_read_mb': 0, 'total_io_write_mb': 0,
                'error_msg': f"Scrapy startproject failed (code {result.returncode}): {result.stderr.strip()}"
            }

        os.makedirs(SPIDERS_DIR, exist_ok=True)

        spider_code = f"""\
import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
import time

class BenchmarkSpider(CrawlSpider):
    name = 'benchmark'
    allowed_domains = []
    start_urls = []
    rules = (Rule(LinkExtractor(), callback='parse_item', follow=True),)

    custom_settings = {{
        'DEPTH_LIMIT': {max_depth},
        'CONCURRENT_REQUESTS': {concurrency},
        'DOWNLOAD_TIMEOUT': 12,
        'RETRY_TIMES': 2,
        'ROBOTSTXT_OBEY': True,
        'CLOSESPIDER_PAGECOUNT': {max_pages},
        'LOG_ENABLED': False,
    }}

    def __init__(self, start_url='', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc.split(':')[0]]
        self.stats = {{'pages': 0, 'errors': 0, 'request_times': []}}

    def parse_item(self, response):
        start = time.time()
        self.stats['request_times'].append(time.time() - start)
        if response.status >= 400:
            self.stats['errors'] += 1
        else:
            self.stats['pages'] += 1
        yield {{
            'url': response.url,
            'status': response.status,
            'depth': response.meta.get('depth', 0),
            'links': [l.url for l in LinkExtractor().extract_links(response)],
        }}
"""

        with open(SPIDER_FILE, "w", encoding="utf-8") as f:
            f.write(spider_code)

        cmd = [
            "scrapy", "crawl", "benchmark",
            "-a", f"start_url={url}",
            "-o", os.path.join(BASE_DIR, "output.jl"),
            "--loglevel=ERROR",
            "--nolog"
        ]

        monitor = self.ResourceMonitor(os.getpid())
        t = threading.Thread(target=monitor.monitor, daemon=True)
        t.start()

        start = time.perf_counter()
        proc = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
        elapsed = time.perf_counter() - start

        monitor.stop()
        t.join()
        stats = monitor.get_stats()

        pages = 0
        errors = 0
        request_times = []
        total_links = 0

        try:
            with open(os.path.join(BASE_DIR, "output.jl"), "r") as f:
                for line in f:
                    if line.strip():
                        item = json.loads(line)
                        total_links += len(item.get("links", []))
                        pages += 1
        except Exception as e:
            logger.warning(f"Erreur lecture output.jl : {e}")

        total_req = pages + errors
        success_rate = (pages / total_req * 100) if total_req else 0
        speed = total_req / elapsed if elapsed else 0

        return {
            'time': elapsed,
            'requests_per_sec': speed,
            'pages': pages,
            'total_requests': total_req,
            'errors': errors,
            'success_rate': success_rate,
            'links': total_links,
            'min_req_time': min(request_times) if request_times else 0,
            'max_req_time': max(request_times) if request_times else 0,
            'avg_req_time': statistics.mean(request_times) if request_times else 0,
            'peak_memory_mb': stats['peak_memory_mb'],
            'avg_cpu_percent': stats['avg_cpu_percent'],
            'total_io_read_mb': stats['total_io_read_mb'],
            'total_io_write_mb': stats['total_io_write_mb'],
            'error_msg': proc.stderr.strip() if proc.returncode != 0 else None,
        }

    def run_selenium(self, url, max_depth, max_pages, concurrency):
        return {
            'time': 0,
            'requests_per_sec': 0,
            'pages': 0,
            'total_requests': 0,
            'errors': 1,
            'success_rate': 0,
            'links': 0,
            'min_req_time': 0,
            'max_req_time': 0,
            'avg_req_time': 0,
            'peak_memory_mb': 0,
            'avg_cpu_percent': 0,
            'total_io_read_mb': 0,
            'total_io_write_mb': 0,
            'error_msg': "Selenium désactivé (chromedriver non configuré sur Fedora)"
        }

    async def run_scenario(self, scenario, run_num):
        results = {}
        for crawler_type in ['custom', "scrapy"]:  # ← Pour tester stable, mets 'custom', 'scrapy' quand prêt
            agg_res = defaultdict(list)
            for url in scenario['urls']:
                logger.info(f"{crawler_type.upper()} - {scenario['name']} - Run {run_num} - {url}")
                if crawler_type == 'custom':
                    res = await self.run_custom_crawler(
                        url, scenario['max_depth'], scenario['max_pages'], scenario['concurrency']
                    )
                elif crawler_type == 'scrapy':
                    res = self.run_scrapy(
                        url, scenario['max_depth'], scenario['max_pages'], scenario['concurrency']
                    )
                else:
                    res = self.run_selenium(
                        url, scenario['max_depth'], scenario['max_pages'], min(5, scenario['concurrency'])
                    )
                agg_res[crawler_type].append(res)

            agg_dict = {}
            for k in agg_res:
                values = [d[k] for d in agg_res[k] if k in d]
                if values and isinstance(values[0], (int, float)):
                    agg_dict[k] = sum(values)
                elif k == 'success_rate' and values:
                    agg_dict[k] = statistics.mean(values)
                else:
                    agg_dict[k] = values[0] if values else None
            results[crawler_type] = agg_dict

        return results

    async def run_full_benchmark(self):
        all_results = defaultdict(dict)
        csv_file = 'benchmark_results.csv'
        fieldnames = [
            'scenario', 'crawler_type', 'run', 'time', 'requests_per_sec', 'peak_memory_mb',
            'success_rate', 'min_req_time', 'max_req_time', 'avg_req_time', 'avg_cpu_percent',
            'total_io_read_mb', 'total_io_write_mb', 'pages', 'errors', 'links', 'error_msg'
        ]

        # with open(csv_file, 'w', newline='', encoding='utf-8') as csvf:
        #     writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        #     writer.writeheader()

        for scenario in self.test_scenarios:
            logger.info(f"\n=== {scenario['name']} ({scenario['description']}) ===")
            for run in range(1, self.num_runs + 1):
                results = await self.run_scenario(scenario, run)
                for crawler_type, res in results.items():
                    row = res.copy()
                    print(res)
                    row['scenario'] = scenario['name']
                    row['crawler_type'] = crawler_type
                    row['run'] = run
                    # writer.writerow(row)
                    if scenario['name'] not in all_results:
                        all_results[scenario['name']] = defaultdict(list)
                    all_results[scenario['name']][crawler_type].append(row)

        self.export_json(all_results)
        self.visualize_results(all_results)
        self.print_colored_table(all_results)
        winners = self.determine_winners(all_results)

        return {'results': all_results, 'winners': winners}

    def export_json(self, results):
        with open('benchmark_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logger.info("Résultats exportés → benchmark_results.json")

    def visualize_results(self, results):
        metrics = ['time', 'requests_per_sec', 'peak_memory_mb', 'success_rate']
        for metric in metrics:
            fig, ax = plt.subplots(figsize=(10, 6))
            scenarios = list(results.keys())
            x = range(len(scenarios))
            for i, ct in enumerate(['custom', "scrapy"]):
                vals = [statistics.mean([r.get(metric, 0) for r in results[s][ct]] ) for s in scenarios if ct in results[s]]
                ax.bar([p + i*0.4 for p in x], vals, width=0.4, label=ct.capitalize())
            ax.set_xticks([p + 0.2 for p in x])
            ax.set_xticklabels(scenarios, rotation=45, ha='right')
            ax.set_ylabel(metric.replace('_', ' ').title())
            ax.legend()
            plt.tight_layout()
            plt.savefig(f"{metric}_comparison.png")
            plt.close()
        logger.info("Graphiques générés")

    def print_colored_table(self, results):
        console = Console()
        for scenario in results:
            table = Table(title=scenario)
            table.add_column("Crawler")
            table.add_column("Temps")
            table.add_column("Req/s")
            table.add_column("Pages")
            table.add_column("Succès")
            table.add_column("Mémoire peak")
            table.add_column("Erreur")

            for ct in results[scenario]:
                data = results[scenario][ct]
                if not data:
                    continue
                avg_time = statistics.mean(d['time'] for d in data)
                avg_rps = statistics.mean(d['requests_per_sec'] for d in data)
                avg_pages = statistics.mean(d['pages'] for d in data)
                avg_success = statistics.mean(d['success_rate'] for d in data)
                avg_mem = statistics.mean(d['peak_memory_mb'] for d in data)
                err = any(d.get('error_msg') for d in data)

                table.add_row(
                    ct.upper(),
                    f"{avg_time:.2f}s",
                    f"{avg_rps:.1f}",
                    f"{int(avg_pages)}",
                    f"{avg_success:.1f}%",
                    f"{avg_mem:.1f} MB",
                    "OUI" if err else "Non"
                )
            console.print(table)

    def determine_winners(self, results):
        winners = {}
        for scenario in results:
            scores = {}
            for ct in results[scenario]:
                data = results[scenario][ct]
                if not data:
                    continue
                avg_rps = statistics.mean(d['requests_per_sec'] for d in data)
                avg_success = statistics.mean(d['success_rate'] for d in data) / 100
                score = avg_rps * avg_success
                scores[ct] = score
            if scores:
                winner = max(scores, key=scores.get)
                winners[scenario] = winner
                logger.info(f"Gagnant {scenario}: {winner.upper()}")

        return winners

async def main():
    benchmark = CrawlerBenchmark(
        test_urls=["http://localhost:8080"],
        num_runs=2,
        selenium_test=False
    )
    result = await benchmark.run_full_benchmark()
    print("\nGagnants globaux :", result['winners'])

if __name__ == "__main__":
    asyncio.run(main())