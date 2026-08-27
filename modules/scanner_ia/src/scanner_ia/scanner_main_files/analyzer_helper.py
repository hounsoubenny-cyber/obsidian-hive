#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 19:29:43 2026

@author: hounsousamuel
"""

import os
import time
import asyncio
import aiohttp
import traceback
import atexit
from uuid import uuid4
from diskcache import Cache
from scanner_ia.core.parser import Parser
from scanner_ia.core.crawler import Crawler
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult, OneAnalyzerHelperResult
from scanner_ia.scanner_utils.utils_scanner import is_url_reachable
from scanner_ia.scanner_utils.signal_manager import signal_manager
from scanner_ia.scanner_utils.logger import get_logger
from typing import Optional, List
from scanner_ia.scanner_utils.helpers.resolve_helpers import HelperCall

logger_analyzer_helper = get_logger()

dir_ = os.path.dirname(os.path.abspath(__file__))
s = os.path.join(dir_, "var", "analyzer_helper_cache")
os.makedirs(s,exist_ok=True)

MAX_CACHE_SIZE = 1 * 1024 * 1024 * 1024
CACHE = Cache(
    directory=s, 
    size_limit=MAX_CACHE_SIZE, 
    cull_limit=40, 
    statistics=True,
    cull_frequency=5
)
CACHE_TIMEOUT = 24 *3600

def close_cache():
    if hasattr(CACHE, "close"):
        CACHE.close()
        
def close_atexit():
    atexit.register(close_cache)

def cache_stats():
    return {
        'size': CACHE.volume(),
        'items': len(CACHE),
        'expired': CACHE.expire(),
        'hit_ratio': CACHE.stats() 
    }

        
def signal_handler(*args, **kwargs):
	close_cache()

signal_manager(signal_handler)
close_atexit()


class Config:
    TEST_SITES = [
        "http://localhost:8081",
        "http://example.com",
        "https://httpbin.org/html",
        "https://quotes.toscrape.com/",
        "https://books.toscrape.com/",
    ]
    
    def __init__(self):
        self.MAX_WORKERS = 3
        self.MAX_URL = 100
        self.DEBUG = False
        self.JOIN_TIMEOUT = 60 * 10
        self.GET_TIMEOUT = 0.1
        self.EMPTY_MAX_COUNT = 3
        self.EMPTY_AWAIT_BETWEEN = 10
    

class AnalyzerHelper:
    """
    Classe dédié qui combine Crawler et Parser pour parser inteligemment toutes les pages
    crawlés et fournie un resultat utilisable par l'Analyzer.
    Ses attributs:
        session: ClientSession aiohttp.
        crawler: Classe de crawl, une instance t il possède déja un parser intégrer, crawler.parser
        use_cache: Détermine si il faut utiliser le cache pour Les résultats.
        cache_key_prefix: Prefix des clé de cache pour l'AnalyzerHelper.
    """
    
    def __init__(self, session:aiohttp.ClientSession = None, use_cache:bool = True, **kwargs):
        """
        
        Parameters
        ----------
        session : aiohttp.ClientSession
            ClientSession aiohttp.
        use_cache : bool, optional
            Détermine si il faut utiliser le cache pour Les résultats. The default is True.
        **kwargs : dict
            Utiliser pour mettre à jour les config pour les instances pour l'AnalyzerHelper et le Crawler.
            Voilà quelque uns:
                MAX_URL: Nombre max d'url pour entamer traitement parallèle. Sinon traitement séquentiel.
                MAX_WORKERS: Nombre de workers (pour les deux).
                GET_TIMEOUT: Temps d'attente pour récupérer un élément (pour les deux).
                DEBUG: Détermine si il faut afficher le tracback des erreurs, utile pour debug (pour les deux).
                MAX_DEEPTH: Profondeur max de crawl (pour crawler seul).
                MAX_PAGES: Nombre max de pages à crawler (pour crwaler seul).
                JOIN_TIMEOUT: Temps d'attente max du crawl (pour crwaler seul).
                SAVE_PERIOD: Période de sauvegarde( toutes les n urls), (pour crwaler seul).
                Semaphore: Limitation concurente (pour les deux)
                RETRIES: Nombre de retry si l'obtention des urls échoue, (pour crwaler seul).
                DELAY: Delai entre les retry (pour crwaler seul).
                MAX_QUEUE: Nombre max d'éléments dans la queue (pour crwaler seul).

        Returns
        -------
        None.

        """
        
        self.session = session
        self.crawler = Crawler(session=self.session, **kwargs) 
        self.config = Config()
        self.update_conf(kwargs)
        self.use_cache = use_cache
        self.cache_key_prefix = "analyzer_helper"
    
    async def create_session(self, session):
        return session or aiohttp.ClientSession()

    def update_conf(self, kwargs: dict = None):
        """
         Méthode pour mettre à jour la config.        
            
         Parameters
         ----------
         kwargs : dict, optional
             Dictionnaire des clé de config si fourni. The default is {}.
 
         Returns
         -------
         None.
 
         """
        kwargs = kwargs or {}
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)
            elif hasattr(self.config, k.upper()):
                setattr(self.config, k.upper(), v)
    
    def _get_cache_key(self, url:str, restore:bool, fetch:bool, verify_reachability:bool) -> str:
        """Génère une clé de cache unique"""
        return f"{self.cache_key_prefix}:{url}:{restore}:{fetch}:{verify_reachability}"
    
    async def _process_url(
        self, 
        queue: asyncio.Queue, 
        lock: asyncio.Lock, 
        result: AnalyzerHelperResult, 
        parser: Parser,
        restore: bool = False, 
        fetch: bool = True, 
        semaphore: int = 50,
        worker_id: str = "",
        silent: bool = True,
    ):
        """
        

        Parameters
        ----------
        queue : asyncio.Queue
            Queue pour les workers.
        lock : asyncio.Lock
            Lock asyncio pour eviter corruption de données.
        result : AnalyzerHelperResult
            Objet resultat pour stocker les éléments.
        parser : Parser
            Parser pour parser rapidement les body html.
        restore : bool, optional
            Détermine si il faut utiliser le cache ou non pour le crawl et le parser. The default is False.
        fetch : bool, optional
            Détermine si les scripts js doivent être téléchargés. The default is True.
        semaphore : int, optional
            Limitation concurrente. The default is 50.
        worker_id : str, optional
            id unique pour chaque worker, utile pour debug. The default is "".
        silent : bool, optional
            Niveau de verbosité pour le parser. The default is True.

        Raises
        ------
        asyncio
            TimeoutError pour signaler la fin.

        Returns
        -------
        None.

        """
        get_timeout_err = 0
        max_get_timeout_err = 3
        queue_empty_count = 0
        max_queue_empty_count = 3
        while True:
            get_item = False
            worker_object = None
            try:
                worker_object = await asyncio.wait_for(queue.get(), timeout=self.config.GET_TIMEOUT)
                get_item = True
                get_timeout_err = 0
                queue_empty_count = 0
                if worker_object is None:
                    break
                
                parse_html_response = await parser.parse_html(
                    url_or_body=worker_object.url,
                    response=True
                )
                parser_response = await parser.parse(
                        url=worker_object.url,
                        parse_html_response=parse_html_response,
                        fetch=fetch,
                        restore=restore,
                        semaphore=semaphore,
                        silent=silent
                    )
                
                new_obj = OneAnalyzerHelperResult()
                new_obj.fetched = parse_html_response.response
                new_obj.parsed = parser_response
                new_obj.crawl = worker_object
                
                async with lock:
                    result.elements[worker_object.url] = new_obj
            
            except asyncio.TimeoutError:
                logger_analyzer_helper.info("Timeout Get!")
                get_timeout_err += 1
                async with lock:
                    if queue.empty() and get_timeout_err >= max_get_timeout_err:
                        logger_analyzer_helper.info("Queue vide, tout sera marqué done !")
                        for _ in range(self.config.MAX_WORKERS):
                            await queue.put(None)
                            # Remarque: Mm que celui du crawler.
                        for _ in range(queue.qsize()):
                            try:
                                queue.task_done() 
                            except Exception:
                                pass
                            
                        break
                                
            except asyncio.QueueEmpty:
                queue_empty_count += 1
                logger_analyzer_helper.debug("Queue vide !")
                # Mm logique par précaution
                if queue_empty_count >= max_queue_empty_count:
                    break
            
            except KeyboardInterrupt:
                break
            
            except asyncio.CancelledError:
                logger_analyzer_helper.debug(f"Worker {worker_id} annulé")
                break
            
            except Exception as e:
                logger_analyzer_helper.error(f"Erreur dans worker {worker_id}: {e}")
                if self.config.DEBUG:
                    logger_analyzer_helper.error(traceback.format_exc())
                    
            finally:
                if get_item:
                    try:
                        queue.task_done() 
                    except Exception:
                        pass
                    
    async def close(self):
        """Ferme les ressources"""
        await self.crawler.close()
        logger_analyzer_helper.debug("AnalyzerHelper fermé")
        
    async def analyse_and_parse_all(
        self, 
        url:str, 
        verify_reachability:bool = True, 
        restore:bool = False, 
        fetch:bool = True, 
        semaphore:int = 50,
        silent:bool = True,
        helpers: Optional[List[callable] | List[dict] | List[HelperCall]] = None,
        raise_on_helper_error: bool = True,
        is_spa: bool = False,
    ):
        """
        Méthode pour parser les liens trouvés par le crawler intelligemment

        Parameters
        ----------
        url : str
            Url source à parser.
        verify_reachability : bool, optional
            Vérifier si l'url est atteignable avant de commencer, utile pour eviter perte de temps. The default is True.
        restore : bool, optional
            Détermine si il faut utiliser le cache ou non pour le crawl et le parser. The default is False.
        fetch : bool, optional
            Détermine si les scripts js doivent être téléchargés. The default is True.
        semaphore : int, optional
            Limitation concurrente. The default is 50.
        silent : bool, optional
            Niveau de verbosité pour le parser. The default is True.
        helpers: Liste de fonctions async à exécuter avant le crawl
        raise_on_helper_error: Lever une exception si un helper échoue
        
        Returns
        -------
        result : AnalyzerHelperResult
            Résultat du parsing et fetching.

        """
        
        result = AnalyzerHelperResult()
        start_time = time.time()
        try:
            url = self.crawler.parser.normalize_link(url, "")
            if not url:
                return result
            
            # Vérification du cache
            cache_key = self._get_cache_key(url, restore, fetch, verify_reachability)
            if self.use_cache and restore:
                cached = CACHE.get(cache_key)
                if cached:
                    result.update_from_dict(cached)
                    result.elapsed = time.time() - start_time
                    logger_analyzer_helper.success(f"Cache utilisé pour {url}")
                    return result
            
            if verify_reachability:
                can = await is_url_reachable(url)
                if not can:
                    logger_analyzer_helper.warning(f"{url} inaccessible, analyse annulée")
                    return result
                
            crawl_response = await self.crawler.crawl(url, restore, helpers, raise_on_helper_error, use_playwright=is_spa)
            
            if len(crawl_response.result) < self.config.MAX_URL:
                # Traitement séquentiel
                logger_analyzer_helper.debug("Traitement séquentiel")
                for worker_result in crawl_response.result:
                    # t = await self.crawler.parser.classify_link(worker_result.url)
                    # if t.type != "html":
                    #     continue
                    parse_html_response = await self.crawler.parser.parse_html(
                        url_or_body=worker_result.url,
                        response=True
                    )
                    parser_response = await self.crawler.parser.parse(
                            url=worker_result.url,
                            parse_html_response=parse_html_response,
                            fetch=fetch,
                            restore=restore,
                            semaphore=semaphore,
                            silent=silent
                        )
                    
                    new_obj = OneAnalyzerHelperResult()
                    new_obj.fetched = parse_html_response.response
                    new_obj.parsed = parser_response
                    new_obj.crawl = worker_result
                    result.elements[worker_result.url] = new_obj
                    
            else:
                # Traitement parallèle avec workers
                logger_analyzer_helper.debug("Traitement parallèle")
                lock = asyncio.Lock()
                queue = asyncio.Queue()
                
                for worker_result in crawl_response.result:
                    await queue.put(worker_result)
                
                base_id = str(uuid4())[:10]
                tasks = [
                    asyncio.create_task(self._process_url(
                        queue=queue, 
                        lock=lock, 
                        result=result, 
                        parser=self.crawler.parser,
                        restore=restore, 
                        fetch=fetch, 
                        semaphore=semaphore,
                        worker_id=f"{i}_{base_id}",
                        silent=silent
                    ))
                    for i in range(self.config.MAX_WORKERS)
                ]
                
                join_task = asyncio.create_task(
                    asyncio.wait_for(
                        queue.join(), 
                        timeout=self.config.JOIN_TIMEOUT
                    )
                )
                try:
                    await join_task
                    logger_analyzer_helper.info("Queue vidée avant timeout")
                    
                except (asyncio.TimeoutError, asyncio.QueueEmpty) as e:
                    if isinstance(e, asyncio.TimeoutError):
                        logger_analyzer_helper.warning(f"Timeout join atteint timeout={self.config.JOIN_TIMEOUT}")
                    else:
                        logger_analyzer_helper.warning("Queue vide !")
                    while not queue.empty():
                        try:
                            queue.get_nowait()
                            queue.task_done()
                        except asyncio.QueueEmpty:
                            break
                        
                except Exception as e:
                    logger_analyzer_helper.error(f"Erreur pour join : {e}")
                    if self.config.DEBUG:
                        logger_analyzer_helper.error(traceback.format_exc())
                        
                finally:
                    self.stop_task(tasks)
                    for _ in range(self.config.MAX_WORKERS):
                        await queue.put(None)
                    await asyncio.gather(*tasks, return_exceptions=True)
                        
            result.elapsed = time.time() - start_time
            if self.use_cache and result.elements:
                CACHE.set(cache_key, result.to_dict(), expire=CACHE_TIMEOUT)
                
        except Exception as e:
            logger_analyzer_helper.error(f"Erreur dans analyzer_helper : {e}")
            if self.config.DEBUG:
                logger_analyzer_helper.error(traceback.format_exc())
        
        result.elapsed = time.time() - start_time
        return result
    
    def stop_task(self, tasks):
        for t in tasks:
            try:
                t.cancel()
            except Exception:
                pass
            
    async def test(self, urls:list|str = None, restore:bool = False):
        """
        Méthode de test pour l'AnalyzerHelper
        
        Args:
            urls: URL unique ou liste d'URLs à tester
            restore: Utiliser le cache ou non
        """
        logger_analyzer_helper.info("\n" + "🔥"*70)
        logger_analyzer_helper.info("🔥 TEST DE L'ANALYZER HELPER")
        logger_analyzer_helper.info("🔥"*70)
        
        if urls is None:
            urls_to_test = self.config.TEST_SITES
            mode = "MULTI (défaut)"
        elif isinstance(urls, str):
            urls_to_test = [urls]
            mode = "SIMPLE"
        elif isinstance(urls, (list, tuple, set)):
            urls_to_test = list(urls)
            mode = "MULTI"
        else:
            raise TypeError(f"Type invalide: {type(urls)}")
        
        logger_analyzer_helper.info(f"\n📌 Mode: {mode} - {len(urls_to_test)} URL(s)")
        logger_analyzer_helper.info(f"💾 Cache: {'ACTIVÉ' if self.use_cache else 'DÉSACTIVÉ'}")
        logger_analyzer_helper.info("-"*70)
        
        results = {}
        total_start = time.time()
        self.session = await self.create_session(None)
        for i, url in enumerate(urls_to_test, 1):
            logger_analyzer_helper.info(f"\n📌 Test {i}/{len(urls_to_test)}: {url}")
            logger_analyzer_helper.info("-"*50)
            
            start = time.time()
            result = await self.analyse_and_parse_all(
                url=url,
                verify_reachability=True,
                restore=restore,
                fetch=True,
                semaphore=50
            )
            elapsed = time.time() - start
            # Stats
            n_elements = len(result.elements)
            n_fetched = sum(1 for e in result.elements.values() if e.fetched and not e.fetched.error)
            n_parsed = sum(1 for e in result.elements.values() if e.parsed)
            
            logger_analyzer_helper.info(f"  ⏱️  Temps: {elapsed:.3f}s")
            logger_analyzer_helper.info(f"  📊 Éléments: {n_elements}")
            logger_analyzer_helper.info(f"  ├─ Fetched OK: {n_fetched}")
            logger_analyzer_helper.info(f"  └─ Parsed OK: {n_parsed}")
            
            results[url] = {
                'time': elapsed,
                'elements': n_elements,
                'fetched': n_fetched,
                'parsed': n_parsed
            }
        
        # Résumé final
        total_time = time.time() - total_start
        total_elements = sum(r['elements'] for r in results.values())
        total_fetched = sum(r['fetched'] for r in results.values())
        total_parsed = sum(r['parsed'] for r in results.values())
        
        logger_analyzer_helper.info("\n" + "★"*70)
        logger_analyzer_helper.info("📊 RÉSUMÉ FINAL")
        logger_analyzer_helper.info("★"*70)
        logger_analyzer_helper.info(f"📌 URLs testées: {len(urls_to_test)}")
        logger_analyzer_helper.info(f"⏱️  Temps total: {total_time:.3f}s")
        logger_analyzer_helper.info(f"📄 Éléments totaux: {total_elements}")
        logger_analyzer_helper.info(f"├─ Fetched OK: {total_fetched}")
        logger_analyzer_helper.info(f"└─ Parsed OK: {total_parsed}")
        logger_analyzer_helper.info(f"⚡ Vitesse: {total_elements/total_time:.1f} élém/s")
        logger_analyzer_helper.info("★"*70)
        
        return results


async def test_analyzer(restore:bool = True, urls:list = None):
    """Fonction de test externe"""
    session = aiohttp.ClientSession()
    analyzer = AnalyzerHelper(session=session, use_cache=False)
    
    try:
        results = await analyzer.test(urls=urls, restore=restore)
        return results
    finally:
        # await analyzer.close()
        # await session.close()
        logger_analyzer_helper.info("\n🧹 Nettoyage terminé")


if __name__ == "__main__":
    asyncio.run(test_analyzer(restore=False, urls=Config.TEST_SITES[0]))
    
    # asyncio.run(test_analyzer(restore=False, urls=["http://example.com"]))