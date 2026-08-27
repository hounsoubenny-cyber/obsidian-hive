#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 11:48:38 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import asyncio
import traceback
import aiohttp
import time
import signal
import atexit
from datetime import datetime
from urllib.parse import urlparse
from diskcache import Cache
from uuid import uuid4
from scanner_ia.base_class.crawler_base_class import CrawlerResult, WorkerResult
from scanner_ia.scanner_utils.signal_manager import signal_manager
from scanner_ia.core.parser import Parser
from nest_asyncio import apply
# from loguru import logger as logger_crawler
from scanner_ia.scanner_utils.logger import get_logger
from typing import Optional, List
from scanner_ia.scanner_utils.helpers.resolve_helpers import resolve_helpers, HelperCall

logger_crawler = get_logger()
# logger_crawler.remove()
# logger_crawler.add(
#     sys.stdout,
#     format=(
#         "<yellow>{time:HH:mm:ss}</yellow> | "
#         "<level>{level: <8}</level> | "
#         "<magenta>{name}</magenta>:<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
#         "└─ <level>{message}</level>"
#     ),
#     level="DEBUG",
#     colorize=True
# )
# logger_crawler.add(
#     "logs/crawler_logs.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )

apply()

dir_ = os.path.dirname(os.path.abspath(__file__))
s = os.path.join(dir_, "var", "crawler_cache")
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
        'https://quotes.toscrape.com/',  
        'https://books.toscrape.com/',   
        'https://httpbin.org/',          
        'https://jsonplaceholder.typicode.com/', 
        'https://www.wikipedia.org'
    ]
    def __init__(self):
        self.MAX_DEEPTH = 5
        self.MAX_PAGES = 1000
        self.JOIN_TIMEOUT = 10 * 10
        self.GET_TIMEOUT = 1
        self.SAVE_PERIOD = 100
        self.DEBUG = True
        self.Semaphore = 50
        self.RETRIES = 2
        self.DELAY = 1
        self.MAX_QUEUE = 1000000
        self.MAX_WORKERS = 4
        self.PRINT_INTERVAL = 10
        self.RESTRAIN_FOR_THIS_DOMAIN = True
        self.EMPTY_MAX_COUNT = 3
        self.EMPTY_AWAIT_BETWEEN = 10
        self.SKIP_EXTERNAL_LINKS:bool = True
    

class QueueEmptyError(Exception):
    def __init__(self, *args):
        pass
    
class Crawler:
    """
    Classe de crawl pour trouver des urls.
    """
    def __init__(self, session:aiohttp.ClientSession, **kwargs):
        """
        
        Parameters
        ----------
        session : aiohttp.ClientSession
            ClientSession aiohttp. The default is None.
        **kwargs : dict
            Utiliser pour mettre à jour les config pour les instances pour le Fetcher et le Crawler.
            Voilà quelque uns:
                MAX_URL: Nombre max d'url pour entamer traitement parallèle. Sinon traitement séquentiel.
                MAX_WORKERS: Nombre de workers (pour le crawler).
                GET_TIMEOUT: Temps d'attente pour récupérer un élément (pour le crawler).
                DEBUG: Détermine si il faut afficher le tracback des erreurs, utile pour debug (pour les deux).
                MAX_DEEPTH: Profondeur max de crawl (pour crawler seul).
                MAX_PAGES: Nombre max de pages à crawler (pour crwaler seul).
                JOIN_TIMEOUT: Temps d'attente max du crawl (pour crwaler seul).
                SAVE_PERIOD: Période de sauvegarde( toutes les n urls), (pour crwaler seul).
                Semaphore: Limitation concurente (pour les deux)
                RETRIES: Nombre de retry si l'obtention des urls échoue, (pour crwaler seul).
                DELAY: Delai entre les retry (pour crwaler seul).
                MAX_QUEUE: Nombre max d'éléments dans la queue (pour crwaler seul).
                MAX_REDIRECTS: Nombre max de redirections à suivre (pour fetcher seul).
                TTL: Durée de validité des éléments mis en cache pour le fetcher (pour fetcher seul).
                MAX_ATTEMPT: Nombre de réessaie si fetch échoue (pour fetcher seul).
                WAIT_BETWEEN: Durée d'attente entre retry pour le fetcher (pour fetcher seul).

        Returns
        -------
        None.

        """
        self.session = session
        self.parser = Parser(session=self.session, **kwargs)
        self.config = Config()
        self.update_conf(kwargs)
        self.counts = {}
    
    async def create_session(self, session):
        return session or aiohttp.ClientSession()
    
    def update_conf(self, kwargs:dict = None):
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
                
    async def close(self):
        """
        Fermer les sessions.

        Returns
        -------
        None.

        """
        if self.session and not self.session.closed:
            await self.session.close()
            logger_crawler.debug("Session crawler fermée")
    
    async def save_worker(
        self,
        url:str,
        visited:set,
        result:CrawlerResult,
    ):
        """
        Méthode pour sauvegarde des résultats sur disque.

        Parameters
        ----------
        url : str
            Url de crawl.
        visited : set
            Set des urls visités.
        result : CrawlerResult
            Résultat actuel du crawl.

        Returns
        -------
        None.

        """
        to_save = {
            "visited": list(visited),
            "result": result.to_dict(),
            }
        CACHE.set(url, to_save, expire=CACHE_TIMEOUT)
        logger_crawler.debug(f"Résultats sauvegardés pour {url}")
    
    async def _restore(self, url:str, visited:set, result:CrawlerResult, queue:asyncio.Queue):
        """
        Mérhode pour restorer les éléments de crawl, utile pour continuer un crawl

        Parameters
        ----------
       url : str
           Url de crawl.
       visited : set
           Set des urls visités.
        result : CrawlerResult
            Un objet CrawlerResult pour crawl.
        queue : asyncio.Queue
            Queue où mettre les éléments.
            
        Returns
        -------
        bool
            True/False selon succès.

        """
        try:
            cache = CACHE.get(url, {})
            if not cache:
                logger_crawler.debug("Pas d'historique, pas de restoration")
                return False
            
            to_crawl = 0
            visited.update(set(cache.get("visited", [])))
            result.update_from_dict(cache.get("result", {}))
            for worker_object in result.result:
                for link in worker_object.html_links:
                    n_link = self.parser.normalize_link(link, "")
                    if link not in visited:
                        if self.config.RESTRAIN_FOR_THIS_DOMAIN and not self.parser.is_same_domain(url, n_link):
                            continue
                        new_worker_result = WorkerResult()
                        new_worker_result.deep = worker_object.deep + 1
                        new_worker_result.url = n_link
                        new_worker_result.source_url = worker_object.url
                        await queue.put(new_worker_result)
                        to_crawl += 1
                        
            logger_crawler.info(f"Restauré: {len(visited)} visitées, {to_crawl} à crawler")
            return True
        except Exception as e:
            logger_crawler.error(f"Erreur de restoration : {e}")
            if self.config.DEBUG:
                logger_crawler.error(traceback.format_exc())
            return False
            
    def _validate_link(self, url:str, max_url_length:int = 2048):
        """
        Méthode de validation de lien.

        Parameters
        ----------
        url : str
            Url à valider.
        max_url_length : int, optional
            Taille max d'une url. The default is 2048.

        Returns
        -------
        bool
            True/False selon succès.

        """
        if not url:
            return False
        
        url = str(url).strip()
        if not url or not isinstance(url, str):
            return False
        
        if url in ("/", "#", "", None):
            return False

        if len(url) > max_url_length:
            logger_crawler.warning(f"URL trop longue ({len(url)}/{max_url_length}): {url[:100]}...")
            return False

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                logger_crawler.warning(f"URL sans hostname valide: {url}")
                return False
            
            l = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if hostname in l or any(c in hostname for c in l):
                return True

            labels = hostname.split(".")
            if len(labels) < 2:
                logger_crawler.warning(f"Domaine invalide (pas de point): {hostname}")
                return False

            for label in labels:
                if not label or len(label) > 63:
                    logger_crawler.warning(f"Label invalide dans {hostname}: '{label}' (longueur: {len(label)})")
                    return False
                try:
                    label.encode('idna').decode('ascii')
                except (UnicodeError, UnicodeDecodeError):
                    logger_crawler.warning(f"Label non-valide IDNA dans {hostname}: {label}")
                    return False
                
            return True
        except Exception as e:
            logger_crawler.error(f"Erreur validation domaine pour {url}: {e}")
            return False
                
    async def _worker(
        self, 
        url:str, 
        visited:set, 
        result:CrawlerResult, 
        queue:asyncio.Queue, 
        signal_queue:asyncio.Queue,
        lock:asyncio.Lock, 
        worker_id:str="",
        use_playwright: bool = False
    ):
        """
        Worker asynchrone pour crawl.

        Parameters
        ----------
        url : str
            Url de crawl.
        visited : set
            Set des urls visités.
         result : CrawlerResult
             Un objet CrawlerResult pour crawl.
         queue : asyncio.Queue
             Queue contenant les éléments à crawler.
        lock : asyncio.Lock
            Lock asyncio pour assurer protection lors de l'accès des ressources partagées.
        worker_id : str, optional
            Identifiant unique pour chaque worker, utile pour debug. The default is "".
        use_playwright: bool, default is False
            Dtermine l'utilisation de playwright pour le crawl.
        Raises
        ------
        asyncio
            QueueEmpty si queue vide.

        Returns
        -------
        None.

        """
        
        local_count = 0
        while True:
            get_item = False
            can_save = False
            can_put = False
            worker_object = WorkerResult()
            get_all_links_result = None
            
            try:
                worker_object:WorkerResult | None = await asyncio.wait_for(fut=queue.get(), timeout=self.config.GET_TIMEOUT)
                get_item = True
                if worker_object is None:
                    await signal_queue.put(None)
                    break
                
                if worker_object.deep >= self.config.MAX_DEEPTH or \
                   not worker_object.url.startswith("http"):
                       continue
                
                same_domain = self.parser.is_same_domain(worker_object.url, url) 
                # async with lock:
                #     is_same = self.parser.is_same_domain(worker_object.url, url)
                #     should_skip = self.config.RESTRAIN_FOR_THIS_DOMAIN and not is_same
                    
                #     print(f"\n{'='*60}")
                #     print(f"🔍 DEBUG FILTRAGE DOMAINE")
                #     print(f"{'='*60}")
                #     print(f"URL source        : {url}")
                #     print(f"Lien trouvé       : {worker_object.url}")
                #     print(f"Same domain       : {is_same}")
                #     print(f"RESTRAIN_FOR_THIS_DOMAIN : {self.config.RESTRAIN_FOR_THIS_DOMAIN}")
                #     print(f"Should skip       : {should_skip} {'🚫 IGNORÉ' if should_skip else '✅ GARDÉ'}")
                #     print(f"Queue size        : {queue.qsize()}")
                #     print(f"Queue content     : {list(queue._queue)[:5]}...")  # Affiche les 5 premiers
                #     print(f"{'='*60}\n")
                if self.config.RESTRAIN_FOR_THIS_DOMAIN and not same_domain:  # Ne pas sortir du domaine
                    continue
                
                can_save = True
                async with lock:
                    if worker_object.url in visited or \
                        len(visited) > self.config.MAX_PAGES:
                            continue
                    visited.add(worker_object.url)
                    # if self.config.DEBUG:
                        # logger_crawler.debug(f"Worker {worker_id} traite {worker_object.url}")
                
                for i in range(self.config.RETRIES):
                    try:
                        get_all_links_result = await self.parser.get_all_links(
                            worker_object.url, 
                            self.config.Semaphore, 
                            self.config.SKIP_EXTERNAL_LINKS,
                            use_playwright=use_playwright
                        )
                        if get_all_links_result:
                            if get_all_links_result.error:
                                worker_object.error = f"Erreur get_all_links {get_all_links_result.error}"
                                continue
                            else:
                                break
                        continue
                    except Exception as e:
                        worker_object.error = f"Erreur get_all_links {str(e)}"
                        if i == self.config.RETRIES - 1:
                            logger_crawler.warning(f"Dernière tentative échoué pour {worker_object.url}")
                        await asyncio.sleep(self.config.DELAY)
                
                # print(get_all_links_result)
                if not get_all_links_result or not get_all_links_result.status or get_all_links_result.error:
                    continue
                
                worker_object.status_code = get_all_links_result.status_code
                
                worker_object.same_domain = same_domain
                worker_object.other_links = list(dict.fromkeys(get_all_links_result.other_links))
                worker_object.type = get_all_links_result.type
                
                for link, data in get_all_links_result.html_links.items():
                    # print(link, data)
                    n_link = self.parser.normalize_link(link, "")
                    if self._validate_link(n_link) and \
                        n_link.startswith("http") and \
                        queue.qsize() < self.config.MAX_QUEUE and \
                        data.get('robot_allow', True):
                            # async with lock:
                            #         # Debug pour le filtrage des domaines
                            #         is_same = self.parser.is_same_domain(url, n_link)
                            #         should_skip = self.config.RESTRAIN_FOR_THIS_DOMAIN and not is_same
                                    
                            #         print(f"\n{'='*60}")
                            #         print(f"🔍 DEBUG FILTRAGE DOMAINE")
                            #         print(f"{'='*60}")
                            #         print(f"URL source        : {url}")
                            #         print(f"Lien trouvé       : {n_link}")
                            #         print(f"Same domain       : {is_same}")
                            #         print(f"RESTRAIN_FOR_THIS_DOMAIN : {self.config.RESTRAIN_FOR_THIS_DOMAIN}")
                            #         print(f"Should skip       : {should_skip} {'🚫 IGNORÉ' if should_skip else '✅ GARDÉ'}")
                            #         print(f"Queue size        : {queue.qsize()}")
                            #         print(f"Queue content     : {list(queue._queue)[:5]}...")  # Affiche les 5 premiers
                            #         print(f"{'='*60}\n")
                            if self.config.RESTRAIN_FOR_THIS_DOMAIN and not self.parser.is_same_domain(url, n_link):  # Ne pas sortir du domaine
                                continue
                            if n_link not in worker_object.html_links:
                                worker_object.html_links.append(n_link)
                                
                            new_worker_result = WorkerResult()
                            new_worker_result.deep = worker_object.deep + 1
                            new_worker_result.url = n_link.rstrip("/")
                            new_worker_result.source_url = worker_object.url
                            async with lock:
                                if new_worker_result.url not in visited:
                                    await queue.put(new_worker_result)
                                    logger_crawler.debug(f"Nouvelle URL ajoutée: {new_worker_result.url}")
                                    # await asyncio.sleep(0.001)
                
                worker_object.update_counts()
                can_put = True
                
            except asyncio.TimeoutError:
                async with lock:
                    if queue.empty():  
                        for _ in range(self.config.MAX_WORKERS):
                            await queue.put(None)
                    await signal_queue.put(None)
                break
            
            except asyncio.CancelledError:
                logger_crawler.debug(f"Worker {worker_id} annulé")
                await signal_queue.put(None)
                break
            
            except asyncio.QueueEmpty:
                logger_crawler.debug("Queue vide !")
                await signal_queue.put(None)
                break
            
            except KeyboardInterrupt:
                break
            
            except Exception as e:
                logger_crawler.error(f"Erreur dans worker crawl {worker_id}: {e}")
                worker_object.error = str(e)
                if self.config.DEBUG:
                    logger_crawler.error(traceback.format_exc())
                    
            finally:
                if get_item:
                    if worker_object is not None:
                        async with lock:
                            worker_object.fin_crawl = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
                            if can_put:
                                result.result.append(worker_object)
                                    
                    queue.task_done()
                
                async with lock:
                    if can_save and len(result.result) % self.config.SAVE_PERIOD == 0:
                        await self.save_worker(url=url, visited=visited, result=result)
                        
                    local_count += 1
                    if url not in self.counts:
                        self.counts[url] = {}
                    self.counts[url][worker_id] = local_count
                # print(worker_object)
                # print(queue._queue)
                
                await asyncio.sleep(0.00001)
     
    async def _compute_stats(self, result:CrawlerResult, elapsed:float):
        """
        Méthode de calcul et d'ajout des stats de crawl.

        Parameters
        ----------
        result : CrawlerResult
            Résultat du crawl.
        elapsed : float
            Durée de crawl.

        Returns
        -------
        None.

        """
        stats = {
            "elapsed": elapsed,
            "fin_crawl": datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
            }
        n_error = 0
        err_list = []
        n_pages = 0
        for r in result.result:
            if r.error:
                err_list.append(r.error)
                n_error += 1
            if r.url.startswith("http"):
                n_pages += 1
        
        stats["n_error"] = n_error
        stats["err_list"] = err_list
        stats["n_pages"] = n_pages  
        stats["speed"] = float(f"{n_pages / elapsed :.2f}") if elapsed > 0 else 0
        result.stats = stats
    
    def stop_task(self, tasks):
        for t in tasks:
            try:
                t.cancel()
            except Exception:
                pass
        
    async def crawl(
        self, 
        url:str, 
        restore:bool = False, 
        helpers: Optional[List[callable] | List[dict] | List[HelperCall]] = None,
        raise_on_helper_error: bool = True,
        use_playwright: bool = False
    ) -> CrawlerResult:
        """
        

        Parameters
        ----------
        url : str
            Url à crawler.
        restore : bool, optional
            Détermine si il faut restorer le cache pour continuer le crawl. The default is False.
        helpers: Liste de fonctions async à exécuter avant le crawl
        raise_on_helper_error: Lever une exception si un helper échoue
        use_playwright: bool, default is False
            Dtermine l'utilisation de playwright pour le crawl.
        Returns
        -------
        result : CrawlerResult
            Résultat de crawl.

        """
        visited = set()
        result = CrawlerResult()
        queue = asyncio.Queue(maxsize=self.config.MAX_QUEUE)
        lock = asyncio.Lock()  
        signal_queue = asyncio.Queue()
        done, pending = [], []
        
        try:
            # ========== HELPERS (si fournie) ==========
            if helpers:
                first = helpers[0]
                if isinstance(first, (dict, HelperCall)):
                    helpers = resolve_helpers(helper_calls=helpers)
                try:
                    logger_crawler.info("🔐 Exécution Helpers...")
                    tasks = []
                    for helper in helpers:
                        # helper = [func, args, kwargs]
                        # session est ajouté automatiquement au début des args
                        func = helper[0]
                        args = helper[1] if len(helper) > 1 else ()
                        kwargs = helper[2] if len(helper) > 2 else {}
                        
                        task = asyncio.create_task(func(self.session, *args, **kwargs))
                        tasks.append(task)
                    
                    _result = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in _result:
                        if isinstance(r, Exception):
                            raise r
                    logger_crawler.info("✅ Exécution réussie")
                except Exception as e:
                    logger_crawler.error(f"❌ Exécution: {e}")
                    if raise_on_helper_error:
                        raise
            
            url = self.parser.normalize_link(url, "")
            if not self._validate_link(url):
                result.error = "Lien invalide"
                return result
            
            url = url.rstrip("/")
            result.url = url
            result.type = await self.parser.classify_link(url)
            result.type = result.type.type
            
            restored = False
            if restore:
                restored = await self._restore(url, visited, result, queue)
                
                if restored and (len(visited) <= 2 or len(result.result) <= 2):
                    visited, result = set(), CrawlerResult()
                    restored = False
                
                if not restored:
                    worker_object = WorkerResult()
                    worker_object.source_url = url
                    worker_object.url = url
                    worker_object.deep = 0
                    worker_object.same_domain = True
                    worker_object.type = result.type
                    await queue.put(worker_object)
                    
            else:
                worker_object = WorkerResult()
                worker_object.source_url = url
                worker_object.url = url
                worker_object.deep = 0
                worker_object.same_domain = True
                worker_object.type = result.type
                await queue.put(worker_object)
                
            base_id = str(uuid4())[:10]
            logger_crawler.info(f"Début crawl pour url = {url}")
            start_time = time.time()     
            tasks = [
                    asyncio.create_task(self._worker(
                        url=url, 
                        visited=visited, 
                        result=result, 
                        queue=queue, 
                        lock=lock, 
                        signal_queue=signal_queue,
                        worker_id=f"{i}_{url[:10]}_{base_id}",
                        use_playwright=use_playwright
                    )
                    )
                    for i in range(self.config.MAX_WORKERS)
                ]
                
            async def monitor_queue():
                empty_count = 0
                while not queue.empty():
                    await asyncio.sleep(0.2)
                    try:
                        item = signal_queue.get_nowait()
                        if item is None:
                            logger_crawler.warning("🚨 SIGNAL NONE DÉTECTÉ ! ARRÊT IMMÉDIAT")
                            raise QueueEmptyError("Signal d'arrêt reçu d'un worker")
            
                    except asyncio.QueueEmpty:
                        pass
                    
                    if queue.empty():
                        await asyncio.sleep(self.config.EMPTY_AWAIT_BETWEEN)
                        if queue.empty():
                            empty_count += 1
                    if empty_count >= self.config.EMPTY_MAX_COUNT:
                        logger_crawler.info("📭 Queue vide, arrêt normal")
                        raise asyncio.QueueEmpty("📭 Queue vide, arrêt normal")
                    
            
            monitor_task = asyncio.create_task(monitor_queue())
            join_task = asyncio.create_task(asyncio.wait_for(queue.join(), self.config.JOIN_TIMEOUT))
            try:
                done, pending = await asyncio.wait(
                    [monitor_task, join_task],
                    timeout=self.config.JOIN_TIMEOUT,
                    return_when=asyncio.FIRST_EXCEPTION
                    )
                for task in done:
                    task.result()   # Pour propager l'erreur
                logger_crawler.info("Queue vidée avant timeout")
                
            except (asyncio.TimeoutError, asyncio.QueueEmpty, QueueEmptyError) as e:
                if isinstance(e, QueueEmptyError):
                    logger_crawler.warning("Signal None reçu, queue vide !")
                elif isinstance(e, asyncio.TimeoutError):
                    logger_crawler.warning(f"Timeout join atteint timeout={self.config.JOIN_TIMEOUT}")
                else:
                    logger_crawler.warning("Queue vide !")
                logger_crawler.info(f"{len(visited)} urls visités")
                # traceback.print_exc()
                while not queue.empty():
                    try:
                        queue.get_nowait()
                        queue.task_done()
                    except asyncio.QueueEmpty:
                        break
                    
            except Exception as e:
                logger_crawler.error(f"Erreur pour join : {e}")
                if self.config.DEBUG:
                    logger_crawler.error(traceback.format_exc())
                    
            finally:
                self.stop_task(tasks)
                if pending:
                    self.stop_task(pending)
                    await asyncio.gather(*pending, return_exceptions=True)
                for _ in range(self.config.MAX_WORKERS):
                    await queue.put(None)
                await asyncio.gather(*tasks, return_exceptions=True)
            
            try:
                monitor_task.cancel()
            except Exception:
                pass
            
            elapsed = float(f"{time.time() - start_time :.2f}")
            await self._compute_stats(result, elapsed)
            await self.save_worker(url, visited, result)
            
        except Exception as e:
            logger_crawler.error(f"Erreur dans crawl : {e}")
            result.error = str(e)
            if self.config.DEBUG:
                logger_crawler.error(traceback.format_exc())
        
        for link in self.counts:
            logger_crawler.info("\n" + "=" * 10 + f" {link} " + "="*10)
            for k in self.counts[link]:
                logger_crawler.info(f"Worker {k} {self.counts[link][k]} url traitées")
        
        if result.stats.get("speed") is not None:
            logger_crawler.info(f"Vitesse de crawl : {result.stats.get('speed')} pages par seconde")
        # for a in result.result:
        #     print(a.url, a.source_url)
        return result
    
    async def multi_crawl(self, list_url:list, restore:bool=False, use_playwright: bool = False):
        """
        Comme crawl mais pour plusieurs sites en parallèle.

        Parameters
        ----------
        list_url : list
            List des url.
        restore : bool, optional
            Détermine si il faut restorer le cache pour continuer le crawl. The default is False.

        Returns
        -------
        dict
            dictionnaire url, result : CrawlerResult.

        """
        tasks = [
                asyncio.create_task(self.crawl(url=url, restore=restore, use_playwright=use_playwright))
                for url in list_url
            ]
        result = await asyncio.gather(*tasks, return_exceptions=True)
        return dict(zip(list_url, result))
    
    async def test(
        self, 
        url=None, 
        restore: bool = False,
        helpers: Optional[List[callable]] = None,
        raise_on_helper_error: bool = True
    ):
        """
        Méthode de test du crawler
        
        Parameters
        ----------
        url : str or list, optional
            URL ou liste d'URLs à tester
        restore : bool, optional
            Restaurer depuis le cache
        helpers : list, optional
            Liste de helpers à exécuter avant le crawl
            Format: [[func, args, kwargs], ...]
        raise_on_helper_error : bool, optional
            Lever une exception si un helper échoue
        """
        default_urls = [
            "https://quotes.toscrape.com/",
            "https://books.toscrape.com/",
        ]
        
        if url is None:
            urls_to_test = default_urls
            mode = "MULTI (défaut)"
        elif isinstance(url, str):
            urls_to_test = [url]
            mode = "SIMPLE"
        elif isinstance(url, (list, set, tuple)):
            urls_to_test = list(url)
            mode = "MULTI"
        else:
            raise TypeError(f"Type invalide: {type(url)}")
        
        self.session = await self.create_session(None)
        logger_crawler.info("\n" + "="*60)
        logger_crawler.info(f"MODE TEST: {mode} - {len(urls_to_test)} URL(s)")
        if helpers:
            logger_crawler.info(f"🔐 Avec helpers: {len(helpers)} helper(s)")
        logger_crawler.info("="*60)
        
        original_config = {
            'DEBUG': self.config.DEBUG,
            'MAX_PAGES': self.config.MAX_PAGES,
            'MAX_DEEPTH': self.config.MAX_DEEPTH,
        }
        
        self.config.DEBUG = True
        self.config.MAX_PAGES = 20
        self.config.MAX_DEEPTH = 2
        
        try:
            if len(urls_to_test) == 1:
                test_url = urls_to_test[0]
                logger_crawler.info(f"\n📌 Crawl simple de: {test_url}")
                result = await self.crawl(
                    test_url, 
                    restore=restore,
                    helpers=helpers,
                    raise_on_helper_error=raise_on_helper_error
                )
                return {
                    test_url: {
                        'success': result.error is None,
                        'error': result.error,
                        'pages': len(result.result),
                        'result': result
                    }
                }
            else:
                logger_crawler.info(f"\n📌 Multi-crawl de {len(urls_to_test)} URLs")
                results = await self.multi_crawl(urls_to_test, restore=restore)
                formatted = {}
                for url, result in results.items():
                    if isinstance(result, Exception):
                        formatted[url] = {
                            'success': False,
                            'error': str(result),
                            'pages': 0
                        }
                    else:
                        formatted[url] = {
                            'success': result.error is None,
                            'error': result.error,
                            'pages': len(result.result),
                            'result': result
                        }
                return formatted
        finally:
            for key, value in original_config.items():
                setattr(self.config, key, value)


async def test_crawl_detailed(
    restore: bool = False, 
    helpers: Optional[List[callable]] = None,
    raise_on_helper_error: bool = True
):
    """
    Test détaillé du crawler avec support des helpers
    """
    logger_crawler.info("\n" + "🔥"*40)
    logger_crawler.info("🔥 TEST CRAWLER - MODE DÉTAILLÉ")
    logger_crawler.info("🔥"*40)
    
    connector = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=60)
    session = aiohttp.ClientSession(connector=connector)
    crawler = Crawler(session)
    crawler.config.RESTRAIN_FOR_THIS_DOMAIN = True
    try:
        test_urls = {
            "test_local": {
                "name": "TEST Local", 
                "urls": "http://localhost:8080", 
                "mode": "simple",
                "helpers": helpers,
                "raise_on_helper_error": raise_on_helper_error
            }
        }
        
        all_results = {}
        
        for test_id, test_info in test_urls.items():
            logger_crawler.info(f"\n{'─'*70}")
            logger_crawler.info(f"🧪 {test_info['name']} | Mode: {test_info['mode']}")
            logger_crawler.info(f"{'─'*70}")
            
            start_time = time.time()
            
            # Appliquer les helpers si présents
            if test_info.get('helpers'):
                logger_crawler.info(f"🔐 Avec helpers: {len(test_info['helpers'])} helper(s)")
            
            # Appeler crawl directement avec helpers
            result = await crawler.crawl(
                url=test_info['urls'],
                restore=restore,
                helpers=test_info.get('helpers'),
                raise_on_helper_error=test_info.get('raise_on_helper_error', True),
            )
            
            elapsed = time.time() - start_time
            
            logger_crawler.info(f"\n✅ Terminé en {elapsed:.2f}s")
            logger_crawler.info(f"📊 Résultat:")
            logger_crawler.info(f"   └─ Succès: {result.error is None}")
            logger_crawler.info(f"   └─ Pages: {len(result.result)}")
            if result.error:
                logger_crawler.info(f"   └─ Erreur: {result.error}")
            
            all_results[test_id] = {
                'info': test_info,
                'result': result,
                'elapsed': elapsed
            }
        
        # Rapport final
        logger_crawler.info("\n" + "★"*70)
        logger_crawler.info("★ RAPPORT FINAL")
        logger_crawler.info("★"*70)
        
        for test_id, data in all_results.items():
            logger_crawler.info(f"\n{data['info']['name']}:")
            logger_crawler.info(f"  ├─ Succès: {data['result'].error is None}")
            logger_crawler.info(f"  ├─ Pages: {len(data['result'].result)}")
            logger_crawler.info(f"  └─ Temps: {data['elapsed']:.2f}s")
        
        logger_crawler.info("\n" + "★"*70)
        return all_results
        
    finally:
        await crawler.close()
        await session.close()
        logger_crawler.info("\n🧹 Nettoyage terminé")


async def quick_test(helpers: Optional[List[callable]] = None, raise_on_helper_error: bool = True):
    """
    Test rapide du crawler avec support des helpers
    """
    test_urls = [
        "http://localhost:8080",
        "http://example.com",
        "https://httpbin.org/html",
    ]
    
    connector = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=60)
    session = aiohttp.ClientSession(connector=connector)
    crawler = Crawler(session)
    
    # Configurer pour un test rapide
    crawler.config.MAX_PAGES = 10
    crawler.config.MAX_DEEPTH = 2
    crawler.config.DEBUG = True
    
    logger_crawler.info("="*60)
    logger_crawler.info("TEST RAPIDE DU CRAWLER")
    logger_crawler.info("="*60)
    
    if helpers:
        logger_crawler.info(f"🔐 Avec helpers: {len(helpers)} helper(s)")
    
    try:
        for url in test_urls:
            logger_crawler.info(f"\n📌 Test de: {url}")
            result = await crawler.crawl(
                url=url, 
                restore=False,
                helpers=helpers,
                raise_on_helper_error=raise_on_helper_error
            )
            logger_crawler.info(f"   Pages: {len(result.result)}")
            logger_crawler.info(f"   Erreur: {result.error}")
        
        logger_crawler.info("\n✅ Tests terminés")
        
    finally:
        await crawler.close()
        await session.close()


if __name__ == "__main__":
    from scanner_ia.scanner_utils.helpers.dvwa_helpers import dvwa_full_setup
    
    URL = "http://localhost:8080"
    # Helper format: [func, args, kwargs]
    # session sera ajouté automatiquement
    helpers = [
        [dvwa_full_setup, (URL, "admin", "password", "low")]
    ]
    helpers=[{'name': 'dvwa_auth',      'kwargs': {'base_url': 'http://localhost:8080', 'password': 'password', 'username': 'admin'}}]
    # Test avec helpers
    asyncio.run(test_crawl_detailed(
        restore=False,
        helpers=helpers,
        raise_on_helper_error=True,
    ))
    
    # Ou test rapide
    # asyncio.run(quick_test(helpers=helpers, raise_on_helper_error=True))
    
    # Nettoyer le cache
    CACHE.delete("https://quotes.toscrape.com")