#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar  3 20:48:22 2026

@author: hounsousamuel
"""

import time
import json
import httpx
import aiohttp
import asyncio
import traceback
from urllib.parse import urlparse
from random import choice
from nest_asyncio import apply
from cachetools import TTLCache
from tenacity import wait_fixed, stop_after_attempt, RetryError, AsyncRetrying
from playwright.async_api import async_playwright
from scanner_ia.base_class.fetcher_base_class import FetcherResult
from scanner_ia.scanner_utils.logger import get_logger

logger_fetcher = get_logger()

CacheMaxSize = 1000
TTL = 10 * 60
MAX_ATTEMPT = 3
WAIT_BETWEEN = 3

class Config:
    HEADERS =  {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'fr-FR,fr;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    def __init__(self):
        self.MAX_REDIRECTS = 3
        self.Semaphore = 20
        self.TIMEOUT = 2
        self.DEBUG = False
        self.MAX_ATTEMPT = MAX_ATTEMPT
        self.WAIT_BETWEEN = WAIT_BETWEEN
    
CACHE = TTLCache(maxsize=CacheMaxSize, ttl=TTL)

# Cache séparé pour les méthodes HTTP autorisées par endpoint (via OPTIONS).
# Clé volontairement par path exact (scheme+host+path), pas par host global :
# deux endpoints du même site peuvent avoir des méthodes autorisées différentes.
METHODS_CACHE_TTL = 15 * 60
METHODS_CACHE = TTLCache(maxsize=5000, ttl=METHODS_CACHE_TTL)

class PlaywrightPool:
    _instance = None
    _browser = None
    _playwright = None
    _lock = asyncio.Lock()
    
    @classmethod
    async def get_browser(cls):
        async with cls._lock:
            if cls._browser is None:
                p = await async_playwright().start()
                cls._browser = await p.chromium.launch(headless=True)
                cls._playwright = p
            return cls._browser
    
    @classmethod
    async def close(cls):
        async with cls._lock:
            if cls._browser:
                if cls._browser:
                    await cls._browser.close()
                    
                if cls._playwright:
                    await cls._playwright.stop()
                    
                cls._browser = None
                cls._playwright = None
            
class Fetcher():
    """
    Classe de Fetch pour les requête web. Méthode supportée :
        GET, POST, HEAD.
    """
    def __init__(
            self, 
            session:aiohttp.ClientSession = None,
            max_redirects:int = None,
            headers:dict = None,
            semaphore:int = None,
            **kwargs
        ):
        self.session = session
        self.map = {
            "get": self._fetch_get,
            "post": self._fetch_post,
            "head": self._fetch_head,
            "playwrigth": self._playwright_fetch,
            }
        self._ip_cache = {}
        self.config = Config()
        self.update_conf(kwargs)
        self.headers = headers or self.config.HEADERS
        self.max_redirects = max_redirects or self.config.MAX_REDIRECTS
        self.semaphore = semaphore or self.config.Semaphore
        self._semaphore = asyncio.Semaphore(self.semaphore)
        self.backup_result = FetcherResult()

    def _get_semaphore(self, override: int = None) -> asyncio.Semaphore:
        """
        Sémaphore partagé par défaut (self._semaphore, créé une seule fois).
        Si un override explicite et différent de self.semaphore est demandé pour
        cet appel précis, on crée un sémaphore dédié pour respecter cette demande
        (throttling propre à cet appel, pas partagé — cas rare).
        """
        if override is None or override == self.semaphore:
            return self._semaphore
        return asyncio.Semaphore(override)
        
      
    async def create_session(self, session):
        return session or aiohttp.ClientSession()
    
    def update_conf(self, kwargs:dict = None):
        kwargs = kwargs or {}
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)
            elif hasattr(self.config, k.upper()):
                setattr(self.config, k.upper(), v)
    
    def _create_key(self, func, **kwargs):
        return f"{func.__name__}:{json.dumps(kwargs)}"
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            logger_fetcher.debug("Session fermée")
    
    async def get_allowed_methods(self, url: str, timeout: float = 3.0):
        """
        Interroge l'endpoint en OPTIONS pour connaître les méthodes qu'il supporte
        (header `Allow`). Retourne un set de méthodes (ex: {"GET", "HEAD"}), ou
        None si l'info n'a pas pu être obtenue de façon fiable — dans ce cas
        l'appelant doit se rabattre sur son comportement normal (tenter quand même).

        Ne fait AUCUNE confiance à un code de statut isolé (ex: 501) car trop
        de serveurs/WAF/proxys l'utilisent de façon incohérente. OPTIONS + header
        Allow est le seul signal qu'on traite comme fiable, et seulement si présent.
        """
        parsed = urlparse(url)
        cache_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        cached = METHODS_CACHE.get(cache_key)
        if cached is not None:
            return cached

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.options(url, headers=self.headers)
                allow_header = response.headers.get("Allow", "")

                if not allow_header:
                    logger_fetcher.debug(f"OPTIONS {url} -> pas de header Allow exploitable")
                    return None

                methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
                METHODS_CACHE[cache_key] = methods
                logger_fetcher.debug(f"OPTIONS {url} -> Allow: {methods}")
                return methods

        except Exception as e:
            logger_fetcher.debug(f"OPTIONS échoué pour {url} ({type(e).__name__}: {e}) -> fallback normal")
            return None

    async def should_skip_method(self, url: str, method: str) -> bool:
        """
        True seulement si on a une confirmation fiable (via OPTIONS) que la
        méthode n'est pas supportée. False dans tous les autres cas, y compris
        quand on n'a pas pu vérifier -> comportement par défaut inchangé.
        """
        allowed = await self.get_allowed_methods(url)
        if allowed is None:
            return False
        return method.upper() not in allowed
    
    async def _get_ip(self, url:str):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return None
            if self._ip_cache.get(hostname, None):
                return self._ip_cache.get(hostname)
            loop = asyncio.get_event_loop()
            ips = await loop.getaddrinfo(hostname, port=None, family=0, type=0, flags=0, proto=0)
            if ips:
                ip = ips[0][4][0]
                self._ip_cache[hostname] = ip
                return ip
        except Exception as e:
            logger_fetcher.debug(f"Erreur résolution IP pour {url}: {e}")
        return None
        
    async def _make_result(self, url:str, result, response:aiohttp.ClientResponse, method:str = "GET"):
        result.url = url
        result.final_url = str(response.url) or url
        result.status_code = int(response.status)
        result.headers = dict(response.headers)
        result.body = await response.text()
        result.cookies = [
            {"key": k, "value": v.value, "attributes": dict(v.items())}
            for k, v in response.cookies.items()
        ]
        result.history = [
            {"url": str(r.url), "status_code": r.status}
            for r in response.history
        ]
        result.ip = await self._get_ip(result.url)
        return result
    
    async def _fetch_get(
        self, 
        url:str, 
        session:aiohttp.ClientSession,
        timeout:int = 2,  
        params:dict = {},
        headers:dict = {},
        cookies:dict = {},
        semaphore:int = None,
        **kwargs
    ):
        headers = headers or self.headers
        timeout = aiohttp.ClientTimeout(timeout or self.config.TIMEOUT)
        if not url.startswith("http"):
            url = "https://" + url
        key = self._create_key(self._fetch_get, **{"url": url, "params": params, "headers": headers, "cookies": cookies})
        cached_result = CACHE.get(key)
        if cached_result:
            logger_fetcher.debug(f"Cache hit Fetch pour {url}")
            return cached_result

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.config.MAX_ATTEMPT),
            wait=wait_fixed(self.config.WAIT_BETWEEN),
        ):
            with attempt:
                SEMAPHORE = self._get_semaphore(semaphore)
                result = FetcherResult()
                start_time = time.time()
                logger_fetcher.debug(f"Début fetching GET url = {url}")
                async with SEMAPHORE:
                    try:
                        async with session.get(
                            url=url, 
                            params=params, 
                            cookies=cookies,
                            headers=self.headers,
                            allow_redirects=True,
                            max_redirects=self.max_redirects,
                        ) as response:
                            result = await self._make_result(url, response=response, result=result, method="GET")
                            result.delay = float(f"{time.time() - start_time:.2f}")
                            if str(response.status).startswith("2") or str(response.status) in ("404", "410", "403", "301", "302"):
                                CACHE[key] = result
                            logger_fetcher.debug(f"GET {url} -> {response.status} en {result.delay}s")
                            return result
                            
                    except Exception as e:
                        result.error = str(e)
                        result.delay = float(f"{time.time() - start_time:.2f}")
                        self.backup_result = result
                        logger_fetcher.warning(f"Échec GET {url} ({type(e).__name__}), {str(e)}")
                        raise
                
    
    async def _fetch_post(
        self, 
        url:str, 
        session:aiohttp.ClientSession,
        timeout:int = 10,  
        params:dict = {},
        headers:dict = {},
        cookies:dict = {},
        semaphore:int = None,
        json:dict = {},
        data:dict = {},
        **kwargs
    ):
        headers = headers or self.headers
        timeout = aiohttp.ClientTimeout(timeout or self.config.TIMEOUT)
        if not url.startswith("http"):
            url = "https://" + url
        key = self._create_key(self._fetch_get, **{"url": url, "params": params, "headers": headers, "cookies": cookies, "json":json})
        cached_result = CACHE.get(key)
        if cached_result:
            logger_fetcher.debug(f"Cache hit Fetch pour POST {url}")
            return cached_result

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.config.MAX_ATTEMPT),
            wait=wait_fixed(self.config.WAIT_BETWEEN),
        ):
            with attempt:
                SEMAPHORE = self._get_semaphore(semaphore)
                result = FetcherResult()
                start_time = time.time()
                logger_fetcher.debug(f"Début fetching POST url = {url}")
                async with SEMAPHORE:
                    try:
                        body_kwargs = {}
                        if json:
                            body_kwargs["json"] = json
                        elif data:
                            body_kwargs["data"] = data
                        
                        async with session.post(
                            url=url,
                            params=params,
                            cookies=cookies,
                            headers=self.headers,
                            allow_redirects=True,
                            max_redirects=self.max_redirects,
                            **body_kwargs
                        ) as response:
                            result = await self._make_result(url, response=response, result=result, method="POST")
                            result.delay = float(f"{time.time() - start_time:.2f}")
                            if str(response.status).startswith("2") or str(response.status) in ("404", "410", "403", "301", "302"):
                                CACHE[key] = result
                            return result
                            
                    except Exception as e:
                        result.error = str(e)
                        result.delay = float(f"{time.time() - start_time:.2f}")
                        self.backup_result = result
                        logger_fetcher.warning(f"Échec POST {url} ({type(e).__name__}), {str(e)}")
                        raise
                       
    async def _fetch_head(
        self, 
        url:str, 
        session:aiohttp.ClientSession,
        timeout:int = 10,  
        headers:dict = {},
        semaphore:int = None,
        **kwargs
    ):
        headers = headers or self.headers
        timeout = aiohttp.ClientTimeout(timeout or self.config.TIMEOUT)
        if not url.startswith("http"):
            url = "https://" + url
        key = self._create_key(self._fetch_get, **{"url": url, "headers": headers})
        cached_result = CACHE.get(key)
        if cached_result:
            logger_fetcher.debug(f"Cache hit Fetch pour HEAD {url}")
            return cached_result

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.config.MAX_ATTEMPT),
            wait=wait_fixed(self.config.WAIT_BETWEEN),
        ):
            with attempt:
                SEMAPHORE = self._get_semaphore(semaphore)
                result = FetcherResult()
                start_time = time.time()
                logger_fetcher.debug(f"Début fetching HEAD url = {url}")
                async with SEMAPHORE:
                    try:
                        async with session.head(
                            url=url, 
                            headers=self.headers,
                        ) as response:
                            result = await self._make_result(url, response=response, result=result, method="HEAD")
                            result.delay = float(f"{time.time() - start_time:.2f}")
                            if str(response.status).startswith("2") or str(response.status) in ("404", "410", "403", "301", "302"):
                                CACHE[key] = result
                            logger_fetcher.debug(f"HEAD {url} -> {response.status} en {result.delay}s")
                            return result
                            
                    except Exception as e:
                        result.error = str(e)
                        result.delay = float(f"{time.time() - start_time:.2f}")
                        self.backup_result = result
                        logger_fetcher.warning(f"Échec HEAD {url} ({type(e).__name__}), {str(e)}")
                        raise
    
    async def _playwright_fetch(
        self,
        url: str,
        session: aiohttp.ClientSession = None, 
        timeout: int = 15,
        **kwargs
    ) -> FetcherResult:
        """
        Fetch via Playwright — exécute le JS et retourne le HTML rendu.
        Retourne un FetcherResult compatible avec les autres fetch methods.
        """
        
        result = FetcherResult()
        start_time = time.time()
        
        key = self._create_key(self._playwright_fetch, **{"url": url})
        cached = CACHE.get(key)
        if cached:
            logger_fetcher.debug(f"Cache hit Fetch playwright pour {url}")
            return cached
        
        logger_fetcher.debug(f"Début playwright fetch url = {url}")
        page = None
        try:
            browser = await PlaywrightPool.get_browser()
            page = await browser.new_page()
            
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=(timeout or self.config.TIMEOUT) * 1000  # playwright en ms
            )
            result.headers = response.headers
            result.status_code = response.status if response else 0
            result.body = await page.content()
            result.url = url
            result.delay = float(f"{time.time() - start_time:.2f}")
            
            if response.ok:
                CACHE[key] = result
            
            logger_fetcher.debug(f"Playwright {url} -> {result.status_code} en {result.delay}s")
            return result
        
        except Exception as e:
            result.error = str(e)
            result.delay = float(f"{time.time() - start_time:.2f}")
            logger_fetcher.warning(f"Échec playwright fetch {url} ({type(e).__name__}): {e}")
            return result
        
        finally:
            (await page.close()) if page else None
    
    async def fetch(self, url:str, method:str = "GET", *args, **kwargs):
        try:
            method = method.lower()
            func = self.map.get(method, self._fetch_get)
            logger_fetcher.debug(f"Fetch {method.upper()} {url}")
            return await func(url, session=self.session, *args, **kwargs)
        
        except RetryError as e:
            logger_fetcher.warning(f"Max essai de fetch atteint, erreur : {str(e)}")
            logger_fetcher.warning(f"Max attempts : {e.last_attempt.attempt_number}")
            if self.config.DEBUG:
                logger_fetcher.error(traceback.format_exc())
                self.backup_result.error = 'RetryError'
            return self.backup_result
        
        except Exception as e:
            logger_fetcher.error(f"Erreur fetch {url}: {type(e).__name__}, erreur: {str(e)}")
            if self.config.DEBUG:
                logger_fetcher.error(traceback.format_exc())
            return self.backup_result
        
    
    async def fetch_once(
        self,
        url: str,
        timeout: int = 3,
        method: str = "GET",
        headers: dict = {},
        params: dict = {},
        cookies: dict = {},
        max_attempts: int = 1,
        wait_between: float = 0.0,
        **kwargs
    ) -> FetcherResult:
        """
        Fetch avec nombre de tentatives configurable — boucle manuelle sans tenacity.
        Défaut : 1 essai, pas d'attente → comportement "fetch_once" pour robots.txt etc.
        Flexible : max_attempts=3, wait_between=2.0 pour simuler le comportement de fetch().
        """
        result = FetcherResult()
        start_time = time.time()
    
        if not url.startswith("http"):
            url = "https://" + url
    
        key = self._create_key(self._fetch_get, **{"url": url, "params": params})
        cached = CACHE.get(key)
        if cached:
            logger_fetcher.debug(f"Cache hit fetch_once pour {url}")
            return cached
    
        _timeout = aiohttp.ClientTimeout(total=timeout)
        _headers = headers or self.headers
        _method  = getattr(self.session, method.lower(), self.session.get)
    
        for attempt in range(1, max_attempts + 1):
            result = FetcherResult()
            try:
                async with _method(
                    url,
                    headers         = _headers,
                    params          = params,
                    cookies         = cookies,
                    timeout         = _timeout,
                    allow_redirects = True,
                    max_redirects   = self.max_redirects,
                ) as response:
                    result = await self._make_result(url, result=result, response=response)
                    result.delay = round(time.time() - start_time, 2)
                    logger_fetcher.debug(
                        f"fetch_once {method.upper()} {url} "
                        f"→ {response.status} en {result.delay}s "
                        f"(essai {attempt}/{max_attempts})"
                    )
                    if str(response.status).startswith("2") or \
                       str(response.status) in ("404", "410", "403", "301", "302"):
                        CACHE[key] = result
                    return result  
    
            except Exception as e:
                result.error = str(e)
                result.delay = round(time.time() - start_time, 2)
                logger_fetcher.debug(
                    f"fetch_once échec {url} ({type(e).__name__}): "
                    f"{str(e)[:60]} (essai {attempt}/{max_attempts})"
                )
                if attempt < max_attempts and wait_between > 0:
                    await asyncio.sleep(wait_between)
    
        return result

    async def test(self, method:str = "GET"):
        logger_fetcher.info("=" * 80)
        logger_fetcher.info("TEST")
        logger_fetcher.info("=" * 80)
        urls = [
            'https://quotes.toscrape.com/',
            'https://books.toscrape.com/',
            'https://httpbin.org/',
            'https://jsonplaceholder.typicode.com/',
            'https://www.google.com',
            'http://www.example.com',
            'https://www.wikipedia.org',
            'https://httpbin.org/status/404',
            'https://invalid-url-that-does-not-exist.com'
        ]
        url = choice(urls)
        url = "http://localhost:5050/comments/cmdi-ping_host_shell_true"
        
        logger_fetcher.info(f"Test sur {url}")
        self.session = await self.create_session(None)
        result = await self.fetch(url, method=method.upper())
        print(result.body_length())
        logger_fetcher.success(f"Résultat: {result.status_code} - {result.error}")
        logger_fetcher.info("=" * 80)
        logger_fetcher.info("FIN DES TESTS")
        logger_fetcher.info("=" * 80)
        await self.close()
                
if __name__ == "__main__":
    apply()
    f = Fetcher()
    asyncio.run(f.test())