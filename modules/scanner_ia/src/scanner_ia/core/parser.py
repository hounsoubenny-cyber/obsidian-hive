#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 00:53:06 2026

@author: hounsousamuel
"""

import os
import re
import time
import asyncio
import aiohttp
import tldextract
import atexit
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag, parse_qs
from urllib import robotparser
from diskcache import Cache
from lxml import html, etree
from scanner_ia.core.fetcher import Fetcher, FetcherResult
from datetime import datetime
from scanner_ia.base_class.parser_base_class import (
    ParserResult, ClassifyLinkResult, GetAllLinkResult, 
    ParseElementResult, ParseResult
)
from scanner_ia.core.core_config import (
    EXTENSIONS_BY_CATEGORY, CONTENT_TYPE_BY_CATEGORY, TESTS_NORMALIZE, USER_AGENT
)
from modules_utils.keyed_lock import KeyedLock
from scanner_ia.scanner_utils.signal_manager import signal_manager
from nest_asyncio import apply
from scanner_ia.scanner_utils.logger import get_logger

logger_parser = get_logger()

dir_ = os.path.dirname(os.path.abspath(__file__))
s = os.path.join(dir_, "var", "parser_cache")
os.makedirs(s,exist_ok=True)

MAX_CACHE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CACHE = Cache(
    directory=s, 
    size_limit=MAX_CACHE_SIZE, 
    cull_limit=40, 
    statistics=True,
    cull_frequency=5
)
CACHE_TIMEOUT = 24 *3600

LOCK = KeyedLock()
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
    # DEBUG = True
    def __init__(self):
        self.DEBUG = True

class Parser:
    """
    Classe de parsing rapide et aasynchrone, intègre un fetcher.
    """
    def __init__(self, session:aiohttp.ClientSession, **kwargs):
        """
        
        Parameters
        ----------
        session : aiohttp.ClientSession
            ClientSession aiohttp.
        **kwargs : dict
            Utiliser pour mettre à jour les config pour le Fetcher.
            Voilà quelque uns:
                Semaphore: Limitation concurente.
                MAX_REDIRECTS: Nombre max de redirections à suivre.
                TTL: Durée de validité des éléments mis en cache pour le fetcher.
                MAX_ATTEMPT: Nombre de réessaie si fetch échoue.
                WAIT_BETWEEN: Durée d'attente entre retry pour le fetcher.

        Returns
        -------
        None.

        """
        self.parse_html_key = "parse_html_cache"
        self.classify_link_key = "classify_link_cache"
        self.robot_allow_key = "robot_allow_cache"
        self.get_all_links_key = "get_all_link_cache"
        self.parse_key = "parse_cache"
        self.keys = [
            self.parse_html_key,
            self.classify_link_key,
            self.robot_allow_key,
            self.get_all_links_key,
            self.parse_key
        ]
        self.__parser = html.HTMLParser(
            remove_comments=False,
            remove_pis=False,
            remove_blank_text=False,
        )
        self.session = session
        self.fetcher = Fetcher(session=self.session, **kwargs)
        self._init_cache()
        self.config = Config()
        self.update_conf(kwargs)
        
    def _init_cache(self):
        for k in self.keys:
            if k not in CACHE:
                CACHE.set(k, {}, expire=CACHE_TIMEOUT)
    
    async def create_session(self, session):
        return session or aiohttp.ClientSession()

    def update_conf(self, kwargs: dict = None):
        kwargs = kwargs or {}
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)
            elif hasattr(self.config, k.upper()):
                setattr(self.config, k.upper(), v)
    
    async def close(self):
        """Fermer les sessions"""
        if self.session and not self.session.closed:
            await self.session.close()
            
    async def parse_html(
        self, 
        url_or_body:str,
        response:bool = False, 
        is_body: bool = False, 
        use_playwright: bool = False,
        use_cache: bool = True,
    ) -> ParserResult:
        """
        Méthode de parsing du html.
        
        Parameters
        ----------
        url_or_body : str
            Url ou body html, base pour donner le tree lxml.
        response : bool, optional
            Détermine si il faut aussi envoyer la sortie du fetcher. The default is False.
        is_body: bool, default = False
            Indique directement que c'est un body html.
        use_playwrigth: bool, default = False
            Indique si il faut use playwright pour le fetch

        Returns
        -------
        ParserResult
            Résultat de parse_html.

        """
        result = ParserResult()
        if not url_or_body:
            return result
        
        if isinstance(url_or_body, bytes):
            result.tree = html.fromstring(url_or_body, parser=self.__parser)
            return result
        
        url_or_body = str(url_or_body)
        if not url_or_body.startswith("http") or is_body:
            result.tree = html.fromstring(url_or_body, parser=self.__parser)
            return result
        
        # Donc url
        method = "PLAYWRIGTH" if use_playwright else "GET"
        cache = CACHE.get(self.parse_html_key, {})
        if use_cache and cache.get(url_or_body, None):
            result.tree = html.fromstring(cache[url_or_body], parser=self.__parser)
            if not response:
                return result
            
            r = await self.fetcher.fetch(
                url=url_or_body,
                method=method
            )
            result.response = r
            return result
        
        else:
            r = await self.fetcher.fetch(
                url=url_or_body,
                method=method
            )
            if response:
                result.response = r
            
            if r:
                if r.body:
                    result.tree = html.fromstring(r.body, parser=self.__parser)
                    cache[url_or_body] = r.body
                    CACHE.set(self.parse_html_key, cache, expire=CACHE_TIMEOUT)
                    return result
            
                else:
                    logger_parser.debug(f"Body vide pour {url_or_body}")
                    result.tree = html.fromstring("<body> Vide! </body>")
                    return result
            else:
                logger_parser.warning(f"Fetcher a echouer, url={url_or_body} inatteignable !")
                return result
    
    @classmethod
    def normalize_link(self, base_url:str, url:str):
        """
        Méthode de normalisation des liens.

        Parameters
        ----------
        base_url : str
            Url de base.
        url : str
            Url a ajoutéz.

        Returns
        -------
        None | str
            None si échec et str si succès.

        """
        if not base_url or url is None:
            return None
        
        url = url.strip()
        base_url = base_url.strip()    
        if base_url.startswith("#"):
            return None
        
        if url.startswith("#"):
            return urldefrag(base_url)[0]
    
        if url.startswith("http"):
            return url
        
        if any(x.startswith(('javascript:', 'data:', 'mailto:', 'blob:', 'tel:')) for x in (url, base_url)):
            return None
        
        url_parse = urlparse(url)
        base_url_parse = urlparse(urldefrag(base_url)[0])
        
        if url_parse.scheme and url_parse.netloc:
            return url
        
        if url.startswith("//"):
            return base_url_parse.scheme + ':' + url
        
        if not base_url_parse.scheme and base_url_parse.netloc:
            return None
        
        
        final_url = urljoin(urlunparse(base_url_parse), urlunparse(url_parse))
        return urldefrag(final_url)[0]
        

    def test_normalize_link(self, advanced=False):
        test_cases = [
            # (base, lien, résultat_attendu)
            ("https://example.com/page", "#section", "https://example.com/page"),
            ("https://example.com/page", "other.html", "https://example.com/other.html"),
            ("https://example.com/blog/", "../images/pic.jpg", "https://example.com/images/pic.jpg"),
            ("https://example.com", "//cdn.com/image.jpg", "https://cdn.com/image.jpg"),
            ("https://example.com", "javascript:alert(1)", None),
        ]
        if advanced:
            test_cases = TESTS_NORMALIZE
        ns = 0
        for base, lien, result in test_cases:
            r = self.normalize_link(base, lien)
            s = r == result
            ns += int(s)
            logger_parser.debug(f"{base} + {lien} ---> attendu={result}, resultat={r}, succès={s}")
        
        logger_parser.info(f"Total {ns}/{len(test_cases)} tests réussis")
        
    async def classify_link(self, url:str, fetch_external: bool = True, base_url: str = None, use_cache: bool = True):
        """
        Méthode de classification des liens en fonction des extensions et/ou du type MIME

        Parameters
        ----------
        url : str
            Url à classée.
        fetch_external : bool, optional
            Si False, ne fait pas de requête HTTP pour les domaines externes (défaut: True)
        base_url : str, optional
            URL de base pour vérifier le même domaine (utilisé si fetch_external=False)

        Returns
        -------
        result : ClassifyLinkResult
            Résultat de la classification.
        """
        result = ClassifyLinkResult()
        try:
            url = url.strip()
            url = self.normalize_link(url, "")
            if not url:
                result.url = None
                return result
        
            result.url = url
            path = urlparse(url).path
            ext = os.path.splitext(path)[-1]
            cache = CACHE.get(self.classify_link_key, {})
            if use_cache and cache.get(url, {}):
                result.update_from_dict(cache.get(url))
                logger_parser.debug(f"Cache hit classify_link pour {url}")
                return result
            
            if not fetch_external and base_url:
                if not self.is_same_domain(base_url, url):
                    # Domaine externe → on ne fait pas de requête
                    result.type = "other"
                    logger_parser.debug(f"Classify_link (skip external): {url} -> other")
                    return result
                
            if ext:
                for k, v in EXTENSIONS_BY_CATEGORY.items():
                    if ext in v:
                        result.type = k.lower().strip()
                        if k.lower().strip() != "other":
                            cache[url] = result.to_dict()
                            CACHE.set(self.classify_link_key, cache, CACHE_TIMEOUT)
                            # if self.config.DEBUG:
                            # logger_parser.debug(f"Classé {url} comme {result.type} (extension)")
                        return result
            else:
                r = await self.fetcher.fetch(
                    url,
                    method="GET",
                )
                headers = r.headers
                headers = {str(k).lower():v for k, v in headers.items()}
                ct = headers.get("content-type", None)
                if not ct:
                    return result
                else:
                    ct = str(ct).split(";")[0]
                    for k, v in CONTENT_TYPE_BY_CATEGORY.items():
                        if ct in v or any (ct in x for x in v):
                            result.type = k.lower().strip()
                            if k.lower().strip() != "other":
                                cache[url] = result.to_dict()
                                CACHE.set(self.classify_link_key, cache, CACHE_TIMEOUT)
                                # if self.config.DEBUG:
                                # logger_parser.debug(f"Classé {url} comme {result.type} (content-type)")
                            return result
                        
                # Si c'est toujours pas Html et pas d'extension asssumons que c'est html
                if result.type == "other":
                    result.type = "html"
            CACHE.set(self.classify_link_key, cache, CACHE_TIMEOUT)
            return result
        except Exception as e:
            logger_parser.error(f"Erreur dans classify_link pour {url}: {e}")
            return result
    
    @classmethod
    def get_domain(self, url:str):
        """
        Méthode pour extraire le domaine.

        Parameters
        ----------
        url : str
            Url à traitée.

        Returns
        -------
        str
            Domaine du lien.

        """
        
        url = url.strip().strip("'\",;").strip()
        if not url.startswith(('http://', 'https://')):
            if url.startswith(':/'):
                url = 'https' + url
            else:
                url = 'https://' + url
                
        parse = urlparse(url)
        extracted = tldextract.extract(url)
        hostname = parse.hostname or ""
        
        if hostname and all(c.isdigit() for c in hostname if c not in ":."):
            return hostname  # IP address
        
        domain = f"{extracted.domain}{('.' + extracted.suffix) if extracted.suffix else ''}"
        return domain or None
    
    @classmethod
    def is_same_domain(self, url1:str, url2:str):
        if any(not x for x in (url1, url2)):
            return False
        domain1 = self.get_domain(url1)
        domain2 = self.get_domain(url2)
        # print(url1, url2, domain1, domain2, domain1 == domain2)
        # trusted = ('0.0.0.0', "127.0.0.1", "127.0.0.0", "localhost")
        # if any(c in domain1 for c in trusted) and any(c in domain2 for c in trusted):
        #     return True 
        return domain1 == domain2 if all(c is not None for c in (domain1, domain2)) else False
   
    async def robot_allow(self, url:str, agent=USER_AGENT, use_cache: bool = True):
        """
        Méthode pour verifié si les robots sont autorisés.

        Parameters
        ----------
        url : str
            Url à vérifiée.
        agent : str, optional
            Agent à donné. The default is USER_AGENT.

        Returns
        -------
        bool
            True/False.

        """
        try:
            domain = self.get_domain(url)
            trusted = ('0.0.0.0', "127.0.0.1", "127.0.0.0", "localhost")
            if any(c in domain for c in trusted) :
                return True
            url = self.normalize_link(url, "")
            if not url:
                return True
            
            parse = urlparse(url)
            schemes = [parse.scheme, "http" if parse.scheme == "https" else "https"]
            
            cache = CACHE.get(self.robot_allow_key, {})
            if use_cache and cache.get(domain, None) is not None:
                logger_parser.debug(f"Cache hit robot_allow pour {url}")
                return cache.get(domain)
            
            rp = robotparser.RobotFileParser()
            body = None
            async with LOCK.acquire(f"parser:{domain}"):
                for scheme in schemes:
                    robot_url = f"{scheme}://{domain}/robots.txt"
                    r = await self.fetcher.fetch_once(
                        url=robot_url, timeout=2, max_attempts=1, wait_between=0, # timeout=0.005
                    )
                    if r:
                        if not r.error and r.body:
                            body = r.body
                            break
                
                can = True
                if body:
                    rp.parse(str(body).splitlines())
                    can = rp.can_fetch(agent, url)
                    # logger_parser.debug(f"robot_allow pour {url}: {can}")
            
            cache[domain] = can
            CACHE.set(self.robot_allow_key, cache, expire=CACHE_TIMEOUT)
            return can
        except Exception as e:
            logger_parser.error(f"Erreur dans robot_allow : {e}")
            return True
        
    async def get_all_links(
        self, url:str, 
        semaphore:int = 50, 
        skip_external_links:bool = True,
        use_playwright: bool = False,
        use_cache: bool = True,
    ):
        """
        Méthode pour extraire les liens.

        Parameters
        ----------
        url : str
            Url à traitée.
        semaphore : int, optional
            Limitation concurrente. The default is 50.
        skip_external_links : bool, optional
            Skipper classification des urls externes. The default is True
        use_playwright: bool, default is False
            Dtermine l'utilisation de playwright pour le crawl.
        
        Returns
        -------
        result : GetAllLinkResult
            Résultat contenant les urls trouvées.

        """
        try:
            result = GetAllLinkResult()
            url = self.normalize_link(url, "")
            if not url:
                result.error = "Lien invalide"
                return result
            
            cache = CACHE.get(self.get_all_links_key, {})
            if use_cache and cache.get(url, {}):
                result.update_from_dict(cache[url])
                logger_parser.debug(f"Cache hit get_all_links pour {url}")
                return result
            
            parse = urlparse(url)
            classify_link_response = await self.classify_link(url, use_cache=use_cache)
            result.type = classify_link_response.type
            # print(f"Clasify Response: {classify_link_response.to_dict()}")
            
            ACCEPTED_TYPES = ("html", "json", "xml", "text", "other")
            if result.type.lower() not in ACCEPTED_TYPES or not parse.scheme.startswith("http"):
                result.error = "Lien non supporté, scheme=" + parse.scheme + ",type=" + classify_link_response.type
                return result
            
            parse_html_response = await self.parse_html(url, response=True, use_playwright=use_playwright, use_cache=use_cache)
            
            # print(parse_html_response.to_dict())
            if not (parse_html_response.response and not str(parse_html_response.response.error).lower() == "retryerror"):
                return result
            
            tree = parse_html_response.tree
            # print(tree)
            result.status_code = parse_html_response.response.status_code
            if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                result.error = "Tree invalide (type=" + type(tree).__name__ + ") !"
                return result
            
            async def process_link(link:str, semaphore=50):
                async with asyncio.Semaphore(semaphore):
                    if skip_external_links:
                        classify = await self.classify_link(link, fetch_external=False, base_url=url, use_cache=use_cache)
                    else:
                        classify = await self.classify_link(link, fetch_external=True, use_cache=use_cache)
                    data = {
                        }
                    data["url"] = link
                    data["type"] = classify.type
                    data["same_domain"] = self.is_same_domain(url, link)
                    data["source_url"] = url
                    data["deep"] = None
                    try:
                        data["robot_allow"] = await asyncio.wait_for(self.robot_allow(link, use_cache=use_cache), timeout=0.3)
                    except Exception:
                        data["robot_allow"] = True
                    data["params"] = parse_qs(urlparse(link).query)
                    if classify.type == "html":
                        result.html_links[link] = data
                    else:
                        result.other_links[link] = data
                    
                    result.all_links[link] = data
                
            links = tree.xpath("//@href | //@src | //@action | //@cite") or []
            pings = tree.xpath("//@ping") or []
            data = tree.xpath("//@*[starts-with(name(), 'data-') and (contains(name(), 'url') or contains(name(), 'src') or contains(name(), 'href'))]") or []
            meta = tree.xpath("//meta[@http-equiv]/@content") or []  #<meta http-equiv="refresh" content="5; url=https://example.com/nouvelle-page"> ou <meta http-equiv="refresh" content="https://example.com/nouvelle-page">
            scrsets = tree.xpath("//@srcset")  or [] # Format <img srcset="small.jpg 300w, medium.jpg 600w, large.jpg 900w">
            tasks = []
            # print("links:", links)
            # print("pings:", pings)
            # print("data:", data)
            # print("meta:", meta)
            # print("scrsets:", scrsets)
            for link in links:
                full_url = self.normalize_link(url, link)
                if full_url:
                    task = asyncio.create_task(
                        process_link(full_url, semaphore=semaphore)
                        )
                    tasks.append(task)
            
            for link in data:
                parts = link.split(",")
                for part in parts:
                    if not part:
                        continue
                    
                    l = part.split()[0].strip()
                    full_url = self.normalize_link(url, l)
                    if full_url:
                        task = asyncio.create_task(
                            process_link(full_url, semaphore=semaphore)
                            )
                        tasks.append(task)
                
            for link in scrsets:
                parts = link.split(",")
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    
                    l = part.split()[0].strip()
                    full_url = self.normalize_link(url, l)
                    if full_url:
                        task = asyncio.create_task(
                            process_link(full_url, semaphore=semaphore)
                            )
                        tasks.append(task)
            
            for link in pings:
                ls = link.split(" ")
                for l in ls:
                    l = l.strip()
                    full_url = self.normalize_link(url, l)
                    if full_url:
                        task = asyncio.create_task(
                            process_link(full_url, semaphore=semaphore)
                            )
                        tasks.append(task)
            
            for link in meta:
                link = link.split(";")
                for l in link:
                    if "url=" in l or l.startswith("http"):
                        l = l.strip().split("url=")[-1]
                        full_url = self.normalize_link(url, l)
                        if full_url:
                            task = asyncio.create_task(
                                process_link(full_url, semaphore=semaphore)
                                )
                            tasks.append(task)
                        break
            # if tasks:
            answer = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(answer):
                if isinstance(r, Exception):
                    logger_parser.error(f"Tâche {i} exception: {r}")

            result.status = len(result.all_links) == (len(result.html_links) + len(result.other_links))
            result.stats = {
                'all_link': len(result.all_links),
                'html': len(result.html_links),
                'others': len(result.other_links),
                'datetime': datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
                'status': 'Traité avec succès' if result.status else 'Pas bien traité'
                }
            if result.status:
                cache[url] = result.to_dict()
                CACHE.set(self.get_all_links_key, cache, expire=CACHE_TIMEOUT)
            return result
        
        except Exception as e:
            logger_parser.error(f"Erreur dans get_all_links : {e}")
            result.error = str(e)
            return result
    
    async def parse_a(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <a> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response:ParserResult = self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result

                balises_a = tree.xpath("//a[@href]")
                if balises_a:
                    for balise_a in balises_a:
                        try:
                            href = balise_a.get("href") if balise_a.get("href") else ""
                            text = balise_a.text_content()
                            target = balise_a.get("target") if balise_a.get("target") else ""
                            rel = balise_a.get("rel") if balise_a.get("rel") else ""
                            abs_link = url
                            if href and not href.startswith("#"):
                                abs_link_ = self.normalize_link(url, href)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "href": href,
                                "abs_link": abs_link,
                                "rel": rel,
                                "target": target,
                                "tag": balise_a.tag or "a",
                                "text": text.strip(),
                                "error": ""
                                }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing lien: {e}")
                            to_add = {
                                "base_url": url,
                                "href": "",
                                "abs_link": url,
                                "rel": "",
                                "target": "",
                                "tag": balise_a.tag or "a",
                                "text": "",
                                "error": "Erreur : " + str(e)
                                }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
                            
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_a : {e}")
            return result
    
    async def parse_style(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <style> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response:ParserResult = self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result

                balise_styles = tree.xpath("//style")
                if balise_styles:
                    for balise_style in balise_styles:
                        try:
                            text = balise_style.text_content()
                            to_add = {
                                "base_url": url,
                                "abs_link": url,
                                "text": text.strip(),
                                "tag": balise_style.tag or "style",
                                "error": ""
                                }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing style: {e}")
                            to_add = {
                                "base_url": url,
                                "abs_link": url,
                                "text": "",
                                "tag": balise_style.tag or "style",
                                "error": "Erreur : " + str(e)
                                }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
                            
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_style : {e}")
            return result
    
    async def parse_img(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <img> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response:ParserResult = self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result

                balise_imgs = tree.xpath("//img[@scr]")
                if balise_imgs:
                    for balise_img in balise_imgs:
                        try:
                            scr = balise_img.get("scr") if balise_img.get("scr") else ""
                            alt = balise_img.get('alt') if balise_img.get('alt') else ''
                            abs_link = url
                            if scr and not scr.startswith("#"):
                                abs_link_ = self.normalize_link(url, scr)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "scr": scr,
                                "abs_link": abs_link,
                                "alt": alt,
                                "tag": balise_img.tag or "img",
                                "error": ""
                                }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing image: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "abs_link": url,
                                "alt": "",
                                "tag": balise_img.tag or "img",
                                "error": "Erreur : " + str(e)
                                }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
                            
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_img : {e}")
            return result
        
    async def parse_script(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False, fetch:bool=True):
        """Récupère toutes les balises <script> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response:ParserResult = self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result

                balises_script = tree.xpath("//script")
                if balises_script:
                    for balise_script in balises_script:
                        try:
                            src = balise_script.get("scr") if balise_script.get("scr") else ""
                            abs_link = url
                            nature = "inline"
                            script_type = balise_script.get('type') if balise_script.get('type') else 'text/javascript'
                            if src and not src.startswith("#"):
                                nature = "externe"
                                abs_link_ = self.normalize_link(url, src)
                                if abs_link_:
                                    abs_link = abs_link_
                                if not fetch:
                                    contenu = ""
                                else:
                                    fetch_response = await self.fetcher.fetch(
                                        abs_link,
                                        method="GET"
                                        )
                                    contenu = fetch_response.body
                                    
                            else:
                                contenu = balise_script.text_content()
                            to_add = {
                                "base_url": url,
                                "scr": src,
                                "type": script_type,
                                "nature": nature,
                                "abs_link": abs_link,
                                "contenu": contenu,
                                "tag": balise_script.tag or "script",
                                "error": ""
                                }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing script: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "type": "",
                                "nature": nature,
                                "abs_link": url,
                                "contenu": "",
                                "tag": balise_script.tag or "script",
                                "error": "Erreur : " + str(e)
                                }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
                            
                        
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_script : {e}")
            return result
        
    async def parse_link(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <link> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response:ParserResult = self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result

                balises_link = tree.xpath("//link[@href]")
                if balises_link:
                    for balise_link in balises_link:
                        try:
                            href = balise_link.get("href") if balise_link.get("href") else ""
                            rel = balise_link.get("rel") if balise_link.get("rel") else ""
                            abs_link = url
                            if href and not href.startswith("#"):
                                abs_link_ = self.normalize_link(url, href)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "href": href,
                                "abs_link": abs_link,
                                "rel": rel,
                                "tag": balise_link.tag or "link",
                                "error": ""
                                }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing link: {e}")
                            to_add = {
                                "base_url": url,
                                "href": "",
                                "abs_link": url,
                                "rel": "",
                                "tag": balise_link.tag or "link",
                                "error": "Erreur : " + str(e)
                                }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
                            
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_link : {e}")
            return result
    
    async def parse_iframe(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <iframe> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_iframe = tree.xpath("//iframe[@src]")
                if balises_iframe:
                    for balise_iframe in balises_iframe:
                        try:
                            src = balise_iframe.get("src") if balise_iframe.get("src") else ""
                            sandbox = balise_iframe.get("sandbox") if balise_iframe.get("sandbox") else ""  #Attribut de securité
                            allow = balise_iframe.get("allow") if balise_iframe.get("allow") else ""  # Permissions
                            abs_link = url
                            if src and not src.startswith("#"):
                                abs_link_ = self.normalize_link(url, src)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "src": src,
                                "abs_link": abs_link,
                                "sandbox": sandbox,
                                "allow": allow,
                                "tag": balise_iframe.tag or "iframe",
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing iframe: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "abs_link": url,
                                "sandbox": "",
                                "allow": "",
                                "tag": "iframe",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_iframe : {e}")
            return result
    
    async def parse_video(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <video> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_video = tree.xpath("//video[@src] | //video/source[@src]")
                if balises_video:
                    for balise_video in balises_video:
                        try:
                            src = balise_video.get("src") if balise_video.get("src") else ""
                            abs_link = url
                            if src and not src.startswith("#"):
                                abs_link_ = self.normalize_link(url, src)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "src": src,
                                "abs_link": abs_link,
                                "tag": balise_video.tag,
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing video: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "abs_link": url,
                                "tag": "video",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_video : {e}")
            return result
    
    async def parse_audio(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <audio> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_audio = tree.xpath("//audio[@src] | //audio/source[@src]")
                if balises_audio:
                    for balise_audio in balises_audio:
                        try:
                            src = balise_audio.get("src") if balise_audio.get("src") else ""
                            abs_link = url
                            if src and not src.startswith("#"):
                                abs_link_ = self.normalize_link(url, src)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "src": src,
                                "abs_link": abs_link,
                                "tag": balise_audio.tag,
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing audio: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "abs_link": url,
                                "tag": "audio",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_audio : {e}")
            return result
    
    async def parse_embed(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <embed> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_embed = tree.xpath("//embed[@src]")
                if balises_embed:
                    for balise_embed in balises_embed:
                        try:
                            src = balise_embed.get("src") if balise_embed.get("src") else ""
                            type_ = balise_embed.get("type") if balise_embed.get("type") else ""
                            abs_link = url
                            if src and not src.startswith("#"):
                                abs_link_ = self.normalize_link(url, src)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "src": src,
                                "abs_link": abs_link,
                                "type": type_,
                                "tag": balise_embed.tag,
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing embed: {e}")
                            to_add = {
                                "base_url": url,
                                "src": "",
                                "abs_link": url,
                                "type": "",
                                "tag": "embed",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_embed : {e}")
            return result
    
    async def parse_object(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <object> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_object = tree.xpath("//object[@data]")
                if balises_object:
                    for balise_object in balises_object:
                        try:
                            data = balise_object.get("data") if balise_object.get("data") else ""  #data = src
                            type_ = balise_object.get("type") if balise_object.get("type") else ""  #type MIME
                            abs_link = url
                            if data and not data.startswith("#"):
                                abs_link_ = self.normalize_link(url, data)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "data": data,
                                "abs_link": abs_link,
                                "type": type_,
                                "tag": balise_object.tag or "object",
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing object: {e}")
                            to_add = {
                                "base_url": url,
                                "data": "",
                                "abs_link": url,
                                "type": "",
                                "tag": "object",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_object : {e}")
            return result
    
    async def parse_form(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <form> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_form = tree.xpath("//form[@action]")
                if balises_form:
                    for balise_form in balises_form:
                        try:
                            action = balise_form.get("action") if balise_form.get("action") else ""
                            method = balise_form.get("method") if balise_form.get("method") else "get"
                            enctype = balise_form.get("enctype") if balise_form.get("enctype") else ""
                            abs_link = url
                            if action and not action.startswith("#"):
                                abs_link_ = self.normalize_link(url, action)
                                if abs_link_:
                                    abs_link = abs_link_
                            
                            # Récupérer les champs du formulaire
                            inputs = balise_form.xpath(".//input | .//button | .//textarea | .//select")
                            champs = []
                            for input_tag in inputs:
                                champs.append({
                                    "name": input_tag.get("name", ""),
                                    "type": input_tag.get("type", ""),
                                    "value": input_tag.get("value", ""),
                                    "tag": input_tag.tag
                                })
                            
                            to_add = {
                                "base_url": url,
                                "action": action,
                                "tag": balise_form.tag,
                                "abs_link": abs_link,
                                "method": method.upper(),
                                "enctype": enctype,
                                "champs": champs,
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing form: {e}")
                            to_add = {
                                "base_url": url,
                                "action": "",
                                "abs_link": url,
                                "tag": "form",
                                "method": "",
                                "enctype": "",
                                "champs": [],
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_form : {e}")
            return result
    
    async def parse_meta(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises <meta> et leurs caractéristiques"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_meta = tree.xpath("//meta")
                if balises_meta:
                    for balise_meta in balises_meta:
                        try:
                            name = balise_meta.get("name") if balise_meta.get("name") else ""
                            property_ = balise_meta.get("property") if balise_meta.get("property") else ""
                            content = balise_meta.get("content") if balise_meta.get("content") else ""
                            http_equiv = balise_meta.get("http-equiv") if balise_meta.get("http-equiv") else ""
                            
                            url_meta = None
                            if http_equiv.lower() == "refresh" and content:
                                # Format: "5; url=https://example.com" ou "5;URL=https://example.com"
                                if "url=" in content.lower():
                                    url_part = content.lower().split("url=")[-1].strip()
                                    url_meta_ = self.normalize_link(url, url_part)
                                    if url_meta_:
                                        url_meta = url_meta_
                            
                            to_add = {
                                "base_url": url,
                                "name": name,
                                "property": property_,
                                "content": content,
                                "http_equiv": http_equiv,
                                "url_in_content": url_meta,
                                "tag": balise_meta.tag or "meta",
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing meta: {e}")
                            to_add = {
                                "base_url": url,
                                "name": "",
                                "property": "",
                                "content": "",
                                "http_equiv": "",
                                "url_in_content": None,
                                "tag": "meta",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_meta : {e}")
            return result
    
    async def parse_cite(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
        """Récupère toutes les balises avec attribut cite (<blockquote>, <q>, <del>, <ins>)"""
        result = ParseElementResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if tree is None:
                    parse_html_response = await self.parse_html(url, False)
                    tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
    
                balises_cite = tree.xpath("//*[@cite]")
                if balises_cite:
                    for balise in balises_cite:
                        try:
                            cite = balise.get("cite") if balise.get("cite") else ""
                            tag = balise.tag
                            text = balise.text_content().strip()[:100]  # Limiter la taille
                            abs_link = url
                            if cite and not cite.startswith("#"):
                                abs_link_ = self.normalize_link(url, cite)
                                if abs_link_:
                                    abs_link = abs_link_
                            to_add = {
                                "base_url": url,
                                "tag": tag,
                                "cite": cite,
                                "abs_link": abs_link,
                                "text": text,
                                "error": ""
                            }
                            result.elements.append(to_add)
                        except Exception as e:
                            logger_parser.error(f"Erreur parsing cite: {e}")
                            to_add = {
                                "base_url": url,
                                "tag": "",
                                "cite": "",
                                "abs_link": url,
                                "text": "",
                                "error": "Erreur : " + str(e)
                            }
                            result.elements.append(to_add)
                    result._update()
                    return result
                return result
        except Exception as e:
            logger_parser.error(f"Erreur global de parse_cite : {e}")
            return result
            
    async def parse_headers(self, url:str, is_normalized:bool = False, semaphore:int = 50, headers:dict = None):
        """Récupère et analyse les en-têtes HTTP d'une réponse."""
        result = ParseElementResult()
        if not is_normalized:
            url = self.normalize_link(url.strip(), "")
            if not url:
                return result
            
        async with asyncio.Semaphore(semaphore):
            try:
                if not headers:
                    fetch_response:FetcherResult = await self.fetcher.fetch(url, method="HEAD") 
                    if not fetch_response or not fetch_response.headers:
                        return result
                    code = fetch_response.status_code
                    headers = {k.lower(): v for k, v in fetch_response.headers.items()}
                    
                else:
                    headers = {k.lower(): v for k, v in headers.items()}    
                    code = 200
                cookies_secure = True
                set_cookie = headers.get("set-cookie", "")
                if set_cookie:
                    cookies = set_cookie.split(",") 
                    for cookie in cookies:
                        if "Secure" not in cookie and "HttpOnly" not in cookie:
                            cookies_secure = False
                            break
                
                security_report = {
                    "strict_transport_security": headers.get("strict-transport-security") is not None,
                    "x_frame_options": headers.get("x-frame-options") is not None,
                    "x_content_type_options": headers.get("x-content-type-options") is not None,
                    "content_security_policy": headers.get("content-security-policy") is not None, 
                    "x_xss_protection": headers.get("x-xss-protection") is not None,
                    "referrer_policy": headers.get("referrer-policy") is not None,
                    "permissions_policy": headers.get("permissions-policy") is not None,
                    "cookies_secure": cookies_secure,
                    "server": headers.get("server", ""), 
                    "powered_by": headers.get("x-powered-by", ""), 
                }
                
                to_add = {
                    "base_url": url,
                    "headers": headers,
                    "security_report": security_report,
                    "status_code": code,
                    "tag": "headers",
                    "error": ""
                }
                result.elements.append(to_add)
                result._update()
                return result
                
            except Exception as e:
                logger_parser.error(f"Erreur de parse_headers : {e}")
                to_add = {
                    "base_url": url,
                    "headers": {},
                    "security_report": {},
                    "status_code": None,
                    "tag": "headers",
                    "error": str(e)
                }
                result.elements.append(to_add)
                return result
    
    async def parse_comment(self, url:str, tree:html.HtmlElement = None, semaphore:int = 50, is_normalized:bool = False):
         """Récupère les commentaires HTML pour analyse de sécurité"""
         result = ParseElementResult()
         try:
             if not is_normalized:
                 url = self.normalize_link(url.strip(), "")
                 if not url:
                     return result
                 
             async with asyncio.Semaphore(semaphore):
                 if tree is None:
                     parse_html_response = await self.parse_html(url, False)
                     tree = parse_html_response.tree
                 if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                     return result
                 
                 comments = tree.xpath('//comment()')
                 if comments:
                     for c in comments:
                         comment_text = str(c.text) if c.text else ""
                         
                         # Détection d'URLs dans les commentaires
                         urls_in_comment = []
                         if comment_text:
                             url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+|/[^\s<>"\'{}|\\^`\[\]]+(?:\.\w+)?'
                             urls_in_comment = re.findall(url_pattern, comment_text)
                         
                         # Détection de mots de passe et credentials
                         password_detected = False
                         credentials = []
                         
                         # Patterns de mots de passe
                         password_patterns = [
                             (r'password\s*[=:]\s*(\S+)', 'password'),
                             (r'pass\s*[=:]\s*(\S+)', 'pass'),
                             (r'pwd\s*[=:]\s*(\S+)', 'pwd'),
                             (r'credentials?\s*[=:]\s*(\S+)', 'credentials'),
                             (r'login\s*[=:]\s*(\S+)', 'login'),
                             (r'username\s*[=:]\s*(\S+)', 'username'),
                             (r'user\s*[=:]\s*(\S+)', 'user'),
                             (r'admin\s*[=:]\s*(\S+)', 'admin'),
                             (r'token\s*[=:]\s*(\S+)', 'token'),
                             (r'key\s*[=:]\s*(\S+)', 'key'),
                             (r'secret\s*[=:]\s*(\S+)', 'secret'),
                             (r'api[_-]?key\s*[=:]\s*(\S+)', 'api_key'),
                         ]
                         
                         for pattern, label in password_patterns:
                             matches = re.findall(pattern, comment_text, re.IGNORECASE)
                             if matches:
                                 password_detected = True
                                 for m in matches:
                                     credentials.append(f"{label}: {m}")
                         
                         # Mots-clés de sécurité à surveiller
                         security_keywords = [
                             'todo', 'fixme', 'bug', 'hack', 'temp', 'remove', 'delete',
                             'admin', 'root', 'backdoor', 'vuln', 'exploit', 'attack'
                         ]
                         
                         has_security_keyword = any(
                             keyword in comment_text.lower() 
                             for keyword in security_keywords
                         )
                         
                         result.elements.append({
                             "tag": "comment",
                             "comment": comment_text[:200] + "..." if len(comment_text) > 200 else comment_text,
                             "urls_found": urls_in_comment,
                             "has_url": len(urls_in_comment) > 0,
                             "has_password": password_detected,
                             "credentials_found": credentials if credentials else None,
                             "has_security_keyword": has_security_keyword,
                             "security_score": sum([
                                 len(urls_in_comment) > 0,
                                 password_detected,
                                 has_security_keyword
                             ]),
                             "length": len(comment_text)
                         })
                 
                 result._update()
                 return result
                 
         except Exception as e:
             logger_parser.error(f"Erreur dans parse_comment : {e}")
             return result
             
    async def parse(
        self,
        url:str,
        fetch:bool = True,
        is_normalized:bool = False,
        semaphore:int = 50,
        restore:bool = False,
        timeout:float|None = None,
        parse_html_response:ParserResult = None,
        silent:bool = True
    ):
        """
        Méthode de parsing totale.

        Parameters
        ----------
        url : str
            Url source.
        fetch : bool, optional
            Détermine si il faut télécharger les scripts js externes. The default is True.
        is_normalized : bool, optional
            Indique si l'url est déjà normalisé. The default is False.
        semaphore : int, optional
            Limtation concurrente. The default is 50.
        restore : bool, optional
            Determine si il faut utiliser le cache. The default is False.
        timeout : float|None, optional
            Tiemout de parsing si fourni. The default is None.
        parse_html_response : ParserResult, optional
            Repose du parse_html, si fourni et validé, il n'est plus téléchargé. The default is None.
        silent : bool, optional
            Détermine niveau de verbisié. The default is True.

        Returns
        -------
        result : ParseResult
            Résultat du parsing.

        """
        result = ParseResult()
        try:
            if not is_normalized:
                url = self.normalize_link(url.strip(), "")
                if not url:
                    return result
            
            if restore:
                cache = CACHE.get(self.parse_key, {})
                data = cache.get(url, None)
                if data:
                    result.update_from_dict(data)
                    logger_parser.debug(f"Cache hit parse pour {url}")
                    return result
                
            async with asyncio.Semaphore(semaphore):
                if parse_html_response:
                    if not (parse_html_response.tree is not None and parse_html_response.response is not None):
                        parse_html_response = await self.parse_html(url, True)
                        
                else:
                    parse_html_response = await self.parse_html(url, True)
                                    
                tree = parse_html_response.tree
                if not isinstance(tree, (html.HtmlElement, etree._ElementTree)):
                    return result
                
                headers = parse_html_response.response.headers
                start_time = time.time()
                
                tasks = [
                    # a # 0
                    asyncio.create_task(self.parse_a(url, tree, semaphore, is_normalized=True)),
                    
                    # Images  # 1
                    asyncio.create_task(self.parse_img(url, tree, semaphore, is_normalized=True)),
                    
                    # Scripts # 2
                    asyncio.create_task(self.parse_script(url, tree, semaphore, is_normalized=True, fetch=fetch)),
                    
                    # link # 3
                    asyncio.create_task(self.parse_link(url, tree, semaphore, is_normalized=True)),
                    
                    # Styles # 4
                    asyncio.create_task(self.parse_style(url, tree, semaphore, is_normalized=True)),
                    
                    # Iframes # 5
                    asyncio.create_task(self.parse_iframe(url, tree, semaphore, is_normalized=True)),
                    
                    # Vidéos # 6
                    asyncio.create_task(self.parse_video(url, tree, semaphore, is_normalized=True)),
                    
                    # Audios # 7
                    asyncio.create_task(self.parse_audio(url, tree, semaphore, is_normalized=True)),
                    
                    # Embeds # 8
                    asyncio.create_task(self.parse_embed(url, tree, semaphore, is_normalized=True)),
                    
                    # Objects # 9
                    asyncio.create_task(self.parse_object(url, tree, semaphore, is_normalized=True)),
                    
                    # Formulaires # 10
                    asyncio.create_task(self.parse_form(url, tree, semaphore, is_normalized=True)),
                    
                    # Métadonnées # 11
                    asyncio.create_task(self.parse_meta(url, tree, semaphore, is_normalized=True)),
                    
                    # Citations # 12
                    asyncio.create_task(self.parse_cite(url, tree, semaphore, is_normalized=True)),
                    
                    # Headers  # 13
                    asyncio.create_task(self.parse_headers(url, is_normalized=True, semaphore=semaphore, headers=headers)),
                    
                    #Commentaires # 14
                    asyncio.create_task(self.parse_comment(url, tree, is_normalized=True, semaphore=semaphore))
                ]
                if timeout:
                    n_error = 0
                    try:
                        answers = await asyncio.wait_for(
                            asyncio.gather(*tasks, return_exceptions=True),
                            timeout=timeout
                        )
                        elapsed = float(f"{time.time() - start_time :.2f}")
                    except asyncio.TimeoutError:
                        logger_parser.warning(f"⏰ Timeout {timeout}s atteint pour {url}")
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                                
                            else:
                                if isinstance(task.exception(), Exception):
                                    n_error += 1
                        if not silent:
                            logger_parser.debug(f"Nombre d'erreur dans le parsing : {n_error}")
                        result.n_error = n_error
                        elapsed = float(f"{time.time() - start_time :.2f}")
                        result.elapsed = elapsed
                        return result
                                
                else:
                    answers = await asyncio.gather(*tasks, return_exceptions=True)
                    elapsed = float(f"{time.time() - start_time :.2f}")
                    
                result.elapsed = elapsed
                result.a = answers[0] if not isinstance(answers[0], Exception) else ParseElementResult()
                result.img = answers[1] if not isinstance(answers[1], Exception) else ParseElementResult()
                result.script = answers[2] if not isinstance(answers[2], Exception) else ParseElementResult()
                result.link = answers[3] if not isinstance(answers[3], Exception) else ParseElementResult()
                result.style = answers[4] if not isinstance(answers[4], Exception) else ParseElementResult()
                result.iframe = answers[5] if not isinstance(answers[5], Exception) else ParseElementResult()
                result.video = answers[6] if not isinstance(answers[6], Exception) else ParseElementResult()
                result.audio = answers[7] if not isinstance(answers[7], Exception) else ParseElementResult()
                result.embed = answers[8] if not isinstance(answers[8], Exception) else ParseElementResult()
                result.object = answers[9] if not isinstance(answers[9], Exception) else ParseElementResult()
                result.form = answers[10] if not isinstance(answers[10], Exception) else ParseElementResult()
                result.meta = answers[11] if not isinstance(answers[11], Exception) else ParseElementResult()
                result.cite = answers[12] if not isinstance(answers[12], Exception) else ParseElementResult()
                result.headers = answers[13] if not isinstance(answers[13], Exception) else ParseElementResult()
                result.comments = answers[14] if not isinstance(answers[14], Exception) else ParseElementResult()
                    
                n_error = sum(isinstance(r, Exception) for r in answers)
                result.n_error = n_error
                if not silent:
                    logger_parser.debug(f"Nombre d'erreur dans le parsing : {n_error}")
                if n_error == 0:
                    cache = CACHE.get(self.parse_key, {})
                    data = result.to_dict()
                    cache[url] = data
                    CACHE.set(self.parse_key, cache, CACHE_TIMEOUT)
                        
                return result
                
        except Exception as e:
            logger_parser.error(f"Erreur global de parse : {e}")
            return result
    
    async def test_parse(self, url:str = "http://localhost:8080", restore:bool = False):
        """Test simple du parseur sur une URL"""
        logger_parser.info("\n" + "="*60)
        logger_parser.info("🧪 TEST DU PARSEUR HTML")
        logger_parser.info("="*60)
        
        logger_parser.info(f"\n📌 Test sur: {url}")
        logger_parser.info("-"*40)
        
        start_time = time.time()
        result = await self.parse(url, fetch=True, restore=restore)
        elapsed = time.time() - start_time
        
        logger_parser.info(f"⏱️  Temps: {elapsed:.3f}s")
        logger_parser.info("📊 Résultats:")
        logger_parser.info(f"  ├─ a: {len(result.a.elements)} liens")
        logger_parser.info(f"  ├─ img: {len(result.img.elements)} images")
        logger_parser.info(f"  ├─ script: {len(result.script.elements)} scripts")
        logger_parser.info(f"  ├─ link: {len(result.link.elements)} links")
        logger_parser.info(f"  ├─ iframe: {len(result.iframe.elements)} iframes")
        logger_parser.info(f"  ├─ form: {len(result.form.elements)} formulaires")
        logger_parser.info(f"  ├─ meta: {len(result.meta.elements)} metas")
        logger_parser.info(f"  └─ headers: {len(result.headers.elements)} en-têtes")
        
        logger_parser.info(f"\n❌ Erreurs: {result.n_error}")
        logger_parser.info("="*60)
        
        return result
    
    async def test_parse_all(self, urls:list = None, restore:bool = False):
        """Test complet du parseur sur plusieurs URLs"""
        if urls is None:
            urls = [
                "http://localhost:8080",
                "http://example.com",
                "https://httpbin.org/html",
                "https://www.google.com", 
                "https://wikipedia.org"
            ]
        
        logger_parser.info("\n" + "🔥"*60)
        logger_parser.info("🔥 TEST COMPLET DU PARSEUR HTML")
        logger_parser.info("🔥"*60)
        
        total_stats = {
            'urls': len(urls),
            'total_time': 0,
            'total_elements': 0,
            'total_errors': 0,
            'details': {}
        }
        
        for i, url in enumerate(urls, 1):
            logger_parser.info(f"\n📌 Test {i}/{len(urls)}: {url}")
            logger_parser.info("-"*40)
            
            start_time = time.time()
            result = await self.parse(url, fetch=True, restore=restore, timeout=5)
            elapsed = time.time() - start_time
            
            # Compter tous les éléments
            n_elements = (
                len(result.a.elements) +
                len(result.img.elements) +
                len(result.script.elements) +
                len(result.link.elements) +
                len(result.style.elements) +
                len(result.iframe.elements) +
                len(result.video.elements) +
                len(result.audio.elements) +
                len(result.embed.elements) +
                len(result.object.elements) +
                len(result.form.elements) +
                len(result.meta.elements) +
                len(result.cite.elements) +
                len(result.headers.elements)
            )
            
            stats = {
                'time': elapsed,
                'elements': n_elements,
                'errors': result.n_error,
                'a': len(result.a.elements),
                'img': len(result.img.elements),
                'script': len(result.script.elements),
                'link': len(result.link.elements),
                'style': len(result.style.elements),
                'iframe': len(result.iframe.elements),
                'video': len(result.video.elements),
                'audio': len(result.audio.elements),
                'embed': len(result.embed.elements),
                'object': len(result.object.elements),
                'form': len(result.form.elements),
                'meta': len(result.meta.elements),
                'cite': len(result.cite.elements),
                'headers': len(result.headers.elements),
            }
            
            total_stats['details'][url] = stats
            total_stats['total_time'] += elapsed
            total_stats['total_elements'] += n_elements
            total_stats['total_errors'] += result.n_error
            
            # Affichage compact
            logger_parser.info(f"  ⏱️  {elapsed:.3f}s | 📄 {n_elements} élém | ❌ {result.n_error} err")
            logger_parser.info(f"  ├─ a:{stats['a']} img:{stats['img']} script:{stats['script']} link:{stats['link']}")
            logger_parser.info(f"  └─ iframe:{stats['iframe']} form:{stats['form']} meta:{stats['meta']}")
        
        # Résumé final
        logger_parser.info("\n" + "★"*60)
        logger_parser.info("📊 RÉSUMÉ FINAL")
        logger_parser.info("★"*60)
        logger_parser.info(f"📌 URLs testées: {total_stats['urls']}")
        logger_parser.info(f"⏱️  Temps total: {total_stats['total_time']:.3f}s")
        logger_parser.info(f"📄 Éléments trouvés: {total_stats['total_elements']}")
        logger_parser.info(f"❌ Erreurs totales: {total_stats['total_errors']}")
        logger_parser.info(f"⚡ Vitesse moyenne: {total_stats['total_elements']/total_stats['total_time']:.1f} élém/s")
        logger_parser.info("★"*60)
        
        return total_stats
    

async def test(urls:list|str = None, restore:bool = False):
    
    session = aiohttp.ClientSession()
    parser = Parser(session=session)
    if isinstance(urls, str):
        await parser.test_parse(url=urls, restore=restore)
    else:
        await parser.test_parse_all(urls, restore)
        
    await session.close()
    await parser.close()

    
if __name__ == "__main__":
    apply()
    parser = Parser(session=aiohttp.ClientSession())
    # print(parser.test_normalize_link(advanced=True))
    # link = 'https://google.com'
    # print("Domaine")
    # print(parser.get_domain(link))
    # print("Classify link")
    # print(asyncio.run(parser.classify_link(link)))
    # print("Robot allow")
    print(asyncio.run(parser.robot_allow(url="https://google.com", agent="*")))
    # print("TEST all links")
    # print(asyncio.run(parser.get_all_links(link)))
    # url = ["http://example.com", "https://www.google.com", "https://wikipedia.org"]
    # url = "http://localhost:8080"
    # # asyncio.run(test(restore=False, urls=url))
    # print(parser.is_same_domain("http://localhost:8080/terms.html", "http://localhost:8080/"))
    # print(asyncio.run(parser.get_all_links(url)))