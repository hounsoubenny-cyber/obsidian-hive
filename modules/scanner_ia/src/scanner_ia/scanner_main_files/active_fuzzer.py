#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 20:16:46 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import lxml
import copy
import json
import traceback
import time
import aiohttp
import asyncio
from collections import Counter
from uuid import uuid4
from typing import Any, Optional, Tuple, List, Dict
# from loguru import logger as logger_fuzzer
from nest_asyncio import apply
from scanner_ia.core.parser import Parser, ParserResult
from scanner_ia.core.fetcher import Fetcher, FetcherResult
from scanner_ia.fuzzer.response_analyzer import ResponseAnalyzer
from scanner_ia.fuzzer.payload_generator import PayloadGenerator
from scanner_ia.base_class.response_analyzer_base_class import ResponseAnalyzerResult
from scanner_ia.base_class.fuzzer_base_class import WorkerFuzzerResult, FuzzerResult, WorkerFuzzerEntry
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult, OneAnalyzerHelperResult
from scanner_ia.base_class.payloads_base_class import PayloadResult, Payloads, Payload
from scanner_ia.scanner_utils.signal_manager import signal_manager
from scanner_ia.scanner_utils.logger import get_logger
import concurrent.futures

apply()

logger_fuzzer = get_logger()
# logger_fuzzer.remove()
# logger_fuzzer.add(
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
# logger_fuzzer.add(
#     "logs/fuzzer.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )


def signal_handler(*args, **kwargs):
	pass

signal_manager(signal_handler)

class Config:
    """Configuration du fuzzer"""
    SEUIL: dict = {
        # ── Preuve directe (réflexion / erreur explicite) ─────────────────
        "XSS":                   0.65,   # réflexion raw prouvée par reflection_score
        "SQLi":                  0.60,   # erreur SQL subtile + time-based bruité
        "DirTrav":               0.65,   # contenu fichier clair
        "XXE":                   0.65,   # parsing XML clair
        "SSTI":                  0.65,   # évaluation template claire
        "IDOR":                  0.65,   # diff de contenu claire
        # ── Signal faible / OOB difficile ────────────────────────────────
        "SSRF":                  0.60,   # OOB difficile sans callback
        "NoSQLi":                0.60,   # erreur subtile
        "LDAPi":                 0.60,   # erreur LDAP subtile
        "XPATH_Injection":       0.60,   # erreur subtile
        "GraphQLi":              0.60,   # erreur subtile
        # ── Mieux vaut FP que FN (InfoSec) ───────────────────────────────
        "CredsExpose":           0.55,   # signaler au moindre doute
        "InfoDisc":              0.55,   # idem
        # ── Risque de faux positif élevé ─────────────────────────────────
        "CMDi":                  0.70,   # output système très distinctif
        "OpenRedirect":          0.70,   # redirect peut être légitime
        "SessFix":               0.70,   # Set-Cookie change souvent
        "CRLF_Injection":        0.70,   # headers sensibles
        "InsecCrypto":           0.70,   # signal faible mais spécifique
        "RaceCondition":         0.70,   # réseau bruité
        "BufOvr":                0.70,   # crash/erreur distinctif
        "CORS":                  0.75,   # headers varient légitimement
        "BrokenAuth":            0.75,   # 4xx→2xx peut être légitime
        "HTTP_Request_Smuggling":0.75,   # très difficile, beaucoup de bruit
        # ── Défaut ───────────────────────────────────────────────────────
        "default":               0.65,
    }
    def __init__(self):
        self.GET_TIMEOUT = 1
        self.TIMEOUT = 5
        self.MAX_KEYS_H: int = 3
        self.MAX_KEYS_C: int = 3
        self.MAX_KEYS_QUERY: Optional[int] = 5
        self.LIMIT_PER_KEY_QUERY: Optional[int] = 2
        self.PATH_LIMIT: Optional[int] = 5
        self.MAX_TEST: Optional[int] = None
        self.MAX_WORKERS: int = 10
        self.FUZZ_TIMEOUT: float = 60 * 2
        self.EMPTY_MAX_COUNT = 3
        self.EMPTY_AWAIT_BETWEEN = 5
        self.EARLY_STOP_PER_VULN: int   = 3     # N confirmations haute-confiance = vuln prouvée
        self.EARLY_STOP_MIN_PROB: float = 0.80  # seulement les confirmations solides comptent


class Fuzzer:
    """
    Fuzzer principal pour les tests d'intrusion actifs.

    Cette classe coordonne la génération de payloads, leur envoi,
    et l'analyse des réponses pour détecter des vulnérabilités.

    Attributes:
        session: Session aiohttp pour les requêtes
        semaphore: Limitation de concurrence
        response_analyzer: Analyseur de réponses
        payload_generator: Générateur de payloads
        parser: Parseur HTML
        debug: Mode debug
    """

    def __init__(
        self,
        session: aiohttp.ClientSession = None,
        semaphore: int = 50,
        debug: bool = True,
        limit: Optional[int] = None,
        use_semantic:bool = True,
        use_arjun: bool = False,   
        arjun_timeout: int = 30,   
        known_params_dir: Optional[str] = None, 
        **kwargs
    ):
        """
        Initialise le fuzzer.

        Args:
            session: Session aiohttp pour les requêtes
            semaphore: Limitation de concurrence
            debug: Mode debug
            limit: Limite de payloads à générer
            **kwargs: Configuration supplémentaire
        """
        self.session = session
        self.semaphore = semaphore
        self.debug = debug
        self.response_analyzer = ResponseAnalyzer(
            debug=debug, 
            use_semantic=use_semantic
        )

        self.payload_generator = PayloadGenerator(
            debug=debug, limit=limit, 
            use_arjun=use_arjun, 
            arjun_timeout=arjun_timeout,
            known_params_dir=known_params_dir
        )
        self.parser = Parser(
            session=self.session,
            semaphore=self.semaphore, 
            **kwargs
        )
        self.config = Config()
        self.update_conf(kwargs)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.MAX_WORKERS, 
            thread_name_prefix="fuzzer_workers"
        )

    def is_in_scope(self, url: str, allowed_domains: list[str]) -> bool:
        if not allowed_domains:
            return True
        return any(Parser.is_same_domain(d, url) for d in allowed_domains)

    async def create_session(self, session):
        return session or aiohttp.ClientSession()

    def update_conf(self, kwargs: dict = None):
        """
        Met à jour la configuration.

        Args:
            kwargs: Dictionnaire des clés de configuration
        """
        kwargs = kwargs or {}
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)
            elif hasattr(self.config, k.upper()):
                setattr(self.config, k.upper(), v)

    def _filter_urls(
            self,
            base_url: str,
            analyzer_helper_result: AnalyzerHelperResult
    ) -> Tuple[AnalyzerHelperResult, AnalyzerHelperResult]:
        """
        Trie les URLs par domaine (même domaine / autres domaines).

        Args:
            base_url: URL ou domaine de base
            analyzer_helper_result: Résultat de l'AnalyzerHelper

        Returns:
            Tuple[AnalyzerHelperResult, AnalyzerHelperResult]: 
                (même_domaine, autres_domaines)
        """
        same_domain = AnalyzerHelperResult()
        other_domain = AnalyzerHelperResult()
        same_domain.elapsed = analyzer_helper_result.elapsed
        other_domain.elapsed = analyzer_helper_result.elapsed

        for url, one_result in analyzer_helper_result.elements.items():
            if Parser.is_same_domain(base_url, url):
                same_domain.elements[url] = one_result
            else:
                other_domain.elements[url] = one_result

        logger_fuzzer.debug(f"Filtrage: {len(same_domain.elements)} même domaine, {len(other_domain.elements)} autres")
        return same_domain, other_domain

    def select_vuln_to_test(self, limit_vuln: Optional[int] | list[str] = None) -> List[Dict[str, Any]]:
        """
        Sélectionne les vulnérabilités à tester par ordre de priorité.

        Args:
            limit_vuln: Nombre maximum de vulnérabilités à tester

        Returns:
            Liste des vulnérabilités avec leurs métadonnées
        """
        severity_mapping: dict = self.response_analyzer.weights["severity_mapping"]
        vulns = []
        for v in severity_mapping.values():
            vulns.extend(v)

        vulns = sorted(vulns, key=lambda x: x.get("priority", 999))

        if limit_vuln:
            if isinstance(limit_vuln, int):
                return vulns[:limit_vuln]
            if isinstance(limit_vuln, list):
                return [vuln for vuln in vulns if vuln["name"] in limit_vuln]
        return vulns

    async def generate_payloads(
        self,
        vulns: List[Dict[str, Any]],
        analyzer_helper_result: AnalyzerHelperResult,
        **kwargs
    ) -> Tuple[asyncio.Queue, Dict]:
        """
        Génère les payloads à tester et les place dans une queue.

        Args:
            vulns: Liste des vulnérabilités à tester
            analyzer_helper_result: Résultat de l'AnalyzerHelper
            **kwargs: Configuration pour get_baseline

        Returns:
            Tuple[asyncio.Queue, Dict]: (queue des payloads, statistiques)
        """
        queue = asyncio.Queue()
        stats = {}

        for url, page in analyzer_helper_result.elements.items():
            if not page.fetched or not page.parsed or not page.fetched.body:
                page_ = await self.get_baseline(url, timeout=self.config.TIMEOUT, **kwargs)
                if not page_.fetched:
                    logger_fuzzer.warning(
                        f"Impossible d'obtenir baseline pour {url}, ignoré")
                    continue
            else:
                page_ = page

            url_stats = 0
            for vuln in vulns:
                name = vuln["name"]
                payload_result = self.payload_generator.inject_payloads(
                    vuln_name=name,
                    data=page_,
                    max_keys_c=self.config.MAX_KEYS_C,
                    max_keys_h=self.config.MAX_KEYS_H,
                    max_keys_query=self.config.MAX_KEYS_QUERY,
                    limit_per_key_query=self.config.LIMIT_PER_KEY_QUERY,
                    path_limit=self.config.PATH_LIMIT
                )

                if payload_result.n_payloads == 0:
                    continue

                injection_points = self.payload_generator.payloads["payloads"].get(
                    name, {}).get("injection_points", [])

                for ip in injection_points:
                    payloads_obj = payload_result.get_payload(ip)
                    if not payloads_obj or not payloads_obj.payloads:
                        continue

                    for p in payloads_obj.payloads:
                        if self.config.MAX_TEST is not None and queue.qsize() >= self.config.MAX_TEST:
                            logger_fuzzer.info(f"Limite MAX_TEST={self.config.MAX_TEST} atteinte")
                            return queue, stats

                        entry = WorkerFuzzerEntry()
                        entry.baseline = page_.fetched
                        entry.url = url
                        entry.vuln_name = payload_result.vuln_name
                        entry.vuln_abbr_name = payload_result.vuln_abbr_name
                        entry.vuln_full_name = payload_result.vuln_full_name
                        entry.priority = vuln.get("priority", 5)
                        entry.payload_type = payloads_obj.payload_type
                        entry.payload = p
                        entry.cvss = payload_result.cvss

                        await queue.put(entry)
                        url_stats += 1
            stats[url] = url_stats

        logger_fuzzer.info(f"Génération terminée: {queue.qsize()} payloads")
        return queue, stats

    async def send_payload(self, entry: WorkerFuzzerEntry, **kwargs) -> Optional[FetcherResult]:
        """
        Envoie un payload selon son type.

        Args:
            entry: Entrée worker contenant le payload
            **kwargs: Paramètres supplémentaires pour fetch

        Returns:
            Résultat de la requête ou None si erreur
        """
        ptype = entry.payload_type
        if not ptype:
            return None

        new_element = entry.payload.new_element
        logger_fuzzer.debug(f"Envoi payload: {ptype}")

        try:
            if "form" in ptype.lower():
                method = new_element.get("method", "GET").upper()
                url = new_element.get("abs_link", entry.url)
                data = new_element.get("champs", [{}])[
                    0] if new_element.get("champs") else {} # Liste de dict d'où le [0]

                if method == "POST":
                    result = await self.parser.fetcher.fetch(
                        url=url,
                        method=method,
                        data=data,
                        timeout=self.config.TIMEOUT,
                        **kwargs
                    )
                else:  # GET
                    result = await self.parser.fetcher.fetch(
                        url=url,
                        method=method,
                        params=data,
                        timeout=self.config.TIMEOUT,
                        **kwargs
                    )

            elif "header" in ptype.lower():
                headers = new_element
                result = await self.parser.fetcher.fetch(
                    url=entry.url,
                    method="GET",
                    headers=headers,
                    timeout=self.config.TIMEOUT,
                    **kwargs
                )

            elif "cookie" in ptype.lower():
                cookies = new_element
                result = await self.parser.fetcher.fetch(
                    url=entry.url,
                    method="GET",
                    cookies=cookies,
                    timeout=self.config.TIMEOUT,
                    **kwargs
                )
            
            elif "body" in ptype.lower(): 
                body_config = new_element        # {"content_type": ..., "data": ..., "raw": ...}
                ct = body_config["content_type"]
                data = body_config["data"]
                if body_config.get("raw"):  # XML brut donc data=data
                    result = await self.parser.fetcher.fetch(
                        url=entry.url,
                        method="POST",
                        timeout=self.config.TIMEOUT,
                        data=data,
                        headers={"Content-Type": ct},
                        **kwargs
                    )
                else: # JSON donc json=data
                    result = await self.parser.fetcher.fetch(
                        url=entry.url,
                        method="POST",
                        timeout=self.config.TIMEOUT,
                        json=data,
                        headers={"Content-Type": ct},
                        **kwargs
                    )
        
            elif any(c in ptype.lower() for c in ("path", "query")):
                result = await self.parser.fetcher.fetch(
                    url=new_element,
                    method="GET",
                    timeout=self.config.TIMEOUT,
                    **kwargs
                )
            else:
                logger_fuzzer.warning(f"Type de payload inconnu: {ptype}")
                return None

            return result

        except Exception as e:
            logger_fuzzer.error(f"Erreur envoi payload {ptype}: {e}")
            return None

    async def get_baseline(self, url: str, **kwargs) -> OneAnalyzerHelperResult:
        """
        Obtient la baseline d'une URL (page de référence).

        Args:
            url: URL à analyser
            **kwargs: Paramètres supplémentaires

        Returns:
            Résultat de l'analyse baseline
        """
        result = OneAnalyzerHelperResult()

        try:
            result_fetch = await self.parser.fetcher.fetch(
                url,
                method="GET",
                timeout=self.config.TIMEOUT,
                **kwargs
            )

            if not result_fetch or result_fetch.error:
                logger_fuzzer.warning(f"Baseline impossible pour {url}: {result_fetch.error if result_fetch else 'inaccessible'}")
                return result

            result.fetched = result_fetch
            parser_r = ParserResult()
            parser_r.response = result_fetch

            # Fallback si body vide
            body = result_fetch.body or "<html><body>Page vide</body></html>"
            parser_r.tree = lxml.html.fromstring(body)

            result.parsed = await self.parser.parse(
                url,
                fetch=True,
                parse_html_response=parser_r
            )

            logger_fuzzer.debug(f"Baseline obtenue pour {url}")

        except Exception as e:
            logger_fuzzer.error(f"Erreur get_baseline pour {url}: {e}")

        return result
    
    @staticmethod
    def _early_stop_min_prob(vuln_name: str) -> float:
        """
        Seuil de confirmation dynamique = (seuil_détection + 1.0) / 2.
        Garanti toujours au-dessus du seuil de détection, jamais arbitraire.
        Ex: SQLi seuil=0.60 → early_stop=0.80 | CORS seuil=0.75 → early_stop=0.875
        """
        seuil = Config.SEUIL.get(vuln_name, Config.SEUIL["default"])
        return (seuil + 1.0) / 2

    def _should_skip(self, url: str, vuln_name: str, result: FuzzerResult) -> bool:
        key = f"{url}|{vuln_name}"
        return result._confirmed.get(key, 0) >= self.config.EARLY_STOP_PER_VULN
    
    def _register_confirmation(self, url: str, vuln_name: str, prob: float, result: FuzzerResult) -> None:
        min_prob = self._early_stop_min_prob(vuln_name)   # dynamique selon la vuln
        if prob >= min_prob:
            key   = f"{url}|{vuln_name}"
            result._confirmed[key] = result._confirmed.get(key, 0) + 1
            count = result._confirmed[key]
            if count == self.config.EARLY_STOP_PER_VULN:
                logger_fuzzer.info(
                    f"🏁 [early_stop] {vuln_name} sur {url} — "
                    f"{count} confirmations (prob≥{min_prob:.3f}) → skippé"
                )
                
    async def _worker(
        self,
        base_url: str,
        queue: asyncio.Queue,
        signal_queue: asyncio.Queue,
        lock: asyncio.Lock,
        result: FuzzerResult,
        worker_id: str = "",
        time_between: float = 0.001
    ) -> None:
        """
        Worker asynchrone pour traiter les payloads.

        Args:
            base_url: URL de base
            queue: Queue des payloads
            lock: Lock pour synchronisation
            result: Résultat à accumuler
            worker_id: Identifiant du worker
            time_between: Temps entre les traitements
        """

        local_count = 0
        while True:
            get_item = False
            can_put = False
            worker_result = WorkerFuzzerResult()

            try:
                worker_entry: WorkerFuzzerEntry = await asyncio.wait_for(queue.get(), timeout=self.config.GET_TIMEOUT)
                get_item = True

                if worker_entry is None:
                    await signal_queue.put(None)
                    break
                
                async with lock:
                    if self._should_skip(worker_entry.url, worker_entry.vuln_name, result):
                        queue.task_done()
                        continue
                
                local_count += 1

                payload_response = await self.send_payload(
                    entry=worker_entry,
                )

                if payload_response is None:
                    continue

                worker_result.url = worker_entry.url
                worker_result.base_url = base_url
                worker_result.payload = worker_entry.payload
                worker_result.payload_type = worker_entry.payload_type
                worker_result.payload_result = payload_response
                worker_result.baseline = worker_entry.baseline
                worker_result.vuln_full_name = worker_entry.vuln_full_name
                worker_result.vuln_name = worker_entry.vuln_name
                worker_result.vuln_abbr_name = worker_entry.vuln_abbr_name
                worker_result.cvss = worker_entry.cvss
                
                loop = asyncio.get_event_loop()
                response_analyzer_result = await loop.run_in_executor(
                    self._executor,
                    self.response_analyzer.analyse,
                    worker_result,
                    self.payload_generator.payloads.get('payloads', {}),
                    self.config.SEUIL.get(
                            worker_result.vuln_name,
                            self.config.SEUIL.get("default", 0.65)
                        )
                )
                # response_analyzer_result = await asyncio.to_thread(
                #     self.response_analyzer.analyse,
                #     worker_result,
                #     self.payload_generator.payloads.get('payloads', {}),
                #     self.config.SEUIL.get(worker_result.vuln_name,
                #                      self.config.SEUIL.get("default", 0.65))
                #     )
                worker_result.response_analyzer_result = response_analyzer_result
                can_put = True
                if response_analyzer_result.is_vulnerable:
                    async with lock:
                        self._register_confirmation(
                            worker_entry.url,
                            worker_entry.vuln_name,
                            # worker_entry.payload_type
                            response_analyzer_result.prob,
                            result
                        )
                
                    if self.debug:
                        async with lock:
                            logger_fuzzer.warning(
                                f"""⚠️ [{worker_id}] Vulnérabilité {worker_entry.vuln_name}, 
                                trouvée sur {worker_entry.url} 
                                (confiance: {response_analyzer_result.prob:.2f})"""
                            ) 

            except asyncio.TimeoutError:
                async with lock:
                    if queue.empty():
                        for _ in range(self.config.MAX_WORKERS):
                            await queue.put(None)

                    await signal_queue.put(None)
                break

            except asyncio.QueueEmpty:
                # async with lock:
                #     if None not in list(queue._queue):
                #         logger_fuzzer.debug(f"Worker {worker_id}: queue vide")
                #         await queue.put(None)
                logger_fuzzer.debug("Queue vide !")
                await signal_queue.put(None)
                break
            
            except asyncio.CancelledError:
                logger_fuzzer.debug(f"Worker {worker_id} annulé")
                await signal_queue.put(None)
                break
            
            except KeyboardInterrupt:
                break
            
            except Exception as e:
                logger_fuzzer.error(f"Erreur worker {worker_id}: {e}")
                worker_result.error = str(e)
                if self.debug:
                    logger_fuzzer.error(traceback.format_exc())

            finally:
                if get_item:
                    if can_put:
                        async with lock:
                            result.results.append(worker_result)
                    queue.task_done()

                if local_count % 20 == 0 and worker_id:
                    logger_fuzzer.info(f"Worker {worker_id} a traité {local_count} payloads")

                await asyncio.sleep(time_between)

    def stop_task(self, tasks):
        for t in tasks:
            try:
                t.cancel()
            except Exception:
                pass
            
    async def fuzz(
        self,
        base_url: str,
        analyzer_helper_result: AnalyzerHelperResult,
        limit_vuln: Optional[int] | list[str] = None,
        time_between: float = 0.001,
        allowed_domains: list[str] | None = ["http://127.0.0.1", "http://localhost"],
        dynamic_timeout: bool = True,
        max_test: int | None = None,
        **kwargs
    ) -> FuzzerResult:
        """
        Lance le fuzzing sur les URLs fournies.

        Args:
            base_url: URL de base pour le filtrage par domaine
            analyzer_helper_result: Résultat de l'AnalyzerHelper
            limit_vuln: Limite de vulnérabilités à tester
            time_between: Temps entre les requêtes
            **kwargs: Paramètres supplémentaires

        Returns:
            Résultat complet du fuzzing
        """
        max_test_b = self.config.MAX_TEST
        self.config.MAX_TEST = max_test
        if allowed_domains:
            if not self.is_in_scope(base_url, allowed_domains=allowed_domains):
                logger_fuzzer.error(f"URL hors scope → {base_url}")
                self.config.MAX_TEST = max_test_b
                return FuzzerResult()

        result = FuzzerResult()
        # await self.ensure_session()
        start_time = time.time()
        same_domain = AnalyzerHelperResult()
        total_payloads = 0
        done, pending = [], []
        try:
            # Sélectionner les vulnérabilités à tester
            vulns_to_test = self.select_vuln_to_test(limit_vuln)
            logger_fuzzer.info(f"{len(vulns_to_test)} vulnérabilités sélectionnées")

            # Filtrer par domaine
            same_domain, other_domain = self._filter_urls(
                base_url, analyzer_helper_result
            )
            result.other_links = other_domain

            if len(same_domain.elements) == 0:
                logger_fuzzer.warning("Aucune URL du même domaine à tester")
                self.config.MAX_TEST = max_test_b
                return result

            # Générer les payloads
            queue, stats = await self.generate_payloads(
                vulns=vulns_to_test,
                analyzer_helper_result=same_domain,
                **kwargs
            )
            signal_queue = asyncio.Queue()
            total_payloads = queue.qsize()
            if dynamic_timeout:
                estimated_time = (total_payloads / self.config.MAX_WORKERS) * (time_between + 0.1)
                self.config.FUZZ_TIMEOUT = max(60, min(600, estimated_time * 1.5))
                logger_fuzzer.info(f"Timeout configuré dynamiquement à {self.config.FUZZ_TIMEOUT:.1f}s")
    
                
            logger_fuzzer.info(f"Stats par URL:\n{json.dumps(stats, indent=2, ensure_ascii=False)}")
            logger_fuzzer.info(f"Lancement de {total_payloads} tests avec {self.config.MAX_WORKERS} workers")

            # Lancer les workers
            lock = asyncio.Lock()
            worker_id_base = str(uuid4())[:10]

            tasks = [
                asyncio.create_task(
                    self._worker(
                        base_url=base_url,
                        queue=queue,
                        signal_queue=signal_queue,
                        lock=lock,
                        result=result,
                        time_between=time_between,
                        worker_id=f"{worker_id_base}_{i}"
                    )
                )
                for i in range(self.config.MAX_WORKERS)
            ]

            logger_fuzzer.debug(f"Workers démarrés: {[t._state for t in tasks]}")
            try:
                async def monitor_queue():
                    empty_count = 0
                    while not queue.empty():
                        await asyncio.sleep(0.2)
                        try:
                            item = signal_queue.get_nowait()
                            if item is None:
                                logger_fuzzer.warning("🚨 SIGNAL NONE DÉTECTÉ ! ARRÊT IMMÉDIAT")
                                raise asyncio.TimeoutError("Signal d'arrêt reçu d'un worker")

                        except asyncio.QueueEmpty:
                            pass

                        if queue.empty():
                            await asyncio.sleep(self.config.EMPTY_AWAIT_BETWEEN)
                            if queue.empty():
                                empty_count += 1
                        if empty_count >= self.config.EMPTY_MAX_COUNT:
                            logger_fuzzer.info("📭 Queue vide, arrêt normal")
                            raise asyncio.QueueEmpty("📭 Queue vide, arrêt normal")
                            

                # print(self.config.FUZZ_TIMEOUT)
                # input()
                monitor_task = asyncio.create_task(monitor_queue())
                # print(tasks)
                join_task = asyncio.create_task(
                    asyncio.wait_for(queue.join(), timeout=self.config.FUZZ_TIMEOUT)
                    )

                done, pending = await asyncio.wait(
                    [monitor_task, join_task],
                    timeout=None,  # ou None, c'est juste mon choix
                    return_when=asyncio.FIRST_EXCEPTION
                )
                for task in done:
                    task.result()   # Pour propager l'erreur
                logger_fuzzer.success(f"Queue fuzz vidée avant timeout({self.config.FUZZ_TIMEOUT}) !")

            except (asyncio.TimeoutError, asyncio.QueueEmpty):
                logger_fuzzer.warning(f"Timeout join atteint timeout={self.config.FUZZ_TIMEOUT}")
                while not queue.empty():
                    try:
                        queue.get_nowait()
                        queue.task_done()
                    except asyncio.QueueEmpty:
                        break

                self.stop_task(tasks)
                self.stop_task(pending)

            except Exception as e:
                logger_fuzzer.error(f"Erreur pour join : {e}")
                if self.debug:
                    logger_fuzzer.error(traceback.format_exc())

            finally:
                for _ in range(self.config.MAX_WORKERS):
                    await queue.put(None)
                await asyncio.gather(*tasks, return_exceptions=True)
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

            try:
                monitor_task.cancel()
            except Exception:
                pass

            self.stop_task(tasks)
            self.stop_task(pending)

            logger_fuzzer.info(f"Fuzzing terminé pour {base_url}")

        except Exception as e:
            logger_fuzzer.error(f"Erreur dans fuzz: {e}")
            if self.debug:
                logger_fuzzer.error(traceback.format_exc())

        finally:
            result.elapsed = time.time() - start_time

        result.stats = self._compute_stats(result, len(same_domain.elements), total_payloads)
        self.config.MAX_TEST = max_test_b
        return result

    def _compute_stats(self, result: FuzzerResult, total_urls: int, total_tests: int) -> Dict:
        """
        Calcule les statistiques du fuzzing.

        Args:
            result: Résultat du fuzzing
            total_urls: Nombre total d'URLs testées
            total_tests: Nombre total de tests effectués

        Returns:
            Dictionnaire des statistiques
        """
        stats = {
            "total_tests": total_tests,
            "total_responses": len(result.results),
            "total_urls": total_urls,
            "vuln_count": {},
            "vuln_by_url": {},
            "vulns_url": []
        }

        vulns_by_name = []
        vulns_by_url_dict = {}
        vulns_url_list = []
        probs_by_url_vuln: Dict[str, Dict[str, list]] = {}
        
        for worker_result in result.results:
            if not worker_result.response_analyzer_result:
                continue

            resp = worker_result.response_analyzer_result

            if resp.is_vulnerable:
                url = worker_result.url

                if url not in vulns_url_list:
                    vulns_url_list.append(url)

                if url not in vulns_by_url_dict:
                    vulns_by_url_dict[url] = []
                
                if url not in probs_by_url_vuln:
                    probs_by_url_vuln[url] = {}

                vuln_name = worker_result.vuln_name

                vulns_by_name.append(vuln_name)

                if vuln_name not in probs_by_url_vuln[url]:
                    probs_by_url_vuln[url][vuln_name] = []
                    
                if vuln_name not in vulns_by_url_dict[url]:
                    vulns_by_url_dict[url].append(vuln_name)
                
                probs_by_url_vuln[url][vuln_name].append({
                    "prob":    resp.prob,
                    "payload": str(worker_result.payload.payload_injected or "")[:120],
                    "type":    worker_result.payload_type or "",
                })
                
            
        vuln_confidence = {}   # {url: {vuln: {"avg": x, "max": y, "count": n}}}
        for url, vulns in probs_by_url_vuln.items():
            vuln_confidence[url] = {}
            for vuln, entries in vulns.items():
                if entries:
                    best   = max(entries, key=lambda e: e["prob"])
                    probs  = [e["prob"] for e in entries]
                    vuln_confidence[url][vuln] = {
                        "count":        len(entries),
                        "prob_max":     round(best["prob"], 3),
                        "prob_avg":     round(sum(probs) / len(probs), 3),
                        "best_payload": best["payload"],
                        "best_type":    best["type"],
                    }
        
        stats["vuln_confidence"] = vuln_confidence
        stats["vuln_count"] = dict(Counter(vulns_by_name))
        stats["vuln_by_url"] = vulns_by_url_dict
        stats["vulns_url"] = vulns_url_list
        stats["total_vulns"] = len(vulns_by_name)

        if total_tests > 0:
            stats["success_rate"] = len(result.results) / total_tests
            stats["vuln_rate"] = (len(vulns_url_list) / total_urls) if total_urls else 0
        return stats

    async def test(self, urls: List[str] = None, use_cache: bool = True) -> None:
        """
        Test le fuzzer sur des URLs.

        Args:
            urls: Liste d'URLs à tester
        """
        logger_fuzzer.info("\n" + "🔥"*60)
        logger_fuzzer.info("🔥 TEST DU FUZZER")
        logger_fuzzer.info("🔥"*60)

        if urls is None:
            urls = ["http://localhost:8080"]
        try:
            from scanner_ia.core.analyzer_helper import AnalyzerHelper
            result = FuzzerResult()
            # async with aiohttp.ClientSession() as session:
            helper = AnalyzerHelper(self.session, use_cache=use_cache, )
            self.debug = True
            for url in urls:
                logger_fuzzer.info(f"\n📌 Test sur {url}")
                logger_fuzzer.info("-"*50)

                # Obtenir les données de base
                page_result = await helper.analyse_and_parse_all(
                    url=url,
                    verify_reachability=True,
                    restore=use_cache,
                    fetch=True
                )

                if not page_result.elements:
                    logger_fuzzer.warning(f"  ⚠️ Aucune donnée pour {url}")
                    continue
                
                self.config.FUZZ_TIMEOUT = 60 * 5
                print(self.config.FUZZ_TIMEOUT)
                print(len(page_result.elements.keys()), "url a fuzzer")
                print(page_result.elements['http://localhost:8080/vulnerabilities/xss_r'].crawl)
                page_result.elements.pop("http://localhost:8080/vulnerabilities/login.php")
                input()
                # self.config.MAX_TEST = 5
                
                # Lancer le fuzzing
                result = await self.fuzz(
                    base_url=url,
                    analyzer_helper_result=page_result,
                    limit_vuln=["XSS"], 
                    time_between=0.001,
                    dynamic_timeout=False,

                )

                # Afficher les résultats
                logger_fuzzer.info(f"\n  ✅ Fuzzing terminé en {result.elapsed:.2f}s")
                logger_fuzzer.info(f"  📊 Tests: {result.stats['total_tests']}")
                logger_fuzzer.info(f"  🔍 Vulnérabilités: {result.stats['total_vulns']}")

                for vuln, count in result.stats['vuln_count'].items():
                    logger_fuzzer.info(f"    • {vuln}: {count}")

                logger_fuzzer.info(f"stats : \n {result.stats}, \nelapsed={result.elapsed}")
            await helper.close()
            return result
            
        except KeyboardInterrupt:
            sys.exit(1)


if __name__ == "__main__":
    # Test simple
    async def main():
        from scanner_utils.helpers import dvwa_full_setup
        async with aiohttp.ClientSession() as session:
            await dvwa_full_setup(session, "http://localhost:8080", "admin", "password", "low")
            fuzzer = Fuzzer(debug=True, session=session)
            # print(fuzzer.select_vuln_to_test(["SQLi"]))
            await fuzzer.test(["http://localhost:8080" + "/vulnerabilities/xss_r"])

    asyncio.run(main())
