#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI ScannerAI - Module de scan de vulnérabilités web
Version: 2.0.0
Author: Samuel HOUNSOU
"""

import os
import sys
import time
import asyncio
import aiohttp
import argparse
import diskcache
import atexit
import threading
import traceback
from uuid import uuid4
from pathlib import Path
from typing import Optional, Union, List, Dict, Any
from datetime import datetime
from nest_asyncio import apply

# Pour le spinner et progress bar
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# =============================================================================
# IMPORTS PROJET
# =============================================================================

from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class.code_analyse_base_class import CodeAnalyzerResult
from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.base_class.main_scanner_base_class import ScannerResult

from scanner_ia.scanner_utils.utils_scanner import is_url_reachable
from scanner_ia.scanner_utils.signal_manager import signal_manager
from scanner_ia.config_manager import ConfigManager, DEFAULT_CONFIG_PATH
from scanner_ia.core.fetcher import Config as FetcherConfig, PlaywrightPool
from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.fuzzer.active_fuzzer import Fuzzer
from scanner_ia.fuzzer.mock_fuzzer import MockFuzzer
from scanner_ia.ml_model.features_extractor import FeatureExtractor
from scanner_ia.ml_model.scanner_ia_v2 import ScannerIA
from scanner_ia.reports.report_generator import ReportGenerator
from scanner_ia.reports.report_builder import ReportBuilder
from scanner_ia.reports.llm_report import generate_report
from scanner_ia.scanner_utils.logger import get_logger
from scanner_ia.scanner_utils.helpers.resolve_helpers import resolve_helpers, HelperCall
from modules_utils.loop_utils import _run_async

# =============================================================================
# CONFIGURATION
# =============================================================================

REPORT_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)),'result_scan')
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),'scanner_cache','cache')
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# Configuration logger
logger = get_logger()

MAX_CACHE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CACHE = diskcache.Cache(
    directory=str(CACHE_DIR),
    size_limit=MAX_CACHE_SIZE,
    cull_limit=40,
    statistics=True,
    cull_frequency=5
)
CACHE_TIMEOUT = 24 * 3600
_ML_AVAILABLE = True
MODEL_DIR = "model_scanner_chain_mvp"
__version__ = "2.0.0"
__author__ = "Samuel HOUNSOU - ScannerAI" #HiveMind Scout


# =============================================================================
# CACHE MANAGEMENT
# =============================================================================
def close_cache():
    if hasattr(CACHE, "close"):
        CACHE.close()


def close_atexit():
    atexit.register(close_cache)


def cache_stats() -> Dict[str, Any]:
    return {
        'size': CACHE.volume(),
        'items': len(CACHE),
        'expired': CACHE.expire(),
        'hit_ratio': CACHE.stats()
    }


def signal_handler(*args, **kwargs):
    close_cache()
    try:
        _run_async(PlaywrightPool.close)
    except Exception as e:
        logger.warning(f"⚠️ Erreur lors de la fermeture du PlaywrightPool : {e}")


signal_manager(signal_handler)
close_atexit()


# =============================================================================
# EXCEPTIONS PERSONNALISÉES
# =============================================================================
class ScannerError(Exception):
    """Erreur générique du scanner"""
    pass


class ScopeError(ScannerError):
    """URL hors scope"""
    pass


class UnreachableError(ScannerError):
    """URL inaccessible"""
    pass


class PhaseError(ScannerError):
    """Erreur pendant une phase de scan"""
    pass


# =============================================================================
# CLASSE PRINCIPALE SCANNER
# =============================================================================
class Scanner:
    __version__ = __version__
    __author__ = __author__

    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        active_scan: bool = True,
        use_cache: bool = True,
        restore: bool = False,
        headers_sev_map: Union[dict, None] = None,
        debug: bool = True,
        semaphore: int = 50,
        limit_payloads: Optional[int] = None,
        use_semantic: bool = True,
        theme: Optional[str] = None,
        model_dir: str = MODEL_DIR,
        use_arjun: bool = False,         
        arjun_timeout: int = 30,          
        known_params_dir: Optional[str] = None,  
        report_dir: Optional[str] = REPORT_DIR
    ):
        self.config_path = Path(config_path)
        if not self.config_path.exists():
            raise FileNotFoundError(f"Fichier de config absent: {config_path}")

        self.use_cache = use_cache
        self.restore = restore
        self.debug = debug
        self.fuzzer_enabled = active_scan
        
        self.config_manager = ConfigManager()
        self._base_scan_key = self.config_manager.configure(path=str(config_path))
        self.sess_limit = semaphore or FetcherConfig().Semaphore
        self.sem = semaphore
        self.report_dir = report_dir
        if self.config_manager.fetcher_conf.get("Semaphore"):
            self.sess_limit = self.config_manager.fetcher_conf.get("Semaphore")
        
        self.loop = None
        self.loop_thread_task = None
        self.session = None
        self._get_session()
        
        # Modules
        self.analyzer_helper = AnalyzerHelper(
            session=self.session,
            use_cache=self.use_cache
        )
        self.analyzer_helper.update_conf(self.config_manager.analyzer_helper_conf)
        self.analyzer_helper.crawler.update_conf(self.config_manager.crawler_conf)
        self.analyzer_helper.crawler.parser.update_conf(self.config_manager.parser_conf)
        self.analyzer_helper.crawler.parser.fetcher.update_conf(self.config_manager.fetcher_conf)
        
        self.passive_analyzer = PassiveCodeAnalyzer(headers_sev_map=headers_sev_map)
        self.code_analyzer = CodeAnalyzer(debug=debug)

        self.fuzzer = None
        if active_scan:
            self.fuzzer = Fuzzer(
                session=self.session,
                debug=debug,
                use_semantic=use_semantic,
                limit=limit_payloads,
                known_params_dir=known_params_dir,
                use_arjun=use_arjun,
                arjun_timeout=arjun_timeout,
                **self.config_manager.fuzzer_conf  # Pour que le pool soit à jour.
            )
            self.fuzzer.update_conf(self.config_manager.fuzzer_conf)
        self.fuzzer_mock = MockFuzzer()

        self.feature_extractor = FeatureExtractor()
        self.scanner_ia = ScannerIA(model_dir=model_dir)
        self.report_generator = ReportGenerator(storage_dir=str(self.report_dir), theme=theme)
        self.report_builder = ReportBuilder()
        
        if threading.current_thread() is threading.main_thread():
            signal_manager(self.override_signal_handler)
                
        self.register_close_session()
        
        if RICH_AVAILABLE and debug:
            console.print(Panel.fit(
                "[bold green]🐝 ShieldAI ScannerAI Initialisé[/bold green]\n"
                f"Scan actif: {'✅' if active_scan else '❌'} | "
                f"Cache: {'✅' if use_cache else '❌'} | "
                f"Sémantique: {'✅' if use_semantic else '❌'}",
                border_style="green"
            ))
            
    def _create_session(self):
        return aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=self.sess_limit
            ),
            headers=FetcherConfig.HEADERS, 
        )
    
    def _get_session(self):
        if self.session is None:
            try:
                asyncio.get_running_loop()
                self.session = self._create_session()
            except RuntimeError:
                self.loop = asyncio.new_event_loop()
                self.loop_thread_task = threading.Thread(
                    target=self.loop.run_forever, daemon=True
                )
                self.loop_thread_task.start()
        
                async def _make_session():
                    return self._create_session()
        
                future = asyncio.run_coroutine_threadsafe(_make_session(), self.loop)
                self.session = future.result()
                
        return self.session
    
    def handle_exception(self, e: Exception, phase: str, url: str = "") -> Dict[str, Any]:
        """Gère les exceptions par phase"""
        return {
            'phase': phase,
            'url': url,
            'error_type': type(e).__name__,
            'error_message': str(e),
            'timestamp': time.time()
        }

    def register_close_session(self):
        atexit.register(self._close_session)

    def override_signal_handler(self, *args, **kwargs):
        signal_handler(*args, **kwargs)
        self._close_session()
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.25)
            logger.info("Session HTTP fermée")
        
    
    def _close_session(self):
        """Version synchrone pour atexit/signaux"""
        if self.loop and self.loop_thread_task:
            future = asyncio.run_coroutine_threadsafe(self.close(), self.loop)
            try:
                future.result(timeout=5)
            except Exception as e:
                logger.warning(f"Erreur en fermant la session : {e}")
    
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.loop_thread_task.join(timeout=2)
        
        elif self.session and not self.session.closed:
           logger.warning(
               "Session encore ouverte, créée sur un loop externe — fermeture différée impossible depuis un contexte sync"
           )
        else:
            pass
            # if self.session:
            #     try:
            #         loop = asyncio.new_event_loop()
            #         loop.run_until_complete(self.close())
            #         loop.close()
            #     except Exception:
            #         pass        
        
    def is_in_scope(self, url: str, allowed_domains: List[str]) -> bool:
        """Vérifie si l'URL est dans le scope autorisé"""
        if not allowed_domains:
            return True
        
        return any(
            # url.startswith(d) or
            self.analyzer_helper.crawler.parser.is_same_domain(d, url)
            for d in allowed_domains
        )

    def _get_cache_key(self, url: str, **scan_params) -> str:
        """Clé de cache incluant tous les paramètres qui influent sur le résultat"""
        import hashlib, json
        relevant = {
            "active": self.fuzzer_enabled,
            "threshold": scan_params.get("threshold"),
            "limit_vuln_for_fuzzer": scan_params.get("limit_vuln_for_fuzzer"),
            "allowed_domains": sorted(scan_params.get("allowed_domains") or []),
            "is_spa": scan_params.get("is_spa"),
            "max_test": scan_params.get("max_test"),
        }
        payload = f"{url}|{self._base_scan_key}|{json.dumps(relevant, sort_keys=True, default=str)}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def _print_start(self, url: str, scan_id: str, date: str):
        """Affiche l'en-tête du scan"""
        crawler_config = self.analyzer_helper.crawler.config
        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold cyan]🎯 SCAN ID:[/bold cyan] {scan_id}\n"
                f"[bold cyan]🌐 URL:[/bold cyan] {url}\n"
                f"[bold cyan]📅 Date:[/bold cyan] {date}\n"
                f"[bold cyan]📏 Profondeur max:[/bold cyan] {crawler_config.MAX_DEEPTH}\n"
                f"[bold cyan]📄 Pages max:[/bold cyan] {crawler_config.MAX_PAGES}\n"
                f"[bold cyan]⚡ Scan actif:[/bold cyan] {'✅ Activé' if self.fuzzer_enabled else '❌ Désactivé'}",
                title="ShieldAI ScannerAI",
                border_style="cyan"
            ))
        else:
            logger.info(f"\n{'=' * 80}")
            logger.info(f"🎯 DÉMARRAGE DU SCAN : {scan_id}")
            logger.info(f"{'=' * 80}")
            logger.info(f"URL cible      : {url}")
            logger.info(f"Date du scan   : {date}")
            logger.info(f"Profondeur max : {crawler_config.MAX_DEEPTH}")
            logger.info(f"Pages max      : {crawler_config.MAX_PAGES}")
            logger.info(f"Scan actif     : {'✅ Activé' if self.fuzzer_enabled else '❌ Désactivé'}")
            logger.info(f"{'=' * 80}\n")

    async def _run_phase(
        self,
        phase_name: str,
        coro,
        result: ScannerResult,
        errors: List[Dict],
        url: str
    ) -> Any:
        """Exécute une phase avec gestion d'erreur propre"""
        if RICH_AVAILABLE:
            console.print(f"\n[bold yellow]📡 PHASE: {phase_name}[/bold yellow]")
        else:
            logger.info(f"\n{'─' * 80}")
            logger.info(f"📡 PHASE: {phase_name}")
            logger.info(f"{'─' * 80}")
            
        start_time = time.time()

        try:
            phase_result = await coro
            elapsed = time.time() - start_time
            result.timings[phase_name] = elapsed
            result.phases_result[phase_name] = phase_result

            if RICH_AVAILABLE:
                console.print(f"[green]✅ {phase_name} terminée en {elapsed:.2f}s[/green]")
            else:
                logger.info(f"✅ {phase_name} terminée en {elapsed:.2f}s")

            return phase_result

        except asyncio.CancelledError:
            logger.warning(f"⚠️ Phase {phase_name} annulée")
            raise

        except (TimeoutError, ConnectionError, aiohttp.ClientError) as e:
            errors.append(self.handle_exception(e, phase_name, url))
            logger.error(f"❌ Erreur réseau dans {phase_name}: {e}")
            raise PhaseError(f"Erreur réseau dans {phase_name}: {e}") from e

        except ValueError as e:
            errors.append(self.handle_exception(e, phase_name, url))
            logger.error(f"❌ Erreur de données dans {phase_name}: {e}")
            raise PhaseError(f"Erreur de données dans {phase_name}: {e}") from e

        except Exception as e:
            errors.append(self.handle_exception(e, phase_name, url))
            logger.error(f"❌ Erreur inattendue dans {phase_name}: {type(e).__name__} - {e}")
            if self.debug:
                logger.error(traceback.format_exc())
            raise PhaseError(f"Erreur inattendue dans {phase_name}: {e}") from e
    
    
    def _propagate_session(self, session: aiohttp.ClientSession):
        """
        Met à jour de façon défensive la référence de session dans toute l'arborescence
        des sous-composants (Crawler, Parser, Fetcher, Fuzzer).
        """
        self.session = session
        
        # Liste de tous les composants susceptibles de porter un attribut .session
        components = []
        
        # 1. Arborescence AnalyzerHelper -> Crawler -> Parser -> Fetcher
        ah = getattr(self, "analyzer_helper", None)
        if ah is not None:
            components.append(ah)
            crawler = getattr(ah, "crawler", None)
            if crawler is not None:
                components.append(crawler)
                parser = getattr(crawler, "parser", None)
                if parser is not None:
                    components.append(parser)
                    components.append(getattr(parser, "fetcher", None))

        # 2. Arborescence Fuzzer -> Parser -> Fetcher
        fuzzer = getattr(self, "fuzzer", None)
        if fuzzer is not None:
            components.append(fuzzer)
            parser = getattr(fuzzer, "parser", None)
            if parser is not None:
                components.append(parser)
                components.append(getattr(parser, "fetcher", None))

        # 3. Application atomique sur tous les objets valides
        for comp in components:
            if comp is not None and hasattr(comp, "session"):
                try:
                    comp.session = session
                except Exception as e:
                    logger.warning(f"Impossible de propager la session sur {type(comp).__name__}: {e}")

    def _ensure_session(self) -> aiohttp.ClientSession:
        """
        Garantit qu'une session HTTP active, valide et ouverte est disponible.
        Recrée et propage automatiquement une nouvelle session si l'existante est fermée.
        """
        is_closed = True
        try:
            is_closed = (self.session is None) or self.session.closed
        except Exception:
            is_closed = True

        if is_closed:
            logger.debug("Création et propagation d'une nouvelle aiohttp.ClientSession")
            new_session = self._get_session()
            self._propagate_session(new_session)

        return self.session
    
    async def scan(
        self,
        url: str,
        fetch: bool = True,
        limit_vuln_for_fuzzer: Optional[int] = None,
        time_between_for_fuzzer: float = 0.001,
        allowed_domains: Optional[List[str]] = None,
        dynamic_timeout_for_fuzzer: bool = False,
        filename: Optional[str] = None,
        threshold: float = 0.5,
        use_cache: bool = False,
        put_result_in_cache: bool = True,
        helpers: Optional[List[callable] | List[dict] | List[HelperCall]] = None,
        raise_on_helper_error:bool = True,
        is_spa: bool = False,
        max_test: int | None = None,
        close_session: bool = True,
        *args,
        **kwargs
    ) -> ScannerResult:
        """
        Lance un scan complet sur une URL
        """
        # Normalisation URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        allowed_domains = allowed_domains or ["http://127.0.0.1", "http://localhost"]
        
        # Vérifications pré-scan
        if not self.is_in_scope(url, allowed_domains):
            raise ScopeError(f"URL {url} hors scope. Domaines autorisés: {allowed_domains}")

        if not await is_url_reachable(url, 10):
            raise UnreachableError(f"URL {url} inaccessible")

        result = ScannerResult()
        cache_key = self._get_cache_key(
            url, 
            threshold=threshold, 
            limit_vuln_for_fuzzer=limit_vuln_for_fuzzer,
            allowed_domains=allowed_domains,
            is_spa=is_spa,
            max_test=max_test
        )

        # Vérification cache
        if use_cache:
            cached = CACHE.get(cache_key)
            if cached:
                result.update_from_dict(cached)
                logger.info(f"📦 Résultat récupéré depuis le cache pour {url}")
                return result

        # Préparation scan
        scan_id = f"{url}|{datetime.now().strftime('%d/%m/%Y_%H:%M:%S')}|{str(uuid4())}"
        date = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        result.date = date
        result.cache_key = cache_key
        result.start_time = time.time()

        if not filename:
            filename = f"report_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}"
        
        self._print_start(url, scan_id, date)

        errors = []
        analyzer_helper_result = None
        passive_result = None
        code_result = None
        fuzzer_result = None
        features_data = None
        ml_predictions = None
        
        self._ensure_session()
        try:
            # ========== HELPERS (si fournie) ==========
            if helpers:
                first = helpers[0]
                if isinstance(first, (dict, HelperCall)):
                    helpers = resolve_helpers(helper_calls=helpers)
                try:
                    logger.info("🔐 Exécution Helpers...")
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
                    logger.info("✅ Exécution réussie")
                except Exception as e:
                    logger.error(f"❌ Exécution: {e}")
                    logger.error(traceback.format_exc())
                    print(traceback.format_exc())
                    if raise_on_helper_error:
                        raise
                    
            # ========== PHASE 1: CRAWL & PARSE ==========
            analyzer_helper_result = await self._run_phase(
                "analyzer_helper (crawl & parse)",
                self.analyzer_helper.analyse_and_parse_all(
                    url=url,
                    verify_reachability=True,
                    restore=self.restore,
                    fetch=fetch,
                    silent=not self.debug,
                    helpers=[],
                    raise_on_helper_error=False,
                    is_spa=is_spa,
                    semaphore=self.sem,
                ),
                result, errors, url
            )
    
            if analyzer_helper_result is None:
                logger.error("❌ Phase 1 échouée, scan interrompu")
                result.errors = errors
                return result
    
            # ========== PHASE 2: PASSIVE ANALYSIS ==========
            passive_result = await self._run_phase(
                "passive_code_analyzer",
                asyncio.to_thread(
                    self.passive_analyzer.analyse,
                    analyzer_helper_result
                ),
                result, errors, url
            )
    
            # ========== PHASE 3: CODE ANALYSIS ==========
            code_result = await self._run_phase(
                "code_analyzer",
                asyncio.to_thread(
                    self.code_analyzer.analyse,
                    analyzer_helper_result
                ),
                result, errors, url
            )
    
            # ========== PHASE 4: FUZZER ==========
            if self.fuzzer_enabled and self.fuzzer:
                fuzzer_result = await self._run_phase(
                    "fuzzer (active)",
                    self.fuzzer.fuzz(
                        base_url=url,
                        analyzer_helper_result=analyzer_helper_result,
                        limit_vuln=limit_vuln_for_fuzzer,
                        time_between=time_between_for_fuzzer,
                        dynamic_timeout=dynamic_timeout_for_fuzzer,
                        allowed_domains=allowed_domains,
                        max_test=max_test,
                    ),
                    result, errors, url
                )
            else:
                logger.info("⏭️ PHASE 4: FUZZER DÉSACTIVÉ - Utilisation du MockFuzzer")
                start_time = time.time()
                fuzzer_result = self.fuzzer_mock.simulate_scan(
                    base_url=url,
                    analyzer_helper_result=analyzer_helper_result,
                )
                result.timings["fuzzer (mock)"] = time.time() - start_time
                result.phases_result["fuzzer"] = fuzzer_result
    
            # ========== PHASE 5: FEATURES EXTRACTION ==========
            features_data = await self._run_phase(
                "features_extraction",
                self.feature_extractor.extract(
                    analyzer_helper_result=analyzer_helper_result,
                    fuzzer_result=fuzzer_result,
                    code_analyzer_result=code_result,
                    passive_analyzer_result=passive_result
                ),
                result, errors, url
            )
    
            # ========== PHASE 6: ML PREDICTIONS ==========
            if _ML_AVAILABLE and features_data is not None and not features_data.empty:
                ml_predictions = await self._run_phase(
                    "ml_predictions",
                    asyncio.to_thread(self._run_ml_predictions, features_data, threshold),
                    result, errors, url
                )
            else:
                result.phases_result["ml_predictions"] = {"proba": {}, "predict": {}}
                result.timings["ml_predictions"] = 0.0
    
            # ========== PHASE 7: REPORT GENERATION ==========
            if analyzer_helper_result and passive_result and code_result and fuzzer_result:
                await self._run_phase(
                    "report_generation",
                    self._generate_report(
                        url=url,
                        scan_id=scan_id,
                        date=date,
                        timings=result.timings,
                        analyzer_helper_result=analyzer_helper_result,
                        passive_result=passive_result,
                        code_result=code_result,
                        fuzzer_result=fuzzer_result,
                        ml_predictions=ml_predictions,
                        filename=filename
                    ),
                    result, errors, url
                )
    
            # Finalisation
            result.end_time = time.time()
            result.elapsed = sum(result.timings.values())
            result.errors = errors
    
            if not errors and put_result_in_cache:
                CACHE.set(cache_key, result.to_dict(), expire=CACHE_TIMEOUT)
    
            # Affichage résumé
            self._print_summary(result, fuzzer_result)
    
            return result
        
        except asyncio.CancelledError:
            """Annulation propre (Ctrl+C dans l'async)"""
            logger.warning(f"⚠️ Scan de {url} annulé")
            result.end_time = time.time()
            result.errors.append({
                'phase': 'scan',
                'url': url,
                'error_type': 'CancelledError',
                'error_message': 'Scan annulé par l\'utilisateur',
                'timestamp': time.time()
            })
            result.elapsed = result.end_time - result.start_time
            raise
        
        except (ConnectionError, aiohttp.ClientError, TimeoutError) as e:
            """Erreurs réseau"""
            logger.error(f"🌐 Erreur réseau pour {url}: {type(e).__name__} - {e}")
            result.end_time = time.time()
            result.errors.append({
                'phase': 'network',
                'url': url,
                'error_type': type(e).__name__,
                'error_message': str(e),
                'timestamp': time.time()
            })
            result.elapsed = result.end_time - result.start_time
            
            if RICH_AVAILABLE:
                console.print(f"[red]❌ Erreur réseau: {e}[/red]")
            
            return result
        
        except PhaseError as e:
            """Erreur pendant une phase (déjà loggée dans _run_phase)"""
            logger.error(f"🔧 Erreur phase pour {url}: {e}")
            result.end_time = time.time()
            result.errors.append({
                'phase': 'phase_execution',
                'url': url,
                'error_type': 'PhaseError',
                'error_message': str(e),
                'timestamp': time.time()
            })
            result.elapsed = result.end_time - result.start_time
            
            if RICH_AVAILABLE:
                console.print(f"[yellow]⚠️ Une phase a échoué: {e}[/yellow]")
            
            return result
        
        except MemoryError as e:
            """Erreur mémoire critique"""
            logger.critical(f"💾 Erreur mémoire pour {url}: {e}")
            result.end_time = time.time()
            result.errors.append({
                'phase': 'memory',
                'url': url,
                'error_type': 'MemoryError',
                'error_message': str(e),
                'timestamp': time.time()
            })
            
            if RICH_AVAILABLE:
                console.print("[red]💥 Erreur critique: Mémoire insuffisante[/red]")
            
            return result
        
        except ScopeError as e:
            """Hors scope - on relève, c'est une erreur utilisateur"""
            logger.error(f"🚫 Hors scope: {e}")
            # On ne retourne pas de résultat, on relève
            raise
        
        except UnreachableError as e:
            """URL inaccessible - on relève"""
            logger.error(f"🌐 Inaccessible: {e}")
            raise
        
        except Exception as e:
            """Toute autre erreur inattendue"""
            logger.exception(f"💥 Erreur inattendue pour {url}: {type(e).__name__} - {e}")
            result.end_time = time.time()
            result.errors.append({
                'phase': 'unknown',
                'url': url,
                'error_type': type(e).__name__,
                'error_message': str(e),
                'traceback': traceback.format_exc(),
                'timestamp': time.time()
            })
            result.elapsed = result.end_time - result.start_time
            
            if RICH_AVAILABLE:
                console.print(f"[red]💥 Erreur inattendue: {e}[/red]")
                if self.debug:
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
            else:
                if self.debug:
                    logger.error(traceback.format_exc())
                    # print(traceback.format_exc())
            
            return result
        
        finally:
            if close_session:
                await self.close()

    def _run_ml_predictions(self, features_df, threshold: float) -> Dict:
        """Exécute les prédictions ML (wrapper synchrone)"""
        
        self.scanner_ia.model_manager.verify_model()
        urls = features_df["url"].tolist()
        data_without_url = features_df.drop("url", axis=1)
        ml_preds = self.scanner_ia.scanner_predict(data_without_url.to_numpy(), threshold=threshold)

        return {
            k: {url: url_v for url, url_v in zip(urls, v.values())}
            for k, v in ml_preds.items()
        }

    @staticmethod
    def _combine_ml_predictions(ml_predictions: Dict) -> Dict:
        """
        Combine ml_predictions['proba'] (magnitudes, toutes classes),
        ml_predictions['predict'] (décision réelle du modèle, selon le seuil
        utilisé à l'inférence) et ml_predictions['is_safe'] (calculé une
        seule fois dans ScannerIA.scanner_predict — source de vérité unique,
        jamais recalculé côté rapport) en
        {url: {"proba": {...}, "predict": [...], "is_safe": bool}}.
        Évite que le rapport ne réinvente sa propre règle de seuil.
        """
        proba   = ml_predictions.get("proba", {})
        predict = ml_predictions.get("predict", {})
        is_safe = ml_predictions.get("is_safe", {})
        return {
            url: {
                "proba":   proba.get(url, {}),
                "predict": predict.get(url, []),
                # fallback si jamais "is_safe" est absent (ancien format) :
                # on retombe sur la même règle, mais is_safe.get(url) est
                # la source canonique tant qu'elle est présente.
                "is_safe": is_safe.get(url, len(predict.get(url, [])) == 0),
            }
            for url in proba
        }

    async def _generate_report(
        self,
        url: str,
        scan_id: str,
        date: str,
        timings: Dict,
        analyzer_helper_result: AnalyzerHelperResult,
        passive_result: PassiveAnalyzerResult,
        code_result: CodeAnalyzerResult,
        fuzzer_result: FuzzerResult,
        ml_predictions: Dict,
        filename: str
    ):
        """Génère le rapport final"""
        report = self.report_builder.build(
            url=url,
            scan_id=scan_id,
            scanner_version=__version__,
            date=date,
            timings=timings,
            analyzer_helper_result=analyzer_helper_result,
            passive_result=passive_result,
            code_result=code_result,
            fuzzer_result=fuzzer_result,
            # On transmet "proba" (magnitudes réelles) ET "predict" (la vraie
            # décision du modèle, quel que soit le seuil utilisé — flat 0.5
            # ou calibré par classe). report_builder dérive "detected" de
            # l'appartenance à "predict", jamais d'un seuil réinventé côté
            # rapport — sinon rapport et modèle peuvent se contredire dès
            # qu'un seuil par classe est introduit.
            ml_predictions=self._combine_ml_predictions(ml_predictions) if ml_predictions else {},
            theme=self.report_generator.theme
        )
        paths = self.report_generator.save_all(report, filename)
        paths = list(paths) if not isinstance(paths, str) else [paths]
        try:
            llm_path = os.path.splitext(os.path.basename(paths[0]))[0] + ".md"
            llm_dir = os.path.join(REPORT_DIR, "LLM_REPORT")
            os.makedirs(llm_dir, exist_ok=True)
            llm_path = os.path.join(llm_dir, llm_path)
            generate_report(report, llm_path)
            paths.append(llm_path)
        except Exception as e:
            logger.warning(f"⚠️ Erreur génération rapport IA: {e}")
                     
        # Unpacking défensif : save_all() peut renvoyer moins de 3 chemins
        # (ex: PDF désactivé/échoué) — un unpack strict à 3 plantait la toute
        # fin d'un scan par ailleurs réussi.
        json_path = paths[0] if len(paths) > 0 else None
        pdf_path  = paths[1] if len(paths) > 1 else None
        html_path = paths[2] if len(paths) > 2 else None
        llm_path = paths[3] if len(paths) > 3 else None
        self._last_report_paths = {
            "json": json_path,
            "html": html_path,
            "pdf":  pdf_path, 
            "llm":  llm_path, 
        }
        messages = "📄 Rapports générés:\n" 
        messages += "\n  - ".join([p for p in paths if p]) # Eviter nonetype dedans
        if RICH_AVAILABLE:
            console.print("\n[bold green]📄 Rapports générés:[/bold green]")
            for path in paths:
                console.print(f"  • [dim]{path}[/dim]")
            
            console.print(Panel(
                f"[bold green]✅ Scan terminé[/bold green]\n"
                f"📁 Dossier: {REPORT_DIR}\n"
                f"📊 Total: {len(paths)} fichiers",
                title="ShieldAI ScannerAI",
                border_style="green"
            ))
            
        else:
            logger.info(messages)
        
        return paths

    def _print_summary(self, result: ScannerResult, fuzzer_result: Optional[FuzzerResult]):
        """Affiche un résumé coloré du scan"""
        if not RICH_AVAILABLE:
            logger.info(f"Scan terminé en {result.elapsed:.2f}s")
            return

        phases = getattr(result, "phases_result", {}) or {}
        timings = getattr(result, "timings", {}) or {}

        # Tableau des timings
        time_table = Table(title="⏱️ Temps par phase", style="cyan")
        time_table.add_column("Phase", style="bold")
        time_table.add_column("Durée", justify="right")

        for phase, t in sorted(timings.items(), key=lambda x: -x[1]):
            time_table.add_row(phase, f"{t:.2f}s")

        console.print(time_table)

        # Résumé fuzzer
        if fuzzer_result and hasattr(fuzzer_result, 'stats') and fuzzer_result.stats:
            stats = fuzzer_result.stats
            vuln_table = Table(title="🐝 Vulnérabilités détectées", style="red")
            vuln_table.add_column("Type", style="bold")
            vuln_table.add_column("Occurrences", justify="right")

            for vuln, count in sorted(stats.get("vuln_count", {}).items(), key=lambda x: -x[1])[:15]:
                vuln_table.add_row(vuln, str(count))

            console.print(vuln_table)

            total_vulns = stats.get("total_vulns", 0)
            total_tests = stats.get("total_tests", 0)
            console.print(
                Panel(
                    f"[bold]📊 Statistiques fuzzer[/bold]\n"
                    f"Tests effectués: {total_tests}\n"
                    f"Vulnérabilités: {total_vulns}\n"
                    f"Taux de succès: {stats.get('success_rate', 0)*100:.1f}%",
                    border_style="yellow"
                )
            )

        # Prédictions ML
        ml_phases = phases.get("ml_predictions", {})
        proba_dict = ml_phases.get("proba", {})

        if proba_dict:
            ml_table = Table(title="🤖 Prédictions ML (Top 3 vulns)", style="magenta")
            ml_table.add_column("URL", style="bold", max_width=50)
            ml_table.add_column("Top vulnérabilités")

            for url, probs in list(proba_dict.items())[:5]:
                top3 = sorted(probs.items(), key=lambda x: -x[1])[:3]
                top3_str = "\n".join([f"  • {v}: {p*100:.1f}%" for v, p in top3])
                ml_table.add_row(url[:50], top3_str)

            console.print(ml_table)

        # Panel final
        console.print(Panel(
            f"[bold green]✅ Scan terminé en {result.elapsed:.2f}s[/bold green]\n"
            f"📁 Rapports générés dans: {REPORT_DIR}",
            title="ShieldAI ScannerAI",
            border_style="green"
        ))

    async def multi_scan(self, urls: List[str], *args, **kwargs) -> Dict[str, Any]:
        """Scan multiple en parallèle"""
        try:
            tasks = [
                asyncio.create_task(
                    self.scan(
                        url,
                        *args,
                        **{**kwargs, "close_session": False}
                    ), 
                    name=f"scan_{url}"
                )
                for url in urls
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
    
            return {
                url: result if not isinstance(result, Exception) else f"Erreur: {result}"
                for url, result in zip(urls, results)
            }
        finally:
            self._close_session()
    
    @staticmethod
    def run_in_loop(coro_func, *args, fallback_result=None, **kwargs):
        """
        Exécute une coroutine de manière synchrone.
        Prend la fonction async et ses args pour pouvoir recréer la coroutine si besoin.
        """
        try:
            return asyncio.run(coro_func(*args, **kwargs))
        
        except RuntimeError as e:
            logger.debug(f"asyncio.run failed (loop running), fallback to manual: {e}")
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro_func(*args, **kwargs))  # coroutine fraîche
            finally:
                loop.close()
        
        except KeyboardInterrupt:
            logger.warning("Opération interrompue par l'utilisateur")
            raise
        
        except Exception as e:
            logger.error(f"Operation failed: {e}")
            return fallback_result
        
    def scan_sync(self, *args, **kwargs) -> ScannerResult:
        """Version synchrone du scan"""
        return self.run_in_loop(
            self.scan, *args, **kwargs,
            fallback_result=ScannerResult()
        )

    def multi_scan_sync(self, urls: List[str], *args, **kwargs) -> Dict[str, Any]:
        """Version synchrone du multi-scan (parallèle)"""
        return self.run_in_loop(
            self.multi_scan, urls, *args, **kwargs,
            fallback_result={url: {"error": "Scan failed"} for url in urls}
        )
    
    def scan_sequential_sync(self, urls: List[str], *args, **kwargs) -> Dict[str, Any]:
        """Version synchrone - scans séquentiels"""
        kwargs["close_session"] = False
        results = {}
        try:
            for i, url in enumerate(urls, 1):
                logger.info(f"Scan {i}/{len(urls)}: {url}")
                results[url] = self.run_in_loop(self.scan, url, *args, **kwargs, fallback_result=ScannerResult())
        finally:
            self._close_session()
        return results
    
    # =========================================================================
    # CLI
    # =========================================================================
    @classmethod
    def scan_cli(cls):
        """Point d'entrée CLI avec argparse"""
        parser = argparse.ArgumentParser(
            prog="hivemind-scout",
            description="ShieldAI ScannerAI - Scanner de vulnérabilités web intelligent",
            epilog="Exemple: hivemind-scout https://example.com --active --debug"
        )
    
        # Arguments positionnels
        parser.add_argument(
            "url",
            nargs="?",
            help="URL cible à scanner"
        )
    
        # Fichier de config
        parser.add_argument(
            "-c", "--config",
            default="shieldai_scanner.config.json5",
            help="Chemin du fichier de configuration (défaut: shieldai_scanner.config.json5)"
        )
    
        # Mode scan
        parser.add_argument(
            "-a", "--active",
            action="store_true",
            default=True,
            help="Activer le scan actif (fuzzer) [défaut: activé]"
        )
        parser.add_argument(
            "--no-active",
            action="store_true",
            help="Désactiver le scan actif (mode passif uniquement)"
        )
    
        # Cache
        parser.add_argument(
            "--no-cache",
            action="store_true",
            help="Désactiver l'utilisation du cache"
        )
        parser.add_argument(
            "--clear-cache",
            action="store_true",
            help="Vider le cache avant le scan"
        )
    
        # Fuzzer
        parser.add_argument(
            "-l", "--limit-payloads",
            type=int,
            default=None,
            help="Limiter le nombre de payloads par vulnérabilité (défaut: illimité)"
        )
        parser.add_argument(
            "-mt", "--max_test",
            type=int,
            default=None,
            help="Limiter le nombre de test"
        )
        parser.add_argument(
            "--limit-vulns",
            type=int,
            default=None,
            help="Limiter le nombre de vulnérabilités à tester (défaut: toutes)"
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=0.001,
            help="Délai entre les requêtes du fuzzer (défaut: 0.001s)"
        )
        parser.add_argument(
            "--no-semantic",
            action="store_true",
            help="Désactiver l'analyse sémantique (plus rapide mais moins précis)"
        )
    
        # Scope
        parser.add_argument(
            "-d", "--domains",
            nargs="+",
            default=["http://127.0.0.1", "http://localhost"],
            help="Domaines autorisés pour le scan (défaut: localhost)"
        )
    
        # Rapports
        parser.add_argument(
            "-o", "--output",
            help="Nom du fichier de rapport (sans extension)"
        )
        parser.add_argument(
            "--theme",
            choices=["light", "dark", "multi"],
            default="multi",
            help="Thème du rapport HTML (défaut: multi)"
        )
        parser.add_argument(
            "--threshold",
            type=float,
            default=0.5,
            help="Seuil de confiance ML (0-1, défaut: 0.5)"
        )
    
        # Mode d'exécution
        parser.add_argument(
            "--parallel",
            action="store_true",
            help="Scanner plusieurs URLs en parallèle (défaut: séquentiel)"
        )
    
        # Debug
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Activer le mode debug (logs détaillés)"
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Mode silencieux (moins de logs)"
        )
    
        # Scan multiple
        parser.add_argument(
            "--urls",
            nargs="+",
            help="Scanner plusieurs URLs (sépare par des espaces)"
        )
        
        # Fuzzer
        parser.add_argument(
            "--use-arjun",
            action="store_true",
            help="Activer Arjun pour découvrir les paramètres query (plus lent mais plus complet)"
        )
        parser.add_argument(
            "--arjun-timeout",
            type=int,
            default=30,
            help="Timeout pour Arjun en secondes (défaut: 30)"
        )
        parser.add_argument(
            "--known-params-dir",
            type=str,
            default=None,
            help="Dossier contenant known_params.json pour les paramètres query personnalisés"
        )
        
        # Version
        parser.add_argument(
            "-v", "--version",
            action="version",
            version=f"ShieldAI ScannerAI v{__version__}"
        )
        parser.add_argument(
            "--is_spa",
            action="store_true",
            help="Précise si l'app est une SPA ou non"
        )
        
        args = parser.parse_args()
    
        # Gestion du cache
        if args.clear_cache:
            CACHE.clear()
            if RICH_AVAILABLE:
                console.print("[green]🧹 Cache vidé[/green]")
            else:
                print("🧹 Cache vidé")
    
        # Déterminer les URLs
        urls = []
        if args.urls:
            urls = args.urls
        elif args.url:
            urls = [args.url]
        else:
            parser.print_help()
            if RICH_AVAILABLE:
                console.print("\n[red]❌ Erreur: Veuillez spécifier une URL avec 'url' ou '--urls'[/red]")
            else:
                print("\n❌ Erreur: Veuillez spécifier une URL avec 'url' ou '--urls'")
            sys.exit(1)
    
        # Configuration du logger selon les arguments
        if args.debug:
            logger.remove()
            logger.add(sys.stdout, level="DEBUG")
        elif args.quiet:
            logger.remove()
            logger.add(sys.stdout, level="WARNING")
    
        # Bannière de démarrage
        mode_text = "Parallèle" if args.parallel else "Séquentiel"
        if RICH_AVAILABLE and not args.quiet:
            console.print(Panel(
                "[bold yellow]🐝 ShieldAI ScannerAI[/bold yellow]\n"
                f"Version {__version__}\n"
                f"URLs: {len(urls)} | Mode: {mode_text}\n"
                f"Scan actif: {'✅' if args.active and not args.no_active else '❌'}\n"
                f"Cache: {'✅' if not args.no_cache else '❌'}\n"
                f"Sémantique: {'✅' if not args.no_semantic else '❌'}",
                title="HiveMind Security",
                border_style="yellow"
            ))
        elif not args.quiet:
            print(f"\n🐝 ShieldAI ScannerAI v{__version__}")
            print(f"URLs: {len(urls)} | Mode: {mode_text}")
            print(f"Scan actif: {'✅' if args.active and not args.no_active else '❌'}")
            print(f"Cache: {'✅' if not args.no_cache else '❌'}")
            print("=" * 50)
    
        # Initialisation du scanner
        active = args.active and not args.no_active
    
        try:
            scanner = cls(
                config_path=args.config,
                active_scan=active,
                use_cache=not args.no_cache,
                debug=args.debug,
                limit_payloads=args.limit_payloads,
                use_semantic=not args.no_semantic,
                theme=args.theme,
                use_arjun=args.use_arjun,            
                arjun_timeout=args.arjun_timeout,    
                known_params_dir=args.known_params_dir,
            )
        except FileNotFoundError as e:
            if RICH_AVAILABLE:
                console.print(f"[red]❌ Erreur: {e}[/red]")
            else:
                print(f"❌ Erreur: {e}")
            sys.exit(1)
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]❌ Erreur d'initialisation: {e}[/red]")
            else:
                print(f"❌ Erreur d'initialisation: {e}")
            if args.debug:
                traceback.print_exc()
            sys.exit(1)
    
        # =========================================================
        # EXÉCUTION DES SCANS
        # =========================================================
        results = {}
    
        if len(urls) == 1:
            # Scan unique
            if RICH_AVAILABLE and not args.quiet:
                console.print(f"\n[bold cyan]📡 Scan: {urls[0]}[/bold cyan]")
            else:
                print(f"\n📡 Scan: {urls[0]}")
    
            result = scanner.scan_sync(
                url=urls[0],
                limit_vuln_for_fuzzer=args.limit_vulns,
                time_between_for_fuzzer=args.delay,
                allowed_domains=args.domains,
                dynamic_timeout_for_fuzzer=True,
                filename=args.output,
                threshold=args.threshold,
                use_cache=not args.no_cache,
                put_result_in_cache=True,
                is_spa=args.is_spa
            )
            results[urls[0]] = result
    
        elif args.parallel:
            # Mode parallèle
            if RICH_AVAILABLE:
                console.print(f"\n[bold green]🚀 Mode parallèle: {len(urls)} scans simultanés[/bold green]")
            else:
                print(f"\n🚀 Mode parallèle: {len(urls)} scans simultanés")
    
            results = scanner.multi_scan_sync(
                urls=urls,
                limit_vuln_for_fuzzer=args.limit_vulns,
                time_between_for_fuzzer=args.delay,
                allowed_domains=args.domains,
                dynamic_timeout_for_fuzzer=True,
                filename=args.output,
                threshold=args.threshold,
                use_cache=not args.no_cache,
                put_result_in_cache=True,
                is_spa=args.is_spa
            )
    
        else:
            # Mode séquentiel
            if RICH_AVAILABLE:
                console.print(f"\n[bold cyan]📡 Mode séquentiel: {len(urls)} scans un par un[/bold cyan]")
            else:
                print(f"\n📡 Mode séquentiel: {len(urls)} scans un par un")
    
            results = scanner.scan_sequential_sync(
                urls=urls,
                limit_vuln_for_fuzzer=args.limit_vulns,
                time_between_for_fuzzer=args.delay,
                allowed_domains=args.domains,
                dynamic_timeout_for_fuzzer=True,
                filename=args.output,
                threshold=args.threshold,
                use_cache=not args.no_cache,
                put_result_in_cache=True,
                is_spa=args.is_spa
            )
    
        # =========================================================
        # RÉSUMÉ FINAL (pour multi-scans)
        # =========================================================
        if len(urls) > 1:
            if RICH_AVAILABLE:
                console.print("\n" + "═" * 60)
                console.print("[bold]📊 RÉSUMÉ DES SCANS[/bold]")
                console.print("═" * 60)
                
                for url, res in results.items():
                    if isinstance(res, dict) and "error" in res:
                        console.print(f"  [red]❌[/red] {url[:60]}: {res['error'][:50]}")
                    elif hasattr(res, 'error') and res.error:
                        console.print(f"  [red]❌[/red] {url[:60]}: {res.error[:50]}")
                    else:
                        pages = len(res.phases_result.get('analyzer_helper (crawl & parse)', {}).get('elements', {}))
                        vulns = res.phases_result.get('fuzzer', {}).stats.get('total_vulns', 0) if res.phases_result.get('fuzzer') else 0
                        console.print(f"  [green]✅[/green] {url[:60]}: {pages} pages, {vulns} vulns")
            else:
                print("\n" + "=" * 60)
                print("📊 RÉSUMÉ DES SCANS")
                print("=" * 60)
                for url, res in results.items():
                    if isinstance(res, dict) and "error" in res:
                        print(f"  ❌ {url[:60]}: {res['error'][:50]}")
                    elif hasattr(res, 'error') and res.error:
                        print(f"  ❌ {url[:60]}: {res.error[:50]}")
                    else:
                        pages = len(res.phases_result.get('analyzer_helper (crawl & parse)', {}).get('elements', {}))
                        vulns = res.phases_result.get('fuzzer', {}).stats.get('total_vulns', 0) if res.phases_result.get('fuzzer') else 0
                        print(f"  ✅ {url[:60]}: {pages} pages, {vulns} vulns")
    
        return results

def test():
    from pathlib import Path
    CACHE.clear()
    # ── 1. Configuration ─────────────────────────────────────────────────
    CONFIG_PATH = "shieldai_scanner.config.json5"          # À adapter si besoin
    MODEL_DIR   = "model_scanner_chain_mvp"       # Modèle fraîchement entraîné
    TARGET_URL  = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

    # Vérifications rapides
    if not Path(CONFIG_PATH).exists():
        print(f"❌ Fichier de config introuvable : {CONFIG_PATH}")
        sys.exit(1)
    
    # ── 2. Instanciation du Scanner ──────────────────────────────────────
    print("\n🔧 Initialisation du scanner...")
    scanner = Scanner(
        config_path = CONFIG_PATH,
        active_scan = True,                # Fuzzer actif pour avoir les flags fuzzer_*
        use_cache   = False,               # Pas de cache pour un test frais
        debug       = True,
        semaphore   = 10,                  # Concurrence modérée
        limit_payloads = 3,                # Limiter le fuzzer pour ce test (None = tout)
        model_dir   = MODEL_DIR,           # Dossier du modèle MVP
    )

    # ── 3. Scan ──────────────────────────────────────────────────────────
    print(f"🎯 Lancement du scan sur {TARGET_URL}")
    result = scanner.scan_sync(
        url                  = TARGET_URL,
        fetch                = True,
        limit_vuln_for_fuzzer= None,       # Tester toutes les vulns (si limit_payloads=3 c'est déjà limité)
        time_between_for_fuzzer = 0.01,
        dynamic_timeout_for_fuzzer = True,
    )

    # ── 4. Affichage des résultats ───────────────────────────────────────
    print("\n" + "="*70)
    print("📊 RÉSULTATS DU SCAN")
    print("="*70)

    if result is None:
        print("❌ Le scan a échoué.")
        sys.exit(1)

    # Phases
    phases = getattr(result, "phases_result", {}) or {}
    timings = getattr(result, "timings", {}) or {}

    print("\n⏱️  Timings :")
    for phase, t in timings.items():
        print(f"   {phase:<40} : {t:.2f}s")

    # Prédictions ML
    ml_preds = phases.get("scanner_ia_preds", {})
    proba_dict = ml_preds.get("proba", {})
    predict_dict = ml_preds.get("predict", {})

    if proba_dict:
        print(f"\n🤖 Prédictions ML ({len(proba_dict)} pages) :")
        for url, probs in proba_dict.items():
            top5 = sorted(probs.items(), key=lambda x: -x[1])[:5]
            predicted = predict_dict.get(url, [])
            safe_prob = probs.get("SAFE", 0.0)
            
            status = "🟢 SAFE" if safe_prob > 0.5 else "🔴 VULNÉRABLE"
            print(f"\n   {url}")
            print(f"   Statut : {status} (SAFE={safe_prob:.3f})")
            print("   Top 5 :")
            for vuln, prob in top5:
                marker = "✅" if vuln in predicted else "  "
                print(f"      {marker} {vuln:<25} : {prob:.3f}")
    
    # Rapport
    report_paths = phases.get("report", {})
    if report_paths:
        print("\n📄 Rapports générés :")
        for fmt, path in report_paths.items():
            print(f"   {fmt} : {path}")

    # Résumé fuzzer
    fuzzer = phases.get("fuzzer")
    if fuzzer:
        stats = getattr(fuzzer, "stats", {}) or {}
        print("\n⚡ Fuzzer :")
        print(f"   Tests total : {stats.get('total_tests', 0)}")
        print(f"   Vulns trouvées : {stats.get('total_vulns', 0)}")
        vuln_count = stats.get("vuln_count", {})
        if vuln_count:
            print("   Distribution :")
            for vn, cnt in sorted(vuln_count.items(), key=lambda x: -x[1])[:10]:
                print(f"      {vn:<25} : {cnt}")

    print("\n✅ Scan terminé.")

# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
if __name__ == "__main__":
    apply()

    # pass
    # Scanner.scan_cli()