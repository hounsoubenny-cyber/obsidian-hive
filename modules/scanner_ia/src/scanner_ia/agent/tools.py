#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — Tools CrewAI pour l'agent Scanner (version complète).
Permet un contrôle granulaire ET des actions haut niveau.
Auteur: HOUNSOU Samuel
"""

import os
import sys
import json
import time
import inspect
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
import pandas as pd
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from scanner_ia.main_scanner import Scanner
from scanner_ia.fuzzer.active_fuzzer import Fuzzer
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult
from scanner_ia.base_class.code_analyse_base_class import CodeAnalyzerResult
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.base_class.main_scanner_base_class import ScannerResult
from scanner_ia.core.crawler import Config as CrawlerConfig
from scanner_ia.scanner_utils.logger import get_logger
from modules_utils.loop_utils import _run_async
from scanner_ia.scanner_utils.helpers.helpers_registry import list_helpers, get
from scanner_ia.config_manager import DEFAULT_CONFIG_PATH
logger = get_logger()

# ============================================================================
# INPUT SCHEMAS
# ============================================================================

class UrlInput(BaseModel):
    url: str = Field(description="URL cible")

class AnalyzeAndParseOnlyInput(BaseModel):
    url: str = Field(description="URL de départ à crawler")
    max_depth: int = Field(default=2, ge=1, le=10, description="Profondeur max")
    max_pages: int = Field(default=50, ge=1, le=500, description="Pages max")
    use_cache: bool = Field(default=True, description="Utiliser le cache")
    restore: bool = Field(default=False, description="Restaurer un crawl précédent")
    allowed_domains: Optional[List[str]] = Field(default=None, description="Domaines autorisés")
    is_spa: bool = Field(default=False, description="Site SPA (utiliser Playwright)")
    fetch: bool = Field(default=True, description="Fetcher les script JS externe")
    silent: bool = Field(default=True, description="Ne pas afficher les logs du parser")
    helpers: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="""Liste des helpers d'authentification. Exemple: 
        [
            {"name": "dvwa_auth", "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "password"}},
            {"name": "bearer_token", "kwargs": {"token": "eyJ..."}}
        ]"""
    )
    raise_on_helper_error: bool = Field(default=True, description="Lever une erreur si un helper échoue")


class PassiveAnalyzeOnlyInput(BaseModel):
    url: str = Field(description="URL cible")
    use_cache: bool = Field(default=True)

class CodeAnalyzeOnlyInput(BaseModel):
    url: str = Field(description="URL cible")
    use_cache: bool = Field(default=True)

class FuzzerOnlyInput(BaseModel):
    url: str = Field(description="URL de base")
    limit_vuln: Optional[int] = Field(default=None, description="Limite de vulnérabilités à tester")
    limit_payloads: Optional[int] = Field(default=None, description="Limite de payloads par vuln")
    max_test: Optional[int] = Field(default=None, description="Nombre max de test à faire")
    time_between: float = Field(default=0.001, ge=0, le=1.0, description="Délai entre requêtes")
    dynamic_timeout: bool = Field(default=True)
    vuln_names: Optional[List[str]] = Field(default=None, description="Liste des vulnérabilités à cibler")
    use_cache: bool = Field(default=True)

class FeaturesExtractOnlyInput(BaseModel):
    url: str = Field(description="URL cible")
    use_cache: bool = Field(default=True)

class MLPredictOnlyInput(BaseModel):
    url: str = Field(description="URL cible")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    use_cache: bool = Field(default=True)

class ConfigureScannerInput(BaseModel):
    param: str = Field(description="Nom du paramètre à modifier")
    value: Any = Field(description="Nouvelle valeur")
    module: Literal["crawler", "fetcher", "analyzer_helper", "fuzzer", "scanner"] = Field(default="scanner")

class GetPhaseResultInput(BaseModel):
    url: str = Field(description="URL cible")
    phase: Literal[
        "analyzer_helper", "passive", "code", "fuzzer", "features", "ml"
    ] = Field(description="Phase à consulter")
    n: int = Field(default=10, description="Nombre max de lignes pour le résulats")

class ListCachedScansInput(BaseModel):
    limit: int = Field(default=20)

class StartScanInput(BaseModel):
    url: str = Field(description="URL cible à scanner")
    active_scan: bool = Field(default=True, description="Activer le scan actif")
    use_cache: bool = Field(default=True, description="Utiliser le cache")
    limit_payloads: Optional[int] = Field(default=None, description="Limite de payloads")
    max_depth: Optional[int] = Field(default=None, description="Profondeur max")
    max_pages: Optional[int] = Field(default=None, description="Pages max")
    allowed_domains: Optional[List[str]] = Field(default=None, description="Domaines autorisés")
    threshold: float = Field(default=0.5, description="Seuil ML")
    helpers: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="""Liste des helpers d'authentification. Exemple: 
        [
            {"name": "dvwa_auth", "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "password"}},
            {"name": "bearer_token", "kwargs": {"token": "eyJ..."}}
        ]"""
    )
    raise_on_helper_error: bool = Field(default=True, description="Lever une erreur si un helper échoue")
    max_test: Optional[int] = Field(default=None, description="Nombre max de test à faire")


class GetVulnerabilitiesInput(BaseModel):
    scan_id: Optional[str] = Field(default=None, description="ID du scan (optionnel)")

class GetReportPathsInput(BaseModel):
    scan_id: Optional[str] = Field(default=None)

class GetFeaturesInput(BaseModel):
    scan_id: Optional[str] = Field(default=None)

class ScanStatusInput(BaseModel):
    scan_id: str = Field(description="ID du scan")

class ListHelpersInput(BaseModel):
    """Pas de paramètres requis."""
    placeholder: str = Field(default="", description="Params factice, pas de params requis")

class GetHelperInfoInput(BaseModel):
    name: str = Field(
        description="Nom du helper à consulter. Exemple: 'dvwa_auth', 'form_login', 'bearer_token'"
    )
    
# ============================================================================
# STATE MANAGER
# ============================================================================

class ScannerStateManager:
    """Gère l'état des scans et les résultats intermédiaires."""
    _instances: Dict[str, 'ScannerStateManager'] = {}
    _scanner_instance: Optional[Scanner] = None
    _last_scan_result: Optional[ScannerResult] = None
    _last_scan_id: Optional[str] = None

    def __init__(self, url: str):
        self.url = url
        self.analyzer_helper_result: Optional[AnalyzerHelperResult] = None
        self.passive_result: Optional[PassiveAnalyzerResult] = None
        self.code_result: Optional[CodeAnalyzerResult] = None
        self.fuzzer_result: Optional[FuzzerResult] = None
        self.features_df: Optional[pd.DataFrame] = None
        self.ml_predictions: Optional[Dict] = None
        self.last_updated: float = 0.0

    @classmethod
    def get_instance(cls, url: str) -> 'ScannerStateManager':
        if url not in cls._instances:
            cls._instances[url] = cls(url)
        return cls._instances[url]

    @classmethod
    def get_or_create_scanner(cls, config_path: str = DEFAULT_CONFIG_PATH, **kwargs) -> Scanner:
        if cls._scanner_instance is None:
            cls._scanner_instance = Scanner(
                config_path=config_path,
                active_scan=kwargs.get("active_scan", True),
                use_cache=kwargs.get("use_cache", True),
                debug=kwargs.get("debug", False),
                limit_payloads=kwargs.get("limit_payloads", None),
                use_semantic=kwargs.get("use_semantic", True),
            )
        return cls._scanner_instance

    @classmethod
    def set_last_result(cls, result: ScannerResult, scan_id: str):
        cls._last_scan_result = result
        cls._last_scan_id = scan_id

    @classmethod
    def get_last_result(cls) -> Optional[ScannerResult]:
        return cls._last_scan_result

    @classmethod
    def get_last_scan_id(cls) -> Optional[str]:
        return cls._last_scan_id

    def update(self, phase: str, result):
        setattr(self, f"{phase}_result", result)
        self.last_updated = time.time()

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "has_analyzer_helper": self.analyzer_helper_result is not None,
            "has_passive": self.passive_result is not None,
            "has_code": self.code_result is not None,
            "has_fuzzer": self.fuzzer_result is not None,
            "has_features": self.features_df is not None,
            "has_ml": self.ml_predictions is not None,
            "last_updated": datetime.fromtimestamp(self.last_updated).isoformat(),
        }


# ============================================================================
# TOOL 1: AnalyzeAndParse ONLY
# ============================================================================

class AnalyzeAndParseOnly(BaseTool):
    name: str = "analyzer_helper_only"
    description: str = """
Lance UNIQUEMENT la phase de crawl et parsing sur une URL.
Retourne le nombre de pages crawlées et la liste des URLs trouvées.
"""
    args_schema: type[BaseModel] = AnalyzeAndParseOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = AnalyzeAndParseOnlyInput(**kwargs)
        scanner = ScannerStateManager.get_or_create_scanner()
        
        max_depth_backup = CrawlerConfig.MAX_DEEPTH
        max_pages_backup = CrawlerConfig.MAX_PAGES
        if inp.max_depth:
            CrawlerConfig.MAX_DEEPTH = inp.max_depth
        if inp.max_pages:
            CrawlerConfig.MAX_PAGES = inp.max_pages

        try:
            result = await scanner.analyzer_helper.analyse_and_parse_all(
                url=inp.url,
                verify_reachability=True,
                restore=inp.restore,
                fetch=inp.fetch,
                silent=inp.silent,
                is_spa=inp.is_spa,
                helpers=inp.helpers,          
                raise_on_helper_error=inp.raise_on_helper_error,
            )
            state = ScannerStateManager.get_instance(inp.url)
            state.update("analyzer_helper", result)
            
            return json.dumps({
                "status": "success",
                "pages_crawled": len(result.elements),
                "elapsed": result.elapsed,
                "top_urls": list(result.elements.keys())[:5],
                # "result": result.to_dict()
            }, ensure_ascii=False, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})
        
        finally:
            CrawlerConfig.MAX_DEEPTH = max_depth_backup
            CrawlerConfig.MAX_PAGES = max_pages_backup

# ============================================================================
# TOOL 2: PASSIVE ANALYZE ONLY
# ============================================================================

class PassiveAnalyzeOnly(BaseTool):
    name: str = "passive_analyze_only"
    description: str = """
Analyse passive (headers, cookies, formulaires) à partir d'un crawl existant.
"""
    args_schema: type[BaseModel] = PassiveAnalyzeOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = PassiveAnalyzeOnlyInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)
        scanner = ScannerStateManager.get_or_create_scanner()

        if state.analyzer_helper_result is None:
            crawler = AnalyzeAndParseOnly()
            await crawler._arun(url=inp.url, use_cache=inp.use_cache)

        result = scanner.passive_analyzer.analyse(state.analyzer_helper_result)
        state.update("passive", result)

        vuln_breakdown = {}
        for page in result.pages.values():
            for v in page._all_vulns() if hasattr(page, "_all_vulns") else []:
                tag = getattr(v, "tag", "other")
                vuln_breakdown[tag] = vuln_breakdown.get(tag, 0) + 1

        return json.dumps({
            "status": "success",
            "total_vulns": result.total_vulns,
            "vuln_breakdown": vuln_breakdown,
            "critical_count": result.summary.get("critical", 0),
            "high_count": result.summary.get("high", 0),
        }, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 3: CODE ANALYZE ONLY
# ============================================================================

class CodeAnalyzeOnly(BaseTool):
    name: str = "code_analyze_only"
    description: str = """
Analyse statique du code HTML/JS via signatures regex.
"""
    args_schema: type[BaseModel] = CodeAnalyzeOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = CodeAnalyzeOnlyInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)
        scanner = ScannerStateManager.get_or_create_scanner()

        if state.analyzer_helper_result is None:
            return json.dumps({"status": "error", "error": "Lancez analyzer_helper_only d'abord"})

        result = scanner.code_analyzer.analyse(state.analyzer_helper_result)
        state.update("code", result)

        total_body = sum(len(r.get("body", {}).vulns) for r in result.results.values())
        total_scripts = sum(
            sum(len(s.vulns) for s in r.get("balises_script", {}).values())
            for r in result.results.values()
        )

        return json.dumps({
            "status": "success",
            "total_vulns_body": total_body,
            "total_vulns_scripts": total_scripts,
        }, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 4: FUZZER ONLY
# ============================================================================

class FuzzerOnly(BaseTool):
    name: str = "fuzzer_only"
    description: str = """
Lance le fuzzer actif sur une URL déjà crawlée.
Peut cibler des vulnérabilités spécifiques via vuln_names.
"""
    args_schema: type[BaseModel] = FuzzerOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = FuzzerOnlyInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)
        scanner = ScannerStateManager.get_or_create_scanner()

        if state.analyzer_helper_result is None:
            return json.dumps({"status": "error", "error": "Lancez analyzer_helper_only d'abord"})
        
        fuzzer = scanner.fuzzer or Fuzzer(
            session=scanner.session,
            debug=scanner.debug,
            limit=inp.limit_payloads,
            use_semantic=True,
        )

        limit_backup = scanner.fuzzer.payload_generator.limit
        if inp.limit_payloads:
            scanner.fuzzer.payload_generator.limit = inp.limit_payloads

        result = await fuzzer.fuzz(
            base_url=inp.url,
            analyzer_helper_result=state.analyzer_helper_result,
            limit_vuln=inp.vuln_names or inp.limit_vuln,
            time_between=inp.time_between,
            dynamic_timeout=inp.dynamic_timeout,
            max_test=inp.max_test,
        )
        state.update("fuzzer", result)
        scanner.fuzzer.payload_generator.limit = limit_backup
        return json.dumps({
            "status": "success",
            "total_tests": result.stats.get("total_tests", 0),
            "total_vulns": result.stats.get("total_vulns", 0),
            "vuln_count": result.stats.get("vuln_count", {}),
        }, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 5: FEATURES EXTRACT ONLY
# ============================================================================

class FeaturesExtractOnly(BaseTool):
    name: str = "features_extract_only"
    description: str = """
Extrait les features ML à partir des phases précédentes.
Nécessite crawl, passive, code et fuzzer.
"""
    args_schema: type[BaseModel] = FeaturesExtractOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = FeaturesExtractOnlyInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)
        scanner = ScannerStateManager.get_or_create_scanner()

        required = ["analyzer_helper", "passive", "code", "fuzzer"]
        missing = [p for p in required if getattr(state, f"{p}_result") is None]
        if missing:
            return json.dumps({"status": "error", "error": f"Phases manquantes : {missing}"})

        df = await scanner.feature_extractor.extract(
            analyzer_helper_result=state.analyzer_helper_result,
            passive_analyzer_result=state.passive_result,
            code_analyzer_result=state.code_result,
            fuzzer_result=state.fuzzer_result,
        )
        state.features_df = df

        return json.dumps({
            "status": "success",
            "num_features": df.shape[1],
            "num_samples": df.shape[0],
            "feature_names": list(df.columns),
        }, default=str, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 6: ML PREDICT ONLY
# ============================================================================

class MLPredictOnly(BaseTool):
    name: str = "ml_predict_only"
    description: str = """
Lance la prédiction ML multi-label sur les features extraites.
"""
    args_schema: type[BaseModel] = MLPredictOnlyInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = MLPredictOnlyInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)
        scanner = ScannerStateManager.get_or_create_scanner()

        if state.features_df is None:
            return json.dumps({"status": "error", "error": "Lancez features_extract_only d'abord"})

        scanner.scanner_ia.model_manager.verify_model()
        urls = state.features_df["url"].tolist()
        X = state.features_df.drop("url", axis=1).to_numpy()
        ml_preds = scanner.scanner_ia.scanner_predict(X, threshold=inp.threshold)

        state.ml_predictions = ml_preds

        return json.dumps({
            "status": "success",
            "predictions": ml_preds.get("proba_predict", {}),
            "safe_urls": [url for url, pred in ml_preds.get("predict", {}).items() if "SAFE" in pred],
            "urls": urls,
        }, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 7: CONFIGURE SCANNER
# ============================================================================

class ConfigureScanner(BaseTool):
    name: str = "configure_scanner"
    description: str = """
Modifie un paramètre de configuration à chaud.
Ex: configure_scanner(param="MAX_DEEPTH", value=5, module="crawler")
"""
    args_schema: type[BaseModel] = ConfigureScannerInput

    def _run(self, **kwargs) -> str:
        inp = ConfigureScannerInput(**kwargs)
        scanner = ScannerStateManager.get_or_create_scanner()

        module_map = {
            "crawler": ("scanner_ia.core.crawler", "Config"),
            "fetcher": ("scanner_ia.core.fetcher", "Config"),
            "analyzer_helper": ("scanner_ia.core.analyzer_helper", "Config"),
            "fuzzer": ("scanner_ia.fuzzer.active_fuzzer", "Config"),
            "scanner": None,
        }

        if inp.module == "scanner":
            if hasattr(scanner, inp.param):
                setattr(scanner, inp.param, inp.value)
                return json.dumps({"status": "success", "message": f"scanner.{inp.param} = {inp.value}"})
        else:
            try:
                mod_name, cls_name = module_map[inp.module]
                import importlib
                module = importlib.import_module(mod_name)
                config_cls = getattr(module, cls_name)
                if hasattr(config_cls, inp.param):
                    setattr(config_cls, inp.param, inp.value)
                    return json.dumps({"status": "success", "message": f"{cls_name}.{inp.param} = {inp.value}"})
            except Exception as e:
                return json.dumps({"status": "error", "message": str(e)})

        return json.dumps({"status": "error", "message": f"Paramètre {inp.param} non trouvé"})


# ============================================================================
# TOOL 8: GET PHASE RESULT
# ============================================================================

class GetPhaseResult(BaseTool):
    name: str = "get_phase_result"
    description: str = """
Récupère le résultat d'une phase déjà exécutée.
"""
    args_schema: type[BaseModel] = GetPhaseResultInput

    def _run(self, **kwargs) -> str:
        inp = GetPhaseResultInput(**kwargs)
        state = ScannerStateManager.get_instance(inp.url)

        result_obj = getattr(state, f"{inp.phase}_result", None)
        if result_obj is None:
            return json.dumps({"status": "error", "error": f"Phase {inp.phase} non exécutée"})

        if inp.phase == "analyzer_helper":
            return json.dumps({"status": "success", "result": state.analyzer_helper_result.to_dict(True)})
        elif inp.phase == "passive":
            return json.dumps({"status": "success", "result": state.passive_result.to_dict(True)})
        elif inp.phase == "code":
            return json.dumps({"status": "success", "result": state.code_result.to_dict(True)})
        elif inp.phase == "fuzzer":
            return json.dumps({"status": "success", "result": state.fuzzer_result.to_dict(True)})
        elif inp.phase == "features":
            if state.features_df is None:
                return json.dumps({"status": "success", "result": None})
            return json.dumps(
                {
                    "status": "success", 
                    "shape": state.features_df.shape,
                    "result": state.features_df.to_dict(orient="records")[:inp.n or 10]
                }
            )
        elif inp.phase == "ml":
            if state.ml_predictions is None:
                return json.dumps(
                    {
                        "status": "success",
                        "predictions": None
                    }
                )
            result = {}
            for k, v in state.ml_predictions.items():
                if isinstance(v, list):
                    result[k] = v[:inp.n]
                elif isinstance(v, dict):
                    keys = list(v.keys())[:inp.n]
                    values = {i:v[i] for i in keys}
                    result[k] = values
                
                else:
                    result[k] = v
                    
            return json.dumps(
                {
                    "status": "success", 
                    "predictions": result
                }
            )

        return json.dumps({"status": "error", "error": f"Phase inconnue: {inp.phase}"})


# ============================================================================
# TOOL 9: LIST CACHED SCANS
# ============================================================================

class ListCachedScans(BaseTool):
    name: str = "list_cached_scans"
    description: str = """
Liste toutes les URLs pour lesquelles un état de scan existe.
"""
    args_schema: type[BaseModel] = ListCachedScansInput

    def _run(self, **kwargs) -> str:
        inp = ListCachedScansInput(**kwargs)
        states = ScannerStateManager._instances
        limited = dict(list(states.items())[:inp.limit])
        return json.dumps({
            "status": "success",
            "total": len(states),
            "scans": {url: state.to_dict() for url, state in limited.items()}
        }, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 10: RESET SCAN STATE
# ============================================================================

class ResetScanState(BaseTool):
    name: str = "reset_scan_state"
    description: str = """
Supprime l'état d'un scan pour une URL.
"""
    args_schema: type[BaseModel] = UrlInput

    def _run(self, **kwargs) -> str:
        url = kwargs.get("url")
        if url in ScannerStateManager._instances:
            del ScannerStateManager._instances[url]
            return json.dumps({"status": "success", "message": f"État supprimé pour {url}"})
        return json.dumps({"status": "error", "message": f"Aucun état pour {url}"})


# ============================================================================
# TOOL 11: START SCAN (haut niveau)
# ============================================================================

class StartScan(BaseTool):
    name: str = "start_scan"
    description: str = """
Lance un scan complet (toutes phases) sur une URL.
C'est l'outil principal pour un audit de sécurité complet.
"""
    args_schema: type[BaseModel] = StartScanInput

    def _run(self, **kwargs) -> str:
        return _run_async(self._arun, **kwargs)

    async def _arun(self, **kwargs) -> str:
        inp = StartScanInput(**kwargs)
        scanner = ScannerStateManager.get_or_create_scanner(
            active_scan=inp.active_scan,
            use_cache=inp.use_cache,
            limit_payloads=inp.limit_payloads,
        )
        max_depth = CrawlerConfig.MAX_DEEPTH
        max_pages = CrawlerConfig.MAX_PAGES
        try:
            if inp.max_depth:
                CrawlerConfig.MAX_DEEPTH = inp.max_depth
            if inp.max_pages:
                CrawlerConfig.MAX_PAGES = inp.max_pages
    
            result = await scanner.scan(
                url=inp.url,
                allowed_domains=inp.allowed_domains,
                threshold=inp.threshold,
                use_cache=inp.use_cache,
                put_result_in_cache=True,
                helpers=inp.helpers,           
                raise_on_helper_error=inp.raise_on_helper_error,
                max_test=inp.max_test,
            )
    
            scan_id = f"{inp.url}|{datetime.now().strftime('%Y%m%d%H%M%S')}"
            ScannerStateManager.set_last_result(result, scan_id)
    
            phases = getattr(result, "phases_result", {}) or {}
            fuzzer = phases.get("fuzzer")
            stats = getattr(fuzzer, "stats", {}) if fuzzer else {}
    
            return json.dumps({
                "status": "success" if not result.errors else "partial",
                "scan_id": scan_id,
                "elapsed": result.elapsed,
                "total_vulns": stats.get("total_vulns", 0),
                "vuln_count": stats.get("vuln_count", {}),
                "pages_crawled": len(phases.get("analyzer_helper(crawl_and_parse)", {}).get("elements", {})),
            }, ensure_ascii=False, indent=2)
        finally:
            CrawlerConfig.MAX_DEEPTH = max_depth
            CrawlerConfig.MAX_PAGES = max_pages


# ============================================================================
# TOOL 12: GET VULNERABILITIES
# ============================================================================

class GetVulnerabilities(BaseTool):
    name: str = "get_vulnerabilities"
    description: str = """
Récupère la liste des vulnérabilités détectées lors du dernier scan.
"""
    args_schema: type[BaseModel] = GetVulnerabilitiesInput

    def _run(self, scan_id: Optional[str] = None) -> str:
        result = ScannerStateManager.get_last_result()
        if result is None:
            return json.dumps({"error": "Aucun scan effectué"})

        phases = getattr(result, "phases_result", {}) or {}
        fuzzer = phases.get("fuzzer")
        if not fuzzer or not hasattr(fuzzer, "stats"):
            return json.dumps({"vulnerabilities": []})

        stats = fuzzer.stats
        vuln_count = stats.get("vuln_count", {})

        def severity(v):
            high = {"SQLi", "CMDi", "XSS", "SSTI", "XXE", "SSRF"}
            medium = {"IDOR", "CSRF", "NoSQLi", "CORS", "OpenRedirect"}
            return "critique" if v in high else "moyen" if v in medium else "faible"

        vulns = [{"name": k, "count": v, "severity": severity(k)} for k, v in vuln_count.items()]
        return json.dumps({"total": len(vulns), "vulnerabilities": vulns}, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 13: GET REPORT PATHS
# ============================================================================

class GetReportPaths(BaseTool):
    name: str = "get_report_paths"
    description: str = """
Retourne les chemins des rapports générés.
"""
    args_schema: type[BaseModel] = GetReportPathsInput

    def _run(self, scan_id: Optional[str] = None) -> str:
        result = ScannerStateManager.get_last_result()
        if result is None:
            return json.dumps({"error": "Aucun scan effectué"})
        phases = getattr(result, "phases_result", {}) or {}
        return json.dumps(phases.get("report_generation", {}), ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 14: GET FEATURES
# ============================================================================

class GetFeatures(BaseTool):
    name: str = "get_features"
    description: str = """
Retourne les features ML extraites sous forme JSON.
"""
    args_schema: type[BaseModel] = GetFeaturesInput

    def _run(self, scan_id: Optional[str] = None) -> str:
        result = ScannerStateManager.get_last_result()
        if result is None:
            return json.dumps({"error": "Aucun scan effectué"})
        phases = getattr(result, "phases_result", {}) or {}
        df = phases.get("features_extraction")
        if df is None:
            return json.dumps({"error": "Features non disponibles"})
        return json.dumps({
            "columns": list(df.columns),
            "data": df.head(10).to_dict(orient="records")
        }, default=str, ensure_ascii=False, indent=2)


# ============================================================================
# TOOL 15: GET SCAN STATUS
# ============================================================================

class GetScanStatus(BaseTool):
    name: str = "get_scan_status"
    description: str = """
Retourne l'état du dernier scan.
"""
    args_schema: type[BaseModel] = ScanStatusInput

    def _run(self, scan_id: str) -> str:
        last_id = ScannerStateManager.get_last_scan_id()
        if scan_id != last_id:
            return json.dumps({"status": "unknown", "message": "ID non reconnu"})
        result = ScannerStateManager.get_last_result()
        if result is None:
            return json.dumps({"status": "unknown"})
        return json.dumps({
            "status": "completed",
            "elapsed": result.elapsed,
            "errors": len(result.errors),
        })

class ListHelpers(BaseTool):
    name: str = "list_helpers"
    description: str = """
    📌 QUAND L'UTILISER :
    - Quand l'utilisateur demande "quels helpers sont disponibles ?"
    - Pour savoir quelles authentifications sont possibles avant un scan
    - Pour explorer les capacités du scanner

    📤 RETOUR (JSON) :
    {
        "total": 25,
        "helpers": [
            {
                "name": "dvwa_auth",
                "description": "Auth DVWA (login + set security level)",
                "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "password"}
            },
            ...
        ]
    }
    """
    args_schema: type[BaseModel] = ListHelpersInput

    def _run(self, **kwargs) -> str:
        helpers = list_helpers()
        return json.dumps({
            "total": len(helpers),
            "helpers": helpers
        }, ensure_ascii=False, indent=2)

    async def _arun(self, **kwargs) -> str:
        return self._run(**kwargs)


class GetHelperInfo(BaseTool):
    name: str = "get_helper_info"
    description: str = """
    📌 QUAND L'UTILISER :
    - Pour savoir exactement comment utiliser un helper
    - Pour connaître les paramètres requis d'un helper spécifique
    - Avant de configurer un scan avec authentification

    📥 PARAMÈTRES (JSON) :
    {
        "name": "dvwa_auth"   // Nom du helper
    }

    📤 RETOUR (JSON) :
    {
        "name": "dvwa_auth",
        "description": "Auth complète DVWA (login + set security level)",
        "signature": "dvwa_auth(session, base_url, username='admin', password='password', security_level='low')",
        "required_kwargs": ["base_url"],
        "optional_kwargs": [
            {"name": "username", "default": "admin"},
            {"name": "password", "default": "password"},
            {"name": "security_level", "default": "low"}
        ],
        "example": {
            "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "password"}
        }
    }
    """
    args_schema: type[BaseModel] = GetHelperInfoInput

    def _run(self, name: str, **kwargs) -> str:
        try:
            func = get(name)
            sig = inspect.signature(func)
            
            required = []
            optional = []
            for param in sig.parameters.values():
                if param.default == inspect.Parameter.empty:
                    required.append(param.name)
                else:
                    optional.append({
                        "name": param.name,
                        "default": str(param.default)
                    })
            
            # Récupère la description depuis list_helpers
            helpers = list_helpers()
            desc = ""
            for h in helpers:
                if h["name"] == name:
                    desc = h.get("description", "")
                    break
            
            # Exemple auto-généré
            example_kwargs = {}
            for opt in optional:
                if opt["name"] != "session":
                    example_kwargs[opt["name"]] = opt["default"]
            
            return json.dumps({
                "name": name,
                "description": desc or func.__doc__ or "",
                "signature": f"{name}({', '.join(sig.parameters.keys())})",
                "required_kwargs": required,
                "optional_kwargs": optional,
                "example": {"kwargs": example_kwargs} if example_kwargs else {}
            }, ensure_ascii=False, indent=2)
            
        except KeyError:
            return json.dumps({"error": f"Helper '{name}' non trouvé"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _arun(self, name: str, **kwargs) -> str:
        return self._run(name, **kwargs)
    
    
# ============================================================================
# LISTE COMPLÈTE DES OUTILS
# ============================================================================

ALL_TOOLS = [
    # Outils granulaires
    AnalyzeAndParseOnly(),
    PassiveAnalyzeOnly(),
    CodeAnalyzeOnly(),
    FuzzerOnly(),
    FeaturesExtractOnly(),
    MLPredictOnly(),
    ConfigureScanner(),
    GetPhaseResult(),
    ListCachedScans(),
    ResetScanState(),
    # Outils haut niveau
    StartScan(),
    GetVulnerabilities(),
    GetReportPaths(),
    GetFeatures(),
    GetScanStatus(),
    GetHelperInfo(),
    ListHelpers(),
]

if __name__ == "__main__":
    import asyncio
    import json
    from pprint import pprint
    
    URL = "http://localhost:8080"
    DVWA_HELPER = [{"name": "dvwa_auth", "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "password"}}]
    
    def test_tool(tool_name: str, **kwargs):
        """Test un outil spécifique."""
        print(f"\n{'='*60}")
        print(f"🧪 TEST: {tool_name}")
        print(f"{'='*60}")
        
        # Mapping des outils
        tools = {
            "analyzer_helper_only": AnalyzeAndParseOnly(),
            "passive_analyze_only": PassiveAnalyzeOnly(),
            "code_analyze_only": CodeAnalyzeOnly(),
            "fuzzer_only": FuzzerOnly(),
            "features_extract_only": FeaturesExtractOnly(),
            "ml_predict_only": MLPredictOnly(),
            "configure_scanner": ConfigureScanner(),
            "get_phase_result": GetPhaseResult(),
            "list_cached_scans": ListCachedScans(),
            "reset_scan_state": ResetScanState(),
            "start_scan": StartScan(),
            "get_vulnerabilities": GetVulnerabilities(),
            "get_report_paths": GetReportPaths(),
            "get_features": GetFeatures(),
            "get_scan_status": GetScanStatus(),
            "get_helper_info": GetHelperInfo(),
            "list_helpers": ListHelpers(),
        }
        
        tool = tools.get(tool_name)
        if not tool:
            print(f"❌ Outil '{tool_name}' non trouvé")
            return
        
        # Exécution
        try:
            if tool_name in ["analyzer_helper_only", "start_scan"]:
                # Ces outils ont besoin de l'URL + helpers
                result = tool._run(url=URL, helpers=DVWA_HELPER, **kwargs)
            elif tool_name in ["passive_analyze_only", "code_analyze_only", "fuzzer_only", 
                               "features_extract_only", "ml_predict_only", "get_phase_result"]:
                # Ces outils ont besoin de l'URL seulement
                result = tool._run(url=URL, **kwargs)
            else:
                # Les autres outils n'ont pas besoin de paramètres ou peu
                result = tool._run(**kwargs)
            
            print(f"\n📤 RÉSULTAT:")
            pprint(json.loads(result) if isinstance(result, str) else result)
            
        except Exception as e:
            print(f"❌ Erreur: {e}")
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # TESTS INDIVIDUELS
    # ============================================================
    
    def test_all():
        """Lance tous les tests dans l'ordre logique."""
        print("\n" + "="*60)
        print("🚀 TEST DE TOUS LES OUTILS")
        print("="*60)
        
        # 1. Liste des helpers
        test_tool("list_helpers")
        
        # 2. Infos sur un helper
        test_tool("get_helper_info", name="dvwa_auth")
        
        # 3. Crawl seul
        test_tool("analyzer_helper_only", max_depth=2, max_pages=20)
        
        # 4. Analyse passive
        test_tool("passive_analyze_only")
        
        # 5. Analyse code
        test_tool("code_analyze_only")
        
        # 6. Fuzzer (attention, peut être long)
        test_tool("fuzzer_only", limit_payloads=5, time_between=0.1, max_test=50)
        
        # 7. Extraction features
        test_tool("features_extract_only")
        
        # 8. ML Predict
        test_tool("ml_predict_only", threshold=0.5)
        
        # 9. Liste des scans en cache
        test_tool("list_cached_scans")
        
        # 10. Scan complet
        test_tool("start_scan", max_depth=2, max_pages=20, limit_payloads=5)
        
        # 11. Vulnérabilités
        test_tool("get_vulnerabilities")
        
        # 12. Rapports
        test_tool("get_report_paths")
        
        # 13. Features
        test_tool("get_features")
        
        # 14. Status
        test_tool("get_scan_status", scan_id="test")
        
        # 15. Reset (attention, supprime l'état)
        # test_tool("reset_scan_state", url=URL)
        
        # 16. Config
        test_tool("configure_scanner", param="MAX_DEEPTH", value=5, module="crawler")
        
        print("\n" + "="*60)
        print("✅ TOUS LES TESTS TERMINÉS")
        print("="*60)
    
    # ============================================================
    # EXÉCUTION
    # ============================================================
    
    
    tool_name = None
    if tool_name == "all":
        test_all()
    
    else:
        # test_tool("list_helpers")
        # test_tool("get_helper_info", name="dvwa_auth")
        test_tool("analyzer_helper_only", )
        test_tool("code_analyze_only")
        test_tool("passive_analyze_only")
        m = ScannerStateManager.get_instance(URL)
        # print(ScannerStateManager.get_or_create_scanner())
        m.passive_result