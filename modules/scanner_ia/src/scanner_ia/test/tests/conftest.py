#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 05:05:51 2026

@author: hounsousamuel
"""

# tests/conftest.py
"""
Fixtures partagées pour les tests unitaires ShieldAI ScannerAI
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List
import aiohttp
from yarl import URL

from scanner_ia.base_class.fetcher_base_class import FetcherResult
from scanner_ia.base_class.crawler_base_class import WorkerResult, CrawlerResult
from scanner_ia.base_class.parser_base_class import ParseResult, ParseElementResult
from scanner_ia.base_class.analyser_helper_base_class import OneAnalyzerHelperResult, AnalyzerHelperResult
from scanner_ia.base_class.fuzzer_base_class import WorkerFuzzerResult, FuzzerResult
from scanner_ia.base_class.response_analyzer_base_class import ResponseAnalyzerResult


@pytest.fixture
def mock_session():
    """Fixture fournissant un mock de aiohttp.ClientSession"""
    session = AsyncMock(spec=aiohttp.ClientSession)
    
    # Mock de session.get
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.text = AsyncMock(return_value="<html><body>Test</body></html>")
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)
    
    session.get.return_value = mock_response
    session.post.return_value = mock_response
    session.head.return_value = mock_response
    
    return session


@pytest.fixture
def mock_fetcher_result():
    """Fixture fournissant un FetcherResult basique"""
    result = FetcherResult()
    result.url = "https://example.com/page"
    result.final_url = "https://example.com/page"
    result.status_code = 200
    result.body = "<html><body><h1>Test Page</h1><a href='/next'>Next</a></body></html>"
    result.headers = {"Content-Type": "text/html", "Server": "nginx"}
    result.delay = 0.15
    result.method = "GET"
    result.error = None
    result.cookies = []
    result.history = []
    result.ip = "93.184.216.34"
    return result


@pytest.fixture
def mock_worker_result():
    """Fixture fournissant un WorkerResult basique"""
    result = WorkerResult()
    result.url = "https://example.com/page"
    result.source_url = "https://example.com"
    result.type = "html"
    result.deep = 1
    result.same_domain = True
    result.status_code = 200
    result.error = None
    result.html_links = ["https://example.com/next", "https://example.com/about"]
    result.other_links = ["https://external.com/image.jpg"]
    result.nbr_html_links = 2
    result.nbr_other_links = 1
    result.fin_crawl = "01/01/2024 à 12:00:00"
    return result


@pytest.fixture
def mock_one_analyzer_helper_result(mock_fetcher_result):
    """Fixture fournissant un OneAnalyzerHelperResult complet"""
    result = OneAnalyzerHelperResult()
    result.fetched = mock_fetcher_result
    
    # ParseResult mocké
    parse_result = ParseResult()
    parse_result.a = ParseElementResult()
    parse_result.a.elements = [{"href": "/next", "abs_link": "https://example.com/next", "text": "Next"}]
    parse_result.a._update()
    
    parse_result.form = ParseElementResult()
    parse_result.form.elements = [{"action": "/login", "method": "POST", "champs": [{"name": "user", "type": "text"}]}]
    parse_result.form._update()
    
    parse_result.script = ParseElementResult()
    parse_result.script.elements = [{"src": "/script.js", "nature": "externe", "contenu": "alert('test')"}]
    parse_result.script._update()
    
    parse_result.headers = ParseElementResult()
    parse_result.headers.elements = [{"headers": mock_fetcher_result.headers, "security_report": {"strict_transport_security": False}}]
    parse_result.headers._update()
    
    result.parsed = parse_result
    result.crawl = WorkerResult()
    result.crawl.url = "https://example.com/page"
    result.crawl.deep = 0
    
    return result


@pytest.fixture
def mock_analyzer_helper_result(mock_one_analyzer_helper_result):
    """Fixture fournissant un AnalyzerHelperResult avec une page"""
    result = AnalyzerHelperResult()
    result.elapsed = 0.5
    result.elements = {
        "https://example.com/page": mock_one_analyzer_helper_result
    }
    return result


@pytest.fixture
def mock_response_analyzer_result():
    """Fixture fournissant un ResponseAnalyzerResult vulnérable"""
    result = ResponseAnalyzerResult()
    result.vuln_name = "XSS"
    result.found_indicators = {"<script>": "contexte trouvé"}
    result.status_changed = False
    result.delay_detected = False
    result.body_length_changed = True
    result.headers_changed = False
    result.is_vulnerable = True
    result.error = ""
    result.score = 85.5
    result.note = 14.5
    result.prob = 0.85
    return result


@pytest.fixture
def mock_worker_fuzzer_result(mock_fetcher_result, mock_response_analyzer_result):
    """Fixture fournissant un WorkerFuzzerResult vulnérable"""
    result = WorkerFuzzerResult()
    result.url = "https://example.com/page?q=test"
    result.base_url = "https://example.com"
    result.baseline = mock_fetcher_result
    result.payload_result = mock_fetcher_result
    result.response_analyzer_result = mock_response_analyzer_result
    result.vuln_name = "XSS"
    result.vuln_full_name = "Cross-Site Scripting"
    result.vuln_abbr_name = "XSS"
    result.payload_type = "query_injection"
    result.cvss = 6.1
    result.error = ""
    
    # Payload mock
    from scanner_ia.base_class.payloads_base_class import Payload
    payload = Payload()
    payload.payload_injected = "<script>alert(1)</script>"
    payload.element_type = "query"
    result.payload = payload
    
    return result


@pytest.fixture
def mock_fuzzer_result(mock_worker_fuzzer_result):
    """Fixture fournissant un FuzzerResult avec vulnérabilités"""
    result = FuzzerResult()
    result.url = "https://example.com"
    result.results = [mock_worker_fuzzer_result]
    result.error = None
    result.stats = {
        "total_tests": 250,
        "total_responses": 248,
        "total_urls": 15,
        "vuln_count": {"XSS": 3, "SQLi": 1},
        "vuln_by_url": {"https://example.com/page?q=test": ["XSS"]},
        "vulns_url": ["https://example.com/page?q=test"],
        "total_vulns": 4,
        "success_rate": 0.98,
        "vuln_rate": 0.27,
        "mock": False,
        "vuln_confidence": {
            "https://example.com/page?q=test": {
                "XSS": {"count": 3, "prob_max": 0.92, "prob_avg": 0.87, "best_payload": "<script>alert(1)</script>", "best_type": "query"}
            }
        }
    }
    result.elapsed = 0.35
    return result


@pytest.fixture
def mock_crawler_result(mock_worker_result):
    """Fixture fournissant un CrawlerResult basique"""
    result = CrawlerResult()
    result.url = "https://example.com"
    result.type = "html"
    result.result = [mock_worker_result]
    result.error = None
    result.stats = {
        "elapsed": 2.5,
        "fin_crawl": "01/01/2024 à 12:00:00",
        "n_error": 0,
        "err_list": [],
        "n_pages": 1,
        "speed": 0.4
    }
    return result


@pytest.fixture
def mock_code_analyzer_result():
    """Fixture fournissant un CodeAnalyzerResult"""
    from scanner_ia.base_class.code_analyse_base_class import CodeAnalyzerResult, CheckResult
    
    result = CodeAnalyzerResult()
    result.elapsed = 0.3
    
    check = CheckResult()
    check.vulns = [
        {"name": "DOM XSS", "severity": "élevé", "line_number": 42, "find": "document.write(", "code": "document.write(location.hash)"},
        {"name": "Info Disclosure", "severity": "moyen", "line_number": 15, "find": "API_KEY", "code": "API_KEY = 'sk-test'"}
    ]
    check.list_vulns = ["DOM XSS", "Info Disclosure"]
    check.stats = {"DOM XSS": 1, "Info Disclosure": 1, "severity_count": {"élevé": 1, "moyen": 1}}
    
    result.results = {
        "https://example.com/page": {
            "body": check,
            "balises_script": {"script_0": check}
        }
    }
    return result


@pytest.fixture
def mock_passive_analyzer_result():
    """Fixture fournissant un PassiveAnalyzerResult"""
    from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult, PagePassiveResult, PassiveVulnerability
    
    result = PassiveAnalyzerResult()
    result.elapsed = 0.2
    
    page_result = PagePassiveResult()
    page_result.url = "https://example.com/page"
    
    vuln = PassiveVulnerability()
    vuln.tag = "headers"
    vuln.message = "En-tête HSTS manquant"
    vuln.severity = "élevé"
    vuln.evidence = "strict-transport-security"
    vuln.recommendation = "Ajouter HSTS"
    page_result.headers_vulns = [vuln]
    
    result.pages = {"https://example.com/page": page_result}
    return result


@pytest.fixture
def mock_scanner_result(mock_analyzer_helper_result, mock_passive_analyzer_result, 
                        mock_code_analyzer_result, mock_fuzzer_result):
    """Fixture fournissant un ScannerResult complet"""
    from scanner_ia.base_class.main_scanner_base_class import ScannerResult
    
    result = ScannerResult()
    result.date = "01/01/2024 à 12:00:00"
    result.start_time = 1704110400.0
    result.end_time = 1704110450.0
    result.scan_id = "scan-test-123"
    result.cache_key = "https://example.com|test"
    result.timings = {
        "analyzer_helper(crawl_and_parse)": 2.5,
        "passive_code_analyzer": 0.2,
        "code_analyzer": 0.3,
        "fuzzer(active)": 0.35,
        "features_extraction": 0.1,
        "ml_predictions": 0.05
    }
    result.phases_result = {
        "analyzer_helper(crawl_and_parse)": mock_analyzer_helper_result,
        "passive_code_analyzer": mock_passive_analyzer_result,
        "code_analyzer": mock_code_analyzer_result,
        "fuzzer": mock_fuzzer_result
    }
    result.errors = []
    result.elapsed = sum(result.timings.values())
    return result