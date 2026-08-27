#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — MockFuzzer
Simule un scan actif réaliste quand active_scan=False.
Author : Samuel — ShieldAI
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import random
import time
from typing import Optional
from urllib.parse import urlparse

from base_class.fuzzer_base_class             import FuzzerResult, WorkerFuzzerResult
from base_class.fetcher_base_class            import FetcherResult
from base_class.payloads_base_class           import Payload
from base_class.response_analyzer_base_class  import ResponseAnalyzerResult
from base_class.analyser_helper_base_class    import AnalyzerHelperResult

_MOCK_VULNS = [
    {"vuln_name":"XSS",        "vuln_full_name":"Cross-Site Scripting",                    "cvss":6.1,  "payload_type":"reflected",   "payload_value":"<script>alert('XSS')</script>",           "indicators":["<script>alert","XSS"],            "score":72.4, "prob":0.81},
    {"vuln_name":"SQLi",       "vuln_full_name":"SQL Injection",                           "cvss":9.8,  "payload_type":"error_based",  "payload_value":"' OR '1'='1",                             "indicators":["SQL syntax","mysql_fetch"],        "score":88.1, "prob":0.93},
    {"vuln_name":"SSRF",       "vuln_full_name":"Server-Side Request Forgery",             "cvss":8.6,  "payload_type":"url_param",    "payload_value":"http://169.254.169.254/latest/meta-data/","indicators":["ami-id","169.254"],               "score":65.3, "prob":0.74},
    {"vuln_name":"SSTI",       "vuln_full_name":"Server-Side Template Injection",          "cvss":9.0,  "payload_type":"template",     "payload_value":"{{7*7}}",                                 "indicators":["49","TemplateSyntaxError"],        "score":91.0, "prob":0.96},
    {"vuln_name":"InfoDisc",   "vuln_full_name":"Information Disclosure",                  "cvss":5.3,  "payload_type":"path",         "payload_value":"/admin/.env",                             "indicators":["DB_PASSWORD","API_KEY"],          "score":58.7, "prob":0.68},
    {"vuln_name":"CMDi",       "vuln_full_name":"Command Injection",                       "cvss":9.8,  "payload_type":"shell",        "payload_value":"; id",                                    "indicators":["uid=0(root)","www-data"],          "score":95.2, "prob":0.98},
    {"vuln_name":"DirTrav",    "vuln_full_name":"Path Traversal",                          "cvss":7.5,  "payload_type":"path",         "payload_value":"../../../../etc/passwd",                  "indicators":["root:x:0:0","/bin/bash"],         "score":77.9, "prob":0.85},
    {"vuln_name":"CORS",       "vuln_full_name":"CORS Misconfiguration",                   "cvss":5.0,  "payload_type":"header",       "payload_value":"Origin: https://evil.com",                "indicators":["Access-Control-Allow-Origin: *"], "score":45.0, "prob":0.54},
    {"vuln_name":"CredsExpose","vuln_full_name":"Credentials Exposure",                    "cvss":7.2,  "payload_type":"path",         "payload_value":"/.git/config",                            "indicators":["[core]","repositoryformatversion"],"score":69.3,"prob":0.77},
    {"vuln_name":"InsecPerm",  "vuln_full_name":"Insecure Permissions",                    "cvss":6.5,  "payload_type":"path",         "payload_value":"/api/admin/users",                        "indicators":["200 OK","admin","role"],          "score":60.1, "prob":0.71},
]

_CLEAN_VULNS = ["NoSQLi","XXE","LDAPi","IDOR","SessFix","JWT","CSRF","CRLF_Injection","RaceCondition","GraphQLi"]


class MockFuzzer:
    """
    Simule un scan actif réaliste quand active_scan=False.
    Produit des FuzzerResult cohérents avec les vraies données du scanner.
    """

    def __init__(self, seed: int = 42, vuln_rate: float = 0.15,
                 fake_delay: float = 0.1):
        self.rng        = random.Random(seed)
        self.vuln_rate  = vuln_rate
        self.fake_delay = fake_delay

    def _make_fetcher(self, url: str, status: int = 200, body: str = "") -> FetcherResult:
        r = FetcherResult()
        r.url         = url
        r.final_url   = url
        r.status_code = status
        r.body        = body or f"<html><body>Response for {url}</body></html>"
        r.headers     = {"Content-Type": "text/html; charset=utf-8", "Server": "nginx/1.18.0"}
        r.delay       = round(self.rng.uniform(0.05, 0.4), 3)
        return r

    def _make_payload(self, vi: dict) -> Payload:
        p = Payload()
        p.payload_injected     = vi["payload_value"]
        p.vuln_name = vi["vuln_name"]
        p.element_type      = vi["payload_type"]
        return p

    def _vuln_worker(self, url: str, base_url: str, vi: dict) -> WorkerFuzzerResult:
        w = WorkerFuzzerResult()
        w.url            = url
        w.base_url       = base_url
        w.vuln_name      = vi["vuln_name"]
        w.vuln_full_name = vi["vuln_full_name"]
        w.vuln_abbr_name = vi["vuln_name"]
        w.payload_type   = vi["payload_type"]
        w.cvss           = vi["cvss"]
        w.payload        = self._make_payload(vi)
        w.baseline       = self._make_fetcher(url)
        w.payload_result = self._make_fetcher(url, body=" ".join(vi["indicators"]))

        rar = ResponseAnalyzerResult()
        rar.vuln_name           = vi["vuln_name"]
        rar.is_vulnerable       = True
        rar.score               = vi["score"]
        rar.prob                = vi["prob"]
        rar.note                = vi["score"]
        rar.found_indicators    = {ind: True for ind in vi["indicators"]}
        rar.status_changed      = self.rng.choice([True, False])
        rar.delay_detected      = self.rng.choice([True, False])
        rar.body_length_changed = True
        rar.headers_changed     = self.rng.choice([True, False])
        w.response_analyzer_result = rar
        return w

    def _clean_worker(self, url: str, base_url: str, vn: str) -> WorkerFuzzerResult:
        w = WorkerFuzzerResult()
        w.url            = url
        w.base_url       = base_url
        w.vuln_name      = vn
        w.vuln_full_name = vn
        w.vuln_abbr_name = vn
        w.payload_type   = "generic"
        w.cvss           = 0.0
        w.baseline       = self._make_fetcher(url)
        w.payload_result = self._make_fetcher(url)

        rar = ResponseAnalyzerResult()
        rar.vuln_name     = vn
        rar.is_vulnerable = False
        rar.score         = round(self.rng.uniform(0, 20), 2)
        rar.prob          = round(self.rng.uniform(0, 0.3), 3)
        rar.note          = rar.score
        w.response_analyzer_result = rar
        return w

    def simulate_scan(
        self,
        base_url:               str,
        analyzer_helper_result: AnalyzerHelperResult,
        limit_vuln:             Optional[int] = None,
        *args, **kwargs
    ) -> FuzzerResult:
        t0     = time.time()
        result = FuzzerResult()
        result.url = base_url

        urls        = list(analyzer_helper_result.elements.keys()) or [base_url]
        parsed_base = urlparse(base_url)
        same        = [u for u in urls if urlparse(u).netloc == parsed_base.netloc]
        if not same:
            same = [base_url]

        result.same_links  = analyzer_helper_result
        result.other_links = AnalyzerHelperResult()

        workers, vuln_count, vuln_by_url, total_tests = [], {}, {}, 0

        for url in same:
            if self.rng.random() < self.vuln_rate:
                n         = self.rng.randint(1, min(3, len(_MOCK_VULNS)))
                chosen    = self.rng.sample(_MOCK_VULNS, n)
                vuln_by_url[url] = []
                for vi in chosen:
                    if limit_vuln and sum(vuln_count.values()) >= limit_vuln:
                        break
                    workers.append(self._vuln_worker(url, base_url, vi))
                    vuln_count[vi["vuln_name"]] = vuln_count.get(vi["vuln_name"], 0) + 1
                    vuln_by_url[url].append(vi["vuln_name"])
                    total_tests += self.rng.randint(50, 200)

            for vn in self.rng.sample(_CLEAN_VULNS, self.rng.randint(2, 5)):
                workers.append(self._clean_worker(url, base_url, vn))
                total_tests += self.rng.randint(10, 50)

        result.results = workers
        total_vulns    = sum(vuln_count.values())

        result.stats = {
            "total_tests":     total_tests,
            "total_responses": int(total_tests * self.rng.uniform(0.7, 0.95)),
            "total_urls":      len(same),
            "vuln_count":      vuln_count,
            "vuln_by_url":     vuln_by_url,
            "vulns_url":       list(vuln_by_url.keys()),
            "total_vulns":     total_vulns,
            "success_rate":    round(self.rng.uniform(0.6, 0.9), 4),
            "vuln_rate":       round(total_vulns / max(total_tests, 1), 4),
            "mock":            True,
        }

        time.sleep(self.fake_delay)
        result.elapsed = round(time.time() - t0, 3)
        return result
