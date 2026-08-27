#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 11 13:55:43 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import List, Optional, Dict, Any
from scanner_ia.base_class.fetcher_base_class import FetcherResult
from scanner_ia.base_class.payloads_base_class import Payload
from scanner_ia.base_class.response_analyzer_base_class import ResponseAnalyzerResult
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class._base_class import Base

class FuzzerResult(Base):
    __slots__ = ('url', 'results', 'error', 'stats', "other_links", "same_links",
                 "elapsed", "_confirmed")
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.results: List[WorkerFuzzerResult] = []  
        self.error: Optional[str] = None
        self.stats: Dict[str, Any] = {}  
        self.other_links:AnalyzerHelperResult = AnalyzerHelperResult()
        self.stats:dict = {}
        self.same_links:AnalyzerHelperResult = AnalyzerHelperResult()
        self.elapsed:float = 0.0
        self._confirmed: Dict[str, int] = {}
        
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'url': self.url,
            'stats': self.stats,
            "error": self.error,
            "other_links": self.other_links.to_dict(deep),
            "same_links": self.same_links.to_dict(deep),
            "elapsed": self.elapsed,
            'results': self.results if not deep else [p.to_dict(deep) for p in self.results]
        }
    
    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
     
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
    
    @property
    def vulns_links(self) -> Dict[str, List]:
        to_return = {}
        for worker_result in self.results:
            url = worker_result.url
            if worker_result.response_analyzer_result.is_vulnerable:
                if url not in to_return:
                    to_return[url] = []
                to_return[url].append(**worker_result.to_dict(True))
                
        return to_return
    
    @property
    def safe_links(self) -> List:
        links = set(self.same_links.elements.keys())
        vulns = set(self.vulns_links.keys())
        return list(links.difference(vulns))
    
class WorkerFuzzerEntry(Base):
    __slots__ = ('url', "baseline", "payload", "vuln_name", 
                 "vuln_full_name", "vuln_abbr_name","priority", 
                 "payload_type", "cvss")
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.baseline:FetcherResult = FetcherResult()
        self.payload:Payload = Payload()
        self.payload_type:str = ""
        self.vuln_full_name:str = ""
        self.vuln_name:str = ""
        self.vuln_abbr_name:str = ""
        self.priority:int = -1
        self.cvss:int|str = 0.0
        
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'url': self.url,
            "baseline": self.baseline.to_dict(deep),
            "payload": self.payload.to_dict(deep),
            "vuln_name": self.vuln_name,
            "vuln_abbr_name": self.vuln_abbr_name,
            "vuln_full_name": self.vuln_full_name,
            "priority": self.priority,
            'payload_type': self.payload_type,
            "cvss": self.cvss
        }
    
    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
        

class WorkerFuzzerResult(Base):
    __slots__ = ('url', "baseline", "payload", "payload_result", 
                 "response_analyzer_result", "error", "vuln_full_name", 
                 "vuln_abbr_name", "priority", "payload_type", "base_url",
                 "vuln_name", "cvss")
    
    def __init__(self):
        super().__init__()
        self.url:str = ""
        self.baseline:FetcherResult = FetcherResult()
        self.payload:Payload = Payload()
        self.payload_result:FetcherResult = FetcherResult()
        self.response_analyzer_result:ResponseAnalyzerResult = ResponseAnalyzerResult()
        self.payload_type:str = ""
        self.error:str = ""
        self.vuln_full_name:str = ""
        self.vuln_name:str = ""
        self.vuln_abbr_name:str = ""
        self.base_url:str = ""
        self.cvss:int|str = 0.0
        
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'url': self.url,
            'base_url': self.base_url,
            "baseline": self.baseline.to_dict(deep),
            "payload_result": self.payload_result.to_dict(deep),
            "response_analyzer_result": self.response_analyzer_result.to_dict(deep),
            "vuln_name": self.vuln_name,
            "vuln_abbr_name": self.vuln_abbr_name,
            "vuln_full_name": self.vuln_full_name,
            'payload_type': self.payload_type,
            "payload": self.payload.to_dict(deep),
            "error": self.error,
            "cvss": self.cvss
        }
    
    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
        
if __name__ == "__main__":
    w = WorkerFuzzerResult()
    