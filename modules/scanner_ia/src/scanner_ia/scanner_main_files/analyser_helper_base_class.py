#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 19:30:23 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Dict, Any
from scanner_ia.base_class.fetcher_base_class import FetcherResult
from scanner_ia.base_class.parser_base_class import ParseResult
from scanner_ia.base_class._base_class import Base
from scanner_ia.base_class.crawler_base_class import WorkerResult

class OneAnalyzerHelperResult(Base):
    __slots__ = ("fetched", "parsed", "crawl")
    
    def __init__(self):
        super().__init__()
        self.fetched:FetcherResult = FetcherResult()
        self.parsed: ParseResult = ParseResult()
        self.crawl:WorkerResult = WorkerResult()

    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        
                
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            "fetched": self.fetched.to_dict(deep) if deep else self.fetched,
            "parsed": self.parsed.to_dict(deep),
            "deep": self.crawl.to_dict(deep)
        }
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine

class AnalyzerHelperResult(Base):
    __slots__ = ("elapsed", "elements")
    
    def __init__(self):
        super().__init__()
        self.elapsed: float = 0.0
        self.elements: dict[str, OneAnalyzerHelperResult] = {}

    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        
                
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            "elapsed": self.elapsed,
            "elements": self.elements if not deep else {k:p.to_dict(deep) for k,p in self.elements.items()}
        }
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine