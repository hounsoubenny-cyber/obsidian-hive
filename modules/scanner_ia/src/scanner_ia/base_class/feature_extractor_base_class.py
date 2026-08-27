#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 11:53:29 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Dict, List, Any
from scanner_ia.base_class.fuzzer_base_class import WorkerFuzzerResult
from scanner_ia.base_class.analyser_helper_base_class import OneAnalyzerHelperResult
from scanner_ia.base_class._base_class import Base
from scanner_ia.base_class.passive_analyzer_base_class import PagePassiveResult
from scanner_ia.base_class.code_analyse_base_class import CheckResult

class WorkerExtractorEntry(Base):
    __slots__ = (
        "analyzer_helper_element", "url", "fuzzer_element", "passive_analyzer_result", "code_analyzer_result"
    )
    def __init__(self):
        self.url:str = ""
        self.analyzer_helper_element:OneAnalyzerHelperResult = OneAnalyzerHelperResult()
        self.fuzzer_element:List[WorkerFuzzerResult] = []
        self.passive_analyzer_result:PagePassiveResult = PagePassiveResult()
        self.code_analyzer_result:Dict[str, CheckResult|Dict[str, CheckResult]] = {}
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            "url": self.url,
            "analyzer_helper_element": self.analyzer_helper_element.to_dict() if deep else self.analyzer_helper_element,
            "fuzzer_element": [p.to_dict() for p in self.fuzzer_element] if deep else self.fuzzer_element,
            "code_analyzer_result": self.code_analyzer_result.to_dict(deep),
            "passive_analyzer_result": self.passive_analyzer_result.to_dict(deep),
        }
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine