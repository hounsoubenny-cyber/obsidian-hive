#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 11 13:58:18 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Dict, Any
from scanner_ia.base_class._base_class import Base

class ResponseAnalyzerResult(Base):
    __slots__ = ('vuln_name', 'found_indicators', 'status_changed', 
                 'delay_detected', 'headers_changed', 'body_length_changed', 
                 'score', 'note', 'is_vulnerable', 'error', "prob")
    
    def __init__(self):
        super().__init__()
        self.vuln_name:str = ""
        self.found_indicators:Dict[str, Any] = {}
        self.status_changed:bool = False
        self.delay_detected:bool = False
        self.body_length_changed:bool = False
        self.headers_changed:bool = False
        self.is_vulnerable:bool = False
        self.error:str = ""
        self.score:float = 0.0
        self.note:float = 0.0
        self.prob:float = 0.0
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            "vuln_name": self.vuln_name,
            "found_indicators": self.found_indicators,
            "status_changed": self.status_changed,
            "delay_detected": self.delay_detected,
            "body_length_changed": self.body_length_changed,
            "headers_changed": self.headers_changed,
            "is_vulnerable": self.is_vulnerable,
            "error": self.error,
            "score": self.score,
            "note": self.note,
            "prob": self.prob,
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
        