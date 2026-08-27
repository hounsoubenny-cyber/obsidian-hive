#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb  7 03:35:40 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import List, Dict, Any
from scanner_ia.base_class._base_class import Base

class CheckResult(Base):
    __slots__ = ("stats", "vulns", "context", "list_vulns")
    
    def __init__(self):
        super().__init__()
        self.stats:Dict[str, Any] = {}
        self.vulns:List[Dict] = []
        self.context:str = ""
        self.list_vulns:List[str] = []
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'stats': self.stats,
            'vulns': self.vulns,
            "context": self.context,
            "list_vulns": self.list_vulns
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
    def total_vulns(self) -> int:
        return len(self.list_vulns or self.vulns)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulns if v.get("severity") == "critique")
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulns if v.get("severity") == "élevé")
    
    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulns if v.get("severity") == "moyen")
    
    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulns if v.get("severity") == "faible")
    
    @property
    def max_score(self) -> float:
        return max((v.get("score", 0) for v in self.vulns), default=0.0)

class CodeAnalyzerResult(Base):
    __slots__ = ("results", "elapsed")
    
    def __init__(self):
        super().__init__()
        self.results:Dict[str, CheckResult|Dict[str, CheckResult]] = {}
        self.elapsed = 0.0
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        if not deep:
            return {
                'results': self.results,
                'elapsed': self.elapsed,
            }
        result = {}
        for k, v in self.results.items():
            result[k] = {}
            for i, j in v.items():
                if not isinstance(j, dict):
                    result[k][i] = j.to_dict()
                else:
                    result[k][i] = {}
                    for u, n in j.items():
                        result[k][i][u] = n.to_dict()
        return {
            'results': result,
            'elapsed': self.elapsed,
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
    def total_vulns(self) -> int:
        return sum(len(r.vulns) for r in self.results.values())
    
    @property
    def summary(self) -> Dict[str, Any]:
        """Résumé global des vulnérabilités"""
        total = self.total_vulns
        critical = sum(r.critical_count for r in self.results.values())
        high = sum(r.high_count for r in self.results.values())
        medium = sum(r.medium_count for r in self.results.values())
        low = sum(r.low_count for r in self.results.values())
        
        return {
            "total": total,
            "critique": critical,
            "élevé": high,
            "moyen": medium,
            "faible": low,
            "temps": self.elapsed
        }