#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 11:17:35 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Dict, List, Any
from scanner_ia.base_class._base_class import Base

class PassiveVulnerability(Base):
    """Une vulnérabilité détectée par analyse passive"""
    __slots__ = ('tag', 'message', 'severity', 'evidence', 'recommendation')
    
    def __init__(self):
        super().__init__()
        self.tag: str = ""
        self.message: str = ""
        self.severity: str = "info"  
        self.evidence: str = ""
        self.recommendation: str = ""
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'tag': self.tag,
            'severity': self.severity,
            'message': self.message,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine


class PagePassiveResult(Base):
    """Résultat analyse passive d'une page"""
    __slots__ = ('url', 'headers_vulns', 'cookies_vulns', 'forms_vulns', 
                 'links_vulns', 'scripts_vulns', 'iframes_vulns', 
                'comments_vulns', 'a_vulns', "ratio_http")
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.headers_vulns: List[PassiveVulnerability] = []
        self.cookies_vulns: List[PassiveVulnerability] = []
        self.forms_vulns: List[PassiveVulnerability] = []
        self.links_vulns: List[PassiveVulnerability] = []
        self.iframes_vulns: List[PassiveVulnerability] = []
        self.comments_vulns: List[PassiveVulnerability] = []
        self.a_vulns: List[PassiveVulnerability] = []
        self.ratio_http:float = 0.0
    
    @property
    def total_vulns(self) -> int:
        """Nombre total de vulnérabilités"""
        return sum([
            len(self.headers_vulns),
            len(self.cookies_vulns),
            len(self.forms_vulns),
            len(self.links_vulns),
            len(self.iframes_vulns),
            len(self.comments_vulns),
            len(self.a_vulns)
        ])
    
    @property
    def critical_count(self) -> int:
        """Nombre de vulnérabilités critiques"""
        all_vulns = self._all_vulns()
        return sum(1 for v in all_vulns if v.severity == 'critique')
    
    @property
    def high_count(self) -> int:
        """Nombre de vulnérabilités élevées"""
        all_vulns = self._all_vulns()
        return sum(1 for v in all_vulns if v.severity == 'élevé')
    
    # @property
    # def max_score(self) -> float:
    #     """Score max parmi toutes les vulnérabilités"""
    #     all_vulns = self._all_vulns()
    #     return max((v.score for v in all_vulns), default=0.0)
    
    def _all_vulns(self) -> List[PassiveVulnerability]:
        """Retourne toutes les vulnérabilités"""
        return (self.headers_vulns + self.cookies_vulns + self.forms_vulns +
                self.links_vulns + self.iframes_vulns + self.comments_vulns)
    
    def to_dict(self, deep: bool = False) -> Dict[str, Any]:
        if not deep:
            return {
                'url': self.url,
                'total_vulns': self.total_vulns,
                'critical_count': self.critical_count,
                'high_count': self.high_count,
                'max_score': self.max_score,
                "ratio_http": self.ratio_http,
            }
        
        return {
            'url': self.url,
            'headers_vulns': [v.to_dict() for v in self.headers_vulns],
            'cookies_vulns': [v.to_dict() for v in self.cookies_vulns],
            'forms_vulns': [v.to_dict() for v in self.forms_vulns],
            'links_vulns': [v.to_dict() for v in self.links_vulns],
            'iframes_vulns': [v.to_dict() for v in self.iframes_vulns],
            'comments_vulns': [v.to_dict() for v in self.comments_vulns],
            "ratio_http": self.ratio_http,
            'stats': {
                'total_vulns': self.total_vulns,
                'critical': self.critical_count,
                'high': self.high_count,
            }
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine


class PassiveAnalyzerResult(Base):
    """Résultat global analyse passive"""
    __slots__ = ('elapsed', 'pages', "summary_")
    
    def __init__(self):
        super().__init__()
        self.elapsed: float = 0.0
        self.pages: Dict[str, PagePassiveResult] = {}
    
    @property
    def total_vulns(self) -> int:
        """Nombre total de vulnérabilités tous URLs confondus"""
        return sum(page.total_vulns for page in self.pages.values())
    
    @property
    def total_pages(self) -> int:
        """Nombre de pages analysées"""
        return len(self.pages)
    
    @property
    def summary(self) -> Dict[str, Any]:
        """Résumé global"""
        critical = sum(page.critical_count for page in self.pages.values())
        high = sum(page.high_count for page in self.pages.values())
        
        return {
            'total_pages': self.total_pages,
            'total_vulns': self.total_vulns,
            'critical': critical,
            'high': high,
            'elapsed': self.elapsed,
        }
    
    def to_dict(self, deep: bool = False) -> Dict[str, Any]:
        if not deep:
            return {
                'elapsed': self.elapsed,
                'summary': self.summary
            }
        
        return {
            'elapsed': self.elapsed,
            'pages': {url: page.to_dict(deep) for url, page in self.pages.items()},
            'summary': self.summary
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
