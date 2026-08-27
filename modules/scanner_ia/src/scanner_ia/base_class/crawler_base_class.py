#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 11:57:02 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import List, Optional, Dict, Any
from scanner_ia.base_class._base_class import Base

class CrawlerResult(Base):
    __slots__ = ('url', 'type', 'result', 'error', 'stats')
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.type: str = "other"
        self.result: List['WorkerResult'] = []  
        self.error: Optional[str] = None
        self.stats: Dict[str, Any] = {}  
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'url': self.url,
            'type': self.type,
            'result': [p.to_dict(deep) for p in self.result] if deep else self.result,
            'error': self.error,
            'stats': self.stats
        }
    
    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        # l = []
        # for w in self.result:
        #     if isinstance(w, dict):
        #         w_n = WorkerResult()
        #         w_n.update_from_dict(w)
        #         l.append(w_n)
        # self.result = l
                
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine


class WorkerResult(Base):
    __slots__ = ('url', 'source_url', 'type', 'deep', 'same_domain', 
                 'status_code', 'error', 'html_links', 'nbr_html_links', 
                 'other_links', 'nbr_other_links', 'fin_crawl')
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.source_url: str = ""
        self.type: str = "other"
        self.deep: Optional[int] = None
        self.same_domain: bool = False
        self.status_code: Optional[int] = None
        self.error: Optional[str] = None
        self.html_links: List[str] = []  
        self.other_links: List[str] = [] 
        self.nbr_html_links: int = 0
        self.nbr_other_links: int = 0
        self.fin_crawl: str = ""
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'url': self.url,
            'source_url': self.source_url,
            'type': self.type,
            'deep': self.deep,
            'same_domain': self.same_domain,
            'status_code': self.status_code,
            'error': self.error,
            'html_links': self.html_links,
            'nbr_html_links': self.nbr_html_links,
            'other_links': self.other_links,
            'nbr_other_links': self.nbr_other_links,
            'fin_crawl': self.fin_crawl
        }
    
    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def update_counts(self) -> None:
        """Met à jour les compteurs basés sur les listes"""
        self.nbr_html_links = len(self.html_links)
        self.nbr_other_links = len(self.other_links)
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine