#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar  3 20:55:47 2026

@author: hounsousamuel
"""

"""
Classe de Base des Resultats du fetcher
"""

import json
from pprint import pformat
from typing import Optional, Dict, List, Any
from scanner_ia.base_class._base_class import Base

class FetcherResult(Base):
    __slots__ = ('body', 'delay', 'method', 'error', 'cookies', 
                 'history', 'url', 'final_url', 'status_code', 
                 'headers', 'ip')
    
    def __init__(self):
        super().__init__()
        self.body: str = ""
        self.delay: float = 0.0
        self.method: str = "GET"
        self.error: Optional[str] = None
        self.cookies: List[Dict] = []  
        self.history: List[Dict] = []  
        self.url: str = ""
        self.final_url: str = ""
        self.status_code: Optional[int] = None
        self.headers: Dict[str, str] = {} 
        self.ip: Optional[str] = None
    
    def update_from_dict(self, data: dict) -> 'FetcherResult':
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
                
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'body': self.body,
            'delay': self.delay,
            'method': self.method,
            'error': self.error,
            'cookies': self.cookies,
            'history': self.history,
            'url': self.url,
            'final_url': self.final_url,
            'status_code': self.status_code,
            'headers': self.headers,
            'ip': self.ip
        }
    
    def is_success(self) -> bool:
        """Vérifie si la requête a réussi (status 2xx)"""
        return self.status_code is not None and 200 <= self.status_code < 300
    
    def is_redirect(self) -> bool:
        """Vérifie si c'est une redirection"""
        return self.status_code in (301, 302, 303, 307, 308)
    
    def body_length(self) -> int:
        """Retourne la longueur du body"""
        return len(self.body) if self.body else 0
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine