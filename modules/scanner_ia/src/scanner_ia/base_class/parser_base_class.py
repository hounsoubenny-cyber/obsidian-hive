#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 00:54:48 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Optional, Dict, Any, List
from scanner_ia.base_class.fetcher_base_class import FetcherResult
from scanner_ia.base_class._base_class import Base

class ParserResult(Base):
    __slots__ = ('tree', 'response')
    
    def __init__(self):
        super().__init__()
        self.tree = None  
        self.response: Optional[FetcherResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tree': str(self.tree) if self.tree is not None else None,  
            'response': self.response.to_dict()
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
    
    def __str__(self):
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine

class ParseElementResult(Base):
    __slots__ = ('n_element', 'elements')
    
    def __init__(self):
        super().__init__()
        self.n_element:int = 0  
        self.elements: list[dict] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'n_element': self.n_element,  
            'elements': self.elements
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
    
    def _update(self):
        self.n_element = len(self.elements)
    
    def __str__(self):
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine

class ParseResult(Base):
    __slots__ = ('a', 'img', 'script', 'link', 'style', 'iframe', 'video', 
                 'audio', 'embed', 'object', 'form', 'meta', 'cite', 'headers',
                 "comments", "n_error", "elapsed")
    
    def __init__(self):
        super().__init__()
        self.a: ParseElementResult = ParseElementResult()
        self.img: ParseElementResult = ParseElementResult()
        self.script: ParseElementResult = ParseElementResult()
        self.link: ParseElementResult = ParseElementResult()
        self.style: ParseElementResult = ParseElementResult()
        self.iframe: ParseElementResult = ParseElementResult()
        self.video: ParseElementResult = ParseElementResult()
        self.audio: ParseElementResult = ParseElementResult()
        self.embed: ParseElementResult = ParseElementResult()
        self.object: ParseElementResult = ParseElementResult()
        self.form: ParseElementResult = ParseElementResult()
        self.meta: ParseElementResult = ParseElementResult()
        self.cite: ParseElementResult = ParseElementResult()
        self.headers: ParseElementResult = ParseElementResult()
        self.comments: ParseElementResult = ParseElementResult()
        self.n_error = 0
        self.elapsed = 0.0

    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'a': self.a if not deep else self.a.to_dict(),
            'img': self.img if not deep else self.img.to_dict(),
            'script': self.script if not deep else self.script.to_dict(),
            'link': self.link if not deep else self.link.to_dict(),
            'style': self.style if not deep else self.style.to_dict(),
            'iframe': self.iframe if not deep else self.iframe.to_dict(),
            'video': self.video if not deep else self.video.to_dict(),
            'audio': self.audio if not deep else self.audio.to_dict(),
            'embed': self.embed if not deep else self.embed.to_dict(),
            'object': self.object if not deep else self.object.to_dict(),
            'form': self.form if not deep else self.form.to_dict(),
            'meta': self.meta if not deep else self.meta.to_dict(),
            'cite': self.cite if not deep else self.cite.to_dict(),
            'headers': self.headers if not deep else self.headers.to_dict(),
            "comments": self.comments if not deep else self.comments.to_dict(),
            "n_error": self.n_error,
            "elapsed": self.elapsed
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
    
    def __str__(self):
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
            
class ClassifyLinkResult(Base):
    __slots__ = ('url', 'ext', 'type')
    
    def __init__(self):
        super().__init__()
        self.url: str = ""
        self.ext: Optional[str] = None
        self.type: str = "other"
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'ext': self.ext,
            'type': self.type
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
    
    def __str__(self):
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine


class GetAllLinkResult(Base):
    __slots__ = ('all_links', 'html_links', 'other_links', 'error', 'stats', 'status', 'status_code', "type")
    
    def __init__(self):
        super().__init__()
        self.all_links: Dict[str, Dict] = {}     
        self.html_links: Dict[str, Dict] = {}    
        self.other_links: Dict[str, Dict] = {}         
        self.error: str = ""
        self.stats: Dict[str, Any] = {}          
        self.status: bool = False
        self.status_code: Optional[int] = None
        self.type:str = "other"
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'all_links': self.all_links,
            'html_links': self.html_links,
            'other_links': self.other_links,
            'error': self.error,
            'stats': self.stats,
            'status': self.status,
            'status_code': self.status_code,
            "type": self.type
        }
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        return self
    
    def update_counts(self):
        """Met à jour les statistiques"""
        self.stats['total_links'] = len(self.all_links)
        self.stats['html_links_count'] = len(self.html_links)
        self.stats['other_links_count'] = len(self.other_links)
    
    def __str__(self):
        try:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine
    
if __name__ == "__main__":
    test_class = ParseResult()
    print(len(test_class.a))
    print(test_class["s"])