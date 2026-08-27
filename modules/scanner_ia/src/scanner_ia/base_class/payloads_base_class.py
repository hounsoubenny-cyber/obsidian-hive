#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 11 04:09:47 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import List, Dict, Any
from scanner_ia.base_class._base_class import Base

class Payload(Base):
    __slots__ = ("base_element", "new_element", "element_type", "payload_injected", "vuln_name")
    def __init__(self):
        super().__init__()
        self.base_element:str|Dict = ""
        self.new_element:str|Dict = ""
        self.element_type:str = ""
        self.payload_injected:str = ""
        self.vuln_name:str = ""
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'base_element': self.base_element,
            'new_element': self.new_element,
            'element_type': self.element_type,
            "payload_injected": self.payload_injected,
            "vuln_name": self.vuln_name
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

class Payloads(Base):
    __slots__ = ("payload_type", "payloads", "n_payloads")
    def __init__(self):
        super().__init__()
        self.payload_type:str = ""
        self.payloads:List[Payload] = []
        self.n_payloads:int = 0
    
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'payload_type': self.payload_type,
            'payloads': self.payloads if not deep else [p.to_dict(True) for p in self.payloads],
            'n_payloads': self.n_payloads,
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

class PayloadResult(Base):
    __slots__ = ("header_payload", "query_payload", "path_payload",
                 "form_payload", "body_payload", "cookie_payload", "url",
                 "vuln_name", "vuln_full_name", "vuln_abbr_name", "priority",
                 "cvss")
    
    def __init__(self):
        super().__init__()
        self.header_payload:Payloads = Payloads()
        self.query_payload:Payloads = Payloads()
        self.body_payload:Payloads = Payloads()
        self.form_payload:Payloads = Payloads()
        self.path_payload:Payloads = Payloads()
        self.cookie_payload: Payloads = Payloads()
        self.url:str = ""
        self.vuln_full_name:str = ""
        self.vuln_name:str = ""
        self.vuln_abbr_name:str = ""
        self.cvss:int|str = 0.0
        self.priority:int = -1
        
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        return {
            'header_payload': self.header_payload.to_dict(deep),
            'query_payload': self.query_payload.to_dict(deep),
            "body_payload": self.body_payload.to_dict(deep),
            "form_payload": self.form_payload.to_dict(deep),
            "path_payload": self.path_payload.to_dict(deep),
            "cookie_payload": self.cookie_payload.to_dict(deep),
            'n_payloads': self.n_payloads,
            "url": self.url,
            "vuln_name": self.vuln_name,
            "vuln_abbr_name": self.vuln_abbr_name,
            "vuln_full_name": self.vuln_full_name,
            "priority": self.priority,
            "cvss": self.cvss
        }
    
    def set_payload(self, payload:Payloads, key:str):
        if "header" in key:
            self.header_payload = payload
            
        elif "query" in key:
            self.query_payload = payload
        
        elif "path" in key:
            self.path_payload = payload
        
        elif "cookie" in key:
            self.cookie_payload = payload
        
        elif "form" in key:
            self.form_payload = payload
        
        elif "body" in key:
            self.body_payload = payload
            
    def get_payload(self, key:str):
        if "header" in key:
            return self.header_payload
            
        elif "query" in key:
            return self.query_payload
        
        elif "path" in key:
            return self.path_payload
        
        elif "cookie" in key:
            return self.cookie_payload
        
        elif "form" in key:
            return self.form_payload
        
        elif "body" in key:
            return self.body_payload
            
            
    @property
    def n_payloads(self):
        return sum((
            self.header_payload.n_payloads,
            self.form_payload.n_payloads,
            self.body_payload.n_payloads,
            self.path_payload.n_payloads,
            self.path_payload.n_payloads,
            self.cookie_payload.n_payloads
            ))
    
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
    