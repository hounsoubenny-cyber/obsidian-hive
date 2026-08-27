#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 27 07:46:40 2026

@author: hounsousamuel
"""

import json
from pprint import pformat
from typing import Dict, List, Any
from scanner_ia.base_class._base_class import Base

class ScannerResult(Base):
    __slots__ = ("timings", "phases_result", "elapsed", "errors", "scan_id",
                 "end_time", "start_time", "date", "cache_key")
    def __init__(self):
        super().__init__()
        self.timings:Dict = {}
        self.phases_result:Dict = {}
        self.elapsed:float = 0.0
        self.errors:List[Dict] = []
        self.date:str = ""
        self.start_time:float = ""
        self.end_time:float = ""
        self.scan_id:str = ""
        self.cache_key:str = ""
    
    def update_from_dict(self, data: dict):
        for key, value in data.items():
            if hasattr(self, key):  
                setattr(self, key, value)
        
                
    def to_dict(self, deep:bool = False) -> Dict[str, Any]:
        import pandas as pd
        import json
        phases_result = {}
        if not deep:
            phases_result = self.phases_result
        else:
            for k, v in self.phases_result.items():
                if hasattr(v, "to_dict"):
                    if isinstance(v, Base):
                        phases_result[k] = v.to_dict(deep)
                    elif isinstance(v, pd.DataFrame):
                        phases_result[k] = v.to_dict(orient="records")
                    else:
                        phases_result[k] = json.loads(json.dumps(v, default=str))
                
                else:
                    phases_result[k] = json.loads(json.dumps(v, default=str))
                
                        
                    
        return {
            "date": self.date,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "scan_id": self.scan_id,
            "cache_key": self.cache_key,
            "timigs": self.timings,
            "phases_result": phases_result,
            "errors": self.errors,
            "elapsed": self.elapsed,
        }
    
    def __str__(self) -> str:
        try:
            return json.dumps(self.to_dict(True), indent=2, ensure_ascii=False)
        except Exception:
            chaine = pformat(self.to_dict(True), indent=2, width=100)
            chaine = chaine.replace(",", "")
            return chaine

if __name__ == "__main__":
    ScannerResult().to_dict(True)