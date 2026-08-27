#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 26 11:51:49 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import json5
import hashlib
from scanner_ia.core.fetcher import Config as FetcherConfig
from scanner_ia.core.parser import Config as ParserConfig
from scanner_ia.core.crawler import Config as CrawlerConfig
from scanner_ia.core.analyzer_helper import Config as AnalyzerHelperConfig

DICT = {
    "fetcher": FetcherConfig,
    "crawler": CrawlerConfig,
    "parser": ParserConfig,
    "analyzer_helper": AnalyzerHelperConfig,
}

DEFAULT_CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".", "shieldai_scanner.config.json5"))

class ConfigManager:
    
    DICT = DICT
    
    def __init__(self):
        self.crawler_conf = {}
        self.parser_conf = {}
        self.fetcher_conf = {}
        self.analyzer_helper_conf = {}
        
    def configure(self, path: str = DEFAULT_CONFIG_PATH):
        if not os.path.exists(path):
            raise FileNotFoundError()
        
        config = None
        with open(path, "r") as f:
            config = json5.load(f)
        
        if config:
            to_return = {}
            for k, v in DICT.items():
                if k in config:
                    to_return[k] = {}
                    conf_k = config[k]
                    for i, j in conf_k.items():
                            if k == "fetcher":
                                self.fetcher_conf[i] = j
                            elif k == "parser":
                                self.parser_conf[i] = j   
                            elif k == "crawler":
                                self.crawler_conf[i] = j
                            elif k == "analyzer_helper":
                                self.analyzer_helper_conf[i] = j
                            to_return[k][i] = j
                            
            return hashlib.sha256(
                json5.dumps(
                    to_return, 
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                    sort_keys=True,
                ).encode()
            ).hexdigest()
    
        return ""
    
if __name__ == "__main__":
    confM = ConfigManager()
    path = "/home/hounsousamuel/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/shieldai_scanner.config.json5"
    print(confM.configure(path))
        
        
            
        
    