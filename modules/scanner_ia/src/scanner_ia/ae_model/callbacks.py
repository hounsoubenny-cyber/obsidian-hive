#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 30 20:56:33 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

class EarlyStopping:
    def __init__(self, patience:int = 10, mode:str = "min", *args, **kwargs):
        if mode not in ("min", "max"):
            raise ValueError("Arg mode invalide !")
        self.patience = patience
        self.mode = mode
        self.count = 0
        self.best_value = None
        self.f = lambda x, y: x > y if self.mode == "max" else x < y
    
    def should_stop(self, value):
        if self.best_value is None:
            print("Initialisation du best_value à", value)
            self.best_value = value
            return False
        
        if self.f(value, self.best_value):
            print("Amelioration du best_value,", self.best_value, "-->", value)
            self.best_value = value
            self.count = 0
            return False
        
        self.count += 1
        print("Pas d'amélioration, valeur actuelle", self.best_value, "count :", self.count)
        if self.count >= self.patience:
            return True
            
    def __call__(self, value, *args, **kwargs):
        return self.should_stop(value)
