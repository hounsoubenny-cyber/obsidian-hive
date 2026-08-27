#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 20 06:18:39 2026

@author: hounsousamuel
"""


_MAP = {
    "min": lambda x, y: x < y,
    "max": lambda x, y: x > y,
    }


class StopFit(Exception):
    def __init__(self):
        super().__init__()
        
class EarlyStopping:
    def __init__(
        self,
        patience:int = 10,
        mode:str = "min",
    ):
        if mode not in ("min", "max"):
            raise ValueError(f"Paramètre mode avec valeur inconnue, accepté 'min', 'max', reçu '{mode}'")
        self.patience = patience
        self.mode = mode
        self.count = 0
        self.best_value = None
        self._is_best = False  # Flag pour save si best
        
        self._compare_func = _MAP[self.mode]
    
    def is_best(self) -> bool:
        return self._is_best
    
    def __call__(self, value:float|int) -> bool:
        if self.best_value is None:
            self.best_value = value
            self._is_best = True
            print(f"EarlyStopping : Initialisation best_value à {self.best_value:.4f}")
            return True   # Pour dire de ne pas arrêter le fit
        
        self._is_best = self._compare_func(value, self.best_value)
        if self._is_best:
            print(f"EarlyStopping : Amelioration {self.best_value:.4f} --> {value:.4f}")
            self.best_value = value
            self.count = 0  # Reinitialiser le compteur
            return True
        else:
            self.count += 1
            if self.count >= self.patience:
                return False
            return True
            
        
        
        
    
    
            
        
        