#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 20 16:14:54 2026

@author: hounsousamuel
"""

import types

class LazyModule(types.ModuleType):
    def __init__(self, name: str):
        super().__init__(name)
        self._loaded = False
        self._real: types.ModuleType = None

    def _load(self):
        if self._loaded:
            return
        import importlib
        self._real = importlib.import_module(f"{self.__name__}")
        self._loaded = True

    def __getattr__(self, name):
        self._load()
        return getattr(self._real, name)

    def __dir__(self):
        self._load()
        return dir(self._real)
