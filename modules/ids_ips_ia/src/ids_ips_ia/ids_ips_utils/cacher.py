#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 00:05:11 2026

@author: hounsousamuel
"""

import json
import hashlib
import asyncio
import threading
from functools import wraps

class Cache:
    def __init__(self, max_len: int = 100):
        self._cache = {}
        self.max_len = max_len or 100
    
    @staticmethod
    def pop_first(dict_obj):
        """Retire et retourne le premier élément (clé, valeur)"""
        if not dict_obj:
            return None
        key = next(iter(dict_obj))
        value = dict_obj.pop(key)
        return key, value

    def generate_key(self, *args, **kwargs):
        key = json.dumps(args, default=str, sort_keys=True) + json.dumps(kwargs, default=str, sort_keys=True)
        return hashlib.sha256(key.encode()).hexdigest()
    
    def cache(self, key, value):
        if len(self._cache) > self.max_len:
            self.pop_first(self._cache)
        
        self._cache[key] = value
    
    def get(self, key):
        return self._cache.get(key, None)
    
    def cache_wrapper(self, func):
        is_async = asyncio.iscoroutinefunction(func)
        if is_async:
            @wraps(func)
            async def wrapper(self_instance, *args, **kwargs):
                key = self.generate_key(*args, **kwargs)
                cache_val = self.get(key)
                if cache_val is not None:
                    return cache_val

                r = await func(self_instance, *args, **kwargs)
                self.cache(key, r)
                return r
        
        else:
            @wraps(func)
            def wrapper(self_instance, *args, **kwargs):
                key = self.generate_key(*args, **kwargs)
                cache_val = self.get(key)
                if cache_val is not None:
                    return cache_val
    
                r = func(self_instance, *args, **kwargs)
                self.cache(key, r)
                return r
            
        return wrapper