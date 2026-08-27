#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 12 08:07:54 2026

@author: hounsousamuel
"""

class Base:
    __slots__ = ("author", "age")
    def __init__(self):
        self.author = "Samuel"
        
    def get(self, key:str, default:None = None):
        return getattr(self, key, default)
    
    def __getitem__(self, key:str|int):
        return self.get(key)
    
    def __setitem__(self, key:str, value:str):
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            print("Valeur ignorée !")
        
    def __len__(self):
        return sum(1 for slot in self.__slots__ if hasattr(self, slot))
    
    def __contains__(self, key:str):
        return key in self.__slots__
    
    # def to_dict(self, data:dict):
    #     import json
    #     return json.loads(json.dumps(data, default=str))
    
if __name__ == "__main__":
    b = Base()
    b["author"]
    print(len(b))