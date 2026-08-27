#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:13:13 2026

@author: hounsousamuel
"""

import bcrypt
            
def hashpw(password:str):
    if isinstance(password, str):
        password = password.encode()
    
    return bcrypt.hashpw(password, bcrypt.gensalt())

def checkpw(password:str, hashed:bytes):
    if isinstance(password, str):
        password = password.encode()

    return bcrypt.checkpw(password=password, hashed_password=hashed)

def checksalt(salt):
    try:
        password = "password".encode()
        bcrypt.hashpw(password, salt)
        return True
    except Exception:
        return False