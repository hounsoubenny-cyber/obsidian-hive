#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May  3 22:48:05 2026

@author: hounsousamuel
"""

import bcrypt

def verify_salt(salt:str|bytes):
    try:
        salt = salt.encode() if isinstance(salt, str) else salt
        bcrypt.hashpw(b"password", salt)
        return True
    except Exception:
        return False