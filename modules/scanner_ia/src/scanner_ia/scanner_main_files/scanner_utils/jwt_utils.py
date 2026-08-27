#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:13:28 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from jose import jwt
from scanner_ia.api.api_config import NOT_BEFORE, EXP
from modules_utils.jwt_utils import create_token as _create_token, verify_token as _verify_token

def create_token(data: dict, key: bytes | str):
    return _create_token(
        data=data,
        key=key,
        exp=EXP,
        not_before=NOT_BEFORE
    )

def verify_token(token: str, key: bytes | str, verify_exp: bool = True):
    return _verify_token(
        token=token,
        key=key,
        verify_exp=verify_exp
    )

if __name__ == "__main__":
    token = jwt.encode({"a": "b"}, "secret".encode(), algorithm="HS256")
    print(token)
    data = jwt.decode(token, "secret")
    print(data)
