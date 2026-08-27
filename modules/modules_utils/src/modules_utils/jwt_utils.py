#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:13:28 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from jose import jwt
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status

def create_token(data:dict, key:bytes|str, exp: int, not_before: int, algorithm: str = None):
    try:
        iat = datetime.now(tz=timezone.utc)
        jwt_data = {
            "sub": data["username"],
            "iat": iat,
            "exp": iat + timedelta(minutes=exp), 
            "nbf": iat - timedelta(seconds=not_before)
            }
        token = jwt.encode(jwt_data, key=key, algorithm=algorithm or jwt.ALGORITHMS.HS256)
        return token
    except Exception as e:
        print("Erreur dans la création du token jwt :", str(e))

def verify_token(token:str, key:bytes|str, verify_exp:bool = True, algorithm: str = None):
    try:
        decoded = jwt.decode(
            token, key, 
            algorithms=[algorithm or jwt.ALGORITHMS.HS256], 
            options={
            'verify_exp': verify_exp,
            }
        )
        return decoded["sub"]
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOKEN_EXPIRED",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    except jwt.JWTError as e:
        print('Erreur jwt: ', type(e).__name__, ": ", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invlide",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    except Exception as e:
        print('Erreur : ', type(e).__name__, ": ", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erreur générale !",
            headers={"WWW-Authenticate": "Bearer"}
            )
        
if __name__ == "__main__":
    token = jwt.encode({'a': 'b'}, 'secret'.encode(), algorithm='HS256')
    print(token)
    data = jwt.decode(token, "secret")
    print(data)