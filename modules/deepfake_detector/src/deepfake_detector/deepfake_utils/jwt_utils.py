#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 09:19:02 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from jose import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from deepfake_detector.api.api_config import NOT_BEFORE, EXP

def create_token(data:dict, key:bytes|str):
    try:
        iat = datetime.utcnow()
        jwt_data = {
            "sub": data["username"],
            "iat": iat,
            "exp": iat + timedelta(minutes=EXP), #timedelta(seconds=EXP),
            "nbf": iat + timedelta(seconds=NOT_BEFORE)
            }
        token = jwt.encode(jwt_data, key=key, algorithm=jwt.ALGORITHMS.HS256, )
        return token
    except Exception as e:
        print("Erreur dans la création du token jwt :", str(e))

def verify_token(token:str, key:bytes|str, verify_exp:bool = True):
    try:
        decoded = jwt.decode(
            token, key, 
            algorithms=[jwt.ALGORITHMS.HS256], 
            options={
            'verify_exp': verify_exp,
            }
        )
        return decoded["sub"]
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOKEN_EXPIRED",
            headers={"WWW-Authenticate": "Baerer"}
        )
        
    except jwt.JWTError as e:
        print('Erreur jwt: ', type(e).__name__, ": ", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invlaide",
            headers={"WWW-Authenticate": "Baerer"}
        )
    
    except Exception as e:
        print('Erreur : ', type(e).__name__, ": ", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erreur générale !",
            headers={"WWW-Authenticate": "Baerer"}
            )
        
if __name__ == "__main__":
    token = jwt.encode({'a': 'b'}, 'secret'.encode(), algorithm='HS256')
    print(token)
    data = jwt.decode(token, "secret")
    print(data)