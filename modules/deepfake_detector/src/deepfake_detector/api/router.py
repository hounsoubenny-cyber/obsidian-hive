#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 09:16:09 2026

@author: hounsousamuel
"""


import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import asyncio
import base64
from fastapi import APIRouter, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from deepfake_detector.database.database import DBManager
from deepfake_detector.api.fernet_manager import FernetManager, checkpw, hashpw
from deepfake_detector.api.jwt_utils import create_token, verify_token
from deepfake_detector.api.limiter import limiter
from deepfake_detector.api.utils import verify_salt
from deepfake_detector.api.api_config import LIMITE as limite
from diskcache import Cache

USERS = Cache(".user_cache")
TTL = None
_BAERER = HTTPBearer()
_DB = None
_MODEL = None
_ONNX_MODEL = None
router = APIRouter()


class LoginData(BaseModel):
    username:str
    password:str
    salt:str|None
    connect:bool = False

class Data(BaseModel):
    username:str
    password:str
    salt:str|None
    token:str 
    verify_connect:bool = True

class RefreshData(BaseModel):
    username:str
    token:str
    salt:str
    
class AnalyseRequest(BaseModel):
    username:str
    password:str
    salt:str
    token:str 
    verify_connect:bool = True
    prompts:list[str]|str = [""]
    threasholds:list[float]|float = [0.5]
    
def get_db():
    global _DB
    if not _DB:
        _DB = DBManager()
        
    return _DB

def verify_username_is_avalable(name:str) -> bool:
    try:
        db = get_db()
        users = db.get_user_by_name(name)
        # print(users, "\n\n")
        if users["user"]:
            return False
        
        return True
    except Exception as e:
        print("Erreur dans vérify username :", str(e))
        return True

def verify_username(name:str, token:str, verify_exp:bool = True, verify_connect:bool = True) -> bool:
    if verify_connect:
        if not (name in USERS):
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail="Username inconnue, veuillez vous authentifier d'abord"
                )
    else:
        key = USERS.get(name)
        sub = verify_token(token, key, verify_exp=verify_exp)
        if sub != name:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail="Le propriétaire du token n'est pas celui qui fait la demande"
                )
    return True

        
@router.post("/login")
@limiter.limit(f"{limite}/minute")
async def login(request: Request, login_data:LoginData):
    try:
        password = login_data.password
        name = login_data.username
        salt = login_data.salt
        connect = login_data.connect
        db = get_db()
        if not salt:
            salt = FernetManager._gen_salt()
            
        if not verify_salt(salt):
            raise HTTPException(
                detail="Salt invalide !",
                status_code=status.HTTP_406_NOT_ACCEPTABLE
            )
        if not connect: #Login
            if not verify_username_is_avalable(name):
                response = {
                    "state": "Unknow",
                    "success": False,
                    "username": name,
                    "reason": "Username is not available",
                    "salt": "Pas de salt",
                    "token": "Pas de token"
                    }
                return JSONResponse(response, status_code=status.HTTP_200_OK)
            
            result = db.add_user(
                username=name,
                password=hashpw(password),
                )    
            USERS.set(key=name, value=salt, expire=TTL)
            return JSONResponse({
                "state": "new user",
                "username": name,
                "success": result["success"],
                "reason": "",
                "salt": str(salt),
                "token": create_token(data={"username": name}, key=salt)
                })
        else:
            result = db.get_user_by_name(name)
            if result["error"]:
                raise HTTPException(
                    detail=f"Erreur serveur : {result['error']}",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                
            if result["user"] and result["success"]:
                user = result["user"][0]
                if not checkpw(password, hashed=user.password):
                    raise HTTPException(
                        detail="Mot de passe incorrect !",
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        )
                
                USERS.set(key=name, value=salt, expire=TTL)
                return JSONResponse({
                    "state": "old user",
                    "username": name,
                    "success": result["success"],
                    "reason": "",
                    "salt": salt,
                    "token": create_token(data={"username": name}, key=salt)
                    })
                
            else:
                return JSONResponse({
                    "state": "Unknow",
                    "success": False,
                    "reason": "Veuillez creer un compte, vous n'êtes pas enrégistré dans la base de donné !",
                    "salt": "Pas de salt",
                    "token": "Pas de token"
                    })
    
    except HTTPException as e:
        raise e
        
    except Exception as e:
        print("Erreur dans la route login :", str(e))
        raise HTTPException(
            detail=f"Erreur dans login : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST
            )
        
@router.post("/refresh_token")          
async def _refresh_token(
    request:Request,
    data:RefreshData
):
    try:
        username = data.username
        token = data.token
        salt = data.salt
        if verify_username(name=username, token=token, verify_exp=False, verify_connect=False):
            return  {
                "token": create_token({"username": username}, key=salt)
            }
        raise HTTPException(
            detail="Erreur refresh token !",
            status_code=406
        )
    except Exception:
        raise
        
            