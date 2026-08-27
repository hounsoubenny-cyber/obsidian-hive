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
from contextguard.core.database import DBManager
from contextguard.core.fernet_manager import FernetManager, checkpw, hashpw
from contextguard.core.jwt_utils import create_token, verify_token
from contextguard.core.limiter import limiter
from contextguard.model.model_guard import PredictWrapper, ContextGuardModel
from contextguard.core.utils import verify_salt
from contextguard.config import LIMITE as limite, MODEL_PATH, TOKENIZER_PATH, MATCH, ONNX_PATH, USE_ONNX
from diskcache import Cache
from collections import Counter
from transformers import BertTokenizer
from contextguard.model.onnx_utils import ONNXUtils

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

def get_onnx():
    global _ONNX_MODEL
    if not _ONNX_MODEL:
        _ONNX_MODEL = ONNXUtils()
    
    return _ONNX_MODEL

def get_model():
    global _MODEL
    if not _MODEL:
        tokenizer = BertTokenizer.from_pretrained(TOKENIZER_PATH)
        model = ContextGuardModel(
            vocab_size=tokenizer.vocab_size,
            d_model=128, max_seq_len=128,
            num_heads=4, feed_forward_factor=4,
            dropout=0.2, num_layer=3, num_classe=4
        )
        model.load(MODEL_PATH)
        model.eval()
        _MODEL = PredictWrapper(tokenizer, model)
        
    return _MODEL


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
        
@router.post("/health")
@limiter.limit(f"{limite}/minute")
async def health(
    request:Request, 
    data: Data,
):
    try:
        token = data.token
        password = data.password
        name = data.username
        salt = data.salt
        db = get_db()
        result = db.get_user_by_name(name)
        verify_connect = data.verify_connect
        if not verify_salt(salt):
            raise HTTPException(
                detail="Salt invalide !",
                status_code=status.HTTP_406_NOT_ACCEPTABLE
            )
            
        if not verify_username(name, token, verify_connect=verify_connect):
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail="User non authorisé !"
                )
            
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
            history_crypted = user.history
            history = {}
            fm = FernetManager(password, salt)
            for k, v in history_crypted.items():
                if isinstance(v, str) and v:
                    v = fm.decrypt(base64.b64decode(v.encode())).decode()
                history[k] = v
            
            return JSONResponse({
                "history": history,
                "username": name,
                "num_analyse": len(history),
                "stats": dict(Counter(list(history.values())))
                })
        
        else:
            raise HTTPException(
                detail="Vous n'êtes pas enrégistré, veuillez vous authentifier !",
                status_code=status.HTTP_401_UNAUTHORIZED
                )
    
    except HTTPException as e:
        raise e
        
    except Exception as e:
        print("Erreur dans la route health :", str(e))
        import traceback
        traceback.print_exc()
        raise HTTPException(
            detail=f"Erreur dans health : {str(e)}",
            status_code=status.HTTP_400_BAD_REQUEST
            )

async def _analyse_one(model:PredictWrapper, prompt:str, threashold):
    prob, pred = model.predict(prompt, threashold, USE_ONNX, get_onnx(), ONNX_PATH)
    if isinstance(pred, list):
        return prompt, prob[0], MATCH[pred[0]]
    pred = pred[0].item()
    prob = prob[0][pred].item()
    label = MATCH[pred]
    return prompt, prob, label
    
@router.post("/analyse")
@limiter.limit(f"{limite + 20}/minute")
async def analyse(
    request:Request,
    analyse_data: AnalyseRequest,
):
    try:
        token = analyse_data.token
        password = analyse_data.password
        name = analyse_data.username
        salt = analyse_data.salt
        verify_connect = analyse_data.verify_connect
        if not verify_salt(salt):
            raise HTTPException(
                detail="Salt invalide !",
                status_code=status.HTTP_406_NOT_ACCEPTABLE
            )
        if not verify_username(name, token, verify_connect=verify_connect):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User non authorisé !"
                )
        
        fernet = FernetManager(password, salt)
        prompts = analyse_data.prompts
        threasholds = analyse_data.threasholds
        model = get_model()
        db = get_db()
        if not isinstance(prompts, list) :
            prompts = [prompts]
        
        if not isinstance(threasholds, list) :
            threasholds = [threasholds for _ in range(len(prompts))]
        
        threasholds = [th if 0 <= th <= 1 else 0.5 for th in threasholds]
                
        tasks = [
            asyncio.create_task(_analyse_one(model, prompt, threashold))
            for prompt, threashold in zip(prompts, threasholds)
        ]
        
        gather_result = await asyncio.gather(*tasks, return_exceptions=True)
        results = {}
        history = {}
        for prompt, threashold, result in zip(prompts, threasholds, gather_result):
            results[prompt] = {
                "threashold": threashold
                }
            if isinstance(result, Exception):
                results[prompt]["label"] = "error"
                results[prompt]["prob"] = 1.0
            else:
                _, prob, label = result
                results[prompt]["label"] = label
                results[prompt]["prob"] = prob
                history[prompt] = base64.b64encode(fernet.encrypt(label)).decode()
                
        db_result = db.update_history_by_name(name, history)
        
        return JSONResponse({
            "result": results,
            "history_update_with_success": db_result["success"]
            })
    
    except HTTPException as e:
        import traceback
        traceback.print_exc()
        print(e)
        raise e
        
    except Exception as e:
        print("Erreur dans la route analyse :", str(e))
        raise HTTPException(
            detail=f"Erreur dans analyse : {str(e)}",
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
        
            