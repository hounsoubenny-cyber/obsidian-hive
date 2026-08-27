#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:06:55 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from uuid import uuid4
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi import status, HTTPException, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from simulateur_attaque_ia.orchestrator.orchestrator_env import get_data
from simulateur_attaque_ia.simulateur_utils.cryto_utils import checkpw
from simulateur_attaque_ia.simulateur_utils.jwt_utils import verify_token, create_token
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.simulateur_utils.ids_utils import random_session_id
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.orchestrator.ws_manager import WSManager as DashWSManager

router = APIRouter()
ADMIN_DATA = get_data()
_DASH_WS_MANAGER = None

def get_ws_manager():
    global _DASH_WS_MANAGER
    if _DASH_WS_MANAGER:
        return _DASH_WS_MANAGER
    
    _DASH_WS_MANAGER = DashWSManager()
    return _DASH_WS_MANAGER

def check_creds(username, password):
    if checkpw(username, ADMIN_DATA["username"]) and checkpw(password, ADMIN_DATA["password"]):
        return True
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Username ou password incorrect"
    )
    
class LoginData(BaseModel):
    username:str
    password:str

class ValidateData(BaseModel):
    token:str

class SetSessionIdData(BaseModel):
    username:str
    password:str
    session_id:str
    user_id:str
    
class GetSessionIdData(BaseModel):
    username:str
    password:str
    user_id:str
    
@router.post("/login")
@limiter.limit(f"{LIMITE}/minute")
async def _login(request: Request, login_data:LoginData):
    try:
        username = login_data.username
        password = login_data.password
        check_creds(username, password)
        user_id = str(uuid4())
        get_ws_manager().register(user_id)
        return {
            "success": True, 
            "token": create_token({"username": username}, ADMIN_DATA["jwt_key"]),
            "user_id": user_id,
            "username": username,
        }
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/validate_token")
async def _validate_token(request: Request, data: ValidateData):
    try:
        verify_token(data.token, ADMIN_DATA["jwt_key"])
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/refresh_token")
@limiter.limit(f"{LIMITE}/minute")
async def _refresh_token(request: Request, data: ValidateData):
    try:
        username = verify_token(data.token, ADMIN_DATA["jwt_key"], verify_exp=False)
        return {
            "succes": True, 
            "token": create_token({"username": username}, ADMIN_DATA["jwt_key"]),
        }
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.websocket("/dashbord_ws")
async def _dashbord_ws(websocket:WebSocket, user_id:str=Query(...)):
    dash_ws_manager = get_ws_manager()
    try:
        await dash_ws_manager.connect(user_id, websocket)
        while True:
            # Attendre un message du client
            await websocket.receive_json()

        
    except (HTTPException, WebSocketDisconnect):
        raise
        
    except Exception as e:
        print("Erreur dans la route websocket : ", str(e))
        raise
    
    finally:
        await dash_ws_manager.disconnect(user_id)


@router.post("/set_session_id")
@limiter.limit(f"{LIMITE}/minute")
async def _set_session_id(request: Request, data:SetSessionIdData):
    try:
        username = data.username
        password = data.password
        check_creds(username, password)
        session_id = data.session_id
        user_id = data.user_id
        dashbord_ws = get_ws_manager()
        if dashbord_ws.is_register(user_id):
            success = dashbord_ws.set_session_id(user_id, session_id)
            return {
                "succes": success, 
            }
        raise HTTPException(
            detail="User not login",
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
        )
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/get_session_id")
@limiter.limit(f"{LIMITE}/minute")
async def _get_session_id_post(request: Request, data:GetSessionIdData):
    try:
        username = data.username
        password = data.password
        check_creds(username, password)
        user_id = data.user_id
        dashbord_ws = get_ws_manager()
        if dashbord_ws.is_register(user_id):
            session_id = dashbord_ws.get_session_id(user_id)
            return {
                "succes": True, 
                "have_session_id": session_id is not None,
                "session_id": session_id
            }
        raise HTTPException(
            detail="User not login",
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
        )
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
        
@router.get("/get_session_id")
@limiter.limit(f"{LIMITE}/minute")
async def _get_session_id_get(request: Request):
    return {
        "session_id": random_session_id()
    }