#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:06:55 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi import status, HTTPException, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from simulateur_attaque_ia.orchestrator.orchestrator_env import get_data
from simulateur_attaque_ia.simulateur_utils.cryto_utils import checkpw
from simulateur_attaque_ia.simulateur_utils.jwt_utils import verify_token, create_token
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.orchestrator.ws_manager import WSManager

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Dashbord Orchestrator lancé")
    yield
    print("Fermeture")

app = FastAPI(
    lifespan=lifespan,
    version="2.0.0",
    docs_url='/api/docs',
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_methods=["*"],
    allow_credentials=True,
    allow_origins=[
        "*"
        # "http://localhost:3000", "http://localhost:3001"
        # "http://0.0.0.0:3000", "http://0.0.0.0:3001"
        # "http://127.0.0.1:3000", "http://127.0.0.1:3001",
        # "http://127.0.0.1:3000"
    ],
    allow_headers=['*'],
)

router = APIRouter()
ADMIN_DATA = get_data()
_WS_MANAGER = None

def get_ws_manager():
    global _WS_MANAGER
    if _WS_MANAGER:
        return _WS_MANAGER
    _WS_MANAGER = WSManager()
    return _WS_MANAGER

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

@router.post("/login")
@limiter.limit(f"{LIMITE}/minute")
async def _login(request: Request, login_data:LoginData):
    try:
        username = login_data.username
        password = login_data.password
        check_creds(username, password)
        return {"succes": True, "token": create_token({"username": username}, ADMIN_DATA["jwt_key"])}
    
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
        return {"succes": True, "token": create_token({"username": username}, ADMIN_DATA["jwt_key"])}
    
    except HTTPException:
        raise
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )










