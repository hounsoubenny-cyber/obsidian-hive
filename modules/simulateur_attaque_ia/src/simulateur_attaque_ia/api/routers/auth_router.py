#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from fastapi import APIRouter, HTTPException, status, Request

from simulateur_attaque_ia.simulateur_utils.cryto_utils import checkpw
from simulateur_attaque_ia.simulateur_utils.jwt_utils import create_token
from simulateur_attaque_ia.api.models.sim_models import LoginRequest, LoginResponse
from simulateur_attaque_ia.api.routers import AUTH_DATA, JWT_KEY
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE

auth_router = APIRouter()

def check_creds(username, password, data):
    if checkpw(username, data["username"]) and checkpw(password, data["password"]):
        return True
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Identifiants incorrects.",
    )
    
@limiter.limit(f"{LIMITE}/minute")
@auth_router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authentification",
    description="Retourne un JWT Bearer à utiliser dans le header `Authorization: Bearer <token>`.",
)
async def login(request: Request, login_data: LoginRequest) -> LoginResponse:
    username = login_data.username
    password = login_data.password
    check_creds(username, password, AUTH_DATA)
    token = create_token({"username": username}, AUTH_DATA[JWT_KEY])
    return LoginResponse(success=True, token=token, message="Authentification réussie.")
