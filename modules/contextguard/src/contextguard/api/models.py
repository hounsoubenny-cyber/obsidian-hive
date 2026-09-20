#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 11:27:09 2026

@author: hounsousamuel
"""

from pydantic import BaseModel

class LoginData(BaseModel):
    username: str
    password: str
    salt: str | None = None # ignoré
    connect: bool = False

class Data(BaseModel):
    username: str
    password: str
    salt: str | None = None # ignoré
    token: str 
    verify_connect:  bool = True

class RefreshData(BaseModel):
    username: str
    token: str
    salt: str | None = None # ignoré
    
class AnalyseRequest(BaseModel):
    username: str
    password: str
    salt: str | None = None # ignoré
    token: str 
    verify_connect: bool = True
    prompts: list[str] | str = [""]
    thresholds: list[float] | float = [0.5]

class LogoutData(BaseModel):
    username: str
    token: str


class DeleteAccountData(BaseModel):
    username: str
    password: str
    token: str
