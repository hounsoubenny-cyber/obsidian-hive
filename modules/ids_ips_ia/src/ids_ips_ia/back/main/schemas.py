#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 06:58:47 2026

@author: hounsousamuel


Modèles Pydantic pour l'API IDS/IPS.
Extrait de api.py — aucune logique ici, juste la forme des données.
"""

from pydantic import BaseModel


class Data(BaseModel):
    username: str
    password: str


class Conf(BaseModel):
    key: str
    data: dict
    username: str
    password: str
    token: str


class UnlockData(BaseModel):
    input: bool
    rule: str
    whitelist: str = 'false'
    ip: str = ""
    username: str
    password: str
    token: str


class WhitelistData(BaseModel):
    add: bool = True
    ip: str = ""
    token: str
    username: str
    password: str


class BasicData(BaseModel):
    username: str
    token: str


class ChangeModeData(BaseModel):
    username: str
    password: str
    token: str
    mode: str


class BlockIPData(BaseModel):
    username: str
    password: str
    token: str
    input: bool
    rule: str
    ip: str = ""
    timeout: int = 3600


class IgnoreIPData(BaseModel):
    ip: str
    direction: str          # "src" ou "dst"
    add: bool = True        # True = ajouter, False = retirer
    username: str
    password: str
    token: str