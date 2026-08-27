#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug  8 23:57:07 2026

@author: hounsousamuel
"""

from uuid import uuid4
from pydantic import BaseModel, Field, model_validator
from typing import Dict, Any

class ToolResult(BaseModel):
    call_id: str | None = Field(default=None, description="Id de l'appel")
    tool_name: str | None = Field(default=None, description="Nom du tool appelé")
    tool_args: Dict[str, Any] | None= Field(default=None, description="Les arguments passés au tool call")
    asset_id: str | None = Field(default=None, description="ID de l'asset")
    result: Dict[str, Any] | None = Field(default=None, description="Résultat du tool call")
    error: str | None = Field(default=None, description="Erreur, optionnel, qui serait survenu lors de l'exec")
    caller: str | None = Field(default=None, description="Nom de l'appelant")

class ToolCall(BaseModel):
    call_id: str | None = Field(description="Id de l'appel", default=None)
    tool_name: str = Field(description="Nom du tool appelé")
    tool_args: Dict[str, Any] = Field(description="Les arguments passés au tool call")
    caller: str | None = Field(description="Nom de l'appelant")
    
    @model_validator(mode="after")
    def validate_model(self) -> "ToolCall":
        self.call_id = self.call_id or str(uuid4())
        return self
    
    