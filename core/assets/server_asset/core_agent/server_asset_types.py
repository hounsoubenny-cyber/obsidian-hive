#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 10 23:32:20 2026

@author: hounsousamuel
"""

from enum import StrEnum
from pydantic import BaseModel, Field

class RequestResponse(BaseModel):
    url: str 
    status_code: int
    reason_phrase: str | None = None
    elapsed: float | None = None
    headers: dict | None = None
    cookies: dict | None = None
    text: str | None = None
    body_json: dict | None = None
    history: list | None = None

class SendMsgType(StrEnum):
    HEARTBEAT = "heartbeat"
    TOOL_RESULT = "tool_result"
    
class ReceiveMsgType(StrEnum):
    HEARTBEAT_ACK = "heartbeat_ack"
    TOOL_CALL = "tool_call"
    SELF_DESTRCUT = "self_destruct"
    SECRET_ROTATED = "secret_rotated"
    REVOKED = "revoked"
    CONFIG_UPDATE = "config_update"
    CONFIG_RELOAD = "config_reload"