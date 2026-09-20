#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  7 07:50:10 2026

@author: hounsousamuel
"""

"""
ContextGuard SDK — Point d'entrée public.
"""

from contextguard.sdk.client import (
    ContextGuardClient,
    DEFAULT_API_URL,
    DEFAULT_CONNECT_PATH,
    DEFAULT_ANALYSE_PATH,
    DEFAULT_REFRESH_PATH,
    DEFAULT_HEALTH_PATH,
    DEFAULT_SALT_PATH,
    DEFAULT_TIMEOUT,
)
from contextguard.sdk.models import (
    SDKResponse,
    ConnectParams,
    ConnectResponse,
    AnalyseParams,
    AnalyseItem,
    AnalyseResponse,
    RefreshParams,
    RefreshResponse,
    HealthParams,
    HealthResponse,
    SaltParams,
    SaltResponse,
    USERNAME_NOT_AVAILABLE_REASON,
    TOKEN_USURPATION_DETAIL,
    VERIFY_CONNECT_ERROR,
    TOKEN_EXPIRED_DETAIL,
    USER_NOT_REGISTERED_REASON,
)

__author__ = "HOUNSOU Samuel Benny"
__version__ = "2.0.0"

__all__ = [
    "ContextGuardClient",
    "SDKResponse",
    "ConnectParams",
    "ConnectResponse",
    "AnalyseParams",
    "AnalyseItem",
    "AnalyseResponse",
    "RefreshParams",
    "RefreshResponse",
    "HealthParams",
    "HealthResponse",
    "SaltParams",
    "SaltResponse",
    "USERNAME_NOT_AVAILABLE_REASON",
    "TOKEN_USURPATION_DETAIL",
    "VERIFY_CONNECT_ERROR",
    "TOKEN_EXPIRED_DETAIL",
    "USER_NOT_REGISTERED_REASON",
    "DEFAULT_API_URL",
    "DEFAULT_CONNECT_PATH",
    "DEFAULT_ANALYSE_PATH",
    "DEFAULT_REFRESH_PATH",
    "DEFAULT_HEALTH_PATH",
    "DEFAULT_SALT_PATH",
    "DEFAULT_TIMEOUT",
]
