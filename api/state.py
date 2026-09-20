#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 17:16:55 2026

@author: hounsousamuel
"""

import asyncio
from typing import Optional
from contextguard.sdk.client import ContextGuardClient
from modules_utils.api_dependencies import AuthManager
from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.assets.workflows.workflow_base import WorkflowBase
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.managers.conversation_manager import ConversationManager
from obsidian_hive.core.managers.extension_token_manager import ExtensionTokenManager
from obsidian_hive.config.config import (
    LLM_MANAGER_CONFIG, ENGINE_CONFIG,
)
from obsidian_hive.api.ap_config import (
    EXP, NOT_BEFORE,
    USER_ENV_KEY, PASSWD_ENV_KEY, 
    SECRET_KEY_ENV_KEY, BASE_URL
)

_auth_manager: Optional[AuthManager] = None

_shared_llm_manager: Optional[LLMManager] = None

_shared_llm_manager_is_set: bool = False

_shared_report_manager: Optional[ReportManager] = None

_shared_report_manager_is_set: bool = False

_shared_conversation_manager: Optional[ConversationManager] = None

_shared_extension_token_manager: Optional[ExtensionTokenManager] = None


_shared_job_manager: Optional[JobManager] = None

_context_guard_client: Optional[ContextGuardClient] = None

_context_guard_client_lock = asyncio.Lock()

def _get_auth_manager() -> AuthManager:
    """
    Retourne l'instance singleton du gestionnaire d'authentification.

    Returns:
        AuthManager: L'instance du gestionnaire d'authentification.
    """
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager(
            exp=EXP,
            not_before=NOT_BEFORE,
            user_env_key=USER_ENV_KEY,
            passwd_env_key=PASSWD_ENV_KEY,
            secret_key_env_key=SECRET_KEY_ENV_KEY,
        )
        _auth_manager.verify_env_utils()
    return _auth_manager


def _get_llm_manager():
    """
    Retourne l'instance singleton du gestionnaire LLM.

    Returns:
        LLMManager: L'instance du gestionnaire LLM.
    """
    global _shared_llm_manager, _shared_llm_manager_is_set
    if not _shared_llm_manager:
        _shared_llm_manager = LLMManager(
            **LLM_MANAGER_CONFIG
        )
    if not _shared_llm_manager_is_set:
        WorkflowBase.set_llm_manager(_shared_llm_manager)
        _shared_llm_manager_is_set = True
    return _shared_llm_manager


async def _get_report_manager():
    """
    Retourne l'instance singleton du gestionnaire de rapports.

    Returns:
        ReportManager: L'instance du gestionnaire de rapports.
    """
    global _shared_report_manager, _shared_report_manager_is_set
    if not _shared_report_manager:
        _shared_report_manager = ReportManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_report_manager.init_db()
    if not _shared_report_manager_is_set:
        WorkflowBase.set_report_manager(_shared_report_manager)
        _shared_report_manager_is_set = True
    return _shared_report_manager


async def _get_job_manager():
    """
    Retourne l'instance singleton du gestionnaire de jobs.

    Returns:
        JobManager: L'instance du gestionnaire de jobs.
    """
    global _shared_job_manager
    if not _shared_job_manager:
        _shared_job_manager = JobManager(db_url=ENGINE_CONFIG["db_url"]) 
        _shared_job_manager.start()
    return _shared_job_manager


async def _get_conversation_manager():
    """
    Retourne l'instance singleton du gestionnaire de conversations.

    Returns:
        ConversationManager: L'instance du gestionnaire de conversations.
    """
    global _shared_conversation_manager
    if not _shared_conversation_manager:
        _shared_conversation_manager = ConversationManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_conversation_manager.init_db()
    return _shared_conversation_manager

async def _get_extension_token_manager():
    global _shared_extension_token_manager
    if not _shared_extension_token_manager:
        _shared_extension_token_manager = ExtensionTokenManager(db_url=ENGINE_CONFIG["db_url"]) 
        await _shared_extension_token_manager.init_db()
    return _shared_extension_token_manager

def get_contextguard_client_kwargs():
    from contextguard.sdk.client import (
        DEFAULT_ANALYSE_PATH, DEFAULT_DELETE_ACCOUNT_PATH, DEFAULT_HEALTH_PATH,
        DEFAULT_CONNECT_PATH, DEFAULT_LOGOUT_PATH, DEFAULT_REFRESH_PATH, DEFAULT_SALT_PATH,
        DEFAULT_TIMEOUT
    )
    from functools import partial
    
    def get_base(path: str): return path.split("/")[-1]
    def join(base: str, path: str):
        base = base.rstrip("/")
        path = path.strip("/")
        return f"{base}/{path}"
    
    prefix = "/api/contextguard"
    partial_join = partial(join, base=prefix)
    
    return dict(
        api_url=BASE_URL.rstrip("/"),
        connect_path=partial_join(path=get_base(DEFAULT_CONNECT_PATH)),
        analyse_path=partial_join(path=get_base(DEFAULT_ANALYSE_PATH)),
        refresh_path=partial_join(path=get_base(DEFAULT_REFRESH_PATH)),
        health_path=partial_join(path=get_base(DEFAULT_HEALTH_PATH)),
        salt_path=partial_join(path=get_base(DEFAULT_SALT_PATH)),
        logout_path=partial_join(path=get_base(DEFAULT_LOGOUT_PATH)),
        delete_account_path=partial_join(path=get_base(DEFAULT_DELETE_ACCOUNT_PATH)),
        timeout=DEFAULT_TIMEOUT,
        username=_get_auth_manager()._user,
        password=_get_auth_manager()._passwd
    )

def build_contextguard_client():
    client = ContextGuardClient(
        **get_contextguard_client_kwargs()
    )
    return client

async def _get_contextguard_client():
    global _context_guard_client
    async with _context_guard_client_lock:
        if not _context_guard_client:
            _context_guard_client = build_contextguard_client()
            conn = await _context_guard_client.connect(
                intelligent=True
            )
            if not conn.success:
                raise RuntimeError(f"ContextGuard : connexion impossible — {conn.errors}")
        
        if not _context_guard_client.connected:
            conn = await _context_guard_client.connect(
                intelligent=True
            )
            conn = await _context_guard_client.connect(
                intelligent=True
            )
            if not conn.success:
                raise RuntimeError(f"ContextGuard : connexion impossible — {conn.errors}")
        
        return _context_guard_client