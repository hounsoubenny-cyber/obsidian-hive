#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 11 07:47:27 2026

@author: hounsousamuel
"""

from typing import Dict, List
from dotenv import load_dotenv
from obsidian_hive.config.config_manager import ConfigManager
from modules_utils.env_utils import getenv_required
load_dotenv()

_config_manager: ConfigManager = None

def _get_config_manager():
    global _config_manager
    if _config_manager is None:
        load_dotenv()
        _config_manager = ConfigManager()
        _config_manager.build_config(getenv_required("OBSIDIAN_CONFIG_FILE", help_text="Fichier de configuration"))
        
    return _config_manager


START_IDS_ON_START = _get_config_manager().global_config.start_ids_on_start

# engine
ENGINE_CONFIG: Dict = _get_config_manager().engine_config.model_dump()

#conf
IDS_CONF_REQUIRED_KEYS: List = _get_config_manager().global_config.ids_conf_required_keys

SCANNER_CONF_REQUIRED_KEYS: List = _get_config_manager().global_config.scanner_conf_required_keys

LLM_MANAGER_CONFIG: Dict = _get_config_manager().llm_manager_config.model_dump()

ANALYST_CONFIG: Dict = _get_config_manager().analyst_config.model_dump()

CORE_CONFIG: Dict = _get_config_manager().core_agent_config.model_dump()

MAX_AGE_DAYS_FOR_PENDING_DELETION = _get_config_manager().global_config.max_age_days_for_pending_deletion

TOOL_LOG_ARCHIVE_DIR = _get_config_manager().global_config.tool_log_archive_dir

TOOL_LOG_MAX_AGE_DAYS = _get_config_manager().global_config.tool_log_max_age_days