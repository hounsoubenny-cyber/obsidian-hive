#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 13:55:45 2026

@author: hounsousamuel
"""


import os
from typing import Optional
from modules_utils.validate_config import ConfigError, validate_and_merge_config as _validate_and_merge_config

def validate_and_merge_config(
    user_config_str: str, 
    default_config_path: str,
    config_temp_dir:str,
    scan_id:str,
    max_size: int = 20 * 1024,
    write_path: str | None = None,
    check_size: bool = True,
) -> Optional[str]:
    return _validate_and_merge_config(
        user_config_str=user_config_str,
        default_config_path=default_config_path,
        config_temp_dir=config_temp_dir,
        id=scan_id,
        max_size=max_size,
        check_size=check_size,
        write_path=write_path
    )