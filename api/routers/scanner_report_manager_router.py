#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug 29 15:35:04 2026

@author: hounsousamuel
"""

import os
from datetime import datetime
from fastapi import HTTPException, APIRouter, Request
from obsidian_hive.core.assets.config import WEB_ASSET_SCAN_REPORT_DIR
from obsidian_hive.core.assets.workflows.web_workflow import DATE_FORMAT
from obsidian_hive.api.api_utils.core_shared import _server_error, get_engine
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE

router = APIRouter()
MOUNT_PATH = "/api/web_asset_scan_report"

@limiter.limit(f"{LIMITE}/minute")
@router.get("/scanner_report/{id}")
async def list_scanner_report(request: Request, id: str, limit: int | None = None):
    try:
        engine = get_engine()
        asset = await engine.asset_manager.get_by_identifier(id,first=True)
        if not asset:
            return {
                "found": False,
                "result": None
            }
        
        results = {}
        for fmt, subdir in [("html", "HTML"), ("json", "JSON"), ("pdf", "PDF"), ("llm", "LLM_REPORT")]:
            folder = os.path.join(WEB_ASSET_SCAN_REPORT_DIR, id, subdir)
            if os.path.exists(folder) and os.path.isdir(folder):
                r = {}
                for file in os.listdir(folder):
                    try:
                        _, date, expected_id, time_monotonic = os.path.splitext(file)[0].split("|@")
                    except ValueError:
                        continue
                    
                    if expected_id == id:
                        r[file] = {
                            "date": datetime.strptime(date, DATE_FORMAT),
                            "time_monotonic": time_monotonic,
                            "path_in_api": f"{MOUNT_PATH}/{id}/{subdir}/{file}"
                        }
                results[fmt] = r
            else:
                results[fmt] = None
                
        return results
    
    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)