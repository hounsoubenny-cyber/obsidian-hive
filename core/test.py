#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 26 14:42:26 2026

@author: hounsousamuel
"""

import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from obsidian_hive.core.managers.asset_manager import AssetManager
from obsidian_hive.core.managers.task_manager import TaskManager
from obsidian_hive.core.managers.workflow_manager import WorkflowManager
from obsidian_hive.core.assets.asset_types import WebAsset


async def test():
    try:
        r, w = None, None
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name
        db_url = f"sqlite+aiosqlite:///{db_path}"
        print(f"\n📁 Base de données: {db_path}")
        
        # 2. Initialiser le manager
        manager = AssetManager(db_url)
        await manager.init_db()
        print("✅ Base initialisée")
        init_config = {
            
        }
        run_config = {
            "limit_vuln_for_fuzzer": 4,
            "max_test": 10,
            "helpers": [
                {
                    "name": "dvwa_auth",
                    "kwargs": {
                        "base_url":       "http://localhost:8080",
                        "username":       "admin",
                        "password":       "password",
                        "security_level": "low",
                    }
                }
            ],
            "raise_on_helper_error": True,
        }
        w = WorkflowManager(task_manager=TaskManager(), do_silence=True)
        asset = WebAsset(
            run_config=run_config,
            init_config=init_config,
            url="http://localhost:8080",
            name="DVWA",
            every=100
        )
        r = await w.manage_async(asset=asset)
        import asyncio
        while True:
            try:
                await asyncio.sleep(1)
                print("I'm here", end="\r")
            except KeyboardInterrupt:
                break
    except Exception:
        pass
    
    return r, w

if __name__ == "__main__":
    import asyncio
    r, w = asyncio.run(test())
        
    
