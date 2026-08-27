#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul  3 07:49:20 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))
import asyncio
from anti_phishing_ia.main_phish import AntiPhishing, get_ap_instance
from obsidian_hive.core.assets.workflows.workflow_base import WorkflowBase
from modules_utils.loop_utils import _run_async
from modules_utils.silence_utils import silence_output
from obsidian_hive.core.assets.asset_types import EmailAsset

class EmailWorkflow(WorkflowBase):
    def __init__(self, asset: EmailAsset, do_silence: bool = False, llm_manager=None):
        super().__init__(llm_manager=llm_manager)
        self.asset = asset
        self.result: dict | None = None
        self.do_silence = do_silence

    async def analyze(self) -> dict:
        ap: AntiPhishing = await asyncio.to_thread(
            get_ap_instance
        )

        if self.asset.input_type == "url":
            self.result = await ap.predict_url_async(
                self.asset.url,
                
            )
        else:
            self.result = await ap.predict_email_async(
                self.asset.raw_content
            )
        return self.result

    async def report(self, result: dict | None = None) -> dict:
        return result if result is not None else self.result

    async def run_async(self):
        async def _run():
            result = await self.analyze()
            return await self.report(result)
        
        if self.do_silence:
            with silence_output():
                return await _run()
        
        return await _run()

    def run(self):
        return _run_async(self.run_async)