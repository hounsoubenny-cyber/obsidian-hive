#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 10:43:32 2026

@author: hounsousamuel
"""

import asyncio

class ScannerTaskManager:
    def __init__(self):
        self.SCANS_TASK: dict[str, dict[str, str|bool|asyncio.Task]] = {}
        self.CANCEL_TASK:dict[str, asyncio.Task] = {}
        
    async def add_task(self, coro, scan_id:str):
        self.SCANS_TASK.setdefault(scan_id, {})["task"] = asyncio.create_task(coro=coro, name=scan_id)
    
    async def cancel_task(self, scan_id:str):
        if scan_id in self.SCANS_TASK:
            try:
                self.SCANS_TASK[scan_id]["task"].cancel()
                await self.SCANS_TASK[scan_id]["task"]
            except asyncio.CancelledError:
                pass
            
            except Exception:
                pass
    
    async def suppress_scan_task(self, scan_id:str):
        if scan_id in self.SCANS_TASK:
            await self.cancel_task(scan_id)
            del self.SCANS_TASK[scan_id]
    
    async def add_cancel_task(self, scan_id:str, timeout:float = 60):
        if scan_id in self.SCANS_TASK:
            async def cancel_task():
                await asyncio.sleep(timeout)
                await self.cancel_task(scan_id)
            
            self.CANCEL_TASK[scan_id] = asyncio.create_task(cancel_task())
    
    async def cancel_cancelling_task(self, scan_id:str):
        if scan_id in self.CANCEL_TASK:
            try:
                self.CANCEL_TASK[scan_id].cancel()
                await self.CANCEL_TASK[scan_id]
            except asyncio.CancelledError:
                pass
            
            except Exception:
                pass
    
    def get_scan_task(self, scan_id:str):
        return self.SCANS_TASK.get(scan_id, None)
            
            
    
    
    
        