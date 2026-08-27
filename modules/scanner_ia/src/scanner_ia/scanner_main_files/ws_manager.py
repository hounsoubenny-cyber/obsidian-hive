#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 20:43:12 2026

@author: hounsousamuel
"""

from fastapi import WebSocket, status, WebSocketDisconnect

class WSManager:
    def __init__(self):
        self._scans: dict[str, WebSocket] = {}
        self._scans_id = []
        self._session_id = {}
        self.messages = {}
        
    async def connect(self, scan_id:str, websocket:WebSocket):
        if not self.is_register(scan_id):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Veuillez donner votre scan task id")
            raise WebSocketDisconnect(
                code=status.WS_1008_POLICY_VIOLATION, reason="Veuillez donner votre scan task id"
            )
        await websocket.accept()
        self._scans[scan_id] = websocket
        return True
    
    def register(self, scan_id:str):
        self._scans_id.append(scan_id)
        # print(scan_id, "registred", self._scans_id)
        return True

    def is_register(self, scan_id:str):
        return str(scan_id) in self._scans_id
    
    async def disconnect(self, scan_id: str):
        """Ferme le WebSocket mais garde le scan_id enregistré."""
        if scan_id in self._scans:
            await self._scans[scan_id].close()
            self._scans.pop(scan_id)
        return True

    def unregister(self, scan_id: str):
        """Supprime définitivement le scan_id du registre."""
        if scan_id in self._scans_id:
            self._scans_id.remove(scan_id)
            
    async def send(self, scan_id:str, message:str|dict, type:str = "log"):
        if self.is_register(scan_id) and scan_id in self._scans:
            if self.messages.get(scan_id):
                for msg in self.messages[scan_id]:
                    await self._scans[scan_id].send_json(
                        {**msg}
                    )
                    self.messages[scan_id] = []
            await self._scans[scan_id].send_json(
                {
                    "message": message,
                    "type": type
                }
            )
        else:
            self.messages.setdefault(scan_id, []).append({
                "message": message,
                "type": type
            })
    