#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug  8 23:50:47 2026

@author: hounsousamuel
"""

import json
import asyncio
from fastapi import WebSocket
from typing import Dict, Any
from uuid import uuid4
from obsidian_hive.core.assets.server_asset.tools.server_asset_tools_type import ToolResult, ToolCall

class ServerAgentConnection:
    def __init__(self, ws: WebSocket, asset_id: str):
        self.asset_id = asset_id
        self.ws = ws
        self._pending_calls: Dict[str, asyncio.Future[ToolResult]] = {}
    
    async def send(self, data: Any):
        try:
            payload = json.dumps(data, default=str, ensure_ascii=False)
            await self.ws.send_text(payload)
            return True
        except Exception as e:
            print(f"Erreur send({self.asset_id!r}): {e}")
            return False
    
    async def send_command(self, tool_call: ToolCall, timeout:float | None = None) -> None | ToolResult:
        tool_call.call_id = tool_call.call_id or str(uuid4())
        fut: asyncio.Future[ToolResult] = asyncio.get_running_loop().create_future()
        self._pending_calls[tool_call.call_id] = fut
        try:
            data = {
                "type": "tool_call",
                "asset_id": self.asset_id,
                "tool_call": tool_call.model_dump(mode="json")
            }
            send_result = await self.send(data)
            if send_result:
                if timeout is None:
                    return await fut
                else:
                    return await asyncio.wait_for(fut, timeout)
            
            return None
        
        except Exception as e:
            print(f"Erreur dans l'envoie de la commande a {self.asset_id}: {e!r}")
            return None
        
        finally:
            self._pending_calls.pop(tool_call.call_id, None)
        
    async def resolve_command(self, tool_result: ToolResult):
        fut = self._pending_calls.get(tool_result.call_id)
        if fut is None or fut.done():
            print(f"resolve_command reçu pour {tool_result.call_id} inconnu ou déjà résolu")
            return False
        fut.set_result(tool_result)
        return True
    
    def pending_count(self) -> int:
        return len(self._pending_calls)

class ServerAgentWSManager:
    def __init__(self):
        self._connections: dict[str, ServerAgentConnection] = {} 
        self._pending_acks: dict[str, asyncio.Event] = {} 
        
    def register_pending_ack(self, asset_id: str) -> asyncio.Event:
        event = asyncio.Event()
        self._pending_acks[asset_id] = event
        return event

    def resolve_pending_ack(self, asset_id: str):
        event = self._pending_acks.get(asset_id)
        if event:
            event.set()

    def clear_pending_ack(self, asset_id: str):
        self._pending_acks.pop(asset_id, None)
        
    def connect(self, asset_id: str, ws: WebSocket) -> ServerAgentConnection:
        conn = ServerAgentConnection(ws=ws, asset_id=asset_id)
        self._connections[asset_id] = conn
        return conn

    def disconnect(self, asset_id: str, conn: ServerAgentConnection | None = None):
        if conn is not None and self._connections.get(asset_id) is not conn:
            return
        self._connections.pop(asset_id, None)

    def is_connected(self, asset_id: str) -> bool:
        return asset_id in self._connections
    
    async def send_to(self, asset_id: str, data: dict) -> bool:
        agent_conn = self._connections.get(asset_id)
        if agent_conn is None:
            return False
        
        r = await agent_conn.send(data)
        if not r:
            self.disconnect(asset_id, agent_conn)
            return False
        return True
    
    async def send_command_to(self, asset_id: str, tool_call: ToolCall, timeout: float | None = None) -> bool:
        agent_conn = self._connections.get(asset_id)
        if agent_conn is None:
            return False
        
        return await agent_conn.send_command(tool_call=tool_call, timeout=timeout)
    
    async def resolve_command(self, asset_id: str, tool_result: ToolResult):
        agent_conn = self._connections.get(asset_id)
        if agent_conn is None:
            return None
        
        return await agent_conn.resolve_command(tool_result)
    
    def get(self, asset_id: str) -> ServerAgentConnection | None:
        return self._connections.get(asset_id)

    async def broadcast(self, data: dict) -> int:
        sent = 0
        for server_agent_connection in list(self._connections.values()):
            if await server_agent_connection.send(data):
                sent += 1
        return sent
        
        