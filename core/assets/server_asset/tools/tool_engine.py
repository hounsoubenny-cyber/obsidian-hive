#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 15:59:06 2026

@author: hounsousamuel
"""

import sys
import json5
import asyncio
from obsidian_hive.core.assets.server_asset.tools.server_asset_tools_type import ToolCall, ToolResult
from obsidian_hive.core.assets.server_asset.tools.tools import (
    server_agent_tools, tool_exists
)
from modules_utils.loop_utils import _run_async

async def exec_func(func, *args, **kwargs):
    r = func(*args, **kwargs)
    if asyncio.iscoroutine(r):
        r = await r
    return r

async def tool_engine(asset_id: str, tool_call: ToolCall):
    if tool_exists(tool_call.tool_name):
        tool = server_agent_tools.get_tool(tool_call.tool_name)
        entry_model = tool.__entry_model__ 
        entry_kwargs = list(entry_model.model_json_schema()["properties"].keys())
        if not entry_kwargs:
            args = {}
        else:
            args = {k : v for k, v in tool_call.tool_args.items() if k in entry_kwargs}
        try:
            result = await exec_func(tool, **args)
            error = None
        except Exception as e:
            error = f"{e!r}"
            result = None
        
        tool_result = ToolResult(
            tool_args=args,
            tool_name=tool_call.tool_name,
            call_id=tool_call.call_id,
            caller=tool_call.caller,
            result=result,
            error=error,
            asset_id=asset_id,
        )
        return tool_result
    
    else:
        return ToolResult(
            tool_args=tool_call.tool_args,
            tool_name=tool_call.tool_name,
            call_id=tool_call.call_id,
            caller=tool_call.caller,
            result=None,
            error="Tool not found",
            asset_id=asset_id,
        )

async def main():
    raw = sys.stdin.read()
    try:
        data = json5.loads(raw)
        asset_id = data["asset_id"]
        tool_call: ToolCall = ToolCall.model_validate(data["tool_call"])
        result = await tool_engine(asset_id, tool_call)
    except Exception as e:
        result = ToolResult(
            error=f"Erreur dans la lecture des données d'entrée: {e!r}"
        )
        
    sys.stdout.write(json5.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    sys.stdout.flush()
    return result

if __name__ == "__main__":
    _run_async(main)