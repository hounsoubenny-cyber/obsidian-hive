#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug  8 23:56:57 2026

@author: hounsousamuel
"""

import os
import asyncio
import shlex
from modules_utils.func_utils import (
    get_func_kwargs as get_tool_kwargs
)
from obsidian_hive.core.assets.asset_types import Severity
from obsidian_hive.core.assets.server_asset.tools.utils import tool_policy
from modules_utils.pydantic_utils import entry_model
from obsidian_hive.core.assets.server_asset.tools.tools_model_entry import (
    GetSystemInfoEntry, ReadLogEntry, CheckServiceStatusEntry,
    ListDirectoryEntry, DiskUsageEntry, ListProcessesEntry, SearchInFileEntry,
    CheckOpenPortsEntry, ListLoggedInUsersEntry, LastLoginsEntry,
    NetworkInterfacesEntry, ListBlockDevicesEntry,
)
from modules_utils.agent_utils import timer
from modules_utils.safe_subprocess import safe_run, CommandNotAllowedError
from obsidian_hive.core.assets.server_asset.tools.allow_commands import SERVER_ALLOWED_COMMANDS
from obsidian_hive.core.assets.server_asset.core_agent.utils import get_system_info

def tool_exists(name: str) -> bool:
    return name in server_agent_tools.tools

def tool_risk(name: str) -> str:
    tool = server_agent_tools.tools.get(name)
    if tool is None:
        return "unknown"
    
    return getattr(tool, "__risk__", Severity.LOW.value) or Severity.LOW.value


def need_confirmation(name: str) -> bool:
    tool = server_agent_tools.tools.get(name)
    if tool is None:
        return True 
    return bool(getattr(tool, "__need_confirmation__", False))
    
def list_tools() -> list[dict]:
    result = []
    for name, func in server_agent_tools.get_tools().items():
        doc = (func.__doc__ or "").strip()
        # Extraire juste la première ligne de la docstring
        first_line = doc.split("\n")[0].strip() if doc else ""
        result.append(
            {
                "name": name,
                "description": first_line,
                "module": func.__module__,
                "args": get_tool_kwargs(func, exclude=["self", "args", "kwargs"])
            }
        )
    return result

async def asafe_run(*args, **kwargs):
    return await asyncio.to_thread(safe_run, *args, **kwargs)

class ServerAssetAgentTools:
    def __init__(self):
        self._tool_suffix = "_server_agent_tool"
        self.tools = {
            str(name).removesuffix(self._tool_suffix): getattr(
                self, name
            ) for name in dir(self) if str(name).endswith(self._tool_suffix)
        }
    
  
    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(GetSystemInfoEntry)
    @timer
    async def get_system_info_server_agent_tool(self):
        """Retourne les infos système de la machine hôte (OS, arch, hostname, python_version)."""
        return {
            "success": True,
            "result": {
                **get_system_info()
            },
            "error": None
        }

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(CheckServiceStatusEntry)
    @timer
    async def check_service_status_server_agent_tool(self, service_name: str):
        """Vérifie l'état d'un service systemd (active/inactive/failed...)."""
        try:
            kwargs = CheckServiceStatusEntry(service_name=service_name)
            result = await asafe_run(
                cmd=f"systemctl status {shlex.quote(kwargs.service_name)}",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {
                "success": result.get("success"),
                "result": result,
                "error": None
            }
        except CommandNotAllowedError as e:
            return {
                "success": False,
                "result": None,
                "error": str(e)
            }

    @tool_policy(risk_level=Severity.MEDIUM, need_confirmation=True)
    @entry_model(ReadLogEntry)
    @timer
    async def read_file_server_agent_tool(self, path: str, lines: int | None = None):
        """Lit les N dernières lignes d'un fichier."""
        try:
            kwargs = ReadLogEntry(
                path=os.path.expanduser(path) if path.startswith("~/") else path,
                lines=lines
            )
            if kwargs.lines is None:
                cmd = f"cat {shlex.quote(kwargs.path)}"
            else:
                cmd = f"tail -n {kwargs.lines} {shlex.quote(kwargs.path)}"
            result = await asafe_run(
                cmd=cmd,
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {
                "success": result.get("success"),
                "result": result,
                "error": None
            }
        except CommandNotAllowedError as e:
            return {
                "success": False,
                "result": None,
                "error": str(e)
            }
    
    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(ListDirectoryEntry)
    @timer
    async def list_directory_server_agent_tool(self, path: str):
        """Liste le contenu d'un répertoire (ls -la)."""
        try:
            kwargs = ListDirectoryEntry(path=path)
            result = await asafe_run(
                cmd=f"ls -la {shlex.quote(kwargs.path)}",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(DiskUsageEntry)
    @timer
    async def disk_usage_server_agent_tool(self, path: str = "/"):
        """Espace disque utilisé/disponible pour un point de montage (df -h)."""
        try:
            kwargs = DiskUsageEntry(path=path)
            result = await asafe_run(
                cmd=f"df -h {shlex.quote(kwargs.path)}",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.MEDIUM, need_confirmation=True)
    @entry_model(ListProcessesEntry)
    @timer
    async def list_processes_server_agent_tool(self):
        """
        Liste tous les processus en cours (ps aux). Confirmation requise :
        peut exposer des arguments de ligne de commande sensibles (certains
        outils mal conçus passent des secrets en argument, visibles ici).
        """
        try:
            result = await asafe_run(
                cmd="ps aux",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.MEDIUM, need_confirmation=True)
    @entry_model(SearchInFileEntry)
    @timer
    async def search_in_file_server_agent_tool(self, path: str, pattern: str):
        """
        Recherche un motif dans un fichier (grep -n). Confirmation requise :
        même raison que read_file — accès à un contenu de fichier arbitraire.
        """
        try:
            kwargs = SearchInFileEntry(path=path, pattern=pattern)
            result = await asafe_run(
                cmd=f"grep -n {shlex.quote(kwargs.pattern)} {shlex.quote(kwargs.path)}",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(CheckOpenPortsEntry)
    @timer
    async def check_open_ports_server_agent_tool(self):
        """Ports en écoute et connexions actives (ss -tulnp) — utile pour repérer une exposition réseau inattendue."""
        try:
            result = await asafe_run(
                cmd="ss -tulnp",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(ListLoggedInUsersEntry)
    @timer
    async def list_logged_in_users_server_agent_tool(self):
        """Utilisateurs actuellement connectés à la machine (who)."""
        try:
            result = await asafe_run(
                cmd="who",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(LastLoginsEntry)
    @timer
    async def last_logins_server_agent_tool(self, limit: int = 20):
        """Historique récent des connexions (last -n) — utile pour repérer un accès SSH suspect."""
        try:
            kwargs = LastLoginsEntry(limit=limit)
            result = await asafe_run(
                cmd=f"last -n {kwargs.limit}",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(NetworkInterfacesEntry)
    @timer
    async def network_interfaces_server_agent_tool(self):
        """Interfaces réseau et adresses IP configurées (ip addr)."""
        try:
            result = await asafe_run(
                cmd="ip addr",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}

    @tool_policy(risk_level=Severity.LOW, need_confirmation=False)
    @entry_model(ListBlockDevicesEntry)
    @timer
    async def list_block_devices_server_agent_tool(self):
        """Disques et partitions détectés sur la machine (lsblk)."""
        try:
            result = await asafe_run(
                cmd="lsblk",
                timeout=30,
                allowed_commands=SERVER_ALLOWED_COMMANDS
            )
            return {"success": result.get("success"), "result": result, "error": None}
        except CommandNotAllowedError as e:
            return {"success": False, "result": None, "error": str(e)}
        
    def get_tools(self):
        return dict(self.tools)
    
    def get_tool(self, name: str):
        tool = self.tools.get(name, None)
        if tool is None:
            return None
        return tool


server_agent_tools = ServerAssetAgentTools()