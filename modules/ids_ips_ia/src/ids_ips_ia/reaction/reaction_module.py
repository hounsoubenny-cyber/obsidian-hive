#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 22:12:11 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import json
import socket
import atexit
import threading
import ipaddress
import subprocess
from geoip2.database import Reader
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.ids_ips_utils.suricata_integration import get_all_locals_ip
from ids_ips_ia.reaction.config import (
    NFT_TABLE_NAME, DEFAULT_RULE_TIMEOUT, 
    DEFAULT_RULE_UNIT,
    NFT_RATE_DATA_LIMITE, NFT_RATE_LIMITE
)
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.utils import _get_ip_type
from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX

logger = get_logger()

BASEDIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(BASEDIR, "data", INSTANCE_SUFFIX)
LOCATOR_DIR = os.path.join(os.path.join(BASEDIR, "data"), "locator")
NFT_DIR = os.path.join(DATADIR, "nft")
HISTORY_DIR = os.path.join(DATADIR, "history")
WHITELIST_DIR = os.path.join(DATADIR, "whitelist")
NFT_CMD_TIMEOUT = 5

os.makedirs(DATADIR, exist_ok=True)
os.makedirs(LOCATOR_DIR, exist_ok=True)
os.makedirs(NFT_DIR, exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)
os.makedirs(WHITELIST_DIR, exist_ok=True)


def clear_sets(set_name: list | str = None):
    trys = []
    try:
        if isinstance(set_name, str):
            set_name = [set_name]
        if set_name is None:
            logger.print("Aucun set !!")
            return
        
        logger.print('Sets entrés par l\'user : ', set_name)
        r = subprocess.run(['sudo', 'nft', 'list', 'sets'], capture_output=True, text=True, check=False)
        logger.print("[AVANT] Set et tables existants : \n", r.stdout[:100], "\n...")
        for s in set_name:
            try:
                cmd = f'sudo nft flush set inet {NFT_TABLE_NAME} {s}'
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False, timeout=NFT_CMD_TIMEOUT)
                logger.print(f'Set {s}: ', 'succès' if r.returncode == 0 else 'échec')
                if r.stderr:
                    logger.print("Stderr : ", r.stderr, '\nStdout : ', r.stdout)
                trys.append(r)
            except subprocess.TimeoutExpired:
                logger.print(f"⏱️ Timeout sur le flush de {s}, on passe au suivant")
                continue
            except Exception:
                pass
            
        r = subprocess.run(['sudo', 'nft', 'list', 'sets'], capture_output=True, text=True, check=False)
        logger.print("[APRÈS] Set et tables existants : \n", r.stdout[:100], "\n...")
    except Exception as e:
        logger.print(f"❌ Erreur vidage des sets : {e}")
    
    return any(f.returncode == 0 for f in trys)


class GeoLocator:
    def __init__(self, filename: str = "GeoLite2-Country.mmdb", suspicious_country: list = None):
        suspicious_country = suspicious_country or []
        self.path = os.path.join(LOCATOR_DIR, filename)
        self.reader = Reader(self.path)
        self.suspicious_country = suspicious_country or ['CN', 'RU', 'KP', 'IR']

    def locate(self, ip):
        try:
            response = self.reader.country(ip)
            return response.country.iso_code or 'XX'
        except Exception:
            return "XX"

    def is_suspicious(self, ip):
        return self.locate(ip) in self.suspicious_country


class React:
    def __init__(
        self, 
        whitelist: list | str = "whitelist.json", 
        history_filename: str = "history.json",
        clear_sets_at_exit: bool = True,
        unlock_at_exit: bool = True,
        nft_filename: str = "nft.conf",
        *args,
        **kwargs,
    ):
        self.history_path = os.path.join(HISTORY_DIR, history_filename)
        self.whitelist = whitelist or []
        if isinstance(self.whitelist, str):
            self.whitelist = os.path.join(WHITELIST_DIR, self.whitelist)
            self.whitelist_filename = self.whitelist
            self.whitelist = self.load_whitelist(self.whitelist)
        else:
            self.whitelist_filename = os.path.join(WHITELIST_DIR, "whitelist.json")
        self.whitelist.extend(get_all_locals_ip())
        
        backup = self.whitelist
        self.whitelist = []
        for ip in backup:
            split = str(ip).split("/")
            
            if len(split) == 1:
                if _get_ip_type(ip) != "error":
                    self.whitelist.append(ip)
                    
            else:
                part2 = split[1]
                if len(str(part2)) <= 2:
                    if _get_ip_type(ip) != "error":
                        self.whitelist.append(ip)
                    
                else:
                    try:
                        ip_network = ipaddress.ip_network(ip, strict=False)
                        self.whitelist.append(str(ip_network))
                        
                    except Exception:
                        pass
        backup.clear()
        del backup
        self.whitelist = list(dict.fromkeys(self.whitelist))
        
        self.nft_path = os.path.join(NFT_DIR, nft_filename)
        self.nft_state_path = os.path.join(NFT_DIR, ".nft_state")
        self.unlock_at_exit = unlock_at_exit
        self.clear_sets_at_exit = clear_sets_at_exit
        self.blocked = {}
        self.set_names = [
            # INPUT IPv4
            "blacklist_input_ip4", 
            "blacklist_rate_limite_input_ip4", 
            "blacklist_rate_limite_data_input_ip4",
            
            # INPUT IPv6
            "blacklist_input_ip6", 
            "blacklist_rate_limite_input_ip6", 
            "blacklist_rate_limite_data_input_ip6",
            
            # OUTPUT IPv4
            "blacklist_output_ip4", 
            "blacklist_rate_limite_output_ip4", 
            "blacklist_rate_limite_data_output_ip4",
            
            # OUTPUT IPv6
            "blacklist_output_ip6", 
            "blacklist_rate_limite_output_ip6", 
            "blacklist_rate_limite_data_output_ip6",
            
            # # WHITELIST
            # "whitelist_ip4",
            # "whitelist_ip6",
            
            # METERS
            "rate_data_in_ip4_meter",
            "rate_in_ip4_meter",
            "rate_data_in_ip6_meter",
            "rate_in_ip6_meter",
            "rate_data_out_ip4_meter",
            "rate_out_ip4_meter",
            "rate_data_out_ip6_meter",
            "rate_out_ip6_meter",
        ]
        
        self.setup_nftables()
        self.at_exit_handle()
        self.load_history(self.history_path)
        self.decrease_access_rights(NFT_DIR)

    # =========================================================================
    # MÉTHODE CENTRALISÉE POUR SUBPROCESS
    # =========================================================================
    def _run_command(
        self, cmd, use_sudo: bool = None, check: bool = False, 
        shell: bool = False, capture: bool = True, 
        success_msg: str = None, error_msg: str = None
    ) -> subprocess.CompletedProcess:
        """
        Exécute une commande système avec gestion automatique de sudo.
        
        Args:
            cmd: Commande (str si shell=True, liste si shell=False)
            use_sudo: Si None, détermine automatiquement selon os.geteuid()
            check: Lève une exception si la commande échoue
            shell: Utilise le shell pour exécuter la commande
            capture: Capture stdout/stderr
            success_msg: Message à afficher en cas de succès
            error_msg: Message à afficher en cas d'erreur
            
        Returns:
            subprocess.CompletedProcess ou None si exception et check=False
        """
        # Déterminer si on doit utiliser sudo
        if use_sudo is None:
            use_sudo = os.geteuid() != 0
        
        if shell:
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)
            if use_sudo and not cmd.startswith("sudo "):
                cmd = "sudo " + cmd
        else:
            if isinstance(cmd, str):
                cmd = cmd.split()
            if use_sudo and cmd[0] != "sudo":
                cmd = ["sudo"] + cmd
        
        cmd_display = cmd if isinstance(cmd, str) else ' '.join(cmd[:5])
        if success_msg:
            logger.print(f"  {success_msg}")
        else:
            logger.print(f"  ▶ {' '.join(cmd[:5]) if isinstance(cmd, list) else cmd[:50]}...")
        
        try:
            if capture:
                r = subprocess.run(cmd, shell=shell, check=check, capture_output=True, text=True)
            else:
                r = subprocess.run(cmd, shell=shell, check=check)
            
            logger.print("Cmd : ", cmd_display)
            if capture:
                if r.returncode == 0:
                    if r.stdout:
                        logger.print(f"    ✓ Stdout: {r.stdout.strip()[:300]}")
                else:
                    if not "interval overlaps with an existing one" in r.stderr:
                        if error_msg:
                            logger.print(f"    ❌ {error_msg}")
                        if r.stderr:
                            logger.print(f"    ⚠️ Stderr: {r.stderr.strip()[:200]}")
            
            return r
            
        except subprocess.CalledProcessError as e:
            logger.print(f"    ❌ Échec (code {e.returncode})")
            if e.stderr:
                logger.print(f"    ⚠️ Stderr: {e.stderr.strip()[:200]}")
            if check:
                raise
            return None
        
        except Exception as e:
            logger.print(f"    ❌ Exception: {e}")
            if check:
                raise
            return None

    # =========================================================================
    # MÉTHODES UTILITAIRES
    # =========================================================================
    def decrease_access_rights(self, filename_or_dir: str):
        try:
            if os.path.exists(filename_or_dir):
                if os.path.isdir(filename_or_dir):
                    cmd = f"sudo chmod -R 700 {filename_or_dir}"
                    for root, dirs, files in os.walk(filename_or_dir):
                        for f in files:
                            os.chmod(os.path.join(root, f), 0o600)
                else:
                    cmd = f"sudo chmod 600 {filename_or_dir}"
                    
                self._run_command(cmd, shell=True, success_msg="Permissions réduites")
        except Exception as e:
            logger.print(f"Erreur dans le changement des permissions : {str(e)}")

    def save_history(self, filename, value):
        try:
            try:
                value = list(set(value))
            except Exception:
                pass
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(value, f, indent=4, ensure_ascii=False)
            os.chmod(filename, 0o644)
            logger.print(f'Fichier historique sauvegardé dans : {filename}')
            return True
        except Exception as e:
            logger.print(f"Erreur lors de la sauvegarde du fichier historique : {str(e)}")
            return False

    def load_whitelist(self, filename: str):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                whitelist = json.load(f)
            
            logger.print(f'Fichier whitelist chargé depuis : {filename}')
            return whitelist
        except Exception as e:
            logger.print(f"Erreur lors du chargement du fichier whitelist : {str(e)}")
            return []
    
    def save_whitelist(self, filename, value):
        try:
            try:
                value = list(dict.fromkeys(value))
            except Exception:
                pass
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(value, f, indent=4, ensure_ascii=False)
            os.chmod(filename, 0o644)
            logger.print(f'Fichier whitelist sauvegardé dans : {filename}')
            return True
        except Exception as e:
            logger.print(f"Erreur lors de la sauvegarde du fichier whitelist : {str(e)}")
            return False

    def load_history(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.print(f'Fichier chargé depuis : {filename} avec {len(data)} entrées !')
            self.blocked = data if isinstance(data, dict) else {}
            return True
        except Exception as e:
            logger.print(f"Erreur lors du chargement du fichier historique : {str(e)}")
            return False

    @staticmethod
    def get_ip_type(ip: str) -> str:
        try:
            ip = ip.split('/')[0].strip()
            for k, v in [(socket.AF_INET, "ip4"), (socket.AF_INET6, "ip6")]:
                try:
                    socket.inet_pton(k, ip)
                    return v
                except Exception:
                    pass
        except Exception:
            return "error"
        return "error"

    # =========================================================================
    # CONFIGURATION NFTABLES
    # =========================================================================
    def _setup_nftables(self):
        logger.print("🔧 Configuration NFTables...")
        white_ip4 = [ip for ip in self.whitelist if self.get_ip_type(ip) == "ip4"]
        white_ip6 = [ip for ip in self.whitelist if self.get_ip_type(ip) == "ip6"]
        
        cmds = [
            # Table et chaînes
            ["nft", "add", "table", "inet", NFT_TABLE_NAME],
            ["nft", "add", "chain", "inet", NFT_TABLE_NAME, "input", 
             "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"],
            ["nft", "add", "chain", "inet", NFT_TABLE_NAME, "output", 
             "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"],
            
            # Sets whitelist
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "whitelist_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "whitelist_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval", ";", "}"],
            
            # Sets blacklist INPUT IPv4
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_input_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_input_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_data_input_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            
            # Sets blacklist INPUT IPv6
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_input_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_input_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_data_input_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            
            # Sets blacklist OUTPUT IPv4
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_output_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_output_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_data_output_ip4",
             "{", "type", "ipv4_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            
            # Sets blacklist OUTPUT IPv6
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_output_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_output_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            ["nft", "add", "set", "inet", NFT_TABLE_NAME, "blacklist_rate_limite_data_output_ip6",
             "{", "type", "ipv6_addr", ";", "flags", "interval,timeout", ";", 
             "timeout", f"{DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT}", ";", "}"],
            
            # Règles whitelist
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip", "saddr", "@whitelist_ip4", "accept"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip6", "saddr", "@whitelist_ip6", "accept"],
            
            # Règles INPUT IPv4
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip", "saddr", "@blacklist_input_ip4",
             "log", "prefix", "SHIELD_IPS_BLACKLIST_IP4 ", "drop"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip", "saddr", "@blacklist_rate_limite_data_input_ip4",
             "meter", "rate_data_in_ip4_meter", "{", "ip", "saddr", "limit", "rate", NFT_RATE_DATA_LIMITE, "}", "accept"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip", "saddr", "@blacklist_rate_limite_input_ip4",
             "meter", "rate_in_ip4_meter", "{", "ip", "saddr", "limit", "rate", NFT_RATE_LIMITE, "}", "accept"],
            
            # Règles INPUT IPv6
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip6", "saddr", "@blacklist_input_ip6",
             "log", "prefix", "SHIELD_IPS_BLACKLIST_IP6 ", "drop"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip6", "saddr", "@blacklist_rate_limite_data_input_ip6",
             "meter", "rate_data_in_ip6_meter", "{", "ip6", "saddr", "limit", "rate", NFT_RATE_DATA_LIMITE, "}", "accept"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "input", "ip6", "saddr", "@blacklist_rate_limite_input_ip6",
             "meter", "rate_in_ip6_meter", "{", "ip6", "saddr", "limit", "rate", NFT_RATE_LIMITE, "}", "accept"],
            
            # Règles OUTPUT IPv4
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip", "daddr", "@blacklist_output_ip4",
             "log", "prefix", "SHIELD_IPS_BLACKLIST_IP4 ", "drop"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip", "daddr", "@blacklist_rate_limite_data_output_ip4",
             "meter", "rate_data_out_ip4_meter", "{", "ip", "daddr", "limit", "rate", NFT_RATE_DATA_LIMITE, "}", "accept"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip", "daddr", "@blacklist_rate_limite_output_ip4",
             "meter", "rate_out_ip4_meter", "{", "ip", "daddr", "limit", "rate", NFT_RATE_LIMITE, "}", "accept"],
            
            # Règles OUTPUT IPv6
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip6", "daddr", "@blacklist_output_ip6",
             "log", "prefix", "SHIELD_IPS_BLACKLIST_IP6 ", "drop"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip6", "daddr", "@blacklist_rate_limite_data_output_ip6",
             "meter", "rate_data_out_ip6_meter", "{", "ip6", "daddr", "limit", "rate", NFT_RATE_DATA_LIMITE, "}", "accept"],
            ["nft", "add", "rule", "inet", NFT_TABLE_NAME, "output", "ip6", "daddr", "@blacklist_rate_limite_output_ip6",
             "meter", "rate_out_ip6_meter", "{", "ip6", "daddr", "limit", "rate", NFT_RATE_LIMITE, "}", "accept"],
        ]
        
        if white_ip4:
            for ip in white_ip4:
                cmds.append(["nft", "add", "element", "inet", NFT_TABLE_NAME, "whitelist_ip4", "{", ip ,"}"]) #", ".join(white_ip4)
        if white_ip6:
            for ip in white_ip6:
                cmds.append(["nft", "add", "element", "inet", NFT_TABLE_NAME, "whitelist_ip6", "{", ip, "}"]) #", ".join(white_ip6)
        
        # Exécution
        for cmd in cmds:
            self._run_command(cmd, check=False)

    def setup_nftables(self):
        returncode = 1
        if os.path.exists(self.nft_path):
            r = self._run_command(
                ["nft", "-c", "-f", self.nft_path],
                check=False, success_msg="Vérification fichier nft"
            )
            if r:
                returncode = r.returncode
        
        if returncode != 0:
            self._setup_nftables()
        else:
            r = self._run_command(
                ["nft", "list", "table", "inet", NFT_TABLE_NAME],
                check=False, success_msg="Vérification table existante"
            )
            table_existe = r and r.returncode == 0
            
            if table_existe:
                self._run_command(
                    ["nft", "delete", "table", "inet", NFT_TABLE_NAME],
                    check=False, success_msg="Suppression ancienne table"
                )
            
            try:
                with open(self.nft_state_path, "r") as f:
                    is_saved = json.load(f).get("is_last_saved", False)
            except Exception:
                is_saved = False
            
            if not is_saved:
                self._setup_nftables()
                return
            
            r = self._run_command(
                ["nft", "-f", self.nft_path],
                check=False, success_msg="Chargement depuis fichier"
            )
            if not r or r.returncode != 0:
                self._setup_nftables()

    # =========================================================================
    # ACTIONS DE BLOCAGE/DÉBLOCAGE
    # =========================================================================
    def block(self, ip, rule: str = "drop", input: bool = False, timeout: int|None = None, unit: str = "m", *args, **kwargs):
        ip_type = self.get_ip_type(ip)
        if ip_type == "error":
            return False
        
        type_dir = "input" if input else "output"  # Type de la diretion, si input est True, donc traffic entrant, set input, sinon traffic sortant, set output
        set_name = f'blacklist_{type_dir}_{ip_type}'
        if rule == "rate_limit":
            set_name = f'blacklist_rate_limite_{type_dir}_{ip_type}'
        elif rule == "rate_limit_data":
            set_name = f'blacklist_rate_limite_data_{type_dir}_{ip_type}'
        
        if timeout:
            if abs(timeout) != float("inf"):
                cmd = ["nft", "add", "element", "inet", NFT_TABLE_NAME, set_name, 
                       "{", ip, "timeout", f"{timeout}{unit}", "}"]
            else:
                cmd = ["nft", "add", "element", "inet", NFT_TABLE_NAME, set_name, 
                       "{", ip, "timeout", "never", "}"]
        else:
            cmd = ["nft", "add", "element", "inet", NFT_TABLE_NAME, set_name, "{", ip, "}"]
        
        r = self._run_command(cmd, check=False, success_msg=f"Blocage de {ip}")
        
        if r and r.returncode == 0:
            self.blocked[ip] = {
                'ip': ip, 'rule': rule, 'set_name': set_name,
                'duration': timeout, "input": input,
            }
            return True
        return False

    def unlock(self, ip, rule: str = "drop", input: bool = False, *args, **kwargs):
        ip_type = self.get_ip_type(ip)
        if ip_type == "error":
            return False
        
        type_dir = "input" if input else "output"
        set_name = f'blacklist_{type_dir}_{ip_type}'
        if rule == "rate_limit":
            set_name = f'blacklist_rate_limite_{type_dir}_{ip_type}'
        elif rule == "rate_limit_data":
            set_name = f'blacklist_rate_limite_data_{type_dir}_{ip_type}'
        
        cmd = ["nft", "delete", "element", "inet", NFT_TABLE_NAME, set_name, "{", ip, "}"]
        r = self._run_command(cmd, check=False, success_msg=f"Déblocage de {ip}")
        return r and r.returncode == 0

    def clear_sets(self, set_name=None):
        if set_name is None:
            set_name = self.set_names
        if isinstance(set_name, str):
            set_name = [set_name]
        return clear_sets(set_name)

    def save_nft_conf(self):
        r = self._run_command(
            ["nft", "list", "table", "inet", NFT_TABLE_NAME],
            check=False, success_msg="Sauvegarde configuration"
        )
        if r and r.returncode == 0:
            with open(self.nft_path, "w") as f:
                f.write(r.stdout)
            with open(self.nft_state_path, "w") as f:
                json.dump({"is_last_saved": True}, f)
            return True
        return False
    
    # =========================================================================
    # AJOUTER / RETIRER DES ÉLÉMENTS DE LA WHITELIST
    # =========================================================================
    def add_to_whitelist(self, ip: str) -> bool:
        """
        Ajoute une IP ou un sous-réseau à la whitelist.
        Supporte IPv4, IPv6 et notation CIDR (ex: 192.168.1.0/24).
        """
        # Déterminer le type (ip4 ou ip6)
        ip_type = self.get_ip_type(ip)
        if ip_type == "error":
            logger.print(f"❌ Format d'IP invalide : {ip}")
            return False
    
        set_name = f"whitelist_{ip_type}"
        
        # Commande nftables
        cmd = ["nft", "add", "element", "inet", NFT_TABLE_NAME, set_name, "{", ip, "}"]
        
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
    
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.print(f"✅ {ip} ajouté à la whitelist ({set_name})")
            
            # Mettre à jour la liste interne
            if ip not in self.whitelist:
                self.whitelist.append(ip)
                
            # Sauvegarder la whitelist si un fichier est défini
            if hasattr(self, 'whitelist_filename') and self.whitelist_filename:
                with open(self.whitelist_filename, 'w') as f:
                    json.dump(self.whitelist, f, indent=4)
                    
            return True
        except subprocess.CalledProcessError as e:
            logger.print(f"❌ Échec ajout whitelist : {e.stderr}")
            return False
    
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """
        Retire une IP ou un sous-réseau de la whitelist.
        """
        ip_type = self.get_ip_type(ip)
        if ip_type == "error":
            logger.print(f"❌ Format d'IP invalide : {ip}")
            return False
    
        set_name = f"whitelist_{ip_type}"
        
        cmd = ["nft", "delete", "element", "inet", NFT_TABLE_NAME, set_name, "{", ip, "}"]
        
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
    
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.print(f"✅ {ip} retiré de la whitelist ({set_name})")
            
            # Mettre à jour la liste interne
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                
            # Sauvegarder
            if hasattr(self, 'whitelist_filename') and self.whitelist_filename:
                with open(self.whitelist_filename, 'w') as f:
                    json.dump(self.whitelist, f, indent=4)
                    
            return True
        except subprocess.CalledProcessError as e:
            logger.print(f"❌ Échec suppression whitelist : {e.stderr}")
            return False
    
    # =========================================================================
    # GESTION DE LA SORTIE
    # =========================================================================
    def _sig_manager(self, *args, **kwargs):
        self.save_history(self.history_path, self.blocked)
        self.save_whitelist(self.whitelist_filename, self.whitelist)
        logger.print('Fin sauvegarde !')
        if self.clear_sets_at_exit:
            self.clear_sets(self.set_names)
        elif self.unlock_at_exit:
            for data in self.blocked.values():
                logger.print("Déblocage de l'ip :", data["ip"])
                self.unlock(**data)
        else:
            self.save_nft_conf()
            
    def at_exit_handle(self):
        def sig_manager(*args, **kwargs):
            self._sig_manager()
            
        atexit.register(sig_manager)
        if threading.current_thread() is threading.main_thread():
            signal_manager(sig_manager)


if __name__ == "__main__":
    logger.print("=" * 60)
    logger.print("🧪 TEST DU MODULE REACT (IDS/IPS NFTables)")
    logger.print("=" * 60)
    
    # 1. Test GeoLocator
    logger.print("\n📍 TEST GeoLocator...")
    geo = GeoLocator()
    test_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.1"]
    for ip in test_ips:
        country = geo.locate(ip)
        is_susp = geo.is_suspicious(ip)
        logger.print(f"  IP: {ip:15} → Pays: {country:2} | Suspect: {is_susp}")
    
    # 2. Test get_ip_type
    logger.print("\n🔍 TEST get_ip_type...")
    test_ips = ["192.168.1.1", "2001:db8::1", "invalid_ip"]
    for ip in test_ips:
        ip_type = React.get_ip_type(ip)
        logger.print(f"  IP: {ip:20} → Type: {ip_type}")
    
    # 3. Whitelist de test
    whitelist = ["127.0.0.1", "::1", "192.168.1.0/24"]
    
    # 4. Initialisation de React
    logger.print("\n🚀 INITIALISATION DE REACT...")
    react = React(
        whitelist=whitelist,
        history_filename="test_history.json",
        nft_filename="test_nft.conf",
        clear_sets_at_exit=False,
        unlock_at_exit=False,
    )
    
    # 5. Test de blocage
    logger.print("\n🚫 TEST BLOCAGE...")
    test_block_ips = [
        ("192.0.2.1", "drop", True, 5),
        ("198.51.100.1", "rate_limit", True, 10),
        ("203.0.113.1", "rate_limit_data", False, 2),
        ("2001:db8::1", "drop", True, 5),
    ]
    
    for ip, rule, input_dir, timeout in test_block_ips:
        logger.print(f"\n  Blocage de {ip} ({rule}, input={input_dir}, timeout={timeout}m)...")
        success = react.block(ip, rule=rule, input=input_dir, timeout=timeout, unit="m")
        logger.print(f"  → {'✅ Succès' if success else '❌ Échec'}")
    
    # 6. Afficher l'état interne
    logger.print("\n📊 ÉTAT INTERNE (self.blocked)...")
    for ip, data in react.blocked.items():
        logger.print(f"  {ip}: {data}")
    
    # 7. Test de déblocage
    logger.print("\n🔓 TEST DÉBLOCAGE...")
    if test_block_ips:
        ip, rule, input_dir, _ = test_block_ips[0]
        logger.print(f"\n  Déblocage de {ip}...")
        success = react.unlock(ip, rule=rule, input=input_dir)
        logger.print(f"  → {'✅ Succès' if success else '❌ Échec'}")
    
    # 8. Lister les règles nftables actuelles
    logger.print("\n📋 RÈGLES NFTABLES ACTUELLES...")
    try:
        cmd = ["sudo", "nft", "list", "table", "inet", NFT_TABLE_NAME] if os.geteuid() != 0 else ["nft", "list", "table", "inet", NFT_TABLE_NAME]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            lines = r.stdout.split("\n")[:30]
            for line in lines:
                logger.print(f"  {line}")
            if len(r.stdout.split("\n")) > 30:
                logger.print("  ... (tronqué)")
        else:
            logger.print("  ⚠️ Table non trouvée")
    except Exception as e:
        logger.print(f"  ⚠️ {e}")
    
    # 9. Test save_nft_conf
    logger.print("\n💾 TEST SAVE_NFT_CONF...")
    success = react.save_nft_conf()
    logger.print(f"  → {'✅ Sauvegarde réussie' if success else '❌ Échec'}")
    logger.print(f"  Fichier: {react.nft_path}")
    logger.print(f"  État: {react.nft_state_path}")
    
    # 10. Vérifier le contenu du fichier de conf
    if os.path.exists(react.nft_path):
        logger.print("\n📄 CONTENU DU FICHIER DE CONF (extrait)...")
        with open(react.nft_path, "r") as f:
            lines = f.readlines()[:20]
            for line in lines:
                logger.print(f"  {line.rstrip()}")
    
    logger.print(f"\n  Blocked après chargement: {len(react.blocked)} entrées")
    
    logger.print("\n" + "=" * 60)
    logger.print("✅ TESTS TERMINÉS")
    logger.print("=" * 60)
    logger.print(f"\n📁 Fichiers créés :")
    logger.print(f"  - Conf NFT    : {react.nft_path}")
    logger.print(f"  - État NFT    : {react.nft_state_path}")
    logger.print(f"  - Historique  : {react.history_path}")
    logger.print("\n⚠️ Pensez à nettoyer avec : sudo nft delete table inet", NFT_TABLE_NAME)