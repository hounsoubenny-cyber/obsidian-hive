#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 08:12:47 2026

@author: hounsousamuel

"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import json
import time
import distro
import socket
import shutil
import yaml
import asyncio
import signal
import netifaces
import ipaddress
import subprocess
import platform
import traceback
import getpass
import threading
import psutil
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.ids_ips_utils.logger import get_logger
from modules_utils.loop_utils import _run_async
from modules_utils.stop_process import kill_process_group_async as kill_process

logger = get_logger()

def get_all_locals_ip():
    ips = set()
    ifaces = netifaces.interfaces()
    try:
        for iface in ifaces:
            info_iface = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in info_iface:
                info = info_iface[netifaces.AF_INET]
                for addr in info:
                    if "addr" in addr:
                        ip = addr['addr']
                        netmask = addr.get("netmask")
                        ips.add(f"{ip}/{netmask}" if netmask else ip)
                            
            if netifaces.AF_INET6 in info_iface:
                info = info_iface[netifaces.AF_INET6]
                for addr in info:
                    if "addr" in addr:
                        ip = addr['addr'].split('%')[0]
                        netmask = addr.get("netmask")
                        if netmask:
                            netmask = netmask.split("/")[-1]
                        if ip and ip != "::":
                            ips.add(f"{ip}/{netmask}" if netmask else ip)
                            
        gateways = netifaces.gateways()
        if netifaces.AF_INET in gateways:
            gate = gateways[netifaces.AF_INET]
            for i in gate:
                ip = i[0]
                if ip:
                    ips.add(ip)
                    
        if netifaces.AF_INET6 in gateways:
            gate = gateways[netifaces.AF_INET6]
            for i in gate:
                ip = i[0]
                if ip and ip != '::':
                    ips.add(ip)
                    
        # default_gateway = gateways['default'][netifaces.AF_INET][0]
        
    except Exception as e:
        logger.print('Erreur netifaces : ', str(e))
        
    try:
        host = socket.gethostname()
        info = socket.gethostbyname_ex(host)[2]
        ips.add(socket.gethostbyname('localhost'))
        for ip in info:
            ips.add(ip)
    except Exception as e:
        logger.print('Erreur socket : ', str(e))
    li = ["::1", "0.0.0.0", "127.0.0.1", "255.255.255.255", "172.17.0.2", "172.17.0.1", "ff02::1", "ff02::2"]
    for i in li:
        ips.add(i)
    return list(ips)


class LocalIPS:
    def __init__(self):
        self.REFRESH_TIME = 600
        self.last_refresh = time.time()
        self.local = self._get_all_locals_ip()
        self.local1 = self.get_all_locals_ip()
        # logger.print(self.local)
        
    def _get_all_locals_ip(self):
        return get_all_locals_ip()
    
    def get_all_locals_ip(self):
        if not self.local:
            self.local = self._get_all_locals_ip()
        ips = []
        for ip in self.local:
            if "/" in ip:
                try:
                    ips.append(
                            ipaddress.ip_network(ip, strict=False)
                        )
                except Exception:
                    ips.append(ip)
        #logger.print("Local ips amélioré : \n", ips)
        return ips
    
    def get_ips(self):
        t = time.time()
        if t - self.last_refresh <= self.REFRESH_TIME:
            return self.local
        self.last_refresh = t
        self.local = get_all_locals_ip()
        self.local1 = self.get_all_locals_ip()
        return self.local
    
    def is_local_ip(self, ip):
        if ip in self.local:
            return True
        
        try:
            ip = ipaddress.ip_address(ip)
            for _ip in self.local1:
                if isinstance(_ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if ip in _ip:
                        return True
        except Exception:
            pass
        
        return False
        
    def __contains__(self, ip):
        return self.is_local_ip(ip)

IPS = LocalIPS()

class State:
    def __init__(self):
        self.current_suricata_mode = None
        self.suricata_processes: list[asyncio.subprocess.Process] = []
        self.threat_detected = asyncio.Event()
        self.last_alert = None
        self.threads = []
        self.sig_manager()
    
    def _sig_manager(self, *args, **kwargs):
        try:
            self.stop()
        except Exception:
            pass
        
        Utils().cleanup_nfqueue()
        
    def sig_manager(self, *args, **kwargs):
        def _sig_manager(*args, **kwargs):
            self._sig_manager()
            
        if threading.current_thread() is threading.main_thread():
            signal_manager(_sig_manager)
        
    def change_state(self, new_mode):
        self.current_suricata_mode = new_mode

    def signal_threat(self, alert_data):
        self.last_alert = alert_data
        self.threat_detected.set()

    def add_threads(self, th):
        if isinstance(th[0], threading.Thread):
            self.threads.append(th)
    
    async def _kill_all_suricata(self):
        tasks = [
            kill_process(proc, name=f"Suricata[{i}] (pid {proc.pid})")
            for i, proc in enumerate(self.suricata_processes)
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)



    def stop(self):
        if self.suricata_processes:
            _run_async(self._kill_all_suricata)
            
            # for proc in self.suricata_processes:
            #     if proc.returncode is None:
            #         try:
            #             logger.print(f"   → SIGKILL sur le groupe de process Suricata (pgid {proc.pid})")
            #             os.killpg(proc.pid, signal.SIGKILL)
            #         except Exception as e:
            #             logger.print(f"   ⚠️ os.killpg indisponible ou échoué ({e}), fallback proc.kill()")
            #             try:
            #                 proc.kill()
            #             except:
            #                 pass

            if self.threads:
                for th in self.threads:
                    logger.print(f' Stop de thread numéro : {self.threads.index(th)} (thread {th[1]}) ')
                    th[0].join(1)

            Utils.stop_suricata()
        
        self.threads = []
        self.suricata_processes = []

state = State()

class Utils:
    def __init__(self):
        self.suricata_table = "shieldai_ids_ipd_suricata_ips"
        self.is_update = False
        
    def detect_os(self):
        sys_ = platform.system().lower()
        if sys_ == 'windows':
            return 'windows'
        elif sys_ == 'darwin':
            return 'macos'
        elif sys_ == 'linux':
            os_ = distro.id().lower()
            return f'linux/{os_}'
        return 'unknown'
    
    def detect_os_and_path(self):
        """
        Retourne les chemins standards de Suricata selon l'OS.
        Sources : documentation officielle, paquets Debian/Ubuntu, Homebrew, Windows.
        """
        paths = {}
        os_id = self.detect_os()
        paths['os_id'] = os_id
        
        if 'darwin' in os_id:
            # macOS avec Homebrew
            if os.path.exists('/opt/homebrew'):  # Apple Silicon
                prefix = '/opt/homebrew'
            else:  # Intel
                prefix = '/usr/local'
            
            paths['config'] = f"{prefix}/etc/suricata/suricata.yaml"
            paths['rules'] = f"{prefix}/var/lib/suricata/rules"
            paths['log'] = f"{prefix}/var/log/suricata"
        
        elif 'linux' in os_id:
            # Linux (Debian, Ubuntu, Fedora, RHEL, Arch...)
            # Les chemins sont quasiment identiques sur toutes les distributions modernes
            paths['config'] = "/etc/suricata/suricata.yaml"
            paths['rules'] = "/var/lib/suricata/rules"
            paths['log'] = "/var/log/suricata"
        
        elif 'windows' in os_id:
            # Windows (installation par défaut)
            prog_files = os.environ.get('ProgramFiles', 'C:\\Program Files')
            paths['config'] = f"{prog_files}\\Suricata\\suricata.yaml"
            paths['rules'] = f"{prog_files}\\Suricata\\rules"
            paths['log'] = f"{prog_files}\\Suricata\\log"
        
        else:
            paths['config'] = None
            paths['rules'] = None
            paths['log'] = None
            
        return paths
    
    def install_suricata(self):
        os_id = self.detect_os().split('/')[-1]
        try:
            if os_id in ['ubuntu', 'debian']:
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(
                    ["sudo", "apt", "install", "-y", "suricata", "libnetfilter-queue-dev"],
                    check=True
                )
            elif os_id == 'fedora':
                subprocess.run(["sudo", "dnf", "install", "-y", "suricata"], check=True)
            elif os_id in ['centos', 'rhel']:
                subprocess.run(["sudo", "yum", "install", "-y", "epel-release"], check=True)
                subprocess.run(["sudo", "yum", "install", "-y", "suricata"], check=True)
            elif os_id == 'arch':
                subprocess.run(["sudo", "pacman", "-S", "--noconfirm", "suricata"], check=True)
            elif os_id == 'macos':
                subprocess.run(["brew", "install", "suricata"], check=True)
            elif os_id == 'windows':
                logger.print("Suricata sur Windows doit être installé manuellement depuis https://suricata.io/")
            else:
                raise ValueError("OS non reconnu pour installation automatique.")
            logger.print("✅ Suricata installé avec succès")
        except Exception as e:
            raise RuntimeError(f"Erreur lors de l'installation de Suricata : {e}")
    
    def update_suricata_rules(self):
        if self.is_update:
            return True
        r = subprocess.run(
            ["sudo", "suricata-update"],
            check=False, capture_output=True, text=True
        )
        logger.print("📦 suricata-update terminé, code retour :", r.returncode)
        if r.stdout:
            logger.print("   📄 Stdout:", r.stdout.strip()[:300] if r.stdout else "Aucun")
        if r.stderr:
            logger.print("   ⚠️ Stderr:", r.stderr.strip()[:300] if r.stderr else "Aucun")
        self.is_update = r.returncode == 0
        return r.returncode == 0
    
    def get_suricata_paths(self):
        """
        Retourne les chemins Suricata + eve.json et fast.log.
        Crée les dossiers si nécessaires.
        Multi-OS compatible (Linux, macOS, Windows).
        """
        paths = self.detect_os_and_path()

        if paths['log']:
            paths['eve_file'] = os.path.join(paths['log'], 'eve.json')
            paths['fast_file'] = os.path.join(paths['log'], 'fast.log')
        else:
            paths['eve_file'] = None
            paths['fast_file'] = None

        try:
            # Création des répertoires
            for key in ['log', 'rules']:
                directory = paths.get(key)
                if directory and not os.path.exists(directory):
                    os.makedirs(directory, exist_ok=True)
                    logger.print(f"✅ Créé: {directory}")

            if paths['config']:
                config_dir = os.path.dirname(paths['config'])
                if not os.path.exists(config_dir):
                    os.makedirs(config_dir, exist_ok=True)
                    logger.print(f"✅ Créé: {config_dir}")

            # Création des fichiers de log s'ils n'existent pas
            for f in [paths.get('eve_file'), paths.get('fast_file')]:
                if f and not os.path.exists(f):
                    open(f, 'a').close()
                    logger.print(f"✅ Créé: {f}")

            # Permissions (hors Windows)
            if paths['os_id'] not in ['windows'] and paths['log']:
                try:
                    os.chmod(paths['log'], 0o775)
                    if paths['eve_file']:
                        os.chmod(paths['eve_file'], 0o664)
                    if paths['fast_file']:
                        os.chmod(paths['fast_file'], 0o664)
                    logger.print("✅ Permissions locales définies")
                except PermissionError:
                    try:
                        subprocess.run(['sudo', 'chmod', '-R', '775', paths['log']],
                                       check=False, capture_output=True)
                        logger.print("✅ Permissions définies (sudo)")
                    except Exception:
                        logger.print("⚠️ Permissions non modifiées")

            logger.print(f"\n📁 Chemins Suricata ({paths['os_id']}):")
            logger.print(f"   Config:    {paths['config']}")
            logger.print(f"   Rules:     {paths['rules']}")
            logger.print(f"   Logs:      {paths['log']}")
            logger.print(f"   EVE.json:  {paths['eve_file']}")
            logger.print(f"   Fast.log:  {paths['fast_file']}\n")

            return paths

        except Exception as e:
            logger.print(f"❌ Erreur get_suricata_paths: {e}")
            traceback.print_exc()
            return paths

    def clear_suricata_logs(self):
        """Vide les fichiers eve.json et fast.log après avoir affiché les dernières lignes."""
        paths = self.get_suricata_paths()
        eve_file = paths.get('eve_file')
        fast_file = paths.get('fast_file')
        
        if not eve_file:
            logger.print("❌ Impossible de localiser les logs Suricata.")
            return False
        
        # Afficher les dernières lignes de eve.json
        try:
            cmd = ['sudo', 'tail', '-n', '10', eve_file]
            result = subprocess.run(cmd, text=True, capture_output=True, check=False)
            logger.print("📄 Dernières entrées eve.json :")
            logger.print(result.stdout if result.stdout else "(vide)")
        except Exception as e:
            logger.print(f"⚠️ Impossible de lire eve.json : {e}")
        
        # Vider les fichiers
        try:
            subprocess.run(['sudo', 'truncate', '-s', '0', eve_file], check=True)
            logger.print(f"✅ {eve_file} vidé")
            if fast_file and os.path.exists(fast_file):
                subprocess.run(['sudo', 'truncate', '-s', '0', fast_file], check=True)
                logger.print(f"✅ {fast_file} vidé")
            return True
        except Exception as e:
            logger.print(f"❌ Erreur lors du nettoyage : {e}")
            return False
    
    def setup_capabilities(self):
        """Ajoute les capabilities réseau à Python et à Suricata pour éviter de lancer en root."""
        if self.detect_os() == 'windows':
            logger.print("Capacités réseau non applicables sur Windows")
            return
        try:
            python_bin = shutil.which(sys.executable.split("/")[-1]) or sys.executable
            result = subprocess.run(
                ["getcap", python_bin],
                capture_output=True, text=True
            )
            if "cap_net_raw,cap_net_admin" not in result.stdout:
                try:
                    subprocess.run(
                        ['sudo', "setcap", "cap_net_raw,cap_net_admin=eip", python_bin],
                        check=True
                    )
                    logger.print(f"✅ Capabilities réseau appliquées à {python_bin}")
                except subprocess.CalledProcessError as e:
                    logger.print(f"⚠️ Échec de setcap sur {python_bin} : {e}")
            else:
                logger.print(f"✅ Capabilities déjà présentes sur {python_bin}")

            suricata_path = shutil.which("suricata")
            if suricata_path and os.path.exists(suricata_path):
                result = subprocess.run(['getcap', suricata_path],
                                        capture_output=True, text=True, check=False)
                if 'cap_net_raw' not in result.stdout:
                    try:
                        subprocess.run(['sudo', shutil.which("setcap"), 'cap_net_raw,cap_net_admin=eip', suricata_path],
                                       check=True, capture_output=True)
                        logger.print(f"✅ Capabilities réseau appliquées à Suricata ({suricata_path})")
                    except subprocess.CalledProcessError as e:
                        logger.print(f"⚠️ Échec setcap Suricata : {e}")
                else:
                    logger.print(f"✅ Suricata a déjà les capabilities ({suricata_path})")
            else:
                logger.print("⚠️ Suricata non trouvé dans le PATH")
        except Exception as e:
            logger.print(f"❌ Erreur configuration capabilities : {e}")

    def setup_permissions(self):
        """Configure les permissions des répertoires Suricata pour l'utilisateur courant."""
        paths = self.detect_os_and_path()
        rules_dir = paths['rules']
        log_dir = paths['log']
        config_path = paths['config']

        if not rules_dir or not log_dir or not config_path:
            logger.print("❌ Chemins Suricata non définis")
            return False

        try:
            subprocess.run(["sudo", "mkdir", "-p", rules_dir], check=True)
            subprocess.run(["sudo", "mkdir", "-p", log_dir], check=True)
            if not os.path.exists(config_path):
                subprocess.run(["sudo", "touch", config_path], check=True)

            if self.detect_os() != 'windows':
                current_user = os.environ.get('SUDO_USER') or os.environ.get('USER') or getpass.getuser()
                
                subprocess.run(["sudo", "chown", "-R", f"{current_user}:{current_user}", rules_dir], check=True)
                subprocess.run(["sudo", "chown", "-R", f"{current_user}:{current_user}", log_dir], check=True)
                subprocess.run(["sudo", "chown", f"{current_user}:{current_user}", config_path], check=True)
                
                subprocess.run(["sudo", "chmod", "-R", "775", rules_dir], check=True)
                subprocess.run(["sudo", "chmod", "-R", "775", log_dir], check=True)
                subprocess.run(["sudo", "chmod", "-R", "775", config_path], check=True)
                
                logger.print(f"✅ Permissions configurées pour {current_user}")
                return True
        except subprocess.CalledProcessError as e:
            logger.print(f"❌ Erreur permissions : {e.cmd}")
            logger.print(f"   Stderr: {e.stderr}")
            return False
        except Exception as e:
            logger.print(f"❌ Erreur inattendue : {e}")
            return False
    
    def is_ipv6(self, ip_str):
        """
        Détecte si une string est une IPv6 valide
        ROBUSTE : Ne confond pas avec IPv4 + port
        """
        try:
            # Teste conversion IPv6
            socket.inet_pton(socket.AF_INET6, ip_str)
            return True
        except (OSError, ValueError):
            return False
        
    
    @staticmethod
    def _parse_eve_timestamp(ts_str: str | None) -> float | None:
        """Convertit le timestamp ISO de Suricata en epoch float (secondes)."""
        from datetime import datetime
        
        if not ts_str:
            return None
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            return dt.timestamp()   # .timestamp() gère le fuseau horaire automatiquement → UTC epoch correct
        except (ValueError, TypeError):
            return None
    
    def parse_eve_line(self, line:str):
        try:
            line:dict = json.loads(line)
            event = {
                "type" : line.get("event_type", "unknown"),
                "proto" : line.get("proto", "N/A"),
                "src_ip" : line.get("src_ip", None),
                "src_port" : line.get("src_port", None),
                "dest_ip" : line.get("dest_ip", None),
                "dest_port" : line.get("dest_port", None),
                "direction": "input",
                "severity": 1,
                "event_type": line.get("event_type"),
                "eve_timestamp": self._parse_eve_timestamp(line.get("timestamp")),
            }
            event.update(line.get("alert", {}))
            if event["src_ip"] and event["dest_ip"]:
                src = event["src_ip"]
                dst = event["dest_ip"]
                if src in IPS and dst in IPS:
                    pass
                elif src in IPS:
                    event["direction"] = "output"  # Sortant
            
            return event
        except Exception as e:
            logger.print("Erreur dans le parsing d'une ligne eve.json :", str(e))
            return {}
    
    @staticmethod
    def stop_suricata():
        """Arrête tous les processus Suricata."""
        subprocess.run(["pkill", "-9", "-f", "suricata"], check=False)
    
    def is_suricata_installed(self):
        """Vérifie si Suricata est installé."""
        return shutil.which("suricata") is not None
    
    def _configure_suricata_ids(self, config_path: str, interfaces: list, home_net: str = None):
        """
        Configure Suricata en mode IDS (détection uniquement).
        
        Args:
            config_path: Chemin vers suricata.yaml
            interfaces: Liste des interfaces à surveiller
            home_net: Plage réseau à protéger (ex: "192.168.1.0/24")
        """
        logger.print(f"📝 Configuration IDS pour {len(interfaces)} interface(s)...")
        
        # Charger la configuration existante ou créer une base
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                content = f.read()
                if content.startswith('%YAML'):
                    content = content.split('---\n', 1)[-1]
                config = yaml.safe_load(content) or {}
        else:
            config = {}
        
        self.cleanup_nfqueue()
        # HOME_NET par défaut : détection automatique
        if home_net is None:
            home_net = self._detect_home_net()
        
        # Configuration des variables réseau
        config['vars'] = config.get('vars', {})
        config['vars']['address-groups'] = config['vars'].get('address-groups', {})
        config['vars']['address-groups']['HOME_NET'] = home_net
        config['vars']['address-groups']['EXTERNAL_NET'] = "!$HOME_NET"
        config['vars']['address-groups']['HTTP_SERVERS'] = "$HOME_NET"
        config['vars']['address-groups']['SMTP_SERVERS'] = "$HOME_NET"
        config['vars']['address-groups']['SQL_SERVERS'] = "$HOME_NET"
        config['vars']['address-groups']['DNS_SERVERS'] = "$HOME_NET"
        config['vars']['address-groups']['TELNET_SERVERS'] = "$HOME_NET"
        config['vars']['address-groups']['SIP_SERVERS'] = "$HOME_NET"
        
        # Configuration AF-PACKET (mode IDS)
        config['af-packet'] = []
        cluster_id = 99
        for iface in interfaces:
            config['af-packet'].append({
                'interface': iface,
                'cluster-id': cluster_id,
                'cluster-type': 'cluster_flow',
                'defrag': True,
                'use-mmap': True,
            })
            cluster_id += 1
        
        # Désactiver NFQUEUE (mode IDS = pas de blocage)
        if 'nfqueue' in config:
            del config['nfqueue']
        
        # Configuration des logs
        config['outputs'] = config.get('outputs', [])
        
        # Supprimer les anciennes configs EVE pour les remplacer
        config['outputs'] = [o for o in config['outputs'] if not (isinstance(o, dict) and 'eve-log' in o)]
        
        config['outputs'].append({
            'eve-log': {
                'enabled': True,
                'filetype': 'regular',
                'filename': f"{self.get_suricata_paths()['log']}/eve.json",
                'types': [
                    {'alert': {'payload': True, 'payload-logger.printable': True, 'tagged-packets': True}},
                    {'http': {'extended': True}},
                    {'dns': {'version': 2}},
                    {'tls': {'extended': True}},
                    {'files': {'force-magic': False}},
                    'flow',
                    'stats'
                ]
            }
        })
        
        # Fast.log pour compatibilité
        config['outputs'].append({
            'fast': {
                'enabled': True,
                'filename': f"{self.get_suricata_paths()['log']}/fast.log",
                'append': True
            }
        })
        
        # Optimisations IDS
        config['max-pending-packets'] = 10000
        config['runmode'] = 'workers'  # Meilleure performance multi-cœur
        
        # Détection avancée
        config['detect'] = config.get('detect', {})
        config['detect']['profile'] = 'high'
        config['detect']['prefilter'] = {'default': 'auto'}
        
        # Écrire la configuration
        with open(config_path, 'w') as f:
            f.write("%YAML 1.1\n---\n")
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        logger.print(f"   ✅ Configuration IDS écrite dans {config_path}")
        logger.print(f"   🏠 HOME_NET = {home_net}")
        logger.print(f"   🌐 Interfaces = {', '.join(interfaces)}")
    
    def _configure_suricata_ips(self, config_path: str, interfaces: list, home_net: str = None, queue_num: int = 0):
        """
        Configure Suricata en mode IPS (blocage via NFQUEUE).
        
        Args:
            config_path: Chemin vers suricata.yaml
            interfaces: Liste des interfaces à surveiller
            home_net: Plage réseau à protéger (ex: "192.168.1.0/24")
            queue_num: Numéro de queue NFQUEUE (défaut: 0)
        """
        logger.print(f"📝 Configuration IPS pour {len(interfaces)} interface(s)...")
        
        # D'abord appliquer la configuration IDS de base
        self._configure_suricata_ids(config_path, interfaces, home_net)
        
        # Charger la configuration
        with open(config_path, 'r') as f:
            content = f.read()
            if content.startswith('%YAML'):
                content = content.split('---\n', 1)[-1]
                
            config = yaml.safe_load(content)
        
        self.setup_nfqueue_for_ips(queue_num)
        # Ajouter la configuration NFQUEUE pour le mode IPS
        config['nfqueue'] = {
            'mode': 'repeat',
            'repeat-mark': 1,
            'repeat-mask': 1,
            'bypass-mark': 1,
            'bypass-mask': 1,
            'route-queue': 2,
            'fail-open': True,
        }
        
        # Modifier les règles par défaut pour qu'elles bloquent
        # (Suricata utilise l'action des règles, pas besoin de dropsid.conf)
        config['engine-analysis'] = config.get('engine-analysis', {})
        config['engine-analysis']['rules-fast-pattern'] = True
        
        # Optimisations IPS (plus agressif)
        config['max-pending-packets'] = 50000
        config['runmode'] = 'workers'
        
        # S'assurer que le mode inline est activé
        config['af-packet'] = []
        cluster_id = 99
        for iface in interfaces:
            config['af-packet'].append({
                'interface': iface,
                'cluster-id': cluster_id,
                'cluster-type': 'cluster_flow',
                'defrag': True,
                'use-mmap': True,
                'ring-size': 300000,
                'mode': 'inline',  # Mode inline pour IPS
            })
            cluster_id += 1
        
        # Écrire la configuration
        with open(config_path, 'w') as f:
            f.write("%YAML 1.1\n---\n")
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        logger.print(f"   ✅ Configuration IPS écrite dans {config_path}")
        logger.print(f"   🛡️ NFQUEUE activé sur queue {queue_num}")
        logger.print("   ⚠️ Les règles avec action 'drop' bloqueront le trafic")
    
    def setup_nfqueue_for_ips(self, queue_num: int = 0):
        """
        Configure NFQUEUE avec nftables pour le mode IPS de Suricata.
        """
        logger.print(f"🛡️ Configuration NFQUEUE (queue {queue_num}) avec nftables...")
        
        table_name = self.suricata_table
        
        # Nettoyer l'ancienne table si elle existe
        subprocess.run(
            ["sudo", "nft", "delete", "table", "inet", table_name],
            check=False, capture_output=True
        )
        
        # Créer la table et les chaînes
        rules = [
            # Table
            ["nft", "add", "table", "inet", table_name],
            
            # Chaîne INPUT
            ["nft", "add", "chain", "inet", table_name, "input",
             "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"],
            
            # Chaîne OUTPUT
            ["nft", "add", "chain", "inet", table_name, "output",
             "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"],
            
            # Chaîne FORWARD (si routage)
            ["nft", "add", "chain", "inet", table_name, "forward",
             "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}"],
            
            # Règle NFQUEUE pour INPUT (sauf loopback)
            ["nft", "add", "rule", "inet", table_name, "input",
             "iif", "!=", "lo", "queue", "num", str(queue_num), "bypass"],
            
            # Règle NFQUEUE pour OUTPUT (sauf loopback)
            ["nft", "add", "rule", "inet", table_name, "output",
             "oif", "!=", "lo", "queue", "num", str(queue_num), "bypass"],
            
            # Règle NFQUEUE pour FORWARD
            ["nft", "add", "rule", "inet", table_name, "forward",
             "queue", "num", str(queue_num), "bypass"],
        ]
        
        success = 0
        for rule in rules:
            try:
                subprocess.run(["sudo"] + rule, check=True, capture_output=True, timeout=5)
                success += 1
                logger.print(f"   ✅ {' '.join(rule[:5])}...")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.decode().strip() if e.stderr else "N/A"
                logger.print(f"   ⚠️ Échec: {' '.join(rule[:5])}... ({stderr})")
        
        logger.print(f"   📊 NFQUEUE configuré ({success}/{len(rules)} règles)")
        return success == len(rules)
    
    def cleanup_nfqueue(self):
        """Nettoie les règles NFQUEUE."""
        logger.print("🧹 Nettoyage des règles NFQUEUE...")
        
        # Supprimer la table entière (simple et propre)
        result = subprocess.run(
            ["sudo", "nft", "delete", "table", "inet", self.suricata_table],
            check=False, capture_output=True
        )
        
        if result.returncode == 0:
            logger.print("   ✅ Table suricata_ips supprimée")
        else:
            logger.print("   ℹ️ Table suricata_ips déjà absente")

    def _detect_home_net(self) -> str:
        """
        Détecte automatiquement TOUS les réseaux locaux (HOME_NET).
        Retourne une liste au format Suricata : "[192.168.1.0/24, 10.0.0.0/8]"
        """
        networks = set()
        
        try:
            # 1. Récupérer le réseau de la passerelle par défaut
            gateways = netifaces.gateways()
            default_gw = gateways.get('default', {})
            
            # IPv4
            if netifaces.AF_INET in default_gw:
                _, iface = default_gw[netifaces.AF_INET][0], default_gw[netifaces.AF_INET][1]
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.add(str(network))
            
            # 2. Ajouter toutes les interfaces locales (hors loopback)
            for iface in netifaces.interfaces():
                if iface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            networks.add(str(network))
                        except Exception:
                            pass
            
            # 3. Ajouter les réseaux privés standards (RFC 1918)
            private_ranges = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
            for local_ip in IPS.local:
                if isinstance(local_ip, str) and '/' not in local_ip:
                    try:
                        ip_obj = ipaddress.ip_address(local_ip.split('/')[0])
                        for private in private_ranges:
                            priv_net = ipaddress.ip_network(private)
                            if ip_obj in priv_net:
                                networks.add(private)
                    except Exception:
                        pass
            
        except Exception as e:
            logger.print(f"⚠️ Erreur détection HOME_NET : {e}")
        
        # Fallback
        if not networks:
            networks = {"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}
        
        # Formater pour Suricata
        home_net = f"[{', '.join(sorted(networks))}]"
        logger.print(f"🏠 HOME_NET détecté : {home_net}")
        return home_net
    
    async def run_suricata(self, mode='ids', interface=None, home_net=None):
        """
        Lance Suricata en mode IDS ou IPS.
        
        Args:
            mode: 'ids' (observation) ou 'ips' (blocage via NFQUEUE)
            interface: Interface(s) réseau à surveiller (str ou list)
            home_net: Plage réseau à protéger (auto-détecté si None)
        """
        paths = self.get_suricata_paths()
        config_path = paths['config']
        log_dir = paths['log']
        
        # Gestion des interfaces
        if isinstance(interface, str):
            interface = [interface]
        
        if interface is None or interface == ["lo"]:
            interfaces = [iface for iface in psutil.net_if_addrs().keys() if iface != 'lo']
        else:
            interfaces = interface
        
        if not interfaces:
            raise RuntimeError("Aucune interface réseau disponible")
        
        # Vérifier si Suricata est déjà lancé dans un autre mode
        if state.current_suricata_mode and state.current_suricata_mode != mode:
            logger.print(f"⚠️ Changement de mode ({state.current_suricata_mode} → {mode}), arrêt...")
            self.stop_suricata()
            await asyncio.sleep(2)
        
        # Installation si nécessaire
        if not self.is_suricata_installed():
            logger.print("📦 Installation de Suricata...")
            self.install_suricata()
        
        # Configuration des permissions
        self.setup_permissions()
        self.setup_capabilities()
        
        # Mise à jour des règles
        logger.print("🔄 Mise à jour des règles...")
        # self.update_suricata_rules()
        
        # Configuration selon le mode
        if mode.lower() == 'ips':
            self._configure_suricata_ips(config_path, interfaces, home_net, queue_num=0)
            cmd_queue = ["-q", "0"]
            mode_desc = "IPS (NFQUEUE)"
        else:
            self._configure_suricata_ids(config_path, interfaces, home_net)
            cmd_queue = []
            mode_desc = "IDS"
        
        # Créer le répertoire de logs
        os.makedirs(log_dir, exist_ok=True)
        state.suricata_processes = []
        state.current_suricata_mode = mode
        
        async def read_stream(stream, prefix):
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode().strip()
                if any(kw in decoded.lower() for kw in ['error', 'fatal', 'failed']):
                    logger.print(f"❌ {prefix}: {decoded}")
        
        try:
            logger.print(f"\n🚀 Lancement de Suricata en mode {mode_desc}")
            logger.print(f"   🌐 Interfaces: {', '.join(interfaces)}")
            logger.print(f"   📁 Logs: {log_dir}")
            
            if mode.lower() == 'ips':
                # Mode IPS : une seule instance avec NFQUEUE
                cmd = [
                    "sudo", "suricata",
                    "-c", config_path,
                    *cmd_queue,
                    "-l", log_dir,
                    # "--af-packet"
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                state.suricata_processes.append(process)
                
                asyncio.create_task(read_stream(process.stdout, "Suricata-IPS"))
                asyncio.create_task(read_stream(process.stderr, "Suricata-IPS"))
                
            else:
                # Mode IDS : une instance par interface
                for iface in interfaces:
                    cmd = [
                        "sudo", "suricata",
                        "-c", config_path,
                        "-i", iface,
                        "-l", log_dir
                    ]
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=True,
                    )
                    state.suricata_processes.append(process)
                    
                    asyncio.create_task(read_stream(process.stdout, f"Suricata-{iface}"))
                    asyncio.create_task(read_stream(process.stderr, f"Suricata-{iface}"))
            
            logger.print(f"\n✅ Suricata {mode.upper()} lancé")
            logger.print("📊 Surveillance en direct :")
            logger.print(f"   tail -f {log_dir}/eve.json | jq 'select(.event_type==\"alert\")'")
            
            await asyncio.gather(*[p.wait() for p in state.suricata_processes])
            
        except asyncio.CancelledError:
            logger.print("🛑 Arrêt de Suricata...")
            self.stop_suricata()
            raise
        except Exception as e:
            raise RuntimeError(f"Erreur lors du lancement : {e}")
    
    def run_suricata_sync(self, mode: str = 'ids', interface=None, home_net=None):
        """Version synchrone (bloquante)."""
        asyncio.run(self.run_suricata(mode, interface, home_net))
    
    def run_suricata_background(self, mode: str = 'ids', interface=None, home_net=None):
        """Lance Suricata en arrière-plan (non-bloquant)."""
        thread = threading.Thread(
            target=self.run_suricata_sync,
            args=(mode, interface, home_net),
            daemon=True, name=f"Suricata - {mode}"
        )
        thread.start()
        state.add_threads((thread, f"SURICATA_{mode.upper()}"))
        logger.print(f"🚀 Suricata {mode.upper()} lancé en arrière-plan")
        return thread

if __name__ == "__main__":
    logger.print("=" * 60)
    logger.print("🧪 TEST DU MODULE SURICATA (IDS/IPS)")
    logger.print("=" * 60)
    
    utils = Utils()
    
    # 1. Détection OS
    logger.print("\n🖥️ 1. DÉTECTION OS")
    logger.print("-" * 40)
    os_detected = utils.detect_os()
    logger.print(f"   OS détecté : {os_detected}")
    
    # 2. Chemins Suricata
    logger.print("\n📁 2. CHEMINS SURICATA")
    logger.print("-" * 40)
    paths = utils.get_suricata_paths()
    logger.print(f"   Config : {paths.get('config')}")
    logger.print(f"   Rules  : {paths.get('rules')}")
    logger.print(f"   Logs   : {paths.get('log')}")
    
    # 3. Vérification installation
    logger.print("\n📦 3. INSTALLATION")
    logger.print("-" * 40)
    is_installed = utils.is_suricata_installed()
    logger.print(f"   Suricata installé : {'✅ Oui' if is_installed else '❌ Non'}")
    
    if not is_installed:
        logger.print("\n   📥 Installation de Suricata...")
        try:
            utils.install_suricata()
        except Exception as e:
            logger.print(f"   ⚠️ Installation échouée : {e}")
            logger.print("   ⚠️ Poursuite des tests sans installation...")
    
    # 4. Détection HOME_NET
    logger.print("\n🏠 4. DÉTECTION HOME_NET")
    logger.print("-" * 40)
    home_net = utils._detect_home_net()
    logger.print(f"   HOME_NET : {home_net}")
    
    # 5. Détection interfaces
    logger.print("\n🌐 5. INTERFACES RÉSEAU")
    logger.print("-" * 40)
    interfaces = [iface for iface in psutil.net_if_addrs().keys() if iface != 'lo']
    logger.print(f"   Interfaces disponibles : {interfaces}")
    
    # 6. Test LocalIPS
    logger.print("\n📍 6. TEST LocalIPS")
    logger.print("-" * 40)
    test_ips = ["192.168.1.1", "8.8.8.8", "127.0.0.1", "10.0.0.1"]
    for ip in test_ips:
        is_local = IPS.is_local_ip(ip)
        emoji = "🏠" if is_local else "🌍"
        logger.print(f"   {emoji} {ip:15} → {'LOCAL' if is_local else 'EXTERNE'}")
    
    # 7. Test parsing eve.json (simulé)
    logger.print("\n📄 7. TEST PARSING EVE.JSON")
    logger.print("-" * 40)
    fake_alert = json.dumps({
        "timestamp": "2026-04-13T10:30:45.123456+0200",
        "event_type": "alert",
        "src_ip": "203.0.113.42",
        "src_port": 12345,
        "dest_ip": "192.168.1.10",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature_id": 2001219,
            "signature": "ET SCAN Potential SSH Scan",
            "severity": 2,
            "category": "Attempted Information Leak"
        }
    })
    parsed = utils.parse_eve_line(fake_alert)
    logger.print(f"   Type      : {parsed.get('type')}")
    logger.print(f"   Src IP    : {parsed.get('src_ip')}")
    logger.print(f"   Dest IP   : {parsed.get('dest_ip')}")
    logger.print(f"   Signature : {parsed.get('signature')}")
    logger.print(f"   Direction : {parsed.get('direction')}")
    
    # 8. Test configuration IDS (sans lancer)
    logger.print("\n⚙️ 8. TEST CONFIGURATION IDS")
    logger.print("-" * 40)
    if interfaces:
        test_iface = interfaces[:1]  # Première interface
        logger.print(f"   Test avec interface : {test_iface[0]}")
        try:
            config_path = paths.get('config')
            if config_path:
                utils._configure_suricata_ids(config_path, test_iface, home_net)
                logger.print("   ✅ Configuration IDS générée")
        except Exception as e:
            logger.print(f"   ⚠️ Erreur configuration : {e}")
    
    # 9. Test configuration IPS
    logger.print("\n🛡️ 9. TEST CONFIGURATION IPS")
    logger.print("-" * 40)
    if interfaces:
        test_iface = interfaces[:1]
        try:
            config_path = paths.get('config')
            if config_path:
                utils._configure_suricata_ips(config_path, test_iface, home_net)
                logger.print("   ✅ Configuration IPS générée")
        except Exception as e:
            logger.print(f"   ⚠️ Erreur configuration : {e}")
    
    # 10. Test update rules
    logger.print("\n🔄 10. TEST MISE À JOUR RÈGLES")
    logger.print("-" * 40)
    logger.print("   (cette opération peut prendre du temps...)")
    try:
        success = utils.update_suricata_rules()
        logger.print(f"   → {'✅ Succès' if success else '❌ Échec'}")
    except Exception as e:
        logger.print(f"   ⚠️ Erreur : {e}")
    
    # 11. Test permissions
    logger.print("\n🔐 11. TEST PERMISSIONS")
    logger.print("-" * 40)
    try:
        success = utils.setup_permissions()
        logger.print(f"   → {'✅ Succès' if success else '❌ Échec'}")
    except Exception as e:
        logger.print(f"   ⚠️ Erreur : {e}")
    
    # 12. Test capabilities
    logger.print("\n⚡ 12. TEST CAPABILITIES")
    logger.print("-" * 40)
    try:
        utils.setup_capabilities()
        logger.print("   → ✅ Test terminé")
    except Exception as e:
        logger.print(f"   ⚠️ Erreur : {e}")
    
    # 13. Test lancement background (5 secondes)
    logger.print("\n🚀 13. TEST LANCEMENT BACKGROUND (5 secondes)")
    logger.print("-" * 40)
    if is_installed and interfaces:
        logger.print(f"   Lancement Suricata IDS sur {interfaces[0]}...")
        thread = utils.run_suricata_background(mode='ids', interface=interfaces[0])
        logger.print("   ⏳ Attente 10 secondes...")
        time.sleep(10)
        logger.print("   🛑 Arrêt de Suricata...")
        state.stop()
        
        logger.print(f"   Lancement Suricata IPS sur {interfaces[0]}...")
        thread = utils.run_suricata_background(mode='ips', interface=interfaces[0])
        logger.print("   ⏳ Attente 10 secondes...")
        time.sleep(10)
        logger.print("   🛑 Arrêt de Suricata...")
        state.stop()
        logger.print("   ✅ Test terminé")
    else:
        logger.print("   ⚠️ Test ignoré (Suricata non installé ou pas d'interface)")
    
    # 14. Test stop_suricata
    logger.print("\n🛑 14. TEST STOP SURICATA")
    logger.print("-" * 40)
    try:
        utils.stop_suricata()
        logger.print("   ✅ Commande stop exécutée")
    except Exception as e:
        logger.print(f"   ⚠️ Erreur : {e}")
    
    # 15. Résumé
    logger.print("\n" + "=" * 60)
    logger.print("📊 RÉSUMÉ DES TESTS")
    logger.print("=" * 60)
    logger.print(f"""
    ✅ OS détecté          : {os_detected}
    ✅ HOME_NET            : {home_net}
    ✅ Interfaces          : {len(interfaces)} trouvée(s)
    ✅ Suricata installé   : {'Oui' if is_installed else 'Non'}
    ✅ Fichier config      : {paths.get('config')}
    ✅ Dossier logs        : {paths.get('log')}
    ✅ EVE.json            : {paths.get('eve_file')}
    """)
    
    logger.print("\n💡 Commandes utiles pour tester manuellement :")
    logger.print(f"   # Vérifier la configuration")
    logger.print(f"   suricata -T -c {paths.get('config')}")
    logger.print(f"   # Lancer Suricata en IDS")
    logger.print(f"   sudo suricata -c {paths.get('config')} -i {interfaces[0] if interfaces else 'eth0'} -l {paths.get('log')}")
    logger.print(f"   # Surveiller les alertes")
    logger.print(f"   tail -f {paths.get('eve_file')} | jq 'select(.event_type==\"alert\")'")
    
    logger.print("\n" + "=" * 60)
    logger.print("✅ TESTS TERMINÉS")
    logger.print("=" * 60)