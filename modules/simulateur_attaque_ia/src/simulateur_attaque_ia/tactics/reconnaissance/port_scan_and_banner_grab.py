#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 22 07:04:12 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import re
import time
import socket
import asyncio
import concurrent.futures
from tactics.base import Base
from simulateur_utils.logger import get_logger
from tactics.mittres import MITRE
logger = get_logger()

class NetworkServiceDiscover(Base):
    """
    Classe qui gère le initial_access
    """
    def __init__(
        self, timeout_socket:int|float=0.2, 
        **kwargs
    ):
        """
        Methode d'instanciation.

        Parameters
        ----------
        timeout_socket : int|float, optional
            tTimeout de connexion. The default is 0.2.
        **kwargs : dict
            Argument supplémentaire pour la classe mère.

        Returns
        -------
        None.

        """
        self.name = ["port_scan", "banner_grab"]
        super().__init__(name=self.name, **kwargs)
        self.timeout_socket = timeout_socket
        self.start_time = time.time()
        self.result = {}
        self.open_port = []
        self.close_port = []
        self.PATTERN_VERSION = re.compile(
            r'(?:.*[\/_\s:])?'
            r'(?P<version>(?:[0-9]{1,4}\.){1,5}[0-9]{1,4}(?:[a-z]{1,3}[0-9]{0,3})?)'  # Capture la version principale
            r'(?:-[a-z0-9]+(?:\.[a-z0-9]+)*)?'  # Consomme le suffixe sans le capturer
            r'(?:~[a-z0-9]+)?',                 # Consomme le suffixe tilde sans le capturer
            re.IGNORECASE
        )
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=150,
            thread_name_prefix="base_reconnaissance_",
        )

    def extract_version(self, banner: str) -> str | None:
        """
        Extraction de version étendue
        """
        if not banner:
            return None

        if isinstance(banner, bytes):
            banner = banner.decode('utf-8', errors='ignore')

        # SSH
        ssh_match = re.search(r'SSH-[\d\.]+-([^\s\r\n]+)', banner)
        if ssh_match:
            return ssh_match.group(1)

        # HTTP Server
        http_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if http_match:
            return http_match.group(1).strip()

        # FTP
        ftp_match = re.search(r'\(Version\s*([^)]+)\)', banner)
        if ftp_match:
            return ftp_match.group(1)
        ftp_match2 = re.search(r'220[^\d]*([\d]+\.[\d]+(?:\.[\d]+)?)', banner)
        if ftp_match2:
            return ftp_match2.group(1)

        # SMTP
        smtp_match = re.search(r'(Postfix|Exim|Sendmail)[\s/]*([\d\.]+)', banner, re.IGNORECASE)
        if smtp_match:
            return f"{smtp_match.group(1)} {smtp_match.group(2)}"

        # MySQL
        mysql_match = re.search(r'([\d]+\.[\d]+\.[\d]+)', banner)
        if any(x in banner.lower() for x in ['mysql', 'mariadb']) and mysql_match:
            return mysql_match.group(1)

        # Redis
        redis_match = re.search(r'redis[_-]?version[:\s]*([\d\.]+)', banner, re.IGNORECASE)
        if redis_match:
            return redis_match.group(1)

        # Elasticsearch
        elastic_match = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        if elastic_match:
            return elastic_match.group(1)

        # Apache
        apache_match = re.search(r'Apache[/\s]([\d\.]+)', banner, re.IGNORECASE)
        if apache_match:
            return apache_match.group(1)

        # Nginx
        nginx_match = re.search(r'nginx[/\s]([\d\.]+)', banner, re.IGNORECASE)
        if nginx_match:
            return nginx_match.group(1)

        # Docker
        docker_match = re.search(r'Docker[/\s]([\d\.]+)', banner, re.IGNORECASE)
        if docker_match:
            return docker_match.group(1)

        # Tomcat
        tomcat_match = re.search(r'Tomcat[/\s]([\d\.]+)', banner, re.IGNORECASE)
        if tomcat_match:
            return tomcat_match.group(1)

        version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)?)', banner)
        if version_match:
            version = version_match.group(1)
            if len(version) > 2 and not version.startswith('0.'):
                return version

        version_match = re.search(r'v?(\d+\.\d+(?:\.\d+)*)', banner)
        if version_match:
            return version_match.group(1)

        else:
            match = self.PATTERN_VERSION.search(banner)
            return match.group('version') if match else None
    
    def detect_service(self, banner) -> str|None:
        """
        Methode d'extraction de service à partir du banner.

        Parameters
        ----------
        banner : str
            Le banner.

        Returns
        -------
        str
            Le service ou None.

        """
        if not banner:
            return None

        if isinstance(banner, bytes):
            banner = banner.decode('utf-8', errors='ignore')

        banner = str(banner)
        banner_lower = banner.lower()
        banner_upper = banner.upper()

        if 'ssh' in banner_lower:
            return 'SSH'
        elif 'http' in banner_lower or 'server:' in banner_lower:
            return 'HTTP'
        elif '220' in banner and 'ftp' in banner_lower:
            return 'FTP'
        elif '220' in banner and ('smtp' in banner_lower or 'mail' in banner_lower):
            return 'SMTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'redis' in banner_lower:
            return 'Redis'
        elif 'elastic' in banner_lower or '"number"' in banner:
            return 'Elasticsearch'
        elif any(x in banner_lower for x in ['mysql', 'mariadb']):
            return 'MySQL'
        elif 'POSTGRESQL' in banner_upper or 'POSTGRES' in banner_upper:
            return 'PostgreSQL'
        elif any(x in banner_lower for x in ['redis', '+redis_version']):
            return 'Redis'
        elif 'MONGODB' in banner_upper:
            return 'MongoDB'
        elif any(x in banner_lower for x in ['oracle', 'oracle database']):
            return 'Oracle DB'
        elif 'SQLSERVER' in banner_upper or 'MICROSOFT SQL' in banner_upper:
            return 'Microsoft SQL Server'
        elif any(x in banner_lower for x in ['cassandra', 'apache cassandra']):
            return 'Cassandra'
        elif 'ELASTICSEARCH' in banner_upper or '"number"' in banner:
            return 'Elasticsearch'
        elif any(x in banner_lower for x in ['memcached', 'stats']):
            return 'Memcached'

        elif any(x in banner_lower for x in ['irc', 'internet relay chat']):
            return 'IRC'
        elif any(x in banner_lower for x in ['xmpp', 'jabber']):
            return 'XMPP'
        elif 'RABBITMQ' in banner_upper:
            return 'RabbitMQ'

        elif any(x in banner_lower for x in ['docker', 'dockerd']):
            return 'Docker'
        elif any(x in banner_lower for x in ['kubernetes', 'k8s']):
            return 'Kubernetes'
        elif 'ETCD' in banner_upper:
            return 'etcd'
        elif any(x in banner_lower for x in ['consul', 'hashicorp']):
            return 'Consul'

        elif any(x in banner_lower for x in ['nfs', 'network file system']):
            return 'NFS'
        elif any(x in banner_lower for x in ['samba', 'samba smbd', 'netbios']):
            return 'Samba'
        elif any(x in banner_lower for x in ['ftp', 'file transfer']):
            return 'FTP'

        elif any(x in banner_lower for x in ['prometheus', 'metrics']):
            return 'Prometheus'
        elif any(x in banner_lower for x in ['grafana', 'dashboard']):
            return 'Grafana'
        elif any(x in banner_lower for x in ['zabbix', 'monitoring']):
            return 'Zabbix'
        elif any(x in banner_lower for x in ['nagios', 'nrpe']):
            return 'Nagios'

        elif any(x in banner_lower for x in ['apache', 'apache/']):
            return 'Apache'
        elif any(x in banner_lower for x in ['nginx', 'nginx/']):
            return 'Nginx'
        elif any(x in banner_lower for x in ['iis', 'microsoft-iis']):
            return 'IIS'
        elif any(x in banner_lower for x in ['tomcat', 'apache-tomcat']):
            return 'Tomcat'
        elif any(x in banner_lower for x in ['jetty', 'eclipse jetty']):
            return 'Jetty'
        elif any(x in banner_lower for x in ['node.js', 'express']):
            return 'Node.js'

        elif any(x in banner_lower for x in ['rdp', 'remote desktop', 'microsoft terminal services']):
            return 'RDP'
        elif any(x in banner_lower for x in ['vnc', 'rfb']):
            return 'VNC'
        elif any(x in banner_lower for x in ['teamviewer']):
            return 'TeamViewer'

        elif any(x in banner_lower for x in ['openvpn', 'open vpn']):
            return 'OpenVPN'
        elif any(x in banner_lower for x in ['wireguard']):
            return 'WireGuard'
        elif any(x in banner_lower for x in ['nessus', 'tenable']):
            return 'Nessus'

        elif any(x in banner_lower for x in ['telnet']):
            return 'Telnet'
        elif any(x in banner_lower for x in ['ldap']):
            return 'LDAP'
        elif any(x in banner_lower for x in ['ntp']):
            return 'NTP'
        elif any(x in banner_lower for x in ['snmp']):
            return 'SNMP'
        elif any(x in banner_lower for x in ['sip']):
            return 'SIP'
        elif any(x in banner_lower for x in ['rtsp']):
            return 'RTSP'
        elif any(x in banner_lower for x in ['git', 'git server']):
            return 'Git'
        elif any(x in banner_lower for x in ['svn', 'subversion']):
            return 'Subversion'

        elif any(x in banner_lower for x in ['welcome', 'ready', 'service', 'server']):
            return 'Generic TCP Service'
        
        return None
    
    def _scan_sync(self, ip:str, port:int) -> (int, dict):
        """
        Méthode privé pour un scan.

        Parameters
        ----------
        ip : str
            L'IP.
        port : int
            Le PORT.

        Returns
        -------
        (int, dict)
            Tuple, le port et le résultat.

        """
        result = {
            "open": False,
            "service": None,
            "banner": None,
            "version": None
        }
        sock = socket.socket()
        try:
            sock.settimeout(self.timeout_socket)
            connect_r = sock.connect_ex((ip, port))
            try:
                banner = sock.recv(1024).decode()
            except Exception:
                # logger.print("Erreur dans l'obtention du banner(1) :", str(e))
                banner = ""
            
            if not banner:
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode()
                except Exception:
                    # logger.print("Erreur dans l'obtention du banner(2) :", str(e))
                    banner = ""
                        
            result["open"] = connect_r == 0
            result["banner"] = banner 
            if result["open"]:
                service = self.detect_service(banner)
                result["service"] =  service.lower() if service else socket.getservbyport(port).split('\n')[0].strip()
                result["version"] = self.extract_version(banner)
        
        except Exception:
            # logger.print("Erreur dans _scan :", str(e))
            pass
        
        sock.close()
        return port, result
    
    async def _scan_async(self, ip: str, port: int) -> (int, dict):
        """ Version asynchrone de _scan_sync"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self._scan_sync, ip, port)
    
    async def scan_async(self, ip:str, port_range:list|range|tuple) -> dict:
        """
        Méthode principale pour le scan.

        Parameters
        ----------
        ip : str
            L' IP.
        port_range : list|range|tuple
            La liste ou le range des port.

        Raises
        ------
        ValueError
            Si ip vide.

        Returns
        -------
        dict
            Dictionnaire des résultats.

        """
        if isinstance(port_range, str):
            port_range = [port_range]
        else:
            port_range = list(port_range)
            
        if not ip:
            raise ValueError('[NetworkServiceDiscover] IP manquant et dois être une string !')
        
        port_range = [int(p) for p in port_range if isinstance(p, (int, float)) and 0 <= int(p) <= 65535]
        self.log(f"Début port scan avec socket à : {time.ctime()}, pour ip : {ip} et {len(port_range)} ports", log=True)
        self.log(f"{port_range}")
        
        tasks = [
            asyncio.create_task(
                self._scan_async(ip, port)
            )
            for port in port_range
        ]
        self.start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for port, result in results:
            self.result[port] = result
            if result["open"]:
                self.open_port.append(port)
            else:
                self.close_port.append(port)
        
        self.end_time = time.time()
        self.log(f'Fin scan socket à {self.end_time}', log=True)
        self.log(f"Open port : {self.open_port}")
        self.log(f"Close port :{self.close_port}")
        logger.print(len(self.open_port), "ports ouverts et", len(self.close_port), "fermés")
        logger.print('Fin scan socket !')
        return self.get_result()
    
    def scan_sync(self, ip, port_range):
        """ Version synchrone de scan_async """
        return asyncio.run(self.scan_async(ip, port_range))
    
    def get_result(self):
        """ Méthode pour former le dictionnaire finale. """
        self.save()
        
        mitres = [MITRE.get("PortScan", {}), MITRE.get("BannerGrab", {})]
        results = {
            'severity': 'LOW',
            'elapsed': self.end_time - self.start_time,
            "mitres": mitres,
            'results': {
                'open_ports': self.open_port,
                'closed_ports': self.close_port,
                'scan_result': self.result,
            },
        }
        
        return results
                


def test_network_service_discover(ip: str = None, port_range: range = range(1, 1025)):
    """Test rapide de NetworkServiceDiscover sur une cible."""
    import json
    try:
       
        logger.print(f"🎯 Scan de {ip} sur {len(list(port_range))} ports...")

        scanner = NetworkServiceDiscover(timeout_socket=0.3)
        result = scanner.scan_sync(ip, list(port_range))

        logger.print("✅ Résultat :")
        logger.print(f"  Ports ouverts  : {result['results']['open_ports']}")
        #logger.print(f"  Ports fermés   : {len(result['results']['closed_ports'])}")
        logger.print(f"  Elapsed        : {result['elapsed']:.2f}s")
        #logger.print(json.dumps(result['results']['scan_result'], indent=2))
        return result

    except Exception as e:
        logger.print(f"❌ Erreur test : {e}")
        import traceback
        logger.print(traceback.format_exc())
        raise

if __name__ == "__main__":
    result = test_network_service_discover("127.0.0.1", range(1000, 9000))
    open_ports = result['results']['open_ports']
    print("Open port :", open_ports)
    for port in open_ports:
        print("PORT:", port)
        print(result["results"]["scan_result"][port])
        print()
        
    


