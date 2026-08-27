#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 2026

@author: hounsousamuel

Environnement de test pour ShieldAI V2.

Deux modes :
    network=False (défaut) — un seul container avec tous les services
    network=True           — N containers sur un réseau Docker isolé,
                             SSH réel, clés croisées, known_hosts peuplés

Usage simple :
    env = TestEnvironment(image_name="clone_xxx:latest")
    ip  = env.setup()
    env.teardown()

Usage réseau :
    env = TestEnvironment(image_name="clone_xxx:latest", network=True, n_nodes=3)
    nodes = env.setup()   # [{"name": "pc1", "ip": "...", "dock": ...}, ...]
    entry = nodes[0]["ip"]
    env.teardown()
"""

import os
import sys
import time
import socket as _socket

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import docker
from typing import List, Dict, Any, Optional, Union

from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.core.fake_services_scripts import (
    FAKE_HTTP_SCRIPT as SERVER_SCRIPT,
    FAKE_FTP_SCRIPT, 
    FAKE_SSH_SCRIPT,
    SSH_SETUP_SCRIPT,
    KEYGEN_SCRIPT
)
logger = get_logger()


# =============================================================================
# TestEnvironment — classe unique fusionnée
# =============================================================================

class TestEnvironment:
    """
    Environnement de test pour ShieldAI V2.

    network=False (défaut) :
        Un seul container avec FakeSSH, FakeFTP, services HTTP.
        Retourne une IP (str).

    network=True :
        N containers sur un réseau Docker isolé.
        SSH réel (OpenSSH), clés SSH croisées propres, known_hosts peuplés.
        Retourne une liste de nodes (List[Dict]).

    Args:
        image_name (str): Image Docker à utiliser.
        container_name (str): Nom du container (mode simple).
        ports (list): Ports à ouvrir sur chaque container.
        container_config (dict): Config Docker custom.
        network (bool): Mode réseau multi-containers.
        n_nodes (int): Nombre de containers en mode réseau.
        network_name (str): Nom du réseau Docker créé.
        subnet (str): Subnet du réseau (ex: "172.30.0.0/24").
    """

    DEFAULT_PORTS = [8080, 8081]
    DEFAULT_CONFIG = {
        "command":      "sleep infinity",
        "detach":       True,
        "remove":       False,
        "ports":        {4444: 4444, 4445: 4445, 4446: 4446, 5000: 5000},
        "cap_add":      ["SYS_ADMIN", "MKNOD", "NET_ADMIN"],
        "security_opt": ["seccomp=unconfined"],
    }

    DEFAULT_NETWORK_NAME  = "shieldai_net"
    DEFAULT_SUBNET        = "172.30.0.0/24"
    DEFAULT_BASE_IP       = "172.30.0."
    DEFAULT_BASE_IP_START = 2

    def __init__(
        self,
        image_name: str,
        container_name: str = "shieldai_test",
        ports: list = None,
        container_config: dict = None,
        network: bool = False,
        n_nodes: int = 3,
        network_name: str = DEFAULT_NETWORK_NAME,
        subnet: str = DEFAULT_SUBNET,
    ):
        self.image_name       = image_name
        self.container_name   = container_name
        self.ports            = ports or self.DEFAULT_PORTS
        self.container_config = container_config or self.DEFAULT_CONFIG
        self.network_mode     = network
        self.n_nodes          = n_nodes
        self.network_name     = network_name
        self.subnet           = subnet

        self.dock      = DockerManager()
        self.container = None
        self.ip        = None

        self.client   = docker.from_env()
        self._network = None
        self.nodes: List[Dict[str, Any]] = []

    # =========================================================================
    # PUBLIC
    # =========================================================================

    def setup(self) -> Union[str, List[Dict[str, Any]]]:
        if self.network_mode:
            return self._setup_network()
        return self._setup_simple()

    def teardown(self):
        if self.network_mode:
            self._teardown_network()
        else:
            self._teardown_simple()

    def get_open_ports(self) -> str:
        output, _ = self.dock.exec_command("netstat -tuln")
        logger.print("🔍 Ports en écoute:\n" + output)
        return output

    def get_entry_point(self) -> Dict[str, Any]:
        return self.nodes[0] if self.nodes else {}

    def print_topology(self):
        logger.print("\n📡 Topologie réseau ShieldAI :")
        logger.print(f"  Réseau : {self.network_name} ({self.subnet})")
        for node in self.nodes:
            neighbors = [n["host"] for n in node.get("known_hosts", [])]
            logger.print(f"  {node['name']:12} → {node['ip']:15} (root:toor)  knows: {neighbors}")

    # =========================================================================
    # MODE SIMPLE
    # =========================================================================

    def _setup_simple(self) -> str:
        logger.print("=" * 55)
        logger.print("🚀 Démarrage environnement de test ShieldAI (simple)")
        logger.print("=" * 55)

        self._start_container()
        self._deploy_script("/tmp/server.py",   SERVER_SCRIPT)
        self._deploy_script("/tmp/fake_ssh.py", FAKE_SSH_SCRIPT)
        self._deploy_script("/tmp/fake_ftp.py", FAKE_FTP_SCRIPT)
        self._start_services_simple()
        self._setup_http_pages()
        self._wait_ports_ready(self.dock, self.ports + [22, 21], timeout=15)

        self.ip = self.dock.get_ip()
        logger.print(f"✅ Environnement prêt — IP : {self.ip}")
        return self.ip

    def _teardown_simple(self):
        logger.print("🛑 Teardown environnement simple...")
        self.dock.stop()
        logger.print("✅ Container nettoyé.")

    def _start_container(self):
        logger.print(f"📦 Lancement container '{self.container_name}'...")
        self.container = self.dock.connect(
            self.image_name,
            self.container_name,
            **self.container_config,
        )

    def _start_services_simple(self):
        logger.print(f"🔧 Démarrage des services ({len(self.ports)} ports)...")
        for port in self.ports:
            self.dock.exec_command(["bash", "-c", f"python3 /tmp/server.py {port} > /http_output.txt &"])
            logger.print(f"  ✅ Service port {port}")
        self.dock.exec_command(["bash", "-c", "python3 /tmp/fake_ssh.py > /ssh_output.txt &"])
        self.dock.exec_command(["bash", "-c", "python3 /tmp/fake_ftp.py > /sftp_output.txt &"])
        logger.print("  ✅ FakeSSH port 22 | FakeFTP port 21")
        time.sleep(1.5)

    def _setup_http_pages(self, port: int = 9090):
        self.dock.exec_command("mkdir -p /tmp/www/admin /tmp/www/backup")
        self.dock.exec_command("echo 'Admin Page' > /tmp/www/admin/index.html")
        self.dock.exec_command("echo 'Backup'     > /tmp/www/backup/index.html")
        self.dock.exec_command(["bash", "-c", f"cd /tmp/www && python3 -m http.server {port} &"])

    # =========================================================================
    # MODE RÉSEAU
    # =========================================================================

    def _setup_network(self) -> List[Dict[str, Any]]:
        logger.print("=" * 60)
        logger.print("🌐 Démarrage NetworkTestEnvironment ShieldAI V2")
        logger.print(f"   Nodes : {self.n_nodes}  |  Réseau : {self.subnet}")
        logger.print("=" * 60)

        self._create_network()
        self._start_nodes()
        self._setup_ssh_on_all()
        self._start_services_on_all()
        self._setup_cross_keys()
        self._setup_known_hosts()
        self._wait_ssh_all()

        logger.print("\n✅ Réseau de test prêt !")
        self.print_topology()
        return self.nodes

    def _teardown_network(self):
        logger.print("\n🛑 Teardown réseau...")
        for node in self.nodes:
            try:
                node["dock"].stop()
                logger.print(f"  ✅ {node['name']} arrêté")
            except Exception as e:
                logger.print(f"  ⚠️ {node['name']}: {e}")
        try:
            if self._network:
                self._network.remove()
                logger.print(f"  ✅ Réseau {self.network_name} supprimé")
        except Exception as e:
            logger.print(f"  ⚠️ Réseau: {e}")

    def _create_network(self):
        logger.print(f"🔧 Création réseau '{self.network_name}'...")
        for i in range(self.n_nodes):
            name = f"shieldai_pc{i + 1}"
            try:
                container = self.client.containers.get(name)
                container.stop()
                container.remove(force=True)
                logger.print(f"  ♻️  Container {name} supprimé")
            except docker.errors.NotFound:
                pass
        try:
            self.client.networks.get(self.network_name).remove()
            logger.print("  ♻️  Réseau existant supprimé")
        except docker.errors.NotFound:
            pass
        except Exception:
            pass

        ipam = docker.types.IPAMConfig(
            pool_configs=[docker.types.IPAMPool(subnet=self.subnet)]
        )
        self._network = self.client.networks.create(
            self.network_name, driver="bridge", ipam=ipam
        )
        logger.print(f"  ✅ Réseau créé ({self.subnet})")

    def _start_nodes(self):
        logger.print(f"\n📦 Lancement de {self.n_nodes} containers...")
        for i in range(self.n_nodes):
            name = f"shieldai_pc{i + 1}"
            ip   = f"{self.DEFAULT_BASE_IP}{self.DEFAULT_BASE_IP_START + i}"

            try:
                old = self.client.containers.get(name)
                old.stop()
                old.remove(force=True)
            except docker.errors.NotFound:
                pass

            container = self.client.containers.run(
                self.image_name,
                name=name,
                detach=True,
                remove=False,
                command="sleep infinity",
                cap_add=["SYS_ADMIN", "MKNOD", "NET_ADMIN"],
                security_opt=["seccomp=unconfined"],
                network=self.network_name,
            )

            try:
                self._network.connect(container, ipv4_address=ip)
                try:
                    self.client.networks.get("bridge").disconnect(container)
                except Exception:
                    pass
            except Exception:
                pass

            dock = DockerManager()
            dock.container  = container
            dock.image_name = self.image_name

            self.nodes.append({
                "name":        name,
                "ip":          ip,
                "dock":        dock,
                "container":   container,
                "public_key":  "",
                "known_hosts": [],
            })
            logger.print(f"  ✅ {name} → {ip}")
            time.sleep(0.3)

    def _setup_ssh_on_all(self):
        """Configure OpenSSH réel sur tous les nodes."""
        logger.print("\n🔧 Configuration OpenSSH sur tous les nodes...")
        for node in self.nodes:
            dock = node["dock"]
            self._deploy_script_on(dock, "/tmp/ssh_setup.sh", SSH_SETUP_SCRIPT)
            dock.exec_command(["bash", "/tmp/ssh_setup.sh"])
            logger.print(f"  ✅ SSH → {node['name']} ({node['ip']})")
            time.sleep(0.3)

    def _start_services_on_all(self):
        """Lance les services (HTTP, FTP, etc.) sur chaque node."""
        logger.print("\n🔧 Démarrage services sur tous les nodes...")
        for node in self.nodes:
            dock = node["dock"]
            self._deploy_script_on(dock, "/tmp/server.py",   SERVER_SCRIPT)
            self._deploy_script_on(dock, "/tmp/fake_ftp.py", FAKE_FTP_SCRIPT)
            for port in self.ports:
                dock.exec_command(["bash", "-c", f"python3 /tmp/server.py {port} &"])
            dock.exec_command(["bash", "-c", "python3 /tmp/fake_ftp.py &"])
            dock.exec_command("mkdir -p /tmp/www/admin /tmp/www/backup")
            dock.exec_command("echo 'Admin' > /tmp/www/admin/index.html")
            dock.exec_command(["bash", "-c", "cd /tmp/www && python3 -m http.server 9090 &"])
            logger.print(f"  ✅ Services → {node['name']}")
            time.sleep(0.5)

    def _setup_cross_keys(self):
        """
        Nettoie les clés canary existantes, génère de vraies clés RSA 2048
        sur chaque node et distribue les clés publiques dans les authorized_keys
        de tous les autres nodes.

        Résultat : chaque node peut SSH vers tous les autres avec sa clé privée.
        SSHKeyTheft pourra lire /root/.ssh/id_rsa et obtenir une clé valide.
        """
        logger.print("\n🔑 Génération et distribution des clés SSH propres...")

        # Étape 1 — nettoyer les canary + générer une vraie clé RSA sur chaque node
        for node in self.nodes:
            dock = node["dock"]
            self._deploy_script_on(dock, "/tmp/keygen.sh", KEYGEN_SCRIPT)
            output, result = dock.exec_command(["bash", "/tmp/keygen.sh"])
            pub_key = output.strip()

            if not pub_key or "ssh-rsa" not in pub_key:
                logger.print(f"  ⚠️ {node['name']} : clé publique invalide — {pub_key[:50]}")
                node["public_key"] = ""
            else:
                node["public_key"] = pub_key
                logger.print(f"  🔑 {node['name']} : clé RSA générée ({pub_key[:40]}...)")

        # Étape 2 — distribuer chaque clé publique vers les authorized_keys de tous les autres
        for src in self.nodes:
            pub_key = src["public_key"]
            if not pub_key:
                continue
            for dst in self.nodes:
                if src["name"] == dst["name"]:
                    continue
                cmd = (
                    f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                    f"echo '{pub_key}' >> /root/.ssh/authorized_keys && "
                    f"chmod 600 /root/.ssh/authorized_keys"
                )
                dst["dock"].exec_command(["bash", "-c", cmd])

        logger.print("  ✅ Clés distribuées — chaque node peut SSH vers les autres")

    def _setup_known_hosts(self):
        """
        Peuple ~/.ssh/known_hosts sur chaque node avec les IPs des voisins
        via ssh-keyscan — known_hosts propres, sans entrées canary.
        """
        logger.print("\n🗺️  Configuration known_hosts croisés...")
        time.sleep(1)

        for node in self.nodes:
            dock = node["dock"]

            # Nettoyer les known_hosts canary existants
            dock.exec_command("rm -f /root/.ssh/known_hosts")

            neighbors = []
            for other in self.nodes:
                if other["name"] == node["name"]:
                    continue
                ip = other["ip"]
                cmd = f"ssh-keyscan -t rsa -T 3 {ip} >> /root/.ssh/known_hosts 2>/dev/null; echo 'ok'"
                dock.exec_command(["bash", "-c", cmd])
                neighbors.append({"host": ip, "port": 22})

            dock.exec_command("chmod 600 /root/.ssh/known_hosts 2>/dev/null || true")
            node["known_hosts"] = neighbors
            logger.print(f"  ✅ {node['name']} known_hosts : {[n['host'] for n in neighbors]}")

    def _wait_ssh_all(self, timeout: int = 30):
        """Attend que SSH soit joignable sur tous les nodes."""
        logger.print("\n⏳ Attente SSH sur tous les nodes...")
        start = time.time()
        while time.time() - start < timeout:
            ready = []
            for node in self.nodes:
                try:
                    s = _socket.create_connection((node["ip"], 22), timeout=2)
                    s.close()
                    ready.append(node["name"])
                except Exception:
                    pass
            if len(ready) == len(self.nodes):
                logger.print(f"  ✅ SSH prêt sur tous les nodes ({time.time()-start:.1f}s)")
                return True
            missing = [n["name"] for n in self.nodes if n["name"] not in ready]
            logger.print(f"  ⏳ En attente : {missing}")
            time.sleep(1)
        logger.print("  ⚠️ Timeout SSH — les nodes sont peut-être prêts quand même")
        return False

    # =========================================================================
    # HELPERS COMMUNS
    # =========================================================================

    def _deploy_script(self, remote_path: str, content: str):
        self._deploy_script_on(self.dock, remote_path, content)

    def _deploy_script_on(self, dock: DockerManager, remote_path: str, content: str):
        filename = os.path.basename(remote_path)
        parent   = os.path.dirname(remote_path)
        dock.exec_command(f"mkdir -p {parent}")
        cmd = f"cat > {remote_path} << 'SHIELDAI_EOF'\n{content}\nSHIELDAI_EOF"
        output, result = dock.exec_command(["bash", "-c", cmd])
        if result.exit_code != 0:
            logger.print(f"  ⚠️ Déploiement {filename}: {output[:100]}")

    def _wait_ports_ready(self, dock: DockerManager, ports: List[int], timeout: int = 10) -> bool:
        logger.print(f"⏳ Attente des ports {ports}...")
        start = time.time()
        while time.time() - start < timeout:
            output, _ = dock.exec_command("netstat -tuln")
            missing = [p for p in ports if str(p) not in output]
            if not missing:
                logger.print(f"✅ Ports prêts en {time.time()-start:.1f}s")
                return True
            logger.print(f"  ⏳ Manquants : {missing}")
            time.sleep(0.5)
        logger.print("⚠️ Timeout ports")
        return False


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    IMAGE_NAME = "shieldai_sim_atk:v2"

    env = TestEnvironment(
        image_name=IMAGE_NAME,
        network=True,
        n_nodes=3,
    )
    try:
        nodes = env.setup()
        env.print_topology()
        logger.print(f"\n🎯 Point d'entrée : {nodes[0]['ip']} (root:toor)")
        logger.print("Ctrl+C pour arrêter")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        env.teardown()
