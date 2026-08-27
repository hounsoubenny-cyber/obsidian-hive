#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 20 12:21:31 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import socket
import docker
from datetime import datetime
from typing import List, Dict, Any, Optional
from simulateur_attaque_ia.simulateur_utils.logger import get_logger

logger = get_logger()

class DockerManager:
    def __init__(self):
        self.client = docker.from_env()
        self.image_name = None
        self.container: docker.models.containers.Container = None
        self.container_conf = {}
        self._network_already_exists = False
    
    def ensure_network(self, name: str = "isolated", internal: bool = True) -> None:
        """Crée le réseau Docker custom s'il n'existe pas déjà (idempotent — 
        ne fait rien s'il existe). 'isolated' n'est PAS un réseau Docker natif,
        contrairement à bridge/host/none : il faut le créer nous-mêmes."""
        try:
            self.client.networks.get(name)
            self._network_already_exists = True
        except docker.errors.NotFound:
            self.client.networks.create(name, driver="bridge", internal=internal)
            self._network_already_exists = False
    
    def remove_network(self, name: str = "isolated"):
        try:
            net = self.client.networks.get(name)
            net.remove()
        except Exception:
            pass
    
    def get_labels(self) -> dict:
        if self.container:
            return (
                self.container.labels or
                self.container.attrs.get("Config", {}).get("Labels", {}) or
                (self.container_conf or {}).get("labels", {})
            )
        else:
            return (self.container_conf or {}).get("labels", {})
        
    def connect(self, name_img, name, **kwargs):
        """ Lance le container :
         Example d'argument ': detach=True,
           name='scan_target',
           remove=True
           cap_add = ["SYS_ADMIN", "MKNOD", "NET_ADMIN"]
           command = 'sleep infinity' #list ou str
          """

        if name is None:
            name = f"container_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.image_name = name_img
        self.container_conf = kwargs
        kwargs.setdefault("labels", {"simatk": "true"})
        kwargs.setdefault("detach", True)
        try:
            self.container = self.client.containers.get(name)
            self.container.reload()
            if self.container.status.lower() != 'running':
                self.container.start()
            logger.print(f"✅ Container existant réutilisé: {name}")
            logger.print("Status du container : ", self.container.status)
        except Exception:
            if 'command' not in kwargs:
                kwargs['command'] = "sleep infinity"

            logger.print(f"📦 Création nouveau container avec image: {name_img}")
            logger.print(f"⚙️ Configuration: {kwargs}")

            try:
                self.container = self.client.containers.run(
                    name_img,
                    name=name,
                    **kwargs
                )
                logger.print(f"✅ Nouveau container créé: {name}")
                logger.print("Status du container : ", self.container.status)
                
            except docker.errors.ImageNotFound:
                logger.print(f"❌ Image non trouvée: {name_img}")
                self.list_images()
                raise
            except docker.errors.APIError as e:
                logger.print(f"❌ Erreur API Docker: {e}")
                raise

        time.sleep(2)
        self.container.reload()
        return self.container

    @staticmethod
    def get_ip_type(ip: str) -> str:
        try:
            ip = ip.split('/')[0].strip()
            for family, label in [(socket.AF_INET, "ip4"), (socket.AF_INET6, "ip6")]:
                try:
                    socket.inet_pton(family, ip)
                    return label
                except Exception:
                    pass
            return "error"
        except Exception:
            return "error"
        return "error"
    
    def is_valid_ip(self, ip_string):
        """Vérifier si c'est une IP valide"""
        return self.get_ip_type(ip_string) != "error"

    def _search_key(self, dic:dict, key):
        for k, v in dic.items():
            if str(k).lower() == str(key).lower():
                return v
            if isinstance(v, dict) and v:
                result = self._search_key(v, key)
                if result is not None:
                    return result
        return None


    def list_images(self) -> list[dict]:
        """Lister toutes les images Docker disponibles."""
        images = self.client.images.list()
        
        # logger.print("📋 IMAGES DOCKER DISPONIBLES:")
        
        result = []
        for img in images:
            size_bytes = img.attrs.get('Size', 0) or img.attrs.get('VirtualSize', 0)
            
            # Taille lisible
            size_str = self._format_size(size_bytes)
            
            tags = img.tags or ["<none>"]
            tags_display = tags[0] if tags else "<none>"
            if len(tags) > 1:
                tags_display += f" (+{len(tags)-1})"
            
            # logger.print(f"   🐳 {tags_display}  |  {size_str}  |  🆔 {img.short_id}")
            
            result.append({
                "id": img.id,
                "short_id": img.short_id,
                "tags": tags,
                "labels": img.labels or {},
                "size": size_bytes,
                "size_human": size_str,
                "created": img.attrs.get("Created", "")
            })
        
        return result
    

    def list_containers(self, all: bool = True, filters: dict = None) -> List[Dict[str, Any]]:
        """
        Liste tous les containers Docker avec leurs métadonnées.
    
        Args:
            all: Inclure les containers arrêtés (True par défaut)
            filters: Filtres Docker (ex: {"status": "running"})
    
        Returns:
            List[Dict]: Liste des containers avec leurs infos
        """
        try:
            containers = self.client.containers.list(all=all, filters=filters)
        except Exception as e:
            logger.print(f"❌ Erreur liste containers: {e}")
            return []
    
        result = []
        for container in containers:
            labels = container.labels or {}
            
            try:
                ip = self.get_ip(container=container)
            except Exception:
                ip = None
            
            size = 0
            try:
                size = container.attrs.get("SizeRootFs", 0) or container.attrs.get("SizeRw", 0)
            except Exception:
                pass
    
            # Tags image
            image_tags = container.image.tags if container.image else []
            status = container.status.lower()
            # Si le statut n'est pas dans la liste, on le met en "unknown"
            valid_statuses = ["created", "running", "exited", "paused", 
                              "restarting", "removing", "dead", "stopped"]
            if status not in valid_statuses:
                status = "unknown"
            
            result.append({
                "id": container.id,
                "short_id": container.short_id,
                "name": container.name,
                "image": image_tags[0] if image_tags else "<none>",
                "status": status,
                "ip": ip,
                "created": container.attrs.get("Created", ""),
                "size": size,
                "size_human": self._format_size(size),
                "labels": labels,
                "is_simatk": labels.get("simatk") == "true" or "simatk_" in container.name,
            })
    
        return result
    
    def _format_size(self, size: int) -> str:
        """Formate une taille en octets."""
        if size >= 1024**3:
            return f"{size / (1024**3):.2f} GB"
        elif size >= 1024**2:
            return f"{size / (1024**2):.2f} MB"
        elif size >= 1024:
            return f"{size / 1024:.2f} KB"
        return "0 B"

    def get_ip(
        self, 
        network:str = "bridge", 
        container: docker.models.containers.Container | None = None,
        container_conf: Dict | None = None
    ):
        """Récupère IP du container"""
        if container is None:
            container = self.container
            container_conf = self.container_conf
            
        else:
            container_conf = container_conf or {}
            
        if not container:
            raise ValueError("Container pas démarré!")
        
        if container_conf.get("network", None) == "host":
            return "127.0.0.1"
        
        container.reload()
        # logger.print("Clé docker : ", list(container.attrs['NetworkSettings'].keys()))
        # logger.print(self.container.attrs['NetworkSettings'])
        try:
            ip = container.attrs['NetworkSettings']['Networks'][network]['IPAddress']
            
        except Exception:
            dic = container.attrs['NetworkSettings']
            key = "IPAddress"
            ip = self._search_key(dic, key)
            
        if not self.is_valid_ip(str(ip)):
            ip = ''
            
        if not ip:
            raise ValueError("Container n'a pas d'IP (réseau pas prêt?)")
        return ip

    def stop(self):
        if self.container:
            logger.print(f"🛑 Arrêt container {self.container.name}...")
            try:
                self.container.stop()
                self.container.remove(force=True)
                try:
                    self.container.kill() #Juste au cas où
                except:
                    pass
                logger.print("✅ Container nettoyé")
            except Exception as e:
                logger.print(f"⚠️ Erreur nettoyage: {e}")

    def exec_command(self, cmd, show: bool = True):
        """Exécute commande dans le container"""
        if not self.container:
            raise ValueError("Container pas démarré!")

        result = self.container.exec_run(cmd, stdout=True, stderr=True)
        if show:
            logger.print()
            logger.print("Commande : ", cmd[:200], verify=False)
            logger.print('Code retour : ', result.exit_code)
            # logger.print('Stderr : ', result.stderr)
            logger.print()
        return result.output.decode(), result

    def exec_command_api(self, cmd):
        print("IN API")
        import shlex
        if isinstance(cmd, str):
            cmd = ["sh", "-c", cmd]
        elif isinstance(cmd, list):
            cmd = ["sh", "-c", shlex.join(cmd)]
        else:
            cmd = ["sh", "-c", str(cmd)]
        print(cmd)
        
        result = self.container.exec_run(cmd, demux=True, stderr=True, stdout=True)
        stdout, stderr = result.output
        return {
            "stdout": stdout.decode(errors="ignore") if stdout else "",
            "stderr": stderr.decode(errors="ignore") if stderr else "",
            "exit_code": result.exit_code,
        }


if __name__ == "__main__":
    d = DockerManager()
    d.list_images()
