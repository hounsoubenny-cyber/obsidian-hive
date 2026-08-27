#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 17:10:02 2026

@author: hounsousamuel
"""

"""
Router /network – gestion des réseaux Docker.

GET    /network/list              → Lister les réseaux
POST   /network/create            → Créer un réseau
GET    /network/{name}/containers → Lister les containers d'un réseau
POST   /network/{name}/remove     → Supprimer un réseau
POST   /network/remove_all        → Supprimer tous les réseaux simatk
POST   /network/{name}/connect    → Connecter un container à un réseau
POST   /network/{name}/disconnect → Déconnecter un container d'un réseau
POST   /network/move              → Déplacer un container d'un réseau à un autre
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import asyncio
import docker
from fastapi import APIRouter, HTTPException, status, Request
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.api.models.sim_models import (
    NetworkCreateRequest,
    NetworkConnectRequest,
    NetworkDisconnectRequest,
    NetworkMoveRequest,
    NetworkListResponse,
    NetworkInfo,
    NetworkCreateResponse,
    NetworkContainersResponse,
    NetworkContainerInfo,
    NetworkRemoveResponse,
    NetworkRemoveAllResponse,
    NetworkConnectResponse,
    NetworkDisconnectResponse,
    NetworkMoveResponse,
)

logger = get_logger()


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup task
# ─────────────────────────────────────────────────────────────────────────────

_cleanup_task: Optional[asyncio.Task] = None
_INACTIVE_TIMEOUT = 600  # 10 minutes


async def _cleanup_empty_networks_loop():
    """
    Tâche de fond : supprime les réseaux simatk qui n'ont plus de containers
    depuis plus de N minutes.
    """
    while True:
        try:
            await asyncio.sleep(120)
            dm = DockerManager()
            client = dm.client
            networks = client.networks.list(filters={"label": "simatk"})
            now = datetime.now(tz=timezone.utc)
            for net in networks:
                try:
                    net.reload()
                    containers = net.containers
                    if containers:
                        continue
                    created_str = net.attrs.get("Created", "")
                    if not created_str:
                        continue
                    try:
                        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        age = (now - created).total_seconds()
                    except Exception:
                        continue
                    if age > _INACTIVE_TIMEOUT:
                        logger.print(f"🧹 Suppression réseau vide inactif: {net.name} (age: {age/60:.1f}min)")
                        net.remove()
                except Exception as e:
                    logger.print(f"⚠️ Erreur cleanup réseau {net.name}: {e}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.print(f"⚠️ Erreur cleanup réseaux: {e}")


def start_network_cleanup():
    """Démarre la tâche de nettoyage des réseaux."""
    global _cleanup_task
    if _cleanup_task is None or _cleanup_task.done():
        _cleanup_task = asyncio.create_task(_cleanup_empty_networks_loop())
        logger.print("🧹 Tâche de nettoyage des réseaux démarrée")


async def stop_network_cleanup():
    """Arrête la tâche de nettoyage des réseaux."""
    global _cleanup_task
    if _cleanup_task and not _cleanup_task.done():
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
        logger.print("🧹 Tâche de nettoyage des réseaux arrêtée")


def remove_networks(networks: list[docker.models.networks.Network], force: bool = True):
    if not networks:
        return {
            "success": True,
            "total": 0,
            "removed": [],
            "failed": [],
            "message": "Aucun réseau simatk trouvé",
        }
    removed = []
    failed = []
    for net in networks:
        try:
            containers = net.containers
            if containers:
                if force:
                    for container in containers:
                        try:
                            container.stop()
                            container.remove(force=True)
                        except Exception:
                            pass
                else:
                    failed.append({
                        "name": net.name,
                        "reason": f"Contient encore {len(net.containers)} container(s)",
                    })
                    continue
            net.remove()
            removed.append(net.name)
            logger.print(f"✅ Réseau {net.name} supprimé")
            
        except Exception as e:
            failed.append({
                "name": net.name,
                "reason": str(e),
            })
    return {
        "success": len(failed) == 0,
        "total": len(networks),
        "removed": removed,
        "failed": failed,
        "message": f"{len(removed)} réseau(x) supprimé(s), {len(failed)} échec(s)",
    }

def remove_all_networks(client, force: bool = False) -> dict:
    """Supprime tous les réseaux simatk."""
    try:
        networks = client.networks.list(filters={"label": "simatk"})
    except Exception as e:
        return {
            "success": False,
            "total": 0,
            "removed": [],
            "failed": [{"error": str(e)}],
            "message": f"Erreur Docker: {e}",
        }
    return remove_networks(networks, force)

def remove_ephemeral_networks(client, force: bool = True) -> dict:
    """
    Nettoyage auto au shutdown : supprime UNIQUEMENT les réseaux liés à une
    sim (simatk.owner commence par 'sim:'). Les réseaux créés à la main par
    l'user via /network/create (simatk.owner='user') sont préservés.
    """
    try:
        networks = client.networks.list(filters={"label": "simatk"})
    except Exception as e:
        return {"success": False, "total": 0, "removed": [], "failed": [{"error": str(e)}]}

    targets = [
        n for n in networks
        if n.attrs.get("Labels", {}).get("simatk.owner", "").startswith("sim:")
    ]

    return remove_networks(targets, force)

# ─────────────────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────────────────

def make_network_router() -> APIRouter:
    router = APIRouter()
    dm = DockerManager()
    client = dm.client

    # ─── GET /list ──────────────────────────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/list",
        response_model=NetworkListResponse,
        summary="Lister les réseaux Docker",
        description="Retourne la liste de tous les réseaux Docker (filtre simatk optionnel).",
    )
    async def list_networks(request: Request, only_simatk: bool = False):
        try:
            if only_simatk:
                networks = client.networks.list(filters={"label": "simatk"})
            else:
                networks = client.networks.list()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur Docker: {e}",
            )

        result = []
        for net in networks:
            containers = net.containers
            subnet = None
            ipam_config = net.attrs.get("IPAM", {}).get("Config", [{}])
            if ipam_config:
                subnet = ipam_config[0].get("Subnet")
            result.append(NetworkInfo(
                name=net.name,
                id=net.id,
                short_id=net.short_id,
                driver=net.attrs.get("Driver", "bridge"),
                subnet=subnet,
                internal=net.attrs.get("Internal", False),
                containers_count=len(containers),
                labels=net.attrs.get("Labels", {}),
                created=net.attrs.get("Created", ""),
            ))

        return {"total": len(result), "networks": result}

    # ─── POST /create ──────────────────────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/create",
        response_model=NetworkCreateResponse,
        summary="Créer un réseau Docker",
        description="Crée un réseau Docker personnalisé.",
    )
    async def create_network(request: Request, data: NetworkCreateRequest):
        try:
            existing = client.networks.get(data.name)
            err = f"Réseau '{data.name}' existe déjà"
            return {
                "success": False,
                "network": {
                    "name": existing.name,
                    "id": existing.id,
                },
                "message": err,
                "error": err,
            }
        except docker.errors.NotFound:
            pass
        
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur Docker: {e}",
            )
    
        # if data.subnet and not data.is_subnet_valid():
        #     err = f"Format de subnet invalide : '{data.subnet}' (exemple valide : 172.30.0.0/24)"
        #     return {
        #         "success": False,
        #         "network": {},
        #         "message": err,
        #         "error": err,
        #     }
    
        try:
            ipam = None
            # if data.subnet:
            #     ipam = docker.types.IPAMConfig(
            #         pool_configs=[docker.types.IPAMPool(subnet=data.subnet)]
            #     )
            labels = data.labels or {}
            labels["simatk"] = "true"
            labels["simatk.owner"] = "user"  
            labels["simatk.created"] = datetime.now(tz=timezone.utc).isoformat()
            network = client.networks.create(
                data.name,
                driver=data.driver or "bridge",
                ipam=ipam,
                internal=data.internal or False,
                labels=labels,
            )
            return {
                "success": True,
                "network": {
                    "name": network.name,
                    "id": network.id,
                    "short_id": network.short_id,
                    "driver": network.attrs.get("Driver", "bridge"),
                    "subnet": data.subnet,
                    "internal": data.internal or False,
                },
                "message": f"Réseau '{data.name}' créé avec succès",
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur création réseau: {e}",
            )

    # ─── GET /{network_name}/containers ────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/{network_name}/containers",
        response_model=NetworkContainersResponse,
        summary="Lister les containers d'un réseau",
    )
    async def list_network_containers(request: Request, network_name: str):
        try:
            network = client.networks.get(network_name)
            
        except docker.errors.NotFound:
            return {
                "network": network_name,
                "network_id": "",
                "total": 0,
                "containers": [],
                "message": f"Réseau '{network_name}' introuvable",
            }
        
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur Docker: {e}",
            )

        containers_info: List[NetworkContainerInfo] = []
        for container in network.containers:
            ip = None
            try:
                ip = dm.get_ip(network=network_name, container=container)
            except Exception:
                pass
            try:
                containers_info.append(NetworkContainerInfo(
                    id=container.id,
                    name=container.name,
                    status=container.status,
                    image=container.image.tags[0] if container.image and container.image.tags else "<none>",
                    ip=ip,
                    labels=container.labels or {},
                    created=container.attrs.get("Created", ""),
                    is_simatk=container.labels.get("simatk") == "true" or "simatk_" in container.name,
                    message=None
                ))
            except Exception as e:
                containers_info.append(NetworkContainerInfo(
                    id=container.id,
                    name=container.name,
                    status="unknown",
                    image="unknown",
                    ip=ip,
                    labels={},
                    created="",
                    is_simatk=False,
                    message=str(e)
                ))

        containers_info.sort(key=lambda x: x.name)
        return {
            "network": network_name,
            "network_id": network.id,
            "total": len(containers_info),
            "containers": [c.model_dump() for c in containers_info],
        }

    # ─── POST /{network_name}/remove ──────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{network_name}/remove",
        response_model=NetworkRemoveResponse,
        summary="Supprimer un réseau",
    )
    async def remove_network(request: Request, network_name: str, force: bool = False):
        try:
            network = client.networks.get(network_name)
            
        except docker.errors.NotFound:
            return {
                "success": False,
                "network": network_name,
                "message": f"Réseau '{network_name}' introuvable",
            }
        
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur Docker: {e}",
            )
        
        labels = network.attrs.get("Labels") or {}
        owner = labels.get("simatk.owner", "")
        
        if owner != "user":
            return {
                "success": False,
                "network": network_name,
                "message": f"Réseau '{network_name}' n'appartient pas à l'utilisateur",
            }
    
        containers = network.containers
        removed_containers = []
        failed_containers = []
        if containers:
            if force:
                logger.print(f"🧹 Suppression de {len(containers)} container(s) sur {network_name}")
                for container in containers:
                    try:
                        container_name = container.name
                        container.stop()
                        container.remove(force=True)
                        removed_containers.append(container_name)
                        logger.print(f"  ✅ Container {container_name} supprimé")
                    except Exception as e:
                        failed_containers.append({
                            "id": container.id,
                            "name": container.name,
                            "message": str(e),
                        })
            else:
                container_names = [c.name for c in containers]
                return {
                    "success": False,
                    "network": network_name,
                    "message": f"Le réseau a {len(containers)} container(s). Utilisez force=true.",
                    "containers": container_names,
                }

        try:
            network.remove()
            if failed_containers:
                return {
                    "success": True,
                    "removed_containers": removed_containers,
                    "failed_containers": failed_containers,
                    "network": network_name,
                    "message": f"Réseau '{network_name}' supprimé mais certains containers n'ont pas pu être supprimés",
                }
            
            return {
                "success": True,
                "network": network_name,
                "message": f"Réseau '{network_name}' supprimé",
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur suppression réseau: {e}",
            )

    # ─── POST /remove_all ──────────────────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/remove_all",
        response_model=NetworkRemoveAllResponse,
        summary="Supprimer tous les réseaux simatk",
    )
    async def remove_all_networks_route(request: Request, force: bool = False):
        return remove_all_networks(client, force)

    # ─── POST /{network_name}/connect ──────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{network_name}/connect",
        response_model=NetworkConnectResponse,
        summary="Connecter un container à un réseau",
    )
    async def connect_container(request: Request, network_name: str, data: NetworkConnectRequest):
        try:
            network = client.networks.get(network_name)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "ip": None,
                "message": f"Réseau '{network_name}' introuvable",
            }

        try:
            container = client.containers.get(data.container_name)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "ip": None,
                "message": f"Container '{data.container_name}' introuvable",
            }

        existing_networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        if network_name in existing_networks:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "ip": None,
                "message": f"Container déjà connecté à '{network_name}'",
            }

        try:
            network.connect(container)

            ip = None
            try:
                container.reload()
                ip = dm.get_ip(network=network_name, container=container)
            except Exception:
                pass

            return {
                "success": True,
                "container": data.container_name,
                "network": network_name,
                "ip": ip or data.ip,
                "message": f"Container connecté au réseau '{network_name}'",
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur connexion: {e}",
            )

    # ─── POST /{network_name}/disconnect ───────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{network_name}/disconnect",
        response_model=NetworkDisconnectResponse,
        summary="Déconnecter un container d'un réseau",
    )
    async def disconnect_container(request: Request, network_name: str, data: NetworkDisconnectRequest):
        try:
            network = client.networks.get(network_name)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "force": data.force,
                "remaining_networks": [],
                "message": f"Réseau '{network_name}' introuvable",
            }

        try:
            container = client.containers.get(data.container_name)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "force": data.force,
                "remaining_networks": [],
                "message": f"Container '{data.container_name}' introuvable",
            }

        existing_networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        if network_name not in existing_networks:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "force": data.force,
                "remaining_networks": list(existing_networks.keys()),
                "message": f"Container non connecté à '{network_name}'",
            }

        if len(existing_networks) == 1 and not data.force:
            return {
                "success": False,
                "container": data.container_name,
                "network": network_name,
                "force": data.force,
                "remaining_networks": list(existing_networks.keys()),
                "message": "Dernier réseau, utilisez force=true pour forcer.",
            }

        try:
            network.disconnect(container, force=data.force)
            container.reload()
            remaining = list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
            return {
                "success": True,
                "container": data.container_name,
                "network": network_name,
                "force": data.force,
                "remaining_networks": remaining,
                "message": f"Container déconnecté de '{network_name}'",
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur déconnexion: {e}",
            )

    # ─── POST /move ─────────────────────────────────────────────────────────
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/move",
        response_model=NetworkMoveResponse,
        summary="Déplacer un container d'un réseau à un autre",
    )
    async def move_container(request: Request, data: NetworkMoveRequest):
        # Vérifier le container
        try:
            container = client.containers.get(data.container_name)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": [],
                "message": f"Container '{data.container_name}' introuvable",
            }

        # Vérifier le réseau source
        try:
            source = client.networks.get(data.source_network)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": [],
                "message": f"Réseau source '{data.source_network}' introuvable",
            }

        # Vérifier le réseau destination
        try:
            dest = client.networks.get(data.destination_network)
        except docker.errors.NotFound:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": [],
                "message": f"Réseau destination '{data.destination_network}' introuvable",
            }

        existing_networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        if data.source_network not in existing_networks:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": list(existing_networks.keys()),
                "message": f"Container non connecté au réseau source '{data.source_network}'",
            }

        if data.destination_network in existing_networks:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": list(existing_networks.keys()),
                "message": f"Container déjà connecté au réseau destination '{data.destination_network}'",
            }

        if len(existing_networks) == 1 and not data.force:
            return {
                "success": False,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": None,
                "networks": list(existing_networks.keys()),
                "message": "Dernier réseau, utilisez force=true.",
            }

        try:
            source.disconnect(container, force=data.force)
            dest.connect(container)
            container.reload()
            new_networks = list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
            ip = None
            try:
                ip = dm.get_ip(network=data.destination_network, container=container)
            except Exception:
                pass

            return {
                "success": True,
                "container": data.container_name,
                "source_network": data.source_network,
                "destination_network": data.destination_network,
                "ip": ip or data.ip,
                "aliases": data.aliases or [],
                "networks": new_networks,
                "message": f"Container déplacé de '{data.source_network}' vers '{data.destination_network}'",
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur déplacement: {e}",
            )

    return router


# ── Export ─────────────────────────────────────────────────────────────────
network_router = make_network_router()
network_router_noauth = make_network_router()