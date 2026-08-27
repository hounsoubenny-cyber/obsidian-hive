#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 15:18:58 2026

@author: hounsousamuel
"""

"""
Router /containers – gestion des containers Docker.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import asyncio
import docker
from fastapi import APIRouter, HTTPException, status, Request
from typing import Optional, List

from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE
from simulateur_attaque_ia.core.docker_manager import DockerManager
from simulateur_attaque_ia.core.containers_manager import ContainerManager
from simulateur_attaque_ia.simulateur_utils.logger import get_logger
from simulateur_attaque_ia.api.models.sim_models import (
    ContainerListResponse, ContainerCreateRequest,
    ContainerCreateResponse, ContainerExecRequest,
    ContainerExecResponse, ContainerStopResponse,
    CacheListResponse,
)

logger = get_logger()


def make_containers_router() -> APIRouter:
    router = APIRouter()
    dm = DockerManager()
    cm = ContainerManager.get_instance()
    
    # ─── GET /list ──────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/list",
        summary="Lister les containers Docker",
        response_model=ContainerListResponse,
    )
    async def list_containers(
        request: Request,
        running: bool | None = None,
        label: Optional[str] = None,
    ) -> ContainerListResponse:
        filters = {}
        if running is not None:
            filters["status"] = "running"
        if label:
            filters["label"] = label

        containers = dm.list_containers(all=True, filters=filters)

        return ContainerListResponse(
            total=len(containers),
            containers=containers,
            filters=filters,
        )
    
    # ─── GET /list_my_own ──────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/list_my_own",
        summary="Lister les containers Docker",
        response_model=ContainerListResponse,
    )
    async def list_my_own_containers(
        request: Request,
        running: bool | None = None,
        label: Optional[str] = None,
    ) -> ContainerListResponse:
        return await list_containers(
            request=request,
            label="simatk.owner=user"
        )
    
    # ─── POST /create ──────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/create",
        summary="Créer ou réutiliser un container",
        response_model=ContainerCreateResponse,
    )
    async def create_container(
        request: Request,
        data: ContainerCreateRequest,
    ) -> ContainerCreateResponse:
        try:
            dm.client.images.get(data.image)
        except Exception:
            return ContainerCreateResponse(
                success=False,
                container={},
                message=f"Image '{data.image}' introuvable",
            )
        
        
        predefined = {"bridge", "none", "host", "isolated"}
        if data.network not in predefined:
            try:
                dm.client.networks.get(data.network)
                
            except (docker.errors.NotFound, docker.errors.APIError):
                return ContainerCreateResponse(
                    success=False,
                    container={},
                    message=(
                        f"Réseau '{data.network}' introuvable. "
                        f"Réseaux prédéfinis : bridge, none, host. "
                        f"Ou créez-le avec 'docker network create {data.network}'"
                    ),
                )
            
            except Exception as e:
                return ContainerCreateResponse(
                    success=False,
                    container={},
                    message=f"Erreur vérification réseau : {e}",
                )
        
        labels = dict(data.labels or {})
        labels.setdefault("simatk", "true")
        labels.setdefault("simatk.owner", "user")
        kwargs = {}
        if data.network:
            kwargs["network"] = data.network
        if data.cap_add:
            kwargs["cap_add"] = data.cap_add
        if data.ports:
            kwargs["ports"] = data.ports
        if data.environment:
            kwargs["environment"] = data.environment
        if data.command:
            kwargs["command"] = data.command
        kwargs["labels"] = labels

        try:
            container_manager = await asyncio.to_thread(
                cm.get_or_create_container,
                image=data.image,
                name=data.name,
                **kwargs
            )
        except Exception as e:
            return ContainerCreateResponse(
                success=False,
                container={},
                message=f"Erreur création: {e}",
            )

        # Récupérer l'IP
        ip = None
        try:
            ip = container_manager.get_ip(network=data.network, container=None)
        except Exception:
            pass

        return ContainerCreateResponse(
            success=True,
            container={
                "name": container_manager.container.name,
                "image": data.image,
                "status": container_manager.container.status,
                "ip": ip,
                "created": container_manager.container.attrs.get("Created", ""),
            },
            message=f"Container '{container_manager.container.name}' prêt",
        )
    
    # ─── POST /{name}/stop ────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{name}/stop",
        summary="Arrêter un container",
        response_model=ContainerStopResponse,
    )
    async def stop_container(
        request: Request,
        name: str,
    ) -> ContainerStopResponse:
        try:
            container = dm.client.containers.get(name)
            labels = container.labels or {}
            owner = labels.get("simatk.owner", "")
            
            if owner != "user":
                return ContainerStopResponse(
                    success=False,
                    container=name,
                    message=f"Container '{name}' n'appartient pas à l'utilisateur",
                )
        except docker.errors.NotFound:
            return ContainerStopResponse(
                success=False,
                container=name,
                message=f"Container '{name}' introuvable",
            )
    
        ok = await cm.stop_container(name)
        if not ok:
            return ContainerStopResponse(
                success=False,
                container=name,
                message=f"Container '{name}' introuvable.",
            )

        return ContainerStopResponse(
            success=True,
            container=name,
            message=f"Container '{name}' arrêté et supprimé",
        )
    
    # ─── POST /{name}/exec ────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{name}/exec",
        summary="Exécuter une commande dans un container",
        response_model=ContainerExecResponse,
    )
    async def exec_command(
        request: Request,
        name: str,
        data: ContainerExecRequest,
    ) -> ContainerExecResponse:
        
        try:
            container = dm.client.containers.get(name)
            labels = container.labels or {}
            owner = labels.get("simatk.owner", "")
            print("owner: ", owner, labels)
            if owner != "user":
                print("Return ?")
                return ContainerExecResponse(
                    success=False,
                    command=data.command,
                    stderr=None,
                    stdout=None,
                    exit_code=1,
                    message=f"Container '{name}' n'appartient pas à l'utilisateur",
                )
        except docker.errors.NotFound:
            return ContainerExecResponse(
                success=False,
                container=name,
                command=data.command,
                stdout=None,
                stderr=None,
                exit_code=1,
                message=f"Container '{name}' introuvable",
            )
        
        try:
            print("Try exec", name, data.command)
            result = await cm.exec_command(name, data.command)
            print("Exec: ", result)
            return ContainerExecResponse(
                success=True,
                container=name,
                command=data.command,
                stdout=result.get("stdout"),
                stderr=result.get("stderr"),
                exit_code=result.get("exit_code", 0),
                message=None,
            )
        except ValueError as e:
            return ContainerExecResponse(
                success=False,
                container=name,
                command=data.command,
                stdout=None,
                stderr=None,
                exit_code=1,
                message=str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur exécution: {e}",
            )
    
    # ─── GET /cache ────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/cache",
        summary="Lister les containers en cache",
        response_model=CacheListResponse,
    )
    async def list_cached_containers(
        request: Request,
    ) -> CacheListResponse:
        containers = cm.list_containers()
        return CacheListResponse(
            total=len(containers),
            containers=containers,
        )
    
    return router


# ── Export ─────────────────────────────────────────────────────────────────
containers_router = make_containers_router()
containers_router_noauth = make_containers_router()