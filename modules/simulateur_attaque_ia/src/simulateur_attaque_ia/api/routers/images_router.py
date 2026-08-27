#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import asyncio
from fastapi import APIRouter, HTTPException, status
from simulateur_attaque_ia.core.docker_manager import DockerManager

def make_images_router() -> APIRouter:
    router = APIRouter()

    @router.get(
        "/list",
        summary="Lister les images Docker locales",
        description="Retourne la liste des images disponibles localement "
                    "via DockerManager.list_images().",
    )
    async def list_images() -> dict:
        try:
            dm = DockerManager()
            images = await asyncio.to_thread(dm.list_images)
            return {"images": images}   
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur Docker : {exc}",
            )

    return router


images_router = make_images_router()
images_router_noauth = make_images_router()
