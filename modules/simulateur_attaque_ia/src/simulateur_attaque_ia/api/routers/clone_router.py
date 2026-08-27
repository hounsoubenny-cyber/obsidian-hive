#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""


"""
Router /clone – clonage du système host dans un container Docker.

POST /clone/start    → lance le clonage (CopyManager.clone())
GET  /clone/{id}/status → état du clonage en cours
POST  /clone/{id}/stop → arrête la tâche de clonage
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, status, Request

from simulateur_attaque_ia.api.models.sim_models import CloneRequest, CloneStatusResponse
from simulateur_attaque_ia.simulateur_utils.limiter import limiter
from simulateur_attaque_ia.configs.config import LIMITE, CLONE_KEEP_DELAY
from simulateur_attaque_ia.core.cloner import CopyManager

# ── State en mémoire des clones en cours ────────────────────────────────────

_clones: Dict[str, dict] = {}
_clone_tasks: Dict[str, asyncio.Task] = {}
_cleanup_clone_task: Optional[asyncio.Task] = None

# ── Cleanup RAM ───────────────────────────────────────────────────────────────

async def _cleanup_old_clones_loop():
    """Purge les clones completed/failed après CLONE_KEEP_DELAY secondes."""
    while True:
        try:
            await asyncio.sleep(60)  # vérifie chaque minute
            now = datetime.now(tz=timezone.utc)
            to_delete = [
                cid for cid, entry in list(_clones.items())
                if entry["status"] in ("completed", "failed", "stopped")
                and entry.get("ended_at")
                and (now - datetime.fromisoformat(entry["ended_at"])).total_seconds() > CLONE_KEEP_DELAY
            ]
            for cid in to_delete:
                _clones.pop(cid, None)
                _clone_tasks.pop(cid, None)
        except asyncio.CancelledError:
            break
        except Exception:
            pass

async def start_clone_cleanup() -> asyncio.Task:
    global _cleanup_clone_task
    _cleanup_clone_task = asyncio.create_task(_cleanup_old_clones_loop())
    return _cleanup_clone_task

async def stop_clone_cleanup():
    if _cleanup_clone_task and not _cleanup_clone_task.done():
        _cleanup_clone_task.cancel()
        try:
            await _cleanup_clone_task
        except asyncio.CancelledError:
            pass
        
async def _do_clone(clone_id: str, data: CloneRequest):
    try:
        manager = CopyManager()
        result = await asyncio.to_thread(
            manager.clone,
            src=data.src,
            dest=data.dest,
            archive_path=data.archive_path,
            remove_back_up=data.remove_back_up,
            container_name=data.container_name,
            network_caps=data.network_caps,
            authorize_network=data.authorize_network,
        )

        if _clones.get(clone_id, {}).get("status") == "stopped":
            return

        if not result or not isinstance(result, dict) or not result.get("success"):
            error = result.get("error") if isinstance(result, dict) else "archive_path introuvable ou clonage échoué"
            _clones[clone_id].update({
                "status": "failed",
                "ended_at": datetime.now(tz=timezone.utc).isoformat(),
                "error": error,
            })
            return

        _clones[clone_id].update({
            "status":   "completed",
            "ended_at": datetime.now(tz=timezone.utc).isoformat(),
            "image":    result["container_name"],
            "services": result.get("services"),
        })

    except asyncio.CancelledError:
        pass
    
    except Exception as exc:
        if _clones.get(clone_id, {}).get("status") != "stopped":
            _clones[clone_id].update({
                "status": "failed",
                "ended_at": datetime.now(tz=timezone.utc).isoformat(),
                "error": str(exc),
            })
         
def make_clone_router() -> APIRouter:
    router = APIRouter()

    # ── POST /start ───────────────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/start",
        summary="Lancer un clonage système",
        description="""
Clone le système host (ou une archive existante) dans un container Docker.

- **src** : répertoire source à copier (défaut : `/` sur Linux).
- **dest** : où stocker l'archive tar.gz temporaire.
- **archive_path** : si un tar.gz existe déjà → skip la copie, utilise directement.
- **remove_back_up** : supprime l'archive après import Docker.
- **container_name** : nom du container (auto-généré si absent).
- **network_caps** : ajoute `NET_RAW` et `NET_ADMIN` au container.
- **authorize_network** : si `false` → `--network=isolated`.

Le clonage génère aussi automatiquement un `services.json` via
`ServiceManager.capture_services()`.
""",
    )
    async def start_clone(
        request: Request,
        data: CloneRequest
    ) -> dict:
        clone_id = f"clone_{uuid.uuid4().hex[:8]}"
        _clones[clone_id] = {
            "clone_id":   clone_id,
            "status":     "running",
            "started_at": datetime.now(tz=timezone.utc).isoformat(),
            "ended_at":   None,
            "image":      None,
            "services":   None,
            "error":      None,
        }

        task = asyncio.create_task(_do_clone(clone_id, data))
        _clone_tasks[clone_id] = task
        return {
            "clone_id": clone_id,
            "status":   "running",
            "message":  "Clonage lancé en arrière-plan. Suivez avec GET /clone/{clone_id}/status.",
        }

    # ── GET /{clone_id}/status ────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.get(
        "/{clone_id}/status",
        response_model=CloneStatusResponse,
        summary="Status d'un clonage",
    )
    async def clone_status(
        request: Request,
        clone_id: str
    ) -> dict:
        entry = _clones.get(clone_id)
        if entry is None:
            return CloneStatusResponse(
                clone_id=clone_id,
                status="not_found",
                message=f"Clone '{clone_id}' introuvable ou déjà purgé.",
            )
        return entry
    
    # ── POST /{clone_id}/stop ────────────────────────────────────────────────
    
    @limiter.limit(f"{LIMITE}/minute")
    @router.post(
        "/{clone_id}/stop",
        summary="Arrêter un clonage en cours",
        description=(
            "Marque le clone comme arrêté et annule la task asyncio. "
            "⚠️ Le thread sous-jacent (copie fichiers / docker import) peut "
            "continuer brièvement en background — son résultat sera ignoré."
        ),
    )
    async def stop_clone(request: Request, clone_id: str) -> dict:
        entry = _clones.get(clone_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"Clone '{clone_id}' introuvable.")
    
        if entry["status"] != "running":
            raise HTTPException(
                status_code=409,
                detail=f"Clone déjà terminé avec statut '{entry['status']}'."
            )
    
        _clones[clone_id]["status"]   = "stopped"
        _clones[clone_id]["ended_at"] = datetime.now(tz=timezone.utc).isoformat()
    
        task = _clone_tasks.get(clone_id)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
    
        _clone_tasks.pop(clone_id, None)
        return {
            "clone_id": clone_id,
            "status":   "stopped",
            "message":  "Clone arrêté. Le thread OS sous-jacent se terminera naturellement.",
        }

    return router


clone_router = make_clone_router()
clone_router_noauth = make_clone_router()
