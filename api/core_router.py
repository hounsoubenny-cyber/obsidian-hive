#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 23:28:10 2026

@author: hounsousamuel
"""

"""
core_router.py

Extrait de l'ancien core_router.py monolithique (split HTTP / WS / shared,
août 2026). Ne contient plus QUE les routes HTTP (router + router_no_auth) :
CRUD d'assets, server assets, et l'endpoint Alex non-streamé (batch).

Le canal WebSocket multiplexé (chat Coralie, analyse Alex, confirmations
humaines, server agent) vit maintenant dans core_ws_router.py.
Les singletons et helpers partagés vivent dans core_shared.py.
"""

import asyncio

from fastapi import HTTPException, APIRouter, status, Request

from obsidian_hive.core.assets.asset_types import list_agent_capabilities
from obsidian_hive.api.models import (
    WebAssetModel, NetworkAssetModel, ListAssetData, GetAssetData, RemoveAssetData,
    ResumeAssetData, PauseAssetData, UpdateAssetData, SyncSourceCodeData,
    AlexAnalyzeData, SearchAssetData, ServerAgentRegisterData, ServerAgentRevokeData,
    ServerAssetModel, ServerToolsData, ServerCapabilitiesData,
    PauseAssetsData, ResumeAssetsData, RotateSecretData, ReactivateServerAssetData
)
from scanner_ia.api.api import _resolve_helpers
from obsidian_hive.agents.analyst.agent import (
    Analyst, AnalystResult,
    NoReportProducedError, create_alex
)
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE
from modules_utils.keyed_lock import resource_lock
from obsidian_hive.core.assets.asset_types import AssetItem
from obsidian_hive.core.assets.server_asset.tools.tools import (
    tool_exists as server_tool_exists,
    list_tools as server_list_tools
)
from modules_utils.cryto_utils import hashpw

from obsidian_hive.api.core_shared import (
    get_engine,
    get_server_agent_ws_manager,
    handle_web_asset_creating,
    handle_network_asset_creating,
    handle_server_asset_creating,
    register_server_agent,
    revoke_server_asset,
    add_asset,
    _server_error,
    _update_server_asset_field,
)
from obsidian_hive.core.assets.asset_types import ServerAsset

router = APIRouter()

router_no_auth = APIRouter()

# =============================================================================
# Routes
# =============================================================================

# =============================================================================
# Asset management
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/asset/create/web_asset")
async def add_web_asset(request: Request, asset_data: WebAssetModel):
    """
    Crée un nouvel asset web (site ou application web).

    Args:
        request (Request): La requête FastAPI.
        asset_data (WebAssetModel): Les données de l'asset web.

    Returns:
        dict: Résultat de la création avec les détails de l'asset.
    """
    try:
        _resolve_helpers(asset_data.scan_args.helpers)
        asset = handle_web_asset_creating(asset_data)
        return await add_asset(asset, asset_data)
    except HTTPException:
        raise

    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/asset/create/network_asset")
async def add_network_asset(request: Request, asset_data: NetworkAssetModel):
    """
    Crée un nouvel asset réseau (IDS/IPS).

    Args:
        request (Request): La requête FastAPI.
        asset_data (NetworkAssetModel): Les données de l'asset réseau.

    Returns:
        dict: Résultat de la création avec les détails de l'asset.
    """
    try:
       asset = handle_network_asset_creating(asset_data)
       return await add_asset(asset, asset_data)

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/asset/create/server_asset")
async def create_server_asset_route(request: Request, asset_data: ServerAssetModel):
    """
    Crée un nouvel asset serveur (avec agent).

    Args:
        request (Request): La requête FastAPI.
        asset_data (ServerAssetModel): Les données de l'asset serveur.

    Returns:
        dict: Résultat de la création avec la commande d'installation.
    """
    try:
        asset = handle_server_asset_creating(asset_data)
        result = await add_asset(asset, asset_data)
        if result["status"] != "error":
            token = result["asset_data"]["install_token"]
            result["install_command"] = (
                f'curl -sSL -H "Authorization: Bearer {token}" https://host/api/download/agent/install.sh | bash'
            )
        return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/list")
async def list_assets(request: Request, options: ListAssetData):
    """
    Liste les assets avec filtrage optionnel.

    Args:
        request (Request): La requête FastAPI.
        options (ListAssetData): Options de filtrage (status, type, priority, tags).

    Returns:
        dict: Liste des assets correspondants.
    """
    try:
        engine = get_engine()
        assets_db = await engine.asset_manager.list_by_filter(**options.model_dump())
        return {
            "assets": [
                engine.asset_manager.asset_item_db_to_asset_item(a).model_dump(mode="json")
                for a in assets_db
            ]
        }

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/get_asset")
async def get_asset(request: Request, options: GetAssetData):
    """
    Récupère un ou plusieurs assets par identifiant.

    Args:
        request (Request): La requête FastAPI.
        options (GetAssetData): Options de recherche (identifier, include_name, first).

    Returns:
        dict: Liste des assets trouvés.
    """
    try:
        engine = get_engine()
        asset_db = await engine.asset_manager.get_by_identifier(
            **options.model_dump()
        )
        if asset_db is None:
            return {"assets": None}
        assets_db = asset_db if isinstance(asset_db, list) else [asset_db]
        return {
            "assets": [
                engine.asset_manager.asset_item_db_to_asset_item(a).model_dump(mode="json")
                for a in assets_db
            ]
        }

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)

@limiter.limit(f"{LIMITE}/minute")
@router.get("/assets/list_network_endpoints")
async def list_network_endpoints(request: Request):
    """Retourne les endpoints joignables de tous les NetworkAsset actifs.

    Utilisé par le frontend pour découvrir dynamiquement l'host:port de
    chaque IDS/IPS actif et s'y connecter directement (modèle gateway).

    Args:
        request (Request): La requête FastAPI (utilisée par le rate limiter).

    Returns:
        dict: Dictionnaire {asset_id: {host, port, is_open}}.

    Raises:
        HTTPException: 500 en cas d'erreur serveur.
    """
    try:
        return await get_engine().asset_manager.get_all_url_of_network_asset()

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)
        
@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/search")
async def search_asset(request: Request, options: SearchAssetData):
    """
    Recherche un ou plusieurs assets par identifiant et/ou nom.

    Cette route combine les fonctionnalités de get_by_identifier et get_asset_by_name
    dans une seule recherche unifiée.

    Args:
        request (Request): La requête FastAPI.
        options (SearchAssetData): Paramètres de recherche.

    Returns:
        dict: {
            "assets": list[AssetItem] | None,
            "total": int,
            "query": str,
            "params": dict
        }
    """
    try:
        engine = get_engine()
        asset_manager = engine.asset_manager

        results = await asset_manager.search_asset(
            query=options.query,
            include_name=options.include_name,
            case_sensitive=options.case_sensitive,
            partial=options.partial,
            first=options.first,
            limit=options.limit
        )

        if options.first:
            assets = [results] if results else []
            total = 1 if results else 0
        else:
            assets = results or []
            total = len(assets)

        assets_data = [
            engine.asset_manager.asset_item_db_to_asset_item(a).model_dump(mode="json")
            for a in assets
        ]

        return {
            "assets": assets_data,
            "total": total,
            "query": options.query,
            "params": {
                "include_name": options.include_name,
                "case_sensitive": options.case_sensitive,
                "partial": options.partial,
                "first": options.first,
                "limit": options.limit
            }
        }

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/manage/delete")
async def delete_asset(request: Request, options: RemoveAssetData):
    """
    Supprime un asset (irréversible).

    Args:
        request (Request): La requête FastAPI.
        options (RemoveAssetData): Données de suppression.

    Returns:
        dict: Résultat de la suppression.
    """
    try:
        engine = get_engine()
        async with resource_lock.acquire(f"asset:{options.asset_id}"):
            asset_manager = engine.asset_manager
            asset = await asset_manager.get_by_identifier(options.asset_id, first=True)
            if not asset:
                return {"status": "error", "error": "Asset introuvable", "asset_id": options.asset_id}

            asset: AssetItem = asset_manager.asset_item_db_to_asset_item(asset)

            if not isinstance(asset, ServerAsset):
                return await engine.remove_asset(delete=True, asset_id=options.asset_id)

            server_agent_ws_manager = get_server_agent_ws_manager()
            conn = server_agent_ws_manager.get(options.asset_id)

            if not conn:
                asset.pending_deletion = True
                await asset_manager.upsert(asset)
                return {"status": "success", "pending_deletion": True}

            ack_event = server_agent_ws_manager.register_pending_ack(options.asset_id)
            sent = await conn.send({"type": "self_destruct"})

            if not sent:
                server_agent_ws_manager.clear_pending_ack(options.asset_id)
                asset.pending_deletion = True
                await asset_manager.upsert(asset)
                return {"status": "success", "pending_deletion": True}

            try:
                await asyncio.wait_for(ack_event.wait(), timeout=30)
                acked = True
            except asyncio.TimeoutError:
                acked = False

            finally:
                server_agent_ws_manager.clear_pending_ack(options.asset_id)

            result = await engine.remove_asset(delete=True, asset_id=options.asset_id)
            try:
                await conn.ws.close(code=1001, reason="self_destruct")
            except Exception:
                pass

            result["self_destruct_acked"] = acked
            return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/manage/pause")
async def pause_asset(request: Request, options: PauseAssetData):
    """
    Met un asset en pause (INACTIVE).

    Args:
        request (Request): La requête FastAPI.
        options (PauseAssetData): Données de mise en pause.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
       engine = get_engine()
       async with resource_lock.acquire(f"asset:{options.asset_id}"):
           result = await engine.pause_asset(
               asset_id=options.asset_id
           )
       if result["status"] == "error":
           raise HTTPException(
               detail={"error": result["error"]},
               status_code=status.HTTP_404_NOT_FOUND
           )
       return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/manage/resume")
async def resume_asset(request: Request, options: ResumeAssetData):
    """
    Reprend un asset en pause (ACTIVE).

    Args:
        request (Request): La requête FastAPI.
        options (ResumeAssetData): Données de reprise.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        engine = get_engine()
        async with resource_lock.acquire(f"asset:{options.asset_id}"):
            result = await engine.resume_asset(
                asset_id=options.asset_id
            )
        if result["status"] == "error":
            raise HTTPException(
                detail={"error": result["error"]},
                status_code=status.HTTP_404_NOT_FOUND
            )
        return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/pause")
async def pause_assets_route(request: Request, data: PauseAssetsData):
    """
    Met en pause plusieurs assets.

    Args:
        request (Request): La requête FastAPI.
        data (PauseAssetsData): Filtres pour la mise en pause groupée.

    Returns:
        dict: Résultats par asset.
    """
    try:
        engine = get_engine()
        results = await engine.pause_assets(
            asset_type=data.asset_type,
            asset_ids=data.asset_ids,
            tags=data.tags,
            priority=data.priority
        )
        return {"status": "success", "results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/resume")
async def resume_assets_route(request: Request, data: ResumeAssetsData):
    """
    Reprend plusieurs assets.

    Args:
        request (Request): La requête FastAPI.
        data (ResumeAssetsData): Filtres pour la reprise groupée.

    Returns:
        dict: Résultats par asset.
    """
    try:
        engine = get_engine()
        results = await engine.resume_assets(
            asset_type=data.asset_type,
            asset_ids=data.asset_ids,
            tags=data.tags,
            priority=data.priority
        )
        return {"status": "success", "results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/manage/update")
async def update_asset(request: Request, options: UpdateAssetData):
    """
    Met à jour les attributs d'un asset.

    Args:
        request (Request): La requête FastAPI.
        options (UpdateAssetData): Données de mise à jour.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        engine = get_engine()
        get_asset_db_result = await get_asset(
            request,
            GetAssetData(**{
                "identifier": options.asset_id,
                "include_name": False,
            })
        )
        if not get_asset_db_result["assets"]:
            return {"status": "error", "error": "Asset non trouvé ou mise à jour échouée"}

        asset_db = get_asset_db_result["assets"][0]
        run_fields = asset_db.get("run_fields", [])
        restart_workflow = options.restart_workflow
        restart_workflow = restart_workflow or any(
            key in run_fields and asset_db.get(key) != value
            for key, value in (options.attrs or {}).items()
        )
        async with resource_lock.acquire(f"asset:{options.asset_id}"):
            result = await engine.update_asset(
                asset_id=options.asset_id,
                attrs=options.attrs or {},
                restart_workflow=restart_workflow
            )
        if result["status"] == "error":
            raise HTTPException(
                detail={"error": result["error"]},
                status_code=status.HTTP_404_NOT_FOUND
            )
        return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/manage/sync_source_code")
async def sync_source_code(request: Request, options: SyncSourceCodeData):
    """
    Synchronise le code source d'un asset web.

    Args:
        request (Request): La requête FastAPI.
        options (SyncSourceCodeData): Données de synchronisation.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        engine = get_engine()
        async with resource_lock.acquire(f"asset:{options.asset_id}"):
            result = await engine.sync_source_code(
                asset_id=options.asset_id,
                admin_source_code_dir=options.admin_source_code_dir,
            )
        if result["status"] == "error":
            raise HTTPException(
                detail={"error": result["error"]},
                status_code=status.HTTP_404_NOT_FOUND
            )
        return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


# =============================================================================
# Server asset
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router_no_auth.post("/assets/server_asset/register")
async def register_server_asset_route(request: Request, data: ServerAgentRegisterData):
    """
    Enregistre un agent serveur auprès du système.

    Route publique (sans authentification JWT) car utilisée par l'agent
    lors de son installation.

    Args:
        request (Request): La requête FastAPI.
        data (ServerAgentRegisterData): Données d'enregistrement.

    Returns:
        dict: Résultat de l'enregistrement avec le secret.
    """
    try:
        result = await register_server_agent(
            data=data
        )
        return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/revoke")
async def revoke_server_asset_route(request: Request, data: ServerAgentRevokeData):
    """
    Révoque un asset serveur (l'agent ne peut plus se connecter).

    Args:
        request (Request): La requête FastAPI.
        data (ServerAgentRevokeData): Données de révocation.

    Returns:
        dict: Résultat de la révocation.
    """
    try:
        async with resource_lock.acquire(f"asset:{data.asset_id}"):
            result = await revoke_server_asset(
                data=data
            )
            server_agent_ws_manager = get_server_agent_ws_manager()
            conn = server_agent_ws_manager.get(data.asset_id)
            has_send_revoke_msg = False
            if conn:
                try:
                    await conn.send({"type": "revoked"})
                    has_send_revoke_msg = True
                    await conn.ws.close(code=4001, reason="revoked")
                except Exception:
                    pass
                server_agent_ws_manager.pop(data.asset_id, conn)

            result["has_send_revoke_msg"] = has_send_revoke_msg
            return result

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/rotate-secret")
async def rotate_secret(request: Request, data: RotateSecretData):
    """
    Rotate le secret d'un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        data (RotateSecretData): Données de rotation.

    Returns:
        dict: Nouveau secret généré.
    """
    try:
        asset_manager = get_engine().asset_manager
        asset = await asset_manager.get_by_identifier(
            data.asset_id,
            first=True,
        )
        if not asset:
            return {"status": "error", "error": "Asset Introuvable !"}

        asset: ServerAsset = asset_manager.asset_item_db_to_asset_item(asset)
        if not isinstance(asset, ServerAsset):
            return {"status": "error", "error": "L'asset n'est pas un asset serveur !"}

        if asset.is_revoked():
            return {"status": "error", "error": "Asset révoké !"}

        new_secret = ServerAsset.generate_secret()
        new_hash = hashpw(ServerAsset.hash_secret_input(new_secret)).decode()
        asset.agent_credential_hash = new_hash
        await asset_manager.upsert(asset)

        server_agent_ws_manager = get_server_agent_ws_manager()
        conn = server_agent_ws_manager.get(data.asset_id)
        if conn:
            await conn.send({"type": "secret_rotated", "secret": new_secret})

        return {"status": "success", "secret": new_secret}

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/reactivate")
async def reactivate_server_asset(request: Request, data: ReactivateServerAssetData):
    """
    Réactive un asset serveur révoqué.

    Args:
        request (Request): La requête FastAPI.
        data (ReactivateServerAssetData): Données de réactivation.

    Returns:
        dict: Nouveau token d'installation.
    """
    try:
        asset_manager = get_engine().asset_manager
        asset = await asset_manager.get_by_identifier(data.asset_id, first=True)
        if not asset:
            return {"status": "error", "error": "Asset introuvable"}

        asset: ServerAsset = asset_manager.asset_item_db_to_asset_item(asset)
        if not isinstance(asset, ServerAsset):
            return {"status": "error", "error": "L'asset n'est pas un asset serveur !"}
        
        # if not asset.is_revoked():
        #     return {"status": "error", "error": "Asset non révoqué, réactivation inutile"}
        
        server_agent_ws_manager = get_server_agent_ws_manager()
        if server_agent_ws_manager.is_connected(asset.id):
            return {"status": "error", "error": "Agent actuellement connecté, réactivation impossible"}

        asset.generate_install_token()
        install_token = asset.install_token
        await asset_manager.upsert(asset)

        install_command = (
            f'curl -sSL -H "Authorization: Bearer {install_token}" '
            f'https://{request.url.hostname}/api/download/agent/reregister.sh | bash'
        )

        return {"status": "success", "install_token": install_token, "install_command": install_command}

    except HTTPException:
        raise

    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/capabilities/add")
async def add_server_capabilities_route(request: Request, data: ServerCapabilitiesData):
    """
    Ajoute des capacités à un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        data (ServerCapabilitiesData): Données des capacités.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        return await _update_server_asset_field(
            asset_id=data.asset_id,
            field="capabilities",
            values=data.capabilities,
            add=True
        )
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/capabilities/remove")
async def remove_server_capabilities_route(request: Request, data: ServerCapabilitiesData):
    """
    Supprime des capacités d'un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        data (ServerCapabilitiesData): Données des capacités.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        return await _update_server_asset_field(
            asset_id=data.asset_id,
            field="capabilities",
            values=data.capabilities,
            add=False
        )
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.get("/assets/server_asset/capabilities/list")
async def list_server_capabilities(request: Request):
    """
    Liste toutes les capacités disponibles pour les assets serveur.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        dict: Dictionnaire des capacités avec leurs descriptions.
    """
    try:
        return list_agent_capabilities()
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/tools/allow")
async def allow_server_tools_route(request: Request, data: ServerToolsData):
    """
    Autorise des outils sur un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        data (ServerToolsData): Données des outils.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        unknown = [t for t in data.tools if not server_tool_exists(t)]
        if unknown:
            return {"status": "error", "message": f"Tool(s) inconnu(s) : {', '.join(unknown)}"}

        return await _update_server_asset_field(
            asset_id=data.asset_id,
            field="allowed_tools",
            values=data.tools,
            add=True
        )
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/assets/server_asset/tools/revoke")
async def revoke_server_tools_route(request: Request, data: ServerToolsData):
    """
    Révoque l'autorisation d'outils sur un asset serveur.

    Args:
        request (Request): La requête FastAPI.
        data (ServerToolsData): Données des outils.

    Returns:
        dict: Résultat de l'opération.
    """
    try:
        unknown = [t for t in data.tools if not server_tool_exists(t)]
        if unknown:
            return {"status": "error", "message": f"Tool(s) inconnu(s) : {', '.join(unknown)}"}

        return await _update_server_asset_field(
            asset_id=data.asset_id,
            field="allowed_tools",
            values=data.tools,
            add=False
        )
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.get("/assets/server_asset/tools/list")
async def list_server_tools(request: Request):
    """
    Liste tous les outils disponibles pour les assets serveur.

    Args:
        request (Request): La requête FastAPI.

    Returns:
        dict: Liste des outils disponibles.
    """
    try:
        return server_list_tools()
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


# =============================================================================
# Agent (HTTP, non-streamé — conservé pour usage batch/non-interactif)
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/agent/alex/analyze")
async def analyze_with_alex(request: Request, options: AlexAnalyzeData):
    """
    Analyse un contenu avec Alex (mode non-streamé, batch).

    Args:
        request (Request): La requête FastAPI.
        options (AlexAnalyzeData): Données de l'analyse.

    Returns:
        dict: Le rapport d'analyse généré par Alex.

    Raises:
        HTTPException: 503 si Alex ne produit pas de rapport.
    """
    llm_manager: LLMManager = request.app.state.llm_manager
    report_manager: ReportManager = request.app.state.report_manager

    alex: Analyst = create_alex(llm_manager)
    content = f"""
    {options.base_prompt}\n\n{options.content}
    """
    try:
        result: AnalystResult = await alex.analyze(
            content, source=options.source
        )
    except NoReportProducedError as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail={"error": str(e)})

    if report_manager and result.report:
        await report_manager.add_report(
            asset_id=options.asset_id,
            source=options.source,
            report=result.report,
        )

    return result.report