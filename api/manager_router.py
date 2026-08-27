#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 26 08:40:03 2026

@author: hounsousamuel
"""

"""
manager_router.py — Routes REST pour JobManager, ReportManager et
ConversationManager. Suit le même pattern que core_router.py : body
Pydantic par route, try/except HTTPException, erreurs 500 avec
{"error":, "type":}, dependency getters depuis request.app.state.

@author: hounsousamuel
"""

from fastapi import APIRouter, HTTPException, Request, Header, status, Depends

from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.managers.conversation_manager import (
    ConversationManager, ConversationNotFoundError,
)
from obsidian_hive.core.managers.job_catalog import JOB_CATALOG, describe_catalog

from obsidian_hive.api.models import (
    GetJobData, ModifyJobData, AddJobData, InMemoryFilterData,
    GetReportData, GetByAssetData, ListReportsByFilterData, ReportStatsData,
    ReportIdData, UpdateReportSeverityData, DeleteOldReportsData,
    CreateConversationData, ConversationRefData, ListConversationsData,
    SearchConversationsData, UpdateConversationTitleData, SetFavoriteData,
    SetArchivedData, GetMessagesData, GetLastMessageData, MessageIdData,
    UpdateMessageContentData, ListCriticalReportsData
)
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE
from modules_utils.keyed_lock import resource_lock
router = APIRouter()


# =============================================================================
# Dependency getters
# =============================================================================

def get_job_manager(request: Request) -> JobManager:
    return request.app.state.job_manager

def get_report_manager(request: Request) -> ReportManager:
    return request.app.state.report_manager

def get_conversation_manager(request: Request) -> ConversationManager:
    return request.app.state.conversation_manager

def get_current_username(request: Request, authorization: str = Header(...)) -> str:
    """
    Dependency FastAPI qui décode le JWT et retourne le username (`sub`).

    Délègue entièrement à AuthManager.verify_token (qui gère déjà le
    parsing du header "Bearer <token>", la vérification de signature et
    d'expiration) — pas de reparsing manuel du header ici.
    """
    from obsidian_hive.api.main_api import _get_auth_manager
    return _get_auth_manager().verify_token(request, authorization)


def _server_error(e: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": str(e), "type": type(e).__name__},
    )


# =============================================================================
# JobManager — routes
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/list")
async def list_jobs(request: Request, options: InMemoryFilterData):
    try:
        jm = get_job_manager(request)
        return {"jobs": jm.list_jobs_wrapped(in_memory=options.in_memory)}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/get")
async def get_job(request: Request, options: GetJobData):
    try:
        jm = get_job_manager(request)
        job = jm.get_job_wrapped(options.job_id, in_memory=options.in_memory)
        if job is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Job introuvable"})
        return {"job": job}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/state")
async def get_job_state(request: Request, options: GetJobData):
    try:
        jm = get_job_manager(request)
        state = jm.get_job_state(options.job_id, in_memory=options.in_memory)
        if state is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Job introuvable"})
        return {"state": state}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.get("/jobs/catalog")
async def list_job_catalog(request: Request):
    """Jobs planifiables via /jobs/create — voir job_catalog.py."""
    return {"catalog": describe_catalog()}


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/create")
async def create_job(request: Request, options: AddJobData):
    try:
        jm = get_job_manager(request)
        spec = JOB_CATALOG[options.job_name]
        merged_kwargs = {**spec.default_kwargs, **(options.kwargs or {})}
        job = jm.add_job_wrapped(
            func=spec.func,
            job_id=options.job_id,
            name=spec.description,
            trigger=options.trigger or spec.default_trigger,
            kwargs=merged_kwargs,
            in_memory=bool(options.in_memory),
        )
        return {"job": job}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/modify")
async def modify_job(request: Request, options: ModifyJobData):
    try:
        jm = get_job_manager(request)
        async with resource_lock.acquire(f"job:{options.job_id}"):
            result = jm.modify_job(options.job_id, in_memory=options.in_memory, **options.changes())
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/pause")
async def pause_job(request: Request, options: GetJobData):
    try:
        jm = get_job_manager(request)
        async with resource_lock.acquire(f"job:{options.job_id}"):
            result = jm.pause_job(options.job_id, in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/resume")
async def resume_job(request: Request, options: GetJobData):
    try:
        jm = get_job_manager(request)
        async with resource_lock.acquire(f"job:{options.job_id}"):
            result = jm.resume_job(options.job_id, in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/remove")
async def remove_job(request: Request, options: GetJobData):
    """⚠️ Irréversible."""
    try:
        jm = get_job_manager(request)
        async with resource_lock.acquire(f"job:{options.job_id}"):
            result = jm.remove_job(options.job_id, in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/remove_all")
async def remove_all_jobs(request: Request, options: InMemoryFilterData):
    """⚠️ Irréversible, large impact — supprime potentiellement TOUS les jobs."""
    try:
        jm = get_job_manager(request)
        result = jm.remove_all_jobs(in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/pause_all")
async def pause_all_jobs(request: Request, options: InMemoryFilterData):
    try:
        jm = get_job_manager(request)
        result = jm.pause_all_jobs(in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/jobs/resume_all")
async def resume_all_jobs(request: Request, options: InMemoryFilterData):
    try:
        jm = get_job_manager(request)
        result = jm.resume_all_jobs(in_memory=options.in_memory)
        if not result["success"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": result["error"]})
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


# =============================================================================
# ReportManager — routes
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/get")
async def get_report(request: Request, options: GetReportData):
    try:
        rm = get_report_manager(request)
        result = await rm.get_by_identifier(
            identifier=options.identifier, first=options.first, limit=options.limit
        )
        if result is None or (isinstance(result, list) and not result):
            return {"reports": None}
        results = result if isinstance(result, list) else [result]
        return {"reports": [rm.report_db_to_dict(r) for r in results]}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/get_latest")
async def get_latest_report(request: Request, options: GetByAssetData):
    try:
        rm = get_report_manager(request)
        report = await rm.get_latest_by_asset(options.asset_id)
        return {"report": rm.report_db_to_dict(report) if report else None}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/get_firstest")
async def get_firstest_report(request: Request, options: GetByAssetData):
    try:
        rm = get_report_manager(request)
        report = await rm.get_firstest_by_asset(options.asset_id)
        return {"report": rm.report_db_to_dict(report) if report else None}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/list_by_filter")
async def list_reports_by_filter(request: Request, options: ListReportsByFilterData):
    try:
        rm = get_report_manager(request)
        reports = await rm.list_by_filter(**options.model_dump())
        return {"reports": rm.reports_to_list(reports)}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/list_critical")
async def list_critical_reports(request: Request, options: ListCriticalReportsData):
    try:
        rm = get_report_manager(request)
        reports = await rm.list_critical(limit=options.limit)
        return {"reports": rm.reports_to_list(reports)}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/stats")
async def get_report_stats(request: Request, options: ReportStatsData):
    try:
        rm = get_report_manager(request)
        stats = await rm.summary_stats(asset_id=options.asset_id)
        return {"stats": stats}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/update_severity")
async def update_report_severity(request: Request, options: UpdateReportSeverityData):
    try:
        rm = get_report_manager(request)
        changes = {"severity": options.severity.value}
        if options.has_fix is not None:
            changes["has_fix"] = options.has_fix
        async with resource_lock.acquire(f"report:{options.report_id}"):
            success = await rm.update_by_id(options.report_id, **changes)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Rapport introuvable"})
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/delete")
async def delete_report(request: Request, options: ReportIdData):
    """⚠️ Irréversible."""
    try:
        rm = get_report_manager(request)
        async with resource_lock.acquire(f"report:{options.report_id}"):
            success = await rm.delete_by_id(options.report_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Rapport introuvable"})
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/reports/delete_older_than")
async def delete_old_reports(request: Request, options: DeleteOldReportsData):
    """⚠️ Irréversible, large impact — supprime TOUS les rapports plus vieux
    que `days` jours, tous assets confondus."""
    try:
        rm = get_report_manager(request)
        count = await rm.delete_older_than(options.days)
        return {"success": True, "deleted_count": count}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


# =============================================================================
# ConversationManager — routes
# owner toujours dérivé du token (get_current_username), jamais du body
# =============================================================================

@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/create")
async def create_conversation(request: Request, options: CreateConversationData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        conv = await cm.create_conversation(owner=owner, title=options.title)
        return {
            "conversation_id": conv.conversation_id,
            "id": conv.id,
            "title": conv.title,
            "created_at": conv.created_at,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/list")
async def list_conversations(request: Request, options: ListConversationsData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        limit = options.limit
        if limit is not None:
            limit = max(limit, 1)
        convs = await cm.list_by_owner(
            owner=owner,
            include_archived=options.include_archived,
            favorites_only=options.favorites_only,
            limit=limit,
            offset=options.offset,
        )
        total = await cm.count_by_owner(owner=owner, include_archived=options.include_archived)
        return {
            "conversations": [
                {
                    "conversation_id": c.conversation_id, "id": c.id, "title": c.title,
                    "created_at": c.created_at, "updated_at": c.updated_at,
                    "archived": c.archived, "is_favorite": c.is_favorite,
                }
                for c in convs
            ],
            "total": total,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/search")
async def search_conversations(request: Request, options: SearchConversationsData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        convs = await cm.search_conversations(owner=owner, query=options.query, limit=options.limit)
        return {
            "conversations": [
                {"conversation_id": c.conversation_id, "id": c.id, "title": c.title, "updated_at": c.updated_at}
                for c in convs
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


async def _get_owned_conversation(cm: ConversationManager, owner: str, ref: ConversationRefData):
    """Résout la conversation ET vérifie qu'elle appartient bien à `owner` —
    sans ce check, n'importe quel utilisateur authentifié pourrait lire/
    modifier la conversation d'un autre en devinant/énumérant un id."""
    conv = await cm.get_conversation(conversation_id=ref.conversation_id, id=ref.id)
    if conv is None or conv.owner != owner:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Conversation introuvable"})
    return conv


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/get")
async def get_conversation(request: Request, options: ConversationRefData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        conv = await _get_owned_conversation(cm, owner, options)
        return {
            "conversation_id": conv.conversation_id, "id": conv.id, "title": conv.title,
            "created_at": conv.created_at, "updated_at": conv.updated_at,
            "archived": conv.archived, "is_favorite": conv.is_favorite,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/delete")
async def delete_conversation(request: Request, options: ConversationRefData, username: str = Depends(get_current_username)):
    """⚠️ Irréversible — supprime la conversation ET tous ses messages (cascade)."""
    try:
        cm = get_conversation_manager(request)
        owner = username
        await _get_owned_conversation(cm, owner, options)  # 404 + ownership check
        async with resource_lock.acquire(f"conversation:{options.conversation_id}"):
            ok = await cm.delete_conversation(conversation_id=options.conversation_id, id=options.id)
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/update_title")
async def update_conversation_title(request: Request, options: UpdateConversationTitleData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        await _get_owned_conversation(cm, owner, options)
        async with resource_lock.acquire(f"conversation:{options.conversation_id}"):
            ok = await cm.update_title(conversation_id=options.conversation_id, id=options.id, title=options.title)
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/set_favorite")
async def set_favorite(request: Request, options: SetFavoriteData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        await _get_owned_conversation(cm, owner, options)
        async with resource_lock.acquire(f"conversation:{options.conversation_id}"):
            ok = await cm.set_favorite(conversation_id=options.conversation_id, id=options.id, favorite=options.favorite)
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/set_archived")
async def set_archived(request: Request, options: SetArchivedData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        await _get_owned_conversation(cm, owner, options)
        async with resource_lock.acquire(f"conversation:{options.conversation_id}"):
            ok = await cm.set_archived(conversation_id=options.conversation_id, id=options.id, archived=options.archived)
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/messages")
async def get_messages(request: Request, options: GetMessagesData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        limit = options.limit
        if limit is not None:
            limit = max(limit, 1)
        await _get_owned_conversation(cm, owner, options)
        messages = await cm.get_messages(
            conversation_id=options.conversation_id, id=options.id,
            limit=limit, offset=options.offset,
        )
        return {"messages": [m.model_dump(mode="json") for m in messages]}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/last_message")
async def get_last_message(request: Request, options: GetLastMessageData, username: str = Depends(get_current_username)):
    try:
        cm = get_conversation_manager(request)
        owner = username
        await _get_owned_conversation(cm, owner, options)
        msg = await cm.get_last_message(
            conversation_id=options.conversation_id, id=options.id, role=options.role
        )
        return {"message": msg.model_dump(mode="json") if msg else None}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


async def _verify_message_ownership(cm: ConversationManager, owner: str, message_id: int):
    """
    Un message n'a pas de champ `owner` direct (seul MessageDB.conversation_pk
    le relie à sa conversation) — donc pour vérifier qu'un user ne modifie
    que ses propres messages : récupérer le message, remonter à sa
    conversation via conversation_pk, comparer son owner. Deux requêtes,
    mais c'est la seule façon fiable sans dupliquer owner sur chaque message.
    """
    msg = await cm.get_message(message_id)
    if msg is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Message introuvable"})
    conv = await cm.get_conversation(id=msg.conversation_pk)
    if conv is None or conv.owner != owner:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Message introuvable"})
    return msg


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/update_message")
async def update_message_content(
    request: Request,
    options: UpdateMessageContentData,
    username: str = Depends(get_current_username),
):
    try:
        cm = get_conversation_manager(request)
        await _verify_message_ownership(cm, username, options.message_id)
        async with resource_lock.acquire(f"conv_message:{options.message_id}"):
            ok = await cm.update_message_content(options.message_id, options.content)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Message introuvable"})
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)


@limiter.limit(f"{LIMITE}/minute")
@router.post("/conversations/delete_message")
async def delete_message(
    request: Request,
    options: MessageIdData,
    username: str = Depends(get_current_username),
):
    """⚠️ Irréversible."""
    try:
        cm = get_conversation_manager(request)
        await _verify_message_ownership(cm, username, options.message_id)
        async with resource_lock.acquire(f"conv_message:{options.message_id}"):
            ok = await cm.delete_message(options.message_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "Message introuvable"})
        return {"success": ok}
    except HTTPException:
        raise
    except Exception as e:
        raise _server_error(e)