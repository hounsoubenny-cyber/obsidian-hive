#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 11:00:00 2026

@author: hounsousamuel
"""

"""
core_ws_router.py

Extrait de l'ancien core_router.py monolithique (split HTTP / WS / shared,
août 2026). Contient UNIQUEMENT le canal WebSocket multiplexé (chat Coralie
en streaming, analyse Alex en streaming, confirmations humaines) ainsi que
le WS de gestion des server agents.

Les routes HTTP classiques vivent maintenant dans core_router.py.
Les singletons et helpers partagés vivent dans core_shared.py.

Modifié le Sun Jul 26 2026 : ajout du canal WebSocket multiplexé (chat
Coralie en streaming, analyse Alex en streaming, confirmations humaines).
"""

import asyncio
from uuid import uuid4
from fastapi import (
    HTTPException, APIRouter, status,
    WebSocket, WebSocketDisconnect, WebSocketException
)
from pydantic import ValidationError

from obsidian_hive.core.managers.conversation_manager import ConversationManager
from obsidian_hive.api.models import AlexAnalyzeData
from obsidian_hive.agents.analyst.agent import (
    AnalystResult,
    NoReportProducedError, create_alex
)
from obsidian_hive.agents.core.agent import Coralie, CoralieResult
from obsidian_hive.agents.shared.human_in_loop import (
    WSConfirmer, ConfirmerNotAttachedError, ConfirmationTimeout, ConfirmationDenied,
    current_confirm_username,
)
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.api.ws_manager import WSManager
from modules_utils.keyed_lock import resource_lock
from modules_utils.cryto_utils import checkpw
from obsidian_hive.api.server_asset_agent_ws_manager import ServerAgentWSManager
from obsidian_hive.core.assets.server_asset.tools.server_asset_tools_type import ToolResult, ToolCall
from obsidian_hive.core.assets.server_asset.tools.tools import (
    need_confirmation as server_tool_need_confirmation,
    tool_risk as server_tool_risk,
    tool_exists as server_tool_exists,
)
from obsidian_hive.core.assets.asset_types import ServerAsset, utcnow, AgentStatus as ServerAgentStatus

from obsidian_hive.api.core_shared import (
    get_engine,
    get_ws_manager,
    get_server_agent_ws_manager,
    get_confirmer,
    get_coralie,
    get_auth_manager,
    get_conversation_manager,
    _notify_agent_config_updated,
)

ws_router = APIRouter()

# ============================================================================
# VERROU PAR CONVERSATION
# ============================================================================
# `active_task` (dans la route ws_route()) protège seulement contre les
# doubles envois SUR LA MÊME connexion WebSocket. Il ne protège PAS contre
# un reload de page : le navigateur ouvre une nouvelle connexion WS avec un
# nouveau `active_task = None`, et si l'ancien run n'a pas fini de se faire
# annuler (task.cancel() n'est pas instantané — il faut atteindre le
# prochain await dans la coroutine), on peut se retrouver avec deux runs
# simultanés sur la MÊME conversation, potentiellement deux
# save_agent_turn() qui se marchent dessus.
#
# Ce verrou-ci protège au niveau qui compte vraiment : le conversation_id,
# peu importe combien de connexions/onglets/reloads sont impliqués.
# ============================================================================

_active_conversation_runs: dict[str, str] = {}  # conversation_id -> run_id
_active_conversation_runs_lock = asyncio.Lock()


async def _try_acquire_conversation(conversation_id: str, run_id: str) -> bool:
    """
    Tente de prendre le verrou pour une conversation.

    Retourne False si un autre run est déjà en cours dessus
    (peu importe la connexion).

    Args:
        conversation_id (str): L'ID de la conversation.
        run_id (str): L'ID du run en cours.

    Returns:
        bool: True si le verrou est acquis, False si la conversation est déjà occupée.
    """
    async with _active_conversation_runs_lock:
        if conversation_id in _active_conversation_runs:
            return False
        _active_conversation_runs[conversation_id] = run_id
        return True


async def _release_conversation(conversation_id: str, run_id: str) -> None:
    """
    Libère le verrou d'une conversation.

    Seulement si c'est bien NOUS qui le détenons (garde-fou au cas où un
    run aurait été forcé/écrasé entre-temps).

    Args:
        conversation_id (str): L'ID de la conversation.
        run_id (str): L'ID du run à libérer.
    """
    async with _active_conversation_runs_lock:
        if _active_conversation_runs.get(conversation_id) == run_id:
            _active_conversation_runs.pop(conversation_id, None)


def is_conversation_busy(conversation_id: str) -> bool:
    """
    Vérifie si une conversation a un run actif.

    Utile pour un endpoint de statut ou le polling ciblé côté frontend.

    Args:
        conversation_id (str): L'ID de la conversation.

    Returns:
        bool: True si un run est actif sur cette conversation.
    """
    return conversation_id in _active_conversation_runs


# =============================================================================
# WebSocket — canal multiplexé (chat Coralie / analyse Alex / confirmations)
# =============================================================================
#
# Protocole — connexion : GET/WS /api/core/ws?token=<jwt>
#
# Messages ENTRANTS (client -> serveur), un objet JSON par message :
#
#   {"type": "chat", "message": str, "conversation_id": str | None}
#       Lance un tour de conversation avec Coralie. Si conversation_id est
#       omis, une nouvelle conversation est créée et son id est renvoyé via
#       un évènement "conversation_created" avant le premier token.
#
#   {"type": "analyze", "content": str, "source": str,
#    "asset_id": str | None, "base_prompt": str | None}
#       Lance une analyse Alex sur `content` (même schéma que
#       POST /api/core/agent/alex/analyze, mais streamé token par token).
#
#   {"type": "confirmation_response", "req_id": str, "approved": bool,
#    "reason": str | None}
#       Répond à une confirmation humaine précédemment demandée par le
#       serveur (voir "confirmation_request" ci-dessous).
#
# Messages SORTANTS (serveur -> client), tous {"type": ..., "run": <uuid>, ...}
# (run = identifiant du tour de chat/analyse en cours, généré côté serveur
# à chaque "chat"/"analyze" reçu — permet au frontend de regrouper les
# évènements d'un même tour) :
#
#   conversation_created  {conversation_id}
#   stream_start           {run, iteration, model}
#   reasoning_token        {run, iteration, text}   — le "thinking"
#   token                  {run, iteration, text}   — texte de réponse
#   tool_call_delta        {run, iteration, delta}  — arguments JSON en cours de streaming
#   tool_calls_planned     {run, iteration, tool_calls: [{id, name}]}
#   tool_exec_start        {run, tool, args}
#   tool_exec_end          {run, tool, args, result}
#   tool_exec_error        {run, tool, args, error}
#   retry                  {run, attempt, max_retries, error}
#   step                   {run, iteration}
#   finish                 {run, response, total_time, iterations, tool_calls}
#   error                  {run, error}
#   report                 {run, report}          — uniquement pour "analyze"
#   persist_error          {run, error}            — le run a réussi mais la
#                                                     sauvegarde DB a échoué
#   confirmation_request   {req_id, tool, risk, args} — poussé par WSConfirmer,
#                                                        PAS de champ "run"
#   ack_error              {message}               — message entrant invalide
#                                                     ou type inconnu
#
# Une seule connexion active à la fois (admin unique) ; une reconnexion
# remplace l'ancienne (voir WSManager.connect). Un seul run (chat OU
# analyze) actif à la fois PAR CONNEXION : un second "chat"/"analyze" reçu
# pendant qu'un run tourne encore reçoit un "ack_error" au lieu d'écraser
# le run en cours (évite de mélanger deux flux de tokens dans le même
# canal — si besoin de parallélisme plus tard, il faudra ajouter un id de
# run côté client dès la requête entrante, pas juste en sortie).
# =============================================================================

def _tc_field(tool_call, field: str, sub: str | None = None):
    """
    Lit un champ d'un tool_call quelle que soit sa forme.

    Supporte les dicts bruts, les objets SDK avec attributs, ou les
    _StreamToolCall du mode streaming.

    Args:
        tool_call: L'objet tool_call.
        field (str): Le nom du champ.
        sub (str | None, optional): Sous-champ à récupérer.

    Returns:
        Any: La valeur du champ, ou None.
    """
    obj = tool_call.get(field) if isinstance(tool_call, dict) else getattr(tool_call, field, None)
    if sub is None:
        return obj
    if obj is None:
        return None
    return obj.get(sub) if isinstance(obj, dict) else getattr(obj, sub, None)


def _stream_callbacks(ws_manager: WSManager, username: str, run_id: str) -> dict:
    """
    Fabrique le jeu complet de callbacks pour le streaming.

    Utilisé par Coralie.chat() et Analyst.analyze() pour relayer en temps
    réel tout ce qu'il faut à une UI façon Claude : le texte streamé, le
    "thinking" (reasoning), les tool calls, les retries, et la fin de run.

    Args:
        ws_manager (WSManager): Le gestionnaire WebSocket.
        username (str): Le nom d'utilisateur.
        run_id (str): L'ID du run en cours.

    Returns:
        dict: Dictionnaire des callbacks pour run_agent.
    """

    async def send(type_: str, **payload):
        await ws_manager.send_to(username, {"type": type_, "run": run_id, **payload})

    async def on_stream_start(iteration, model_name):
        await send("stream_start", iteration=iteration, model=model_name)

    async def on_stream_reasoning_token(text, iteration):
        await send("reasoning_token", iteration=iteration, text=text)

    async def on_stream_token(text, iteration):
        await send("token", iteration=iteration, text=text)

    async def on_stream_tool_call_delta(delta, iteration):
        await send("tool_call_delta", iteration=iteration, delta=delta)

    async def on_tool_call(tool_calls):
        planned = [
            {"id": _tc_field(tc, "id"), "name": _tc_field(tc, "function", "name")}
            for tc in (tool_calls or [])
        ]
        await send("tool_calls_planned", tool_calls=planned)

    async def on_tool_exec_before(name, args, call_id=None):
        await send("tool_exec_start", tool=name, args=args, id=call_id)

    async def on_tool_exec_after(name, args, result, call_id=None):
        await send("tool_exec_end", tool=name, args=args, result=result, id=call_id)

    async def on_tool_exec_error(name, args, exc, call_id=None):
        await send("tool_exec_error", tool=name, args=args, error=str(exc), id=call_id)

    async def on_retry(attempt, max_retries, exc):
        await send("retry", attempt=attempt, max_retries=max_retries, error=str(exc))

    async def on_step(iteration, messages, response):
        # Volontairement léger : `messages`/`response` peuvent être gros et
        # contenir des objets non-JSON-natifs. Le détail utile (tokens,
        # tool calls...) part déjà via les autres callbacks ci-dessus.
        await send("step", iteration=iteration)

    async def on_finish(response, total_time, iterations, tool_calls_count):
        await send(
            "finish", response=response, total_time=total_time,
            iterations=iterations, tool_calls=tool_calls_count,
        )

    async def on_error(exc, iteration, messages):
        await send("error", iteration=iteration, error=str(exc))

    return dict(
        show_reasoning=True,
        stream=True,
        on_stream_start=on_stream_start,
        on_stream_token=on_stream_token,
        on_stream_reasoning_token=on_stream_reasoning_token,
        on_stream_tool_call_delta=on_stream_tool_call_delta,
        on_tool_call=on_tool_call,
        on_tool_exec_before=on_tool_exec_before,
        on_tool_exec_after=on_tool_exec_after,
        on_tool_exec_error=on_tool_exec_error,
        on_retry=on_retry,
        on_step=on_step,
        on_finish=on_finish,
        on_error=on_error,
    )


async def _run_chat(
    ws_manager: WSManager,
    username: str,
    conversation_manager: ConversationManager,
    coralie: Coralie,
    data: dict,
) -> None:
    """
    Exécute un tour de chat avec Coralie en streaming.

    Args:
        ws_manager (WSManager): Gestionnaire WebSocket.
        username (str): Nom d'utilisateur.
        conversation_manager (ConversationManager): Gestionnaire des conversations.
        coralie (Coralie): Instance de Coralie.
        data (dict): Données du message (message, conversation_id).
    """
    run_id = str(uuid4())
    message = (data.get("message") or "").strip()
    conversation_id = data.get("conversation_id")

    if not message:
        await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": "Message vide"})
        return

    if not conversation_id:
        conv = await conversation_manager.create_conversation(owner=username)
        conversation_id = conv.conversation_id
        await ws_manager.send_to(username, {"type": "conversation_created", "conversation_id": conversation_id})

    # ---- verrou par conversation --------------------------------------
    # Bloque même si le run "concurrent" tourne sur une AUTRE connexion WS
    # (autre onglet, ou reload de page pendant qu'un run n'a pas fini de
    # s'annuler). Un type dédié "conversation_busy" plutôt que "error" :
    # ça permet au frontend de distinguer une vraie erreur d'un simple
    # "patiente, ça tourne déjà" et d'afficher un message adapté (pas un
    # toast rouge qui fait peur pour rien).
    if not await _try_acquire_conversation(conversation_id, run_id):
        await ws_manager.send_to(username, {
            "type": "conversation_busy",
            "run": run_id,
            "conversation_id": conversation_id,
            "message": "Un run est déjà en cours pour cette conversation, patiente qu'il se termine.",
        })
        return

    try:
        history = await conversation_manager.get_chat_history(conversation_id)
        callbacks = _stream_callbacks(ws_manager, username, run_id)

        ctx_token = current_confirm_username.set(username)
        try:
            result: CoralieResult = await coralie.chat(message, history=history, **callbacks)
        except (ConfirmationDenied, ConfirmationTimeout, ConfirmerNotAttachedError) as e:
            # Un tool a demandé une confirmation qui a été refusée/expirée/
            # impossible à demander — ce n'est pas une erreur serveur, Coralie
            # s'est juste arrêtée en plein milieu d'un tool sensible.
            await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": str(e)})
            return
        except Exception as e:
            print("erreur chat :", str(e))
            await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": str(e)})
            return
        finally:
            current_confirm_username.reset(ctx_token)

        try:
            if result.success and result.raw.get("success"):
                await conversation_manager.save_agent_turn(
                    conversation_id=conversation_id,
                    user_content=message,
                    agent_result=result.raw,
                )
            else:
                msg = f"Msg: {result.raw.get('response')}\n\n{result.raw.get('error')}"
                raise ValueError(msg)
        except Exception as e:
            # Le tour a été streamé avec succès côté client même si la
            # persistance échoue : on prévient sans le faire passer pour une
            # erreur de chat (le client a déjà sa réponse).
            print("erreur chat :", str(e))
            await ws_manager.send_to(username, {"type": "persist_error", "run": run_id, "error": str(e)})

    finally:
        # try/finally englobant : garantit la libération même si coralie.chat
        # lève une exception inattendue, ou si la tâche est annulée depuis
        # l'extérieur (ws_route() fait active_task.cancel() dans son finally
        # au moment d'une déconnexion — un CancelledError traverse ce bloc
        # exactement comme n'importe quelle autre exception ici).
        await _release_conversation(conversation_id, run_id)


async def _run_analyze(
    ws_manager: WSManager,
    username: str,
    report_manager: ReportManager,
    llm_manager: LLMManager,
    data: dict,
) -> None:
    """
    Exécute une analyse avec Alex en streaming.

    Args:
        ws_manager (WSManager): Gestionnaire WebSocket.
        username (str): Nom d'utilisateur.
        report_manager (ReportManager): Gestionnaire des rapports.
        llm_manager (LLMManager): Gestionnaire LLM.
        data (dict): Données de l'analyse (content, source, asset_id, base_prompt).
    """
    run_id = str(uuid4())

    try:
        options = AlexAnalyzeData(
            **{
                k: v
                for k, v in data.items()
                if k != "type" and k in AlexAnalyzeData.model_json_schema()["properties"].keys()
            }
        )
    except ValidationError as e:
        await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": str(e)})
        return

    alex = create_alex(llm_manager)
    content = f"{options.base_prompt}\n\n{options.content}"
    callbacks = _stream_callbacks(ws_manager, username, run_id)

    ctx_token = current_confirm_username.set(username)
    try:
        result: AnalystResult = await alex.analyze(content, source=options.source, **callbacks)
    except NoReportProducedError as e:
        await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": str(e)})
        return
    except Exception as e:
        await ws_manager.send_to(username, {"type": "error", "run": run_id, "error": str(e)})
        return
    finally:
        current_confirm_username.reset(ctx_token)

    if report_manager and result.report:
        try:
            await report_manager.add_report(
                asset_id=options.asset_id,
                source=options.source,
                report=result.report,
            )
        except Exception as e:
            await ws_manager.send_to(username, {"type": "persist_error", "run": run_id, "error": str(e)})

    await ws_manager.send_to(username, {"type": "report", "run": run_id, "report": result.report})


async def cancel_task(task: asyncio.Task):
    """Annule une tâche asynchrone de manière sécurisée.

    Args:
        task (asyncio.Task): La tâche à annuler.
    """
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def manage_server_tool_call(
    asset_id: str,
    username: str,
    tool_call: ToolCall,
    confirmer: WSConfirmer,
    ws_manager: WSManager,
    server_agent_ws_manager: ServerAgentWSManager,
):
    """
    Gère l'exécution d'un tool call sur un asset serveur.

    Vérifie les permissions, demande une confirmation humaine si nécessaire,
    envoie la commande à l'agent et retourne le résultat.

    Args:
        asset_id (str): L'ID de l'asset.
        username (str): Nom de l'utilisateur.
        tool_call (ToolCall): L'appel d'outil.
        confirmer (WSConfirmer): Gestionnaire de confirmation humaine.
        ws_manager (WSManager): Gestionnaire WebSocket.
        server_agent_ws_manager (ServerAgentWSManager): Gestionnaire WS des agents.
    """
    asset_db = await (get_engine().asset_manager.get_by_identifier(identifier=asset_id, first=True))
    asset = get_engine().asset_manager.asset_item_db_to_asset_item(asset_db)

    if not asset:
        await ws_manager.send_to(username, {
            "type": "tool_result",
            "message": f"Asset non trouvé {asset_id}",
            "call_id": tool_call.call_id,
            "code": "asset_not_found",
        })
        return

    if not server_tool_exists(tool_call.tool_name):
        await ws_manager.send_to(username, {
            "type": "tool_result",
            "message": "Tool inexistant",
            "result": None,
            "call_id": tool_call.call_id,
            "code": "tool_not_found",
        })
        return

    if tool_call.tool_name not in asset.allowed_tools:
        await ws_manager.send_to(username, {
            "type": "tool_result",
            "message": f"Tool {tool_call.tool_name!r} non autorisé sur cet asset",
            "call_id": tool_call.call_id,
            "code": "tool_not_allowed",
        })
        return

    if tool_call.caller == username:
        if server_tool_need_confirmation(tool_call.tool_name):
            try:
                req_id = str(uuid4())
                await confirmer(
                    req_id=req_id, tool_name=tool_call.tool_name,
                    risk=server_tool_risk(tool_call.tool_name),
                    args=tool_call.tool_args,
                )
            except ConfirmationDenied as e:
                await ws_manager.send_to(username, {
                    "type": "tool_result",
                    "message": (
                        f"Exécution du tool call ({e.tool_name}) refusé par l'utilisateur"
                        + (f", raison: {e.reason}." if e.reason else ".")
                    ),
                    "result": None,
                    "code": "tool_confirmation_denied",
                    "call_id": tool_call.call_id
                })
                return

            except ConfirmationTimeout as e:
                await ws_manager.send_to(username, {
                    "type": "tool_result",
                    "message": (
                        f"Délai d'approbation du tool call {e.too_name}, requête {e.req_id} dépassé."
                    ),
                    "result": None,
                    "code": "tool_confirmation_timeout",
                    "call_id": tool_call.call_id
                })
                return

        tool_result: ToolResult | None = await server_agent_ws_manager.send_command_to(
            asset_id, tool_call=tool_call
        )

        if tool_result is None:
            await ws_manager.send_to(username, {
                "type": "tool_result",
                "message": "Echec de l'envoie du tool call ou de la résolution (timeout)",
                "result": None,
                "call_id": tool_call.call_id,
                "code": "tool_send_failed",
            })
        else:
            await ws_manager.send_to(
                username,
                {
                    "type": "tool_result",
                    "message": "Succès de l'éxécution du tool call",
                    "result": tool_result.model_dump(mode="json"),
                    "call_id": tool_call.call_id,
                    "code": "tool_exec_successfuly"  # Possible erreur coté agent
                }
            )

    else:
        await ws_manager.send_to(username, {
            "type": "tool_result",
            "message": "Username incorrect ! (Possible tentation d'usurpation)",
            "call_id": tool_call.call_id,
            "reason": "identity_theft",
        })


async def clear_tasks(
    tasks: list[asyncio.Task],
    stop_event: asyncio.Event,
    delay: int | float = 2,
):
    """
    Nettoie périodiquement les tâches terminées d'une liste.

    Args:
        tasks (list[asyncio.Task]): Liste des tâches à surveiller.
        stop_event (asyncio.Event): Événement d'arrêt.
        delay (int | float, optional): Intervalle de nettoyage. Par défaut 2.
    """
    delay = delay if delay is not None else 2
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass
        if tasks:
            tasks[:] = [t for t in tasks if not t.done()]


@ws_router.websocket("/ws")
async def ws_route(ws: WebSocket, token: str):
    """
    Route WebSocket principale pour les clients humains (administrateurs).

    Gère le chat avec Coralie, les analyses Alex en streaming,
    les confirmations humaines et les tool calls serveur.

    Args:
        ws (WebSocket): La connexion WebSocket.
        token (str): Token JWT d'authentification.

    Raises:
        WebSocketException: En cas d'erreur d'authentification.
    """
    ws_manager = get_ws_manager()
    server_agent_ws_manager = get_server_agent_ws_manager()
    conversation_manager = get_conversation_manager(ws.app.state)
    auth_manager = get_auth_manager(ws.app.state)
    llm_manager: LLMManager = ws.app.state.llm_manager
    report_manager: ReportManager = ws.app.state.report_manager
    tasks = []
    clear_tasks_task: asyncio.Task | None = None
    clear_task_stop_event: asyncio.Event = asyncio.Event()
    username: str | None = None
    active_task: asyncio.Task | None = None
    my_channel = None  # jeton d'identité du canal attaché

    try:
        try:
            username = auth_manager.verify_token_params(token)
            auth_manager.verify_username(username)
        except HTTPException as e:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=str(e.detail))

        await ws.accept()
        ws_manager.connect(ws, username)

        confirmer = get_confirmer()
        my_channel = confirmer.attach(username, lambda data: ws_manager.send_to(username, data), force=True)
        coralie = get_coralie(ws.app.state)

        while True:
            try:
                raw = await ws.receive_json()
            except WebSocketDisconnect:
                raise
            except Exception as e:
                await ws_manager.send_to(username, {"type": "ack_error", "message": f"JSON invalide: {e}"})
                continue

            msg_type = raw.get("type")

            if msg_type == "confirmation_response":
                ok = confirmer.resolve(
                    req_id=raw.get("req_id"),
                    approved=bool(raw.get("approved")),
                    reason=raw.get("reason"),
                )
                if not ok:
                    await ws_manager.send_to(username, {
                        "type": "ack_error",
                        "message": f"req_id inconnu ou déjà résolu: {raw.get('req_id')}",
                    })
                continue

            if msg_type in ("chat", "analyze"):
                if active_task and not active_task.done():
                    await ws_manager.send_to(username, {
                        "type": "ack_error",
                        "message": "Un run est déjà en cours sur cette connexion, attends qu'il finisse",
                    })
                    continue

                if msg_type == "chat":
                    active_task = asyncio.create_task(
                        _run_chat(ws_manager, username, conversation_manager, coralie, raw)
                    )
                else:
                    active_task = asyncio.create_task(
                        _run_analyze(ws_manager, username, report_manager, llm_manager, raw)
                    )
                continue

            if msg_type == "server_tool_call":
                asset_id = raw.get("asset_id")
                tool_call: ToolCall = ToolCall.model_validate(raw.get("tool_call"))
                if clear_tasks_task is None:
                    clear_tasks_task = asyncio.create_task(
                        clear_tasks(tasks, stop_event=clear_task_stop_event)
                    )
                tasks.append(
                    asyncio.create_task(
                        manage_server_tool_call(
                            asset_id=asset_id,
                            tool_call=tool_call,
                            username=username,
                            ws_manager=ws_manager,
                            server_agent_ws_manager=server_agent_ws_manager,
                            confirmer=confirmer,
                        )
                    )
                )
                continue

            if msg_type == "server_config_reload":
                asset_id = raw.get("asset_id")
                server_agent_ws_manager.send_to(
                    asset_id,
                    data={
                        "type": "config_reload",
                    }
                )
                continue

            await ws_manager.send_to(username, {
                "type": "ack_error",
                "message": f"Type de message inconnu: {msg_type!r}",
            })

    except WebSocketDisconnect:
        pass

    except (WebSocketException,):
        pass

    except Exception as e:
        print(f"Erreur WS inattendue: {e}")

    finally:
        await cancel_task(active_task)
        clear_task_stop_event.set()
        if clear_tasks_task:
            try:
                await asyncio.wait_for(clear_tasks_task, 2.5)
            except asyncio.TimeoutError:
                pass

            await cancel_task(clear_tasks_task)

        if tasks:
            await asyncio.gather(
                *[cancel_task(t) for t in tasks],
                return_exceptions=True
            )

        if username:
            get_confirmer().detach(username, my_channel)

        try:
            await ws.close()
        except Exception:
            pass

        if username:
            ws_manager.disconnect(username, ws)


@ws_router.websocket("/ws/server_agent")
async def agent_ws(ws: WebSocket, asset_id: str):
    """
    Route WebSocket pour les agents serveurs.

    Gère la connexion des agents serveurs, le heartbeat, les tool calls
    et l'autodestruction.

    Args:
        ws (WebSocket): La connexion WebSocket.
        asset_id (str): L'ID de l'asset serveur.

    Raises:
        WebSocketException: En cas d'erreur d'authentification ou d'asset invalide.
    """
    engine = get_engine()
    ws_manager = get_server_agent_ws_manager()
    # client_ws_manager = get_ws_manager()  # noqa: F841
    auth_header = ws.headers.get("authorization", "")
    secret = auth_header.removeprefix("Bearer ").strip()

    asset_db = await engine.asset_manager.get_by_identifier(asset_id, first=True)
    if not asset_db:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="Asset introuvable")

    asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset_db)

    if not isinstance(asset, ServerAsset):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="Type d'asset non supporté")

    if asset.is_revoked() or not asset.agent_credential_hash:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="Agent non autorisé")

    if not secret or not checkpw(ServerAsset.hash_secret_input(secret), asset.agent_credential_hash.encode()):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="Credential invalide")

    await ws.accept()
    conn = ws_manager.connect(asset_id, ws)
    try:
        if asset.pending_deletion:
            await conn.send({"type": "self_destruct"})
            # acked = False
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 30
            try:
                while (remaining := deadline - loop.time()) > 0:
                    raw = await asyncio.wait_for(ws.receive_json(), timeout=remaining)
                    if raw.get("type") == "self_destruct_ack":
                        # acked = True
                        break
            except (asyncio.TimeoutError, WebSocketDisconnect):
                pass

            async with resource_lock.acquire(f"asset:{asset_id}"):
                await engine.remove_asset(delete=True, asset_id=asset_id)

            try:
                await ws.close(code=1001, reason="self_destruct")
            except Exception:
                pass

            return

        async with resource_lock.acquire(f"asset:{asset_id}"):
            asset.agent_status = ServerAgentStatus.CONNECTED
            asset.last_heartbeat = utcnow()
            asset.install_token = None
            await engine.asset_manager.upsert(asset)

        await _notify_agent_config_updated(ws_manager, asset)
        while True:
            raw = await ws.receive_json()
            msg_type = raw.get("type")

            if msg_type == "heartbeat":  # ping de connection, marque le statut en ligne
                async with resource_lock.acquire(f"asset:{asset_id}"):
                    a_db = await engine.asset_manager.get_by_identifier(asset_id, first=True)
                    a = engine.asset_manager.asset_item_db_to_asset_item(a_db)
                    a.last_heartbeat = utcnow()
                    asset.install_token = None
                    await engine.asset_manager.upsert(a)

                await ws_manager.send_to(asset_id, {"type": "heartbeat_ack"})
                await _notify_agent_config_updated(ws_manager, a)
                continue

            if msg_type == "tool_result":  # Résultat d'un tool call
                tool_result: ToolResult = ToolResult.model_validate(raw.get("tool_result"))
                await ws_manager.resolve_command(
                    asset_id=asset_id,
                    tool_result=tool_result
                )
                # caller = tool_result.caller
                # await client_ws_manager.send_to(
                #     caller,
                #     tool_result.model_dump(mode="json")
                # )
                continue

            elif msg_type == "self_destruct_ack":
                ws_manager.resolve_pending_ack(asset_id)
                return            await ws.send_json({"type": "ack_error", "message": f"Type inconnu: {msg_type!r}"})

    except WebSocketDisconnect:
        pass

    finally:
        try:
            await ws.close()
        except Exception:
            pass

        ws_manager.disconnect(asset_id, conn)
        async with resource_lock.acquire(f"asset:{asset_id}"):
            a_db = await engine.asset_manager.get_by_identifier(asset_id, first=True)
            if a_db:
                a = engine.asset_manager.asset_item_db_to_asset_item(a_db)
                if a.agent_status != ServerAgentStatus.REVOKED:
                    a.agent_status = ServerAgentStatus.OFFLINE
                await engine.asset_manager.upsert(a)