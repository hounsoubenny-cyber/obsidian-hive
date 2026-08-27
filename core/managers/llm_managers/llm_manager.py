#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 30 15:57:48 2026

@author: hounsousamuel
"""

import os
import threading
import json
import time
import asyncio
import requests
import subprocess
import itertools
import configparser
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin
from typing import Callable, Optional, Any, Dict, List, Union, Awaitable
from modules_utils.logger import get_logger
from obsidian_hive.core.managers.llm_managers.api_key_client_mapper import (
    get_client,
    CLIENT_UNION
)
from anthropic import Anthropic, AsyncAnthropic
from obsidian_hive.core.managers.llm_managers.tool_builder import build_tools
from modules_utils.loop_utils import _run_async

BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEFAUlT_LLAMA_SERVER_DIR = os.path.join(
    BASEDIR,
    "llama_server_logs"
)
os.makedirs(DEFAUlT_LLAMA_SERVER_DIR, exist_ok=True)

LLAMA_MODELS = [
    "qwen2.5-7b",
    "llama-3.1-8b",
    "qwen2.5-3b",
    "qwen3.5-4b",
    "ornith1.0-9b"
]

logger = get_logger("obsidian_llm_manager")

OnBeforeTool = Union[
    Callable[[str, dict, str | None], None],
    Callable[[str, dict], Awaitable[None]]
]  # (nom_du_tool, args, call_id) — juste avant l'exécution du tool

OnAfterTool = Union[
    Callable[[str, dict, str, str | None], None],
    Callable[[str, dict, str, str | None], Awaitable[None]]
]  # (nom_du_tool, args, résultat, call_id) — juste après l'exécution réussie du tool

OnToolError = Union[
    Callable[[str, dict, Exception, str | None], None],
    Callable[[str, dict, Exception, str | None], Awaitable[None]]
]  # (nom_du_tool, args, exception, call_id) — le tool a levé une erreur (ou nom inconnu)

OnStep = Union[
    Callable[[int, List[dict], Any], None],
    Callable[[int, List[dict], Any], Awaitable[None]]
]  # (iteration, messages_actuels, response_brute_du_LLM) — à chaque tour de la boucle agent

OnToolCall = Union[
    Callable[[List[Dict[str, str]]], None],
    Callable[[List[Dict[str, str]]], Awaitable[None]]
]  # (liste_des_tool_calls_décidés_par_le_LLM) — juste avant de les exécuter un par un

OnFinish = Union[
    Callable[[str, float, int, int], None],
    Callable[[str, float, int, int], Awaitable[None]]
]  # (réponse_finale, temps_total_sec, nb_itérations, nb_tool_calls) — succès de l'agent

OnAgentError = Union[
    Callable[[Exception, int, List[dict]], None],
    Callable[[Exception, int, List[dict]], Awaitable[None]]
]  # (exception, iteration, messages_actuels) — échec définitif (modèle indispo, erreur non-retryable...)

OnRetry = Union[
    Callable[[int, int, Exception], None],
    Callable[[int, int, Exception], Awaitable[None]]
]  # (tentative_actuelle, max_retries, exception) — juste avant de retenter l'appel LLM

# =============================================================================
# 🌊 STREAMING — types de callbacks
# =============================================================================
OnStreamStart = Union[
    Callable[[int, str], None],
    Callable[[int, str], Awaitable[None]]
]  # (iteration, model_name)

OnStreamToken = Union[
    Callable[[str, int], None],
    Callable[[str, int], Awaitable[None]]
]  # (texte_delta, iteration)

OnStreamReasoningToken = Union[
    Callable[[str, int], None],
    Callable[[str, int], Awaitable[None]]
]  # (reasoning_delta, iteration)

OnStreamToolCallDelta = Union[
    Callable[[dict, int], None],
    Callable[[dict, int], Awaitable[None]]
]  # (delta_dict normalisé, iteration)

OnStreamMessage = Union[
    Callable[[dict, int], None],
    Callable[[dict, int], Awaitable[None]]
]  # (message complet reconstitué, iteration) — juste avant le traitement normal


# =============================================================================
# 🔔 EVENT BUS — Bus d'événements générique
# =============================================================================

class EventBus:
    """
    Bus d'événements générique pour LLMManager.

    Permet à plusieurs abonnés d'écouter le même évènement en permanence,
    sans avoir à repasser les callbacks à chaque appel.

    Attributs de classe :
        STREAM_EVENTS: tuple — événements qui ne sont émis que pendant un stream
        ALL_EVENTS: tuple — tous les événements disponibles
    """

    # 🔥 Événements UNIQUEMENT émis pendant un stream
    STREAM_EVENTS = (
        "start_stream",           # (iteration, model_name)
        "token_stream",           # (texte_delta, iteration)
        "reasoning_token_stream", # (reasoning_delta, iteration)
        "tool_call_delta_stream", # (delta_dict, iteration)
        "message_stream",         # (message_dict complet, iteration)
    )

    # 📦 Tous les événements (stream + non-stream)
    ALL_EVENTS = STREAM_EVENTS + (
        "step",            # (iteration, messages, response)
        "tool_call",       # (tool_calls_list)
        "finish",          # (response, total_time, iterations, tool_calls_count)
        "error",           # (exception, iteration, messages)
        "retry",           # (attempt, max_retries, exception)
        "tool_exec_before",# (tool_name, args)
        "tool_exec_after", # (tool_name, args, result)
        "tool_exec_error", # (tool_name, args, exception)
        "any",             # (event_name, *args, **kwargs) — écoute TOUS les évènements
    )

    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = defaultdict(list)

    def on(self, event: str, callback: Callable) -> Callable:
        """
        S'abonne à un évènement.

        Args:
            event: Nom de l'évènement ("token", "step", "finish", ...)
            callback: Fonction à appeler (sync ou async)

        Returns:
            Le callback (utilisable en décorateur)

        Example:
            @bus.on("token")
            async def on_token(text, iteration):
                print(f"[{iteration}] {text}")
        """
        self._listeners[event].append(callback)
        return callback

    def off(self, event: str, callback: Callable) -> None:
        """Se désabonne d'un évènement précis."""
        try:
            self._listeners[event].remove(callback)
        except ValueError:
            pass

    def once(self, event: str, callback: Callable) -> Callable:
        """
        S'abonne à un évènement pour une seule exécution.
        Le callback est automatiquement retiré après son appel.
        """
        async def _wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(*args, **kwargs)
                else:
                    result = callback(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    await result
            finally:
                self.off(event, _wrapper)

        self._listeners[event].append(_wrapper)
        return _wrapper

    def clear(self, event: Optional[str] = None) -> None:
        """Vide les abonnés d'un évènement, ou tout le bus si event=None."""
        if event is None:
            self._listeners.clear()
        else:
            self._listeners.pop(event, None)

    def is_stream_event(self, event: str) -> bool:
        """Vérifie si un événement est spécifique au streaming."""
        return event in self.STREAM_EVENTS

    async def emit(self, event: str, *args, **kwargs) -> None:
        """Émet un évènement à tous ses abonnés."""
        async def _run(callback, *args, **kwargs):
            if asyncio.iscoroutinefunction(callback):
                result = await callback(*args, **kwargs)
            else:
                result = callback(*args, **kwargs)
            if asyncio.iscoroutine(result):
                await result
                
        for callback in list(self._listeners.get(event, [])):
            try:
                await _run(callback, *args, **kwargs)
            except Exception as e:
                logger.warning(f"[EventBus:{event}] Erreur callback: {e}")

        # Émettre également sur "any" pour les abonnés qui écoutent tout
        for callback in list(self._listeners.get("any", [])):
            try:
                await _run(callback, *args, **kwargs)
            except Exception as e:
                logger.warning(f"[EventBus:any] Erreur callback pour {event}: {e}")

    def __call__(self, event: str) -> Callable:
        """Décorateur pour s'abonner à un évènement."""
        def decorator(callback: Callable) -> Callable:
            self.on(event, callback)
            return callback
        return decorator

# =============================================================================
# 🧩 Objets "façade" pour le streaming
# Une fois le stream terminé, on reconstruit un objet qui a EXACTEMENT la
# même forme que response.choices[0] en mode non-streaming (.message.content,
# .message.tool_calls, .message.model_dump(), .finish_reason...), pour que
# TOUT le reste de run_agent (tool calling, retry, etc.) fonctionne à
# l'identique, sans savoir si la réponse vient d'un stream ou non.
# =============================================================================

class _StreamFunction:
    __slots__ = ("name", "arguments")

    def __init__(self, name: str = "", arguments: str = ""):
        self.name = name
        self.arguments = arguments


class _StreamToolCall:
    __slots__ = ("id", "type", "function")

    def __init__(self, id: str = "", type: str = "function", function: Optional[_StreamFunction] = None):
        self.id = id
        self.type = type
        self.function = function or _StreamFunction()


class _StreamMessage:
    def __init__(
        self,
        content: str = "",
        tool_calls: Optional[List[_StreamToolCall]] = None,
        reasoning: Optional[str] = None,
        role: str = "assistant",
    ):
        self.role = role
        self.content = content
        self.tool_calls = tool_calls or []
        self.reasoning = reasoning
        self.reasoning_content = reasoning

    def model_dump(self) -> dict:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in self.tool_calls
            ] if self.tool_calls else None,
            "reasoning": self.reasoning,
            "reasoning_content": self.reasoning_content,
        }

    def dict(self) -> dict:
        return self.model_dump()


class _StreamChoice:
    def __init__(self, message: _StreamMessage, finish_reason: str = "stop"):
        self.message = message
        self.finish_reason = finish_reason


class _StreamResponse:
    def __init__(self, choices: List[_StreamChoice]):
        self.choices = choices


def load_llama_models(models_preset_path: str) -> list[str]:
    if not os.path.exists(models_preset_path):
        return LLAMA_MODELS

    try:
        config = configparser.ConfigParser()
        config.read(models_preset_path)
        models = [s for s in config.sections() if s != "*"]
        return models if models else LLAMA_MODELS
    except Exception as e:
        logger.warning(f"Erreur lecture {models_preset_path}: {e}, fallback liste statique")
        return LLAMA_MODELS


class LLMManager:
    def __init__(
        self,
        llama_server_path: str,
        port: int,
        host: str | None = "127.0.0.1",
        models_preset: str | None = None,
        log_file: str | None = None,
        models_max: int | None = 1,
        api_keys: list | None = None,
        wait_timeout: int | float = 120,
        sync: bool = False,
    ):
        if not os.path.exists(llama_server_path):
            raise RuntimeError("LLama server path is required")

        self.llama_server_path = llama_server_path
        self.log_file = log_file if log_file else os.path.join(
            DEFAUlT_LLAMA_SERVER_DIR,
            f"llama_server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        if models_preset and not os.path.exists(models_preset):
            raise ValueError("Model preset file is getted but file don't exits")

        self.models_preset = models_preset or os.path.join(BASEDIR, "models.ini")
        self.llama_models = load_llama_models(self.models_preset)
        self.host = host or "127.0.0.1"
        self.port = port
        self.local_base_url = f"http://{self.host}:{self.port}"
        self.models_max = models_max if models_max is not None else 1
        if not isinstance(api_keys, (list, tuple, str)):
            raise ValueError("api key types is not acceptable")

        self.api_keys = list(api_keys) if not isinstance(api_keys, str) else [api_keys.split(",")]
        if not self.api_keys:
            raise ValueError("api_keys cannot be empty")
        
        if any(isinstance(key[0], (tuple, list)) or len(key) not in (2, 3) for key in self.api_keys):
            raise ValueError("Chaque élément doit être (model_name, api_key) ou (model_name, provider, api_key)")
        
        self.api_keys = [self.normalize_key_entry(e) for e in self.api_keys]
        self._keys = itertools.cycle(self.api_keys)
        self.wait_timeout = wait_timeout if wait_timeout is not None else 120
        self._sync = sync
        self._current_model_name: str | None = None
        self._current_api_key: str | None = None
        self._current_provider: str | None = None
        self._client: CLIENT_UNION = self._make_client()
        self._chat_history: List[Dict[str, str]] = []
        self._system_append: bool = False
        self._last_model: Optional[str] = None
        self._system_prompt: Optional[str] = None
        self._server_process: Optional[subprocess.Popen] = None
        self._lock = asyncio.Lock()
        
        # 🔔 Bus d'événements
        self.events = EventBus()
        self._key_lock = threading.Lock()

        self.start_server()
        if not self.wait_for_server(wait_timeout):
            raise RuntimeError("Server start failed")
        _run_async(
            self._validate_all_key,
            self.api_keys
        )
    
    def _get_next_key_pair(self) -> tuple[str, str, str | None]:
        with self._key_lock:
            return next(self._keys)
        
    @staticmethod
    def normalize_key_entry(entry: tuple | list):
        if len(entry) == 2:
            model_name, api_key = entry
            return (model_name, api_key, None)
        model_name, provider, api_key = entry
        return (model_name, api_key, provider)

    # =========================================================================
    # Méthodes publiques pour le bus d'événements
    # =========================================================================
    
    def on_stream(self, event: str, callback: Callable) -> Callable:
        """Abonnement PERMANENT à un évènement de streaming.
        Ex: mgr.on_stream("token_stream", lambda t, it: websocket.send(t))"""
        return self.events.on(event, callback)

    def off_stream(self, event: str, callback: Callable) -> None:
        self.events.off(event, callback)
        
    def on_event(self, event: str, callback: Callable) -> Callable:
        """S'abonne à un évènement du bus."""
        return self.events.on(event, callback)

    def off_event(self, event: str, callback: Callable) -> None:
        """Se désabonne d'un évènement."""
        self.events.off(event, callback)

    def once_event(self, event: str, callback: Callable) -> Callable:
        """S'abonne à un évènement pour une seule exécution."""
        return self.events.once(event, callback)

    def clear_events(self, event: Optional[str] = None) -> None:
        """Vide les abonnés d'un évènement."""
        self.events.clear(event)

    async def _fire_event(self, event: str, *args, **kwargs) -> None:
        """Émet un évènement sur le bus."""
        await self.events.emit(event, *args, **kwargs)

    # =========================================================================
    # Gestion des clés et des clients
    # =========================================================================

    def set_keys(self, api_keys):
        if not isinstance(api_keys, (list, tuple, str)):
            raise ValueError("api key types is not acceptable")
            
        if any(isinstance(key[0], (tuple, list)) or len(key) not in (2, 3) for key in api_keys):
            raise ValueError("Chaque élément doit être (model_name, api_key) ou (model_name, provider, api_key)")
            
        if not api_keys:
            raise ValueError("api_keys cannot be empty")
        
        self.api_keys = list(api_keys) if not isinstance(api_keys, str) else [api_keys.split(",")]
        self.api_keys = [self.normalize_key_entry(e) for e in self.api_keys]
        self._keys = itertools.cycle(self.api_keys)

    def _make_client(self, api_key: str | None = None, provider: str | None = None):
        if not api_key:
            model_name, api_key, provider = self._get_next_key_pair()
            self._current_api_key = api_key
            self._current_model_name = model_name
            self._current_provider = provider
        result = get_client(api_key, raise_=False, provider=provider)
        client_dict = result["client"]
        client_cls = client_dict["client_async_class"] if not self._sync else client_dict["client_sync_class"]
        logger.info(f"Client créer pour {api_key[:6]}{'...' if len(api_key) > 6 else ''}, client {client_dict['name']}")
        kwargs = dict(client_dict["init_kwargs"])
        kwargs.setdefault("api_key", "")
        kwargs["api_key"] = api_key
    
        if result.get("prefix") == "local":
            kwargs["base_url"] = urljoin(self.local_base_url, "v1")
        elif not kwargs.get("base_url"):
            kwargs.pop("base_url", None)
    
        return client_cls(**kwargs)

    def _rotate(self):
        self._client = self._make_client()

    # =========================================================================
    # Validation des clés
    # =========================================================================

    async def list_available_models(self, api_key: str | None = None, provider: str | None = None) -> list[str]:
        owns_client = api_key is not None
        client = self._make_client(api_key=api_key, provider=provider) if api_key else self._client
        ids = []
        try:
            method = client.models.list
            resp = (
                (await method()) 
                if asyncio.iscoroutinefunction(method) 
                else (await asyncio.to_thread(method))
            )
            if hasattr(resp, "__aiter__"):
                ids = [m.id async for m in resp]
            elif hasattr(resp, "data"):
                ids = [m.id for m in resp.data]
            else:
                ids = [m.id for m in resp]
        except Exception as e:
            logger.warning(f"Impossible de lister les modèles: {e}")
        
        finally:
            if owns_client:
                try:
                    (
                        (await client.close())
                        if asyncio.iscoroutinefunction(client.close) 
                        else (await asyncio.to_thread(client.close))
                    )
                except Exception:
                    pass
        return ids
    
    async def _validate_user_key(self, api_key: str, model_name: str, provider: str | None = None) -> tuple[bool, str]:
        result = get_client(api_key, raise_=False, provider=provider)
        client_dict = result["client"]
        skip_model_list = client_dict.get("skip_model_list", False)
    
        if not skip_model_list:
            try:
                available = await self.list_available_models(api_key=api_key, provider=provider)
            except Exception as e:
                return False, f"Clé invalide ou erreur d'auth: {e}"
            if not available:
                return False, "Impossible de récupérer la liste des modèles (clé invalide ?)"
            if model_name not in available:
                return False, f"Modèle '{model_name}' non disponible pour cette clé"
            return True, "ok"
    
        client = self._make_client(api_key=api_key, provider=provider)
        try:
            method = client.chat.completions.create
            kwargs = dict(model=model_name, messages=[{"role": "user", "content": "hi"}], max_tokens=1)
            resp = (
                (await method(**kwargs)) if asyncio.iscoroutinefunction(method)
                else (await asyncio.to_thread(method, **kwargs))
            )
            return (True, "ok (validé via chat.completions)") if resp and getattr(resp, "choices", None) \
                else (False, "Réponse vide lors de la validation par chat.completions")
        except Exception as e:
            return False, f"Clé invalide ou erreur d'auth (fallback chat.completions): {e}"
    
    async def validate_user_key(self, api_key: str, model_name: str, provider: str | None = None, raise_: bool = True) -> tuple[bool, str]:
        available, msg = await self._validate_user_key(api_key=api_key, model_name=model_name, provider=provider)
        if available:
            return available, msg
        if raise_:
            raise ValueError(msg)
        return available, msg
    
    async def _validate_all_key(self, paires: list[tuple[str, str, str | None]]) -> tuple[bool, str]:
        if not paires:
            return True
        
        result = await asyncio.gather(
            *[
                self.validate_user_key(api_key, model_name, provider=provider, raise_=True)
                for model_name, api_key, provider in paires
            ],
            return_exceptions=True
        )
        errors = []
        for (model_name, api_key, provider), res in zip(paires, result):
            if isinstance(res, Exception):
                errors.append(f"{model_name} {api_key[:8]}... : {res}")
            else:
                ok, msg = res
                if not ok:
                    errors.append(f"{model_name} {api_key[:8]}... : {msg}")
        if errors:
            raise ValueError("Clés invalides détectés:\n" + "\n".join(errors))
        return True, "ok"
    
    async def _exec_callback(self, callback: Optional[Callable], *args, **kwargs) -> None:
        if callback is None:
            return

        try:
            if asyncio.iscoroutinefunction(callback):
                result = await callback(*args, **kwargs)
            else:
                result = callback(*args, **kwargs)
            
            if asyncio.iscoroutine(result):
                result = await result
            
            return result
        except Exception as e:
            logger.warning(f"[Callback] Erreur: {e}")

    # =========================================================================
    # Serveur llama.cpp
    # =========================================================================

    def start_server(self) -> subprocess.Popen:
        log_fd = open(self.log_file, "w")

        cmd = [
            self.llama_server_path,
            "--models-preset", self.models_preset,
            "--host", self.host,
            "--port", str(self.port),
            "--jinja",
            "--models-max", str(self.models_max),
        ]
        if self.api_keys:
            cmd.extend(["--api-key", ",".join([key[1] for key in self.api_keys])])
        self._server_process = subprocess.Popen(cmd, stdout=log_fd, stderr=log_fd)
        return self._server_process

    def stop_server(self, timeout: float = 5) -> None:
        if self._server_process is None:
            return
        if self._server_process.poll() is not None:
            self._server_process = None
            return
        self._server_process.terminate()
        try:
            self._server_process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._server_process.kill()
            self._server_process.wait(timeout=timeout)
        self._server_process = None

    def wait_for_server(self, timeout=120) -> bool:
        print("⏳ Attente du serveur", end="", flush=True)
        start = time.time()
        url = urljoin(self.local_base_url, "v1/models")
        while time.time() - start < timeout:
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    print(" ✅")
                    return True
            except requests.RequestException:
                pass
            print(".", end="", flush=True)
            time.sleep(2)
        print(" ❌")
        return False

    # =========================================================================
    # EXECUTE TOOL AVEC CALLBACKS (sync/async)
    # =========================================================================

    async def execute_tool(
        self,
        tool_map: dict,
        name: str,
        args: dict,
        call_id: str | None = None,         
        on_before: Optional[OnBeforeTool] = None,
        on_after: Optional[OnAfterTool] = None,
        on_error: Optional[OnToolError] = None,
    ) -> str:
        await self._exec_callback(on_before, name, args, call_id)       
        await self._fire_event("tool_exec_before", name, args, call_id)   
 
        if name not in tool_map:
            result = f"❌ Outil inconnu : {name}"
            await self._exec_callback(on_error, name, args, ValueError(result), call_id)
            await self._fire_event("tool_exec_error", name, args, ValueError(result), call_id)
            return result
 
        try:
            func = tool_map[name]
            if asyncio.iscoroutinefunction(func):
                result = await func(**args)
            else:
                result = func(**args)
        except Exception as e:
            result = f"❌ Erreur outil {name}: {e}"
            await self._exec_callback(on_error, name, args, e, call_id)
            await self._fire_event("tool_exec_error", name, args, e, call_id)
            return result
 
        await self._exec_callback(on_after, name, args, result, call_id)
        await self._fire_event("tool_exec_after", name, args, result, call_id)
 
        return result

    
    # =========================================================================
    # 🌊 STREAMING
    # =========================================================================

    def _normalize_stream_chunk(self, raw_chunk: Any, provider_family: str) -> List[dict]:
        """
        Traduit UN chunk brut (OpenAI-compatible ou Anthropic) en 0..N évènements
        normalisés, indépendants du provider :
            {"type": "text_delta", "text": "..."}
            {"type": "reasoning_delta", "text": "..."}
            {"type": "tool_call_delta", "index": 0, "id": "..."|None, "name": "..."|None, "arguments_delta": "..."}
            {"type": "stop", "finish_reason": "stop"|"tool_calls"|"tool_use"|...}
        """
        events: List[dict] = []

        if provider_family == "anthropic":
            etype = getattr(raw_chunk, "type", None)

            if etype == "content_block_start":
                block = getattr(raw_chunk, "content_block", None)
                if block is not None and getattr(block, "type", None) == "tool_use":
                    events.append({
                        "type": "tool_call_delta",
                        "index": getattr(raw_chunk, "index", 0),
                        "id": getattr(block, "id", None),
                        "name": getattr(block, "name", None),
                        "arguments_delta": "",
                    })

            elif etype == "content_block_delta":
                delta = getattr(raw_chunk, "delta", None)
                dtype = getattr(delta, "type", None)
                if dtype == "text_delta":
                    text = getattr(delta, "text", "") or ""
                    if text:
                        events.append({"type": "text_delta", "text": text})
                elif dtype == "thinking_delta":
                    thinking = getattr(delta, "thinking", "") or ""
                    if thinking:
                        events.append({"type": "reasoning_delta", "text": thinking})
                elif dtype == "input_json_delta":
                    partial = getattr(delta, "partial_json", "") or ""
                    events.append({
                        "type": "tool_call_delta",
                        "index": getattr(raw_chunk, "index", 0),
                        "id": None,
                        "name": None,
                        "arguments_delta": partial,
                    })
            
            elif etype == "message_delta":
                delta = getattr(raw_chunk, "delta", None)
                stop_reason = getattr(delta, "stop_reason", None)
                if stop_reason:
                    finish_reason = "stop" if stop_reason == "end_turn" else stop_reason 
                    events.append({"type": "stop", "finish_reason": finish_reason})

        else:  # openai-compatible (OpenAI, Groq, OpenRouter, llama.cpp local...)
            choices = getattr(raw_chunk, "choices", None)
            if not choices:
                return events
            choice = choices[0]
            delta = getattr(choice, "delta", None)

            if delta is not None:
                content = getattr(delta, "content", None)
                if content:
                    events.append({"type": "text_delta", "text": content})

                reasoning = getattr(delta, "reasoning_content", None) or getattr(delta, "reasoning", None)
                if reasoning:
                    events.append({"type": "reasoning_delta", "text": reasoning})

                tool_calls = getattr(delta, "tool_calls", None)
                if tool_calls:
                    for tc in tool_calls:
                        fn = getattr(tc, "function", None)
                        events.append({
                            "type": "tool_call_delta",
                            "index": getattr(tc, "index", 0) or 0,
                            "id": getattr(tc, "id", None),
                            "name": getattr(fn, "name", None) if fn else None,
                            "arguments_delta": (getattr(fn, "arguments", None) or "") if fn else "",
                        })

            finish_reason = getattr(choice, "finish_reason", None)
            if finish_reason:
                events.append({"type": "stop", "finish_reason": finish_reason})

        return events

    async def _stream_completion(
        self,
        client_chat_method: Callable,
        req_kwargs: dict,
        provider_family: str,
        iteration: int,
        on_stream_start: Optional[OnStreamStart] = None,
        on_stream_token: Optional[OnStreamToken] = None,
        on_stream_reasoning_token: Optional[OnStreamReasoningToken] = None,
        on_stream_tool_call_delta: Optional[OnStreamToolCallDelta] = None,
        on_stream_message: Optional[OnStreamMessage] = None,
    ) -> _StreamResponse:
        """
        Consomme un stream (OpenAI-compatible OU Anthropic, sync ou async client)
        et retourne, une fois terminé, une _StreamResponse ayant EXACTEMENT la
        même forme qu'une réponse non-streaming (choices[0].message.content,
        .tool_calls, .model_dump(), finish_reason...).

        Deux façons d'être notifié en temps réel pendant que ça coule :
          1. les callbacks on_stream_* passés à CET appel précis
          2. self.stream_events (StreamEventBus) — abonnements permanents,
             partagés entre tous les appels/agents
        """
        req_kwargs = {**req_kwargs, "stream": True}
        model_name = req_kwargs.get("model", "")

        await self._fire_event("start_stream", iteration, model_name)
        await self._exec_callback(on_stream_start, iteration, model_name)

        raw_stream = (
            (await client_chat_method(**req_kwargs))
            if asyncio.iscoroutinefunction(client_chat_method)
            else (await asyncio.to_thread(client_chat_method, **req_kwargs))
        )
        if asyncio.iscoroutine(raw_stream):
            raw_stream = await raw_stream

        content_parts: List[str] = []
        reasoning_parts: List[str] = []
        tool_calls_acc: Dict[int, _StreamToolCall] = {}
        finish_reason = "stop"

        async def _handle_event(ev: dict) -> None:
            nonlocal finish_reason
            etype = ev["type"]

            if etype == "text_delta":
                content_parts.append(ev["text"])
                await self._fire_event("token_stream", ev["text"], iteration)
                await self._exec_callback(on_stream_token, ev["text"], iteration)

            elif etype == "reasoning_delta":
                reasoning_parts.append(ev["text"])
                await self._fire_event("reasoning_token_stream", ev["text"], iteration)
                await self._exec_callback(on_stream_reasoning_token, ev["text"], iteration)

            elif etype == "tool_call_delta":
                idx = ev["index"]
                tc = tool_calls_acc.setdefault(idx, _StreamToolCall())
                if ev.get("id"):
                    tc.id = ev["id"]
                if ev.get("name"):
                    tc.function.name = ev["name"]
                if ev.get("arguments_delta"):
                    tc.function.arguments += ev["arguments_delta"]
                await self._fire_event("tool_call_delta_stream", ev, iteration)
                await self._exec_callback(on_stream_tool_call_delta, ev, iteration)

            elif etype == "stop":
                if ev.get("finish_reason"):
                    finish_reason = ev["finish_reason"]

        if hasattr(raw_stream, "__aiter__"):
            async for raw_chunk in raw_stream:
                for ev in self._normalize_stream_chunk(raw_chunk, provider_family):
                    await _handle_event(ev)

                    
        elif hasattr(raw_stream, "__iter__"):
            # Client synchrone : consommé dans un thread pour ne pas bloquer
            # la boucle asyncio. Trade-off assumé : les évènements sont donc
            # livrés d'un bloc une fois le stream réseau terminé (pas de vrai
            # temps réel token-par-token), mais l'ordre et le contenu restent
            # corrects. Pour du vrai streaming temps réel, utilise sync=False.
            def _consume() -> List[dict]:
                evs: List[dict] = []
                for raw_chunk in raw_stream:
                    evs.extend(self._normalize_stream_chunk(raw_chunk, provider_family))
                return evs

            for ev in await asyncio.to_thread(_consume):
                await _handle_event(ev)
        else:
            raise TypeError(
                "La réponse en streaming n'est ni itérable ni async-itérable "
                f"(type reçu: {type(raw_stream)!r})"
            )

        if tool_calls_acc and finish_reason == "stop":
            finish_reason = "tool_calls"

        message = _StreamMessage(
            content="".join(content_parts),
            tool_calls=[tool_calls_acc[i] for i in sorted(tool_calls_acc)],
            reasoning="".join(reasoning_parts) or None,
        )

        await self._fire_event("message_stream", message.model_dump(), iteration)
        await self._exec_callback(on_stream_message, message.model_dump(), iteration)

        return _StreamResponse(choices=[_StreamChoice(message=message, finish_reason=finish_reason)])

    def _normalize_anthropic_response(self, response: Any) -> _StreamResponse:
        """
        🩹 Fix : une vraie réponse du client Anthropic (`messages.create` SANS
        stream) n'a pas de `.choices` — elle a `.content` (liste de blocs
        text/tool_use/thinking) et `.stop_reason`. Le reste de run_agent
        (traitement des tool_calls, model_dump, etc.) suppose la forme
        OpenAI-like `.choices[0].message...`. On convertit donc ici vers la
        même façade _StreamMessage/_StreamChoice utilisée pour le streaming,
        pour que le code en aval marche à l'identique quel que soit le
        provider.
        """
        content_parts: List[str] = []
        reasoning_parts: List[str] = []
        tool_calls: List[_StreamToolCall] = []

        for block in getattr(response, "content", None) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                content_parts.append(getattr(block, "text", "") or "")
            elif btype == "thinking":
                reasoning_parts.append(getattr(block, "thinking", "") or "")
            elif btype == "tool_use":
                # response.content[i].input est déjà un dict Python (pas du
                # JSON brut comme chez OpenAI) -> on le sérialise pour rester
                # cohérent avec ce que json.loads() attend plus loin.
                tool_calls.append(_StreamToolCall(
                    id=getattr(block, "id", "") or "",
                    function=_StreamFunction(
                        name=getattr(block, "name", "") or "",
                        arguments=json.dumps(getattr(block, "input", {}) or {}, ensure_ascii=False),
                    ),
                ))

        stop_reason = getattr(response, "stop_reason", None) or "stop"
        # Anthropic ne renvoie jamais littéralement "stop" pour une fin normale
        # (c'est "end_turn") -> on normalise pour coller à la logique existante
        # (`choice.finish_reason == "stop"`) sans avoir à la dupliquer.
        finish_reason = "stop" if stop_reason == "end_turn" else stop_reason

        message = _StreamMessage(
            content="".join(content_parts),
            tool_calls=tool_calls,
            reasoning="".join(reasoning_parts) or None,
        )
        return _StreamResponse(choices=[_StreamChoice(message=message, finish_reason=finish_reason)])

    def build_request_kwargs(
        self,
        provider_family: str,
        model_name: str,
        messages: List[Dict[str, str]],
        tools: List[Callable] | None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 300,
        seed: int = 42,
        stop: list | None = None,
        system: str | None = None,
        unsupported_params: list[str] | None = None
    ) -> dict:
        req_kwargs = dict(
            model=model_name,
            timeout=timeout,
            tools=tools
        )
        req_kwargs = {
            **req_kwargs, 
            **({"temperature": temperature} if 0 <= temperature <= 1 else {})
        }
        if provider_family == "anthropic":
            req_kwargs = {
                **req_kwargs,
                "messages": [m for m in messages if m["role"] != "system"],
                "system": system,
                "max_tokens": max_tokens if max_tokens and max_tokens >= 1 else 1024,  # jamais absent pour Anthropic
                **({"tools": tools, "tool_choice": {"type": "auto"}} if tools else {}),
                **({"stop_sequences": stop} if stop else {}),
            }
        else:  # openai-compatiblprovider: str | None = None,e
            req_kwargs = {
                **req_kwargs,
                "messages": messages,
                "seed": seed or 42,
                **({"tools": tools, "tool_choice": "auto"} if tools else {}),
                **({"temperature": temperature} if 0 <= temperature <= 1 else {}),
                **({"max_tokens": max_tokens} if max_tokens and max_tokens >= 1 else {}),
                **({"stop": stop} if stop else {}),
            }
        
        for p in (unsupported_params or []):
            req_kwargs.pop(p, None)
        return req_kwargs
    
    def _normalize_messages_for_anthropic(self, messages: list[dict]) -> list[dict]:
        """
        Anthropic a une structure légèrement différente pour les tool_results
        dans l'historique de conversation — on normalise ici.
        """
        normalized = []
        for msg in messages:
            if msg.get("role") == "tool":
                # Format OpenAI : {"role": "tool", "tool_call_id": "...", "content": "..."}
                # Format Anthropic attendu dans messages : {"role": "user", "content": [{"type": "tool_result", ...}]}
                normalized.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", ""),
                    }]
                })
            else:
                normalized.append(msg)
        return normalized

    # =========================================================================
    # RUN AGENT 
    # =========================================================================
    
    async def _process_single_tool(
        self,
        tool_call: Any,
        call_key: str,
        tool_mapping: dict,
        on_before: Optional[OnBeforeTool],
        on_after: Optional[OnAfterTool],
        on_error: Optional[OnToolError],
    ) -> dict:
        """
        Gère l'exécution isolée d'un seul outil pour permettre le gather sécurisé.
        Retourne toujours un dict contenant l'état de tracking et le message formaté.
        """
        tool_name = tool_call.function.name
        
        # État initial de tracking
        track_info = {
            "name": tool_name,
            "args_str": tool_call.function.arguments,
            "tool_call_id": tool_call.id,
            "args": {},
            "result": "",
            "started_at": time.time(),
            "ended_at": time.time(),
            "duration": 0,
            "success": False
        }
        
        # Message de base pour le LLM
        message_res = {
            "role": "tool",
            "tool_call_id": tool_call.id,
            "name": tool_name,
            "content": ""
        }

        # 1. Validation du JSON des arguments
        try:
            tool_args = json.loads(tool_call.function.arguments)
            if not isinstance(tool_args, dict):
                tool_args = {}
            track_info["args"] = tool_args
        except json.JSONDecodeError as e:
            tool_result = f"❌ Arguments invalides pour {tool_name}: {e}"
            track_info["result"] = tool_result
            track_info["ended_at"] = time.time()
            track_info["duration"] = track_info["ended_at"] - track_info["started_at"]
            
            await self._exec_callback(on_error, tool_name, {}, e)
            await self._fire_event("tool_exec_error", tool_name, {}, e)
            
            message_res["content"] = tool_result
            return {"call_key": call_key, "track_info": track_info, "message": message_res}

        # 2. Exécution de l'outil (execute_tool gère déjà ses propres callbacks/events)
        try:
            tool_result = await self.execute_tool(
                tool_map=tool_mapping,
                name=tool_name,
                args=tool_args,
                on_before=on_before,
                on_after=on_after,
                on_error=on_error,
                call_id=tool_call.id
            )
            track_info["success"] = True
            track_info["result"] = tool_result
        except Exception as e:
            # Sécurité absolue au cas où execute_tool laisserait passer une erreur
            tool_result = f"❌ Erreur critique inattendue : {e}"
            track_info["success"] = False
            track_info["result"] = tool_result
            await self._exec_callback(on_error, tool_name, tool_args, e)
            await self._fire_event("tool_exec_error", tool_name, tool_args, e)

        # 3. Finalisation des métriques et du résultat
        track_info["ended_at"] = time.time()
        track_info["duration"] = track_info["ended_at"] - track_info["started_at"]
        
        message_res["content"] = json.dumps(tool_result, default=str)
        
        return {"call_key": call_key, "track_info": track_info, "message": message_res}
    
    
    async def run_agent(
        self,
        model_name: str = None,
        api_key: str | None = None,
        provider: str | None = None,
        messages: Optional[List[dict]] = None,
        system: str | None = None,
        user: str | None = None,
        assistant: str | None = None,
        tools: List[Callable] | Callable = None,
        tool_mapping: Dict = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 300,
        seed: int = 42,
        stop: List | None = None,
        max_iter: int = 5,
        max_retries: int = 2,
        on_step: Optional[OnStep] = None,
        on_tool_call: Optional[OnToolCall] = None,
        on_finish: Optional[OnFinish] = None,
        on_error: Optional[OnAgentError] = None,
        on_retry: Optional[OnRetry] = None,
        on_tool_exec_before: Optional[OnBeforeTool] = None,
        on_tool_exec_after: Optional[OnAfterTool] = None,
        on_tool_exec_error: Optional[OnToolError] = None,
        show_reasoning: Optional[bool] = None,
        stream: bool = False,
        on_stream_start: Optional[OnStreamStart] = None,
        on_stream_token: Optional[OnStreamToken] = None,
        on_stream_reasoning_token: Optional[OnStreamReasoningToken] = None,
        on_stream_tool_call_delta: Optional[OnStreamToolCallDelta] = None,
        on_stream_message: Optional[OnStreamMessage] = None,
        *args, 
        **kwargs
    ) -> dict:
        
        if tools:
            if not tool_mapping:
                raise ValueError("Tool mapping is needed because tools is not None")
            
            if not isinstance(tool_mapping, dict):
                raise ValueError("Tool mapping should be a dictionnary")
            
            if isinstance(tools, list):
                if any(not callable(func) for func in tools):
                    raise ValueError("All tools should be callable")
                    
            elif callable(tools):
                tools = [tools]
            
            if any(name not in tool_mapping for name in (func.__name__ for func in tools)):
                missings = []
                for name in (func.__name__ for func in tools):
                    if name not in tool_mapping:
                        missings.append(name)
                        
                raise ValueError(
                    f"Tool mapping is not complete, some functions name are missing ({', '.join(missings)})"
                )
                
        model_name = model_name or self._current_model_name or "ornith1.0-9b"
        effective_api_key = self._current_api_key
        effective_provider = self._current_provider
        
        try:
            owns_client = bool(api_key)
            if api_key:
                active_client = self._make_client(api_key=api_key, provider=provider)
                effective_provider = provider
                effective_api_key = api_key
                await self.validate_user_key(api_key, model_name, raise_=True, provider=provider)
            else:
                active_client = self._client
                await self.validate_user_key(effective_api_key, model_name, raise_=True, provider=effective_provider)
            
    
            if not isinstance(messages, list) and messages is not None:
                raise ValueError(f"Messages types is not acceptable ({type(messages).__name__})")
                
            if messages is not None:
                msgs = messages.copy()
    
            else:
                msgs = []
                if system:
                    msgs.append({"role": "system", "content": system})
                if user:
                    msgs.append({"role": "user", "content": user})
                if assistant:
                    msgs.append({"role": "assistant", "content": assistant})
    
            if not msgs:
                raise ValueError("Au moins un message (messages, system, user, ou assistant) est requis")
    
            t_start = time.time()
            iteration = 0
            tool_calls_count = 0
            provider_family = "openai"
            steps: List[Dict] = []
            
            client_dict = get_client(effective_api_key, raise_=False, provider=effective_provider)["client"]
            unsupported = client_dict.get("unsupported_params", [])
            
            while iteration < max_iter:
                iteration += 1
    
                response = None
                model_unavailable = False
                break_retry = False
                step = {
                    "think": "",
                    "content": "",
                    "attempts": 1,
                    "attempts_error": {},
                    "tool_calls": {},
                    "started_at": time.time(),
                    "ended_at": time.time(),
                    "duration": 0,
                }
                step["ended_at"] = time.time()
                
                for attempt in range(max_retries + 1):
                    if break_retry:
                        break
                    try:
                        provider_family = (
                            "anthropic" if isinstance(
                                active_client, (Anthropic, AsyncAnthropic)
                            ) else "openai"
                        )
                        
                        req_kwargs = self.build_request_kwargs(
                            provider_family=provider_family,
                            system=system,
                            model_name=model_name,
                            messages=msgs,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            seed=seed,
                            timeout=timeout,
                            tools=build_tools(
                                funcs=tools or [],
                                provider_family=provider_family,
                            ),
                            unsupported_params=unsupported
                        )
                        try:
                            client_chat_method = active_client.chat.completions.create
                        except AttributeError:
                            try:
                                client_chat_method = active_client.messages.create
                            except AttributeError:
                                raise 
                            
                        if stream:
                            response = await self._stream_completion(
                                client_chat_method=client_chat_method,
                                req_kwargs=req_kwargs,
                                provider_family=provider_family,
                                iteration=iteration,
                                on_stream_start=on_stream_start,
                                on_stream_token=on_stream_token,
                                on_stream_reasoning_token=on_stream_reasoning_token,
                                on_stream_tool_call_delta=on_stream_tool_call_delta,
                                on_stream_message=on_stream_message,
                            )
                        else:
                            response = (
                                (await asyncio.to_thread(client_chat_method, **req_kwargs))
                                if not asyncio.iscoroutinefunction(client_chat_method) 
                                else (await client_chat_method(**req_kwargs))
                            )
                            if asyncio.iscoroutine(response):
                                response = await response
                            if response is not None and (not hasattr(response, "choices") or provider_family == "anthropic"):
                                response = self._normalize_anthropic_response(response)
                        
                        step["attempts"] = attempt
                        step["attempts_error"][attempt] = None
                        break
    
                    except Exception as e:
                        err = str(e).lower()
                        step["attempts"] = attempt
                        step["attempts_error"][attempt] = err
                        logger.warning(f"[LLM] Erreur (tentative {attempt+1}/{max_retries+1}): {e}")
                        
                        if any(x in err for x in ["rate", "limit", "429", "quota", "capacity"]):
                            if api_key:
                                logger.warning(f"⚠️  Rate limit [{model_name}] clé fournie — pas de rotation.")
                                break_retry = True
                                break
                            logger.warning(f"⚠️  Rate limit [{model_name}] — rotation pool système...")
                            
                            async with self._lock:
                                self._rotate()
                            active_client = self._client
                            model_name = self._current_model_name
                            await self.validate_user_key(self._current_api_key, model_name)
    
                        elif "model" in err and ("not found" in err or "deprecated" in err):
                            logger.warning(f"⚠️  Modèle {model_name} indisponible.")
                            model_unavailable = True
                            break_retry = True
                            await self._exec_callback(on_error, e, iteration, msgs)
                            await self._fire_event("error", e, iteration, msgs)
                            break
    
                        if attempt < max_retries and not model_unavailable:
                            await self._exec_callback(on_retry, attempt + 1, max_retries, e)
                            await self._fire_event("retry", attempt + 1, max_retries, e)
                            await asyncio.sleep(attempt + 1)
                            
                        elif not model_unavailable:
                            await self._exec_callback(on_error, e, iteration, msgs)
                            await self._fire_event("error", e, iteration, msgs)
                            step["ended_at"] = time.time()
                            step["duration"] = step["ended_at"] - step["started_at"]
                            steps.append(step)
                            return {
                                "response": f"ERREUR (après {max_retries+1} tentatives): {e}",
                                "total_time": time.time() - t_start,
                                "iterations": iteration,
                                "tool_calls": tool_calls_count,
                                "steps": steps,
                                "messages": msgs,
                                "success": False,
                                "error": str(e),
                            }
    
                if model_unavailable or response is None:
                    step["ended_at"] = time.time()
                    step["duration"] = step["ended_at"] - step["started_at"]
                    steps.append(step)
                    return {
                        "response": f"ERREUR: modèle {model_name} indisponible",
                        "total_time": time.time() - t_start,
                        "iterations": iteration,
                        "tool_calls": tool_calls_count,
                        "messages": msgs,
                        "steps": steps,
                        "success": False,
                        "error": f"model {model_name} unavailable",
                    }
                
                choice = response.choices[0]
    
                await self._exec_callback(on_step, iteration, msgs, response)
                await self._fire_event("step", iteration, msgs, response)
                
                reasoning = getattr(
                    choice.message, 
                    'reasoning', 
                    getattr(
                        choice.message,
                        "reasoning_content",
                        None
                    )
                )
                step["think"] = reasoning or ""
                step["content"] = (choice.message.content or "").strip()
                
                if show_reasoning and reasoning:
                    logger.info(f"🧠 RAISONNEMENT (itération {iteration}):\n{reasoning}\n\n")
    
                if choice.finish_reason == "stop" or not choice.message.tool_calls:
                    final = choice.message.content
                    if final and final.strip():
                        step["ended_at"] = time.time()
                        step["duration"] = step["ended_at"] - step["started_at"]
                        steps.append(step)
                        _args = (final.strip(), time.time() - t_start, iteration, tool_calls_count)
                        await self._exec_callback(on_finish, *_args)
                        await self._fire_event("finish", *_args)
    
                        return {
                            "response": final.strip(),
                            "total_time": time.time() - t_start,
                            "iterations": iteration,
                            "tool_calls": tool_calls_count,
                            "messages": msgs,
                            "steps": steps,
                            "success": True,
                            "error": None
                        }
                    else:
                        step["ended_at"] = time.time()
                        step["duration"] = step["ended_at"] - step["started_at"]
                        steps.append(step)
                        msgs.append({
                            "role": "user",
                            "content": "Donne ta réponse finale en français."
                        })
                        continue
    
                elif choice.message.tool_calls:
                    try:
                        message_dict = choice.message.model_dump()
                    except AttributeError:
                        message_dict = choice.message.dict()
                        
                    if message_dict.get("content") is None:
                        message_dict["content"] = ""
                    
                    tool_calls_list = message_dict.get("tool_calls", [])
                    await self._exec_callback(on_tool_call, tool_calls_list)
                    await self._fire_event("tool_call", tool_calls_list)
                    
                    for key in list(message_dict.keys()):
                        if key not in ("content", "role", "tool_calls"): #reasoning
                            message_dict.pop(key)
                    
                    msgs.append(message_dict)
                    tools_result = []
                    tool_calls = {}
                    tasks = []
                    
                    # Préparation de toutes les tâches à lancer en parallèle
                    for tool_call in choice.message.tool_calls:
                        tool_calls_count += 1
                        tool_name = tool_call.function.name
                        call_key = tool_call.id or f"{tool_name}_{tool_calls_count}"
                        
                        tasks.append(
                            self._process_single_tool(
                                tool_call=tool_call,
                                call_key=call_key,
                                tool_mapping=tool_mapping,
                                on_before=on_tool_exec_before,
                                on_after=on_tool_exec_after,
                                on_error=on_tool_exec_error
                            )
                        )
    
                    # 🔥 Exécution massive en parallèle
                    # return_exceptions=True garantit que si une task crash salement (hors de nos try/except),
                    # elle ne fera pas crasher le gather entier.
                    results = await asyncio.gather(*tasks, return_exceptions=True)
    
                    # Traitement des résultats
                    for res in results:
                        if isinstance(res, Exception):
                            # Cas extrême : l'exception a traversé toutes nos sécurités dans _process_single_tool
                            logger.error(f"[GATHER] Erreur critique non catchée sur un outil : {res}")
                            continue
                        
                        # On ré-intègre l'état de tracking et le message pour l'historique
                        tool_calls[res["call_key"]] = res["track_info"]
                        tools_result.append(res["message"])
    
                    # Normalisation finale selon le provider
                    msgs.extend(
                        self._normalize_messages_for_anthropic(
                            messages=tools_result
                        ) if provider_family == "anthropic" else tools_result
                    )
                    step["tool_calls"] = tool_calls
                    
                step["ended_at"] = time.time()
                step["duration"] = step["ended_at"] - step["started_at"]
                steps.append(step)
                
            await self._exec_callback(on_finish, "MAX ITERATIONS ATTEINT", time.time() - t_start, iteration, tool_calls_count)
            await self._fire_event("finish", "MAX ITERATIONS ATTEINT", time.time() - t_start, iteration, tool_calls_count)
    
            return {
                "response": "MAX ITERATIONS ATTEINT",
                "total_time": time.time() - t_start,
                "iterations": iteration,
                "tool_calls": tool_calls_count,
                "messages": msgs,
                "steps": steps,
                "success": False,
                "error": None,
            }
        
        finally:
            if owns_client and active_client is not None:
                try:
                    close_method = getattr(active_client, "close", None) or getattr(active_client, "aclose", None)
                    if close_method:
                        if asyncio.iscoroutinefunction(close_method):
                            await close_method()
                        else:
                            await asyncio.to_thread(close_method)
                except Exception:
                    pass
    
    def _clean_message(self, message_dict: dict) -> dict:
        allowed = {"role", "content", "tool_calls", "reasoning", "name", "tool_call_id"}
        cleaned = {}
        for key, value in message_dict.items():
            if key in allowed:
                cleaned[key] = value
        if "content" not in cleaned or cleaned["content"] is None:
            cleaned["content"] = ""
        return cleaned

    async def call(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> dict:
        result = await self.run_agent(
            user=prompt,
            system=system,
            **kwargs
        )
        return result

    def __call__(self, *args, **kwargs):
        return self.call(*args, **kwargs)

    async def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        model_name: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        tools: Optional[List[dict]] = None,
        tool_mapping: Optional[dict] = None,
        max_iter: int = 5,
        max_retries: int = 2,
        reset_history: bool = False,
        on_step: Optional[OnStep] = None,
        on_tool_call: Optional[OnToolCall] = None,
        on_finish: Optional[OnFinish] = None,
        on_error: Optional[OnAgentError] = None,
        on_retry: Optional[OnRetry] = None,
        on_tool_exec_before: Optional[OnBeforeTool] = None,
        on_tool_exec_after: Optional[OnAfterTool] = None,
        on_tool_exec_error: Optional[OnToolError] = None,
        show_reasoning: Optional[bool] = None,
        stream: bool = False,
        on_stream_start: Optional[OnStreamStart] = None,
        on_stream_token: Optional[OnStreamToken] = None,
        on_stream_reasoning_token: Optional[OnStreamReasoningToken] = None,
        on_stream_tool_call_delta: Optional[OnStreamToolCallDelta] = None,
        on_stream_message: Optional[OnStreamMessage] = None,
    ) -> Dict[str, Any]:
        if reset_history:
            self._chat_history = []
            self._system_append = False
            self._system_prompt = None
            self._last_model = None

        if model_name is None:
            model_name = self._last_model or self._current_model_name or "qwen2.5-3b"
        self._last_model = model_name

        if system and not self._system_append:
            self._system_prompt = system
            self._chat_history.append({
                "role": "system",
                "content": system
            })
            self._system_append = True
        elif system and self._system_append:
            for msg in self._chat_history:
                if msg["role"] == "system":
                    msg["content"] = system
                    self._system_prompt = system
                    break

        self._chat_history.append({
            "role": "user",
            "content": prompt
        })

        result = await self.run_agent(
            model_name=model_name,
            messages=self._chat_history.copy(),
            tools=tools,
            tool_mapping=tool_mapping,
            temperature=temperature,
            max_tokens=max_tokens,
            max_iter=max_iter,
            max_retries=max_retries,
            on_step=on_step,
            on_tool_call=on_tool_call,
            on_finish=on_finish,
            on_error=on_error,
            on_retry=on_retry,
            on_tool_exec_before=on_tool_exec_before,
            on_tool_exec_after=on_tool_exec_after,
            on_tool_exec_error=on_tool_exec_error,
            show_reasoning=show_reasoning,
            stream=stream,
            on_stream_start=on_stream_start,
            on_stream_token=on_stream_token,
            on_stream_reasoning_token=on_stream_reasoning_token,
            on_stream_tool_call_delta=on_stream_tool_call_delta,
            on_stream_message=on_stream_message,
        )

        if result.get("success"):
            self._chat_history.append({
                "role": "assistant",
                "content": result["response"]
            })
        else:
            self._chat_history.pop()

        return result

    def save_history(self, path: str) -> None:
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self._chat_history, f, indent=2, ensure_ascii=False)
            logger.info(f"Historique sauvegardé dans {path}")
        except Exception as e:
            logger.error(f"Erreur sauvegarde historique: {e}")

    def load_history(self, path: str) -> None:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self._chat_history = json.load(f)
            self._system_append = any(
                msg["role"] == "system" for msg in self._chat_history
            )
            if self._system_append:
                for msg in self._chat_history:
                    if msg["role"] == "system":
                        self._system_prompt = msg["content"]
                        break
            logger.info(f"Historique chargé depuis {path} ({len(self._chat_history)} messages)")
        except Exception as e:
            logger.error(f"Erreur chargement historique: {e}")

    def clear_history(self) -> None:
        self._chat_history = []
        self._system_append = False
        self._system_prompt = None
        logger.info("Historique vidé")

    def get_history(self) -> List[Dict[str, str]]:
        return self._chat_history.copy()

    def get_last_message(self) -> Optional[str]:
        for msg in reversed(self._chat_history):
            if msg["role"] == "assistant":
                return msg["content"]
        return None