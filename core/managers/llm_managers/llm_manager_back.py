#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 11 09:43:40 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 30 15:57:48 2026

@author: hounsousamuel
"""

import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", "..", ".."))))
import json
import time
import asyncio
import requests
import subprocess
import itertools
import configparser
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
    Callable[[str, dict], None],
    Callable[[str, dict], Awaitable[None]]
]
OnAfterTool = Union[
    Callable[[str, dict, str], None],
    Callable[[str, dict, str], Awaitable[None]]
]
OnToolError = Union[
    Callable[[str, dict, Exception], None],
    Callable[[str, dict, Exception], Awaitable[None]]
]

OnStep = Union[
    Callable[[int, List[dict], Any], None],
    Callable[[int, List[dict], Any], Awaitable[None]]
]
OnToolCall = Union[
    Callable[[List[Dict[str, str]]], None],
    Callable[[List[Dict[str, str]]], Awaitable[None]]
]
OnFinish = Union[
    Callable[[str, float, int, int], None],
    Callable[[str, float, int, int], Awaitable[None]]
]
OnAgentError = Union[
    Callable[[Exception, int, List[dict]], None],
    Callable[[Exception, int, List[dict]], Awaitable[None]]
]
OnRetry = Union[
    Callable[[int, int, Exception], None],
    Callable[[int, int, Exception], Awaitable[None]]
]

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
        
        if any(isinstance(key[0], (tuple, list)) or not len(key) == 2 for key in self.api_keys):
            raise ValueError("All element of api_key should be a list or tuple of two elements")
            
        self._keys = itertools.cycle(self.api_keys)
        self.wait_timeout = wait_timeout if wait_timeout is not None else 120
        self._sync = sync
        self._current_model_name = None
        self._current_api_key: str | None = None
        self._client: CLIENT_UNION = self._make_client()
        self._chat_history: List[Dict[str, str]] = []
        self._system_append: bool = False
        self._last_model: Optional[str] = None
        self._system_prompt: Optional[str] = None
        self._server_process: Optional[subprocess.Popen] = None
        self._lock = asyncio.Lock()
        # print(f"🔑 api_keys: {api_keys}")
        self.start_server()
        if not self.wait_for_server(wait_timeout):
            raise RuntimeError("Server start failed")
        _run_async(
            self._validate_all_key,
            self.api_keys
        )

    def set_keys(self, api_keys):
        if not isinstance(api_keys, (list, tuple, str)):
            raise ValueError("api key types is not acceptable")
        self.api_keys = list(api_keys) if not isinstance(api_keys, str) else [api_keys]
        if not self.api_keys:
            raise ValueError("api_keys cannot be empty")
        self._keys = itertools.cycle(self.api_keys)

    def _make_client(self, api_key: str | None = None):
        if not api_key:
            model_name, api_key = next(self._keys)
            self._current_api_key = api_key
            self._current_model_name = model_name
        result = get_client(api_key, raise_=False)
        client_dict = result["client"]
        client_cls = client_dict["client_async_class"] if not self._sync else client_dict["client_sync_class"]
        logger.info(f"Client créer pour {api_key[:100]}{'...' if len(api_key) > 6 else ''}, client {client_dict['name']}")
        kwargs = dict(client_dict["init_kwargs"])
        kwargs.setdefault("api_key", "")
        # if not kwargs.get("api_key"):
        kwargs["api_key"] = api_key
    
        if result.get("prefix") == "local":
            kwargs["base_url"] = urljoin(self.local_base_url, "v1")
        elif not kwargs.get("base_url"):
            kwargs.pop("base_url", None)
    
        return client_cls(**kwargs)

    def _rotate(self):
        self._client = self._make_client()

    async def list_available_models(self, api_key: str | None = None) -> list[str]:
        owns_client = api_key is not None
        client = self._make_client(api_key=api_key) if api_key else self._client
        ids = []
        try:
            method = client.models.list
            resp = (
                (await method()) 
                if asyncio.iscoroutinefunction(method) 
                else (await asyncio.to_thread(method))
            )
            # print(resp)
            if hasattr(resp, "__aiter__"):
                ids = [m.id async for m in resp]
            elif hasattr(resp, "data"):
                ids = [m.id for m in resp.data]
            else:
                ids = [m.id for m in resp]
        except Exception as e:
            logger.warning(f"Impossible de lister les modèles: {e}")
            # import traceback
            # traceback.print_exc()
        
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
    
    async def _validate_user_key(self, api_key: str, model_name: str) -> tuple[bool, str]:
        try:
            available = await self.list_available_models(api_key=api_key)
        except Exception as e:
            return False, f"Clé invalide ou erreur d'auth: {e}"
        if not available:
            return False, "Impossible de récupérer la liste des modèles (clé invalide ?)"
        if model_name not in available:
            return False, f"Modèle '{model_name}' non disponible pour cette clé"
        return True, "ok"
    
    async def validate_user_key(self, api_key: str, model_name: str, raise_: bool = True) -> tuple[bool, str]:
        available, msg = await self._validate_user_key(api_key=api_key, model_name=model_name)
        if available:
            return available, msg
        
        if raise_:
            raise ValueError(msg)
        
        return available, msg
    
    async def _validate_all_key(self, paires: list[tuple[str, str]]) -> tuple[bool, str]:
        if not paires:
            return True
        
        result = await asyncio.gather(
            *[
                self.validate_user_key(api_key, model_name, raise_=True)
                for model_name, api_key in paires
            ],
            return_exceptions=True
        )
        errors = []
        for (model_name, api_key), result in zip(paires, result):
            if isinstance(result, Exception):
                errors.append(f"{model_name} {api_key[:8]}... : {result}")
            
            else:
                ok, msg = result
                if not ok:
                    errors.append(f"{model_name} {api_key[:8]}... : {msg}")
        
        if errors:
            raise ValueError("Clés invalides détectés:\n" + "\n".join(errors))
    
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
        on_before: Optional[OnBeforeTool] = None,
        on_after: Optional[OnAfterTool] = None,
        on_error: Optional[OnToolError] = None,
    ) -> str:
        await self._exec_callback(on_before, name, args)

        if name not in tool_map:
            result = f"❌ Outil inconnu : {name}"
            await self._exec_callback(on_error, name, args, ValueError(result))
            return result

        try:
            func = tool_map[name]
            if asyncio.iscoroutinefunction(func):
                result = await func(**args)
            else:
                result = func(**args)
        except Exception as e:
            result = f"❌ Erreur outil {name}: {e}"
            await self._exec_callback(on_error, name, args, e)
            return result

        await self._exec_callback(on_after, name, args, result)

        return result
    
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
        else:  # openai-compatible
            req_kwargs = {
                **req_kwargs,
                "messages": messages,
                "seed": seed or 42,
                **({"tools": tools, "tool_choice": "auto"} if tools else {}),
                **({"temperature": temperature} if 0 <= temperature <= 1 else {}),
                **({"max_tokens": max_tokens} if max_tokens and max_tokens >= 1 else {}),
                **({"stop": stop} if stop else {}),
            }
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

    async def run_agent(
        self,
        model_name: str = None,
        api_key: str | None = None,
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
        
        if api_key:
            active_client = self._make_client(api_key=api_key)
            await self.validate_user_key(api_key, model_name, raise_=True)    
        else:
            active_client = self._client
            await self.validate_user_key(self._current_api_key, model_name, raise_=True)
    
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
        while iteration < max_iter:
            iteration += 1

            response = None
            model_unavailable = False
            break_retry = False
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
                            # default="openai"
                        )
                    )
                    try:
                        client_chat_method = active_client.chat.completions.create
                    except AttributeError:
                        try:
                            client_chat_method = active_client.messages.create
                        except AttributeError:
                            raise 
                        
                    response = (
                        (await asyncio.to_thread(client_chat_method, **req_kwargs))
                        if not asyncio.iscoroutinefunction(client_chat_method) 
                        else (await client_chat_method(**req_kwargs))
                    )
                    if asyncio.iscoroutine(response):
                        response = await response
                    # print(response)
                    break

                except Exception as e:
                    err = str(e).lower()
                    logger.warning(f"[LLM] Erreur (tentative {attempt+1}/{max_retries+1}): {e}")
                    import traceback
                    traceback.print_exc()
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
                        break

                    if attempt < max_retries and not model_unavailable:
                        await self._exec_callback(on_retry, attempt + 1, max_retries, e)
                        await asyncio.sleep(attempt + 1)
                        
                    elif not model_unavailable:
                        await self._exec_callback(on_error, e, iteration, msgs)
                        return {
                            "response": f"ERREUR (après {max_retries+1} tentatives): {e}",
                            "total_time": time.time() - t_start,
                            "iterations": iteration,
                            "tool_calls": tool_calls_count,
                            "messages": msgs,
                            "success": False,
                            "error": str(e),
                        }

            if model_unavailable or response is None:
                return {
                    "response": f"ERREUR: modèle {model_name} indisponible",
                    "total_time": time.time() - t_start,
                    "iterations": iteration,
                    "tool_calls": tool_calls_count,
                    "messages": msgs,
                    "success": False,
                    "error": f"model {model_name} unavailable",
                }
            
            choice = response.choices[0]

            await self._exec_callback(on_step, iteration, msgs, response)
            reasoning = getattr(
                choice.message, 
                'reasoning', 
                getattr(
                    choice.message,
                    "reasoning_content",
                    None
                )
            )
            if show_reasoning and reasoning:
                logger.info(f"🧠 RAISONNEMENT (itération {iteration}):\n{reasoning}")

            if choice.finish_reason == "stop" or not choice.message.tool_calls:
                final = choice.message.content
                if final and final.strip():
                    await self._exec_callback(on_finish, final.strip(), time.time() - t_start, iteration, tool_calls_count)

                    return {
                        "response": final.strip(),
                        "total_time": time.time() - t_start,
                        "iterations": iteration,
                        "tool_calls": tool_calls_count,
                        "messages": msgs,
                        "success": True,
                        "error": None
                    }
                else:
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
                
                await self._exec_callback(on_tool_call, message_dict.get("tool_calls", []))
                for key in list(message_dict.keys()):
                    if key not in ("content", "role", "reasoning", "tool_calls"):
                        message_dict.pop(key)
                
                msgs.append(message_dict)
                tools_result = []
                for tool_call in choice.message.tool_calls:
                    tool_calls_count += 1
                    tool_name = tool_call.function.name
                    try:
                        tool_args = json.loads(tool_call.function.arguments)
                        if not isinstance(tool_args, dict):
                            tool_args = {}
                    except json.JSONDecodeError as e:
                        tool_result = f"❌ Arguments invalides pour {tool_name}: {e}"
                        await self._exec_callback(on_tool_exec_error, tool_name, {}, e)
                        tools_result.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": tool_name,
                            "content": tool_result,
                        })
                        continue

                    tool_result = await self.execute_tool(
                        tool_map=tool_mapping,
                        name=tool_name,
                        args=tool_args,
                        on_after=on_tool_exec_after,
                        on_before=on_tool_exec_before,
                        on_error=on_tool_exec_error,
                    )
                    tool_result = json.dumps(tool_result, default=str)
                    tools_result.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_name,
                        "content": tool_result,
                    })
                msgs.extend(
                    self._normalize_messages_for_anthropic(
                        messages=tools_result
                    ) if provider_family == "anthropic" else tools_result
                )
        await self._exec_callback(on_finish, "MAX ITERATIONS ATTEINT", time.time() - t_start, iteration, tool_calls_count)

        return {
            "response": "MAX ITERATIONS ATTEINT",
            "total_time": time.time() - t_start,
            "iterations": iteration,
            "tool_calls": tool_calls_count,
            "messages": msgs,
            "success": False,
            "error": None,
        }
    
    def _clean_message(self, message_dict: dict) -> dict:
        """Nettoie un message pour le rendre compatible avec tous les providers."""
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