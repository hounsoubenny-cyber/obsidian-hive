#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 15:45:00 2026

@author: hounsousamuel
"""

"""
agent.py — Agent Décisionnaire (Coralie) du système Obsidian.

Comme Alex, Coralie ne connaît ni ne construit jamais son propre LLMManager :
elle en reçoit une instance déjà configurée en injection de dépendance (voir
agents/analyst/agent.py pour la justification complète, identique ici).

Différence fondamentale avec Alex : Coralie n'a AUCUN contrat de type "doit
toujours conclure par tel tool". Elle est conversationnelle par nature — sa
sortie normale est du texte libre, éventuellement précédé d'appels de tools
pour vérifier des faits avant de répondre. Il n'y a donc pas de
NoReportProducedError équivalent ici : ne rien appeler comme tool et
répondre directement est un cas normal, pas une divergence.

Coralie ne persiste rien elle-même : charger l'historique d'une conversation
et sauvegarder le tour user+assistant (via ConversationManager.save_agent_turn)
est la responsabilité de l'appelant (la future route de chat), pas de cette
classe. Ça garde Coralie testable sans base de données, et cohérent avec le
fait qu'elle peut aussi être invoquée en mode "synthèse périodique" sans
conversation persistée du tout.
"""

import asyncio
import inspect
import logging
from pydantic import BaseModel, Field
from typing import Any, Awaitable, Callable, Optional, Union

from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.managers.report_manager import ReportManager
from obsidian_hive.agents.core.prompts.system import get_system_prompt
from obsidian_hive.agents.core.tools.tools import CoreTools
from obsidian_hive.config.config import CORE_CONFIG
from obsidian_hive.agents.shared.human_in_loop import Confirmer

logger = logging.getLogger("obsidian_coralie")

Callback = Union[Callable[..., None], Callable[..., Awaitable[None]]]


class CoralieResult(BaseModel):
    """Résultat d'un tour de conversation avec Coralie."""

    #: Réponse en texte libre de Coralie — c'est le cas normal, contrairement
    #: à Alex où response_text n'est qu'un cas de repli. Reste None seulement
    #: si le modèle a fini son run sans produire de texte final exploitable
    #: (ex: max_iter atteint en pleine investigation par tools).
    response_text: Optional[str] = Field(
        default=None,
        description="Réponse en texte libre de Coralie pour ce tour"
    )

    #: Résultat brut renvoyé par LLMManager.run_agent (steps détaillés par
    #: itération, utile pour MessageDB.steps côté ConversationManager, et
    #: pour le debug/logs : nombre d'itérations, temps total...).
    raw: dict = Field(default_factory=dict, description="Sortie brute du LLMManager")

    #: Liste de tous les tools appelés pour ce tour (peut être vide : une
    #: réponse conversationnelle simple n'a besoin d'aucun tool).
    all_tools: Optional[list] = Field(
        default=None,
        description="Liste des tools appelés durant ce tour"
    )
    max_iter_reached: bool =  Field(default=False, description="Nombre max d'iteration atteint")

    @property
    def success(self) -> bool:
        """True si Coralie a produit une réponse exploitable pour ce tour."""
        return self.response_text is not None

    def model_dump(self, *args, **kwargs):
        result = super().model_dump(*args, **kwargs)
        result["success"] = self.success
        return result


async def _maybe_await(callback: Optional[Callback], *args: Any) -> None:
    """Appelle callback(*args), qu'il soit sync ou async. No-op si None."""
    if callback is None:
        return
    result = callback(*args)
    if inspect.isawaitable(result):
        await result


class Coralie:
    """
    Agent Décisionnaire (Coralie) : vue d'ensemble du système ShieldAI, chat
    avec l'administrateur, exécution d'actions sur les assets, et synthèse
    cross-module de l'historique des rapports produits par Alex.
    """

    def __init__(
        self,
        llm_manager: LLMManager,
        job_manager: JobManager | None = None,
        engine: ObsidianEngine | None = None,
        report_manager: ReportManager | None = None,
        model_name: Optional[str] = None,
        tools_provider: Optional[CoreTools] = None,
        confirmer: Optional[Confirmer] = None,
        system_prompt: Optional[str] = None,
        max_iter: int = 20,
        max_retries: int = 2,
        temperature: float = 0.6,
        max_tokens: int = 32768,
    ):
        if llm_manager is None:
            raise ValueError(
                "llm_manager est requis — Coralie ne crée jamais le sien, "
                "il doit être injecté (voir docstring du module)."
            )
        
        self.llm_manager = llm_manager
        self.model_name = model_name
        self.system_prompt = system_prompt or get_system_prompt(mode="full")
        self.max_iter = max_iter
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_tokens = max_tokens

        self.tools_provider = tools_provider or CoreTools(
            job_manager=job_manager,
            engine=engine,
            report_manager=report_manager,
            confirmer=confirmer
        )
        if not isinstance(self.tools_provider, CoreTools):
            raise RuntimeError("Tool provider should be instance of CoreTools")
        self._llm_tools = self.tools_provider.get_llm_tools()
        self.tool_mapping = {func.__name__: func for func in self._llm_tools}
    
    def _validate_history(self, history: list[dict]) -> list[dict]:
        """
        Valide et nettoie un historique de conversation avant de le préfixer
        au system prompt + message courant. Retire toute entrée "system"
        (déjà géré par chat() lui-même) et rejette tout le reste dès qu'une
        entrée est malformée — jamais d'historique partiellement construit.
        """
        clean_history = []
        for i, turn in enumerate(history):
            try:
                role = str(turn["role"]).lower()
                content = turn["content"]
            except KeyError as e:
                raise ValueError(
                    f"Tour {i} de l'historique invalide : clé manquante ({e})"
                ) from e
    
            if role not in ("system", "assistant", "user"):  
                raise ValueError(
                    f"Tour {i} de l'historique a un rôle invalide : {role!r}"
                )
    
            if not isinstance(content, str) or not content.strip():
                raise ValueError(
                    f"Tour {i} de l'historique a un content invalide ou vide"
                )
    
            if role == "system":
                logger.debug("Entrée 'system' ignorée dans history (tour %d)", i)
                continue
    
            clean_history.append({"role": role, "content": content})
    
        return clean_history
        
    async def chat(
        self,
        message: str,
        *,
        history: Optional[list[dict]] = None,
        model_name: Optional[str] = None,
        max_iter: Optional[int] = None,
        max_retries: Optional[int] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        on_step: Optional[Callback] = None,
        on_tool_call: Optional[Callback] = None,
        on_finish: Optional[Callback] = None,
        on_error: Optional[Callback] = None,
        on_retry: Optional[Callback] = None,
        on_tool_exec_before: Optional[Callback] = None,
        on_tool_exec_after: Optional[Callback] = None,
        on_tool_exec_error: Optional[Callback] = None,
        show_reasoning: Optional[bool] = None,
        stream: bool = False,
        on_stream_start: Optional[Callback] = None,
        on_stream_token: Optional[Callback] = None,
        on_stream_reasoning_token: Optional[Callback] = None,
        on_stream_tool_call_delta: Optional[Callback] = None,
        on_stream_message: Optional[Callback] = None,
        **run_agent_kwargs: Any,
    ) -> CoralieResult:
        """
        Fait traiter un message par Coralie et retourne sa réponse.

        Args:
            message: Le message de l'administrateur pour ce tour.
            history: Historique de conversation déjà existant, au format
                [{"role": "user"|"assistant"|"tool", "content": ...}, ...]
                — typiquement chargé par l'appelant depuis
                ConversationManager avant d'appeler chat(). None pour un
                premier tour, ou pour un usage hors conversation persistée
                (ex: synthèse périodique ponctuelle).
            **run_agent_kwargs: tout kwarg supplémentaire accepté par
                LLMManager.run_agent (ex: seed, stop, api_key...).

        Returns:
            CoralieResult avec la réponse texte, le résultat brut du
            LLMManager (pour persistance des steps côté appelant), et la
            liste des tools utilisés pour ce tour.

        Note:
            Ne persiste rien : c'est à l'appelant de sauvegarder le tour
            (user + assistant) via ConversationManager.save_agent_turn une
            fois la réponse obtenue.
        """
        tools_used: set[str] = set()

        async def _on_tool_after(name: str, args: dict, result: Any, call_id = None) -> None:
            if name:
                tools_used.add(name)
            await _maybe_await(on_tool_exec_after, name, args, result, call_id)

        msgs = [{"role": "system", "content": self.system_prompt}]
        if history:
            msgs.extend(self._validate_history(history))
        msgs.append({"role": "user", "content": message})
        
        run_agent_kwargs.setdefault("timeout", 2 * 3600)
        raw_result = await self.llm_manager.run_agent(
            model_name=model_name or self.model_name,
            messages=msgs,
            system=self.system_prompt,
            tools=self._llm_tools,
            tool_mapping=self.tool_mapping,
            temperature=temperature if temperature is not None else self.temperature,
            max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
            max_iter=max_iter if max_iter is not None else self.max_iter,
            max_retries=max_retries if max_retries is not None else self.max_retries,
            on_step=on_step,
            on_error=on_error,
            on_finish=on_finish,
            on_retry=on_retry,
            on_tool_call=on_tool_call,
            on_tool_exec_before=on_tool_exec_before,
            on_tool_exec_after=_on_tool_after,
            on_tool_exec_error=on_tool_exec_error,
            show_reasoning=show_reasoning,
            stream=stream,
            on_stream_message=on_stream_message,
            on_stream_reasoning_token=on_stream_reasoning_token,
            on_stream_start=on_stream_start,
            on_stream_token=on_stream_token,
            on_stream_tool_call_delta=on_stream_tool_call_delta,
            **run_agent_kwargs,
        )

        result = CoralieResult(
            response_text=raw_result.get("response"),
            raw=raw_result,
            all_tools=list(tools_used) or None,
            max_iter_reached=raw_result.get("max_iter_reached")
        )

        if not result.success:
            logger.warning(
                "Coralie a terminé ce tour sans texte de réponse "
                "(iterations=%s, tool_calls=%s, tools_used=%s)",
                raw_result.get("iterations"),
                raw_result.get("tool_calls"),
                result.all_tools,
            )

        return result

    def chat_sync(self, message: str, **kwargs: Any) -> CoralieResult:
        """
        Version synchrone de chat(), pratique hors d'un event loop (script
        CLI, tests). Réutilise l'utilitaire déjà employé pour Alex.
        """
        from modules_utils.loop_utils import _run_async

        return _run_async(self.chat, message, **kwargs)


def create_coralie(
    llm_manager: LLMManager,
    job_manager: JobManager | None = None,
    engine: ObsidianEngine | None = None,
    report_manager: ReportManager | None = None,
    confirmer: Optional[Confirmer] = None,
    overrides: Optional[dict] = None,
) -> Coralie:
    """
    Crée une instance de Coralie avec une configuration par défaut.

    Note : `confirmer` n'est volontairement PAS dans CORE_CONFIG/overrides
    comme les autres réglages — c'est un objet vivant (ex: WSConfirmer
    attaché à une connexion WS), pas une valeur de config statique.
    CoreTools lève une erreur si confirmer est None, donc il faut le
    fournir dès lors que Coralie doit pouvoir exécuter des tools sensibles.
    """
    config = CORE_CONFIG.copy()
    if overrides:
        config.update(overrides)

    return Coralie(
        llm_manager=llm_manager,
        job_manager=job_manager,
        engine=engine,
        report_manager=report_manager,
        confirmer=confirmer,
        model_name=config["model_name"],
        system_prompt=get_system_prompt(config["system_prompt_mode"]),
        max_iter=config["max_iter"],
        max_retries=config["max_retries"],
        max_tokens=config["max_tokens"],
        temperature=config["temperature"],
    )