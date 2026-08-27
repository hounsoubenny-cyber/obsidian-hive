#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul  7 21:17:39 2026

@author: hounsousamuel
"""

"""
agent.py — Agent Analyst (Alex) du système Obsidian.

Alex ne connaît ni ne construit jamais son propre LLMManager : il en reçoit
une instance déjà configurée (clés API, pool de modèles, serveur llama...)
en injection de dépendance. Ça permet :
    - de partager un seul LLMManager (donc un seul pool de clés / rotation
      de modèles) entre plusieurs agents Obsidian tournant en parallèle ;
    - de tester Alex facilement en injectant un LLMManager mocké, sans
      jamais démarrer un vrai serveur ni valider de vraies clés API.

@author: hounsousamuel
"""

import json
import inspect
import asyncio
import logging
from pydantic import BaseModel, Field
from typing import Any, Awaitable, Callable, Optional, Union

from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
from obsidian_hive.config.config import ANALYST_CONFIG
from obsidian_hive.agents.analyst.prompts.system import get_system_prompt
from obsidian_hive.agents.analyst.tools.tools import MAPPING

logger = logging.getLogger("obsidian_analyst")

Callback = Union[Callable[..., None], Callable[..., Awaitable[None]]]


class NoReportProducedError(Exception):
    """
    Levée quand Alex termine son exécution sans avoir appelé create_report.

    C'est une violation de son contrat comportemental (voir system prompt :
    Alex doit TOUJOURS conclure par un rapport). Si ça arrive, c'est le
    signe d'une divergence du modèle — boucle sur les outils d'investigation
    sans conclure, max_iter atteint, ou tentative de réponse en texte libre
    au lieu d'un tool call.
    """


class AnalystResult(BaseModel):
    """Résultat d'une analyse effectuée par Alex."""

    #: Un ou plusieurs rapports capturés (normalement un seul, mais Alex
    #: peut en théorie appeler create_report plusieurs fois sur un contenu
    #: qui contient plusieurs findings distincts).
    reports: list[dict] = Field(default_factory=list, description="Liste des raports")

    #: Résultat brut renvoyé par LLMManager.run_agent (utile pour debug/logs :
    #: nombre d'itérations, temps total, historique complet des messages...).
    raw: dict = Field(default_factory=dict, description="Sortie brut dur llm manager")
    
    #: Réponse en texte libre d'Alex, uniquement pour le cas légitime où
    #: aucun outil n'a été utilisé (petite conversation, salutation...).
    #: Reste None dès qu'un tool a été appelé, même sans rapport final.
    response_text: Optional[str] = Field(
        default=None, 
        description="Réponse en texte libre de Alex si conversation sans tool"
    )
    
    #: Liste de tout les tools appelé pour cette réponse/analyse
    all_tools: Optional[list] = Field(
        default=None,
        description="Liste des tools appelés"
    )

    @property
    def report(self) -> Optional[dict]:
        """Le rapport final (cas normal : un seul rapport produit)."""
        return self.reports[-1] if self.reports else None

    @property
    def success(self) -> bool:
        return bool(self.reports)
    
    @property
    def is_conversational(self) -> bool:
        """True si Alex a répondu en texte libre légitime (pas de tool
        utilisé), plutôt que d'avoir produit un rapport structuré."""
        return not self.success and self.response_text is not None
    
    def model_dump(self, *args, **kwargs):
        result = super().model_dump(*args, **kwargs)
        result["success"] = self.success
        result["is_conversational"] = self.is_conversational
        result["report"] = self.report
        return result

async def _maybe_await(callback: Optional[Callback], *args: Any) -> None:
    """Appelle callback(*args), qu'il soit sync ou async. No-op si None."""
    if callback is None:
        return
    result = callback(*args)
    if inspect.isawaitable(result):
        await result


class Analyst:
    """
    Agent Analyst (Alex) : traduit un résultat brut (scan de vulnérabilités,
    événement IDS/IPS, sortie sandbox, code source...) en rapport structuré,
    avec proposition de fix si pertinent et si le code source est disponible.
    """

    #: Nom du tool qu'Alex DOIT appeler pour rendre sa réponse finale.
    REPORT_TOOL_NAME = "create_report"

    #: Tools qui modifient un fichier et renvoient un diff mécaniquement
    #: calculé (via difflib) dans leur résultat — ce diff est la seule
    #: source de vérité, jamais celui qu'Alex pourrait écrire à la main.
    DIFF_PRODUCING_TOOLS = {"replace_file_content", "modify_file_content"}
    
    MODIFIY_TOOL = "modify_file_content"
    
    #: Tools qui, s'ils réussissent, constituent une preuve mécanique qu'un
    #: fichier a réellement été modifié/créé — pas seulement "déclaré" par Alex.
    APPLIED_PRODUCING_TOOLS = {"create_file", "replace_file_content", "modify_file_content"}
    
    def __init__(
        self,
        llm_manager: LLMManager,
        model_name: Optional[str] = None,
        tool_mapping: Optional[dict[str, Callable]] = None,
        system_prompt: Optional[str] = None,
        max_iter: int = 8,
        max_retries: int = 2,
        temperature: float = 0.8,
        max_tokens: int = 32768,
    ):
        if llm_manager is None:
            raise ValueError(
                "llm_manager est requis — Analyst ne crée jamais le sien, "
                "il doit être injecté (voir docstring du module)."
            )

        self.llm_manager = llm_manager
        self.model_name = model_name
        self.tool_mapping = tool_mapping if tool_mapping is not None else MAPPING
        self.system_prompt = system_prompt or get_system_prompt(mode="full")
        self.max_iter = max_iter
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_tokens = max_tokens

        if self.REPORT_TOOL_NAME not in self.tool_mapping:
            raise ValueError(
                f"tool_mapping doit contenir {self.REPORT_TOOL_NAME!r} — "
                "Alex ne peut pas fonctionner sans son outil de rapport final."
            )

    async def analyze(
        self,
        content: str,
        *,
        source: Optional[str] = None,
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
    ) -> AnalystResult:
        """
        Fait analyser un contenu par Alex et retourne le(s) rapport(s)
        structuré(s) réellement produit(s) via l'outil create_report.

        Args:
            content: Le résultat brut à analyser (sortie du scanner de
                vulnérabilités, événement IDS/IPS, log, extrait de code...).
            source: Étiquette optionnelle indiquant l'origine du contenu
                (ex: "ids_ips", "scanner", "sandbox") — juste ajoutée
                en tête du message pour donner du contexte à Alex.
            on_tool_exec_after: callback optionnel de l'appelant — toujours
                déclenché en plus de la capture interne du rapport, jamais
                remplacé par elle.
            **run_agent_kwargs: tout kwarg supplémentaire accepté par
                LLMManager.run_agent (ex: seed, stop, api_key, messages...).

        Returns:
            AnalystResult contenant le(s) rapport(s) capturé(s) en
            interceptant l'appel réel à create_report — jamais le texte
            libre final, qu'Alex n'est de toute façon pas censé produire.

        Raises:
            NoReportProducedError: si Alex termine sans avoir appelé
            create_report — signale une divergence du modèle plutôt que
            de renvoyer silencieusement un résultat vide.

        """
        captured_reports: list[dict] = []
        # path -> diff calcule mecaniquement par le tool lui-meme (source de
        # verite), a ne jamais remplacer par un diff qu'Alex aurait pu ecrire
        # a la main dans son appel a create_report.
        captured_diffs: dict[str, str] = {}
        captured_lines: dict[str, dict[int, str]] = {}
        tools_used: set[str] = set()
        applied_paths: set[str] = set()

        async def _on_tool_after(name: str, args: dict, result: Any, call_id = None) -> None:
            if name:
                tools_used.add(name)
            
            if name in self.APPLIED_PRODUCING_TOOLS and isinstance(result, dict) and result.get("success"):
                path = result.get("path")
                if path:
                    applied_paths.add(path)
            
            if name == self.MODIFIY_TOOL and isinstance(result, dict) and result.get("success"):
                path = result.get("path")
                submitted_lines = args.get("lines")
                if path and submitted_lines:
                    captured_lines[path] = submitted_lines
                    
            if name == self.REPORT_TOOL_NAME and isinstance(result, dict):
                captured_reports.append(result)
                
            elif name in self.DIFF_PRODUCING_TOOLS and isinstance(result, dict):
                path = result.get("path")
                diff = result.get("diff")
                if path and diff is not None:
                    captured_diffs[path] = diff
            
            await _maybe_await(on_tool_exec_after, name, args, result, call_id)

        user_message = content if not source else f"[Source: {source}]\n\n{content}"
        tools = list(self.tool_mapping.values())

        raw_result = await self.llm_manager.run_agent(
            model_name=model_name or self.model_name,
            user=user_message,
            system=self.system_prompt,
            tools=tools,
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

        self._enforce_reliable_diffs(captured_reports, captured_diffs)
        self._enforce_applied_state(captured_reports, applied_paths)
        self._enforce_reliable_lines(captured_reports, captured_lines)
        tool_calls_made = raw_result.get("tool_calls", 0)
        result = AnalystResult(
            reports=captured_reports, 
            raw=raw_result,
            all_tools=list(tools_used) or None
        )
        
        if not result.success and tool_calls_made == 0:
            # Aucun tool utilisé : cas légitime de texte libre (petite
            # conversation, salutation, question générale) — pas une
            # violation. On garde la réponse brute, on ne lève rien.
            result.response_text = raw_result.get("response")
            return result
        
        if not result.success:
            # Au moins un tool a été utilisé (investigation entamée,
            # potentiellement échouée) mais aucun rapport n'a suivi —
            # ça, c'est une vraie violation du contrat comportemental.
            logger.warning(
                "Alex a terminé sans appeler %s (iterations=%s, success=%s, "
                "response=%r)",
                self.REPORT_TOOL_NAME,
                raw_result.get("iterations"),
                raw_result.get("success"),
                raw_result.get("response"),
            )
            raise NoReportProducedError(
                f"Alex n'a produit aucun rapport via {self.REPORT_TOOL_NAME} "
                f"(iterations={raw_result.get('iterations')}, "
                f"success={raw_result.get('success')})."
            )
        
        return result

    @staticmethod
    def _enforce_reliable_diffs(
        reports: list[dict], captured_diffs: dict[str, str]
    ) -> None:
        """
        Remplace, dans chaque rapport capturé, le diff que le champ
        fix_output.files[i].diff pourrait contenir par le diff réellement
        capturé lors de l'exécution des tools de modification.

        C'est volontairement destructif envers ce qu'Alex a pu écrire lui-
        même : le diff qu'il rédige à la main dans son tool call n'est
        qu'indicatif et peut contenir des erreurs de retranscription (lignes
        oubliées, contexte mal recopié...). Seul le diff calculé
        mécaniquement (via difflib, au moment de l'écriture réelle du
        fichier) fait foi.

        Ne modifie rien pour un fichier dont le path n'a pas été vu dans
        captured_diffs (ex: fix proposé mais pas encore appliqué — dans ce
        cas le diff écrit par Alex, même imparfait, reste la seule info
        disponible et n'est donc pas touché ici).
        """
        if not captured_diffs:
            return

        for report in reports:
            fix_output = report.get("fix_output")
            if not fix_output:
                continue

            files = fix_output.get("files") or []
            for fix_file in files:
                path = fix_file.get("path")
                if path in captured_diffs:
                    fix_file["diff"] = captured_diffs[path]
    
    @staticmethod
    def _enforce_reliable_lines(reports: list[dict], captured_lines: dict[str, dict]) -> None:
        if not captured_lines:
            return
        for report in reports:
            fix_output = report.get("fix_output")
            if not fix_output:
                continue
            for fix_file in fix_output.get("files") or []:
                path = fix_file.get("path")
                if path in captured_lines:
                    fix_file["lines"] = captured_lines[path]
                
    @staticmethod
    def _enforce_applied_state(reports: list[dict], applied_paths: set[str]) -> None:
        """
        Écrase fix_applied_tofile par la vérité mécanique (le chemin a-t-il
        vraiment été vu dans un tool de modification qui a réussi ?), jamais
        par ce qu'Alex a déclaré lui-même — même philosophie que
        _enforce_reliable_diffs pour les diffs.
        """
        for report in reports:
            fix_output = report.get("fix_output")
            if not fix_output:
                continue
    
            files = fix_output.get("files") or []
            for fix_file in files:
                fix_file["fix_applied_tofile"] = fix_file.get("path") in applied_paths
    
            fix_output["all_fix_applied"] = bool(files) and all(
                f["fix_applied_tofile"] for f in files
            )
            
    def analyze_sync(self, content: str, **kwargs: Any) -> AnalystResult:
        """
        Version synchrone de analyze(), pratique hors d'un event loop
        (script CLI, tests). Réutilise l'utilitaire déjà employé ailleurs
        dans le projet pour exécuter une coroutine de façon synchrone.
        """
        from modules_utils.loop_utils import _run_async

        return _run_async(self.analyze, content, **kwargs)



def create_alex(llm_manager: LLMManager, overrides: dict = None) -> Analyst:
    """Crée une instance d'Alex avec la configuration actuelle."""
    config = ANALYST_CONFIG.copy()
    if overrides:
        config.update(overrides)
    
    return Analyst(
        llm_manager=llm_manager,
        tool_mapping=MAPPING,
        system_prompt=get_system_prompt(config["system_prompt_mode"]),
        max_iter=config["max_iter"],
        max_retries=config["max_retries"],
        max_tokens=config["max_tokens"],
        temperature=config["temperature"],
        model_name=config["model_name"],
    )