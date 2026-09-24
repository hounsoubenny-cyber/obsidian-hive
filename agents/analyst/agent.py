#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 22 10:01:56 2026

@author: hounsousamuel
"""


"""
agent.py — Agent Analyst (Alex) du système Obsidian.

Alex opère dans un sandbox container via un WorkSpaceManager qui expose
un jeu réduit de tools shell-first. Ce module gère :
    - la délégation au LLMManager pour l'exécution de l'agent
    - l'interception des appels à create_report / export pour valider le
      contrat comportemental (export AVANT report, slot_keys cohérents)
    - l'enrichissement mécanique des fix_files avec les données d'export
      (diff, modified/new/delete, applied) — jamais déclaratif
"""

import copy
import inspect
import logging
from pydantic import BaseModel, Field
from typing import Any, Awaitable, Callable, Optional, Union

from obsidian_hive.core.managers.llm_managers.llm_manager import (
    LLMManager, ToolExecSpecialError,
)
from obsidian_hive.config.config import ANALYST_CONFIG
from obsidian_hive.agents.analyst.prompts.system import get_system_prompt
# from obsidian_hive.agents.analyst.analayst_workspace.workspace import (
#     WorkSpace,
# )
from obsidian_hive.agents.analyst.tools.tools import WorkSpaceManager

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

    reports: list[dict] = Field(
        default_factory=list,
        description="Liste des rapports capturés (normalement un seul).",
    )
    raw: dict = Field(
        default_factory=dict,
        description="Sortie brute du LLMManager (debug/logs).",
    )
    response_text: Optional[str] = Field(
        default=None,
        description="Réponse en texte libre si conversation sans tool.",
    )
    all_tools: Optional[list] = Field(
        default=None,
        description="Liste des tools appelés pour cette analyse.",
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
    avec proposition de fix si pertinent.

    Le mapping des tools est **dérivé du WorkSpaceManager** — pas de dict
    module-level. C'est le manager qui reste la source de vérité pour les
    noms exposés et les fonctions à exécuter.
    """

    #: Nom du tool de conclusion obligatoire.
    REPORT_TOOL_NAME = "create_report"

    #: Nom du tool qui matérialise les modifications sur l'hôte. Doit être
    #: appelé AVANT create_report si un fix est proposé.
    EXPORT_TOOL_NAME = "export"

    def __init__(
        self,
        llm_manager: LLMManager,
        workspace_manager: WorkSpaceManager,
        model_name: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_iter: int = 20,
        max_retries: int = 2,
        temperature: float = 0.6,
        max_tokens: int = 32768,
    ):
        if llm_manager is None:
            raise ValueError(
                "llm_manager est requis — Analyst ne crée jamais le sien, "
                "il doit être injecté."
            )
        if workspace_manager is None:
            raise ValueError(
                "workspace_manager est requis — Analyst ne crée jamais le "
                "sien, il doit être injecté (fournit tools + workspace)."
            )

        self.llm_manager = llm_manager
        self.workspace_manager = workspace_manager
        self.model_name = model_name
        self.system_prompt = system_prompt or get_system_prompt(mode="full")
        self.max_iter = max_iter
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._llm_tools = self.workspace_manager.get_llm_tools()
        self.tool_mapping = {func.__name__: func for func in self._llm_tools}

        if self.REPORT_TOOL_NAME not in self.tool_mapping:
            raise ValueError(
                f"Le WorkSpaceManager doit exposer {self.REPORT_TOOL_NAME!r} "
                "— l'Analyst ne peut pas fonctionner sans son outil de rapport."
            )
        if self.EXPORT_TOOL_NAME not in self.tool_mapping:
            raise ValueError(
                f"Le WorkSpaceManager doit exposer {self.EXPORT_TOOL_NAME!r} "
                "— l'Analyst ne peut pas matérialiser de fix sans lui."
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
            content: Le résultat brut à analyser.
            source: Étiquette optionnelle indiquant l'origine du contenu.
            **run_agent_kwargs: tout kwarg supplémentaire accepté par
                LLMManager.run_agent.

        Returns:
            AnalystResult contenant le(s) rapport(s) capturé(s) — jamais
            le texte libre final.

        Raises:
            NoReportProducedError: si Alex termine sans avoir appelé
                create_report (après avoir utilisé au moins un tool).
        """
        
        call_report_without_export_error = ToolExecSpecialError(
            "Tu dois appeler 'export' AVANT 'create_report'. "
            "Le rapport final décrit les fix appliqués à l'hôte — "
            "sans export préalable, aucun fichier n'a été écrit et "
            "ton rapport serait sans effet. Appelle d'abord "
            "export(all_slots=True) ou export(slot_keys=[...]) pour "
            "matérialiser tes modifications."
        )
        # ── État de la session d'analyse ─────────────────────────
        captured_reports: list[dict] = []
        tools_used: set[str] = set()
        # {slot_key: {filename: state}} — alimenté à chaque export réussi,
        # consommé pour enrichir les fix_files.
        files_state: dict[str, dict[str, dict]] = {}
        # True dès qu'un export a réussi — bloquant pour create_report.
        export_done = False

        # ── Callback BEFORE : garde-fou comportemental ───────────
        async def _on_tool_before(
            name: str, args: dict, call_id: str | None = None
        ) -> None:
            if name == self.REPORT_TOOL_NAME and not export_done:
                raise call_report_without_export_error
            await _maybe_await(on_tool_exec_before, name, args, call_id)

        # ── Callback AFTER : capture + validation + enrichissement ──
        async def _on_tool_after(
            name: str, args: dict, result: Any, call_id: str | None = None
        ) -> None:
            nonlocal export_done

            if name:
                tools_used.add(name)

            # ── Export réussi : on rapatrie les states ─────────
            if name == self.EXPORT_TOOL_NAME and isinstance(result, dict):
                if result.get("success"):
                    export_done = True
                    # On parcourt workspace_manager.files_state
                    # {slot_key: {fid: state}} et on reconstruit
                    # {slot_key: {filename: state}} pour lookup rapide.
                    for slot_key, slot_states in list((
                        self.workspace_manager.files_state or {}
                    ).items()):
                        # print("Export")
                        # print("slots states")
                        # print(slot_states)
                        if not isinstance(slot_states, dict):
                            continue
                        value = files_state.setdefault(slot_key, {})
                        # print("Values")
                        for state in slot_states.values():
                            print(state)
                            if not isinstance(state, dict):
                                continue
                            fname = state.get("filename")
                            if fname:
                                value[fname] = copy.deepcopy(state)

            # ── create_report : validation + enrichissement ────
            elif name == self.REPORT_TOOL_NAME and isinstance(result, dict):
                if not export_done:
                    raise call_report_without_export_error
                else:
                    fix_output = result.get("fix_output")
                    if fix_output:
                        error = self._validate_fix_output(fix_output, files_state)
                        if error:
                            raise ToolExecSpecialError(error)
                        self._ensure_diff([result], files_state, add_diff=False)
                    captured_reports.append(copy.deepcopy(result))
                    

            await _maybe_await(on_tool_exec_after, name, args, result, call_id)

        # ── Exécution de l'agent ────────────────────────────────
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
            on_tool_exec_before=_on_tool_before,
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

        self._ensure_diff(captured_reports, files_state)
        tool_calls_made = raw_result.get("tool_calls", 0)
        result = AnalystResult(
            reports=captured_reports,
            raw=raw_result,
            all_tools=list(tools_used) or None,
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

    # ═══════════════════════════════════════════════════════════
    # Helpers mécaniques
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _validate_fix_output(
        fix_output: dict,
        files_state: dict[str, dict[str, dict]],
    ) -> str | None:
        """
        Valide que chaque FixFile référence un slot_key connu et un
        filename présent dans cet export.

        Returns
        -------
        str | None
            Message d'erreur à renvoyer au LLM, ou None si tout est bon.
        """
        if not fix_output:
            return None
        
        files = fix_output.get("files") or []
        if not files:
            return None

        valid_keys = sorted(files_state.keys())

        for i, fix_file in enumerate(files):
            slot_key = fix_file.get("slot_key")
            if not slot_key:
                return (
                    f"fix_output.files[{i}] : 'slot_key' manquant. "
                    f"Chaque fix doit préciser dans quel slot il s'applique. "
                    f"Clés disponibles : {valid_keys}. "
                    f"Récupère-les via list_slots() ou depuis les clés "
                    f"retournées par export()."
                )
            if slot_key not in files_state:
                return (
                    f"fix_output.files[{i}] : slot_key {slot_key!r} inconnu. "
                    f"Clés valides : {valid_keys}."
                )
            path = fix_file.get("path")
            if not path:
                return (
                    f"fix_output.files[{i}] : 'path' manquant. "
                    f"C'est le chemin relatif du fichier dans son slot "
                    f"(ex: 'src/auth.py'), tel que retourné par export()."
                )
            if path not in files_state[slot_key]:
                available = sorted(files_state[slot_key].keys())
                return (
                    f"fix_output.files[{i}] : path {path!r} introuvable dans "
                    f"le slot {slot_key!r}. Chemins disponibles dans ce slot : "
                    f"{available}. Utilise EXACTEMENT le 'filename' retourné "
                    f"par export()."
                )

        return None

    @staticmethod
    def _ensure_diff(
        captured_reports: list[dict],
        files_state: dict[str, dict[str, dict]],
        add_diff: bool = True
    ) -> None:
        """
        Enrichit chaque FixFile avec les données mécaniques issues de
        l'export — jamais ce que le LLM a pu écrire à la main :

            - diff               : diff calculé par _export_slot (difflib)
            - new_file           : fichier créé dans le sandbox
            - delete_file        : fichier supprimé dans le sandbox
            - modified_file      : fichier modifié dans le sandbox
            - fix_applied_tofile : True si au moins un des trois ci-dessus

        Met aussi à jour ``fix_output.all_fix_applied`` : True s'il y a
        au moins un fichier ET que tous les fichiers sont appliqués.
        """
        for report in captured_reports:
            fix_output = report.get("fix_output")
            if not fix_output:
                continue
            
            files = fix_output.get("files") or []
            
            for fix_file in files:
                slot_key = fix_file.get("slot_key")
                path = fix_file.get("path")
    
                state = (files_state.get(slot_key) or {}).get(path)
                if state is None:
                    fix_file["fix_applied_tofile"] = False
                    continue
    
                fix_file["diff"] = state.get("diff", None) if add_diff else None
                fix_file["new_file"] = bool(state.get("new_file", False))
                fix_file["delete_file"] = bool(state.get("deleted", False))
                fix_file["modified_file"] = bool(state.get("modified", False))
                fix_file["fix_applied_tofile"] = (
                    fix_file["new_file"]
                    or fix_file["delete_file"]
                    or fix_file["modified_file"]
                    or (bool(fix_file["diff"]) if add_diff else False)
                )
    
            fix_output["all_fix_applied"] = bool(files) and all(
                f.get("fix_applied_tofile", False) for f in files
            )
            report["have_proposed_fix"] = bool(fix_output)

    def analyze_sync(self, content: str, **kwargs: Any) -> AnalystResult:
        """Version synchrone de analyze(), pratique hors event loop."""
        from modules_utils.loop_utils import _run_async
        return _run_async(self.analyze, content, **kwargs)


def create_alex(
    llm_manager: LLMManager,
    workspace_manager: WorkSpaceManager,
    overrides: dict = None,
) -> Analyst:
    """Crée une instance d'Alex avec la configuration actuelle."""
    config = ANALYST_CONFIG.copy()
    if overrides:
        config.update(overrides)

    return Analyst(
        llm_manager=llm_manager,
        workspace_manager=workspace_manager,
        system_prompt=get_system_prompt(config["system_prompt_mode"]),
        max_iter=config["max_iter"],
        max_retries=config["max_retries"],
        max_tokens=config["max_tokens"],
        temperature=config["temperature"],
        model_name=config["model_name"],
    )