#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 13:23:15 2026

@author: hounsousamuel
"""

"""
Utilitaire partagé entre agents (Alex, Coralie, futurs agents) pour fabriquer
une documentation complète d'un tool à la demande, via get_info_about_tool.

Principe : combiner deux sources qui ne doivent JAMAIS être fusionnées à la
main dans un seul gros dict statique, pour éviter le drift entre le code
réel et sa doc :

  1. La partie MÉCANIQUE (nom, description, schéma des args, required/
     optional/defaults) — générée à la volée depuis le @entry_model et la
     docstring de la fonction, via function_to_generic_schema (déjà utilisé
     par tool_builder.py pour construire les tools au format OpenAI/Anthropic).
     Comme c'est lu directement sur la fonction au moment de l'appel, ça ne
     peut pas se désynchroniser du code : si tu changes un arg, la doc suit.

  2. La partie NARRATIVE (use_case, impact, warnings, examples) — ne peut
     PAS se déduire du code (aucune fonction Python ne "sait" qu'elle est
     "destructive" ou dans quel contexte l'utiliser) — donc écrite à la main
     dans un dict TOOL_DOCS propre à chaque agent (agents/core/tools/tool_docs.py
     pour Coralie, agents/analyst/tools/tool_docs.py pour Alex).
"""

from typing import Callable
from obsidian_hive.core.managers.llm_managers.tool_builder import function_to_generic_schema

# Valeurs par défaut si un tool existe dans le code mais n'a pas encore
# d'entrée dans le TOOL_DOCS de l'agent — signale le trou plutôt que de
# renvoyer silencieusement une doc vide.
_MISSING_DOC = "⚠️ Non documenté — à compléter dans tool_docs.py"


def describe_tool(func: Callable, tool_docs: dict, name: str | None = None) -> dict:
    """
    Construit la doc complète d'un tool : mécanique (auto, fiable) +
    narrative (curée à la main, peut être incomplète).

    Args:
        func: la fonction/méthode réelle du tool (peut être décorée @entry_model).
        tool_docs: le dict TOOL_DOCS propre à l'agent (clé = nom canonique du tool).
        name: nom canonique du tool à utiliser pour le lookup dans tool_docs et
            pour le champ "name" du résultat. Si None, on retombe sur
            func.__name__ (schema["name"]) — MAIS attention : pour des tools
            dont le nom réel diffère du nom exposé (ex: CoreTools suffixe ses
            méthodes en "_core_tool" puis les expose sans suffixe dans
            self.tools), func.__name__ != nom canonique. Toujours passer name
            explicitement dans ce genre de cas.
    """
    schema = function_to_generic_schema(func)
    canonical_name = name or schema["name"]
    curated = tool_docs.get(canonical_name, {})

    return {
        "name": canonical_name,
        "description": schema["description"],
        "parameters": schema["parameters"],
        "use_case": curated.get("use_case", _MISSING_DOC),
        "impact": curated.get("impact", _MISSING_DOC),
        "warnings": curated.get("warnings", []),
        "examples": curated.get("examples", []),
        "more_info": curated.get("more_info", "N/A"),
    }


def list_available_tools(tools_mapping: dict) -> list[str]:
    """Liste triée des noms de tools disponibles (pour messages d'erreur clairs)."""
    return sorted(tools_mapping.keys())