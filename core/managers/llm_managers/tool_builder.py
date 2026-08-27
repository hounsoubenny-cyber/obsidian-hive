#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul  6 08:09:35 2026

@author: hounsousamuel
"""

import inspect
from typing import get_type_hints, Callable

try:
    from docstring_parser import parse as parse_docstring
    HAS_DOCSTRING_PARSER = True
except ImportError:
    HAS_DOCSTRING_PARSER = False  # fallback si la lib n'est pas installée

TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}

def _extract_docstring_info(func) -> tuple[str, dict]:
    """Sépare le résumé général des descriptions par paramètre."""
    doc = inspect.getdoc(func) or ""

    if HAS_DOCSTRING_PARSER:
        parsed = parse_docstring(doc)
        summary = parsed.long_description or f"Fonction {func.__name__}"
        param_docs = {p.arg_name: p.description for p in parsed.params}
        return summary, param_docs

    # Fallback sans la lib : on prend juste ce qu'il y a avant "Args:"
    summary = doc.split("Args:")[0].strip() or f"Fonction {func.__name__}"
    return summary, {}


# def function_to_generic_schema(func: Callable) -> dict:
#     """Génère un schéma de tool générique (indépendant du provider) depuis une fonction Python."""
#     sig = inspect.signature(func)
#     hints = get_type_hints(func)
#     summary, param_docs = _extract_docstring_info(func)

#     properties, required = {}, []
#     for name, param in sig.parameters.items():
#         if name == "self":
#             continue
#         json_type = TYPE_MAP.get(hints.get(name, str), "string")
#         properties[name] = {
#             "type": json_type,
#             "description": param_docs.get(name, f"Paramètre {name}"),
#         }
#         if param.default is inspect.Parameter.empty:
#             required.append(name)

#     return {
#         "name": func.__name__,
#         "description": summary,
#         "parameters": {"type": "object", "properties": properties, "required": required},
#     }

def function_to_generic_schema(func: Callable) -> dict:
    """Génère un schéma de tool générique depuis une fonction Python.

    Si la fonction porte un __entry_model__ (via @entry_model), le schéma
    est généré à partir du vrai modèle Pydantic — fidèle, avec enums,
    objets imbriqués, dicts typés. Sinon, on retombe sur l'ancienne
    méthode par type hints bruts (types simples uniquement).
    """
    summary, param_docs = _extract_docstring_info(func)
    entry_model_cls = getattr(func, "__entry_model__", None)

    if entry_model_cls is not None:
        model_schema = entry_model_cls.model_json_schema()
        parameters = {
            "type": "object",
            "properties": model_schema.get("properties", {}),
            "required": model_schema.get("required", []),
        }
        if "$defs" in model_schema:
            parameters["$defs"] = model_schema["$defs"]

        return {
            "name": func.__name__,
            "description": summary,
            "parameters": parameters,
        }

    # --- Fallback historique (types simples uniquement) -----------------
    sig = inspect.signature(func)
    hints = get_type_hints(func)
    properties, required = {}, []
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        json_type = TYPE_MAP.get(hints.get(name, str), "string")
        properties[name] = {
            "type": json_type,
            "description": param_docs.get(name, f"Paramètre {name}"),
        }
        if param.default is inspect.Parameter.empty:
            required.append(name)

    return {
        "name": func.__name__,
        "description": summary,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }

def _to_openai_format(schema: dict) -> dict:
    return {
        "type": "function",
        "function": {
            "name": schema["name"],
            "description": schema["description"],
            "parameters": schema["parameters"],
        },
    }

def _to_anthropic_format(schema: dict) -> dict:
    return {
        "name": schema["name"],
        "description": schema["description"],
        "input_schema": schema["parameters"],
    }


PROVIDER_FORMATTERS = {
    "openai": _to_openai_format,
    "anthropic": _to_anthropic_format,
}

def build_tools(funcs: Callable | list[Callable], provider_family: str, *args, **kwargs) -> list[dict]:
    """
    🎯 La fonction principale : donne une fonction seule ou une liste,
    précise le provider, récupère les schémas déjà au bon format.
    """
    if callable(funcs):
        funcs = [funcs]
    
    if provider_family not in PROVIDER_FORMATTERS:
        raise ValueError(
            f"Provider inconnu : {provider_family!r}. Options : {list(PROVIDER_FORMATTERS)}"
        )
    formatter = PROVIDER_FORMATTERS[provider_family]

    return [formatter(function_to_generic_schema(f)) for f in funcs]

if __name__ == "__main__":
    from modules_utils.pydantic_utils import entry_model
    import json
    from enum import Enum
    from pydantic import BaseModel, Field

    # =====================================================================
    # Test 1 : fallback historique — fonction SANS @entry_model
    # (vérifie qu'on n'a rien cassé pour les tools qui n'ont pas encore
    # de modèle Pydantic associé)
    # =====================================================================
    def send_alert(level: str, message: str, urgent: bool = False):
        """Envoie une alerte à l'admin.

        Args:
            level: Niveau de criticité ("info", "warning", "critical")
            message: Contenu du message à envoyer
            urgent: Si True, notifie aussi par SMS
        """
        ...

    # =====================================================================
    # Test 2 : nouveau chemin — fonction AVEC @entry_model, type imbriqué
    # + enum, pour vérifier que $defs et les valeurs d'enum apparaissent
    # bien dans le schéma généré (le vrai problème qu'on corrige ici)
    # =====================================================================
    class Priority(str, Enum):
        LOW = "low"
        HIGH = "high"

    class SubItem(BaseModel):
        name: str = Field(description="Nom de l'item")
        priority: Priority = Field(description="Priorité de l'item")

    class ComplexEntry(BaseModel):
        title: str = Field(description="Titre de la tâche")
        items: list[SubItem] = Field(description="Sous-items associés")
        note: str | None = Field(default=None, description="Note optionnelle")

    @entry_model(ComplexEntry)
    def create_complex_task(title: str, items: list, note: str = None):
        """Crée une tâche complexe avec des sous-items."""
        ...

    print("=" * 70)
    print("TEST 1 — fallback historique (send_alert, sans @entry_model)")
    print("=" * 70)
    schema_simple = build_tools(send_alert, "openai")
    print(json.dumps(schema_simple, indent=2, ensure_ascii=False))

    assert schema_simple[0]["function"]["parameters"]["properties"]["urgent"]["type"] == "boolean"
    assert "level" in schema_simple[0]["function"]["parameters"]["required"]
    assert "urgent" not in schema_simple[0]["function"]["parameters"]["required"]
    print("\n✅ Fallback historique toujours fonctionnel (types simples, required correct).\n")

    print("=" * 70)
    print("TEST 2 — @entry_model avec type imbriqué + enum (create_complex_task)")
    print("=" * 70)
    schema_complex = build_tools(create_complex_task, "anthropic")
    print(json.dumps(schema_complex, indent=2, ensure_ascii=False))

    params = schema_complex[0]["input_schema"]
    assert "$defs" in params, "Le schéma imbriqué devrait contenir $defs pour SubItem/Priority"
    assert "items" in params["properties"], "Le champ 'items' devrait être présent"
    assert "note" not in params.get("required", []), "'note' a un défaut, ne doit pas être required"
    assert "title" in params.get("required", []), "'title' n'a pas de défaut, doit être required"
    print("\n✅ $defs bien présent pour le type imbriqué, required correct.\n")
 
    print("=" * 70)
    print("TEST 3 — plusieurs tools mélangés (avec et sans @entry_model) en un appel")
    print("=" * 70)
    both = build_tools([send_alert, create_complex_task], "openai")
    assert len(both) == 2
    print(f"✅ {len(both)} tools générés correctement à partir d'une liste mixte.\n")
 
    print("=" * 70)
    print("TEST 4 — provider inconnu doit lever une erreur claire (fail-fast)")
    print("=" * 70)
    try:
        build_tools(send_alert, "provider_totalement_inconnu")
        raise AssertionError("Aurait dû lever une ValueError")
    except ValueError as e:
        print(f"✅ ValueError bien levée comme attendu : {e}\n")
 
    print("Tous les tests sont passés. ✅")
 
