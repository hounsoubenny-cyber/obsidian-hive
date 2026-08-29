"""InsecDeser (safe) — uniquement du JSON, jamais pickle/yaml.unsafe_load."""
import json
from .base import Unit, UnitCtx


def make_units(resource):
    def pickle_import(ctx: UnitCtx):
        raw = ctx.value("")
        try:
            obj = json.loads(raw) if raw else {}
            return {"parsed": obj, "note": "json.loads() utilisé, pickle.loads() jamais appelé sur input client"}
        except json.JSONDecodeError:
            return {"error": "JSON invalide", "note": "input rejeté, pas de désérialisation dangereuse"}

    def yaml_unsafe(ctx: UnitCtx):
        raw = ctx.value("{}")
        try:
            obj = json.loads(raw)
            return {"parsed": obj, "note": "format JSON strict imposé, yaml.unsafe_load jamais utilisé"}
        except json.JSONDecodeError:
            return {"error": "format invalide, rejeté"}

    return [
        Unit("InsecDeser", "pickle_b64_import", "json", "payload", f"parsing JSON strict pour {resource}, pas de pickle", pickle_import, "hard"),
        Unit("InsecDeser", "yaml_unsafe_load", "form", "config", "parsing JSON strict, pas de yaml.unsafe_load", yaml_unsafe, "medium"),
    ]
