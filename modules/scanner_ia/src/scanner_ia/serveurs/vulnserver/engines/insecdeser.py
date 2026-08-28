"""InsecDeser — désérialisation non fiable (pickle / yaml.load)."""
import base64
import pickle
import yaml
from .base import Unit, UnitCtx


def make_units(resource):
    def pickle_import(ctx: UnitCtx):
        raw = ctx.value("")
        try:
            data = base64.b64decode(raw) if raw else b""
            obj = pickle.loads(data) if data else None
            return {"deserialized_type": str(type(obj)), "note": "pickle.loads() appelé directement sur input client"}
        except Exception as e:
            return {"error": str(e), "note": "pickle.loads() appelé directement sur input client"}

    def yaml_unsafe(ctx: UnitCtx):
        raw = ctx.value("a: 1")
        try:
            obj = yaml.unsafe_load(raw)
            return {"parsed": str(obj), "note": "yaml.unsafe_load() sur input client"}
        except Exception as e:
            return {"error": str(e), "note": "yaml.unsafe_load() sur input client"}

    return [
        Unit("InsecDeser", "pickle_b64_import", "json", "payload",
             f"objet {resource} importé via pickle.loads(base64_input)", pickle_import, "hard"),
        Unit("InsecDeser", "yaml_unsafe_load", "form", "config",
             f"config {resource} parsée via yaml.unsafe_load", yaml_unsafe, "medium"),
    ]
