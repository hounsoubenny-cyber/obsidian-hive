"""Prototype_Pollution — analogue Python d'une fusion d'objets non contrôlée.

Le concept vient du JS (pollution d'Object.prototype). En Python on simule
l'équivalent avec une fusion récursive non filtrée dans un dict de settings
PARTAGÉ globalement, ce qui permet d'y injecter des clés arbitraires qui
affectent ensuite tout le reste de l'application — même impact logique."""
from .base import Unit, UnitCtx

SHARED_SETTINGS = {"theme": "default", "is_admin": False, "rate_limit": 100}


def _deep_merge(base: dict, incoming: dict):
    for k, v in incoming.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v  # aucune clé n'est bloquée (équivalent __proto__/constructor non filtré)


def make_units(resource):
    def merge_settings_json(ctx: UnitCtx):
        body = ctx.raw_json()
        incoming = body.get("settings", {})
        before = dict(SHARED_SETTINGS)
        if isinstance(incoming, dict):
            _deep_merge(SHARED_SETTINGS, incoming)
        return {"settings_before": before, "settings_after": dict(SHARED_SETTINGS),
                "note": f"fusion récursive de settings {resource} sans liste de clés autorisées (analogue prototype pollution)"}

    def merge_preferences_json(ctx: UnitCtx):
        body = ctx.raw_json()
        incoming = body.get("preferences", {})
        before = dict(SHARED_SETTINGS)
        if isinstance(incoming, dict):
            _deep_merge(SHARED_SETTINGS, incoming)
        return {"settings_before": before, "settings_after": dict(SHARED_SETTINGS)}

    return [
        Unit("Prototype_Pollution", "deep_merge_settings", "json", "settings",
             f"fusion non filtrée d'un objet settings {resource} partagé globalement", merge_settings_json, "hard"),
        Unit("Prototype_Pollution", "deep_merge_preferences", "json", "preferences",
             "fusion non filtrée de préférences dans un objet global partagé", merge_preferences_json, "hard"),
    ]
