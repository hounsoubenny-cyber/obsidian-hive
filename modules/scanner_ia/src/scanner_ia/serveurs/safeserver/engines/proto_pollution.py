"""Prototype_Pollution (safe) — clés dangereuses bloquées, fusion restreinte à une whitelist."""
from .base import Unit, UnitCtx

SHARED_SETTINGS = {"theme": "default", "is_admin": False, "rate_limit": 100}
ALLOWED_KEYS = {"theme"}  # seule cette clé peut être modifiée par le client
DANGEROUS_KEYS = {"__proto__", "constructor", "prototype", "is_admin", "rate_limit"}


def _safe_merge(base: dict, incoming: dict):
    for k, v in incoming.items():
        if k in DANGEROUS_KEYS or k not in ALLOWED_KEYS:
            continue  # clé ignorée silencieusement (rejetée)
        base[k] = v


def make_units(resource):
    def merge_settings_json(ctx: UnitCtx):
        body = ctx.raw_json()
        incoming = body.get("settings", {})
        before = dict(SHARED_SETTINGS)
        rejected = []
        if isinstance(incoming, dict):
            rejected = [k for k in incoming if k in DANGEROUS_KEYS or k not in ALLOWED_KEYS]
            _safe_merge(SHARED_SETTINGS, incoming)
        return {"settings_after": dict(SHARED_SETTINGS), "keys_rejected": rejected,
                "note": f"fusion {resource} restreinte à une liste blanche de clés autorisées"}

    def merge_preferences_json(ctx: UnitCtx):
        body = ctx.raw_json()
        incoming = body.get("preferences", {})
        rejected = []
        if isinstance(incoming, dict):
            rejected = [k for k in incoming if k in DANGEROUS_KEYS or k not in ALLOWED_KEYS]
            _safe_merge(SHARED_SETTINGS, incoming)
        return {"settings_after": dict(SHARED_SETTINGS), "keys_rejected": rejected}

    return [
        Unit("Prototype_Pollution", "deep_merge_settings", "json", "settings", "whitelist stricte de clés modifiables", merge_settings_json, "hard"),
        Unit("Prototype_Pollution", "deep_merge_preferences", "json", "preferences", "clés dangereuses bloquées", merge_preferences_json, "hard"),
    ]
