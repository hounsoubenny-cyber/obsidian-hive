"""CORS (safe) — liste blanche stricte d'origines, aucun reflect automatique."""
from .base import Unit, UnitCtx

ALLOWED_ORIGINS = {"https://app.example.test", "https://admin.example.test"}


def make_units(resource):
    def reflect_origin_with_credentials(ctx: UnitCtx):
        origin = ctx.value("https://attacker.example")
        allowed = origin in ALLOWED_ORIGINS
        return {"access_control_allow_origin": origin if allowed else None,
                "access_control_allow_credentials": allowed,
                "note": f"origine validée contre une liste blanche pour l'API {resource}"}

    def wildcard_with_sensitive_data(ctx: UnitCtx):
        origin = ctx.value("https://attacker.example")
        allowed = origin in ALLOWED_ORIGINS
        return {"access_control_allow_origin": origin if allowed else None,
                "note": f"pas de wildcard * sur endpoint sensible {resource}"}

    return [
        Unit("CORS", "reflect_origin_credentials_true", "header", "Origin", "liste blanche stricte d'origines", reflect_origin_with_credentials, "medium"),
        Unit("CORS", "wildcard_origin_sensitive_endpoint", "header", "Origin", "pas de wildcard sur endpoint sensible", wildcard_with_sensitive_data, "medium"),
    ]
