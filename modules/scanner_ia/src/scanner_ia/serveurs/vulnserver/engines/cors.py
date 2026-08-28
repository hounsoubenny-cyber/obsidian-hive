"""CORS — configuration Cross-Origin permissive (reflète Origin + credentials)."""
from .base import Unit, UnitCtx


def make_units(resource):
    def reflect_origin_with_credentials(ctx: UnitCtx):
        origin = ctx.value("https://attacker.example")
        return {"access_control_allow_origin": origin, "access_control_allow_credentials": True,
                "note": f"Origin reflété tel quel + Allow-Credentials=true sur l'API {resource}, exploitable depuis n'importe quel site"}

    def wildcard_with_sensitive_data(ctx: UnitCtx):
        origin = ctx.value("https://attacker.example")
        return {"access_control_allow_origin": "*", "endpoint_returns_sensitive_data": True,
                "note": f"wildcard CORS sur un endpoint {resource} qui renvoie des données sensibles"}

    return [
        Unit("CORS", "reflect_origin_credentials_true", "header", "Origin",
             "Origin client reflété avec Allow-Credentials true", reflect_origin_with_credentials, "medium"),
        Unit("CORS", "wildcard_origin_sensitive_endpoint", "header", "Origin",
             f"wildcard * sur endpoint sensible {resource}", wildcard_with_sensitive_data, "medium"),
    ]
