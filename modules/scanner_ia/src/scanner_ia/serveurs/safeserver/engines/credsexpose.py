"""CredsExpose (safe) — aucun secret dans les réponses, endpoints de debug désactivés."""
from .base import Unit, UnitCtx


def make_units(resource):
    def debug_config_endpoint(ctx: UnitCtx):
        return {"error": "not found", "status": 404, "note": f"endpoint de debug {resource} désactivé en dehors du dev local"}

    def verbose_error_leak(ctx: UnitCtx):
        return {"error": "une erreur est survenue, contactez le support", "note": "message générique, aucun détail interne exposé"}

    def response_header_leak(ctx: UnitCtx):
        return {"headers_would_include": {}, "note": "aucune clé/secret renvoyé dans les headers de réponse"}

    return [
        Unit("CredsExpose", "debug_endpoint_left_on", "path", "resource_name", "endpoint de debug désactivé", debug_config_endpoint),
        Unit("CredsExpose", "verbose_error_with_secret", "query", "q", "message d'erreur générique, aucun secret exposé", verbose_error_leak, "medium"),
        Unit("CredsExpose", "secret_in_response_header", "query", "id", "aucun secret dans les headers", response_header_leak, "medium"),
    ]
