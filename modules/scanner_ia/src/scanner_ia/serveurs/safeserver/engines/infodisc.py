"""InfoDisc (safe) — messages d'erreur génériques, aucune stack trace ni version exposée."""
from .base import Unit, UnitCtx


def make_units(resource):
    def stack_trace_on_error(ctx: UnitCtx):
        val = ctx.value("1")
        try:
            result = 100 / int(val)
            return {"result": result}
        except Exception:
            return {"error": "requête invalide", "note": "message générique, aucune stack trace exposée"}

    def verbose_server_header(ctx: UnitCtx):
        return {"server_header": "server", "note": "aucune version de framework/langage exposée"}

    def debug_env_dump(ctx: UnitCtx):
        return {"error": "not found", "status": 404, "note": f"endpoint de debug {resource} désactivé"}

    return [
        Unit("InfoDisc", "stack_trace_leak_on_error", "query", "divisor", "message d'erreur générique", stack_trace_on_error, "medium"),
        Unit("InfoDisc", "verbose_server_version_header", "query", "id", "aucune version exposée", verbose_server_header),
        Unit("InfoDisc", "debug_env_endpoint", "path", "resource_name", "endpoint de debug désactivé", debug_env_dump),
    ]
