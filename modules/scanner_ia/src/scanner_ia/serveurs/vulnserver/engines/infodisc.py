"""InfoDisc — divulgation d'information via erreurs verbeuses / endpoints de debug."""
from .base import Unit, UnitCtx


def make_units(resource):
    def stack_trace_on_error(ctx: UnitCtx):
        val = ctx.value("1")
        try:
            result = 100 / int(val)
            return {"result": result}
        except Exception as e:
            return {"error_type": type(e).__name__, "error_detail": str(e),
                    "fake_traceback": f'File "/app/models/{resource}.py", line 42, in compute\n    return 100 / value\n{type(e).__name__}: {e}',
                    "note": "stack trace complète renvoyée au client au lieu d'un message générique"}

    def verbose_server_header(ctx: UnitCtx):
        return {"server_header": "Werkzeug/3.1.3 Python/3.12.4 Flask/3.1.0",
                "note": "version exacte du framework/langage exposée dans les headers"}

    def debug_env_dump(ctx: UnitCtx):
        return {"env_dump": {"FLASK_ENV": "development", "DEBUG": True, "APP_SECRET_SET": True},
                "note": f"endpoint de debug {resource} qui liste les variables d'environnement"}

    return [
        Unit("InfoDisc", "stack_trace_leak_on_error", "query", "divisor",
             "exception non gérée renvoyée avec stack trace complète au client", stack_trace_on_error, "medium"),
        Unit("InfoDisc", "verbose_server_version_header", "query", "id",
             "version exacte du serveur/framework exposée", verbose_server_header),
        Unit("InfoDisc", "debug_env_endpoint", "path", "resource_name",
             f"endpoint /{resource}/debug/env accessible publiquement", debug_env_dump),
    ]
