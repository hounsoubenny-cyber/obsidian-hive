"""CRLF_Injection (safe) — tout \\r \\n est filtré/rejeté avant insertion dans un header ou un log."""
from .base import Unit, UnitCtx


def _strip_crlf(s: str) -> str:
    return s.replace("\r", "").replace("\n", "")


def make_units(resource):
    def redirect_header_injection(ctx: UnitCtx):
        url = ctx.value("/home")
        cleaned = _strip_crlf(url)
        return {"location_header_used": cleaned, "note": f"caractères CR/LF filtrés avant construction du header pour {resource}"}

    def log_line_injection(ctx: UnitCtx):
        val = ctx.value("normal log entry")
        cleaned = _strip_crlf(val)
        return {"log_line_written": f"[{resource}] user_action={cleaned}", "note": "CR/LF filtrés avant écriture en log"}

    return [
        Unit("CRLF_Injection", "location_header_crlf", "query", "url", "CR/LF filtrés avant header", redirect_header_injection, "medium"),
        Unit("CRLF_Injection", "log_injection_crlf", "form", "message", "CR/LF filtrés avant log", log_line_injection, "medium"),
    ]
