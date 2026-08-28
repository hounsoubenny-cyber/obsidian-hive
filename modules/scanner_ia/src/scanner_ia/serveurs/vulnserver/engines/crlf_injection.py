"""CRLF_Injection — injection de \\r\\n dans des headers HTTP construits manuellement."""
from .base import Unit, UnitCtx


def make_units(resource):
    def redirect_header_injection(ctx: UnitCtx):
        url = ctx.value("/home")
        has_crlf = "\r" in url or "\n" in url or "%0d" in url.lower() or "%0a" in url.lower()
        fake_response_headers = f"Location: {url}"
        return {"raw_location_header": fake_response_headers, "crlf_detected_in_input": has_crlf,
                "note": f"valeur non filtrée insérée dans un header Location pour {resource}"}

    def log_line_injection(ctx: UnitCtx):
        val = ctx.value("normal log entry")
        has_crlf = "\r" in val or "\n" in val
        fake_log_line = f"[{resource}] user_action={val}"
        return {"log_line_written": fake_log_line, "crlf_detected_in_input": has_crlf,
                "note": "entrée utilisateur écrite dans les logs sans filtrage des retours à la ligne"}

    return [
        Unit("CRLF_Injection", "location_header_crlf", "query", "url",
             f"header Location {resource} construit sans filtrage CRLF", redirect_header_injection, "medium"),
        Unit("CRLF_Injection", "log_injection_crlf", "form", "message",
             "entrée utilisateur écrite dans un log sans filtrage CRLF", log_line_injection, "medium"),
    ]
