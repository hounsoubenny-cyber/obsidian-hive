"""HTTP_Request_Smuggling (safe) — requête rejetée si CL et TE sont présents simultanément."""
from .base import Unit, UnitCtx


def make_units(resource):
    def ambiguous_cl_te_header(ctx: UnitCtx):
        from flask import request as freq
        te = ctx.value("")
        cl = freq.headers.get("Content-Length")
        if te and cl:
            return {"rejected": True, "reason": "Content-Length et Transfer-Encoding présents simultanément",
                    "note": f"requête ambiguë rejetée sur {resource} (comportement conforme RFC 7230 §3.3.3)"}
        return {"rejected": False}

    def duplicate_content_length(ctx: UnitCtx):
        from flask import request as freq
        raw_headers = list(freq.headers.items())
        cl_count = sum(1 for k, v in raw_headers if k.lower() == "content-length")
        rejected = cl_count > 1
        return {"content_length_header_count": cl_count, "rejected": rejected,
                "note": f"headers Content-Length dupliqués rejetés sur {resource}"}

    return [
        Unit("HTTP_Request_Smuggling", "cl_te_both_accepted", "header", "Transfer-Encoding", "requête ambiguë rejetée", ambiguous_cl_te_header, "hard"),
        Unit("HTTP_Request_Smuggling", "duplicate_content_length_accepted", "header", "X-Trigger", "headers dupliqués rejetés", duplicate_content_length, "hard"),
    ]
