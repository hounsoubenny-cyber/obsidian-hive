"""HTTP_Request_Smuggling — désaccord Content-Length / Transfer-Encoding.

Une vraie smuggling nécessite une chaîne proxy + back-end. Ici on expose
la SURFACE de la vuln : le serveur applicatif accepte et traite un body
selon Content-Length ET Transfer-Encoding simultanément sans rejeter la
requête ambiguë (comportement CL.TE typique), ce qui est le signal que
cherche un scanner à détecter en boîte noire."""
from .base import Unit, UnitCtx


def make_units(resource):
    def ambiguous_cl_te_header(ctx: UnitCtx):
        te = ctx.value("")
        cl = flask_cl = None
        from flask import request as freq
        cl = freq.headers.get("Content-Length")
        ambiguous = bool(te) and bool(cl)
        return {"content_length": cl, "transfer_encoding": te, "both_present_and_accepted": ambiguous,
                "note": f"endpoint {resource} ne rejette pas une requête avec CL et TE présents simultanément"}

    def duplicate_content_length(ctx: UnitCtx):
        from flask import request as freq
        raw_headers = list(freq.headers.items())
        cl_count = sum(1 for k, v in raw_headers if k.lower() == "content-length")
        return {"content_length_header_count": cl_count,
                "note": f"endpoint {resource} ne rejette pas les en-têtes Content-Length dupliqués/conflictuels"}

    return [
        Unit("HTTP_Request_Smuggling", "cl_te_both_accepted", "header", "Transfer-Encoding",
             "Content-Length et Transfer-Encoding acceptés simultanément sans rejet", ambiguous_cl_te_header, "hard"),
        Unit("HTTP_Request_Smuggling", "duplicate_content_length_accepted", "header", "X-Trigger",
             f"headers Content-Length dupliqués non rejetés sur {resource}", duplicate_content_length, "hard"),
    ]
