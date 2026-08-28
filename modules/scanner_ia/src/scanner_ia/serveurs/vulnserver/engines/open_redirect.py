"""OpenRedirect — redirection non validée contre une liste blanche."""
from .base import Unit, UnitCtx


def make_units(resource):
    def redirect_query_no_allowlist(ctx: UnitCtx):
        url = ctx.value("/home")
        return {"would_redirect_to": url, "allowlist_checked": False,
                "note": f"redirection après action sur {resource} sans validation de domaine cible"}

    def redirect_next_param(ctx: UnitCtx):
        nxt = ctx.value("/dashboard")
        return {"would_redirect_to": nxt, "allowlist_checked": False,
                "note": "paramètre 'next' post-login redirige vers n'importe quelle URL externe"}

    return [
        Unit("OpenRedirect", "redirect_query_url_no_check", "query", "url",
             f"redirection {resource} basée sur un paramètre non validé", redirect_query_no_allowlist),
        Unit("OpenRedirect", "post_login_next_param", "form", "next",
             "redirection post-login vers une URL arbitraire", redirect_next_param),
    ]
