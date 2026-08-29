"""OpenRedirect (safe) — redirection validée contre une liste blanche de chemins internes."""
from .base import Unit, UnitCtx

ALLOWED_PATHS = {"/home", "/dashboard", "/profile", "/settings"}


def make_units(resource):
    def redirect_query_no_allowlist(ctx: UnitCtx):
        url = ctx.value("/home")
        allowed = url in ALLOWED_PATHS
        return {"would_redirect_to": url if allowed else "/home", "allowlist_checked": True,
                "note": f"redirection {resource} restreinte à une liste blanche de chemins internes"}

    def redirect_next_param(ctx: UnitCtx):
        nxt = ctx.value("/dashboard")
        allowed = nxt in ALLOWED_PATHS
        return {"would_redirect_to": nxt if allowed else "/dashboard", "allowlist_checked": True}

    return [
        Unit("OpenRedirect", "redirect_query_url_no_check", "query", "url", "liste blanche de chemins", redirect_query_no_allowlist),
        Unit("OpenRedirect", "post_login_next_param", "form", "next", "liste blanche de chemins", redirect_next_param),
    ]
