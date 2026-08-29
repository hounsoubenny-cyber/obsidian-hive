"""SSRF (safe) — URL validée contre une liste blanche de hosts, IP internes bloquées."""
from urllib.parse import urlparse
from .base import Unit, UnitCtx

ALLOWED_HOSTS = {"api.example.test", "cdn.example.test", "images.example.test"}


def _validate(url: str):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("https", "http"):
        return False, "schéma non autorisé"
    if host not in ALLOWED_HOSTS:
        return False, "host non présent dans la liste blanche"
    return True, None


def make_units(resource):
    def fetch_url_query(ctx: UnitCtx):
        url = ctx.value("https://api.example.test/")
        ok, err = _validate(url)
        return {"requested_url": url, "allowed": ok, "reason": err, "note": "liste blanche stricte de hosts"}

    def fetch_url_json(ctx: UnitCtx):
        url = ctx.value("https://api.example.test/")
        ok, err = _validate(url)
        return {"requested_url": url, "allowed": ok, "reason": err, "context": f"webhook/preview pour {resource}"}

    def fetch_url_form(ctx: UnitCtx):
        url = ctx.value("https://images.example.test/")
        ok, err = _validate(url)
        return {"requested_url": url, "allowed": ok, "reason": err, "context": f"import d'image pour {resource}"}

    return [
        Unit("SSRF", "url_fetch_query_no_allowlist", "query", "url", "liste blanche de hosts appliquée", fetch_url_query, "medium"),
        Unit("SSRF", "url_fetch_json_webhook", "json", "url", "liste blanche de hosts appliquée", fetch_url_json, "medium"),
        Unit("SSRF", "url_fetch_form_image_import", "form", "image_url", "liste blanche de hosts appliquée", fetch_url_form, "medium"),
    ]
