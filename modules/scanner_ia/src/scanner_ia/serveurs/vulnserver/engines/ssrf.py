"""SSRF — Server-Side Request Forgery : le serveur fetch une URL fournie par le client."""
import socket
from urllib.parse import urlparse
from .base import Unit, UnitCtx


def _fake_fetch(url: str):
    """On ne fait PAS de vraie requête réseau sortante (sécurité de la démo) :
    on simule le comportement d'un fetch non filtré et on signale les cibles
    sensibles qui auraient été atteignables (metadata cloud, réseau interne)."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    internal_targets = ("169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal")
    is_internal = host in internal_targets or host.startswith("10.") or host.startswith("192.168.") or host.startswith("172.")
    return {
        "requested_url": url,
        "would_reach_internal_target": is_internal,
        "note": "aucune restriction de host/IP appliquée avant le fetch côté serveur (simulation, pas de requête réelle envoyée)",
    }


def make_units(resource):
    def fetch_url_query(ctx: UnitCtx):
        url = ctx.value("http://example.test/")
        return _fake_fetch(url)

    def fetch_url_json(ctx: UnitCtx):
        url = ctx.value("http://example.test/")
        result = _fake_fetch(url)
        result["context"] = f"webhook/preview pour {resource}"
        return result

    def fetch_url_form(ctx: UnitCtx):
        url = ctx.value("http://example.test/")
        result = _fake_fetch(url)
        result["context"] = f"import d'image distante pour {resource}"
        return result

    return [
        Unit("SSRF", "url_fetch_query_no_allowlist", "query", "url", "URL de fetch sans liste blanche de hosts", fetch_url_query, "medium"),
        Unit("SSRF", "url_fetch_json_webhook", "json", "url", f"webhook {resource} fetché côté serveur sans validation", fetch_url_json, "medium"),
        Unit("SSRF", "url_fetch_form_image_import", "form", "image_url", f"import d'image distante pour {resource} sans validation de host", fetch_url_form, "medium"),
    ]
