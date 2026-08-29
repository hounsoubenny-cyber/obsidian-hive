"""SessFix (safe) — session toujours régénérée côté serveur au login, ID client jamais accepté."""
import secrets
from .base import Unit, UnitCtx


def make_units(resource):
    def accept_client_sessionid_query(ctx: UnitCtx):
        client_sid = ctx.value("")
        new_sid = secrets.token_hex(32)  # ID client ignoré, toujours régénéré
        return {"client_supplied_sessionid_ignored": bool(client_sid), "session_id": new_sid,
                "note": "un nouvel ID est toujours généré côté serveur, celui du client est ignoré"}

    def accept_client_sessionid_cookie(ctx: UnitCtx):
        client_sid = ctx.value("")
        new_sid = secrets.token_hex(32)
        return {"client_supplied_sessionid_ignored": bool(client_sid), "session_id": new_sid,
                "note": f"session régénérée après authentification sur {resource}"}

    return [
        Unit("SessFix", "sessionid_accepted_from_query", "query", "sessionid", "ID client ignoré, régénération serveur", accept_client_sessionid_query, "medium"),
        Unit("SessFix", "sessionid_not_regenerated_on_login", "cookie", "sessionid", "session régénérée après login", accept_client_sessionid_cookie, "medium"),
    ]
