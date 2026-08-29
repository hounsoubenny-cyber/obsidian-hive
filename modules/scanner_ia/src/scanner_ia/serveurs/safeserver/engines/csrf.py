"""CSRF (safe) — token anti-CSRF requis et vérifié pour toute action qui modifie un état."""
import hmac
import secrets
from .base import Unit, UnitCtx

CSRF_SECRET = secrets.token_hex(32)
VALID_TOKEN = hmac.new(CSRF_SECRET.encode(), b"session-fixed", "sha256").hexdigest()


def _check_token(token: str) -> bool:
    return bool(token) and hmac.compare_digest(token, VALID_TOKEN)


def make_units(resource):
    def state_change_no_token(ctx: UnitCtx):
        from flask import request as freq
        token = freq.headers.get("X-CSRF-Token", "")
        body = ctx.raw_json()
        action = body.get("action", f"update_{resource}")
        if not _check_token(token):
            return {"action_executed": None, "rejected": True, "note": "token CSRF manquant ou invalide, action refusée"}
        return {"action_executed": action, "csrf_token_checked": True}

    def delete_resource_no_token(ctx: UnitCtx):
        from flask import request as freq
        token = freq.headers.get("X-CSRF-Token", "")
        rid = ctx.value("1")
        if not _check_token(token):
            return {"deleted_id": None, "rejected": True, "note": "token CSRF manquant ou invalide"}
        return {"deleted_id": rid, "resource": resource, "csrf_token_checked": True}

    def transfer_action_no_token(ctx: UnitCtx):
        from flask import request as freq
        token = freq.headers.get("X-CSRF-Token", "")
        body = ctx.raw_json()
        if not _check_token(token):
            return {"transferred_amount": 0, "rejected": True, "note": "action sensible refusée sans token CSRF valide"}
        return {"transferred_amount": body.get("amount", 0), "csrf_token_checked": True}

    return [
        Unit("CSRF", "generic_state_change_no_token", "json", "action", f"token CSRF requis sur {resource}", state_change_no_token, "medium"),
        Unit("CSRF", "delete_no_token", "query", "id", "token CSRF requis pour suppression", delete_resource_no_token, "medium"),
        Unit("CSRF", "sensitive_transfer_no_token", "json", "amount", "token CSRF requis pour action sensible", transfer_action_no_token, "hard"),
    ]
