"""CSRF — action qui modifie un état sans token anti-CSRF."""
from .base import Unit, UnitCtx


def make_units(resource):
    def state_change_no_token(ctx: UnitCtx):
        body = ctx.raw_json()
        action = body.get("action", f"update_{resource}")
        return {"action_executed": action, "csrf_token_required": False, "csrf_token_checked": False,
                "note": f"action d'état sur {resource} exécutée sans vérification de token CSRF"}

    def delete_resource_no_token(ctx: UnitCtx):
        rid = ctx.value("1")
        return {"deleted_id": rid, "resource": resource, "csrf_token_checked": False,
                "note": f"suppression de {resource}/{rid} déclenchable par un simple GET/POST sans token"}

    def transfer_action_no_token(ctx: UnitCtx):
        body = ctx.raw_json()
        amount = body.get("amount", 0)
        to = body.get("to", "unknown")
        return {"transferred_amount": amount, "to": to, "csrf_token_checked": False,
                "note": f"action sensible sur {resource} exécutable via formulaire cross-site auto-soumis"}

    return [
        Unit("CSRF", "generic_state_change_no_token", "json", "action",
             f"endpoint {resource} modifiant l'état sans token CSRF", state_change_no_token, "medium"),
        Unit("CSRF", "delete_no_token", "query", "id",
             f"suppression de {resource} sans protection CSRF", delete_resource_no_token, "medium"),
        Unit("CSRF", "sensitive_transfer_no_token", "json", "amount",
             "action sensible (transfert/paiement) sans protection CSRF", transfer_action_no_token, "hard"),
    ]
