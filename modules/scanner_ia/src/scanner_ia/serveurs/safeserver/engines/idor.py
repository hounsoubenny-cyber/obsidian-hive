"""IDOR (safe) — vérification systématique que l'utilisateur courant est propriétaire de la ressource."""
from .base import Unit, UnitCtx, fake_records

CURRENT_USER_ID = 1


def make_units(resource):
    records = {r["id"]: r for r in fake_records(resource, 10)}

    def _get_with_owner_check(rid):
        rec = records.get(rid)
        if rec is None:
            return None, "introuvable"
        if rec["owner_id"] != CURRENT_USER_ID:
            return None, "accès refusé : vous n'êtes pas propriétaire de cette ressource"
        return rec, None

    def path_id_no_owner_check(ctx: UnitCtx):
        rid = ctx.value("1")
        try:
            rid = int(rid)
        except ValueError:
            rid = 1
        rec, err = _get_with_owner_check(rid)
        return {"requested_id": rid, "record": rec, "error": err, "owner_check_performed": True}

    def query_id_no_owner_check(ctx: UnitCtx):
        rid = ctx.value("1")
        try:
            rid = int(rid)
        except ValueError:
            rid = 1
        rec, err = _get_with_owner_check(rid)
        return {"requested_id": rid, "record": rec, "error": err, "owner_check_performed": True}

    def json_id_no_owner_check(ctx: UnitCtx):
        body = ctx.raw_json()
        rid = body.get("id", 1)
        try:
            rid = int(rid)
        except (ValueError, TypeError):
            rid = 1
        rec, err = _get_with_owner_check(rid)
        return {"requested_id": rid, "record": rec, "error": err, "owner_check_performed": True}

    return [
        Unit("IDOR", "path_id_direct_access", "path", "obj_id", f"vérification owner_id sur {resource}", path_id_no_owner_check),
        Unit("IDOR", "query_id_direct_access", "query", "id", "vérification owner_id systématique", query_id_no_owner_check),
        Unit("IDOR", "json_body_id_direct_access", "json", "id", "vérification owner_id systématique", json_id_no_owner_check),
    ]
