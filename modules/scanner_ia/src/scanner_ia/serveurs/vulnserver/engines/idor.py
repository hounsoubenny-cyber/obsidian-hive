"""IDOR — Insecure Direct Object Reference : accès par ID sans vérif propriétaire."""
from .base import Unit, UnitCtx, fake_records

CURRENT_USER_ID = 1  # utilisateur "connecté" simulé


def make_units(resource):
    records = {r["id"]: r for r in fake_records(resource, 10)}

    def path_id_no_owner_check(ctx: UnitCtx):
        rid = ctx.value("1")
        try:
            rid = int(rid)
        except ValueError:
            rid = 1
        rec = records.get(rid)
        return {"requested_id": rid, "record": rec, "owner_check_performed": False,
                "current_user_id": CURRENT_USER_ID,
                "note": f"accès à {resource}/{rid} sans vérifier que owner_id == current_user_id"}

    def query_id_no_owner_check(ctx: UnitCtx):
        rid = ctx.value("1")
        try:
            rid = int(rid)
        except ValueError:
            rid = 1
        rec = records.get(rid)
        return {"requested_id": rid, "record": rec, "owner_check_performed": False}

    def json_id_no_owner_check(ctx: UnitCtx):
        body = ctx.raw_json()
        rid = body.get("id", 1)
        try:
            rid = int(rid)
        except (ValueError, TypeError):
            rid = 1
        rec = records.get(rid)
        return {"requested_id": rid, "record": rec, "owner_check_performed": False}

    return [
        Unit("IDOR", "path_id_direct_access", "path", "obj_id",
             f"accès direct à un {resource} par ID dans l'URL, sans vérif de propriétaire", path_id_no_owner_check),
        Unit("IDOR", "query_id_direct_access", "query", "id",
             f"accès direct à un {resource} par ID en query, sans vérif de propriétaire", query_id_no_owner_check),
        Unit("IDOR", "json_body_id_direct_access", "json", "id",
             f"accès direct à un {resource} par ID en JSON body, sans vérif de propriétaire", json_id_no_owner_check),
    ]
