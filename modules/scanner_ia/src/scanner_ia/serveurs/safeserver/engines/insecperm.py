"""InsecPerm (safe) — le rôle vient toujours de l'état serveur, jamais d'un input client."""
from .base import Unit, UnitCtx

SERVER_SIDE_ROLE = "user"  # jamais lu depuis le client


def make_units(resource):
    def role_trusted_from_header(ctx: UnitCtx):
        claimed = ctx.value("user")
        granted = SERVER_SIDE_ROLE == "admin"  # ignore complètement le header client
        return {"role_claimed_by_client": claimed, "admin_action_allowed": granted,
                "note": "le rôle réel vient de la session serveur, le header client est ignoré"}

    def world_readable_export(ctx: UnitCtx):
        return {"export_url": f"/{resource}/export-all", "auth_required": True,
                "note": f"export {resource} exige une session authentifiée avec le bon rôle"}

    def missing_role_check_query(ctx: UnitCtx):
        claimed = ctx.value("false")
        return {"acts_as_admin": False, "note": "le flag client 'as_admin' est ignoré, seule la session serveur compte"}

    return [
        Unit("InsecPerm", "role_trusted_from_header", "header", "X-User-Role", "rôle jamais lu depuis un header client", role_trusted_from_header, "medium"),
        Unit("InsecPerm", "world_readable_export_endpoint", "path", "id", "export protégé par authentification + rôle", world_readable_export),
        Unit("InsecPerm", "client_controlled_admin_flag", "query", "as_admin", "flag client ignoré pour les décisions d'autorisation", missing_role_check_query, "medium"),
    ]
