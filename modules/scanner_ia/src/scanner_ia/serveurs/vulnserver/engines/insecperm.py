"""InsecPerm — permissions/contrôle d'accès mal configurés (pas d'IDOR direct, plutôt niveau ressource/rôle)."""
from .base import Unit, UnitCtx


def make_units(resource):
    def role_trusted_from_header(ctx: UnitCtx):
        role = ctx.value("user")
        # le rôle est FAIT CONFIANCE depuis un header client, jamais vérifié côté serveur
        granted = role == "admin"
        return {"role_claimed": role, "admin_action_allowed": granted,
                "note": f"accès admin à {resource} basé uniquement sur un header client non signé"}

    def world_readable_export(ctx: UnitCtx):
        return {"export_url": f"/{resource}/export-all", "auth_required": False,
                "note": f"export complet de {resource} accessible sans authentification ni rôle"}

    def missing_role_check_query(ctx: UnitCtx):
        as_admin = ctx.value("false")
        return {"acts_as_admin": as_admin.lower() == "true",
                "note": f"paramètre client 'as_admin' déterminant les droits sur {resource}"}

    return [
        Unit("InsecPerm", "role_trusted_from_header", "header", "X-User-Role",
             "rôle utilisateur lu et approuvé depuis un header client", role_trusted_from_header, "medium"),
        Unit("InsecPerm", "world_readable_export_endpoint", "path", "id",
             f"endpoint d'export {resource} sans aucun contrôle d'accès", world_readable_export),
        Unit("InsecPerm", "client_controlled_admin_flag", "query", "as_admin",
             "élévation de privilège via un flag contrôlé par le client", missing_role_check_query, "medium"),
    ]
