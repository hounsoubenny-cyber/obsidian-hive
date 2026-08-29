"""GraphQLi (safe) — introspection désactivée, profondeur de requête limitée."""
from .base import Unit, UnitCtx

MAX_DEPTH = 5


def make_units(resource):
    def introspection_enabled(ctx: UnitCtx):
        body = ctx.raw_json()
        query = body.get("query", "")
        is_introspection = "__schema" in query or "__type" in query
        return {"introspection_query_detected": is_introspection, "introspection_enabled": False,
                "data": None if is_introspection else {"note": "introspection désactivée en production"},
                "note": f"introspection GraphQL désactivée sur {resource}"}

    def no_depth_limit(ctx: UnitCtx):
        body = ctx.raw_json()
        query = body.get("query", "")
        depth = query.count("{")
        rejected = depth > MAX_DEPTH
        return {"estimated_query_depth": depth, "depth_limit_enforced": True, "rejected": rejected,
                "note": f"limite de profondeur ({MAX_DEPTH}) appliquée sur {resource}"}

    return [
        Unit("GraphQLi", "introspection_left_enabled", "json", "query", "introspection désactivée", introspection_enabled, "medium"),
        Unit("GraphQLi", "no_query_depth_limit", "json", "query", "limite de profondeur appliquée", no_depth_limit, "medium"),
    ]
