"""GraphQLi — introspection laissée active, absence de limite de profondeur/complexité."""
from .base import Unit, UnitCtx


def make_units(resource):
    def introspection_enabled(ctx: UnitCtx):
        body = ctx.raw_json()
        query = body.get("query", "")
        is_introspection = "__schema" in query or "__type" in query
        response = None
        if is_introspection:
            response = {"__schema": {"types": [{"name": resource}, {"name": "User"}, {"name": "Query"}]}}
        return {"introspection_query_detected": is_introspection, "introspection_enabled": True,
                "data": response, "note": "introspection GraphQL laissée active en production"}

    def no_depth_limit(ctx: UnitCtx):
        body = ctx.raw_json()
        query = body.get("query", "")
        depth = query.count("{")
        return {"estimated_query_depth": depth, "depth_limit_enforced": False,
                "note": f"requête {resource} imbriquée sans limite de profondeur/complexité côté serveur"}

    return [
        Unit("GraphQLi", "introspection_left_enabled", "json", "query",
             f"schéma GraphQL {resource} entièrement exposé via introspection", introspection_enabled, "medium"),
        Unit("GraphQLi", "no_query_depth_limit", "json", "query",
             "aucune limite de profondeur/complexité de requête, DoS possible", no_depth_limit, "medium"),
    ]
