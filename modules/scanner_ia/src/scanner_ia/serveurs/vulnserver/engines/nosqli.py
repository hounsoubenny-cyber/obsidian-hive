"""NoSQLi — injection d'opérateurs dans une requête NoSQL style MongoDB."""
from .base import Unit, UnitCtx, USERS_TABLE


def _mongo_like_find(collection, query: dict):
    """Simule un moteur de requête Mongo minimal supportant $ne/$gt/$regex/$where."""
    def match(doc, q):
        for k, v in q.items():
            if isinstance(v, dict):
                for op, opval in v.items():
                    if op == "$ne" and not (doc.get(k) != opval):
                        return False
                    if op == "$gt" and not (doc.get(k, 0) > opval):
                        return False
                    if op == "$regex":
                        import re
                        if not re.search(opval, str(doc.get(k, ""))):
                            return False
            else:
                if doc.get(k) != v:
                    return False
        return True
    return [d for d in collection if match(d, query)]


def make_units(resource):
    def auth_operator_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        username = body.get("username", "admin")
        password = body.get("password", "wrongpass")
        # si password est un dict (ex: {"$ne": ""}), l'opérateur est utilisé tel quel
        query = {"username": username, "password": password}
        results = _mongo_like_find(USERS_TABLE, query)
        return {"query_used": query, "authenticated": len(results) > 0,
                "note": "opérateurs Mongo ($ne, $gt, $regex) acceptés tels quels depuis le body JSON"}

    def search_operator_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        filt = body.get("filter", {"role": "user"})
        results = _mongo_like_find(USERS_TABLE, filt if isinstance(filt, dict) else {"role": filt})
        return {"query_used": filt, "count": len(results),
                "note": f"filtre {resource} passé tel quel au moteur de requête"}

    def regex_dos_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        pattern = body.get("q", "^a")
        query = {"username": {"$regex": pattern}}
        try:
            results = _mongo_like_find(USERS_TABLE, query)
            return {"query_used": query, "count": len(results)}
        except Exception as e:
            return {"error": str(e)}

    return [
        Unit("NoSQLi", "auth_operator_bypass", "json", "password",
             "opérateur $ne injecté dans le champ password d'un login", auth_operator_injection, "medium"),
        Unit("NoSQLi", "search_filter_injection", "json", "filter",
             f"filtre de recherche {resource} contrôlé entièrement par le client", search_operator_injection, "medium"),
        Unit("NoSQLi", "regex_operator_injection", "json", "q",
             "opérateur $regex injecté depuis l'input utilisateur", regex_dos_injection, "hard"),
    ]
