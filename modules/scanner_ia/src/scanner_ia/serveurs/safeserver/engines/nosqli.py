"""NoSQLi (safe) — les champs sensibles n'acceptent que des scalaires, pas d'opérateurs."""
from .base import Unit, UnitCtx, USERS_TABLE


def _strict_find(collection, query: dict):
    def match(doc, q):
        for k, v in q.items():
            if isinstance(v, dict):
                return False  # opérateurs jamais acceptés sur ces champs
            if doc.get(k) != v:
                return False
        return True
    return [d for d in collection if match(d, query)]


def make_units(resource):
    def auth_operator_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        username = body.get("username", "admin")
        password = body.get("password", "wrongpass")
        if not isinstance(username, str) or not isinstance(password, str):
            return {"authenticated": False, "note": "types non-scalaires rejetés (opérateurs $ne/$gt bloqués)"}
        results = _strict_find(USERS_TABLE, {"username": username, "password": password})
        return {"authenticated": len(results) > 0, "note": "seuls des types scalaires str sont acceptés"}

    def search_operator_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        filt = body.get("filter", {"role": "user"})
        if not isinstance(filt, dict) or any(isinstance(v, dict) for v in filt.values()):
            return {"count": 0, "note": "filtre rejeté : opérateurs imbriqués non autorisés"}
        results = _strict_find(USERS_TABLE, filt)
        return {"count": len(results), "note": f"filtre {resource} restreint aux égalités simples"}

    def regex_dos_injection(ctx: UnitCtx):
        body = ctx.raw_json()
        pattern = body.get("q", "")
        if len(pattern) > 50 or not isinstance(pattern, str):
            return {"error": "motif rejeté", "note": "opérateur $regex non exposé au client"}
        return {"count": 0, "note": "recherche textuelle simple (pas d'opérateur $regex exposé)"}

    return [
        Unit("NoSQLi", "auth_operator_bypass", "json", "password", "seuls des scalaires acceptés dans le login", auth_operator_injection, "medium"),
        Unit("NoSQLi", "search_filter_injection", "json", "filter", f"filtre {resource} restreint aux égalités simples", search_operator_injection, "medium"),
        Unit("NoSQLi", "regex_operator_injection", "json", "q", "opérateur $regex non exposé au client", regex_dos_injection, "hard"),
    ]
