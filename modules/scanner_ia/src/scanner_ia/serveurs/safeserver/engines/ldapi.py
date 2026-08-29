"""LDAPi (safe) — échappement des caractères spéciaux LDAP avant construction du filtre."""
from .base import Unit, UnitCtx

DIRECTORY = [
    {"uid": "admin", "password": "AdminLdap123", "cn": "Administrator"},
    {"uid": "alice", "password": "AlicePwd1", "cn": "Alice Martin"},
]

_LDAP_ESCAPE = {"\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29", "\x00": "\\00"}


def _ldap_escape(s: str) -> str:
    return "".join(_LDAP_ESCAPE.get(c, c) for c in s)


def make_units(resource):
    def login_filter_injection(ctx: UnitCtx):
        username = ctx.value("")
        escaped = _ldap_escape(username)
        ldap_filter = f"(&(uid={escaped})(objectClass=person))"
        matches = [e for e in DIRECTORY if e["uid"] == username]  # comparaison exacte, pas de wildcard
        return {"ldap_filter": ldap_filter, "authenticated_bypass": False,
                "note": "caractères spéciaux LDAP échappés, comparaison exacte côté serveur"}

    def search_filter_injection(ctx: UnitCtx):
        q = ctx.value("")
        escaped = _ldap_escape(q)
        ldap_filter = f"(cn=*{escaped}*)"
        matches = [e for e in DIRECTORY if q.lower() in e["cn"].lower()]
        return {"ldap_filter": ldap_filter, "count": len(matches), "note": f"recherche {resource} avec entrée échappée"}

    return [
        Unit("LDAPi", "login_filter_wildcard", "form", "username", "caractères LDAP échappés", login_filter_injection, "medium"),
        Unit("LDAPi", "search_filter_wildcard", "query", "q", "caractères LDAP échappés", search_filter_injection, "medium"),
    ]
