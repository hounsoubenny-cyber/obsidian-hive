"""LDAPi — injection dans un filtre LDAP (simulation via annuaire in-memory)."""
import re
from .base import Unit, UnitCtx

DIRECTORY = [
    {"uid": "admin", "password": "AdminLdap123", "cn": "Administrator"},
    {"uid": "alice", "password": "AlicePwd1", "cn": "Alice Martin"},
]


def _ldap_filter_match(filter_str: str, entry: dict) -> bool:
    """Évaluateur ultra-simplifié : traite '*' comme wildcard sans échappement,
    reproduisant le comportement vulnérable d'un vrai serveur LDAP mal protégé."""
    pattern = re.escape(filter_str).replace(r"\*", ".*")
    try:
        return bool(re.search(pattern, entry.get("uid", ""), re.IGNORECASE))
    except re.error:
        return False


def make_units(resource):
    def login_filter_injection(ctx: UnitCtx):
        username = ctx.value("*")
        # filtre LDAP construit par concaténation directe, non échappé
        ldap_filter = f"(&(uid={username})(objectClass=person))"
        matches = [e for e in DIRECTORY if _ldap_filter_match(username, e)]
        return {"ldap_filter": ldap_filter, "matches": [m["uid"] for m in matches],
                "authenticated_bypass": len(matches) > 0}

    def search_filter_injection(ctx: UnitCtx):
        q = ctx.value("*")
        ldap_filter = f"(cn=*{q}*)"
        matches = [e for e in DIRECTORY if _ldap_filter_match(q, e)]
        return {"ldap_filter": ldap_filter, "count": len(matches),
                "note": f"recherche annuaire {resource} avec filtre LDAP non échappé"}

    return [
        Unit("LDAPi", "login_filter_wildcard", "form", "username",
             "filtre LDAP de login construit par concaténation directe", login_filter_injection, "medium"),
        Unit("LDAPi", "search_filter_wildcard", "query", "q",
             f"filtre LDAP de recherche {resource} non échappé", search_filter_injection, "medium"),
    ]
