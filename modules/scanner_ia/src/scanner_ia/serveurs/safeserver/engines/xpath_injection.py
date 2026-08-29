"""XPATH_Injection (safe) — comparaison en Python après extraction, pas de concaténation dans l'expression XPath."""
from lxml import etree
from .base import Unit, UnitCtx

_XML_USERS = etree.fromstring("""
<users>
  <user><username>admin</username><password>AdminXPath1</password><role>admin</role></user>
  <user><username>alice</username><password>AliceXPath1</password><role>user</role></user>
</users>
""")


def make_units(resource):
    def login_xpath_concat(ctx: UnitCtx):
        from flask import request as freq
        user = ctx.value("nobody")
        pwd = freq.form.get("password", "wrong")
        # extraction fixe puis comparaison en Python, aucune valeur client dans l'expression XPath
        nodes = _XML_USERS.xpath("//user")
        match = any(n.findtext("username") == user and n.findtext("password") == pwd for n in nodes)
        return {"authenticated": match, "note": "expression XPath fixe, comparaison faite en Python après extraction"}

    def search_xpath_concat(ctx: UnitCtx):
        q = ctx.value("admin")
        nodes = _XML_USERS.xpath("//user")
        matches = [n.findtext("username") for n in nodes if q.lower() in (n.findtext("username") or "").lower()]
        return {"matches": len(matches), "note": f"recherche {resource} : filtrage Python, expression XPath non paramétrée par le client"}

    return [
        Unit("XPATH_Injection", "login_xpath_concat", "form", "username", "expression XPath fixe, comparaison Python", login_xpath_concat, "medium"),
        Unit("XPATH_Injection", "search_xpath_concat", "query", "q", "filtrage Python, pas de concaténation XPath", search_xpath_concat, "medium"),
    ]
