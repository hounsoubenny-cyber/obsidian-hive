"""XPATH_Injection — filtre XPath construit par concaténation directe."""
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
        pwd = freq.values.get("password", "wrong")
        expr = f"//user[username='{user}' and password='{pwd}']"
        try:
            nodes = _XML_USERS.xpath(expr)
            return {"xpath_expr": expr, "matches": len(nodes), "authenticated": len(nodes) > 0}
        except Exception as e:
            return {"xpath_expr": expr, "error": str(e)}

    def search_xpath_concat(ctx: UnitCtx):
        q = ctx.value("admin")
        expr = f"//user[contains(username,'{q}')]"
        try:
            nodes = _XML_USERS.xpath(expr)
            return {"xpath_expr": expr, "matches": len(nodes),
                    "note": f"recherche {resource} construite par concaténation directe dans une requête XPath"}
        except Exception as e:
            return {"xpath_expr": expr, "error": str(e)}

    return [
        Unit("XPATH_Injection", "login_xpath_concat", "form", "username",
             "filtre XPath de login construit par concaténation directe", login_xpath_concat, "medium"),
        Unit("XPATH_Injection", "search_xpath_concat", "query", "q",
             f"filtre XPath de recherche {resource} non paramétré", search_xpath_concat, "medium"),
    ]
