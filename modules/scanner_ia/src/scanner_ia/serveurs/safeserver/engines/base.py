"""
Base commune à tous les moteurs de vulnérabilités.

Chaque moteur (engines/<vuln>.py) expose une fonction:
    make_units(resource: str) -> list[Unit]

Un Unit représente UNE variante technique d'UNE vulnérabilité, appliquée
à une "ressource" (nom métier utilisé pour la route / les données, ex:
"products", "invoices"...). Un Unit sait:
  - où se trouve le point d'injection (context: query/form/json/header/cookie/path)
  - comment extraire la valeur envoyée par le client
  - exécuter le comportement réellement vulnérable et retourner un fragment
    de réponse JSON

Les routes "mono-vuln" utilisent un seul Unit.
Les routes "multi-vuln" combinent plusieurs Units (potentiellement de
moteurs différents) dans le même handler HTTP.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, Any, Optional
from flask import request as flask_request

VALID_CONTEXTS = ("query", "form", "json", "header", "cookie", "path")


@dataclass
class Unit:
    vuln_id: str                 # ex: "SQLi"
    variant: str                 # ex: "order_by_injection"
    context: str                 # query|form|json|header|cookie|path
    param: str                   # nom du paramètre / header / cookie / segment de path
    description: str             # description courte de CE variant précis
    handler: Callable[["UnitCtx"], Dict[str, Any]]
    difficulty: str = "easy"     # easy|medium|hard (pour équilibrer le dataset)
    http_method: Optional[str] = None  # forcé à GET/POST si besoin, sinon déduit du context


@dataclass
class UnitCtx:
    """Contexte passé au handler() d'un Unit au moment de la requête."""
    unit: Unit
    path_kwargs: Dict[str, str]

    def value(self, default: str = "") -> str:
        u = self.unit
        r = flask_request
        if u.context == "query":
            return r.args.get(u.param, default)
        if u.context == "form":
            return r.form.get(u.param, default)
        if u.context == "json":
            body = r.get_json(silent=True) or {}
            return str(body.get(u.param, default))
        if u.context == "header":
            return r.headers.get(u.param, default)
        if u.context == "cookie":
            return r.cookies.get(u.param, default)
        if u.context == "path":
            return self.path_kwargs.get(u.param, default)
        return default

    def raw_json(self) -> dict:
        return flask_request.get_json(silent=True) or {}


def context_needs(context: str) -> str:
    """Méthode HTTP naturelle pour un contexte donné."""
    return "POST" if context in ("form", "json") else "GET"


# ---------------------------------------------------------------------
# Fake data partagée entre moteurs (données factices, pas de vraies PII)
# ---------------------------------------------------------------------

def fake_records(resource: str, n: int = 6):
    """Génère une petite table factice pour une ressource donnée."""
    out = []
    for i in range(1, n + 1):
        out.append({
            "id": i,
            "name": f"{resource}_{i}",
            "owner_id": (i % 3) + 1,
            "secret": f"internal-{resource}-token-{i}-XZ9",
            "email": f"user{i}@example.test",
        })
    return out


USERS_TABLE = [
    {"id": 1, "username": "admin", "password": "admin123", "role": "admin",
     "email": "admin@example.test", "api_key": "sk_live_TESTKEY_ADMIN_0001"},
    {"id": 2, "username": "alice", "password": "alicepwd", "role": "user",
     "email": "alice@example.test", "api_key": "sk_live_TESTKEY_ALICE_0002"},
    {"id": 3, "username": "bob", "password": "bobpwd123", "role": "user",
     "email": "bob@example.test", "api_key": "sk_live_TESTKEY_BOB_0003"},
]

JWT_SECRET = "dev-secret-please-change"  # volontairement faible pour le moteur JWT
