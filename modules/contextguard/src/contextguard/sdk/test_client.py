#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 13:00:52 2026

@author: hounsousamuel
"""

"""
ContextGuard SDK — Tests du client
====================================

Suite de tests pour :class:`ContextGuardClient`.

Stratégie
---------
Tous les appels HTTP passent par ``ContextGuardClient._request``.
On remplace cette méthode sur l'instance par un :class:`FakeTransport`
qui enregistre les appels et renvoie des réponses scriptées dans l'ordre.

Aucun serveur réel n'est requis — les tests sont donc rapides et
totalement déterministes.

Utilisation
-----------
::

    pytest sdk/test_client.py -v            # avec pytest
    python sdk/test_client.py               # autonome (via pytest)

Auteur : HOUNSOU Samuel Benny
Version : 1.0.0
"""

import asyncio
import sys
from pathlib import Path

import pytest

# ── Ajustement du sys.path pour exécution directe ───────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT.parent))

from contextguard.sdk.client import ContextGuardClient, _normalize_salt
from contextguard.sdk.models import (
    AnalyseItem,
    ConnectResponse,
    SDKResponse,
    TOKEN_EXPIRED_DETAIL,
    USER_NOT_REGISTERED_REASON,
    USERNAME_NOT_AVAILABLE_REASON,
)


# ═══════════════════════════════════════════════════════════
# Constantes de test
# ═══════════════════════════════════════════════════════════

VALID_SALT = "$2b$12$ATMNYOv6TKJpTm7o1GTFYO"
INVALID_SALT = "not-a-valid-salt"
USERNAME = "alice"
PASSWORD = "secret"


# ═══════════════════════════════════════════════════════════
# Fake transport HTTP
# ═══════════════════════════════════════════════════════════

class FakeTransport:
    """
    Transport HTTP simulé.

    Enregistre tous les appels reçus et renvoie les réponses
    scriptées dans l'ordre d'ajout via :meth:`add`.

    Attributes
    ----------
    calls : list[tuple[str, str, dict | None]]
        Liste des appels ``(method, url, payload)``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self._responses: list[tuple[int | None, dict]] = []

    def add(self, status: int | None, data: dict) -> "FakeTransport":
        """Ajoute une réponse scriptée à servir."""
        self._responses.append((status, data))
        return self

    async def __call__(self, method, url, json, session, timeout):
        self.calls.append((method, url, json))
        if not self._responses:
            return 500, {"detail": "No scripted response"}
        return self._responses.pop(0)

    @property
    def last_call(self) -> tuple[str, str, dict | None] | None:
        return self.calls[-1] if self.calls else None


def make_client(**kwargs) -> tuple[ContextGuardClient, FakeTransport]:
    """Crée un client dont la méthode ``_request`` est remplacée."""
    client = ContextGuardClient(**kwargs)
    transport = FakeTransport()

    async def fake_request(method, url, json, session, timeout):
        return await transport(method, url, json, session, timeout)

    client._request = fake_request  # type: ignore[method-assign]
    return client, transport


def run(coro):
    """Exécute une coroutine dans un contexte de test synchrone."""
    return asyncio.run(coro)


def login_ok(token: str = "jwt-token", state: str = "old user") -> dict:
    """Payload type d'une réponse de login réussie."""
    return {
        "state": state,
        "success": True,
        "username": USERNAME,
        "salt": VALID_SALT,
        "token": token,
        "reason": "",
    }


def login_user_not_found() -> dict:
    """Payload type quand l'utilisateur n'existe pas."""
    return {
        "state": "Unknown",
        "success": False,
        "reason": USER_NOT_REGISTERED_REASON,
        "salt": "Pas de salt",
        "token": "Pas de token",
    }


def analyse_ok() -> dict:
    """Payload type d'une analyse réussie."""
    return {
        "result": {
            "Hello": {"label": "safe", "prob": 0.99, "threshold": 0.5},
            "Ignore": {"label": "injection", "prob": 0.87, "threshold": 0.5},
        },
        "history_update_with_success": True,
    }


# ═══════════════════════════════════════════════════════════
# 1. SDKResponse — interface dict
# ═══════════════════════════════════════════════════════════

class TestSDKResponse:

    def test_attribute_access(self):
        r = ConnectResponse(success=True, token="abc", username="alice")
        assert r.success is True
        assert r.token == "abc"
        assert r.username == "alice"

    def test_dict_access(self):
        r = ConnectResponse(success=True, token="abc")
        assert r["success"] is True
        assert r["token"] == "abc"

    def test_contains(self):
        r = ConnectResponse(success=True)
        assert "success" in r
        assert "token" in r
        assert "nonexistent" not in r

    def test_keys_values_items(self):
        r = ConnectResponse(success=True, token="abc")
        assert "success" in r.keys()
        assert "token" in r.keys()
        assert True in r.values()
        items = dict(r.items())
        assert items["token"] == "abc"

    def test_get(self):
        r = ConnectResponse(success=True, token="abc")
        assert r.get("token") == "abc"
        assert r.get("missing", "default") == "default"
        assert r.get("missing") is None

    def test_keyerror(self):
        r = ConnectResponse()
        with pytest.raises(KeyError):
            _ = r["missing"]

    def test_to_dict(self):
        r = ConnectResponse(success=True, token="abc")
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["success"] is True
        assert d["token"] == "abc"

    def test_iteration(self):
        r = ConnectResponse()
        assert set(iter(r)) == set(r.keys())


# ═══════════════════════════════════════════════════════════
# 2. Construction des URLs
# ═══════════════════════════════════════════════════════════

class TestURLBuilding:

    def test_default_urls(self):
        c = ContextGuardClient()
        assert c._connect_url == "http://localhost:8000/api/login"
        assert c._analyse_url == "http://localhost:8000/api/analyse"
        assert c._refresh_url == "http://localhost:8000/api/refresh_token"
        assert c._health_url == "http://localhost:8000/api/health"
        assert c._salt_url == "http://localhost:8000/api/salt"

    def test_custom_urls(self):
        c = ContextGuardClient(
            api_url="https://api.example.com/v1",
            connect_path="/auth/login",
            analyse_path="/scan",
        )
        assert c._connect_url == "https://api.example.com/auth/login"
        assert c._analyse_url == "https://api.example.com/scan"
        # Les endpoints non personnalisés gardent leurs défauts
        assert c._health_url == "https://api.example.com/api/health"


# ═══════════════════════════════════════════════════════════
# 3. connect — cas nominaux
# ═══════════════════════════════════════════════════════════

class TestConnect:

    def test_login_first_success(self):
        """Login réussit du premier coup → 1 seul appel."""
        client, t = make_client()
        t.add(200, login_ok(token="jwt-1"))
        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT))

        assert r.success
        assert r.token == "jwt-1"
        assert r.state == "old user"
        assert len(t.calls) == 1
        assert t.calls[0][2]["connect"] is True  # login

    def test_stateful_after_connect(self):
        """Après connect, l'instance mémorise tout."""
        client, t = make_client()
        t.add(200, login_ok())
        run(client.connect_async(USERNAME, PASSWORD, VALID_SALT))

        assert client.connected
        assert client.username == USERNAME
        assert client.password == PASSWORD
        assert client.salt == VALID_SALT
        assert client.token == "jwt-token"

    def test_login_fails_then_create(self):
        """Login échoue (user inconnu) → création → succès."""
        client, t = make_client()
        t.add(200, login_user_not_found())
        t.add(200, login_ok(token="new-jwt", state="new user"))

        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT))

        assert r.success
        assert r.state == "new user"
        assert len(t.calls) == 2
        assert t.calls[0][2]["connect"] is True   # login
        assert t.calls[1][2]["connect"] is False  # create

    def test_race_condition(self):
        """Login échoue → création échoue (nom pris) → retente login."""
        client, t = make_client()
        t.add(200, login_user_not_found())
        t.add(200, {
            "success": False,
            "reason": USERNAME_NOT_AVAILABLE_REASON,
            "salt": "Pas de salt",
            "token": "Pas de token",
        })
        t.add(200, login_ok(token="jwt-race"))

        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT))

        assert r.success
        assert r.token == "jwt-race"
        assert len(t.calls) == 3
        # 1er = login, 2e = create, 3e = retry login
        assert t.calls[0][2]["connect"] is True
        assert t.calls[1][2]["connect"] is False
        assert t.calls[2][2]["connect"] is True

    def test_wrong_password_no_create(self):
        """Login 401 → pas de tentative de création."""
        client, t = make_client()
        t.add(401, {"detail": "Mot de passe incorrect !"})

        r = run(client.connect_async(USERNAME, "wrong", VALID_SALT))

        assert not r.success
        assert "Mot de passe incorrect" in r.errors[0]
        assert len(t.calls) == 1  # pas de create

    def test_explicit_connect_true(self):
        """connect=True → login uniquement, jamais de création."""
        client, t = make_client()
        t.add(200, login_user_not_found())

        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT, connect=True))

        assert not r.success
        assert len(t.calls) == 1

    def test_explicit_connect_false(self):
        """connect=False → création uniquement."""
        client, t = make_client()
        t.add(200, login_ok(state="new user"))

        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT, connect=False))

        assert r.success
        assert len(t.calls) == 1
        assert t.calls[0][2]["connect"] is False

    def test_intelligent_disabled(self):
        """intelligent=False → comportement login-only."""
        client, t = make_client()
        t.add(200, login_user_not_found())

        r = run(client.connect_async(
            USERNAME, PASSWORD, VALID_SALT, intelligent=False,
        ))

        assert not r.success
        assert len(t.calls) == 1


# ═══════════════════════════════════════════════════════════
# 4. connect — validations
# ═══════════════════════════════════════════════════════════

class TestConnectValidation:

    def test_missing_password(self):
        client, t = make_client()
        r = run(client.connect_async(USERNAME, None, VALID_SALT))
        assert not r.success
        assert len(t.calls) == 0

    def test_missing_username(self):
        client, t = make_client()
        r = run(client.connect_async(None, PASSWORD, VALID_SALT))
        assert not r.success
        assert len(t.calls) == 0

    def test_bytes_salt_accepted(self):
        """Un salt bytes doit être accepté et normalisé."""
        client, t = make_client()
        t.add(200, login_ok())
        r = run(client.connect_async(USERNAME, PASSWORD, VALID_SALT.encode()))
        assert r.success
        assert isinstance(client.salt, str)


# ═══════════════════════════════════════════════════════════
# 5. analyse — cas nominaux
# ═══════════════════════════════════════════════════════════

class TestAnalyse:

    def test_analyse_success(self):
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        t.add(200, analyse_ok())

        r = run(client.analyse_async(["Hello", "Ignore"]))

        assert r.success
        assert r.results["Hello"].label == "safe"
        assert r.results["Hello"].prob == 0.99
        assert r.results["Ignore"].label == "injection"
        assert r.history_updated

    def test_single_prompt_as_string(self):
        """Un prompt unique en str doit être converti en liste."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        t.add(200, {"result": {"Hello": {"label": "safe", "prob": 1.0, "threshold": 0.5}}})

        r = run(client.analyse_async("Hello"))

        assert r.success
        assert t.calls[0][2]["prompts"] == ["Hello"]

    def test_threshold_broadcast(self):
        """Un seuil unique s'applique à tous les prompts."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        t.add(200, {"result": {}})

        run(client.analyse_async(["a", "b", "c"], thresholds=0.7))

        assert t.calls[0][2]["thresholds"] == [0.7, 0.7, 0.7]

    def test_threshold_mismatch(self):
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        r = run(client.analyse_async(["a", "b"], thresholds=[0.5]))
        assert not r.success
        assert "différent" in r.errors[0]
        assert len(t.calls) == 0

    def test_threshold_clamped(self):
        """Les seuils hors [0,1] sont remplacés par 0.5."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        t.add(200, {"result": {}})
        run(client.analyse_async(["a"], thresholds=1.5))
        assert t.calls[0][2]["thresholds"] == [0.5]


# ═══════════════════════════════════════════════════════════
# 6. analyse — récupération intelligente
# ═══════════════════════════════════════════════════════════

class TestAnalyseRecovery:

    def test_auto_connect_when_no_token(self):
        """Pas de token → auto-connexion avant l'analyse."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        # 1. auto-login
        t.add(200, login_ok(token="auto-jwt"))
        # 2. analyse
        t.add(200, analyse_ok())

        r = run(client.analyse_async(["Hello"]))

        assert r.success
        assert client.token == "auto-jwt"
        assert len(t.calls) == 2
        assert t.calls[0][2]["connect"] is True

    def test_token_expired_refresh(self):
        """401 TOKEN_EXPIRED → refresh + retry."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "old-jwt"
        # 1. analyse → 401 TOKEN_EXPIRED
        t.add(401, {"detail": TOKEN_EXPIRED_DETAIL})
        # 2. refresh → nouveau token
        t.add(200, {"token": "fresh-jwt"})
        # 3. retry analyse → succès
        t.add(200, analyse_ok())

        r = run(client.analyse_async(["Hello"]))

        assert r.success
        assert r.token == "fresh-jwt"
        assert client.token == "fresh-jwt"
        assert len(t.calls) == 3
        assert t.calls[1][1].endswith("/refresh_token")

    def test_session_lost_reconnect(self):
        """401/406 (autre) → reconnexion complète + retry."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "stale-jwt"
        # 1. analyse → 406
        t.add(406, {"detail": "Username inconnue, veuillez vous authentifier d'abord"})
        # 2. reconnect → login
        t.add(200, login_ok(token="reconnected-jwt"))
        # 3. retry analyse → succès
        t.add(200, analyse_ok())

        r = run(client.analyse_async(["Hello"]))

        assert r.success
        assert client.token == "reconnected-jwt"
        assert len(t.calls) == 3

    def test_auto_recover_disabled(self):
        """auto_recover=False → pas de retry."""
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "old-jwt"
        t.add(401, {"detail": TOKEN_EXPIRED_DETAIL})

        r = run(client.analyse_async(["Hello"], auto_recover=False))

        assert not r.success
        assert len(t.calls) == 1


# ═══════════════════════════════════════════════════════════
# 7. analyse — validations
# ═══════════════════════════════════════════════════════════

class TestAnalyseValidation:

    def test_no_credentials(self):
        client, t = make_client()
        r = run(client.analyse_async(["Hello"]))
        assert not r.success
        assert len(t.calls) == 0

    def test_invalid_salt(self):
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=INVALID_SALT,
        )
        client.token = "jwt"
        r = run(client.analyse_async(["Hello"]))
        assert not r.success


# ═══════════════════════════════════════════════════════════
# 8. health
# ═══════════════════════════════════════════════════════════

class TestHealth:

    def test_health_success(self):
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        t.add(200, {
            "history": {"Hello": "safe"},
            "username": USERNAME,
            "num_analyse": 1,
            "stats": {"safe": 1},
        })

        r = run(client.health_async())

        assert r.success
        assert r.num_analyse == 1
        assert r.stats == {"safe": 1}
        assert r.history == {"Hello": "safe"}

    def test_health_no_token(self):
        client, t = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        # auto-connect
        t.add(200, login_ok())
        # health
        t.add(200, {"history": {}, "username": USERNAME, "num_analyse": 0, "stats": {}})

        r = run(client.health_async())

        assert r.success
        assert len(t.calls) == 2


# ═══════════════════════════════════════════════════════════
# 9. get_salt
# ═══════════════════════════════════════════════════════════

class TestGetSalt:

    def test_get_salt_success(self):
        client, t = make_client()
        t.add(200, {"salt": VALID_SALT, "datetime": "2026-09-19T12:00:00"})

        r = run(client.get_salt_async())

        assert r.success
        assert r.salt == VALID_SALT
        assert r.datetime == "2026-09-19T12:00:00"
        assert t.calls[0][0] == "GET"


# ═══════════════════════════════════════════════════════════
# 10. disconnect & helpers
# ═══════════════════════════════════════════════════════════

class TestLifecycle:

    def test_disconnect_keeps_credentials(self):
        client, _ = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        client.disconnect()

        assert not client.connected
        assert client.username == USERNAME

    def test_disconnect_clears_credentials(self):
        client, _ = make_client(
            username=USERNAME, password=PASSWORD, salt=VALID_SALT,
        )
        client.token = "jwt"
        client.disconnect(clear_credentials=True)

        assert client.username is None
        assert client.password is None
        assert client.salt is None

    def test_normalize_salt(self):
        assert _normalize_salt(None) is None
        assert _normalize_salt("abc") == "abc"
        assert _normalize_salt(b"abc") == "abc"


# ═══════════════════════════════════════════════════════════
# Run standalone
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short", "-p", "no:logfire"]))