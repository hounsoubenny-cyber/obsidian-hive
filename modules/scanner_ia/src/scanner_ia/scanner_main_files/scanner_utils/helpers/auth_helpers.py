#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 16:46:58 2026

@author: hounsousamuel
"""

"""
ShieldAI — Auth Helpers
=======================
Base de helpers d'authentification génériques.
Chaque helper reçoit `session: aiohttp.ClientSession` en premier argument
et mute la session (cookies, headers) pour que le scanner soit authentifié.

Catégories :
  1. Form Login         — POST classique sur formulaire HTML
  2. CSRF Form Login    — Form login avec récupération de token CSRF
  3. Basic Auth         — HTTP Basic Authentication
  4. Bearer / API Key   — Header Authorization ou X-Api-Key
  5. Cookie Inject      — Injection directe de cookies
  6. Header Inject      — Injection directe de headers arbitraires
  7. JWT Login          — POST → token JWT → injecté dans Authorization
  8. OAuth2 Password    — Resource Owner Password Credentials
  9. Digest Auth        — HTTP Digest (via aiohttp DigestAuth)
 10. NTLM / Windows     — NTLM via requests-ntlm (sync fallback)
 11. Multi-step Login   — Enchaînement séquentiel de helpers
 12. Apps connues       — DVWA, Juice Shop, WebGoat, bWAPP, Mutillidae, HackTheBox, TryHackMe,
                          Grafana, Jenkins, GitLab, Gitea, Nextcloud, WordPress, Joomla,
                          phpMyAdmin, Adminer, Roundcube, OpenWRT, pfSense, Keycloak,
                          Metabase, Portainer, Traefik, AWX/Tower
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import re
import base64
import json
import aiohttp
from typing import Optional
from bs4 import BeautifulSoup

# import scanner_ia.scanner_utils.helpers.auth_helpers as auth_helpers

from scanner_ia.scanner_utils.logger import get_logger

logger = get_logger()
# =============================================================================
# UTILITAIRES INTERNES
# =============================================================================


async def _get_html(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url, allow_redirects=True) as r:
        return await r.text()


def _find_csrf(
    html: str,
    field_names=(
        "csrf_token",
        "user_token",
        "_token",
        "authenticity_token",
        "__RequestVerificationToken",
        "csrfmiddlewaretoken",
        "_csrf",
        "token",
    ),
) -> str:
    """Cherche un token CSRF dans le HTML (input hidden)."""
    soup = BeautifulSoup(html, "html.parser")
    for name in field_names:
        inp = soup.find("input", {"name": name})
        if inp and inp.get("value"):
            return inp["value"]
    # Fallback : meta tag
    meta = soup.find("meta", {"name": re.compile("csrf", re.I)})
    if meta and meta.get("content"):
        return meta["content"]
    return ""


def _inject_bearer(session: aiohttp.ClientSession, token: str, scheme: str = "Bearer"):
    session.headers.update({"Authorization": f"{scheme} {token}"})


def _inject_cookies(session: aiohttp.ClientSession, cookies: dict, domain: str = ""):
    jar = aiohttp.CookieJar()
    for name, value in cookies.items():
        morsel = {"name": name, "value": value}
        jar.update_cookies({name: value})
    session.cookie_jar.update_cookies(cookies)


# =============================================================================
# 1. FORM LOGIN SIMPLE
# =============================================================================


async def form_login(
    session: aiohttp.ClientSession,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "",
    password: str = "",
    extra_fields: Optional[dict] = None,
    success_check: Optional[str] = None,
    method: str = "POST",
    *args,
    **kwargs,
) -> bool:
    """
    Login via formulaire HTML simple (sans CSRF).

    Params:
        login_url       : URL du formulaire de login
        username_field  : nom du champ username (défaut: "username")
        password_field  : nom du champ password (défaut: "password")
        username        : valeur username
        password        : valeur password
        extra_fields    : champs supplémentaires à envoyer {name: value}
        success_check   : string à chercher dans la réponse pour valider
        method          : "POST" ou "GET"

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "form_login",
            "kwargs": {
                "login_url": "http://target.com/login",
                "username": "admin",
                "password": "secret"
            }
        }]
    """
    data = {
        username_field: username,
        password_field: password,
    }
    if extra_fields:
        data.update(extra_fields)

    if method.upper() == "POST":
        async with session.post(login_url, data=data, allow_redirects=True) as resp:
            html = await resp.text()
    else:
        async with session.get(login_url, params=data, allow_redirects=True) as resp:
            html = await resp.text()

    if success_check and success_check not in html:
        raise Exception(f"form_login: succès non confirmé ('{success_check}' absent de la réponse)")

    logger.info(f"✅ form_login: authentifié sur {login_url}")
    return True


# =============================================================================
# 2. CSRF FORM LOGIN
# =============================================================================


async def csrf_form_login(
    session: aiohttp.ClientSession,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "",
    password: str = "",
    csrf_field: Optional[str] = None,
    extra_fields: Optional[dict] = None,
    success_check: Optional[str] = None,
    get_url: Optional[str] = None,
    *args,
    **kwargs,
) -> bool:
    """
    Login via formulaire avec token CSRF auto-récupéré.

    Params:
        get_url     : URL pour récupérer le CSRF (défaut = login_url)
        csrf_field  : nom du champ CSRF (None = auto-detect)

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "csrf_form_login",
            "kwargs": {
                "login_url": "http://target.com/login",
                "username": "admin",
                "password": "pass123",
                "success_check": "Dashboard"
            }
        }]
    """
    page_url = get_url or login_url
    html = await _get_html(session, page_url)

    csrf_names = (csrf_field,) if csrf_field else None
    token = _find_csrf(
        html,
        csrf_names
        or (
            "csrf_token",
            "user_token",
            "_token",
            "authenticity_token",
            "__RequestVerificationToken",
            "csrfmiddlewaretoken",
            "_csrf",
            "token",
        ),
    )

    data = {
        username_field: username,
        password_field: password,
    }
    if token:
        detected_field = csrf_field or "csrf_token"
        # Chercher le vrai nom dans le HTML
        soup = BeautifulSoup(html, "html.parser")
        for name in (
            "csrf_token",
            "user_token",
            "_token",
            "authenticity_token",
            "__RequestVerificationToken",
            "csrfmiddlewaretoken",
            "_csrf",
            "token",
        ):
            inp = soup.find("input", {"name": name})
            if inp and inp.get("value") == token:
                detected_field = name
                break
        data[detected_field] = token

    if extra_fields:
        data.update(extra_fields)

    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        resp_html = await resp.text()

    if success_check and success_check not in resp_html:
        raise Exception(f"csrf_form_login: succès non confirmé ('{success_check}' absent)")

    logger.info(f"✅ csrf_form_login: authentifié sur {login_url} (token CSRF = {token[:12]}...)")
    return True


# =============================================================================
# 3. BASIC AUTH
# =============================================================================


async def basic_auth(
    session: aiohttp.ClientSession, username: str, password: str, *args, **kwargs
) -> bool:
    """
    Injecte un header Authorization: Basic dans la session.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "basic_auth",
            "kwargs": {"username": "admin", "password": "admin"}
        }]
    """
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    session.headers.update({"Authorization": f"Basic {encoded}"})
    logger.info(f"✅ basic_auth: header injecté pour {username}")
    return True


# =============================================================================
# 4. BEARER TOKEN / API KEY
# =============================================================================


async def bearer_token(
    session: aiohttp.ClientSession, token: str, scheme: str = "Bearer", *args, **kwargs
) -> bool:
    """
    Injecte un header Authorization: Bearer <token>.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "bearer_token",
            "kwargs": {"token": "eyJhbGci..."}
        }]
    """
    session.headers.update({"Authorization": f"{scheme} {token}"})
    logger.info(f"✅ bearer_token: {scheme} token injecté")
    return True


async def api_key_header(
    session: aiohttp.ClientSession, api_key: str, header_name: str = "X-Api-Key", *args, **kwargs
) -> bool:
    """
    Injecte une API key dans un header custom.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "api_key_header",
            "kwargs": {"api_key": "abc123", "header_name": "X-API-KEY"}
        }]
    """
    session.headers.update({header_name: api_key})
    logger.info(f"✅ api_key_header: {header_name} injecté")
    return True


async def api_key_cookie(
    session: aiohttp.ClientSession, api_key: str, cookie_name: str = "api_key", *args, **kwargs
) -> bool:
    """
    Injecte une API key comme cookie.
    """
    session.cookie_jar.update_cookies({cookie_name: api_key})
    logger.info(f"✅ api_key_cookie: cookie {cookie_name} injecté")
    return True


# =============================================================================
# 5. COOKIE INJECT
# =============================================================================


async def inject_cookies(session: aiohttp.ClientSession, cookies: dict, *args, **kwargs) -> bool:
    """
    Injecte un dictionnaire de cookies directement.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "inject_cookies",
            "kwargs": {"cookies": {"PHPSESSID": "abc123", "auth": "1"}}
        }]
    """
    session.cookie_jar.update_cookies(cookies)
    logger.info(f"✅ inject_cookies: {len(cookies)} cookie(s) injecté(s)")
    return True


# =============================================================================
# 6. HEADER INJECT
# =============================================================================


async def inject_headers(session: aiohttp.ClientSession, headers: dict, *args, **kwargs) -> bool:
    """
    Injecte des headers arbitraires dans la session.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "inject_headers",
            "kwargs": {"headers": {"X-Forwarded-For": "127.0.0.1", "X-Custom": "val"}}
        }]
    """
    session.headers.update(headers)
    logger.info(f"✅ inject_headers: {list(headers.keys())} injecté(s)")
    return True


# =============================================================================
# 7. JWT LOGIN
# =============================================================================


async def jwt_login(
    session: aiohttp.ClientSession,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "",
    password: str = "",
    token_path: str = "token",
    scheme: str = "Bearer",
    extra_body: Optional[dict] = None,
    content_type: str = "json",
    *args,
    **kwargs,
) -> bool:
    """
    POST JSON → récupère un JWT → injecte Authorization: Bearer.

    Params:
        token_path  : clé JSON du token dans la réponse (ex: "token", "access_token", "data.token")
        content_type: "json" ou "form"

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "jwt_login",
            "kwargs": {
                "login_url": "http://api.target.com/auth/login",
                "username": "admin",
                "password": "pass",
                "token_path": "access_token"
            }
        }]
    """
    body = {
        username_field: username,
        password_field: password,
    }
    if extra_body:
        body.update(extra_body)

    if content_type == "json":
        async with session.post(login_url, json=body, allow_redirects=True) as resp:
            data = await resp.json(content_type=None)
    else:
        async with session.post(login_url, data=body, allow_redirects=True) as resp:
            data = await resp.json(content_type=None)

    # Navigation dans le JSON pour token_path composé ("data.token")
    token = data
    for key in token_path.split("."):
        if isinstance(token, dict):
            token = token.get(key)
        else:
            token = None
            break

    if not token:
        raise Exception(f"jwt_login: token non trouvé à '{token_path}' dans la réponse: {data}")

    _inject_bearer(session, str(token), scheme)
    logger.info(f"✅ jwt_login: JWT injecté depuis {login_url}")
    return True


# =============================================================================
# 8. OAUTH2 PASSWORD GRANT
# =============================================================================


async def oauth2_password(
    session: aiohttp.ClientSession,
    token_url: str,
    username: str,
    password: str,
    client_id: str = "",
    client_secret: str = "",
    scope: str = "",
    scheme: str = "Bearer",
    *args,
    **kwargs,
) -> bool:
    """
    OAuth2 Resource Owner Password Credentials Grant.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "oauth2_password",
            "kwargs": {
                "token_url": "http://target.com/oauth/token",
                "username": "admin",
                "password": "pass",
                "client_id": "myapp",
                "client_secret": "secret"
            }
        }]
    """
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret
    if scope:
        data["scope"] = scope

    async with session.post(token_url, data=data) as resp:
        result = await resp.json(content_type=None)

    token = result.get("access_token")
    if not token:
        raise Exception(f"oauth2_password: access_token absent dans la réponse: {result}")

    _inject_bearer(session, token, scheme)
    logger.info(f"✅ oauth2_password: access_token injecté depuis {token_url}")
    return True


# =============================================================================
# 9. DIGEST AUTH
# =============================================================================


async def digest_auth(
    session: aiohttp.ClientSession, url: str, username: str, password: str, *args, **kwargs
) -> bool:
    """
    Effectue une requête Digest Auth pour initialiser les cookies/headers de la session.

    Note: aiohttp ne supporte pas nativement DigestAuth dans les headers de session.
    Cette implémentation fait un GET initial pour déclencher le challenge.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "digest_auth",
            "kwargs": {
                "url": "http://target.com/protected",
                "username": "admin",
                "password": "pass"
            }
        }]
    """
    auth = aiohttp.DigestAuth(username, password)
    async with aiohttp.ClientSession(auth=auth) as tmp_session:
        async with tmp_session.get(url) as resp:
            cookies = {c.key: c.value for c in tmp_session.cookie_jar}

    if cookies:
        session.cookie_jar.update_cookies(cookies)

    logger.info(f"✅ digest_auth: authentifié via Digest sur {url}")
    return True


# =============================================================================
# 10. MULTI-STEP LOGIN
# =============================================================================


async def multi_step_login(session: aiohttp.ClientSession, steps: list, *args, **kwargs) -> bool:
    """
    Enchaîne plusieurs helpers dans l'ordre.
    Utile pour des flows multi-étapes (ex: récupérer un token, puis le soumettre).

    Params:
        steps: liste de {name, args, kwargs} — même format que helpers dans l'API

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "multi_step_login",
            "kwargs": {
                "steps": [
                    {"name": "inject_cookies", "kwargs": {"cookies": {"pre_auth": "1"}}},
                    {"name": "csrf_form_login", "kwargs": {"login_url": "...", "username": "a", "password": "b"}}
                ]
            }
        }]
    """

    for i, step in enumerate(steps):
        name = step.get("name")
        args = step.get("args", [])
        kwargs = step.get("kwargs", {})
        func = getattr(sys.modules[__name__], name, None)
        if func is None:
            raise ValueError(f"Helper inconnu dans multi_step_login: '{name}'")
        logger.info(f"  ↳ multi_step_login étape {i+1}: {name}")
        await func(session, *args, **kwargs)

    logger.info(f"✅ multi_step_login: {len(steps)} étape(s) exécutée(s)")
    return True


# =============================================================================
# 11. APPS CONNUES — DVWA
# =============================================================================


async def dvwa_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    security_level: str = "low",
    *args,
    **kwargs,
) -> bool:
    """
    Auth complète DVWA (login + set security level).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "dvwa_auth",
            "kwargs": {"base_url": "http://localhost:8080", "security_level": "low"}
        }]
    """
    from scanner_ia.scanner_utils.helpers.dvwa_helpers import dvwa_full_setup
    return await dvwa_full_setup(session, base_url, username, password, security_level)


# =============================================================================
# 12. APPS CONNUES — JUICE SHOP
# =============================================================================


async def juice_shop_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    email: str = "admin@juice-sh.op",
    password: str = "admin123",
    *args,
    **kwargs,
) -> bool:
    """
    Auth OWASP Juice Shop via API REST (/api/Users/login) → JWT Bearer.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "juice_shop_auth",
            "kwargs": {"base_url": "http://localhost:3000"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/api/Users/login"
    return await jwt_login(
        session,
        login_url=login_url,
        username_field="email",
        password_field="password",
        username=email,
        password=password,
        token_path="authentication.token",
    )


# =============================================================================
# 13. APPS CONNUES — WEBGOAT
# =============================================================================


async def webgoat_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "guest",
    password: str = "guest",
    *args,
    **kwargs,
) -> bool:
    """
    Auth WebGoat via form login.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "webgoat_auth",
            "kwargs": {"base_url": "http://localhost:8080"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/WebGoat/login"
    return await csrf_form_login(
        session,
        login_url=login_url,
        username_field="username",
        password_field="password",
        username=username,
        password=password,
        success_check="WebGoat",
    )


# =============================================================================
# 14. APPS CONNUES — BWAPP
# =============================================================================


async def bwapp_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    login: str = "bee",
    password: str = "bug",
    security_level: str = "0",
    *args,
    **kwargs,
) -> bool:
    """
    Auth bWAPP (login + set security level via cookie).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "bwapp_auth",
            "kwargs": {"base_url": "http://localhost:8888"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/login.php"
    data = {
        "login": login,
        "password": password,
        "security_level": security_level,
        "form": "submit",
    }
    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "Logged in as" not in html and "portal.php" not in str(resp.url):
            raise Exception("bwapp_auth: échec de connexion")

    session.cookie_jar.update_cookies({"security_level": security_level})
    logger.info(f"✅ bwapp_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 15. APPS CONNUES — MUTILLIDAE II
# =============================================================================


async def mutillidae_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "adminpass",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Mutillidae II.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "mutillidae_auth",
            "kwargs": {"base_url": "http://localhost/mutillidae"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/index.php?page=login.php"
    data = {
        "username": username,
        "password": password,
        "login-php-submit-button": "Login",
    }
    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "Logged In Admin" not in html and username not in html:
            raise Exception("mutillidae_auth: échec de connexion")

    logger.info(f"✅ mutillidae_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 16. APPS CONNUES — WORDPRESS
# =============================================================================


async def wordpress_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    redirect_to: str = "/wp-admin/",
    *args,
    **kwargs,
) -> bool:
    """
    Auth WordPress via wp-login.php avec CSRF (nonce automatique).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "wordpress_auth",
            "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "pass"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/wp-login.php"
    return await csrf_form_login(
        session,
        login_url=login_url,
        username_field="log",
        password_field="pwd",
        username=username,
        password=password,
        extra_fields={
            "wp-submit": "Log In",
            "redirect_to": redirect_to,
            "testcookie": "1",
        },
        success_check=None,
    )


# =============================================================================
# 17. APPS CONNUES — JOOMLA
# =============================================================================


async def joomla_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "admin123",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Joomla Administrator (index.php?option=com_login) avec token CSRF.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "joomla_auth",
            "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "pass"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/administrator/index.php"
    html = await _get_html(session, login_url)

    # Joomla utilise un champ "option" + token aléatoire comme champ caché
    soup = BeautifulSoup(html, "html.parser")
    csrf_token = ""
    # Le token Joomla est un input hidden avec value="1" et un nom de 32 chars hex
    for inp in soup.find_all("input", {"type": "hidden"}):
        name = inp.get("name", "")
        if len(name) == 32 and all(c in "0123456789abcdef" for c in name):
            csrf_token = name
            break

    data = {
        "username": username,
        "passwd": password,
        "option": "com_login",
        "task": "login",
        "return": "aW5kZXgucGhw",
    }
    if csrf_token:
        data[csrf_token] = "1"

    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "com_cpanel" not in html and "Administrator" not in html:
            raise Exception("joomla_auth: échec de connexion")

    logger.info(f"✅ joomla_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 18. APPS CONNUES — PHPMYADMIN
# =============================================================================


async def phpmyadmin_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "root",
    password: str = "",
    *args,
    **kwargs,
) -> bool:
    """
    Auth phpMyAdmin via form login avec token.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "phpmyadmin_auth",
            "kwargs": {"base_url": "http://localhost/phpmyadmin"}
        }]
    """
    index_url = f"{base_url.rstrip('/')}/"
    html = await _get_html(session, index_url)

    token = _find_csrf(html, ("token",))

    data = {
        "pma_username": username,
        "pma_password": password,
        "server": "1",
    }
    if token:
        data["token"] = token

    async with session.post(index_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "pma_navigation" not in html and "Welcome to" not in html:
            raise Exception("phpmyadmin_auth: échec de connexion")

    logger.info(f"✅ phpmyadmin_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 19. APPS CONNUES — GRAFANA
# =============================================================================


async def grafana_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Grafana via API REST (/api/login).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "grafana_auth",
            "kwargs": {"base_url": "http://localhost:3000"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/login"
    return await csrf_form_login(
        session,
        login_url=login_url,
        username_field="user",
        password_field="password",
        username=username,
        password=password,
    )


# =============================================================================
# 20. APPS CONNUES — JENKINS
# =============================================================================


async def jenkins_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Jenkins via Basic Auth (Jenkins accepte Basic nativement).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "jenkins_auth",
            "kwargs": {"base_url": "http://localhost:8080", "username": "admin", "password": "token_or_pass"}
        }]
    """
    return await basic_auth(session, username, password)


# =============================================================================
# 21. APPS CONNUES — GITLAB
# =============================================================================


async def gitlab_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "root",
    password: str = "password",
    *args,
    **kwargs,
) -> bool:
    """
    Auth GitLab via form login avec CSRF (authenticity_token).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "gitlab_auth",
            "kwargs": {"base_url": "http://localhost", "username": "root", "password": "pass"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/users/sign_in"
    return await csrf_form_login(
        session,
        login_url=login_url,
        username_field="user[login]",
        password_field="user[password]",
        username=username,
        password=password,
        csrf_field="authenticity_token",
        extra_fields={"user[remember_me]": "0"},
        success_check=None,
    )


# =============================================================================
# 22. APPS CONNUES — GITEA
# =============================================================================


async def gitea_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "gitea_admin",
    password: str = "gitea_admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Gitea via form login avec _csrf.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "gitea_auth",
            "kwargs": {"base_url": "http://localhost:3000"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/user/login"
    return await csrf_form_login(
        session,
        login_url=login_url,
        username_field="_user_name",
        password_field="_password",
        username=username,
        password=password,
        csrf_field="_csrf",
        success_check=None,
    )


# =============================================================================
# 23. APPS CONNUES — NEXTCLOUD
# =============================================================================


async def nextcloud_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Nextcloud via form login avec requesttoken CSRF.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "nextcloud_auth",
            "kwargs": {"base_url": "http://localhost:8080"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/login"
    html = await _get_html(session, login_url)

    # Nextcloud utilise un requesttoken dans la page
    match = re.search(r'"requesttoken"\s*:\s*"([^"]+)"', html)
    request_token = match.group(1) if match else _find_csrf(html)

    data = {
        "user": username,
        "password": password,
        "timezone": "Europe/Paris",
        "timezone_offset": "1",
    }
    if request_token:
        data["requesttoken"] = request_token

    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        final_url = str(resp.url)
        if "/login" in final_url:
            raise Exception("nextcloud_auth: échec de connexion")

    logger.info(f"✅ nextcloud_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 24. APPS CONNUES — PORTAINER
# =============================================================================


async def portainer_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Portainer via API REST (/api/auth) → JWT.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "portainer_auth",
            "kwargs": {"base_url": "http://localhost:9000"}
        }]
    """
    return await jwt_login(
        session,
        login_url=f"{base_url.rstrip('/')}/api/auth",
        username_field="username",
        password_field="password",
        username=username,
        password=password,
        token_path="jwt",
    )


# =============================================================================
# 25. APPS CONNUES — KEYCLOAK
# =============================================================================


async def keycloak_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    realm: str = "master",
    client_id: str = "admin-cli",
    username: str = "admin",
    password: str = "admin",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Keycloak via OAuth2 password grant sur /token.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "keycloak_auth",
            "kwargs": {
                "base_url": "http://localhost:8080",
                "realm": "master",
                "username": "admin",
                "password": "admin"
            }
        }]
    """
    token_url = f"{base_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
    return await oauth2_password(
        session,
        token_url=token_url,
        username=username,
        password=password,
        client_id=client_id,
    )


# =============================================================================
# 26. APPS CONNUES — METABASE
# =============================================================================


async def metabase_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin@example.com",
    password: str = "password",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Metabase via /api/session → session token dans X-Metabase-Session.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "metabase_auth",
            "kwargs": {"base_url": "http://localhost:3000"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/api/session"
    async with session.post(login_url, json={"username": username, "password": password}) as resp:
        data = await resp.json(content_type=None)

    token = data.get("id")
    if not token:
        raise Exception(f"metabase_auth: token absent dans la réponse: {data}")

    session.headers.update({"X-Metabase-Session": token})
    logger.info(f"✅ metabase_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 27. APPS CONNUES — AWX / ANSIBLE TOWER
# =============================================================================


async def awx_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    *args,
    **kwargs,
) -> bool:
    """
    Auth AWX/Ansible Tower via Basic Auth (API REST).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "awx_auth",
            "kwargs": {"base_url": "http://localhost:8013"}
        }]
    """
    return await basic_auth(session, username, password)


# =============================================================================
# 28. APPS CONNUES — ROUNDCUBE
# =============================================================================


async def roundcube_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    *args,
    **kwargs,
) -> bool:
    """
    Auth Roundcube webmail avec token CSRF.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "roundcube_auth",
            "kwargs": {"base_url": "http://localhost/roundcube"}
        }]
    """
    index_url = f"{base_url.rstrip('/')}/"
    html = await _get_html(session, index_url)

    token = _find_csrf(html, ("_token",))

    data = {
        "_user": username,
        "_pass": password,
        "_action": "login",
        "_task": "login",
    }
    if token:
        data["_token"] = token

    async with session.post(index_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "_task=mail" not in html and "compose" not in html:
            raise Exception("roundcube_auth: échec de connexion")

    logger.info(f"✅ roundcube_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 29. APPS CONNUES — OPENWRT LUCI
# =============================================================================


async def openwrt_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "root",
    password: str = "",
    *args,
    **kwargs,
) -> bool:
    """
    Auth OpenWRT LuCI via form login.

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "openwrt_auth",
            "kwargs": {"base_url": "http://192.168.1.1"}
        }]
    """
    login_url = f"{base_url.rstrip('/')}/cgi-bin/luci/"
    data = {
        "luci_username": username,
        "luci_password": password,
    }
    async with session.post(login_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "logout" not in html.lower() and "sysauth" in str(resp.url):
            raise Exception("openwrt_auth: échec de connexion")

    logger.info(f"✅ openwrt_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 30. APPS CONNUES — PFSENSE
# =============================================================================


async def pfsense_auth(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "admin",
    password: str = "pfsense",
    *args,
    **kwargs,
) -> bool:
    """
    Auth pfSense avec CSRF (__csrf_magic).

    Exemples d'usage depuis l'API:
        helpers: [{
            "name": "pfsense_auth",
            "kwargs": {"base_url": "https://192.168.1.1"}
        }]
    """
    index_url = f"{base_url.rstrip('/')}/index.php"
    html = await _get_html(session, index_url)

    # pfSense utilise __csrf_magic
    match = re.search(r'name="__csrf_magic"\s+value="([^"]+)"', html)
    csrf = match.group(1) if match else ""

    data = {
        "usernamefld": username,
        "passwordfld": password,
        "login": "Sign In",
        "__csrf_magic": csrf,
    }

    async with session.post(index_url, data=data, allow_redirects=True) as resp:
        html = await resp.text()
        if "Dashboard" not in html and "logout" not in html.lower():
            raise Exception("pfsense_auth: échec de connexion")

    logger.info(f"✅ pfsense_auth: connecté sur {base_url}")
    return True


# =============================================================================
# 31. HELPER NOOP (utile pour les tests)
# =============================================================================


async def noop(session: aiohttp.ClientSession, *args, **kwargs) -> bool:
    """Ne fait rien. Utile pour les tests ou les sites sans auth."""
    logger.info("✅ noop: aucune action requise")
    return True
