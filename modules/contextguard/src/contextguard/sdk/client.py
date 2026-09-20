#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 19 12:10:59 2026

@author: hounsousamuel
"""


"""
ContextGuard SDK — Client
==========================

Client stateful et configurable pour interagir avec l'API ContextGuard.

Caractéristiques
----------------
- **Stateful** : après un ``connect`` réussi, l'instance mémorise
  ``username``, ``password`` et ``token``.
- **Configurable** : URL de base et chemins d'endpoints personnalisables.
- **Intelligent** : ``connect`` (login-first + fallback create),
  ``analyse`` (auto-connect, refresh, reconnect).
- **Sync + Async** : chaque méthode existe en version ``_async`` et
  synchrone.

Auteur : HOUNSOU Samuel Benny
Version : 2.0.0
"""

import asyncio
import aiohttp
import concurrent.futures
from typing import Any, Coroutine, TypeVar
from urllib.parse import urljoin

from contextguard.sdk.models import (
    TOKEN_EXPIRED_DETAIL,
    USERNAME_NOT_AVAILABLE_REASON,
    USER_NOT_REGISTERED_REASON,
    AnalyseParams,
    ConnectParams,
    HealthParams,
    RefreshParams,
    LogoutParams,
    DeleteAccountParams,
    AnalyseItem,
    AnalyseResponse,
    ConnectResponse,
    HealthResponse,
    RefreshResponse,
    SaltResponse,
    LogoutResponse,
    DeleteAccountResponse,
)


# ═══════════════════════════════════════════════════════════
# Constantes par défaut
# ═══════════════════════════════════════════════════════════

DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_CONNECT_PATH = "/api/login"
DEFAULT_ANALYSE_PATH = "/api/analyse"
DEFAULT_REFRESH_PATH = "/api/refresh_token"
DEFAULT_HEALTH_PATH = "/api/health"
DEFAULT_SALT_PATH = "/api/salt"
DEFAULT_LOGOUT_PATH = "/api/logout"
DEFAULT_DELETE_ACCOUNT_PATH = "/api/delete_account"
DEFAULT_TIMEOUT = 10.0

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
# Utilitaires
# ═══════════════════════════════════════════════════════════

def _normalize_salt(salt: str | bytes | None) -> str | None:
    """Normalise un salt ``bytes`` en ``str`` (idempotent)."""
    if salt is None:
        return None
    if isinstance(salt, bytes):
        return salt.decode()
    return salt


# ═══════════════════════════════════════════════════════════
# Client
# ═══════════════════════════════════════════════════════════

class ContextGuardClient:
    """
    Client SDK pour l'API ContextGuard.

    Parameters
    ----------
    api_url : str, optional
        URL de base. Défaut ``http://localhost:8000``.
    connect_path, analyse_path, refresh_path, health_path, salt_path : str
        Chemins des endpoints. Défauts : ``/api/...``.
    logout_path : str
        Défaut ``/api/logout``.
    delete_account_path : str
        Défaut ``/api/delete_account``.
    timeout : float
        Timeout par défaut en secondes. Défaut ``10.0``.
    username : str | None
        Mémorisé dès l'instanciation.
    password : str | None
        Idem.
    salt : str | bytes | None
        Idem (accepté pour compat, plus utilisé).
    """

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        connect_path: str = DEFAULT_CONNECT_PATH,
        analyse_path: str = DEFAULT_ANALYSE_PATH,
        refresh_path: str = DEFAULT_REFRESH_PATH,
        health_path: str = DEFAULT_HEALTH_PATH,
        salt_path: str = DEFAULT_SALT_PATH,
        logout_path: str = DEFAULT_LOGOUT_PATH,
        delete_account_path: str = DEFAULT_DELETE_ACCOUNT_PATH,
        timeout: float = DEFAULT_TIMEOUT,
        username: str | None = None,
        password: str | None = None,
        salt: str | bytes | None = None,
    ) -> None:
        self.api_url = api_url
        self.connect_path = connect_path
        self.analyse_path = analyse_path
        self.refresh_path = refresh_path
        self.health_path = health_path
        self.salt_path = salt_path
        self.logout_path = logout_path
        self.delete_account_path = delete_account_path
        self.timeout = timeout

        self._connect_url = urljoin(api_url, connect_path)
        self._analyse_url = urljoin(api_url, analyse_path)
        self._refresh_url = urljoin(api_url, refresh_path)
        self._health_url = urljoin(api_url, health_path)
        self._salt_url = urljoin(api_url, salt_path)
        self._logout_url = urljoin(api_url, logout_path)
        self._delete_account_url = urljoin(api_url, delete_account_path)

        self.username: str | None = username
        self.password: str | None = password
        self.salt: str | None = _normalize_salt(salt)
        self.token: str | None = None

    # ═══════════════════════════════════════════════════════
    # Propriétés publiques
    # ═══════════════════════════════════════════════════════

    @property
    def connected(self) -> bool:
        """``True`` si un token est actuellement mémorisé."""
        return self.token is not None

    def disconnect(self, clear_credentials: bool = False) -> None:
        """
        Réinitialise l'état de session.

        Parameters
        ----------
        clear_credentials : bool, optional
            Si ``True``, efface aussi ``username``, ``password`` et ``salt``.
        """
        self.token = None
        if clear_credentials:
            self.username = None
            self.password = None
            self.salt = None

    # ═══════════════════════════════════════════════════════
    # Helpers HTTP
    # ═══════════════════════════════════════════════════════

    async def _do_request(
        self,
        method: str,
        url: str,
        session: aiohttp.ClientSession,
        json: dict | None,
        timeout: float,
    ) -> tuple[int | None, dict]:
        try:
            async with session.request(
                method, url, json=json,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                try:
                    data = await response.json()
                except Exception:
                    data = {}
                return response.status, data
        except asyncio.TimeoutError:
            return None, {"detail": f"Timeout après {timeout}s"}
        except aiohttp.ClientError as exc:
            return None, {"detail": f"Erreur réseau : {exc!r}"}
        except Exception as exc:
            return None, {"detail": f"Erreur inattendue : {exc!r}"}

    async def _request(
        self,
        method: str,
        url: str,
        json: dict | None,
        session: aiohttp.ClientSession | None,
        timeout: float | None,
    ) -> tuple[int | None, dict]:
        effective_timeout = timeout if timeout is not None else self.timeout
        if session is not None and isinstance(session, aiohttp.ClientSession):
            return await self._do_request(method, url, session, json, effective_timeout)
        async with aiohttp.ClientSession() as transient:
            return await self._do_request(method, url, transient, json, effective_timeout)

    # ═══════════════════════════════════════════════════════
    # Parsers
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _parse_connect(status_code: int | None, data: dict) -> ConnectResponse:
        if status_code != 200 or "detail" in data:
            return ConnectResponse(
                errors=[str(data.get("detail", "Erreur inconnue"))],
                status_code=status_code,
                success=False,
                username=data.get("username"),
                token=data.get("token"),
            )
        return ConnectResponse(
            status_code=status_code,
            success=bool(data.get("success", False)),
            state=data.get("state"),
            username=data.get("username"),
            token=data.get("token"),
            reason=str(data.get("reason", "")),
        )

    @staticmethod
    def _parse_analyse(
        status_code: int | None,
        data: dict,
        token: str | None,
    ) -> AnalyseResponse:
        if status_code != 200 or "detail" in data:
            return AnalyseResponse(
                errors=[str(data.get("detail", "Erreur inconnue"))],
                status_code=status_code,
                success=False,
                token=token,
            )

        raw = data.get("result", {}) or {}
        results: dict[str, AnalyseItem] = {}
        for prompt, item in raw.items():
            if isinstance(item, dict):
                results[prompt] = AnalyseItem(
                    label=str(item.get("label", "")),
                    prob=float(item.get("prob", 0.0)),
                    threshold=float(item.get("threshold", 0.5)),
                )

        return AnalyseResponse(
            status_code=status_code,
            success=True,
            token=token,
            results=results,
            history_updated=bool(data.get("history_update_with_success", False)),
        )

    @staticmethod
    def _parse_refresh(status_code: int | None, data: dict) -> RefreshResponse:
        if status_code != 200 or "token" not in data:
            return RefreshResponse(
                errors=[str(data.get("detail", "Échec du rafraîchissement"))],
                status_code=status_code,
                success=False,
            )
        return RefreshResponse(status_code=status_code, success=True, token=data.get("token"))

    @staticmethod
    def _parse_health(status_code: int | None, data: dict) -> HealthResponse:
        if status_code != 200 or "detail" in data:
            return HealthResponse(
                errors=[str(data.get("detail", "Erreur inconnue"))],
                status_code=status_code,
                success=False,
            )
        return HealthResponse(
            status_code=status_code,
            success=True,
            username=data.get("username"),
            num_analyse=int(data.get("num_analyse", 0)),
            stats=dict(data.get("stats", {}) or {}),
            history=dict(data.get("history", {}) or {}),
        )

    @staticmethod
    def _parse_salt(status_code: int | None, data: dict) -> SaltResponse:
        if status_code != 200 or "salt" not in data:
            return SaltResponse(
                errors=[str(data.get("detail", "Impossible d'obtenir un salt"))],
                status_code=status_code,
                success=False,
            )
        return SaltResponse(
            status_code=status_code,
            success=True,
            salt=data.get("salt"),
            datetime=str(data.get("datetime", "")) or None,
        )

    @staticmethod
    def _parse_logout(status_code: int | None, data: dict) -> LogoutResponse:
        if status_code != 200 or not data.get("success", False):
            return LogoutResponse(
                errors=[str(data.get("detail", "Échec du logout"))],
                status_code=status_code,
                success=False,
            )
        return LogoutResponse(
            status_code=status_code,
            success=True,
            username=data.get("username"),
            message=str(data.get("message", "")),
        )

    @staticmethod
    def _parse_delete_account(status_code: int | None, data: dict) -> DeleteAccountResponse:
        if status_code != 200 or not data.get("success", False):
            return DeleteAccountResponse(
                errors=[str(data.get("detail", "Échec de la suppression"))],
                status_code=status_code,
                success=False,
            )
        return DeleteAccountResponse(
            status_code=status_code,
            success=True,
            username=data.get("username"),
            message=str(data.get("message", "")),
        )

    
    # ═══════════════════════════════════════════════════════
    # State
    # ═══════════════════════════════════════════════════════

    def _save_state(
        self,
        username: str | None,
        password: str | None,
        token: str | None,
    ) -> None:
        if username:
            self.username = username
        if password:
            self.password = password
        if token:
            self.token = token

    # ═══════════════════════════════════════════════════════
    # get_salt
    # ═══════════════════════════════════════════════════════

    async def get_salt_async(
        self,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> SaltResponse:
        """Récupère un nouveau sel bcrypt depuis l'API."""
        status_code, data = await self._request(
            "GET", self._salt_url, None, session, timeout
        )
        return self._parse_salt(status_code, data)

    def get_salt(
        self,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> SaltResponse:
        """Version synchrone de :meth:`get_salt_async`."""
        return self._run(self.get_salt_async(session=session, timeout=timeout))

    # ═══════════════════════════════════════════════════════
    # connect
    # ═══════════════════════════════════════════════════════

    async def connect_async(
        self,
        username: str | None = None,
        password: str | None = None,
        connect: bool | None = None,
        intelligent: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> ConnectResponse:
        """
        Crée un compte ou connecte l'utilisateur.

        Comportement selon ``connect`` et ``intelligent`` :

        - ``connect=True``  → login uniquement.
        - ``connect=False`` → création uniquement.
        - ``connect=None`` et ``intelligent=True`` (défaut) → **login-first** :
            1. tentative de login ;
            2. si user inconnu → création ;
            3. si création échoue (nom pris) → retente login (race condition).
        - ``connect=None`` et ``intelligent=False`` → login uniquement.
        """
        params = ConnectParams(
            username=username if username is not None else self.username,
            password=password if password is not None else self.password,
            connect=connect,
        )

        if not params.username or not params.password:
            return ConnectResponse(
                errors=["Paramètres manquants : username et password sont requis"],
                success=False,
            )

        # Mode explicite
        if params.connect is not None:
            resp = await self._connect_impl(params, params.connect, session, timeout)
            if resp.success:
                self._save_state(params.username, params.password, resp.token)
            return resp

        # Mode non-intelligent → login
        if not intelligent:
            resp = await self._connect_impl(params, True, session, timeout)
            if resp.success:
                self._save_state(params.username, params.password, resp.token)
            return resp

        # Mode intelligent (login-first)
        login_resp = await self._connect_impl(params, True, session, timeout)
        if login_resp.success:
            self._save_state(params.username, params.password, login_resp.token)
            return login_resp

        # User inconnu → tentative de création
        if login_resp.reason == USER_NOT_REGISTERED_REASON:
            create_resp = await self._connect_impl(params, False, session, timeout)
            if create_resp.success:
                self._save_state(params.username, params.password, create_resp.token)
                return create_resp

            # Race condition : compte créé entre-temps
            if create_resp.reason == USERNAME_NOT_AVAILABLE_REASON:
                retry = await self._connect_impl(params, True, session, timeout)
                if retry.success:
                    self._save_state(params.username, params.password, retry.token)
                return retry
            return create_resp

        return login_resp

    async def _connect_impl(
        self,
        params: ConnectParams,
        connect: bool,
        session: aiohttp.ClientSession | None,
        timeout: float | None,
    ) -> ConnectResponse:
        payload = {
            "username": params.username,
            "password": params.password,
            "connect": connect,
        }
        status_code, data = await self._request(
            "POST", self._connect_url, payload, session, timeout
        )
        return self._parse_connect(status_code, data)

    def connect(
        self,
        username: str | None = None,
        password: str | None = None,
        connect: bool | None = None,
        intelligent: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> ConnectResponse:
        """Version synchrone de :meth:`connect_async`."""
        return self._run(self.connect_async(
            username=username, password=password,
            connect=connect, intelligent=intelligent,
            session=session, timeout=timeout,
        ))

    # ═══════════════════════════════════════════════════════
    # refresh_token
    # ═══════════════════════════════════════════════════════

    async def refresh_token_async(
        self,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> RefreshResponse:
        """Rafraîchit un token JWT expiré."""
        params = RefreshParams(
            username=username if username is not None else self.username,
            token=token if token is not None else self.token,
        )

        if not params.username or not params.token:
            return RefreshResponse(
                errors=["Paramètres manquants pour le rafraîchissement du token"],
                success=False,
            )

        payload = {"username": params.username, "token": params.token}
        status_code, data = await self._request(
            "POST", self._refresh_url, payload, session, timeout
        )
        resp = self._parse_refresh(status_code, data)
        if resp.success and resp.token:
            self.token = resp.token
        return resp

    def refresh_token(
        self,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> RefreshResponse:
        """Version synchrone de :meth:`refresh_token_async`."""
        return self._run(self.refresh_token_async(
            username=username, token=token, session=session, timeout=timeout,
        ))

    # ═══════════════════════════════════════════════════════
    # analyse
    # ═══════════════════════════════════════════════════════

    async def analyse_async(
        self,
        prompts: list[str] | str,
        thresholds: list[float] | float = 0.5,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        auto_recover: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> AnalyseResponse:
        """
        Analyse un ou plusieurs prompts.

        Récupération intelligente si ``auto_recover=True`` :

        1. Auto-connect si pas de token.
        2. Refresh sur ``401 TOKEN_EXPIRED`` puis retry.
        3. Reconnexion sur ``401/406`` (session perdue) puis retry.
        """
        prompts_list = [prompts] if isinstance(prompts, str) else list(prompts)
        if isinstance(thresholds, (int, float)):
            thresholds_list = [float(thresholds) for _ in range(len(prompts_list))]
        else:
            thresholds_list = [float(t) for t in thresholds]

        if len(thresholds_list) != len(prompts_list):
            return AnalyseResponse(
                errors=[
                    f"Nombre de seuils ({len(thresholds_list)}) différent "
                    f"du nombre de prompts ({len(prompts_list)})"
                ],
                success=False,
            )

        params = AnalyseParams(
            username=username if username is not None else self.username,
            password=password if password is not None else self.password,
            token=token if token is not None else self.token,
            prompts=prompts_list,
            thresholds=[
                t if 0.0 <= t <= 1.0 else 0.5 for t in thresholds_list
            ],
        )

        if not params.username or not params.password:
            return AnalyseResponse(
                errors=["Non connecté et identifiants manquants"],
                success=False,
            )

        # Auto-connect si pas de token
        if not params.token and auto_recover:
            conn = await self.connect_async(
                username=params.username,
                password=params.password,
                session=session,
                timeout=timeout,
                intelligent=True,
            )
            if not conn.success:
                return AnalyseResponse(
                    errors=[f"Auto-connexion échouée : {conn.errors}"],
                    success=False,
                )
            params.token = conn.token

        if not params.token:
            return AnalyseResponse(
                errors=["Aucun token disponible (client non connecté)"],
                success=False,
            )

        resp = await self._analyse_impl(params, session, timeout)

        if not auto_recover or resp.success:
            return resp

        first_error = resp.errors[0] if resp.errors else ""

        # Cas A : token expiré → refresh + retry
        if resp.status_code == 401 and first_error == TOKEN_EXPIRED_DETAIL:
            refresh = await self.refresh_token_async(
                username=params.username,
                token=params.token,
                session=session, timeout=timeout,
            )
            if refresh.success and refresh.token:
                params.token = refresh.token
                return await self._analyse_impl(params, session, timeout)
            return AnalyseResponse(
                errors=[f"Rafraîchissement échoué : {refresh.errors}"],
                success=False,
                token=params.token,
            )

        # Cas B : session perdue → reconnexion + retry
        if resp.status_code in (401, 406):
            conn = await self.connect_async(
                username=params.username,
                password=params.password,
                session=session, timeout=timeout,
            )
            if conn.success and conn.token:
                params.token = conn.token
                return await self._analyse_impl(params, session, timeout)
            return AnalyseResponse(
                errors=[f"Reconnexion échouée : {conn.errors}"],
                success=False,
                token=params.token,
            )

        return resp

    async def _analyse_impl(
        self,
        params: AnalyseParams,
        session: aiohttp.ClientSession | None,
        timeout: float | None,
    ) -> AnalyseResponse:
        payload = {
            "username": params.username,
            "password": params.password,
            "token": params.token,
            "verify_connect": False,
            "prompts": params.prompts,
            "thresholds": params.thresholds,
        }
        status_code, data = await self._request(
            "POST", self._analyse_url, payload, session, timeout
        )
        return self._parse_analyse(status_code, data, params.token)

    def analyse(
        self,
        prompts: list[str] | str,
        thresholds: list[float] | float = 0.5,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        auto_recover: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> AnalyseResponse:
        """Version synchrone de :meth:`analyse_async`."""
        return self._run(self.analyse_async(
            prompts=prompts, thresholds=thresholds,
            username=username, password=password, token=token,
            auto_recover=auto_recover, session=session, timeout=timeout,
        ))

    # ═══════════════════════════════════════════════════════
    # health
    # ═══════════════════════════════════════════════════════

    async def health_async(
        self,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        auto_recover: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> HealthResponse:
        """Récupère l'état de santé et l'historique."""
        params = HealthParams(
            username=username if username is not None else self.username,
            password=password if password is not None else self.password,
            token=token if token is not None else self.token,
        )

        if not params.username or not params.password:
            return HealthResponse(
                errors=["Non connecté et identifiants manquants"],
                success=False,
            )

        if not params.token and auto_recover:
            conn = await self.connect_async(
                username=params.username,
                password=params.password,
                session=session, timeout=timeout,
            )
            if not conn.success:
                return HealthResponse(
                    errors=[f"Auto-connexion échouée : {conn.errors}"],
                    success=False,
                )
            params.token = conn.token

        if not params.token:
            return HealthResponse(
                errors=["Aucun token disponible (client non connecté)"],
                success=False,
            )

        resp = await self._health_impl(params, session, timeout)

        if not auto_recover or resp.success:
            return resp

        first_error = resp.errors[0] if resp.errors else ""

        if resp.status_code == 401 and first_error == TOKEN_EXPIRED_DETAIL:
            refresh = await self.refresh_token_async(
                username=params.username, token=params.token,
                session=session, timeout=timeout,
            )
            if refresh.success and refresh.token:
                params.token = refresh.token
                return await self._health_impl(params, session, timeout)
            return HealthResponse(
                errors=[f"Rafraîchissement échoué : {refresh.errors}"],
                success=False,
            )

        if resp.status_code in (401, 406):
            conn = await self.connect_async(
                username=params.username, password=params.password,
                session=session, timeout=timeout,
            )
            if conn.success and conn.token:
                params.token = conn.token
                return await self._health_impl(params, session, timeout)
            return HealthResponse(
                errors=[f"Reconnexion échouée : {conn.errors}"],
                success=False,
            )

        return resp

    async def _health_impl(
        self,
        params: HealthParams,
        session: aiohttp.ClientSession | None,
        timeout: float | None,
    ) -> HealthResponse:
        payload = {
            "username": params.username,
            "password": params.password,
            "token": params.token,
            "verify_connect": False,
        }
        status_code, data = await self._request(
            "POST", self._health_url, payload, session, timeout
        )
        return self._parse_health(status_code, data)

    def health(
        self,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        auto_recover: bool = True,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> HealthResponse:
        """Version synchrone de :meth:`health_async`."""
        return self._run(self.health_async(
            username=username, password=password, token=token,
            auto_recover=auto_recover, session=session, timeout=timeout,
        ))

    
    # ═══════════════════════════════════════════════════════
    # logout
    # ═══════════════════════════════════════════════════════

    async def logout_async(
        self,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> LogoutResponse:
        """
        Révoque la session serveur.

        Si le client n'a aucun token, l'appel est considéré comme
        un succès (idempotent). Le token local est effacé en cas de
        succès serveur.
        """
        params = LogoutParams(
            username=username if username is not None else self.username,
            token=token if token is not None else self.token,
        )

        if not params.username or not params.token:
            self.disconnect()
            return LogoutResponse(
                success=True,
                username=params.username,
                message="Aucune session active.",
            )

        payload = {"username": params.username, "token": params.token}
        status_code, data = await self._request(
            "POST", self._logout_url, payload, session, timeout
        )
        resp = self._parse_logout(status_code, data)
        if resp.success:
            self.disconnect()
        return resp

    def logout(
        self,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> LogoutResponse:
        """Version synchrone de :meth:`logout_async`."""
        return self._run(self.logout_async(
            username=username, token=token, session=session, timeout=timeout,
        ))

    # ═══════════════════════════════════════════════════════
    # delete_account
    # ═══════════════════════════════════════════════════════

    async def delete_account_async(
        self,
        password: str | None = None,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> DeleteAccountResponse:
        """
        Supprime définitivement le compte.

        ⚠️  Irréversible. Le serveur exige token **et** mot de passe.
        En cas de succès, le client efface **toutes** ses credentials
        locales (``clear_credentials=True``).
        """
        params = DeleteAccountParams(
            username=username if username is not None else self.username,
            password=password if password is not None else self.password,
            token=token if token is not None else self.token,
        )

        if not params.username or not params.password or not params.token:
            return DeleteAccountResponse(
                errors=["Username, password et token sont requis"],
                success=False,
            )

        payload = {
            "username": params.username,
            "password": params.password,
            "token": params.token,
        }
        status_code, data = await self._request(
            "POST", self._delete_account_url, payload, session, timeout
        )
        resp = self._parse_delete_account(status_code, data)
        if resp.success:
            self.disconnect(clear_credentials=True)
        return resp

    def delete_account(
        self,
        password: str | None = None,
        username: str | None = None,
        token: str | None = None,
        session: aiohttp.ClientSession | None = None,
        timeout: float | None = None,
    ) -> DeleteAccountResponse:
        """Version synchrone de :meth:`delete_account_async`."""
        return self._run(self.delete_account_async(
            password=password, username=username, token=token,
            session=session, timeout=timeout,
        ))

    # ═══════════════════════════════════════════════════════
    # Exécution synchrone
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def _run(coro: Coroutine[Any, Any, T]) -> T:
        """
        Exécute une coroutine en mode synchrone.

        - Hors boucle : ``asyncio.run``.
        - Dans une boucle (Jupyter, etc.) : thread dédié.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()


__all__ = [
    "ContextGuardClient",
    "DEFAULT_API_URL",
    "DEFAULT_CONNECT_PATH",
    "DEFAULT_ANALYSE_PATH",
    "DEFAULT_REFRESH_PATH",
    "DEFAULT_HEALTH_PATH",
    "DEFAULT_SALT_PATH",
    "DEFAULT_LOGOUT_PATH",
    "DEFAULT_DELETE_ACCOUNT_PATH",
    "DEFAULT_TIMEOUT",
]