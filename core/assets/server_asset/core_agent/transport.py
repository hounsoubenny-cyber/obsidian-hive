#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 10 23:32:09 2026

@author: hounsousamuel
"""

import os
import time
import json
import httpx
import asyncio
import aiofiles
import websockets
from tenacity import stop_after_attempt, retry_if_exception, wait_exponential, retry
from obsidian_hive.core.assets.server_asset.core_agent.server_asset_types import (
    RequestResponse, SendMsgType, ReceiveMsgType
)
from obsidian_hive.core.assets.server_asset.core_agent.utils import exec_func, cancel_tasks


def _should_retry(exc: BaseException) -> bool:
    """Détermine si une exception doit déclencher une nouvelle tentative.

    Args:
        exc (BaseException): L'exception à évaluer.

    Returns:
        bool: True si la requête doit être retentée, False sinon.
    """
    if isinstance(exc, httpx.RequestError):
        return True  # coupure réseau, timeout, DNS...
    if isinstance(exc, httpx.HTTPStatusError):
        # 429 (rate limit) et 5xx (le serveur a un souci temporaire) : ça vaut le coup
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return False


MAX_ATTEMPTS = 3
WAIT_KWARGS = dict(multiplier=1, min=1, max=30)


class AgentHttpClient:
    """Client HTTP pour l'agent serveur.
    
    Gère les appels HTTP vers le central avec retry automatique,
    téléchargement de fichiers et gestion d'authentification.
    
    Attributes:
        base_url (str): URL de base du central.
        timeout (float): Timeout par défaut pour les requêtes.
        secret (str | None): Secret d'authentification.
        install_token (str): Token d'installation (pour l'enregistrement).
        client (httpx.AsyncClient): Client HTTP asynchrone.
    """
    
    def __init__(
        self,
        base_url: str,
        install_token: str,
        secret: str | None = None,
        timeout: float | int = 30.0,
    ):
        """Initialise le client HTTP.

        Args:
            base_url (str): URL de base du central.
            install_token (str): Token d'installation.
            secret (str | None, optional): Secret d'authentification. Par défaut None.
            timeout (float | int, optional): Timeout en secondes. Par défaut 30.

        Raises:
            RuntimeError: Si l'URL est invalide ou mal formée.
        """
        if not isinstance(base_url, str):
            raise RuntimeError(
                f"Base url doit être une string, reçu ({type(base_url).__name__}, {base_url}"
            )
        
        if not base_url.startswith(("http://", "https://")):
            raise RuntimeError("Url invalide !")
            
        self.base_url = base_url
        self.timeout = timeout if timeout is not None and timeout > 0 else 30.0
        self.secret = secret
        self.install_token = install_token
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=self.timeout,
        )
    
    async def close(self):
        """Ferme le client HTTP et libère les ressources."""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    def build_default_json(
        self,
        include_secret: bool = True,
        include_token: bool = False
    ):
        """Construit le JSON par défaut pour les requêtes.

        Args:
            include_secret (bool, optional): Inclure le secret. Par défaut True.
            include_token (bool, optional): Inclure le token d'installation. Par défaut False.

        Returns:
            dict: Dictionnaire avec les champs demandés.
        """
        return {
           **({"install_token": self.install_token} if include_token else {}) ,
           **({"secret": self.secret} if include_secret else {}) ,
        }
    
    def set_secret(self, secret: str):
        """Met à jour le secret d'authentification.

        Args:
            secret (str): Le nouveau secret.
        """
        self.secret = secret
        self.client.headers["Authorization"] = f"Bearer {secret}"
    
    @retry(
        stop=stop_after_attempt(MAX_ATTEMPTS),
        wait=wait_exponential(**WAIT_KWARGS),
        retry=retry_if_exception(_should_retry),
        reraise=True
    )
    async def fetch_get(
        self, path: str,
        client: httpx.AsyncClient | None = None,
        url: str | None = None,
        timeout: float | int | None = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> RequestResponse:
        """Effectue une requête GET avec retry automatique.

        Args:
            path (str): Chemin de la requête.
            client (httpx.AsyncClient | None, optional): Client HTTP personnalisé.
            url (str | None, optional): URL complète (remplace path).
            timeout (float | int | None, optional): Timeout personnalisé.
            params (dict | None, optional): Paramètres de requête.
            headers (dict | None, optional): En-têtes personnalisés.

        Returns:
            RequestResponse: La réponse structurée.

        Raises:
            RuntimeError: Si l'URL est invalide.
            httpx.HTTPStatusError: Si la réponse a un code d'erreur.
        """
        timeout = timeout or self.timeout
        params = params or {}
        headers = headers or {}
        client = client or self.client
        if url and not url.startswith(("http://", "https://")):
            raise RuntimeError("Url invalide !") 
            
        resp = await client.get(
            url or path,
            timeout=timeout,
            params=params, 
            headers=headers,
        )
        resp.raise_for_status()
        
        try:
            resp_json = resp.json()
        except Exception:
            resp_json = None
            
        result = {
            "url": str(resp.url),
            "reason_phrase": resp.reason_phrase,
            "headers": resp.headers,
            "text": resp.text,
            "body_json": resp_json,
            "history": resp.history,
            "status_code": resp.status_code,
            "elapsed": resp.elapsed.total_seconds() if resp.elapsed is not None else None,
        }
        return RequestResponse(**result)
    
    @retry(
        stop=stop_after_attempt(MAX_ATTEMPTS),
        wait=wait_exponential(**WAIT_KWARGS),
        retry=retry_if_exception(_should_retry),
        reraise=True
    )
    async def fetch_post(
        self, path: str,
        client: httpx.AsyncClient | None = None,
        url: str | None = None,
        timeout: float | int | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        json_data: dict | None = None,
    ) -> RequestResponse:
        """Effectue une requête POST avec retry automatique.

        Args:
            path (str): Chemin de la requête.
            client (httpx.AsyncClient | None, optional): Client HTTP personnalisé.
            url (str | None, optional): URL complète (remplace path).
            timeout (float | int | None, optional): Timeout personnalisé.
            params (dict | None, optional): Paramètres de requête.
            headers (dict | None, optional): En-têtes personnalisés.
            json_data (dict | None, optional): Données JSON à envoyer.

        Returns:
            RequestResponse: La réponse structurée.

        Raises:
            RuntimeError: Si l'URL est invalide.
            httpx.HTTPStatusError: Si la réponse a un code d'erreur.
        """
        timeout = timeout or self.timeout
        params = params or {}
        headers = headers or {}
        json_data = json_data or {}
        client = client or self.client
        if url and not url.startswith(("http://", "https://")):
            raise RuntimeError("Url invalide !") 
        
        resp = await client.post(
            url or path,
            timeout=timeout,
            params=params, 
            headers=headers,
            json=json_data
        )
        resp.raise_for_status()
        try:
            resp_json = resp.json()
        except Exception:
            resp_json = None
            
        result = {
            "url": str(resp.url),
            "reason_phrase": resp.reason_phrase,
            "headers": dict(resp.headers),
            "text": resp.text,
            "body_json": resp_json,
            "history": resp.history,
            "status_code": resp.status_code,
            "elapsed": resp.elapsed.total_seconds() if resp.elapsed is not None else None,
        }
        return RequestResponse(**result)
    
    @retry(
        stop=stop_after_attempt(MAX_ATTEMPTS),
        wait=wait_exponential(**WAIT_KWARGS),
        retry=retry_if_exception(_should_retry),
        reraise=True
    )
    async def _download_file(
        self,
        path: str,
        dest_path: str,
        client: httpx.AsyncClient | None = None,
        url: str | None = None,
        method: str = "GET",
        timeout: float | int | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        json_data: dict | None = None,
        perm: int = 0o777
    ):
        """Télécharge un fichier avec retry automatique (méthode interne).

        Args:
            path (str): Chemin de la requête.
            dest_path (str): Chemin de destination du fichier.
            client (httpx.AsyncClient | None, optional): Client HTTP personnalisé.
            url (str | None, optional): URL complète (remplace path).
            method (str, optional): Méthode HTTP. Par défaut "GET".
            timeout (float | int | None, optional): Timeout personnalisé.
            params (dict | None, optional): Paramètres de requête.
            headers (dict | None, optional): En-têtes personnalisés.
            json_data (dict | None, optional): Données JSON à envoyer.
            perm (int, optional): Permissions du fichier créé. Par défaut 0o777.

        Returns:
            dict: Résultat du téléchargement avec 'success', 'path', 'chunks' et 'error'.

        Raises:
            httpx.HTTPStatusError: Si la réponse a un code d'erreur.
        """
        timeout = timeout or self.timeout
        params = params or {}
        headers = headers or {}
        json_data = json_data or {}
        client = client or self.client
        async with client.stream(
            method=method,
            url=url or path,
            params=params,
            headers=headers,
            json=json_data
        ) as resp:
            resp.raise_for_status()
            chunks = 0
            async with aiofiles.open(dest_path, "wb") as f:
                async for chunk in resp.aiter_bytes():
                    chunks += 1
                    await f.write(chunk)
            os.chmod(dest_path, perm)
            return {
                "success": True,
                "path": dest_path,
                "chunks": chunks,
                "error": None,
            }
    
    async def download_file(self, *args, **kwargs):
        """Télécharge un fichier avec gestion des erreurs.

        Version publique de _download_file qui capture les exceptions.

        Returns:
            dict: Résultat du téléchargement avec 'success' et 'error' éventuel.
        """
        try:
            return await self._download_file(*args, **kwargs)
        except Exception as e:
            return {
                "success": False,
                "error": repr(e),
                "path": None,
                "chunks": None,
            }


class AgentWSClient:
    """Client WebSocket pour l'agent serveur.
    
    Gère la connexion WebSocket persistante avec le central,
    les heartbeats, la reconnexion automatique et le dispatch des messages.
    
    Attributes:
        ws_url (str): URL WebSocket du central.
        heartbeat_interval (float): Intervalle entre les heartbeats.
        ack_timeout (float): Timeout d'attente du heartbeat_ack.
        secret (str): Secret d'authentification.
        default_headers (dict): En-têtes par défaut (Authorization).
        _last_ack_at (float | None): Timestamp du dernier heartbeat_ack.
        n_messages (int): Compteur de messages reçus.
        dispatcher (callable): Fonction de dispatch des messages.
        _revoked (bool): Indique si l'agent est révoqué.
    """
    
    def __init__(
        self,
        ws_url: str,
        secret: str,
        dispatcher: callable,
        heartbeat_interval: float = 30,
        ack_timeout: float = 10,
        
    ):
        """Initialise le client WebSocket.

        Args:
            ws_url (str): URL WebSocket du central.
            secret (str): Secret d'authentification.
            dispatcher (callable): Fonction de dispatch des messages.
            heartbeat_interval (float, optional): Intervalle des heartbeats. Par défaut 30.
            ack_timeout (float, optional): Timeout d'attente du ack. Par défaut 10.

        Raises:
            RuntimeError: Si le secret est manquant.
        """
        if not secret:
            raise RuntimeError("Secret requis !")
        
        self.ws_url = ws_url
        self.heartbeat_interval = heartbeat_interval
        self.ack_timeout = ack_timeout
        self.secret = secret
        self.default_headers = {
            "Authorization": f"Baerer {self.secret}"
        }
        self._last_ack_at: float | None = None
        self.n_messages: int = 0
        self.dispatcher = dispatcher
        self._revoked = False
        
    def mark_heartbeat_ack(self):
        """Marque la réception d'un heartbeat_ack."""
        self._last_ack_at = time.monotonic()
    
    def mark_revoked(self):
        """Marque l'agent comme révoqué."""
        self._revoked = True
    
    async def _heartbeat_loop(self, ws: websockets.ClientConnection):
        """Boucle d'envoi des heartbeats.

        Envoie un heartbeat toutes les `heartbeat_interval` secondes.
        Si aucun ack n'est reçu dans `ack_timeout`, ferme la connexion.

        Args:
            ws (websockets.ClientConnection): La connexion WebSocket.
        """
        while True:
            if self._revoked:
                await ws.close()
                return 
            
            await asyncio.sleep(self.heartbeat_interval)
            self._last_ack_at = None
            await ws.send(json.dumps({"type": SendMsgType.HEARTBEAT.value}))

            await asyncio.sleep(self.ack_timeout)
            if self._last_ack_at is None:
                await ws.close()
                return 
    
    async def _dispatch(self, data: dict, ws: websockets.ClientConnection):
        """Dispatch un message vers le handler approprié.

        Args:
            data (dict): Le message reçu.
            ws (websockets.ClientConnection): La connexion WebSocket.
        """
        await exec_func(
            self.dispatcher,
            data, ws
        )
        
    async def listening_loop(self, ws: websockets.ClientConnection):
        """Boucle d'écoute des messages WebSocket.

        Reçoit les messages, les décode en JSON et les dispatch.

        Args:
            ws (websockets.ClientConnection): La connexion WebSocket.
        """
        async for raw_message in ws:
            self.n_messages += 1
            try:
                data = json.loads(raw_message)
            except Exception as e:
                print(f"Erreur dans le chargement du message, {raw_message}.\n Erreur {e!r}")
                continue
            
            try:
                await self._dispatch(data, ws)
            except Exception as e:
                print(f"Erreur dans le dispatch (type={data.get('type')!r}): {e!r}")
    
    async def _run_once(self):
        """Exécute une session WebSocket unique avec heartbeat et écoute.

        Gère la connexion, la boucle de heartbeat et la boucle d'écoute.
        La session se termine quand l'une des boucles se termine.
        """
        ws: websockets.ClientConnection
        async with websockets.connect(
            self.ws_url,
            additional_headers={"Authorization": f"Bearer {self.secret}"},
            max_size=None,
        ) as ws:
            heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
            listening_task = asyncio.create_task(self.listening_loop(ws))
            try:
                await asyncio.wait(
                    [heartbeat_task, listening_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                await cancel_tasks(tasks=[heartbeat_task, listening_task])
                
                
    async def run_forever(self):
        """Boucle principale de connexion WebSocket avec backoff exponentiel.

        Tente de se connecter au central en continu. En cas de déconnexion,
        attend un temps croissant avant de réessayer (backoff exponentiel).

        La boucle s'arrête si l'agent est révoqué.
        """
        backoff = 1  
        max_backoff = 60

        while True:
            try:
                await self._run_once()
                backoff = 1  
            except (websockets.ConnectionClosed, OSError, asyncio.TimeoutError) as e:
                print(f"WS déconnecté ou injoignable : {e!r} — retry dans {backoff}s")
            
            if self._revoked:
                break
            
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        
        return