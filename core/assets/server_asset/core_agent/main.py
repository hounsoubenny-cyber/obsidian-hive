#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 11 21:01:32 2026

@author: hounsousamuel
"""

import asyncio
import signal
import functools
from obsidian_hive.core.assets.server_asset.core_agent.config import AgentConfig
from obsidian_hive.core.assets.server_asset.core_agent.transport import AgentHttpClient, AgentWSClient
from obsidian_hive.core.assets.server_asset.core_agent.dispatcher import AgentDispatcher
from obsidian_hive.core.assets.server_asset.core_agent.utils import get_system_info
from modules_utils.loop_utils import _run_async
from obsidian_hive.core.assets.server_asset.core_agent.agent_signal import build_shutdown_handler
from urllib.parse import urlencode


class Agent:
    """Agent serveur principal d'Obsidian Hive.
    
    Cette classe représente l'agent qui s'exécute sur les serveurs clients.
    Elle gère :
    - L'enregistrement auprès du central
    - La communication WebSocket avec le central
    - L'exécution des outils (tools)
    - La gestion de la configuration
    - Le cycle de vie (démarrage, arrêt, auto-destruction)
    
    Attributes:
        config (AgentConfig): Configuration de l'agent chargée depuis le fichier.
        http_client (AgentHttpClient): Client HTTP pour les appels vers le central.
        secret (str | None): Le secret d'authentification (après enregistrement).
        ws_client (AgentWSClient | None): Client WebSocket pour la communication.
        dispatcher (AgentDispatcher | None): Dispatcher des messages WS.
    """
    
    def __init__(
        self,
    ):
        """Initialise l'agent et charge la configuration."""
        self.config = AgentConfig.load()
        self.http_client = AgentHttpClient(
            install_token=self.config.pending_token,
            base_url=self.config.central_http_url,
            secret=None,
        )
        self.secret = self.config.secret
        self.ws_client: AgentWSClient = None
        self.dispatcher: AgentDispatcher = None
    
    def set_secret(self, secret: str):
        self.secret = secret
        self.config.set_secret(secret)
        self.http_client.set_secret(secret)
        return
    
    async def _register(self):
        """Enregistre l'agent auprès du central.

        Envoie les informations système et le token d'installation.
        Reçoit le secret, les outils autorisés et les capacités en retour.

        Returns:
            tuple: (bool, dict) - Succès et réponse du central.
        """
        data = {
            "system_info": get_system_info(),
            "install_token": self.config.pending_token
        }
        resp = await self.http_client.fetch_post(
            path=self.config.register_path,
            json_data=data
        )
        resp_json = resp.body_json
        if not resp_json or resp_json.get("status") == "error":
            return False, resp_json
        
        secret = resp_json["secret"]
        self.config.allowed_tools = resp_json.get("allowed_tools", [])
        self.config.capabilities = resp_json.get("capabilities", [])
        self.set_secret(secret)
        return True, resp_json
    
    def init_classes(self):
        """Initialise les classes de transport et de dispatch.

        Crée le client WebSocket et le dispatcher après avoir obtenu le secret.

        Raises:
            RuntimeError: Si le secret est introuvable.
        """
        if not self.secret:
            raise RuntimeError("Secret introuvable")
        
        ws_url = f"{self.config.central_ws_url}?{urlencode({'asset_id': self.config.asset_id})}"
        self.ws_client = AgentWSClient(
            ws_url=ws_url,
            secret=self.secret,
            dispatcher=None,
            heartbeat_interval=self.config.heartbeat_interval,
            ack_timeout=self.config.ack_timeout
        )
        self.dispatcher = AgentDispatcher(
            config=self.config,
            http_client=self.http_client,
            ws_client=self.ws_client
        )
        self.ws_client.dispatcher = self.dispatcher.handle
        
    async def init(self):
        """Initialise l'agent.

        1. Si un token d'installation est présent, enregistrement auprès du central.
        2. Initialisation des classes de transport et de dispatch.
        3. Téléchargement du binaire tool_engine.

        Raises:
            RuntimeError: En cas d'échec de l'enregistrement ou du téléchargement.
        """
        try:
            if self.config.pending_token: # Si pending token, enrégister
               success, response = await self._register()
               if not success:
                   raise RuntimeError(f"Erreur de régistration, échec. Réponse: {response!r}")
               self.config.pending_token = None
               self.config.persist()
            else:
                self.set_secret(self.config.secret)
            self.init_classes()
            # print("Téléchargement du binaire !")
            d_response = await self.dispatcher._download_tool_engine()
            # print(d_response)
            if not d_response["success"]:
                raise RuntimeError("Erreur lors du téléchargement du tool engine.")
        
        except asyncio.CancelledError:
            pass
        
        except Exception:
            raise
        
        return 
    
    def register_signal(self):
        """Enregistre les gestionnaires de signaux pour un arrêt propre.

        Configure les handlers pour SIGTERM et SIGINT qui annuleront la tâche principale.
        """
        try:
            loop = asyncio.get_running_loop()
            main_task = asyncio.current_task()
            handler = build_shutdown_handler(main_task)
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, functools.partial(handler, sig.name))
        except Exception:
            pass
        
    async def run(self):
        """Point d'entrée principal de l'agent.

        Initialise l'agent puis lance la boucle WebSocket pour la communication
        avec le central.

        Raises:
            Exception: Toute exception non gérée.
        """
        try:
            await self.init()
            await self.ws_client.run_forever()
        except asyncio.CancelledError:
            pass
        
        except Exception:
            raise


async def main():
    """Fonction principale de l'agent."""
    agent = Agent()
    await agent.run()
    

if __name__ == "__main__":
    _run_async(main)
    # pass