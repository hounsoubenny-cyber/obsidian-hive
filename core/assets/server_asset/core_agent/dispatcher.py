#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 10 23:32:15 2026

@author: hounsousamuel
"""

"""
dispatcher.py — route les messages WS entrants vers la bonne action
"""

import os
import copy
import json
import json5
import asyncio

from obsidian_hive.core.assets.server_asset.core_agent.config import AgentConfig
from obsidian_hive.core.assets.server_asset.tools.server_asset_tools_type import ToolResult, ToolCall
from obsidian_hive.core.assets.server_asset.core_agent.server_asset_types import ReceiveMsgType
from obsidian_hive.core.assets.server_asset.core_agent.transport import AgentHttpClient, AgentWSClient

TOOL_ENGINE_PATH = "/opt/obsidian-agent/bin/tool_engine"
UNINSTALL_SCRIPT_PATH = "/opt/obsidian-agent/uninstall.sh"
TOOL_CALL_TIMEOUT = 60  # secondes, évite qu'un tool bloqué gèle l'agent indéfiniment


class AgentDispatcher:
    """Dispatch les messages WebSocket entrants vers les handlers appropriés.
    
    Cette classe est le cœur du routage des messages reçus par l'agent serveur.
    Elle gère les différents types de messages (heartbeat, tool calls,
    autodestruction, révocation, rotation de secret, mise à jour de config)
    et exécute les actions correspondantes.
    
    Attributes:
        config (AgentConfig): Configuration de l'agent.
        http_client (AgentHttpClient): Client HTTP pour les appels vers le central.
        ws_client (AgentWSClient): Client WebSocket pour la communication.
    """
    
    def __init__(self, config: AgentConfig, http_client: AgentHttpClient, ws_client: AgentWSClient):
        """Initialise le dispatcher.

        Args:
            config (AgentConfig): Configuration de l'agent.
            http_client (AgentHttpClient): Client HTTP.
            ws_client (AgentWSClient): Client WebSocket.
        """
        self.config = config
        self.http_client = http_client
        self.ws_client = ws_client

    async def handle(self, data: dict, ws):
        """Point d'entrée principal pour le traitement des messages.

        Identifie le type de message et appelle le handler correspondant.

        Args:
            data (dict): Le message reçu (au format JSON décodé).
            ws: La connexion WebSocket.
        """
        msg_type = data.get("type")

        handler = {
            ReceiveMsgType.HEARTBEAT_ACK.value : self._on_heartbeat_ack,
            ReceiveMsgType.TOOL_CALL.value : self._on_tool_call,
            ReceiveMsgType.SELF_DESTRCUT.value : self._on_self_destruct,
            ReceiveMsgType.REVOKED.value : self._on_revoked,
            ReceiveMsgType.SECRET_ROTATED.value : self._on_secret_rotated,
            ReceiveMsgType.CONFIG_RELOAD.value : self._on_config_reload,
            ReceiveMsgType.CONFIG_UPDATE.value : self._on_config_update,
        }.get(msg_type)

        if handler is None:
            print(f"Type de message inconnu, ignoré: {msg_type!r}")
            return

        await handler(data, ws)
    
    # =============================================================================
    # TÉLÉCHARGEMENTS
    # =============================================================================
        
    async def _download_tool_engine(self):
        """Télécharge le binaire tool_engine si nécessaire.

        Vérifie si le binaire existe déjà. Si ce n'est pas le cas, le télécharge
        depuis le central et le rend exécutable.

        Returns:
            dict: Résultat du téléchargement avec 'success', 'path' et 'already_present'.
        """
        if os.path.exists(TOOL_ENGINE_PATH):
            return {"success": True, "path": TOOL_ENGINE_PATH, "already_present": True}
        os.makedirs(os.path.dirname(TOOL_ENGINE_PATH), exist_ok=True)
        return await self.http_client.download_file(
            path=self.config.download_tool_engine_path,
            dest_path=TOOL_ENGINE_PATH,
            params={"version": "latest", "asset_id": self.config.asset_id},
            perm=0o700,
        )
        
    # =============================================================================
    # HANDLERS    
    # =============================================================================
    
    # Heartbeat_ack
    
    async def _on_heartbeat_ack(self, data: dict, ws):
        """Handler pour les accusés de réception heartbeat.

        Marque la réception du heartbeat_ack pour maintenir la connexion active.

        Args:
            data (dict): Le message reçu.
            ws: La connexion WebSocket.
        """
        self.ws_client.mark_heartbeat_ack()
        return

    # Tool call

    async def _run_tool_engine(
        self, 
        asset_id: str, 
        tool_call: dict, 
        timeout: int | float = TOOL_CALL_TIMEOUT
    ) -> dict:
        """Exécute un tool via le binaire tool_engine.

        Lance le binaire tool_engine en sous-processus, lui passe l'appel d'outil
        via stdin et récupère le résultat.

        Args:
            asset_id (str): L'ID de l'asset serveur.
            tool_call (dict): L'appel d'outil à exécuter.
            timeout (int | float, optional): Timeout en secondes. Par défaut 60.

        Returns:
            dict: Le résultat de l'exécution du tool.

        Raises:
            RuntimeError: Si le binaire tool_engine échoue ou si le timeout est dépassé.
            asyncio.TimeoutError: Si le timeout est dépassé.
        """
        proc = await asyncio.create_subprocess_exec(
            TOOL_ENGINE_PATH,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout: bytes
        stderr: bytes
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(json.dumps({"asset_id": asset_id, "tool_call": tool_call}).encode()),
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"tool_engine a échoué (code {proc.returncode}): {stderr.decode(errors='replace')}")
        response = stdout.decode()
        idx = response.find("{")
        if idx == -1:
            raise RuntimeError(f"Réponse invalide de tool_engine (aucun JSON trouvé) : {response}")
        return json5.loads(response[idx:])
    
    async def _on_tool_call(self, data: dict, ws):
        """Handler pour les appels d'outils.

        Vérifie si l'outil est autorisé, télécharge le binaire si nécessaire,
        exécute l'outil et renvoie le résultat.

        Args:
            data (dict): Le message reçu contenant 'tool_call' et éventuellement 'asset_id'.
            ws: La connexion WebSocket.
        """
        asset_id = data.get("asset_id") or self.config.asset_id
        tool_call = data.get("tool_call")
        tool_result = {}
        try:
            if tool_call:            
                tool_call: ToolCall = ToolCall.model_validate(tool_call)
                if tool_call.tool_name not in self.config.allowed_tools:
                    tool_result = {
                        "error": "Tool non autorisé !",
                        "tool_name": tool_call.tool_name,
                        "call_id": tool_call.call_id,
                        "caller": tool_call.caller,
                        "asset_id": asset_id,
                    }
                else:
                    try:
                        await self._download_tool_engine()
                        if not os.path.exists(TOOL_ENGINE_PATH):
                            tool_result = {
                                "error": "Le binaire d'execution des tools est introuvable !"
                            }
                        else:
                            tool_result = await self._run_tool_engine(asset_id, tool_call.model_dump(), TOOL_CALL_TIMEOUT)
                    except Exception as e:
                        tool_result = {
                            "error": f"Erreur dans le moteur d'exécution: {e!r}",
                        }
                    
                    tool_result.update(dict(
                        tool_name=tool_call.tool_name,
                        call_id=tool_call.call_id,
                        caller=tool_call.caller,
                        asset_id=asset_id,
                    ))
            else:
                msg = ""
                if not tool_call:
                    msg = "L'entré tool call est absente !"
                
                tool_result = {
                    "error": msg
                }
                
        finally:        
            tool_result: ToolResult = ToolResult.model_validate(tool_result)
            tool_result = tool_result.model_dump()
            await ws.send(json.dumps({"type": "tool_result", "tool_result": tool_result}))
    
    # Self destruct
    
    async def _on_self_destruct(self, data: dict, ws):
        """Handler pour l'autodestruction de l'agent.

        Lance le script de désinstallation, envoie un accusé de réception
        et termine le processus.

        Args:
            data (dict): Le message reçu.
            ws: La connexion WebSocket.
        """
        try:
            os.chmod(UNINSTALL_SCRIPT_PATH, 0o755) # Rendre exécutable
            process = await asyncio.create_subprocess_exec(
                "sudo", UNINSTALL_SCRIPT_PATH,
                start_new_session=True,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        finally:
            try:
                await ws.send(json.dumps({"type": "self_destruct_ack"}))
                await ws.close()
            except Exception:
                pass
            os._exit(0)

    # Revoked
    
    async def _on_revoked(self, data: dict, ws):
        """Handler pour la révocation de l'agent.

        Marque l'agent comme révoqué, ce qui empêchera les futures connexions.

        Args:
            data (dict): Le message reçu.
            ws: La connexion WebSocket.
        """
        self.ws_client.mark_revoked()
    
    # Secret rotate
    
    async def _on_secret_rotated(self, data: dict, ws):
        """Handler pour la rotation du secret.

        Met à jour le secret dans la configuration, le client HTTP et le client WS.

        Args:
            data (dict): Le message reçu contenant le nouveau 'secret'.
            ws: La connexion WebSocket.
        """
        new_secret = data.get("secret")
        if not new_secret:
            return
        self.config.set_secret(new_secret) 
        self.http_client.set_secret(new_secret)
        self.ws_client.secret = new_secret  
        return
    
    # Config update
    
    async def _on_config_update(self, data: dict, ws):
        """Handler pour la mise à jour de configuration.

        Met à jour les champs de configuration qui ont changé et persiste les changements.

        Args:
            data (dict): Le message reçu contenant les nouvelles valeurs de config.
            ws: La connexion WebSocket.
        """
        data_copy = copy.deepcopy(data)
        data_copy.pop("type", None)
        to_set = {k: v for k, v in data_copy.items() if hasattr(self.config, k)}
        changed = any(getattr(self.config, k) != v for k, v in to_set.items())
        if changed:
            self.config.update(to_set, persist=True)
        return
    
    # Config reload
    
    async def _on_config_reload(self, data: dict, ws):
        """Handler pour le rechargement de configuration.

        Recharge la configuration depuis le fichier et met à jour les clients.

        Args:
            data (dict): Le message reçu.
            ws: La connexion WebSocket.
        """
        self.config.reload()
        self.ws_client.secret = self.config.secret
        self.http_client.set_secret(self.config.secret)
        return