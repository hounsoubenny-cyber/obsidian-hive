#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 26 02:21:04 2026

@author: hounsousamuel
"""

"""
Réécrit le Sun Jul 26 2026 : le modèle who/to (relais user-to-user) est
remplacé par un simple registre de connexions + push serveur->client
(send_to/broadcast), qui correspond au besoin réel (streaming Coralie/Alex,
confirmations, notifications de jobs/IDS en tâche de fond) — vous êtes en
admin unique pour l'instant, pas de chat inter-utilisateurs à relayer.

@author: hounsousamuel
"""

import json
from fastapi import WebSocket


class WSManager:
    """
    Registre des connexions WebSocket actives, indexées par username.

    Usage principal : push serveur -> client (tokens de streaming d'un
    agent, confirmations humaines, notifications de jobs/IDS en tâche de
    fond). Une connexion à la fois par username : une reconnexion
    remplace simplement l'ancienne entrée (utile en dev avec hot-reload
    frontend, pas besoin de gérer explicitement les doublons).
    """

    def __init__(self):
        self.ws: dict[str, WebSocket] = {}

    def connect(self, ws: WebSocket, username: str) -> None:
        self.ws[username] = ws

    def disconnect(self, username: str, ws: WebSocket | None = None) -> bool:
        """Retire la connexion. Retourne False si le username n'était pas
        enregistré (no-op silencieux, pratique à appeler dans un `finally`
        même si la connexion n'a jamais abouti)."""
        if ws is not None and not self.ws.get(username) is ws:
            return
        return self.ws.pop(username, None) is not None

    def is_connected(self, username: str) -> bool:
        return username in self.ws

    async def send_to(self, username: str, data: dict) -> bool:
        """
        Pousse un évènement structuré à UN client précis.

        Ne lève jamais : retourne False si le client n'est pas (ou plus)
        connecté, ou si l'envoi échoue (auquel cas la connexion morte est
        nettoyée du registre au passage).

        Sérialise via json.dumps(default=str) plutôt que
        WebSocket.send_json (qui utilise json.dumps sans `default` et
        plante sur tout objet non-JSON-natif). C'est important ici : les
        payloads d'évènements agent (résultats de tools, exceptions,
        datetimes...) contiennent souvent des objets Python bruts, pas
        déjà nettoyés pour la sérialisation.
        """
        ws = self.ws.get(username)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(data, default=str, ensure_ascii=False))
            return True
        except Exception as e:
            print(f"Erreur send_to({username!r}): {e}")
            self.disconnect(username)
            return False

    async def broadcast(self, data: dict) -> int:
        """Pousse un évènement à tous les clients connectés (ex: alerte
        IDS/IPS globale). Retourne le nombre d'envois réussis."""
        sent = 0
        for username in list(self.ws):
            if await self.send_to(username, data):
                sent += 1
        return sent
