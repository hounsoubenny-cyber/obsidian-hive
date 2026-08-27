#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 07:29:01 2026

@author: hounsousamuel
"""

import signal
import functools
import asyncio


def build_shutdown_handler(task: asyncio.Task):
    """
    À enregistrer sur SIGTERM/SIGINT via loop.add_signal_handler(). Annule
    `task` (la coroutine run() de l'agent) plutôt que de laisser le process
    se faire tuer à la sauvage. L'annulation traverse naturellement
    ws_client.run_forever() -> _run_once() -> le `async with
    websockets.connect(...)`, qui ferme le WS proprement dans son
    __aexit__ même en cas de CancelledError — pas besoin de gérer ça
    explicitement ailleurs.
    """
    def _handler(sig_name: str):
        print(f"Signal {sig_name} reçu, arrêt en cours...")
        task.cancel()
    return _handler