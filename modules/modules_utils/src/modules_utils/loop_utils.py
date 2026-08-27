#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 12 20:01:10 2026

@author: hounsousamuel
"""

import asyncio
import threading

def _run_async(func, *args, **kwargs):
    """Exécute une coroutine de façon synchrone, même si une loop tourne déjà dans ce thread."""
    try:
        asyncio.get_running_loop()
        loop_running = True
    except RuntimeError:
        loop_running = False

    if not loop_running:
        return asyncio.run(func(*args, **kwargs))

    # Une loop tourne déjà dans ce thread -> impossible d'en nester une autre ici.
    # On exécute dans un thread séparé, avec sa propre loop indépendante.
    box = {}

    def _runner():
        new_loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(new_loop)
            box["result"] = new_loop.run_until_complete(func(*args, **kwargs))
        except Exception as e:
            box["error"] = e
        finally:
            new_loop.close()

    t = threading.Thread(target=_runner)
    t.start()
    t.join()

    if "error" in box:
        raise box["error"]
    return box["result"]