#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul  3 21:08:33 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import time
from ids_ips_ia.main.server_state import (
    start, stop, logger
)

from ids_ips_ia.main.services import (
    _do_stop_logic,
)

from ids_ips_ia.main.api import (
    app, host, port, GRAPH, graph, signal_manager
)
from modules_utils.loop_utils import _run_async

def run_ids_ips():
    try:
        th, server = start(app, host, port)
        th.start()
        def _main_signal_handler(*args, **kwargs):
            logger.print("\n[SIGNAL] Arrêt demandé...")
            server.should_exit = True
            _run_async(
                _do_stop_logic,
                app.state
            )
        
        signal_manager(_main_signal_handler)
        while True:
            time.sleep(1)
            # print("En cours...", end="\r")
            
    except Exception as e:
        if GRAPH:
            graph.end()
    
    stop(th, 2)

if __name__ == "__main__":
    run_ids_ips()