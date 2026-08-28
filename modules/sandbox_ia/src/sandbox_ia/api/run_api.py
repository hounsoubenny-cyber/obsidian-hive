#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 21 11:36:20 2026

@author: hounsousamuel
"""

import sys
import time
import nest_asyncio

from sandbox_ia.api.main_api import app, start, stop
from sandbox_ia.api.api_config import API_HOST, API_PORT
from modules_utils.signal_manager import signal_manager

def run_api():
    """Lance l'API Sandbox."""
    
    thread, server = start(app, host=API_HOST, port=API_PORT)
    thread.start()
    time.sleep(2)
    
    def signal_handler(sig, frame):
        print(f'Signal reçu: {sig}')
        server.should_exit = True
        stop(thread, 2)
        sys.exit(0)
    
    signal_manager(signal_handler)
    
    print(f'🚀 API Sandbox lancée sur http://{API_HOST}:{API_PORT}')
    print(f'📚 Documentation: http://{API_HOST}:{API_PORT}/api/docs')
    print(f'⏱️  Démarrage: {time.ctime()}')
    
    start_time = time.time()
    
    try:
        while True:
            time.sleep(1)
            elapsed = time.time() - start_time
            print(f'⏳ API lancée depuis: {elapsed:.1f}s', end='\r')
    except KeyboardInterrupt:
        print('\n⏹️ Interruption utilisateur')
    finally:
        print(f'🔴 Fermeture API à {time.ctime()}')


if __name__ == '__main__':
    nest_asyncio.apply()
    run_api()