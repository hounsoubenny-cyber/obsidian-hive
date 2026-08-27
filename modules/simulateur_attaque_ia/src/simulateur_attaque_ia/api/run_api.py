#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 10:57:00 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from simulateur_attaque_ia.api.api import start, app, close_api, close_api_atexit, stop
from simulateur_attaque_ia.configs.config import IP, PORT
import signal
import time
import asyncio
import nest_asyncio

nest_asyncio.apply()


def run_api():
    thread, server = start(app, host=IP, port=PORT)
    thread.start()
    time.sleep(2)
    TARGET = f'http://{IP}:{PORT}/api'
    CLOSE_TARGET = TARGET + "/close"
    close_api_atexit(CLOSE_TARGET)
    
    def signal_handler(sig, frame):
        print('Signal envoyé : ', sig)
        server.should_exit = True
        stop(thread, 2)
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if sys.platform != "win32":
        signal.signal(signal.SIGQUIT, signal_handler)
    
    print('API lancé à : ', time.ctime())
    start_time = time.time()
    
    while True:
        try:
            time.sleep(1)
            elapsed = time.time() - start_time
            print(f'API lancé depuis :  {elapsed:.2f} {"seconde" if elapsed < 2 else "secondes"} ({elapsed / 60 :.2f} {"minute" if elapsed / 60 < 2 else "minutes"})', end="\r")
            
        except KeyboardInterrupt:
            print('Interruption , sortie !')
            break
        except Exception:
            break
    print('Fermeture API à : ', time.ctime())
    
if __name__ == '__main__':
    run_api()
    
    