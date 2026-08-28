#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 10:57:00 2026

@author: hounsousamuel
"""

import sys
from simulateur_attaque_ia.api.api import start, app, close_api_atexit, stop
from simulateur_attaque_ia.configs.config import IP, PORT
import time
from modules_utils.signal_manager import signal_manager


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
        
    signal_manager(signal_handler)
    
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
    nest_asyncio.apply()
    run_api()
    
    