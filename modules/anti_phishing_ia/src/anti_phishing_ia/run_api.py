#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Dec 30 21:02:30 2025

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import signal
import asyncio
import time
from anti_phishing_ia.main_phish import start, app, close_api_atexit, close_api, stop, clear
from anti_phishing_ia.config import HOST, PORT
import nest_asyncio
nest_asyncio.apply()

def run():
    thread, server = start(app, host=HOST, port=PORT)
    thread.start()
    time.sleep(2)
    # close_api_atexit(CLOSE_TARGET)
    
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
    # clear()
    run()
    
    