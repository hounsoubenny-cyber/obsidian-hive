#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Dec 30 21:02:30 2025

@author: hounsousamuel
"""

import sys
import time
from anti_phishing_ia.main_phish import start, app, stop
from anti_phishing_ia.config import HOST, PORT
import nest_asyncio
from modules_utils.signal_manager import signal_manager


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
    # clear()
    nest_asyncio.apply()
    run()
    
    