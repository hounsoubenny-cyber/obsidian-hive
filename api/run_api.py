#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul  7 02:18:37 2026

@author: hounsousamuel
"""

import sys
import time
from obsidian_hive.api.main_api import start, app, stop
from obsidian_hive.api.ap_config import API_HOST, API_PORT
from modules_utils.signal_manager import signal_manager
import nest_asyncio

def run():
    thread, server = start(app, host=API_HOST, port=API_PORT)
    thread.start()
    time.sleep(2)
    # TARGET = f'http://{API_HOST}:{API_PORT}/api'
    # CLOSE_TARGET = TARGET + "/close"
    # close_api_atexit(CLOSE_TARGET)
    
    def signal_handler(sig, frame):
        print('Signal envoyé : ', sig)
        server.should_exit = True
        stop(thread, 2)
        sys.exit(0)
        
    signal_manager(signal_handler)
    # signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(signal.SIGTERM, signal_handler)
    # if sys.platform != "win32":
    #     signal.signal(signal.SIGQUIT, signal_handler)
    
    print('API lancé à : ', time.ctime())
    start_time = time.time()
    
    while True:
        try:
            time.sleep(1)
            elapsed = time.time() - start_time
            print(
                f'API lancé depuis :  {elapsed:.2f} {"seconde" if elapsed < 2 else "secondes"} ({elapsed / 60 :.2f} {"minute" if elapsed / 60 < 2 else "minutes"})',
                end="\r"
            )
            
        except KeyboardInterrupt:
            print('Interruption , sortie !')
            break
        
        except Exception:
            break
        
    print('Fermeture API à : ', time.ctime())
    
if __name__ == '__main__':
    nest_asyncio.apply()
    run()
    
    