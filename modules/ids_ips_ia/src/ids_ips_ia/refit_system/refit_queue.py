#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 21:16:21 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import time
import joblib
import threading
import multiprocessing as mp
from collections import deque
from ids_ips_ia.refit_system.config import FILE_PREFIX, REFIT_DIR
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

class RefitQueue:
    def __init__(self, session_id:str, max_file_size:int = 100 * 1024 * 1024, save_interval:int|float = 3600):
        self.session_id = session_id
        self.current_num = 0
        self.last_save_time = time.time()
        self.stop_event = threading.Event()
        self.max_file_size = max_file_size
        self.current_filename = ""
        self.q_size = 500_00
        self.queue = deque(maxlen=self.q_size)
        self._lock = mp.Lock()
        self.thread = None
        self.save_interval = save_interval
    
    def stop(self):
        self.stop_event.set()
        try:
            self.thread.join(1)
        except Exception:
            pass
    
    def start(self):
        self.thread = threading.Thread(
            target=self.save_periodic,
            args=(self.save_interval,), 
            daemon=True
        )
        self.thread.start()
    
    def put(self, item):
        try:
            if len(self.queue) >= self.q_size:
                return
            
            with self._lock:
                self.queue.append(item)
        except Exception:
            return
    
    def put_nowait(self, item):
        self.put(item)
    
    def get(self):
        try:
            with self._lock:
                return self.queue.popleft()
        except Exception:
            pass
    
    def get_nowait(self):
        return self.get()
    
    def build_filename(self):
        filename = f"{FILE_PREFIX}__{self.session_id}__{self.current_num}.pkl"
        self.current_filename = filename
        self.current_num += 1
        return filename
    
    def is_current_refit_queue_file(self, path:str) -> bool:
        # FORMAT "FILE_PREFIX__session_id__num.pkl"
        return self.session_id in path
    
    def remove_files(self):
        filenames = [
            path for path in os.listdir(REFIT_DIR) 
            if os.path.isfile(path) and str(path).startswith(FILE_PREFIX) \
            and str(path).endswith(".pkl")
        ]
            
        for filename in filenames:
            if not self.is_current_refit_queue_file():
                os.remove(os.path.join(REFIT_DIR,filename))
    
    def save_periodic(self, save_interval):
        while not self.stop_event.is_set():
            time.sleep(60 * 5)
            if time.time() - self.last_save_time >= save_interval:
                self.save()
    
    def save(self):
        try:
            if not self.current_filename:
                filename = os.path.join(REFIT_DIR, self.build_filename())
                data = []
                with self._lock:
                    data = list(self.queue)
                    self.queue.clear()
                joblib.dump(data, filename, compress=5)
                
            else:
                filename = os.path.join(REFIT_DIR, self.current_filename)
                size = os.path.getsize(filename) * 1024 * 1024
                if size > self.max_file_size:
                    filename = os.path.join(REFIT_DIR, self.build_filename())
                    data = []
                    with self._lock:
                        data = list(self.queue)
                        self.queue.clear()
                    joblib.dump(data, filename, compress=5)
                    
                else:
                    data = joblib.load(self.current_filename)
                    with self._lock:
                        data.extend(list(self.queue))
                        self.queue.clear()
                    joblib.dump(data, filename, compress=5)
            
        except Exception as e:
            logger.print("Erreur survenu lors de la sauegarde :", str(e))
        
        self.last_save_time = time.time()
        
                

if __name__ == "__main__":
    filesname = [
        path for path in os.listdir(REFIT_DIR) 
        if os.path.isfile(path) and str(path).startswith(FILE_PREFIX) \
        and str(path).endswith(".pkl")
    ]
    logger.print(filesname)
        