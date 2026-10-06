#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 09:29:19 2026

@author: hounsousamuel
"""

import queue
import pickle
import threading
import multiprocessing as mp
from typing import Union
from ids_ips_ia.core.capture import Capture
from ids_ips_ia.refit_system.refit_queue import RefitQueue
from ids_ips_ia.memory_managers.ring import Ring, RingWriter

_QUEUE_TYPE = type(mp.Queue())
_EVENT_TYPE = type(mp.Event())
# Structure d'une demande (id: str, attr: str, attr_for: str, callable: bool, args: list | None, kwargs: dict | None)
# Structure de la sortie (id: str, message: str, is_error: bool, result: Any)
_ATTR_NOT_FOUND = object()

class ProcessCaptureAdapter:
    def __init__(
        self,
        pcid: str,
        refit_args: dict,
        ring_args: dict,
        capture_kwargs: dict,
        command_queue: _QUEUE_TYPE,
        result_queue: _QUEUE_TYPE,
        stop_event: _EVENT_TYPE,
        capture_event: Union[threading.Event, _EVENT_TYPE, None] = None,
        log_interval: float = 10.0,
        sleep_time: float = 2,
    ):
        if not isinstance(ring_args, dict):
            raise TypeError("`ring_arg` doit être un dictionnaire !")
        
        for q in (command_queue, result_queue):
            if not isinstance(q, _QUEUE_TYPE):
                raise TypeError("Les queues attendus doivent être des queues Process")
        
        if not isinstance(stop_event, _EVENT_TYPE):
            raise TypeError("L'event doit être un event Process !")
            
        ring_args["role"] =  "W"
        ring_args["create"] = False
        self._pcid = pcid
        self._ring_args = ring_args
        self._ring = Ring(**ring_args)
        self._ring_writer = RingWriter(ring=self._ring)
        self._refit_kwargs = refit_args
        self._refit_queue = RefitQueue(**self._refit_kwargs)
        self._capture = Capture(
            queue=self._ring_writer,
            log_interval=log_interval,
            backup_queue=self._refit_queue,
            event=capture_event
        )
        self._capture_kwargs = capture_kwargs
        self._command_queue = command_queue
        self._result_queue = result_queue
        self._stop_event = stop_event
        self._sleep_time = float(sleep_time)
        self._stop = False
        self._started = False
        self._threads = []
    
    def _run_cmd_thread(self):
        while True:
            if self._stop_event.is_set() or self._stop:
                break
            
            # if self._stop_event.wait(self._sleep_time):
            #     break
            
            try:
                
                item = self._command_queue.get(timeout=self._sleep_time)
            except (queue.Empty, ):
                continue         
            except (EOFError, OSError):
                break
            except Exception as e:
                print('Erreur dans _run_cmd_thread:', repr(e))
                continue
            
            if not item:
                continue
            
            request_result = None
            error = False
            
            try:
                cmd_id, attr, attr_for, is_callable, args, kwargs = item
                cmd_id, attr, attr_for = str(cmd_id), str(attr), str(attr_for)
            except Exception as e:
                error = True
                request_result = (str(e), "INVALID_REQUEST", error, None)
            
            if error:
                try:
                    self._result_queue.put(request_result, timeout=2)
                    continue
                except Exception:
                    continue
            
            try:
                if attr_for == "self":
                    attr = getattr(self, attr, _ATTR_NOT_FOUND)
                elif attr_for == "ring":
                    attr = getattr(self._ring, attr, _ATTR_NOT_FOUND)    
                elif attr_for == "capture":
                    attr = getattr(self._capture, attr, _ATTR_NOT_FOUND)    
                elif attr_for == "refit_queue":
                    attr = getattr(self._refit_queue, attr, _ATTR_NOT_FOUND)    
                else:
                    error = True
                    request_result = (cmd_id, "UNKNOW_VALUE_FOR_ATTR_FOR", error, None)
            except Exception as e:
                error = True
                request_result = (cmd_id, "ATTR_ACCESS_ERROR", error, str(e))
            
            if not error:
                if attr is _ATTR_NOT_FOUND:
                    error = True
                    request_result = (cmd_id, "ATTR_NOT_FOUND", error, None)
                
                if (not error) and (is_callable and not callable(attr)):
                    error = True
                    request_result = (cmd_id, "REQUEST_CALLABLE_ARG_WHO_IS_NOT_CALLABLE", error, None)
                
                if (not error) and ((not is_callable) and callable(attr)):
                    error = True
                    request_result = (cmd_id, "REQUEST_NOT_CALLABLE_ARG_WHO_IS_CALLABLE", error, None)


            if not error:
                args = args if args and isinstance(args, (list, tuple)) else []
                kwargs = kwargs if kwargs and isinstance(kwargs, dict) else {}
                try:
                    result = attr if not is_callable else attr(*list(args), **dict(kwargs))
                    request_result = (cmd_id, None, False, result)
                except Exception as e:
                    request_result = (cmd_id, "RUN_ERROR", False, str(e))
                # print("Debug", request_result)
            
            try:
                pickle.dumps(request_result)
            except Exception as e:
                request_result = (cmd_id, f"RESULT_NOT_PICKLABLE: {e}", True, None)
                
            try:
                self._result_queue.put(request_result, timeout=2)
            except Exception:
                continue
        
    def _start_capture(self):
        self._refit_queue.start()
        self._capture.capture(**self._capture_kwargs)
    
    def start(self):
        if self._started:
            return
        th1 = threading.Thread(target=self._run_cmd_thread, daemon=True, name=f"CommandThread-{self._pcid}")
        th2 = threading.Thread(target=self._start_capture, daemon=True, name=f"CaptureThread-{self._pcid}")
        th1.start()
        th2.start()
        self._threads.extend([th1, th2])
        self._started = True
        return
    
    def wait(self, timeout: float | None = None):
        if not self._started:
            return
        
        for event in (self._stop_event, self._capture.event, self._refit_queue.stop_event):
            event.wait(timeout)
        return 
    
    def stop(self, timeout: float = 5.0):
        if self._started:
            if self._stop:
                return
            self._stop = True
            try:
                self._capture.stop(timeout=timeout)
            except Exception as e:
                print(f"Erreur de stop de la capture {self._pcid}: {e!r}")
            
            try:
                self._refit_queue.stop(timeout=timeout)
            except Exception as e:
                print(f"Erreur de stop de la refit queue {self._pcid}: {e!r}")
                
            try:
                self._ring.close()
            except Exception as e:
                print(f"Erreur de fermeture du ring {self._pcid}: {e!r}")
            return
        
        return