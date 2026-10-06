#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 21:45:13 2026

@author: hounsousamuel
"""

import time
import threading
import multiprocessing as mp
from typing import Union
from uuid import uuid4

_QUEUE = type(mp.Queue())
_MP_EVENT_TYPE = type(mp.Event())
_EVENT = Union[threading.Event, _MP_EVENT_TYPE, None]
_SENTINEL = object()
# Structure [pcid: str, cmd_queue: _QUEUE (LA COMMANDE QUEUE), result_queue: _QUEUE, stop_event: _EVENT, capture_stop_event: _EVENT]

class _CaptureProxyItem:
    __slots__ = (
        "pcid", "cmd_queue", "result_queue", "stop_event",
        "capture_stop_event"
    )
    def __init__(
        self, pcid: str, 
        cmd_queue: _QUEUE, result_queue: _QUEUE,
        stop_event: _EVENT, capture_stop_event: _EVENT
    ):
        for q in (cmd_queue, result_queue):
            if not isinstance(q, _QUEUE):
                raise TypeError("Les queues attendus doivent être des queues Process")
        
        for e in (stop_event, capture_stop_event):
            if e:
                if not isinstance(e, _EVENT):
                    raise TypeError("L'event doit être un event Process !")
            
        self.pcid = pcid
        self.cmd_queue = cmd_queue
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.capture_stop_event = capture_stop_event

class CaptureProxy:
    def __init__(
        self,
        items: list[list[str, _QUEUE, _QUEUE, _EVENT, _EVENT]]
    ):
        self.items = {i[0]: _CaptureProxyItem(*i) for i in items}
        self.lock = threading.Lock()
        
        self.cmd_queues, self.result_queues, self.matching = self.get_queues()
        
    def get_queues(self):
        cmd_queues, result_queues, r = [], [], {}
        seen_cmd, seen_res = set(), set()
        for pcid, item in self.items.items():
            cid, rid = id(item.cmd_queue), id(item.result_queue)
            if cid not in seen_cmd:
                seen_cmd.add(cid)
                cmd_queues.append(item.cmd_queue)
            if rid not in seen_res:
                seen_res.add(rid)
                result_queues.append(item.result_queue)
            r[pcid] = (cid, rid)
        return cmd_queues, result_queues, r
    
    def get_pcid(self, id_):
        for pcid, item in self.matching.items():
            if id_ in item:
                return pcid
            
    def found_result(self, rid: str):
        results = {}
        with self.lock:
            seen = set()
            for result_queue in self.result_queues:
                if id(result_queue) in seen:
                    continue
                
                seen.add(id(result_queue))
                try:
                    item = result_queue.get(timeout=0.001)
                except (mp.queues.Empty, ):
                     continue
                
                if item and str(item[0]) == str(rid):
                     results[self.get_pcid(id(result_queue))] = item[-1]
                     continue
                
                # result_queue.put_nowait(_SENTINEL)
                items = [item]
                while True:
                    try:
                        item = result_queue.get(timeout=0.001)
                    except (mp.queues.Empty, ):
                        break
                    
                    if not item:
                        continue
                    
                    if str(item[0]) == str(rid):
                        results[self.get_pcid(id(result_queue))] = item[-1]
                        break
                    
                    items.append(item)
                    
                for item in items:
                    result_queue.put_nowait(item)
        
        return results
            
    def _do_request(self, rid, attr, attr_for, is_callable, args, kwargs, timeout: float = 2.0) -> dict:
        attr_for = attr_for or "capture"
        request = (
            rid, attr, attr_for, is_callable, args or [], kwargs or {}
        )
        one_set = False
        for cmd_queue in self.cmd_queues:
            try:
                cmd_queue.put(request, timeout=0.001)
                one_set = True
            except (mp.queues.Full, ):
                continue
        
        if not one_set:
            return {}
        
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.found_result(rid)
            if r:                          # non-vide
                return r
            time.sleep(0.005)
        return self.found_result(rid)
    
    @staticmethod
    def _create_rid():
        return str(uuid4())
    
    def add_src_ip_to_ignore(self, ip: str, return_bool: bool = True):
        rid = self._create_rid()
        result = self._do_request(
            rid, "add_src_ip_to_ignore", "capture", True, [], {"ip": ip}
        )
        if not return_bool:
            return result
        values = list(result.values())
        return result and values and all(values)
       
    def remove_src_ip_to_ignore(self, ip: str, return_bool: bool = True):
        rid = self._create_rid()
        result = self._do_request(
            rid, "remove_src_ip_to_ignore", "capture", True, [], {"ip": ip}
        )
        if not return_bool:
            return result
        values = list(result.values())
        return result and values and all(values)
        
    def stats(self):
        rid = self._create_rid()
        return (
            self._do_request(
                rid, "stats", "capture", True, [], {}
            )
        )
        
    def dropped_packets(self):
        rid = self._create_rid()
        return (
            self._do_request(
                rid, "dropped_packets", "capture", False, [], {}
            )
        )
        
    def snapshot(self):
        rid = self._create_rid()
        return (
            self._do_request(
                rid, "snapshot", "capture", True, [], {}
            )
        )
    
    def metrics(self):
        rid = self._create_rid()
        return (
            self._do_request(
                rid, "metrics", "capture", True, [], {}
            )
        )
    
    