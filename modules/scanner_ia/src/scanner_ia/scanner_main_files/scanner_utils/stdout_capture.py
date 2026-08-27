#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 26 10:26:37 2026

@author: hounsousamuel
"""

import io, sys
import contextlib
import asyncio


class WSTextIO(io.StringIO):
    def __init__(self, ws_manager, loop: asyncio.AbstractEventLoop, scan_id: str):
        self.ws_manager = ws_manager
        self.loop = loop
        self.scan_id = scan_id

    def write(self, text: str):
        if text.strip():
            if self.loop.is_closed() or not self.loop.is_running():
                print(text, file=sys.__stdout__)  # fallback propre
                return len(text)
            asyncio.ensure_future(
                self.ws_manager.send(scan_id=self.scan_id, type="log", message=text), loop=self.loop
            )
        return len(text)
