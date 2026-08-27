#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 08:34:38 2026

@author: hounsousamuel
"""

import os, sys, signal

def signal_manager(func, *args, **kwargs): 
    def function(sig, frame):
        func(sig, frame, *args, **kwargs)
        # os.kill(os.getpid(), 9)
        # os._exit(1)
        sys.exit(1)
        
    signal.signal(signal.SIGINT, function)
    signal.signal(signal.SIGTERM, function)
    signal.signal(signal.SIGQUIT, function)
