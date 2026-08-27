#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 08:34:38 2026

@author: hounsousamuel
"""


import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from modules_utils.signal_manager import signal_manager, ignore_termination_signals
