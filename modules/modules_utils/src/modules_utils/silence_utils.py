#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 20:46:57 2026

@author: hounsousamuel
"""

import sys
import io
import contextlib

@contextlib.contextmanager
def silence_output():
    old_stdout, old_stderr = sys.stdout, sys.stderr
    buf_out, buf_err = io.StringIO(), io.StringIO()
    sys.stdout, sys.stderr = buf_out, buf_err
    try:
        yield buf_out, buf_err
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__