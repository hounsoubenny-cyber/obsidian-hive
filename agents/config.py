#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jul  8 22:44:53 2026

@author: hounsousamuel
"""

import os

obsidian_code_fix = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "obsidian_code_fix"
    )
)

OBSIDIAN_SANDBOX_ROOTS = [
    obsidian_code_fix
]
