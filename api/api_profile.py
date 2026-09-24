#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Sep 23 10:17:51 2026

@author: hounsousamuel
"""

def do_import():
    from obsidian_hive.api.main_api import _routes
    _routes()

def profile():
    import cProfile, pstats
    pr = cProfile.Profile()
    pr.enable()
    do_import()
    pr.disable()
    stats = pstats.Stats(pr).sort_stats("cumulative")
    stats.print_stats(10)

if __name__ == "__main__":
    profile()