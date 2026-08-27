#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 20 08:45:42 2026

@author: hounsousamuel
"""

import random
import secrets

def random_session_id():
    session_id = secrets.token_hex(10)
    return f"simatk-{session_id}"

if __name__ == "__main__":
    print(random_session_id())