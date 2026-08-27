#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 07:21:13 2026

@author: hounsousamuel
"""

import socket

def get_ip_type(ip: str) -> str:
    try:
        for k, v in [(socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")]:
            try:
                socket.inet_pton(k, ip)
                return v
            except Exception:
                pass
            
        return "error"
    
    except Exception:
        return "error"
    
if __name__ == "__main__":
    get_ip_type("127.0.0.1")