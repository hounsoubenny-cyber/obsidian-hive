#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug 11 10:29:44 2026

@author: hounsousamuel
"""

import os
import aiofiles
import asyncio
import platform
import socket
import shutil
import time
import psutil
    
def read_file(path, mode: str = "r"):
    if path and os.path.exists(path):
        with open(path, mode=mode) as f:
            return f.read()
    return None

async def aread_file(path, mode: str = "r"):
    if path and os.path.exists(path):
        async with aiofiles.open(path, mode=mode) as f:
            return await f.read()
    return None

async def exec_func(func, *args, **kwargs):
    r = func(*args, **kwargs)
    if asyncio.iscoroutine(r):
        r = await r
    
    return r

async def cancel_tasks(tasks: list[asyncio.Task]):
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


def get_system_info() -> dict:
    info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),          # "Linux", "Windows", "Darwin"
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),  # "x86_64", "aarch64"...
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "boot_time": None,
        "uptime_seconds": None,
        "memory": None,
        "disk": None,
        "load_average": None,
        "ip_addresses": [],
    }

    # IP locales — best effort, jamais bloquant
    try:
        hostname = socket.gethostname()
        info["ip_addresses"] = list(set(
            addr[4][0]
            for addr in socket.getaddrinfo(hostname, None)
            if addr[0] in (socket.AF_INET, socket.AF_INET6)
        ))
    except Exception:
        pass

    # Disque — stdlib pur, toujours dispo
    try:
        total, used, free = shutil.disk_usage("/")
        info["disk"] = {
            "total_gb": round(total / (1024 ** 3), 2),
            "used_gb": round(used / (1024 ** 3), 2),
            "free_gb": round(free / (1024 ** 3), 2),
            "used_percent": round((used / total) * 100, 1) if total else None,
        }
    except Exception:
        pass

    # Load average — Linux/macOS seulement, pas Windows
    try:
        info["load_average"] = os.getloadavg()
    except (AttributeError, OSError):
        pass

    try:
        info["boot_time"] = psutil.boot_time()
        info["uptime_seconds"] = round(time.time() - psutil.boot_time())
        vm = psutil.virtual_memory()
        info["memory"] = {
            "total_gb": round(vm.total / (1024 ** 3), 2),
            "available_gb": round(vm.available / (1024 ** 3), 2),
            "used_percent": vm.percent,
        }
        info["cpu_percent"] = psutil.cpu_percent(interval=0.5)
    except Exception:
        pass

    return info