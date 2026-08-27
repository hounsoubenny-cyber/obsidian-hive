#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 13 06:42:38 2026

@author: hounsousamuel
"""

import os
import signal
import asyncio
import subprocess

# ─────────────────────────────────────────────────────────────────────────
# 1. SYNC — groupe de processus, asyncio.subprocess.Process (start_new_session=True)
# ─────────────────────────────────────────────────────────────────────────


async def kill_process_group_async(process: asyncio.subprocess.Process, name: str = ""):
    try:
        pgid = os.getpgid(process.pid)

    except ProcessLookupError:
        print(f"[INFO] Process {name}  déjà terminé")
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
        await asyncio.wait_for(process.wait(), timeout=2)
        print(f"[INFO] Process  {name} arrêté proprement")

    except asyncio.TimeoutError:
        print(f"[WARN] Process {name} ne répond pas, SIGKILL du groupe")
        try:
            os.killpg(pgid, signal.SIGKILL)

        except ProcessLookupError:
            pass

        await process.wait()

    except ProcessLookupError:
        pass

# ─────────────────────────────────────────────────────────────────────────
# 2. ASYNC — process unique (pas de groupe), asyncio.subprocess.Process
# ─────────────────────────────────────────────────────────────────────────

async def kill_process_async(process: asyncio.subprocess.Process, name: str = ""):
    """Tue un seul process async (pas son groupe) — SIGTERM puis SIGKILL."""
    if process is None or process.returncode is not None:
        print(f"[INFO] Process {name} déjà terminé")
        return
    try:
        process.terminate()  # SIGTERM sur le process seul
        await asyncio.wait_for(process.wait(), timeout=2)
        print(f"[INFO] Process {name} arrêté proprement")
    except asyncio.TimeoutError:
        print(f"[WARN] Process {name} ne répond pas, SIGKILL")
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
    except ProcessLookupError:
        pass


# ─────────────────────────────────────────────────────────────────────────
# 3. SYNC — groupe de processus, subprocess.Popen (start_new_session=True)
# ─────────────────────────────────────────────────────────────────────────

def kill_process_group_sync(process: subprocess.Popen, name: str = "", timeout: float = 2.0):
    """Tue tout le groupe de processus d'un Popen lancé avec start_new_session=True."""
    if process is None or process.poll() is not None:
        print(f"[INFO] Process {name} déjà terminé")
        return
    try:
        pgid = os.getpgid(process.pid)
    except ProcessLookupError:
        print(f"[INFO] Process {name} déjà terminé")
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
        process.wait(timeout=timeout)
        print(f"[INFO] Process {name} arrêté proprement")
    except subprocess.TimeoutExpired:
        print(f"[WARN] Process {name} ne répond pas, SIGKILL du groupe")
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    except ProcessLookupError:
        pass


# ─────────────────────────────────────────────────────────────────────────
# 4. SYNC — process unique (pas de groupe), subprocess.Popen
# ─────────────────────────────────────────────────────────────────────────

def kill_process_sync(process: subprocess.Popen, name: str = "", timeout: float = 2.0):
    """Tue un seul process Popen (pas son groupe) — SIGTERM puis SIGKILL."""
    if process is None or process.poll() is not None:
        print(f"[INFO] Process {name} déjà terminé")
        return
    try:
        process.terminate()  # SIGTERM sur le process seul
        process.wait(timeout=timeout)
        print(f"[INFO] Process {name} arrêté proprement")
    except subprocess.TimeoutExpired:
        print(f"[WARN] Process {name} ne répond pas, SIGKILL")
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()
    except ProcessLookupError:
        pass