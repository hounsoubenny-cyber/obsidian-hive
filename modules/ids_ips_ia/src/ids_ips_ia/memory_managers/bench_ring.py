#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 10:27:43 2026

@author: hounsousamuel
"""

"""
bench_ring.py — Benchmark : Ring (mémoire partagée) vs multiprocessing.Queue.

Compare, sur des paquets de taille VARIABLE (60–1518 octets, comme Ethernet) :
  1) 1 writer  -> 1 reader
  2) N writers -> 1 reader

Pour chaque scénario :
  - Ring  (ton implémentation)
  - mp.Queue, un put/get par paquet
  - mp.Queue, put/get par batch de 64 paquets (une list dans la queue)

Utilisation : python3 bench_ring.py
Prérequis  : ring.py (ton fichier) dans le même dossier.
"""

import os
import time
import random
import multiprocessing as mp
from statistics import median

from ring import Ring, MultiReader


# ============================ CONFIG ============================
N_PACKETS   = 200_000
CAP_BYTES   = 1 << 22        # 4 Mio par ring
BATCH_SIZE  = 64
RUNS        = 3
N_WRITERS   = 4
QUEUE_MAXSIZE = 10_000
PKT_MIN, PKT_MAX = 60, 1518

_ring_counter = 0


def _new_ring_name():
    global _ring_counter
    _ring_counter += 1
    return f"bench_{os.getpid()}_{_ring_counter}"


def _cleanup_old(name):
    from multiprocessing import shared_memory
    try:
        old = shared_memory.SharedMemory(name=name)
        old.close()
        old.unlink()
    except FileNotFoundError:
        pass


def _mk_pkts(n, seed):
    """Génère n paquets de taille variable (60–1518 octets)."""
    rng = random.Random(seed)
    return [b"\xAB" * rng.randint(PKT_MIN, PKT_MAX) for _ in range(n)]


# ============================ WORKERS ============================
def _ring_writer(name, cap, n_pkts, seed, barrier):
    ring = Ring(name=name, cap=cap, create=False, role="W")
    pkts = _mk_pkts(n_pkts, seed)   # pré-généré AVANT le chrono
    barrier.wait()                  # on attend que tout le monde soit prêt
    for p in pkts:
        while not ring.put(p):      # plein : on spin
            pass
    ring.close()


def _queue_writer(q, n_pkts, seed, barrier, batch_size=None):
    pkts = _mk_pkts(n_pkts, seed)
    barrier.wait()
    if batch_size is None:
        for p in pkts:
            q.put(p)
    else:
        for i in range(0, len(pkts), batch_size):
            q.put(pkts[i:i + batch_size])


# ============================ BENCH 1W1R ============================
def bench_ring_1w1r(n, cap):
    name = _new_ring_name()
    _cleanup_old(name)
    parent = Ring(name=name, cap=cap, create=True, role="P")

    barrier = mp.Barrier(2)
    w = mp.Process(target=_ring_writer, args=(name, cap, n, 1, barrier))
    w.start()
    barrier.wait()                  # les deux processus démarrent ensemble

    t0 = time.perf_counter()
    got = 0
    total_bytes = 0
    while got < n:
        ts, pkt = parent.get()
        if pkt is not None:
            got += 1
            total_bytes += len(pkt)
    t1 = time.perf_counter()

    w.join()
    parent.close()
    parent.unlink()
    return t1 - t0, got, total_bytes


def bench_queue_1w1r(n, batched=False):
    q = mp.Queue(maxsize=QUEUE_MAXSIZE)
    barrier = mp.Barrier(2)
    bs = BATCH_SIZE if batched else None
    w = mp.Process(target=_queue_writer, args=(q, n, 1, barrier, bs))
    w.start()
    barrier.wait()

    t0 = time.perf_counter()
    got = 0
    total_bytes = 0
    if batched:
        while got < n:
            batch = q.get()
            got += len(batch)
            total_bytes += sum(len(p) for p in batch)
    else:
        while got < n:
            p = q.get()
            got += 1
            total_bytes += len(p)
    t1 = time.perf_counter()

    w.join()
    return t1 - t0, got, total_bytes


# ============================ BENCH Nw1r ============================
def bench_ring_nw1r(n_total, nw, cap):
    per = n_total // nw
    names = [_new_ring_name() for _ in range(nw)]
    for nm in names:
        _cleanup_old(nm)
    parents = [Ring(name=nm, cap=cap, create=True, role="P") for nm in names]
    configs = [{"name": nm, "cap": cap} for nm in names]

    barrier = mp.Barrier(nw + 1)
    procs = []
    for k, nm in enumerate(names):
        p = mp.Process(target=_ring_writer, args=(nm, cap, per, 100 + k, barrier))
        p.start()
        procs.append(p)
    barrier.wait()

    reader = MultiReader(configs, verbose=False)
    t0 = time.perf_counter()
    target = per * nw
    got = 0
    total_bytes = 0
    while got < target:
        idx, ts, pkt = reader.get()
        if pkt is not None:
            got += 1
            total_bytes += len(pkt)
    t1 = time.perf_counter()

    for p in procs:
        p.join()
    reader.close()
    for r in parents:
        r.close()
        r.unlink()
    return t1 - t0, got, total_bytes


def bench_queue_nw1r(n_total, nw, batched=False):
    per = n_total // nw
    q = mp.Queue(maxsize=QUEUE_MAXSIZE)
    bs = BATCH_SIZE if batched else None

    barrier = mp.Barrier(nw + 1)
    procs = []
    for k in range(nw):
        p = mp.Process(target=_queue_writer, args=(q, per, 100 + k, barrier, bs))
        p.start()
        procs.append(p)
    barrier.wait()

    t0 = time.perf_counter()
    target = per * nw
    got = 0
    total_bytes = 0
    if batched:
        while got < target:
            batch = q.get()
            got += len(batch)
            total_bytes += sum(len(p) for p in batch)
    else:
        while got < target:
            p = q.get()
            got += 1
            total_bytes += len(p)
    t1 = time.perf_counter()

    for p in procs:
        p.join()
    return t1 - t0, got, total_bytes


# ============================ REPORT ============================
def run_and_report(label, func, n_runs=RUNS, **kwargs):
    n = kwargs.get("n") or kwargs.get("n_total")
    times, bytes_list = [], []
    for _ in range(n_runs):
        t, got, tb = func(**kwargs)
        assert got == n, f"{label}: got={got} != {n}"
        times.append(t)
        bytes_list.append(tb)
    med_t = median(times)
    med_b = median(bytes_list)
    pps  = n / med_t
    mbps = (med_b / (1 << 20)) / med_t
    print(f"  {label:<40s} {med_t * 1000:8.1f} ms   "
          f"{pps / 1e6:6.3f} M pkt/s   {mbps:7.1f} MB/s")
    return med_t


def main():
    print(f"Paquets totaux par test : {N_PACKETS:,}")
    print(f"Taille paquets          : {PKT_MIN}-{PKT_MAX} octets (variable)")
    print(f"Cap ring                : {CAP_BYTES // 1024} Kio")
    print(f"Batch size              : {BATCH_SIZE}")
    print(f"Runs (médiane)          : {RUNS}")
    print(f"mp.Queue maxsize        : {QUEUE_MAXSIZE:,}")
    print(f"CPU count               : {os.cpu_count()}")
    print()

    print(f"=== 1 writer -> 1 reader ({N_PACKETS:,} paquets) ===")
    run_and_report("Ring (shared memory)", bench_ring_1w1r,
                   n=N_PACKETS, cap=CAP_BYTES)
    run_and_report("mp.Queue (1 par 1)", bench_queue_1w1r,
                   n=N_PACKETS, batched=False)
    run_and_report("mp.Queue (batch de 64)", bench_queue_1w1r,
                   n=N_PACKETS, batched=True)

    print()
    print(f"=== {N_WRITERS} writers -> 1 reader ({N_PACKETS:,} paquets) ===")
    run_and_report(f"Ring ({N_WRITERS} rings + MultiReader)", bench_ring_nw1r,
                   n_total=N_PACKETS, nw=N_WRITERS, cap=CAP_BYTES)
    run_and_report("mp.Queue (1 par 1)", bench_queue_nw1r,
                   n_total=N_PACKETS, nw=N_WRITERS, batched=False)
    run_and_report("mp.Queue (batch de 64)", bench_queue_nw1r,
                   n_total=N_PACKETS, nw=N_WRITERS, batched=True)


if __name__ == "__main__":
    main()