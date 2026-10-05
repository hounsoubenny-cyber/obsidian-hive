#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 10:28:04 2026

@author: hounsousamuel
"""

"""
bench_ring.py : Benchmark comparatif Ring (SharedMemory) vs multiprocessing.Queue.
Trafic réseau réaliste (mix 64B - 1500B).
"""

import sys
import time
import random
import multiprocessing as mp

# Import de ton implémentation
try:
    from ring import Ring, cleanup_old
except ImportError:
    print("❌ Impossible d'importer Ring depuis ring.py. Assure-toi que les deux fichiers sont côte à côte.")
    sys.exit(1)


# =====================================================================
# 1. Génération de paquets réalistes (avant les tests pour ne pas fausser le CPU)
# =====================================================================
def generate_traffic(count: int) -> tuple[list[bytes], int]:
    """Génère un mix réaliste :
    - 40% petits paquets (SYN/ACK/DNS : 64 à 128 octets)
    - 40% gros paquets (MTU plein : 1400 à 1514 octets)
    - 20% paquets moyens (300 à 800 octets)
    """
    print(f"📦 Pré-génération de {count:,} paquets réalistes en RAM...")
    packets = []
    total_bytes = 0
    rng = random.Random(42)

    for i in range(count):
        r = rng.random()
        if r < 0.40:
            sz = rng.randint(64, 128)
        elif r < 0.80:
            sz = rng.randint(1400, 1514)
        else:
            sz = rng.randint(300, 800)
        
        # En-tête bidon de 4 octets + padding
        pkt = (i % 256).to_bytes(1, "little") * sz
        packets.append(pkt)
        total_bytes += sz

    print(f"   Terminé : {total_bytes / (1024 * 1024):.2f} Mo de données brutes.")
    return packets, total_bytes


# =====================================================================
# 2. Worker Ring
# =====================================================================
def ring_writer(name: str, cap: int, packets: list[bytes], start_ev: mp.Event):
    ring = Ring(name=name, cap=cap, create=False, role="W")
    start_ev.wait()
    t0 = time.time()
    for i, pkt in enumerate(packets):
        while not ring.put(pkt, ts=t0 + i):
            pass  # Attente active si buffer plein
    ring.close()

def ring_reader(name: str, cap: int, count: int, start_ev: mp.Event, res_q: mp.Queue):
    ring = Ring(name=name, cap=cap, create=False, role="R")
    received = 0
    start_ev.wait()
    t_start = time.perf_counter()
    while received < count:
        ts, pkt = ring.get()
        if ts is not None:
            received += 1
    t_end = time.perf_counter()
    ring.close()
    res_q.put(t_end - t_start)


# =====================================================================
# 3. Worker multiprocessing.Queue (1 à 1)
# =====================================================================
def mp_queue_writer(q: mp.Queue, packets: list[bytes], start_ev: mp.Event):
    start_ev.wait()
    t0 = time.time()
    for i, pkt in enumerate(packets):
        q.put((t0 + i, pkt))

def mp_queue_reader(q: mp.Queue, count: int, start_ev: mp.Event, res_q: mp.Queue):
    received = 0
    start_ev.wait()
    t_start = time.perf_counter()
    while received < count:
        item = q.get()
        received += 1
    t_end = time.perf_counter()
    res_q.put(t_end - t_start)


# =====================================================================
# 4. Worker multiprocessing.Queue (Batch de N)
# =====================================================================
def mp_batch_writer(q: mp.Queue, packets: list[bytes], batch_size: int, start_ev: mp.Event):
    start_ev.wait()
    t0 = time.time()
    batch = []
    for i, pkt in enumerate(packets):
        batch.append((t0 + i, pkt))
        if len(batch) >= batch_size:
            q.put(batch)
            batch = []
    if batch:
        q.put(batch)

def mp_batch_reader(q: mp.Queue, count: int, start_ev: mp.Event, res_q: mp.Queue):
    received = 0
    start_ev.wait()
    t_start = time.perf_counter()
    while received < count:
        batch = q.get()
        received += len(batch)
    t_end = time.perf_counter()
    res_q.put(t_end - t_start)


# =====================================================================
# Exécution des Benchmarks
# =====================================================================
def run_bench():
    N_PACKETS = 300_000         # 300k paquets (environ 250 Mo de données brutes)
    RING_CAP = 32 * 1024 * 1024 # 32 Mo de buffer circulaire
    SHM_NAME = "bench_shm_test"

    packets, total_bytes = generate_traffic(N_PACKETS)
    mb_total = total_bytes / (1024 * 1024)

    results = []

    print("\n" + "=" * 70)
    print(f"🚀 LANCEMENT DU BENCHMARK : {N_PACKETS:,} paquets ({mb_total:.1f} Mo)")
    print("=" * 70)

    # --- TEST 1 : TON RING (SharedMemory) ---
    print("\n▶ [1/3] Test de ton RING (SharedMemory sans lock)...")
    cleanup_old(SHM_NAME)
    parent_ring = Ring(name=SHM_NAME, cap=RING_CAP, create=True)
    res_q = mp.Queue()
    start_ev = mp.Event()

    p_w = mp.Process(target=ring_writer, args=(SHM_NAME, RING_CAP, packets, start_ev))
    p_r = mp.Process(target=ring_reader, args=(SHM_NAME, RING_CAP, N_PACKETS, start_ev, res_q))
    p_w.start(); p_r.start()
    time.sleep(0.5)
    start_ev.set()

    duration_ring = res_q.get()
    p_w.join(); p_r.join()
    parent_ring.close(); parent_ring.unlink()
    results.append(("Ring (SharedMemory)", duration_ring))

    # --- TEST 2 : mp.Queue (1 à 1) ---
    print("▶ [2/3] Test de multiprocessing.Queue (1 par 1)...")
    q_single = mp.Queue(maxsize=50_000)
    start_ev = mp.Event()

    p_w = mp.Process(target=mp_queue_writer, args=(q_single, packets, start_ev))
    p_r = mp.Process(target=mp_queue_reader, args=(q_single, N_PACKETS, start_ev, res_q))
    p_w.start(); p_r.start()
    time.sleep(0.5)
    start_ev.set()

    duration_mp = res_q.get()
    p_w.join(); p_r.join()
    results.append(("mp.Queue (1 par 1)", duration_mp))

    # --- TEST 3 : mp.Queue (Batch de 100) ---
    print("▶ [3/3] Test de multiprocessing.Queue (Batch de 100)...")
    q_batch = mp.Queue(maxsize=1_000)
    start_ev = mp.Event()

    p_w = mp.Process(target=mp_batch_writer, args=(q_batch, packets, 100, start_ev))
    p_r = mp.Process(target=mp_batch_reader, args=(q_batch, N_PACKETS, start_ev, res_q))
    p_w.start(); p_r.start()
    time.sleep(0.5)
    start_ev.set()

    duration_batch = res_q.get()
    p_w.join(); p_r.join()
    results.append(("mp.Queue (Batch 100)", duration_batch))

    # =====================================================================
    # Tableau récapitulatif
    # =====================================================================
    print("\n" + "=" * 75)
    print(f"{'MÉTHODE':<25} | {'TEMPS (s)':<10} | {'DÉBIT (Mo/s)':<15} | {'K-PAQUETS/s':<12}")
    print("-" * 75)

    base_time = None
    for name, dur in results:
        kpkts = (N_PACKETS / dur) / 1000.0
        mbs = mb_total / dur
        print(f"{name:<25} | {dur:<10.3f} | {mbs:<15.2f} | {kpkts:<12.1f}")

    print("=" * 75)


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    run_bench()