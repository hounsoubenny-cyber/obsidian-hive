#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 23:23:28 2026

@author: hounsousamuel
"""

"""
Benchmark de predict_packet : latence réelle par paquet, avec/sans to_thread.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import time
import statistics
import asyncio
import dill
import joblib

from ids_ips_ia.models.models import Models
from ids_ips_ia.core.features_extractor import FeatureExtractor
from ids_ips_ia.ids_ips_utils.loader import load

MODEL_PATH = "/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/models/data/models/model_2026-07-03T21:50:36.964201.pkl"      # ton fichier préfit
PACKETS_PATH = "/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/core/data/capture_last.pkl"   # ta sortie de collect_and_process / capture backup
N_SAMPLES = 100000   # nombre de paquets à mesurer (assez pour une stat stable, pas trop pour rester rapide)
mod = None

def load_everything():
    global mod
    
    mod = dill.loads(load(MODEL_PATH))
    packets = joblib.load(PACKETS_PATH)
    print(f"📦 Modèle chargé : {list(mod.keys())}")
    print(f"📦 {len(packets)} paquets chargés")
    return mod, packets

def extract_features(packets, extractor, n):
    feats = []
    for pkt in packets[:n]:
        try:
            feats.append(extractor.extract_pack_features(pkt))
        except Exception as e:
            print(f"⚠️ Paquet ignoré (extraction) : {e}")
    return feats

def bench_sync(models_instance, mod, feats, method="decision_function"):
    """Mesure predict_packet en direct, synchrone, sans event loop."""
    ae_pkt, if_pkt, lof_pkt, scaler = mod["ae_pkt"], mod["if_pkt"], mod["lof_pkt"], mod["scaler_pkt"]

    # 🔥 Warm-up : le premier appel compile le graphe tf.function (jit_compile=True)
    # C'est un coût "one-shot", pas représentatif du régime de croisière — on l'exclut
    models_instance.predict_packet(ae_pkt, if_pkt, lof_pkt, scaler, feats[0], method=method)

    latencies = []
    for f in feats[1:]:
        t0 = time.perf_counter()
        models_instance.predict_packet(ae_pkt, if_pkt, lof_pkt, scaler, f, method=method)
        latencies.append(time.perf_counter() - t0)

    return latencies

async def bench_async(models_instance, mod, feats, method="decision_function"):
    """Mesure apredict_packet (via asyncio.to_thread), pour voir l'overhead du dispatch thread."""
    ae_pkt, if_pkt, lof_pkt, scaler = mod["ae_pkt"], mod["if_pkt"], mod["lof_pkt"], mod["scaler_pkt"]

    await models_instance.apredict_packet(ae_pkt, if_pkt, lof_pkt, scaler, feats[0], method=method)

    latencies = []
    for f in feats[1:]:
        t0 = time.perf_counter()
        await models_instance.apredict_packet(ae_pkt, if_pkt, lof_pkt, scaler, f, method=method)
        latencies.append(time.perf_counter() - t0)

    return latencies

def print_stats(latencies, label):
    latencies_ms = [l * 1000 for l in latencies]
    latencies_ms.sort()
    n = len(latencies_ms)
    mean = statistics.mean(latencies_ms)
    median = statistics.median(latencies_ms)
    p95 = latencies_ms[int(n * 0.95)]
    p99 = latencies_ms[int(n * 0.99)]
    throughput = 1000 / mean  # paquets/seconde, en traitement séquentiel pur

    print(f"\n📊 {label} (n={n})")
    print(f"   Moyenne     : {mean:.2f} ms")
    print(f"   Médiane     : {median:.2f} ms")
    print(f"   P95         : {p95:.2f} ms")
    print(f"   P99         : {p99:.2f} ms")
    print(f"   Débit théorique max (séquentiel) : ~{throughput:.0f} paquets/s")

def main():
    import nest_asyncio
    nest_asyncio.apply()
    mod, packets = load_everything()
    extractor = FeatureExtractor()
    feats = extract_features(packets, extractor, N_SAMPLES)
    print(f"✅ {len(feats)} vecteurs de features extraits\n")

    models_instance = Models()

    print("⏱️  Benchmark SYNCHRONE (predict_packet direct)...")
    lat_sync = bench_sync(models_instance, mod, feats)
    print_stats(lat_sync, "SYNC — predict_packet")

    print("\n⏱️  Benchmark ASYNC (apredict_packet via to_thread)...")
    lat_async = asyncio.run(bench_async(models_instance, mod, feats))
    print_stats(lat_async, "ASYNC — apredict_packet. (to_thread)")

    overhead = statistics.mean(lat_async) - statistics.mean(lat_sync)
    print(f"\n🔍 Overhead moyen du dispatch to_thread : {overhead*1000:.3f} ms/appel")

if __name__ == "__main__":
    main()