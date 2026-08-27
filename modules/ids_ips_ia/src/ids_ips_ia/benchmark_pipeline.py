#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Profiling complet du pipeline IDS/IPS ShieldAI / Obsidian Hive.
Mesure chaque étage indépendamment : capture, extraction features,
inférence ML, et réaction nftables.

Usage:
    python benchmark_pipeline.py --model /chemin/vers/model.pkl
    sudo python benchmark_pipeline.py --capture --iface wlp1s0   # pour la capture seule
"""

import os
import sys
import time
import socket
import argparse
import statistics
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import dpkt
import numpy as np

# ============================================================================
# UTILITAIRES
# ============================================================================

def create_fake_packet():
    eth = dpkt.ethernet.Ethernet()
    eth.src = b'\x00\x11\x22\x33\x44\x55'
    eth.dst = b'\xff\xff\xff\xff\xff\xff'
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.src = socket.inet_aton("192.168.1.100")
    ip.dst = socket.inet_aton("8.8.8.8")
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.ttl = 64

    tcp = dpkt.tcp.TCP()
    tcp.sport = 54321
    tcp.dport = 80
    tcp.flags = dpkt.tcp.TH_SYN
    tcp.seq = 123456789
    tcp.ack = 0
    tcp.win = 65535
    tcp.data = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

    ip.data = tcp
    eth.data = ip
    eth.ts = time.time()
    return eth


def report(name, times_s, unit="ops"):
    """Affiche un rapport stat propre pour une série de mesures (en secondes)."""
    times_s = np.array(times_s)
    total = times_s.sum()
    n = len(times_s)
    rate = n / total if total > 0 else 0
    mean_ms = times_s.mean() * 1000
    p50_ms = np.percentile(times_s, 50) * 1000
    p95_ms = np.percentile(times_s, 95) * 1000
    p99_ms = np.percentile(times_s, 99) * 1000

    print(f"\n{'='*70}")
    print(f"📊 {name}")
    print(f"{'='*70}")
    print(f"   Itérations       : {n:,}")
    print(f"   Débit            : {rate:,.0f} {unit}/sec")
    print(f"   Latence moyenne  : {mean_ms:.4f} ms")
    print(f"   p50              : {p50_ms:.4f} ms")
    print(f"   p95              : {p95_ms:.4f} ms")
    print(f"   p99              : {p99_ms:.4f} ms")
    return {"name": name, "rate": rate, "mean_ms": mean_ms, "p50_ms": p50_ms,
             "p95_ms": p95_ms, "p99_ms": p99_ms, "n": n}


# ============================================================================
# ÉTAGE 1 : FEATURE EXTRACTION (paquet unique)
# ============================================================================

def bench_feature_extraction(n_iter=20000):
    from ids_ips_ia.core.features_extractor import FeatureExtractor

    pkt = create_fake_packet()
    extractor = FeatureExtractor()
    print(f"\n🔧 Cython actif : {extractor._USE_CYTHON}")

    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        _ = extractor.extract_pack_features(pkt)
        times.append(time.perf_counter() - t0)

    return report("Feature Extraction (extract_pack_features)", times, unit="pkt")


def bench_seq_extraction(n_iter=2000, seq_length=60):
    from ids_ips_ia.core.features_extractor import FeatureExtractor

    extractor = FeatureExtractor()
    pkt = create_fake_packet()
    features = extractor.extract_pack_features(pkt)
    seq = np.array([features for _ in range(seq_length)])

    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        _ = extractor.extract_seq_features(seq)
        times.append(time.perf_counter() - t0)

    return report("Sequence Feature Extraction (extract_seq_features)", times, unit="seq")


# ============================================================================
# ÉTAGE 2 : ML INFERENCE (charge un vrai modèle .pkl)
# ============================================================================

def bench_ml_packet(model_path, n_iter=500):
    import dill
    from ids_ips_ia.models.models import Models
    from ids_ips_ia.core.features_extractor import FeatureExtractor
    from ids_ips_ia.ids_ips_utils.loader import load

    print(f"\n📦 Chargement du modèle : {model_path}")
    try:
        mod = dill.loads(load(model_path))
    except Exception:
        with open(model_path, "rb") as f:
            mod = dill.load(f)

    extractor = FeatureExtractor()
    pkt = create_fake_packet()
    pkt_fea = extractor.extract_pack_features(pkt)
    models = Models()

    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        _ = models.predict_packet(
            mod["ae_pkt"], mod["if_pkt"], mod["lof_pkt"], mod["scaler_pkt"],
            pkt_fea, method="decision_function", how="any"
        )
        times.append(time.perf_counter() - t0)

    return report("ML Inference — predict_packet (decision_function)", times, unit="pred")


def bench_ml_sequence(model_path, n_iter=200, seq_length=60):
    import dill
    from ids_ips_ia.models.models import Models
    from ids_ips_ia.core.features_extractor import FeatureExtractor
    from ids_ips_ia.ids_ips_utils.loader import load

    try:
        mod = dill.loads(load(model_path))
    except Exception:
        with open(model_path, "rb") as f:
            mod = dill.load(f)

    extractor = FeatureExtractor()
    pkt = create_fake_packet()
    pkt_fea = extractor.extract_pack_features(pkt)
    seq = np.array([pkt_fea for _ in range(seq_length)])
    models = Models()

    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        _ = models.predict_sequence(
            mod["ae_seq"], mod["cnn_seq"], mod["if_seq"], mod["lof_seq"],
            mod["scaler_seq"], seq, method="decision_function", how="any"
        )
        times.append(time.perf_counter() - t0)

    return report("ML Inference — predict_sequence (decision_function)", times, unit="pred")


# ============================================================================
# ÉTAGE 3 : NFTABLES (coût réel d'un subprocess de blocage)
# ============================================================================

def bench_nftables(n_iter=20):
    import subprocess

    print("\n⚠️  Ce test exécute de vraies commandes nft (lecture seule, 'nft list ruleset')")
    times = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, check=False)
        times.append(time.perf_counter() - t0)

    return report("nftables subprocess (nft list ruleset)", times, unit="op")


# ============================================================================
# ÉTAGE 4 : CAPTURE AF_PACKET (nécessite root)
# ============================================================================

def bench_capture(iface, duration=10, batch_size=64):
    print(f"\n📡 Capture AF_PACKET sur {iface} pendant {duration}s (root requis)...")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.settimeout(0.04)

    packets = 0
    bytes_total = 0
    start = time.perf_counter()
    end_time = start + duration

    while time.perf_counter() < end_time:
        try:
            raw = sock.recv(65535)
            packets += 1
            bytes_total += len(raw)
        except socket.timeout:
            continue

    elapsed = time.perf_counter() - start
    sock.close()

    print(f"\n{'='*70}")
    print(f"📊 Capture AF_PACKET réelle ({iface})")
    print(f"{'='*70}")
    print(f"   Paquets capturés : {packets:,}")
    print(f"   Débit            : {packets/elapsed:,.0f} pkt/sec")
    print(f"   Débit data       : {bytes_total*8/elapsed/1e6:.2f} Mbps")
    return {"name": "capture", "rate": packets/elapsed if elapsed > 0 else 0}


# ============================================================================
# RAPPORT FINAL — projection du pipeline complet
# ============================================================================

def final_projection(results):
    print(f"\n{'='*70}")
    print("🎯 PROJECTION DU PIPELINE COMPLET")
    print(f"{'='*70}")
    print("""
ATTENTION : ces chiffres sont des MAXIMUMS THÉORIQUES par étage isolé.
Le débit réel global = le MINIMUM des étages, car ils sont enchaînés
séquentiellement pour chaque paquet anormal (capture → features → ML → nft).
""")

    rates = {r["name"]: r["rate"] for r in results if r}
    if rates:
        bottleneck = min(rates.items(), key=lambda x: x[1])
        print(f"   🔴 Goulot d'étranglement : {bottleneck[0]}")
        print(f"   🔴 Débit limite          : {bottleneck[1]:,.0f} /sec")
        print()
        for name, rate in sorted(rates.items(), key=lambda x: x[1]):
            bar = "█" * min(50, int(rate / max(rates.values()) * 50))
            print(f"   {name[:40]:40s} {rate:>12,.0f}/s  {bar}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark pipeline IDS/IPS")
    parser.add_argument("--model", type=str, help="Chemin vers un modèle .pkl entraîné")
    parser.add_argument("--capture", action="store_true", help="Lancer le test de capture (root requis)")
    parser.add_argument("--iface", type=str, default="wlp1s0", help="Interface pour le test de capture")
    parser.add_argument("--duration", type=int, default=10, help="Durée du test de capture (s)")
    parser.add_argument("--skip-nft", action="store_true", help="Skip le test nftables")
    args = parser.parse_args()

    results = []

    print("=" * 70)
    print("🔬 BENCHMARK PIPELINE IDS/IPS — OBSIDIAN HIVE")
    print("=" * 70)

    # Feature extraction (toujours testable, pas besoin de root ni modèle)
    results.append(bench_feature_extraction())
    results.append(bench_seq_extraction())

    # ML inference (besoin d'un modèle réel)
    if args.model and os.path.exists(args.model):
        results.append(bench_ml_packet(args.model))
        results.append(bench_ml_sequence(args.model))
    else:
        print("\n⚠️  Pas de modèle fourni (--model) → skip des tests ML")

    # nftables
    if not args.skip_nft:
        try:
            results.append(bench_nftables())
        except Exception as e:
            print(f"\n⚠️  Test nftables échoué (besoin de droits ?) : {e}")

    # Capture réseau (root requis, optionnel)
    if args.capture:
        if os.geteuid() != 0:
            print("\n❌ --capture nécessite root (sudo python benchmark_pipeline.py --capture ...)")
        else:
            results.append(bench_capture(args.iface, args.duration))

    final_projection(results)

    print("\n✅ Benchmark terminé")