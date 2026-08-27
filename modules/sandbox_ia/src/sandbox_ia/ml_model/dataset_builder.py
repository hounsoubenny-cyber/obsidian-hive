#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun  6 20:01:00 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import numpy as np
from sklearn.preprocessing import RobustScaler

from sandbox_ia.ml_model.features_extractor_v2 import FeatureExtractor, EXCLUDED
from sandbox_ia.ml_model.vocab import encode
from sandbox_ia.tracers.fs_monitor import SandBoxQueue

def build_dataset_from_events(
    events: list,
    label: int,
    extractor: "FeatureExtractor",
    seq_len: int = 100,
    reset: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Transforme une liste d'events sandbox en arrays numpy pour SandBoxDataset.

    Applique le FeatureExtractor sur chaque event pour obtenir un vecteur
    de features, puis découpe la séquence en fenêtres glissantes de seq_len.
    Si la séquence est trop courte, padding à droite avec des zéros.

    Parameters
    ----------
    events : list[FSEvent | SyscallEvent]
        Events bruts d'une session sandbox dans l'ordre chronologique.
    label : int
        0 = normal, 1 = malveillant.
    extractor : FeatureExtractor
        Extracteur de features stateful. Reset automatique si reset=True.
    seq_len : int
        Longueur de chaque fenêtre. 100 par défaut.
    reset : bool
        Si True, reset la fenêtre glissante avant extraction.
        Mettre False si tu veux continuer une session existante.

    Returns
    -------
    tuple[np.ndarray, np.ndarray, np.ndarray]
        X_seq  : (n_seq, seq_len, n_numeric_features) features numériques
        X_ebd  : (n_seq, seq_len) indices syscall pour nn.Embedding
        y      : (n_seq,) labels répétés
    """
    if reset:
        extractor.reset()

    feature_names = extractor.get_feature_names()
    event_list = [extractor.extract(event) for event in events]

    # Extraire syscall séparément AVANT de construire X
    syscall_list = [encode(event["syscall"]) for event in event_list]

    # Construire X sans les colonnes exclues (syscall, timestamp, ...)
    feature_names_no_syscall = [f for f in feature_names if f not in EXCLUDED]
    event_list_num = [[event[f] for f in feature_names_no_syscall] for event in event_list]

    X = np.array(event_list_num, dtype=np.float32)
    X_syscall = np.array(syscall_list, dtype=np.int32)  # (n_events,)

    # Compression log signée de "retval" : pour les syscalls qui renvoient
    # une adresse mémoire brute (mmap, brk, mmap2...), la magnitude explose
    # (~1e14) et ne généralise pas (adresses ~aléatoires via ASLR).
    # sign(x) * log1p(|x|) écrase l'échelle tout en gardant signe + ordre relatif.
    if "retval" in feature_names_no_syscall:
        retval_idx = feature_names_no_syscall.index("retval")
        retval_col = X[:, retval_idx]
        X[:, retval_idx] = np.sign(retval_col) * np.log1p(np.abs(retval_col))

    n_seq = X.shape[0] - seq_len + 1
    if n_seq <= 0:
        pad_size = seq_len - X.shape[0]
        X = np.concatenate([X, np.zeros((pad_size, X.shape[1]), dtype=np.float32)], axis=0)
        X_syscall = np.concatenate([X_syscall, np.zeros(pad_size, dtype=np.int32)], axis=0)
        n_seq = 1

    X = np.nan_to_num(X, neginf=0)

    X_seq = np.array([X[i: i + seq_len] for i in range(n_seq)])         # (n_seq, seq_len, n_features)
    X_ebd = np.array([X_syscall[i: i + seq_len] for i in range(n_seq)]) # (n_seq, seq_len)
    y = np.repeat(label, n_seq).astype(np.int32)

    return X_seq, X_ebd, y

class RealtimeProcessor:
    def __init__(self, queue: SandBoxQueue):
        self.queue = queue

if __name__ == "__main__":
    def test():
        from datetime import datetime
        from sandbox_ia.tracers.syscall_tracer import SyscallEvent
        from sandbox_ia.tracers.fs_monitor import FSEvent
    
        print("\n" + "="*60)
        print("🧪 TEST build_dataset_from_events")
        print("="*60)
    
        extractor = FeatureExtractor(window_size=20)
    
        def make_syscall(syscall, args="", family="file", score=10):
            return SyscallEvent(
                timestamp_date=datetime.utcnow(),
                timestamp_str="12:34:56.000000",
                pid=None, syscall=syscall, args_raw=args,
                retval=0, duration=0.0001,
                family=family, threat_score=score, is_error=False,
            )
    
        def make_fs(path, event_type="created", canary=False, score=10):
            return FSEvent(
                timestamp_date=datetime.utcnow(),
                timestamp_time=datetime.utcnow().timestamp(),
                event_type=event_type, path=path,
                src_path=path, dest_path="",
                is_directory=False, is_canary=canary,
                is_suspicious=False, threat_score=score,
            )
    
        # ── Test 1 : séquence normale → padding ──
        print("\n📌 TEST 1 — séquence courte (50 events) → padding à droite")
        events_short = [make_syscall("openat", "/etc/passwd") for _ in range(50)]
        X, X_ebd, y = build_dataset_from_events(events_short, label=0, extractor=extractor, seq_len=100)
        assert X.shape == (1, 100, X.shape[2]), f"Shape X incorrect: {X.shape}"
        assert X_ebd.shape == (1, 100), f"Shape X_ebd incorrect: {X_ebd.shape}"
        assert y.shape == (1,) and y[0] == 0
        print(f"   X.shape    : {X.shape}")
        print(f"   X_ebd.shape: {X_ebd.shape}")
        print(f"   y          : {y}")
        print("   ✅ OK")
    
        # ── Test 2 : séquence longue → sliding window ──
        print("\n📌 TEST 2 — séquence longue (250 events) → 151 fenêtres")
        events_long = [make_syscall("execve", "/bin/bash", "process", 25) for _ in range(250)]
        X2, X_ebd2, y2 = build_dataset_from_events(events_long, label=1, extractor=extractor, seq_len=100)
        expected_n_seq = 250 - 100 + 1  # 151
        assert X2.shape[0] == expected_n_seq, f"n_seq incorrect: {X2.shape[0]} vs {expected_n_seq}"
        assert X_ebd2.shape == (expected_n_seq, 100)
        assert y2.shape == (expected_n_seq,) and y2[0] == 1
        print(f"   X.shape    : {X2.shape}")
        print(f"   X_ebd.shape: {X_ebd2.shape}")
        print(f"   n_seq      : {X2.shape[0]} (attendu {expected_n_seq})")
        print("   ✅ OK")
    
        # ── Test 3 : séquence exacte → 1 fenêtre ──
        print("\n📌 TEST 3 — séquence exacte (100 events) → 1 fenêtre")
        events_exact = [make_syscall("connect", "AF_INET", "network", 20) for _ in range(100)]
        X3, X_ebd3, y3 = build_dataset_from_events(events_exact, label=1, extractor=extractor, seq_len=100)
        assert X3.shape[0] == 1
        print(f"   X.shape    : {X3.shape}")
        print("   ✅ OK")
    
        # ── Test 4 : mix FSEvent + SyscallEvent ──
        print("\n📌 TEST 4 — mix FSEvent + SyscallEvent")
        events_mix = []
        for i in range(60):
            if i % 3 == 0:
                events_mix.append(make_fs("/etc/shadow", "opened", canary=True, score=40))
            else:
                events_mix.append(make_syscall("openat", "/etc/shadow", "file", 10))
        X4, X_ebd4, y4 = build_dataset_from_events(events_mix, label=1, extractor=extractor, seq_len=100)
        assert X4.shape[0] == 1  # padding
        print(f"   X.shape    : {X4.shape}")
        print("   ✅ OK")
    
        # ── Test 5 : reset=False ──
        print("\n📌 TEST 5 — reset=False, contexte conservé")
        events_a = [make_syscall("read", "", "file", 2) for _ in range(30)]
        events_b = [make_syscall("write", "", "file", 5) for _ in range(30)]
        build_dataset_from_events(events_a, label=0, extractor=extractor, reset=True)
        X5, _, _ = build_dataset_from_events(events_b, label=0, extractor=extractor, reset=False)
        print(f"   X.shape    : {X5.shape}")
        print("   ✅ OK — contexte conservé entre sessions")
    
        print("\n" + "="*60)
        print("🎉 TOUS LES TESTS PASSÉS")
        print("="*60)
    
    test()
    
    
    
    
    