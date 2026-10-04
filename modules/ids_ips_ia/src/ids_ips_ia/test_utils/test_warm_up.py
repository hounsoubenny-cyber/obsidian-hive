#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test de Models.warm_up avec de VRAIES architectures (build_models, en petit) :

  1. EFFICACITÉ  : le 1er lot après "rechargement" est bien plus rapide après warm_up qu'à froid.
  2. PAS D'EFFET DE BORD : warm_up ne touche pas à `last_batch_error` (état partagé avec le consommateur).
  3. COEXISTENCE : préchauffer le NOUVEAU CNN n'évince pas le bottleneck de l'ANCIEN (cache par clé).
  4. INTERRUPTION : stop_event levé -> warm_up s'arrête, sans exception.

⚠️ Petits modèles (L=16, quelques features) : les durées absolues sont bien plus faibles qu'en prod ;
   c'est le RAPPORT froid/chaud qui compte. Mesure le 1er lot de ton vrai modèle pour le gain réel.

Lancer : python test_warm_up.py
"""
import sys, os, time, threading, importlib
from pathlib import Path
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

_SRC = Path(__file__).resolve().parents[2]
for p in (str(_SRC), str(_SRC.parent.parent.parent), str(_SRC.parent.parent / "modules_utils" / "src")):
    sys.path.insert(0, p)
os.environ.setdefault("IDS_ADMIN_USERNAME", "test"); os.environ.setdefault("IDS_ADMIN_PASSWORD", "Str0ng!Passw0rd#2026")
os.environ.setdefault("IDS_JWT_SECRET", "a" * 64)

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

M = importlib.import_module("ids_ips_ia.models.models")

L, F, P = 16, 12, 14            # longueur de séquence, features par pas, features par paquet
BATCH_PKT, BATCH_SEQ = 64, 8    # plus gros lot de paquets / de séquences attendus
rng = np.random.default_rng(0)
models = M.Models()


def make_mod():
    """Un jeu de modèles NEUF (nouveaux objets Keras, comme après un dill.load)."""
    ae_seq, cnn_seq, if_seq, lof_seq, ae_pkt, if_pkt, lof_pkt = models.build_models(
        n_pkt=L, n_seq_features=F, n_pkt_features=P, mode="fast")
    if_pkt = IsolationForest(n_estimators=20, random_state=0).fit(rng.normal(size=(200, P + 2)))
    if_seq = IsolationForest(n_estimators=20, random_state=0).fit(rng.normal(size=(200, 2 * L * F + 4)))
    return {
        "ae_pkt": ae_pkt, "ae_seq": ae_seq, "cnn_seq": cnn_seq, "if_pkt": if_pkt, "if_seq": if_seq,
        "scaler_pkt": StandardScaler().fit(rng.normal(size=(100, P))),
        "scaler_seq": StandardScaler().fit(rng.normal(size=(100, F))),
    }


def first_real_batch(mod):
    """Chemin d'inférence réel (mêmes appels que predict_*_batch côté TensorFlow). Retourne des ms."""
    x_pkt = rng.normal(size=(BATCH_PKT, P))                       # float64, comme scaler.transform
    x_seq = rng.normal(size=(BATCH_SEQ, L, F))
    t = time.perf_counter()
    M._run_bucketed(M._predict_ae_pkt, mod["ae_pkt"], x_pkt)
    mem = M._run_bucketed(M._predict_cnn_memory, models._get_cnn_bottleneck(mod["cnn_seq"]), x_seq)
    M._run_bucketed(M._predict_ae_seq, mod["ae_seq"], x_seq, mem)
    M._run_bucketed(M._predict_cnn_seq, mod["cnn_seq"], x_seq)
    return (time.perf_counter() - t) * 1000


# --- l'ancien modèle sert déjà (chaud) --------------------------------------------------------------------
old = make_mod()
first_real_batch(old)
old_bottleneck = models._get_cnn_bottleneck(old["cnn_seq"])
models.last_batch_error = {"stage": "packet", "type": "SENTINELLE"}      # erreur "réelle" à ne pas écraser

# --- 1) modèle neuf À FROID : le 1er lot paie la compilation -----------------------------------------------
cold_mod = make_mod()
cold_ms = first_real_batch(cold_mod)
steady_ms = min(first_real_batch(cold_mod) for _ in range(3))

# --- 2) modèle neuf PRÉCHAUFFÉ -----------------------------------------------------------------------------
warm_mod = make_mod()
info = models.warm_up(warm_mod, max_pkt_batch=BATCH_PKT, max_seq_batch=BATCH_SEQ)
warm_ms = first_real_batch(warm_mod)

print(f"warm_up : {info}")
print(f"1er lot à FROID      : {cold_ms:8.1f} ms")
print(f"1er lot PRÉCHAUFFÉ   : {warm_ms:8.1f} ms   (régime établi : {steady_ms:.1f} ms)")
assert not info["interrupted"], info
assert warm_ms < 0.5 * cold_ms, (warm_ms, cold_ms)
print("efficacité OK")

# --- 3) pas d'effet de bord / coexistence ------------------------------------------------------------------
assert models.last_batch_error == {"stage": "packet", "type": "SENTINELLE"}, models.last_batch_error
assert models._get_cnn_bottleneck(old["cnn_seq"]) is old_bottleneck, "l'ancien bottleneck a été évincé"
assert models._get_cnn_bottleneck(warm_mod["cnn_seq"]) is not old_bottleneck
print("pas d'effet de bord sur last_batch_error | cache bottleneck : ancien et nouveau coexistent OK")

# --- 4) interruption ---------------------------------------------------------------------------------------
ev = threading.Event(); ev.set()
info2 = models.warm_up(make_mod(), max_pkt_batch=BATCH_PKT, max_seq_batch=BATCH_SEQ, stop_event=ev)
assert info2["interrupted"] and info2["pkt_buckets"] == 0 and info2["seq_buckets"] == 0, info2
print("interruption par stop_event OK")
