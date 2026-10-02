#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 04:32:28 2026

@author: hounsousamuel
"""

"""Route /stats : Capture.metrics (maths), detector.stats (compteurs réels après une détection), agrégateur du service."""
import sys, os, asyncio, runpy, tempfile, time, traceback, threading
from pathlib import Path
from types import SimpleNamespace
import numpy as np
from unittest.mock import MagicMock
sys.modules.setdefault("pcap", MagicMock())
try:
    ns = runpy.run_path(str(Path(__file__).with_name("test_detect_loop.py")), run_name="not_main")
    from ids_ips_ia.main import services as svc
    from ids_ips_ia.core.capture import Capture
    from ids_ips_ia.detection.anomaly_logger import AnomalyLogger
    D, make_detector = ns["D"], ns["make_detector"]

    # --- Capture.metrics : mêmes formules que summary()
    cap = Capture.__new__(Capture)
    cap._stats_lock = threading.Lock(); cap._t0 = time.monotonic() - 10.0
    cap._stats = dict(recv=900, kept=800, ignored=50, filtered=50, dropped=50, errors=0, k_seen=1000, k_drops=50)
    m = cap.metrics()
    assert m["lost_total"] == 100 and m["loss_pct"] == 10.0 and m["kernel_loss_pct"] == 5.0 and m["app_loss_pct"] == 5.0, m
    assert 9.9 < m["elapsed_s"] < 10.5 and 75 < m["kept_per_s"] < 82 and m["kept"] == 800
    cap._stats.update(k_seen=0, k_drops=0)                       # sans stats noyau : seen = recv + dropped
    assert cap.metrics()["loss_pct"] == round(100 * 50 / 950, 3)
    cap._t0 = None; assert cap.metrics()["kept_per_s"] == 0.0     # capture pas démarrée : pas de division par 0
    print("Capture.metrics : pertes / débit / cas limites  OK")

    # --- detector.stats après une vraie détection (500 paquets, lots de 256)
    async def run():
        D.DETECT_BATCH_SIZE = 256; D.MODEL_ERROR_THRESHOLD = 5
        d = make_detector(500, {100})
        async def stopper():
            while not d.q.empty(): await asyncio.sleep(0.01)
            await asyncio.sleep(0.3); d.stop_event.set()
        t = asyncio.create_task(stopper())
        await d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False); await t
        return d
    det = asyncio.run(run())
    st = det.stats()
    assert st["packets_processed"] == 500 and st["batches"] == 2 and st["last_batch_size"] == 244, st
    assert st["avg_batch_size"] == 250.0 and st["sequences_evaluated"] == 45, st
    assert st["queue"] == {"size": 0, "max": None, "fill_pct": None}, st["queue"]
    assert st["inference"]["packet"] == {"consecutive_failures": 0, "failing": False} and st["system_alerts_open"] == 0
    assert st["config"]["seq_stride"] == D.SEQ_STRIDE and st["uptime_s"] > 0
    print("detector.stats : paquets/lots/taille moyenne/séquences/file  OK ->", {k: st[k] for k in ("packets_processed", "batches", "avg_batch_size", "sequences_evaluated")})

    # --- service : agrégation + robustesse
    tmp = tempfile.mkdtemp(); lg = AnomalyLogger(tmp, "anomalies", max_per_file=100, batch_size=10, flush_interval=0.2)
    lg.log(np.random.rand(60, 4), -1, "IA"); lg.close()
    det.anomaly_logger = lg; det.skipper = SimpleNamespace(stats=lambda: {"checked": 10, "skipped": 2, "skip_ratio": 0.2, "skipped_per_s": 0.1})
    cap._t0 = time.monotonic() - 5
    ids = SimpleNamespace(detector=det, Capture=cap, session_id="sess-1")
    r = asyncio.run(svc._do_get_stats(ids))
    assert r["running"] and r["session_id"] == "sess-1" and r["capture"]["kept"] == 800
    assert r["detector"]["packets_processed"] == 500 and r["blocked_skipper"]["skipped"] == 2
    assert r["anomaly_logger"]["logged"] == 1 and "/" not in str(r["anomaly_logger"]["file"]), r["anomaly_logger"]   # basename seulement
    det.skipper = SimpleNamespace(stats=lambda: 1 / 0)                  # un composant cassé ne casse pas la route
    r = asyncio.run(svc._do_get_stats(ids)); assert "ZeroDivisionError" in r["blocked_skipper"]["error"] and r["detector"]["batches"] == 2
    assert asyncio.run(svc._do_get_stats(None))["running"] is False
    r = asyncio.run(svc._do_get_stats(SimpleNamespace(detector=None, Capture=None, session_id="s"))); assert r["running"] is False and r["capture"] is None
    h = asyncio.run(svc._do_help())["endpoints"]["monitoring_bearer"]
    assert {e["path"] for e in h} == {"/api/stats", "/api/system-alerts", "/api/anomaly-files"}
    print("service /stats : agrégation, basename, composant cassé isolé, non démarré, /help à jour  OK")
except BaseException:
    print("TEST ECHEC :\n" + traceback.format_exc()); raise SystemExit(1)
