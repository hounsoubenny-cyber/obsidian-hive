#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 04:06:21 2026

@author: hounsousamuel
"""

"""Routes /system-alerts et /anomaly-files : liste, contenu paginé, rejet des noms piégés. (services appelés directement)"""
import sys, os, asyncio, runpy, tempfile, traceback
from pathlib import Path
from types import SimpleNamespace
import numpy as np
from unittest.mock import MagicMock
sys.modules.setdefault("pcap", MagicMock())   # binding libpcap : inutile ici (pas de capture réelle)
try:
    ns = runpy.run_path(str(Path(__file__).with_name("test_detect_loop.py")), run_name="not_main")  # monte les stubs / sys.path
    from fastapi import HTTPException
    from ids_ips_ia.main import services as svc
    from ids_ips_ia.detection.anomaly_logger import AnomalyLogger
    D = ns["D"]

    tmp = tempfile.mkdtemp()
    lg = AnomalyLogger(tmp, "anomalies", max_per_file=100, batch_size=10, flush_interval=0.2)
    for k in range(250):
        a = np.random.rand(60, 8); a[0, 0] = k
        assert lg.log(a, -1, "IA")
    lg.close()
    open(os.path.join(tmp, "secret.txt"), "w").write("nope")            # fichier hors motif
    det = ns["make_detector"](0, set()); det.anomaly_logger = lg
    ids = SimpleNamespace(detector=det)
    run = asyncio.run

    r = run(svc._do_get_anomaly_files(ids, None, 0, 100, False))
    assert [f["name"] for f in r["files"]] == ["anomalies_0.pkl", "anomalies_1.pkl", "anomalies_2.pkl"], r   # secret.txt exclu
    r = run(svc._do_get_anomaly_files(ids, "anomalies_0.pkl", 0, 5, False))
    assert r["total"] == 100 and len(r["entries"]) == 5 and "features" not in r["entries"][0]
    assert r["entries"][0]["features_shape"] == [60, 8] and r["entries"][2]["index"] == 2
    r = run(svc._do_get_anomaly_files(ids, "anomalies_2.pkl", 40, 100, True))      # dernier fichier : 50 entrées
    assert r["total"] == 50 and len(r["entries"]) == 10 and r["limit"] == 50      # limit borné à 50 avec features
    assert isinstance(r["entries"][0]["features"], list) and len(r["entries"][0]["features"]) == 60
    for bad in ("../secret.txt", "/etc/passwd", "anomalies_1.pkl/../../x", "secret.txt", "anomalies_x.pkl", "..%2f..%2fetc"):
        try:
            run(svc._do_get_anomaly_files(ids, bad, 0, 5, False)); raise AssertionError(f"accepté : {bad}")
        except HTTPException as e:
            assert e.status_code == 400, (bad, e.status_code)
    try:
        run(svc._do_get_anomaly_files(ids, "anomalies_9.pkl", 0, 5, False)); raise AssertionError("404 attendu")
    except HTTPException as e:
        assert e.status_code == 404
    r = run(svc._do_get_anomaly_files(None, None, 0, 5, False)); assert r["files"] == []
    print("anomaly-files : liste, pagination, features optionnelles, noms piégés -> 400, absent -> 404  OK")

    # system-alerts
    det.system_alerts["a"] = {"id": "a", "status": "open"}; det.system_alerts["b"] = {"id": "b", "status": "resolved"}
    r = run(svc._do_get_system_alerts(ids, 10, None)); assert r["total"] == 2 and r["open"] == 1
    r = run(svc._do_get_system_alerts(ids, 10, "resolved")); assert [a["id"] for a in r["system_alerts"]] == ["b"]
    try:
        run(svc._do_get_system_alerts(ids, 10, "nimporte")); raise AssertionError("400 attendu")
    except HTTPException as e:
        assert e.status_code == 400
    print("system-alerts : liste, filtre status, status invalide -> 400  OK")
except BaseException:
    print("TEST ECHEC :\n" + traceback.format_exc()); raise SystemExit(1)