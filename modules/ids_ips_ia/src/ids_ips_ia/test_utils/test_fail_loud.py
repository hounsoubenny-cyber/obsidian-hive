#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 04:07:47 2026

@author: hounsousamuel
"""

"""Fail-loud : NaN = inconnu, K échecs consécutifs -> UNE entrée système complète, détection qui continue, puis 'resolved'."""
import sys, asyncio, runpy
from pathlib import Path
import numpy as np

# on réutilise le montage de test_detect_loop (stubs TF, faux modèles...) sans exécuter ses assertions
ns = runpy.run_path(str(Path(__file__).with_name("test_detect_loop.py")), run_name="not_main")
D, make_detector, FakeModels = ns["D"], ns["make_detector"], ns["FakeModels"]
alerts_log, scored = ns["alerts"], ns["scored"]

class FlakyModels(FakeModels):
    """Les 6 premiers lots de paquets échouent (NaN), les suivants sont sains."""
    def __init__(self): super().__init__(); self.n = 0; self.last_batch_error = None
    async def apredict_packet_batch(self, *a, how, method, return_pred=False):
        n = len(a[4]); self.n += 1
        if self.n <= 6:
            self.last_batch_error = {"stage": "packet", "type": "ValueError", "message": "boom", "at": 1.0}
            sc = np.full(n, np.nan); return (sc, np.zeros(n, dtype=int)) if return_pred else sc
        self.last_batch_error = None
        return await super().apredict_packet_batch(*a, how=how, method=method, return_pred=return_pred)

async def run():
    alerts_log.clear(); scored.clear()          # le module importé a déjà tourné une fois
    D.DETECT_BATCH_SIZE = 10; D.MODEL_ERROR_THRESHOLD = 3
    d = make_detector(100, set(range(70, 100)))        # anomalies seulement APRÈS la panne (batch 7)
    d.Models = FlakyModels()
    async def stopper():
        while not d.q.empty(): await asyncio.sleep(0.01)
        await asyncio.sleep(0.3); d.stop_event.set()
    t = asyncio.create_task(stopper())
    await d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False)
    await t
    return d

import traceback
try:
    d = asyncio.run(run())
    sys_al = d._get_system_alerts()
    assert d.pkt_proccessed == 100, d.pkt_proccessed                       # la détection a CONTINUÉ pendant la panne
    assert len(sys_al) == 1, sys_al                                         # UNE entrée pour toute la panne (pas une par lot)
    a = sys_al[0]
    assert a["type"] == "model_inference_failure" and a["stage"] == "packet" and a["severity"] == "critical"
    assert a["threshold"] == 3 and a["consecutive_failures"] == 6 and a["detection_continues"] is True
    assert a["items_unscored"] == 40                                        # lots 3..6 (10 paquets chacun) comptés dès l'ouverture
    # assert a["last_error"]["type"] == "ValueError" and a["last_error"]["message"] == "boom"
    assert a["status"] == "resolved" and a["resolved_at"] is not None        # un lot sain a refermé l'incident
    n_pkt_alerts = sum(1 for x in alerts_log if x[0] == "alert")
    assert n_pkt_alerts == 31, n_pkt_alerts      # 30 paquets anormaux (70..99, après la reprise)  1 alerte de séquence (fenêtre finale 30/60)
    assert d._get_system_alerts(10, "open") == [] and len(d._get_system_alerts(10, "resolved")) == 1
    print("fail-loud : 6 lots NaN -> 1 alerte système complète (resolved), 100/100 paquets traités, 31 alertes d'attaque après reprise  OK")
    print({k: a[k] for k in ("id", "status", "consecutive_failures", "items_unscored")})
except BaseException:
    print('TEST ECHEC :\n' + traceback.format_exc()); raise SystemExit(1)
