"""
Test du pipeline capture || traitement de AnomalyDetector.detect().

Vérifie 3 choses :
  1. ÉQUIVALENCE : mêmes paquets traités, mêmes séquences, mêmes alertes qu'avant.
  2. ORDRE       : les anomalies arrivent au scorer dans l'ordre d'arrivée des paquets (FIFO, 1 consommateur).
  3. RECOUVREMENT: avec des durées SIMULÉES (features = CPU bloquant, inférence = thread), le temps total
                   doit être nettement inférieur à (features + inférence) cumulés.

⚠️ Les durées sont fictives (FE_S_PER_PKT / INFER_S_PER_BATCH) : le test prouve que le recouvrement
   fonctionne, pas le gain réel sur ta machine (pour ça : test_utils/benchmark_pipeline.py).

Lancer : python test_pipeline_overlap.py
"""
import sys, os, asyncio, importlib, queue, time, threading
from pathlib import Path
from collections import deque
from unittest.mock import MagicMock
from types import SimpleNamespace
import numpy as np

_SRC = Path(__file__).resolve().parents[2]
from unittest.mock import MagicMock as _MM
for name in ["tensorflow", "tensorflow.keras", "tensorflow.keras.models", "tensorflow.keras.optimizers",
             "tensorflow.keras.callbacks", "tensorflow.keras.layers", "tensorflow.keras.regularizers",
             "tensorflow.keras.utils", "tensorflow.keras.losses", "tensorflow.keras.metrics", "optuna"]:
    sys.modules.setdefault(name, _MM())
for p in (str(_SRC), str(_SRC.parent.parent.parent), str(_SRC.parent.parent / "modules_utils" / "src")):
    sys.path.insert(0, p)
os.environ.setdefault("IDS_ADMIN_USERNAME", "test"); os.environ.setdefault("IDS_ADMIN_PASSWORD", "Str0ng!Passw0rd#2026")
os.environ.setdefault("IDS_JWT_SECRET", "a" * 64)

D = importlib.import_module("ids_ips_ia.detection.detection_module")
L, STRIDE = D.SEQ_LENGTH, D.SEQ_STRIDE

# --- paramètres de la simulation ------------------------------------------------------------
N = 600                       # paquets
BATCH = 50                    # taille de lot (patch de DETECT_BATCH_SIZE) -> 12 lots
FE_S_PER_PKT = 0.0006         # extraction de features : 30 ms / lot, CPU BLOQUANT (comme le vrai code)
INFER_S_PER_BATCH = 0.05      # inférence : 50 ms / lot, dans un THREAD (comme apredict_packet_batch)
ANOM = {100, 101, 300, 450}
D.DETECT_BATCH_SIZE = BATCH   # lu à chaque appel de _drain_entries -> le patch est pris en compte

stamps = {"first": None, "last": None}
scored_ts, alerts = [], []
pkt_calls, seq_calls = [], []


class SlowModels:
    async def apredict_packet_batch(self, *a, how, method, return_pred=False):
        feats = a[4]; pkt_calls.append(len(feats))
        await asyncio.to_thread(time.sleep, INFER_S_PER_BATCH)           # l'inférence tourne dans un thread
        stamps["last"] = time.perf_counter()
        sc = np.array([-1.0 if f[0] > 5 else 1.0 for f in feats])
        return (sc, np.where(sc < 0, -1, 1)) if return_pred else sc

    async def apredict_sequence_batch(self, *a, how, method, return_pred=False):
        X = a[5]; seq_calls.append(len(X))
        sc = np.ones(len(X))
        return (sc, np.ones(len(X), dtype=int)) if return_pred else sc


class SlowFE:
    @staticmethod
    def extract_pack_features(pkt):
        time.sleep(FE_S_PER_PKT)                                          # CPU bloquant
        if stamps["first"] is None:
            stamps["first"] = time.perf_counter()
        return np.array([pkt.v, 0.0, 0.0])

    @staticmethod
    def extract_seq_features(arr): return np.asarray(arr)


class FakeScorer:
    async def detect_pkt(self, **kw):
        scored_ts.append(kw["pkt"].ts); return 0.5

    @staticmethod
    def _get_ip(pkt, with_dst=False): return ("1.1.1.1", "2.2.2.2")


def make_detector(n_packets=N):
    d = D.AnomalyDetector.__new__(D.AnomalyDetector)        # sans __init__ : on pose à la main le strict nécessaire
    d.q = queue.Queue(); d.skipper = SimpleNamespace(should_skip=lambda item: False)
    d.pkt_proccessed = 0; d.enable_graphe = False; d.mode = "ids"
    d._started_at = time.monotonic(); d.stat_batches = d.stat_scored = d.stat_last_batch = d.stat_sequences = 0
    d.last_anomalies_queue = deque(maxlen=100)
    d.system_alerts = {}; d._system_alerts_lock = threading.Lock()
    d._infer_fail = {k: {"consecutive": 0, "alert_id": None} for k in ("packet", "sequence")}
    d.stop_event = threading.Event(); d.model_lock = threading.Lock()
    d.Models = SlowModels(); d.FeatureExtractor = SlowFE; d.AnomalyScorer = FakeScorer()
    d.log_anomaly = lambda *a, **k: None
    d._add_alert = lambda data: alerts.append(data)
    d._to_alert_entry = lambda *a, **k: {}
    d.anomaly_logger = MagicMock(); d.stop = lambda: None
    async def _stop_mon(): pass
    d.stop_monitor_task = _stop_mon
    d._update_model_refs = lambda with_lock=True: setattr(d, "_model_refs", tuple(object() for _ in range(9)))
    D.load = lambda path: b""; D.dill = MagicMock(); D.dill.loads = lambda b: {}
    for i in range(n_packets):
        d.q.put_nowait(SimpleNamespace(v=10.0 if i in ANOM else 0.0, ts=float(i)))
    return d


async def run():
    d = make_detector()
    async def stopper():
        while not d.q.empty(): await asyncio.sleep(0.01)
        await asyncio.sleep(0.4); d.stop_event.set()
    t = asyncio.create_task(stopper())
    await d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False)
    await t
    return d


d = asyncio.run(run())

# 1) équivalence
expected_seq = (N - L) // STRIDE + 1
assert d.pkt_proccessed == N, d.pkt_proccessed
assert sum(pkt_calls) == N, sum(pkt_calls)
assert max(pkt_calls) <= BATCH
assert sum(seq_calls) == expected_seq, (sum(seq_calls), expected_seq)
assert len(alerts) == len(ANOM), (len(alerts), ANOM)

# 2) ordre
assert scored_ts == sorted(float(i) for i in ANOM), scored_ts

# 3) recouvrement
n_batches = len(pkt_calls)
fe_total = N * FE_S_PER_PKT
infer_total = n_batches * INFER_S_PER_BATCH
sequentiel = fe_total + infer_total                 # ce que coûterait "tout l'un après l'autre"
mesure = stamps["last"] - stamps["first"]
print(f"{n_batches} lots | features {fe_total*1000:.0f} ms + inférence {infer_total*1000:.0f} ms "
      f"=> séquentiel théorique {sequentiel*1000:.0f} ms")
print(f"temps mesuré (1er paquet -> fin du dernier lot) : {mesure*1000:.0f} ms "
      f"(borne basse = étape la plus lente = {max(fe_total, infer_total)*1000:.0f} ms)")
print("équivalence OK | ordre OK |", "recouvrement OK" if mesure < 0.85 * sequentiel else "PAS DE RECOUVREMENT")
assert mesure < 0.85 * sequentiel, (mesure, sequentiel)


# 4) robustesse : pas de blocage à l'arrêt ni si une des deux tâches plante ------------------------
async def scenario_idle():
    """Aucun paquet : le producteur rend sa place et dort ; stop_event doit terminer detect() proprement."""
    d = make_detector(0)
    async def stopper():
        await asyncio.sleep(0.3); d.stop_event.set()
    t = asyncio.create_task(stopper())
    await asyncio.wait_for(d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False), timeout=3)
    await t
    assert d._pipe_queue is None

async def scenario_consumer_crash():
    """Références modèles cassées -> le consommateur plante : detect() doit rendre la main (producteur annulé)."""
    d = make_detector(10)
    d._update_model_refs = lambda with_lock=True: setattr(d, "_model_refs", None)
    await asyncio.wait_for(d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False), timeout=3)
    assert d._pipe_queue is None

asyncio.run(scenario_idle())
asyncio.run(scenario_consumer_crash())
print("arrêt au repos OK | plantage du consommateur sans blocage OK")
