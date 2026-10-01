import sys, os, asyncio, importlib, queue
from pathlib import Path
_SRC = Path(__file__).resolve().parents[2]   # .../ids_ips_ia/src
from unittest.mock import MagicMock
from types import SimpleNamespace
import numpy as np

for name in ["tensorflow", "tensorflow.keras", "tensorflow.keras.models", "tensorflow.keras.optimizers",
             "tensorflow.keras.callbacks", "tensorflow.keras.layers", "tensorflow.keras.regularizers",
             "tensorflow.keras.utils", "tensorflow.keras.losses", "tensorflow.keras.metrics", "optuna"]:
    sys.modules.setdefault(name, MagicMock())
for p in (str(_SRC), str(_SRC.parent.parent.parent),
          str(_SRC.parent.parent / "modules_utils" / "src")):
    sys.path.insert(0, p)
os.environ.setdefault("IDS_ADMIN_USERNAME", "test"); os.environ.setdefault("IDS_ADMIN_PASSWORD", "Str0ng!Passw0rd#2026")
os.environ.setdefault("IDS_JWT_SECRET", "a" * 64)

try:
    D = importlib.import_module("ids_ips_ia.detection.detection_module")
except ModuleNotFoundError as e:
    print("MODULE MANQUANT:", e.name); sys.exit(2)

L, STRIDE, BATCH = D.SEQ_LENGTH, D.SEQ_STRIDE, D.DETECT_BATCH_SIZE
print(f"config lue : SEQ_LENGTH={L} SEQ_STRIDE={STRIDE} DETECT_BATCH_SIZE={BATCH}")

class FakeModels:
    def __init__(self): self.pkt_calls = []; self.seq_calls = []
    async def apredict_packet_batch(self, *a, how, method, return_pred=False):
        feats = a[4]; self.pkt_calls.append(len(feats))
        sc = np.array([-1.0 if f[0] > 5 else 1.0 for f in feats])        # f[0] > 5 -> anomalie paquet
        return (sc, np.where(sc < 0, -1, 1)) if return_pred else sc
    async def apredict_sequence_batch(self, *a, how, method, return_pred=False):
        X = a[5]; self.seq_calls.append(len(X)); assert X.shape[1:] == (L, 3), X.shape
        sc = np.ones(len(X))                                               # séquences normales
        return (sc, np.ones(len(X), dtype=int)) if return_pred else sc

class FakeFE:
    @staticmethod
    def extract_pack_features(pkt): return np.array([pkt.v, 0.0, 0.0])
    @staticmethod
    def extract_seq_features(arr): return np.asarray(arr)

alerts, scored, ia_seen = [], [], []
class FakeScorer:
    async def detect_pkt(self, **kw):
        scored.append(kw["seq_anomaly"]); ia_seen.append(kw.get("ia_preds")); return 0.5
    @staticmethod
    def _get_ip(pkt, with_dst=False): return ("1.1.1.1", "2.2.2.2")

def make_detector(n_packets, anomalous_idx):
    d = D.AnomalyDetector.__new__(D.AnomalyDetector)
    d.q = queue.Queue(); d.skipper = SimpleNamespace(should_skip=lambda item: False)
    d.pkt_proccessed = 0; d.enable_graphe = False; d.mode = "ids"
    d.stop_event = __import__("threading").Event(); d.model_lock = __import__("threading").Lock()
    d.Models = FakeModels(); d.FeatureExtractor = FakeFE; d.AnomalyScorer = FakeScorer()
    d.log_anomaly = lambda *a, **k: alerts.append(("log", k.get("source")))
    d._add_alert = lambda data: alerts.append(("alert", data))
    d._to_alert_entry = lambda *a, **k: {}
    d.anomaly_logger = MagicMock(); d.stop = lambda: None
    async def _stop_mon(): pass
    d.stop_monitor_task = _stop_mon
    d._update_model_refs = lambda with_lock=True: setattr(d, "_model_refs", tuple(object() for _ in range(9)))
    D.load = lambda path: b""; D.dill = MagicMock(); D.dill.loads = lambda b: {}
    for i in range(n_packets):
        d.q.put_nowait(SimpleNamespace(v=10.0 if i in anomalous_idx else 0.0, ts=float(i)))
    return d

async def run(n, anomalous):
    d = make_detector(n, anomalous)
    async def stopper():
        while not d.q.empty(): await asyncio.sleep(0.01)
        await asyncio.sleep(0.3); d.stop_event.set()
    t = asyncio.create_task(stopper())
    await d.detect("x", combination_mode="or", packet_anomaly=0.4, verbose=False)
    await t
    return d

N = 500
anom = {100, 101, 300}
d = asyncio.run(run(N, anom))
fm = d.Models
expected_seq = (N - L) // STRIDE + 1
print("paquets traités :", d.pkt_proccessed, "| appels modèle paquet :", len(fm.pkt_calls), "| tailles :", fm.pkt_calls[:6], "...")
print("séquences évaluées :", sum(fm.seq_calls), "(attendu", expected_seq, ") en", len(fm.seq_calls), "appel(s) modèle")
assert d.pkt_proccessed == N
assert sum(fm.pkt_calls) == N
assert len(fm.pkt_calls) <= (N + BATCH - 1) // BATCH + 2 and max(fm.pkt_calls) <= BATCH
assert sum(fm.seq_calls) == expected_seq, (sum(fm.seq_calls), expected_seq)
n_pkt_alerts = sum(1 for a in alerts if a[0] == "alert")
assert n_pkt_alerts == len(anom), (n_pkt_alerts, anom)
assert scored.count(None) == len(anom)
print("alertes paquet :", n_pkt_alerts, "OK ; reaction appelée", len(scored), "fois")
# le scorer reçoit les prédictions DÉJÀ calculées en lot -> aucune ré-inférence unitaire (le goulot de result003)
assert len(ia_seen) == len(scored) and all(p is not None for p in ia_seen), ia_seen
assert all(set(p) == {"decision_function", "predict"} for p in ia_seen)
assert all(p["predict"] == -1 and p["decision_function"] == -1.0 for p in ia_seen), ia_seen
print("ia_preds transmis au scorer (decision_function + predict) :", len(ia_seen), "fois OK")
print("AVANT (stride 1, un-par-un) :", N, "appels paquet +", N - L + 1, "appels séquence")
print("APRÈS :", len(fm.pkt_calls), "appel(s) paquet +", len(fm.seq_calls), "appel(s) séquence")
