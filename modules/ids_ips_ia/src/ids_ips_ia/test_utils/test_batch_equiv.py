import sys, types, importlib
from pathlib import Path
_SRC = Path(__file__).resolve().parents[2]   # .../ids_ips_ia/src
from unittest.mock import MagicMock
import numpy as np

# TensorFlow & co ne sont pas installés dans ce sandbox : on les remplace par des mocks, seule la partie
# numpy/sklearn de models.py est testée ; les 4 fonctions TF sont remplacées par des équivalents numpy.
for name in ["tensorflow", "tensorflow.keras", "tensorflow.keras.models", "tensorflow.keras.optimizers",
             "tensorflow.keras.callbacks", "tensorflow.keras.layers", "tensorflow.keras.regularizers",
             "tensorflow.keras.utils", "tensorflow.keras.losses", "tensorflow.keras.metrics",
             "optuna", "tensorflow.keras.mixed_precision"]:
    sys.modules.setdefault(name, MagicMock())
sys.path.insert(0, str(_SRC))
sys.path.insert(0, str(_SRC.parent.parent.parent))
sys.path.insert(0, str(_SRC.parent.parent / "modules_utils" / "src"))
import os
os.environ.setdefault("IDS_ADMIN_USERNAME", "test")
os.environ.setdefault("IDS_ADMIN_PASSWORD", "Str0ng!Passw0rd#2026")
os.environ.setdefault("IDS_JWT_SECRET", "a" * 64)
M = importlib.import_module("ids_ips_ia.models.models")

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

rng = np.random.default_rng(0)
F, L = 12, 60
calls = []          # tailles de lots réellement vues par les "modèles" (doivent être des buckets)

W = rng.normal(size=(F, F))
def fake_ae_pkt(model, x):            calls.append(len(x)); return np.tanh(x @ W)
def fake_cnn_mem(model, x):           calls.append(len(x)); return x.mean(axis=1, keepdims=True) * 0.5
def fake_ae_seq(model, x, mem):       calls.append(len(x)); return np.tanh(x * 0.7 + mem)
def fake_cnn_seq(model, x):           calls.append(len(x)); return np.tanh(x * 0.3)
M._predict_ae_pkt, M._predict_cnn_memory, M._predict_ae_seq, M._predict_cnn_seq = fake_ae_pkt, fake_cnn_mem, fake_ae_seq, fake_cnn_seq

# --- paquets
Xtr = rng.normal(size=(2000, F))
sc_p = StandardScaler().fit(Xtr)
Ztr = np.concatenate([np.tanh(sc_p.transform(Xtr) @ W), np.ones((2000, 2))*.1], axis=1)
if_p = IsolationForest(n_estimators=100, random_state=0).fit(Ztr)
lof_p = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(Ztr)
for m_ in (if_p, lof_p): m_.norm_min_, m_.norm_max_ = -0.5, 0.5

mods = M.Models.__new__(M.Models)
mods.cnn_bottleneck_model = object()           # évite la création keras
mods._cnn_bottleneck_for = None
mods._get_cnn_bottleneck = lambda cnn: object()  # le bottleneck est simulé par fake_cnn_mem
mods.verbose = 0

test = np.concatenate([rng.normal(size=(40, F)), rng.normal(5, 3, size=(10, F))])   # 10 anomalies
for method in ("decision_function", "predict"):
    for how in ("any", "all"):
        one = np.array([mods.predict_packet(None, if_p, lof_p, sc_p, t, method=method, how=how) for t in test])
        calls.clear()
        bat = mods.predict_packet_batch(None, if_p, lof_p, sc_p, list(test), method=method, how=how)
        assert bat.shape == (50,), bat.shape
        np.testing.assert_allclose(one, bat, rtol=1e-9, atol=1e-9)
        assert set(calls) <= set(M._BATCH_BUCKETS), calls
print("paquets : lot == un-par-un  (decision_function/predict x any/all)  OK ; tailles vues :", sorted(set(calls)))

# tailles de lot variées, y compris > 256 (découpage) et 1
for n in (1, 2, 3, 5, 33, 256, 257, 600):
    X = rng.normal(size=(n, F))
    a = np.array([mods.predict_packet(None, if_p, lof_p, sc_p, t, method="decision_function", how="any") for t in X])
    b = mods.predict_packet_batch(None, if_p, lof_p, sc_p, list(X), method="decision_function", how="any")
    np.testing.assert_allclose(a, b, rtol=1e-9, atol=1e-9)
print("tailles 1,2,3,5,33,256,257,600 : OK")

# --- séquences
Fs = F
seq_tr = rng.normal(size=(300, L, Fs))
sc_s = StandardScaler().fit(seq_tr.reshape(-1, Fs))
def flat(batch):
    new = sc_s.transform(batch.reshape(-1, Fs)).reshape(len(batch), L, Fs)
    mem = fake_cnn_mem(None, new); xp = fake_ae_seq(None, new, mem); xc = fake_cnn_seq(None, new)
    d, dc = new - xp, new - xc
    return np.concatenate((xp.reshape(len(batch), -1), xc.reshape(len(batch), -1),
        np.mean(d**2, axis=(1,2)).reshape(-1,1), np.mean(np.abs(d), axis=(1,2)).reshape(-1,1),
        np.mean(dc**2, axis=(1,2)).reshape(-1,1), np.mean(np.abs(dc), axis=(1,2)).reshape(-1,1)), axis=1)
Ftr = flat(seq_tr)
if_s = IsolationForest(n_estimators=100, random_state=0).fit(Ftr)
lof_s = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(Ftr)
for m_ in (if_s, lof_s): m_.norm_min_, m_.norm_max_ = -0.5, 0.5
seq_test = np.concatenate([rng.normal(size=(7, L, Fs)), rng.normal(4, 2, size=(3, L, Fs))])
for method in ("decision_function", "predict"):
    one = np.array([mods.predict_sequence(None, None, if_s, lof_s, sc_s, s, method=method, how="any") for s in seq_test])
    bat = mods.predict_sequence_batch(None, None, if_s, lof_s, sc_s, seq_test, method=method, how="any")
    np.testing.assert_allclose(one, bat, rtol=1e-9, atol=1e-9)
print("séquences : lot == un-par-un  OK")

# --- _normalize_decision_function reste rétro-compatible (scalaire -> float)
r = mods._normalize_decision_function(0.1, 0.2, who="pkt", if_model=if_p, lof_model=lof_p)
assert isinstance(r, float)
print("normalize scalaire -> float OK")
