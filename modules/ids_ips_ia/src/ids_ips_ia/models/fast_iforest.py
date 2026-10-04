#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fast_iforest.py — Scoring IsolationForest vectorisé (numpy pur) : MÊMES scores que sklearn, bien plus rapide.

Pourquoi sklearn est lent en inférence : IsolationForest.score_samples boucle sur les arbres EN PYTHON
(un appel tree.apply + decision_path par arbre, et avec n_jobs != 1 un joblib.Parallel qui dispatche chaque
arbre à chaque appel). Le coût dépend donc du nombre d'arbres, presque pas du nombre d'échantillons.

Ici : on aplatit tous les arbres dans des tableaux numpy et on descend TOUS les arbres pour TOUS les
échantillons en même temps, niveau par niveau (≤ ~8-10 itérations : profondeur max = ceil(log2(max_samples))).
Chaque nœud-feuille contient déjà (profondeur + average_path_length(n_samples_feuille)) -> la somme sur les
arbres donne exactement le `depths` de sklearn.

Usage :
    fast = FastIForest.try_build(if_model)          # None si non supporté / écart avec sklearn
    scores = (fast or if_model).decision_function(Z)

Garanties :
  - try_build() se VÉRIFIE contre sklearn sur des points tirés autour des seuils des arbres ; en cas d'écart
    (> 1e-9) ou d'exception (version de sklearn différente...) il renvoie None -> l'appelant garde sklearn ;
  - même convention que sklearn : X converti en float32, test `x <= seuil` (seuil en float64) ;
  - attributs inconnus (norm_min_, norm_max_, offset_, ...) délégués au modèle sklearn d'origine ;
  - à reconstruire quand le modèle change (refit) : voir Models._fast_if dans le patch d'intégration.
"""

import numpy as np


def _avg_path(n) -> np.ndarray:
    """average_path_length de sklearn (IsolationForest), vectorisé."""
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    out[n == 2] = 1.0
    m = n > 2
    out[m] = 2.0 * (np.log(n[m] - 1.0) + np.euler_gamma) - 2.0 * (n[m] - 1.0) / n[m]
    return out


class FastIForest:
    def __init__(self, model):
        self.model = model                       # référence gardée : le cache vérifie `entry.model is m`
        est, feats = model.estimators_, model.estimators_features_
        T = len(est)
        N = max(e.tree_.node_count for e in est)
        self.T, self.N = T, N
        self.n_features = int(model.n_features_in_)

        feature = np.zeros((T, N), dtype=np.intp)
        thr = np.zeros((T, N), dtype=np.float64)
        left = np.zeros((T, N), dtype=np.intp)
        right = np.zeros((T, N), dtype=np.intp)
        val = np.zeros((T, N), dtype=np.float64)
        max_depth = 0
        for t, (e, f) in enumerate(zip(est, feats)):
            tr = e.tree_
            n = tr.node_count
            cl, cr = tr.children_left, tr.children_right
            leaf = cl == -1                                   # TREE_LEAF
            idx = np.arange(n)
            depth = np.zeros(n, dtype=np.int64)               # profondeur de chaque nœud, niveau par niveau
            cur, d = np.array([0]), 0
            while cur.size:
                depth[cur] = d
                inner = cur[~leaf[cur]]
                cur = np.concatenate([cl[inner], cr[inner]])
                d += 1
            max_depth = max(max_depth, int(depth.max()))
            f = np.asarray(f)
            feature[t, :n] = np.where(leaf, 0, f[np.clip(tr.feature, 0, None)])   # index de colonne GLOBAL
            thr[t, :n] = np.where(leaf, 0.0, tr.threshold)
            left[t, :n] = np.where(leaf, idx, cl)             # une feuille boucle sur elle-même
            right[t, :n] = np.where(leaf, idx, cr)
            val[t, :n] = np.where(leaf, depth + _avg_path(tr.n_node_samples), 0.0)
        self.max_depth = max_depth
        self._off = (np.arange(T, dtype=np.intp) * N)[None, :]
        self._feat = feature.ravel()
        self._thr = thr.ravel()
        self._val = val.ravel()
        child = np.empty(2 * T * N, dtype=np.intp)            # child[2*i] = gauche, child[2*i+1] = droite
        child[0::2], child[1::2] = left.ravel(), right.ravel()
        self._child = child
        self._denom = T * float(_avg_path([model.max_samples_])[0])
        self._chunk = max(1, 2_000_000 // T)                  # borne la mémoire des tableaux (B, T)

    # ------------------------------------------------------------------ scoring
    def _depths(self, X: np.ndarray) -> np.ndarray:
        X = np.ascontiguousarray(X, dtype=np.float32)
        if X.ndim != 2 or X.shape[1] != self.n_features:
            raise ValueError(f"X doit avoir {self.n_features} colonnes, reçu {X.shape}")
        out = np.empty(len(X), dtype=np.float64)
        for s in range(0, len(X), self._chunk):
            xb = X[s:s + self._chunk]
            rows = np.arange(len(xb))[:, None]
            node = np.zeros((len(xb), self.T), dtype=np.intp)
            for _ in range(self.max_depth):
                flat = node + self._off
                go_right = ~(xb[rows, self._feat[flat]] <= self._thr[flat])   # float32 <= float64, comme sklearn
                node = self._child[2 * flat + go_right]
            out[s:s + self._chunk] = self._val[node + self._off].sum(axis=1)
        return out

    def score_samples(self, X) -> np.ndarray:
        return -(2.0 ** (-self._depths(X) / self._denom))

    def decision_function(self, X) -> np.ndarray:
        return self.score_samples(X) - self.model.offset_

    def predict(self, X) -> np.ndarray:
        return np.where(self.decision_function(X) < 0, -1, 1)

    def __getattr__(self, name):                              # norm_min_, norm_max_, offset_, n_estimators ...
        if name in ("model", "__setstate__"):
            raise AttributeError(name)
        return getattr(self.model, name)

    # ------------------------------------------------------------ construction sûre
    @classmethod
    def try_build(cls, model, n_check: int = 64, tol: float = 1e-9):
        """FastIForest vérifié contre sklearn, ou None (-> utiliser sklearn tel quel)."""
        try:
            fast = cls(model)
            nf = fast.n_features
            rng = np.random.default_rng(0)
            # points de test autour des seuils réellement utilisés par chaque feature
            internal = fast._thr != 0
            cnt = np.bincount(fast._feat[internal], minlength=nf).astype(float)
            s1 = np.bincount(fast._feat[internal], weights=fast._thr[internal], minlength=nf)
            s2 = np.bincount(fast._feat[internal], weights=fast._thr[internal] ** 2, minlength=nf)
            mu = np.divide(s1, cnt, out=np.zeros(nf), where=cnt > 0)
            sd = np.sqrt(np.maximum(np.divide(s2, cnt, out=np.zeros(nf), where=cnt > 0) - mu ** 2, 0.0)) + 1e-6
            X = (mu + sd * rng.normal(size=(n_check, nf))).astype(np.float32)
            ref = model.decision_function(X)
            if np.max(np.abs(fast.decision_function(X) - ref)) > tol:
                return None
            if np.max(np.abs(fast.decision_function(X[:1]) - ref[:1])) > tol:     # invariance à la taille du lot
                return None
            return fast
        except Exception:
            return None


if __name__ == "__main__":
    # Auto-test + benchmark : python3 fast_iforest.py
    import time
    from sklearn.ensemble import IsolationForest

    rng = np.random.default_rng(1)
    print("== exactitude vs sklearn ==")
    for T, F, ms, mf, boot in [(100, 14, "auto", 1.0, False), (300, 40, 256, 1.0, False),
                               (150, 30, 128, 0.5, False), (80, 20, 256, 0.7, True)]:
        Xtr = rng.normal(size=(3000, F)) * rng.uniform(0.5, 3, size=F)
        m = IsolationForest(n_estimators=T, max_samples=ms, max_features=mf, bootstrap=boot,
                            contamination=0.01, random_state=0).fit(Xtr)
        fast = FastIForest.try_build(m)
        assert fast is not None, f"build/verify a échoué pour {(T, F, ms, mf, boot)}"
        Xte = np.concatenate([rng.normal(size=(500, F)) * 2, rng.normal(6, 4, size=(500, F))])
        for name in ("score_samples", "decision_function"):
            d = np.max(np.abs(getattr(fast, name)(Xte) - getattr(m, name)(Xte)))
            assert d < 1e-12, (name, d)
        assert np.array_equal(fast.predict(Xte), m.predict(Xte))
        print(f"  T={T:4d} F={F:3d} max_samples={ms} max_features={mf} bootstrap={boot} : OK (écart ≤ 1e-12, predict identique)")

    print("== benchmark (1 cœur ici ; sur ta machine n_jobs=-1 ajoute l'overhead joblib de sklearn) ==")
    print(f"{'config':34s} {'lot':>5s} {'sklearn':>10s} {'FastIForest':>12s} {'gain':>6s}")
    for T, F in [(100, 14), (300, 14), (1000, 14), (300, 1204)]:
        Xtr = rng.normal(size=(3000, F))
        m = IsolationForest(n_estimators=T, contamination=0.01, random_state=0, n_jobs=1).fit(Xtr)
        fast = FastIForest.try_build(m)
        for B in (1, 26, 256):
            X = rng.normal(size=(B, F)).astype(np.float32)
            reps = 5 if T < 1000 else 3
            t0 = time.perf_counter(); [m.decision_function(X) for _ in range(reps)]; a = (time.perf_counter() - t0) / reps
            t0 = time.perf_counter(); [fast.decision_function(X) for _ in range(reps)]; b = (time.perf_counter() - t0) / reps
            print(f"T={T:<5d} F={F:<5d}{'':18s} {B:5d} {a*1000:8.1f}ms {b*1000:10.2f}ms {a/b:5.0f}x")
