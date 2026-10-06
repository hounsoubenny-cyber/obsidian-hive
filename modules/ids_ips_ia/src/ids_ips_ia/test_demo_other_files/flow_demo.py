"""Démo pédagogique — IDS Obsidian Hive
1) Table de flux (5-tuple canonique, bornée LRU)
2) ProcessPoolExecutor : submit -> Future -> asyncio
3) Scoring paquet : boucle Python vs numpy vectorisé vs to_thread
"""
import asyncio
import time
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

import numpy as np


# ───────────── 1) TABLE DE FLUX ─────────────
def flow_key(src, sport, dst, dport, proto):
    """Clé canonique : A->B et B->A donnent la MÊME clé (bidirectionnel)."""
    a, b = (src, sport), (dst, dport)
    return (proto, *(a + b if a <= b else b + a))


@dataclass
class Flow:
    first_src: str                      # qui a ouvert le flux (définit le sens "aller")
    t0: float
    t_last: float
    pkts: list = field(default_factory=lambda: [0, 0])    # [aller, retour]
    bytes_: list = field(default_factory=lambda: [0, 0])
    syn: int = 0
    rst: int = 0
    sizes_sum: float = 0.0
    sizes_sq: float = 0.0
    iat_max: float = 0.0


class FlowTable:
    def __init__(self, max_flows=100_000, emit_after=20, idle_timeout=30.0):
        self.flows: OrderedDict = OrderedDict()   # ordre = LRU
        self.max_flows = max_flows
        self.emit_after = emit_after
        self.idle_timeout = idle_timeout
        self.evicted = 0                          # compteur "non analysé" (jamais en silence)

    def update(self, ts, src, sport, dst, dport, proto, length, flags=0):
        k = flow_key(src, sport, dst, dport, proto)
        f = self.flows.get(k)
        if f is None:
            if len(self.flows) >= self.max_flows:      # table BORNÉE : on évince le plus ancien
                self.flows.popitem(last=False)
                self.evicted += 1
            f = self.flows[k] = Flow(first_src=src, t0=ts, t_last=ts)
        else:
            self.flows.move_to_end(k)
            f.iat_max = max(f.iat_max, ts - f.t_last)
        d = 0 if src == f.first_src else 1             # sens du paquet
        f.pkts[d] += 1
        f.bytes_[d] += length
        f.sizes_sum += length
        f.sizes_sq += length * length
        f.syn += bool(flags & 0x02)
        f.rst += bool(flags & 0x04)
        f.t_last = ts
        n = f.pkts[0] + f.pkts[1]
        # évaluation précoce, ou fin de flux (RST)
        if n == self.emit_after or (flags & 0x04):
            return k, self.features(f)
        return None

    @staticmethod
    def features(f: Flow):
        n = f.pkts[0] + f.pkts[1]
        mean = f.sizes_sum / n
        std = max(f.sizes_sq / n - mean * mean, 0.0) ** 0.5
        dur = max(f.t_last - f.t0, 1e-6)
        return np.array([
            dur, f.pkts[0], f.pkts[1], f.bytes_[0], f.bytes_[1],
            mean, std, f.iat_max, f.syn, f.rst,
            n / dur,                                   # paquets/s
            f.bytes_[0] / max(f.bytes_[1], 1),         # ratio octets aller/retour
        ], dtype=np.float32)


def demo_flows():
    t = FlowTable(emit_after=5)
    out = []
    for i in range(6):                                  # client -> serveur
        out.append(t.update(i * 0.01, "10.0.0.5", 51000, "10.0.0.9", 443, 6, 100 + i, flags=0x02 if i == 0 else 0x10))
        out.append(t.update(i * 0.01 + 0.005, "10.0.0.9", 443, "10.0.0.5", 51000, 6, 1400))  # retour
    emitted = [o for o in out if o]
    print(f"[flux] {len(t.flows)} flux en table, {len(emitted)} enregistrement(s) émis")
    print(f"[flux] features du 1er flux émis : {emitted[0][1].round(3)}")


# ───────────── 2) PROCESSPOOL ─────────────
def heavy(batch_id: int, x: np.ndarray):
    """Tourne dans un AUTRE process (donc hors GIL). Doit être picklable (def au niveau module)."""
    return batch_id, float(np.sqrt(x).sum())


async def demo_pool():
    loop = asyncio.get_running_loop()
    with ProcessPoolExecutor(max_workers=2) as pool:
        fut = pool.submit(heavy, 1, np.arange(1000.0))     # concurrent.futures.Future (non bloquant)
        print(f"[pool] submit() renvoie : {type(fut).__name__}")
        print(f"[pool] fut.result() = {fut.result()}")       # bloquant !

        # Version asyncio : ne bloque PAS la boucle
        q: asyncio.Queue = asyncio.Queue()
        async def worker():
            while (item := await q.get()) is not None:
                print(f"[pool] résultat reçu via queue : {await item}")
        w = asyncio.create_task(worker())
        for i in range(3):
            await q.put(loop.run_in_executor(pool, heavy, i, np.arange(1000.0)))  # un awaitable DANS la queue
        await q.put(None)
        await w


# ───────────── 3) VECTORISATION DU SCORING ─────────────
def score_loop(dec, pred, port_score, rate):
    out = []
    for d, p, ps, r in zip(dec, pred, port_score, rate):
        s = ps
        if p == -1: s += 15
        if d <= -0.8: s += 40
        elif d <= -0.7: s += 30
        elif d <= -0.5: s += 25
        elif d <= -0.3: s += 17
        elif d <= -0.1: s += 12
        elif d <= 0.0: s += 10
        if r > 0.9: s += 30
        elif r > 0.75: s += 25
        elif r > 0.6: s += 20
        elif r > 0.5: s += 15
        elif r > 0.3: s += 10
        elif r > 0.1: s += 5
        out.append(min(s, 180))
    return out


def score_np(dec, pred, port_score, rate):
    # np.digitize / searchsorted : les "if/elif" deviennent des tables de seuils
    dec_pts = np.array([40, 30, 25, 17, 12, 10, 0])[np.clip(np.searchsorted([-0.8, -0.7, -0.5, -0.3, -0.1, 0.0], dec, side="left"), 0, 6)]
    dec_pts = np.where(dec > 0.0, 0, dec_pts)
    rate_pts = np.array([0, 5, 10, 15, 20, 25, 30])[np.searchsorted([0.1, 0.3, 0.5, 0.6, 0.75, 0.9], rate, side="left")]
    s = port_score + np.where(pred == -1, 15, 0) + dec_pts + rate_pts
    return np.minimum(s, 180)


async def demo_vector(n=100_000):
    rng = np.random.default_rng(0)
    dec = rng.uniform(-1, 0.5, n)
    pred = np.where(dec < -0.3, -1, 1)
    ps = np.full(n, 10)
    rate = rng.uniform(0, 1, n)

    t = time.perf_counter(); a = score_loop(dec, pred, ps, rate); t_loop = time.perf_counter() - t
    t = time.perf_counter(); b = score_np(dec, pred, ps, rate);   t_np = time.perf_counter() - t
    print(f"[vec] {n} scores : boucle {t_loop*1e3:.1f} ms ({t_loop/n*1e6:.2f} µs/élt) | numpy {t_np*1e3:.2f} ms ({t_np/n*1e6:.3f} µs/élt)")
    print(f"[vec] résultats identiques : {np.array_equal(np.array(a), b)}")

    # coût d'un to_thread vide (le prix du "jeter dans un thread")
    N = 2000
    t = time.perf_counter()
    for _ in range(N):
        await asyncio.to_thread(lambda: None)
    print(f"[thread] to_thread vide : {(time.perf_counter()-t)/N*1e6:.0f} µs par appel")
    t = time.perf_counter()
    for _ in range(N):
        await asyncio.sleep(0)
    print(f"[thread] await sleep(0)  : {(time.perf_counter()-t)/N*1e6:.1f} µs par appel (coût d'un simple await)")


if __name__ == "__main__":
    demo_flows()
    asyncio.run(demo_pool())
    asyncio.run(demo_vector())
