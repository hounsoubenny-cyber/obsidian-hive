#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Oct  5 09:55:09 2026

@author: hounsousamuel
"""

"""
test_torture_adapter_proxy.py

Suite de tests « torture » pour ProcessCaptureAdapter <-> CaptureProxy.
Ne remplace pas le test complet précédent — il le complète.

Philosophie : pour chaque cas subtil, on documente le comportement observé
plutôt que de forcer un « attendu ». Si un cas casse, c'est un bug à examiner.

Usage :
    python test_torture_adapter_proxy.py
    python test_torture_adapter_proxy.py --section proxy
"""
import argparse
import gc
import sys
import threading
import multiprocessing as mp
import time
import traceback
import queue as _q
import importlib.util
import types
from multiprocessing import shared_memory
from uuid import uuid4


# ============================================================================
# 1) FAKES
# ============================================================================
class FakeCapture:
    MODE = "normal"

    def __init__(self, queue=None, log_interval=10.0, backup_queue=None,
                 event=None, *args, **kwargs):
        self.queue = queue
        self.log_interval = log_interval
        self.backup_queue = backup_queue
        self.event = event or threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._packets = 0
        self._dropped = 0
        self._ignored_ips = set()
        self._started_at = None
        self._write_period = 0.02
        self._huge = b"X" * (5 * 1024 * 1024)   # 5 Mo, pour tests de taille

    def capture(self, *args, **kwargs):
        if FakeCapture.MODE == "noop":
            return
        if FakeCapture.MODE == "raises":
            raise RuntimeError("fake capture boom")
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            time.sleep(self._write_period)
            self._packets += 1
            ts = time.time()
            raw = f"pkt-{self._packets:06d}".encode()
            if self.queue is not None:
                try:
                    self.queue.put((ts, raw))
                except Exception:
                    self._dropped += 1

    def stop(self, timeout=5.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self.event.set()

    def add_src_ip_to_ignore(self, ip):
        self._ignored_ips.add(ip)
        return True

    def remove_src_ip_to_ignore(self, ip):
        self._ignored_ips.discard(ip)
        return True

    def stats(self):
        return {"packets": self._packets, "dropped": self._dropped,
                "ignored": sorted(self._ignored_ips),
                "uptime_s": (time.time() - self._started_at) if self._started_at else 0.0}

    @property
    def dropped_packets(self):
        return self._dropped

    @property
    def raises_on_access(self):
        raise RuntimeError("property crash")

    def raises_on_call(self, *args, **kwargs):
        raise RuntimeError("method crash")

    def needs_two_args(self, a, b):
        return a + b

    def huge_response(self):
        return self._huge

    def nested_deep(self, depth=50):
        d = {"leaf": 1}
        for i in range(depth):
            d = {"level": i, "child": d}
        return d

    def cyclic(self):
        d = {}
        d["self"] = d
        return d

    def with_lambda(self):
        return {"fn": lambda x: x}

    def with_memoryview(self):
        return {"buf": memoryview(b"hello")}

    def with_bytearray(self):
        return bytearray(b"\x00\x01\x02")

    def snapshot(self):
        return {"packets": self._packets}

    def metrics(self):
        return {"metric": True, **self.stats()}

    def echo(self, *args, **kwargs):
        return {"args": list(args), "kwargs": dict(kwargs)}


class FakeRefitQueue:
    def __init__(self, session_id="test", tag="t", *args, **kwargs):
        self.session_id = session_id
        self.tag = tag
        self.stop_event = threading.Event()
        self._thread = None
        self._started = False
        self._stopped = False

    def start(self):
        if self._started:
            return
        self._started = True
        self.stop_event.clear()
        self._thread = threading.Thread(target=lambda: self.stop_event.wait(3600),
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        self._stopped = True
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def stats(self):
        return {"queued": 0, "session_id": self.session_id, "started": self._started}


# Injection
_fc = types.ModuleType("ids_ips_ia.core.capture")
_fc.Capture = FakeCapture
sys.modules["ids_ips_ia.core.capture"] = _fc

_fr = types.ModuleType("ids_ips_ia.refit_system.refit_queue")
_fr.RefitQueue = FakeRefitQueue
sys.modules["ids_ips_ia.refit_system.refit_queue"] = _fr


# ============================================================================
# 2) IMPORTS RÉELS
# ============================================================================
import ids_ips_ia.memory_managers.ring as ring_mod
import ids_ips_ia.adapters.capture_proxy as proxy_mod
import ids_ips_ia.adapters.process_capture_adapter as adapter_mod

Ring = ring_mod.Ring
ProcessCaptureAdapter = adapter_mod.ProcessCaptureAdapter
CaptureProxy = proxy_mod.CaptureProxy


# ============================================================================
# 3) HARNESS
# ============================================================================
_RESULTS = []
_NOTES = []
_SHM_COUNTER = [0]


def check(name, cond, detail=""):
    _RESULTS.append((name, bool(cond), detail))
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  \033[90m[{detail}]\033[0m" if detail else ""))


def observe(name, value, note=""):
    """Enregistre un comportement observé sans rien imposer. Toujours vert."""
    _RESULTS.append((name, True, f"obs={value!r}"))
    _NOTES.append((name, value, note))
    print(f"  \033[36m◇\033[0m {name}  \033[90m[{value!r}]\033[0m" +
          (f"  {note}" if note else ""))


def section(title):
    print(f"\n\033[1m══ {title} ══\033[0m")


def summarize():
    ok = sum(1 for _, c, _ in _RESULTS if c)
    total = len(_RESULTS)
    print(f"\n\033[1m{ok}/{total} tests passés\033[0m")
    if ok < total:
        print("\033[31mÉchecs :\033[0m")
        for name, c, d in _RESULTS:
            if not c:
                print(f"  ✗ {name} {d}")
    if _NOTES:
        print(f"\n\033[1m{len(_NOTES)} comportements observés (non-bloquants) :\033[0m")
        for name, value, note in _NOTES:
            line = f"  ◇ {name} → {value!r}"
            if note:
                line += f"  ({note})"
            print(line)
    return ok == total


def unique_name(prefix="tst"):
    _SHM_COUNTER[0] += 1
    return f"{prefix}_{_SHM_COUNTER[0]}_{uuid4().hex[:6]}"


def cleanup_shm(name):
    try:
        old = shared_memory.SharedMemory(name=name)
        old.close()
        old.unlink()
    except FileNotFoundError:
        pass


def make_ring(cap=4096):
    name = unique_name()
    cleanup_shm(name)
    return Ring(name=name, cap=cap, create=True, role="P"), name, cap


def destroy_ring(ring):
    for op in (ring.close, ring.unlink):
        try:
            op()
        except Exception:
            pass


class AdapterCtx:
    def __init__(self, capture_mode="normal", start_cmd=True, sleep_time=0.005,
                 cmd_maxsize=0, res_maxsize=0):
        FakeCapture.MODE = capture_mode
        self.parent_ring, self.ring_name, self.ring_cap = make_ring()
        self.cmd_q = mp.Queue(maxsize=cmd_maxsize)
        self.res_q = mp.Queue(maxsize=res_maxsize)
        self.stop_ev = mp.Event()
        self.cap_ev = mp.Event()
        self.adapter = ProcessCaptureAdapter(
            pcid=f"t-{uuid4().hex[:6]}",
            ring_args={"name": self.ring_name, "cap": self.ring_cap},
            refit_args={"session_id": "s"},
            capture_kwargs={"interface": "eth0"},
            command_queue=self.cmd_q,
            result_queue=self.res_q,
            stop_event=self.stop_ev,
            capture_event=self.cap_ev,
            log_interval=1.0,
            sleep_time=sleep_time,
        )
        self._thread = None
        if start_cmd:
            self._thread = threading.Thread(
                target=self.adapter._run_cmd_thread, daemon=True)
            self._thread.start()

    def request(self, attr, attr_for, is_callable=False, args=None, kwargs=None,
                timeout=2.0, rid=None):
        rid = rid if rid is not None else str(uuid4())
        self.cmd_q.put((rid, attr, attr_for, is_callable, args or [], kwargs or {}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                item = self.res_q.get(timeout=0.05)
            except _q.Empty:
                continue
            if item and item[0] == rid:
                return item
        return None

    def send_raw(self, payload, timeout=2.0):
        """Envoie un payload brut dans la queue. Renvoie ce qui sort (n'importe quoi)."""
        self.cmd_q.put(payload)
        try:
            return self.res_q.get(timeout=timeout)
        except _q.Empty:
            return "TIMEOUT"

    def shutdown(self):
        self.stop_ev.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        try:
            self.adapter._ring.close()
        except Exception:
            pass
        destroy_ring(self.parent_ring)


# ============================================================================
# SUITE A — Cycle de vie (idempotence, ordre, concurrency)
# ============================================================================
def suite_lifecycle():
    section("A. Cycle de vie torturé")

    # A.1 — stop() sans start()
    ctx = AdapterCtx(start_cmd=False)
    try:
        try:
            ctx.adapter.stop(timeout=0.5)
            observe("A.1 stop() sans start()", "aucune exception")
        except Exception as e:
            observe("A.1 stop() sans start()", f"{type(e).__name__}: {e}")
    finally:
        ctx.shutdown()

    # A.2 — start() deux fois → observe
    ctx = AdapterCtx(start_cmd=False)
    try:
        try:
            ctx.adapter.start()
            ctx.adapter.start()
            observe("A.2 start() deux fois", "aucune exception")
        except Exception as e:
            observe("A.2 start() deux fois", f"{type(e).__name__}: {e}")
    finally:
        ctx.shutdown()

    # A.3 — stop() deux fois de suite
    ctx = AdapterCtx(capture_mode="noop", start_cmd=False)
    try:
        ctx.adapter.start()
        ctx.adapter.stop(timeout=0.5)
        try:
            ctx.adapter.stop(timeout=0.5)
            observe("A.3 stop() deux fois", "aucune exception")
        except Exception as e:
            observe("A.3 stop() deux fois", f"{type(e).__name__}: {e}")
    finally:
        ctx.shutdown()

    # A.4 — restart après stop
    ctx = AdapterCtx(capture_mode="noop", start_cmd=False)
    try:
        ctx.adapter.start()
        ctx.adapter.stop(timeout=0.5)
        try:
            ctx.adapter.start()  # déjà stoppé, ring fermé
            observe("A.4 restart après stop", "aucune exception")
        except Exception as e:
            observe("A.4 restart après stop", f"{type(e).__name__}: {e}")
    finally:
        ctx.shutdown()

    # A.5 — run_cmd_thread lancé deux fois → duplique les réponses ?
    ctx = AdapterCtx(capture_mode="noop", start_cmd=False)
    try:
        t1 = threading.Thread(target=ctx.adapter._run_cmd_thread, daemon=True)
        t2 = threading.Thread(target=ctx.adapter._run_cmd_thread, daemon=True)
        t1.start()
        t2.start()
        time.sleep(0.05)
        rid = str(uuid4())
        ctx.cmd_q.put((rid, "dropped_packets", "capture", False, [], {}))
        seen = 0
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and seen < 2:
            try:
                item = ctx.res_q.get(timeout=0.1)
                if item and item[0] == rid:
                    seen += 1
            except _q.Empty:
                pass
        observe("A.5 deux command threads → doublons", seen,
                "2 = les deux threads ont traité la même requête")
    finally:
        ctx.shutdown()


# ============================================================================
# SUITE B — Requêtes malformées
# ============================================================================
def suite_malformed():
    section("B. Requêtes malformées")

    # B.1 — tuple trop court
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.send_raw(("rid1", "stats"))  # 2 éléments au lieu de 6
        observe("B.1 tuple 2 éléments", r, "si TIMEOUT, l'adapter a crashé")
        check("B.1b thread survit", ctx._thread.is_alive(),
              "le thread ne doit pas mourir sur input malformé")
    finally:
        ctx.shutdown()

    # B.2 — tuple trop long
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.send_raw(("rid2", "stats", "capture", True, [], {}, "extra", "junk"))
        observe("B.2 tuple 8 éléments", r)
        check("B.2b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # B.3 — payload non-tuple
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.send_raw("pas un tuple")
        observe("B.3 payload non-tuple", r)
        check("B.3b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # B.4 — None
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.send_raw(None)
        observe("B.4 payload None", r)
        check("B.4b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # B.5 — tuple vide
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.send_raw(())
        observe("B.5 tuple vide", r)
        check("B.5b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # B.6 — rid non-string (int)
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("dropped_packets", "capture", False, rid=12345)
        check("B.6 rid int préservé",
              r is not None and r[0] == 12345,
              f"r={r}")
    finally:
        ctx.shutdown()

    # B.7 — rid None
    ctx = AdapterCtx(capture_mode="noop")
    try:
        # None comme rid, mais on ne peut pas utiliser request() qui génère un uuid
        ctx.cmd_q.put((None, "dropped_packets", "capture", False, [], {}))
        try:
            item = ctx.res_q.get(timeout=1.0)
            observe("B.7 rid None", item[0] if item else None)
        except _q.Empty:
            observe("B.7 rid None", "TIMEOUT")
    finally:
        ctx.shutdown()

    # B.8 — args non-list (string) — observe
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("echo", "capture", True, args="abc")
        observe("B.8 args='abc' (string au lieu de list)", r)
    finally:
        ctx.shutdown()

    # B.9 — kwargs non-dict
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("echo", "capture", True, kwargs=[1, 2, 3])
        observe("B.9 kwargs=[1,2,3]", r)
    finally:
        ctx.shutdown()

    # B.10 — attr None
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request(None, "capture", False)
        observe("B.10 attr=None", r)
    finally:
        ctx.shutdown()

    # B.11 — attr_for None
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("stats", None, True)
        observe("B.11 attr_for=None", r)
    finally:
        ctx.shutdown()

    # B.12 — unicode dans attr
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("메서드", "capture", True)
        observe("B.12 attr unicode", r)
    finally:
        ctx.shutdown()

    # B.13 — attr avec caractères bizarres
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("__class__", "capture", False)
        observe("B.13 attr='__class__'", r,
                "fuite potentielle : retourne la classe de Capture")
    finally:
        ctx.shutdown()

    # B.14 — attr='__dict__' → fuite mémoire
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("__dict__", "capture", False)
        observe("B.14 attr='__dict__'", r,
                "contient éventuellement des références non picklables")
    finally:
        ctx.shutdown()


# ============================================================================
# SUITE C — Attributs qui explosent
# ============================================================================
def suite_attr_torture():
    section("C. Attributs qui explosent")

    # C.1 — property qui lève
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("raises_on_access", "capture", False)
        observe("C.1 property qui lève", r,
                "si None, l'adapter a crashé sur le getattr")
        check("C.1b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # C.2 — méthode qui lève
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("raises_on_call", "capture", True)
        observe("C.2 méthode qui lève", r)
        check("C.2b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # C.3 — méthode avec mauvais nombre d'args
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("needs_two_args", "capture", True, args=[1])
        observe("C.3 args insuffisants", r)
        check("C.3b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # C.4 — méthode avec kwargs inattendus
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("needs_two_args", "capture", True, args=[1], kwargs={"z": 3})
        observe("C.4 kwargs inattendus", r)
        check("C.4b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()


# ============================================================================
# SUITE D — Réponses tordues
# ============================================================================
def suite_response_torture():
    section("D. Réponses tordues")

    # D.1 — réponse énorme (5 Mo)
    ctx = AdapterCtx(capture_mode="noop")
    try:
        t0 = time.monotonic()
        r = ctx.request("huge_response", "capture", True, timeout=5.0)
        dt = time.monotonic() - t0
        ok = r is not None and isinstance(r[-1], bytes) and len(r[-1]) == 5 * 1024 * 1024
        check("D.1 réponse 5 Mo reçue", ok, f"en {dt*1000:.0f} ms")
    finally:
        ctx.shutdown()

    # D.2 — réponse imbriquée profonde
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("nested_deep", "capture", True, kwargs={"depth": 30})
        ok = r is not None and isinstance(r[-1], dict)
        check("D.2 réponse imbriquée 30 niveaux", ok)
    finally:
        ctx.shutdown()

    # D.3 — réponse cyclique
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("cyclic", "capture", True, timeout=1.0)
        observe("D.3 réponse cyclique", r, "pickle gère les cycles nativement")
    finally:
        ctx.shutdown()

    # D.4 — réponse avec lambda (non picklable)
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("with_lambda", "capture", True, timeout=1.0)
        observe("D.4 réponse avec lambda", r, "non picklable → feeder thread va crier")
        time.sleep(0.1)
        check("D.4b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # D.5 — réponse avec memoryview
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("with_memoryview", "capture", True, timeout=1.0)
        observe("D.5 réponse avec memoryview", r, "memoryview non picklable")
        check("D.5b thread survit", ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # D.6 — réponse avec bytearray (picklable)
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("with_bytearray", "capture", True)
        observe("D.6 réponse bytearray", r,
                "bytearray picklable, devrait passer")
    finally:
        ctx.shutdown()


# ============================================================================
# SUITE E — Stress : milliers de requêtes
# ============================================================================
def suite_stress():
    section("E. Stress : milliers de requêtes")

    # E.1 — 500 requêtes en rafale, vérifier qu'aucune n'est perdue
    ctx = AdapterCtx(capture_mode="noop", sleep_time=0.001)
    try:
        N = 500
        rids = [str(uuid4()) for _ in range(N)]
        t0 = time.monotonic()
        for rid in rids:
            ctx.cmd_q.put((rid, "dropped_packets", "capture", False, [], {}))
        seen = set()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and len(seen) < N:
            try:
                item = ctx.res_q.get(timeout=0.1)
                if item and item[0] in rids:
                    seen.add(item[0])
            except _q.Empty:
                pass
        dt = time.monotonic() - t0
        check(f"E.1 {N} requêtes, aucune perdue",
              len(seen) == N,
              f"{len(seen)}/{N} en {dt*1000:.0f} ms ({N/dt:.0f} req/s)")
    finally:
        ctx.shutdown()

    # E.2 — proxy appelé depuis 10 threads en parallèle
    proxy_testable = True
    try:
        # On a besoin de vrais workers pour ce test → on lance des process
        ctx_mp = mp.get_context("fork")

        def worker(pcid, ring_name, cap, cmd_q, res_q, stop_ev, cap_ev, ready_ev):
            try:
                a = ProcessCaptureAdapter(
                    pcid=pcid,
                    ring_args={"name": ring_name, "cap": cap},
                    refit_args={"session_id": pcid},
                    capture_kwargs={},
                    command_queue=cmd_q,
                    result_queue=res_q,
                    stop_event=stop_ev,
                    capture_event=cap_ev,
                    log_interval=10.0,
                )
                a.start()
                ready_ev.set()
                stop_ev.wait()
                a.stop(timeout=1.0)
            except Exception:
                traceback.print_exc()
                ready_ev.set()

        cap = 1 << 12
        names = []
        parent_rings = []
        entries = []
        workers = []
        for i in range(3):
            name = unique_name(f"str{i}")
            cleanup_shm(name)
            parent_rings.append(Ring(name=name, cap=cap, create=True, role="P"))
            names.append(name)

        for i, name in enumerate(names):
            cmd_q = ctx_mp.Queue()
            res_q = ctx_mp.Queue()
            stop_ev = ctx_mp.Event()
            cap_ev = ctx_mp.Event()
            ready_ev = ctx_mp.Event()
            entries.append([f"pc{i}", cmd_q, res_q, stop_ev, cap_ev])
            p = ctx_mp.Process(target=worker,
                               args=(f"pc{i}", name, cap, cmd_q, res_q,
                                     stop_ev, cap_ev, ready_ev),
                               daemon=True)
            p.start()
            workers.append((p, stop_ev, cap_ev, ready_ev))

        for _, _, _, rdy in workers:
            rdy.wait(timeout=5.0)

        proxy = CaptureProxy(entries)

        results_lock = threading.Lock()
        all_results = []
        errors = []

        def caller(k):
            try:
                for _ in range(30):
                    r = proxy.dropped_packets()
                    with results_lock:
                        all_results.append((k, r))
            except Exception as e:
                errors.append((k, repr(e)))

        threads = [threading.Thread(target=caller, args=(k,), daemon=True)
                   for k in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        check("E.2 10 threads × 30 appels sans erreur",
              len(errors) == 0, f"erreurs={errors[:3]}")
        empties = sum(1 for _, r in all_results if r == {})
        check("E.2b aucun résultat vide",
              empties == 0,
              f"{empties}/{len(all_results)} vides — race dans found_result ?")

        for p, stop_ev, cap_ev, _ in workers:
            stop_ev.set(); cap_ev.set()
        for p, *_ in workers:
            p.join(timeout=2.0)
        for r in parent_rings:
            destroy_ring(r)

    except Exception:
        traceback.print_exc()


# ============================================================================
# SUITE F — Proxy : cas tordus
# ============================================================================
def suite_proxy_torture():
    section("F. Proxy torturé")

    # F.1 — entries vide
    p = CaptureProxy([])
    check("F.1 proxy sans items → dict vide", p.items == {})
    check("F.1b _do_request sans queue → {}", p._do_request(str(uuid4()), "x", "capture", False, [], {}) == {})

    # F.2 — pcid dupliqué (même clé deux fois)
    q1, q2 = mp.Queue(), mp.Queue()
    entries = [
        ["same", q1, mp.Queue(), mp.Event(), mp.Event()],
        ["same", q2, mp.Queue(), mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    check("F.2 pcid dupliqué → 1 seule entrée", len(p.items) == 1)
    observe("F.2 dernier écrase le premier",
            list(p.items.keys()),
            "q2 est celui qui reste")

    # F.3 — get_pcid collision après libération d'id
    q_a = mp.Queue()
    entries = [["a", q_a, mp.Queue(), mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    id_a = id(q_a)
    del q_a
    gc.collect()
    q_c = mp.Queue()
    # Si id(q_c) == id_a par réutilisation, get_pcid va mentir
    observe("F.3 id réutilisé après del",
            (id_a, id(q_c)),
            "si égaux → get_pcid ment" if id(q_c) == id_a else "OK, pas de collision")

    # F.4 — found_result avec 1000 messages, aucun match
    q_res = mp.Queue()
    for i in range(1000):
        q_res.put((f"filler-{i}", None, False, i))
    entries = [["a", mp.Queue(), q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    t0 = time.monotonic()
    r = p._do_request(str(uuid4()), "x", "capture", False, [], {})
    dt = time.monotonic() - t0
    observe("F.4 1000 messages sans match",
            f"{dt*1000:.0f} ms",
            "devrait être rapide si remis en queue proprement")

    # F.5 — _do_request avec timeout=0 → observe
    q_res = mp.Queue()
    entries = [["a", mp.Queue(), q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    try:
        r = p._do_request(str(uuid4()), "x", "capture", False, [], {}, timeout=0)
        observe("F.5 timeout=0", r)
    except Exception as e:
        observe("F.5 timeout=0", f"{type(e).__name__}: {e}")

    # F.6 — même proxy appelé récursivement (deadlock potentiel si lock non-RLock)
    # skip — nécessiterait du multi-process


# ============================================================================
# SUITE G — Mort de worker
# ============================================================================
def suite_worker_death():
    section("G. Mort d'un worker en cours de route")

    ctx_mp = mp.get_context("fork")

    def worker_quick(ring_name, cap, cmd_q, res_q, stop_ev, cap_ev, ready_ev):
        try:
            a = ProcessCaptureAdapter(
                pcid="dying",
                ring_args={"name": ring_name, "cap": cap},
                refit_args={"session_id": "d"},
                capture_kwargs={},
                command_queue=cmd_q,
                result_queue=res_q,
                stop_event=stop_ev,
                capture_event=cap_ev,
                log_interval=10.0,
            )
            a.start()
            ready_ev.set()
            time.sleep(0.3)
            # Simulation : le worker meurt brutalement
        except Exception:
            traceback.print_exc()
            ready_ev.set()

    cap = 1 << 12
    name = unique_name("dead")
    cleanup_shm(name)
    parent_ring = Ring(name=name, cap=cap, create=True, role="P")

    cmd_q = ctx_mp.Queue()
    res_q = ctx_mp.Queue()
    stop_ev = ctx_mp.Event()
    cap_ev = ctx_mp.Event()
    ready_ev = ctx_mp.Event()
    p = ctx_mp.Process(target=worker_quick,
                       args=(name, cap, cmd_q, res_q, stop_ev, cap_ev, ready_ev),
                       daemon=True)
    p.start()
    ready_ev.wait(timeout=5.0)
    time.sleep(0.1)

    entries = [["dying", cmd_q, res_q, stop_ev, cap_ev]]
    proxy = CaptureProxy(entries)

    # G.1 — requête avant la mort
    r1 = proxy.dropped_packets()
    observe("G.1 requête avant la mort du worker", r1)

    # Attendre la mort effective
    time.sleep(0.5)
    p.join(timeout=1.0)

    # G.2 — requête après la mort → doit timeout, pas crasher
    t0 = time.monotonic()
    r2 = proxy.dropped_packets()
    dt = time.monotonic() - t0
    observe("G.2 requête après la mort",
            f"r={r2} en {dt:.2f} s",
            "devrait timeout proprement")

    try:
        stop_ev.set()
        cap_ev.set()
    except Exception:
        pass
    destroy_ring(parent_ring)


# ============================================================================
# SUITE H — Mémoire et fuites
# ============================================================================
def suite_leaks():
    section("H. Fuites (détection légère)")

    # H.1 — 1000 requêtes, vérifier que la mémoire ne croît pas linéairement
    import gc as _gc
    ctx = AdapterCtx(capture_mode="noop")
    try:
        # Warm-up
        for _ in range(50):
            ctx.request("dropped_packets", "capture", False)
        _gc.collect()
        # Snapshot
        import sys as _sys
        objs_avant = len(_gc.get_objects())

        for _ in range(500):
            ctx.request("stats", "capture", True)

        _gc.collect()
        objs_apres = len(_gc.get_objects())
        delta = objs_apres - objs_avant
        observe("H.1 500 requêtes → Δ objets",
                delta,
                "acceptable < 100 ; suspect > 500")
        check("H.1b pas de fuite massive", delta < 1000, f"Δ={delta}")
    finally:
        ctx.shutdown()

    # H.2 — vérifier que les threads ne s'accumulent pas
    n_threads_avant = threading.active_count()
    for _ in range(5):
        ctx = AdapterCtx(capture_mode="noop")
        ctx.shutdown()
    time.sleep(0.1)
    n_threads_apres = threading.active_count()
    check("H.2 pas de fuite de threads",
          abs(n_threads_apres - n_threads_avant) <= 2,
          f"{n_threads_avant} → {n_threads_apres}")


# ============================================================================
# SUITE I — Ring torture
# ============================================================================
def suite_ring_torture():
    section("I. Ring torturé")

    # I.1 — put avant que le reader soit prêt (bug classique)
    name = unique_name()
    cleanup_shm(name)
    r_creator = Ring(name=name, cap=4096, create=True, role="P")

    # Un writer attache et écrit tout de suite
    import multiprocessing as _mp
    ctx = _mp.get_context("fork")

    def writer_immediate(name, cap, done_ev):
        try:
            r = Ring(name=name, cap=cap, create=False, role="W")
            for i in range(50):
                pkt = f"pkt-{i}".encode()
                r.put(pkt, 1000.0 + i)
            r.close()
            done_ev.set()
        except Exception as e:
            print(f"[writer] {e}")
            done_ev.set()

    done_ev = ctx.Event()
    p = ctx.Process(target=writer_immediate, args=(name, 4096, done_ev), daemon=True)
    p.start()
    done_ev.wait(timeout=5.0)

    # Le parent lit
    n_lus = 0
    for _ in range(100):
        ts, pkt = r_creator.get()
        if ts is None:
            break
        n_lus += 1
    check("I.1 writer écrit avant reader lit", n_lus == 50, f"lus={n_lus}")

    destroy_ring(r_creator)

    # I.2 — put jusqu'à saturation puis re-remplissage
    name = unique_name()
    cleanup_shm(name)
    r = Ring(name=name, cap=512, create=True, role="P")
    try:
        # Remplir jusqu'à saturation
        count = 0
        while r.put(b"X" * 40, 1000.0):
            count += 1
            if count > 1000:
                break
        observe("I.2 saturé à", f"{count} paquets de 40 o sur 512 o de cap")

        # Vider tout
        drained = 0
        while True:
            ts, pkt = r.get()
            if ts is None:
                break
            drained += 1
        check("I.2b drain complet", drained == count, f"{drained}/{count}")
    finally:
        destroy_ring(r)


# ============================================================================
# MAIN
# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", default="all",
                    choices=["all", "lifecycle", "malformed", "attr",
                             "response", "stress", "proxy", "death",
                             "leaks", "ring"])
    args = ap.parse_args()

    print("\033[1m" + "=" * 78)
    print(" TORTURE TEST : ProcessCaptureAdapter <-> CaptureProxy")
    print("=" * 78 + "\033[0m")

    sections = {
        "lifecycle": suite_lifecycle,
        "malformed": suite_malformed,
        "attr":      suite_attr_torture,
        "response":  suite_response_torture,
        "stress":    suite_stress,
        "proxy":     suite_proxy_torture,
        "death":     suite_worker_death,
        "leaks":     suite_leaks,
        "ring":      suite_ring_torture,
    }

    if args.section == "all":
        for fn in sections.values():
            try:
                fn()
            except Exception:
                traceback.print_exc()
                _RESULTS.append((f"section {fn.__name__}", False,
                                 "exception non gérée"))
    else:
        try:
            sections[args.section]()
        except Exception:
            traceback.print_exc()

    ok = summarize()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())