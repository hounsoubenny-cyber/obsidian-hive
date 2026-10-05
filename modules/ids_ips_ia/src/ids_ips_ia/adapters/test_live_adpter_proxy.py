#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_live_adapter_proxy.py — test live pour ProcessCaptureAdapter <-> CaptureProxy.

Version 3 : rings RÉELS (ring.py), Capture/RefitQueue mockés via sys.modules.
Les fakes sont injectés AVANT tout import de ids_ips_ia.adapters.* — sinon le
`from ids_ips_ia.core.capture import Capture` de l'adapter ramasse la VRAIE classe
et la signature ne correspond plus.

Usage :
    python test_live_adapter_proxy.py

Linux/macOS uniquement (fork + shared_memory).
"""
import sys
import types
import threading
import multiprocessing as mp
import time
import traceback
import importlib.util
import queue as _q
from multiprocessing import shared_memory
from uuid import uuid4


# ============================================================================
# 1) FAKES — INJECTÉS AVANT TOUT IMPORT `ids_ips_ia.*`
# ============================================================================
class FakeCapture:
    """Capture simulée : écrit sur le RingWriter (réel) et pousse dans le RefitQueue (fake)."""

    def __init__(self, queue=None, log_interval=10.0, backup_queue=None, event=None,
                 *args, **kwargs):
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

    def capture(self, *args, **kwargs):        # accepte TOUT (interface, bpf, ...)
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="FakeCapture")
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
                except _q.Full:
                    self._dropped += 1
                except Exception:
                    self._dropped += 1
            if self.backup_queue is not None:
                try:
                    self.backup_queue.put((ts, raw))
                except Exception:
                    pass

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

    def snapshot(self):
        return {"packets": self._packets, "ignored": sorted(self._ignored_ips)}

    def metrics(self):
        return {"metric": True, **self.stats()}


class FakeRefitQueue:
    """RefitQueue simulée : garde tout en mémoire, API identique à la vraie."""
    def __init__(self, session_id="test", tag="t", *args, **kwargs):
        self.session_id = session_id
        self.tag = tag
        self.kwargs = kwargs
        self.stop_event = threading.Event()
        self._thread = None
        self._items = []
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False

    def start(self):
        if self._started:
            return
        self._started = True
        self.stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name=f"FakeRefitQueue-{self.session_id}")
        self._thread.start()

    def _loop(self):
        while not self.stop_event.wait(0.05):
            pass

    def stop(self, timeout=5.0):
        self._stopped = True
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def put(self, item) -> bool:
        with self._lock:
            self._items.append(item)
        return True

    put_nowait = put

    def put_many(self, items) -> int:
        with self._lock:
            self._items.extend(items)
        return len(items)

    def get(self):
        with self._lock:
            return self._items.pop(0) if self._items else None

    def stats(self) -> dict:
        with self._lock:
            n = len(self._items)
        return {"queued": n, "started": self._started, "stopped": self._stopped,
                "session_id": self.session_id, "tag": self.tag}


# --- INJECTION AVANT LES IMPORTS RÉELS ------------------------------------
# Note : ces ModuleType n'ont pas besoin d'un vrai parent package pour être
# résolus par `from ids_ips_ia.core.capture import Capture`. Python regarde
# sys.modules en premier.
_fake_capture_mod = types.ModuleType("ids_ips_ia.core.capture")
_fake_capture_mod.Capture = FakeCapture
sys.modules["ids_ips_ia.core.capture"] = _fake_capture_mod

_fake_refit_mod = types.ModuleType("ids_ips_ia.refit_system.refit_queue")
_fake_refit_mod.RefitQueue = FakeRefitQueue
sys.modules["ids_ips_ia.refit_system.refit_queue"] = _fake_refit_mod


# ============================================================================
# 2) MAINTENANT : imports réels — ils vont ramasser les fakes
# ============================================================================
import ids_ips_ia.memory_managers.ring as ring_mod
import ids_ips_ia.adapters.capture_proxy as capture_proxy_mod
import ids_ips_ia.adapters.process_capture_adapter as process_adapter_mod

Ring = ring_mod.Ring
RingWriter = ring_mod.RingWriter
MultiReader = ring_mod.MultiReader
RingQueue = ring_mod.RingQueue
ProcessCaptureAdapter = process_adapter_mod.ProcessCaptureAdapter
CaptureProxy = capture_proxy_mod.CaptureProxy


# Sanity-check : l'adapter doit voir le FAKE, pas la vraie classe.
from ids_ips_ia.core.capture import Capture as _C
assert _C is FakeCapture, (
    f"L'adapter voit toujours le vrai Capture ({_C!r}). "
    f"L'injection des fakes doit se faire AVANT l'import de process_capture_adapter."
)


# ============================================================================
# 3) Worker (dans un sous-process, après fork)
# ============================================================================
def worker(pcid, ring_name, ring_cap, refit_args, cmd_q, res_q, stop_ev, cap_ev, ready_ev):
    try:
        adapter = ProcessCaptureAdapter(
            pcid=pcid,
            ring_args={"name": ring_name, "cap": ring_cap},
            refit_args=refit_args,
            capture_kwargs={"interface": "eth0"},
            command_queue=cmd_q,
            result_queue=res_q,
            stop_event=stop_ev,
            capture_event=cap_ev,
            log_interval=2.0,
            sleep_time=0.001,
        )
        adapter.start()
        ready_ev.set()
        stop_ev.wait()
        adapter.stop(timeout=2.0)
    except Exception:
        print(f"\n[worker {pcid}] EXCEPTION :", flush=True)
        traceback.print_exc()
        ready_ev.set()
        raise


# ============================================================================
# 4) Helpers
# ============================================================================
def _try(label, fn):
    print(f"\n--- {label} ---")
    try:
        r = fn()
        print(f"    retour : {r!r}")
        return r
    except Exception:
        traceback.print_exc()
        return None


def _cleanup_shm(name):
    try:
        old = shared_memory.SharedMemory(name=name)
        old.close()
        old.unlink()
        print(f"   (ancien bloc {name} supprimé)")
    except FileNotFoundError:
        pass


def _drain(ring, max_items=100_000):
    n = 0
    while n < max_items:
        ts, pkt = ring.get()
        if ts is None:
            break
        n += 1
    return n


def _shutdown(workers, parent_rings):
    print("\n[main] Arrêt des workers…")
    for (_, stop_ev, cap_ev, _) in workers:
        try:
            stop_ev.set()
            cap_ev.set()
        except Exception:
            pass
    for (proc, *_r) in workers:
        proc.join(timeout=3.0)
        if proc.is_alive():
            print(f"[main] {proc.name} toujours vivant → terminate()")
            proc.terminate()
            proc.join(timeout=1.0)
    for ring in parent_rings:
        try:
            ring.close()
        except Exception:
            pass
        try:
            ring.unlink()
        except Exception:
            pass


# ============================================================================
# 5) Test live
# ============================================================================
def main():
    print("=" * 78)
    print(" TEST LIVE : ProcessCaptureAdapter  <->  CaptureProxy")
    print("             (rings RÉELS via ring.py, Capture/RefitQueue mockés)")
    print("=" * 78)

    if sys.platform.startswith("win"):
        print("Ce test utilise fork + shared_memory : Linux/macOS uniquement.", file=sys.stderr)
        sys.exit(2)

    ctx = mp.get_context("fork")

    pcs = ["pc-alpha", "pc-beta"]
    ring_cap = 1 << 16
    parent_rings = []
    entries = []
    workers = []

    # 1) Rings côté parent
    for pcid in pcs:
        name = f"ring-{pcid}"
        _cleanup_shm(name)
        r = Ring(name=name, cap=ring_cap, create=True, role="P")
        parent_rings.append(r)
        print(f"   ring {name} créé (cap={ring_cap} o)")

    # 2) Workers
    for pcid in pcs:
        cmd_q = ctx.Queue()
        res_q = ctx.Queue()
        stop_ev = ctx.Event()
        cap_ev = ctx.Event()
        ready_ev = ctx.Event()
        entries.append([pcid, cmd_q, res_q, stop_ev, cap_ev])
        proc = ctx.Process(
            target=worker,
            args=(pcid, f"ring-{pcid}", ring_cap,
                  {"session_id": pcid, "tag": pcid, "save_interval": 30.0},
                  cmd_q, res_q, stop_ev, cap_ev, ready_ev),
            name=f"worker-{pcid}",
            daemon=True,
        )
        proc.start()
        workers.append((proc, stop_ev, cap_ev, ready_ev))

    for (_, _, _, rdy) in workers:
        rdy.wait(timeout=5.0)
    print(f"\n[main] {len(workers)} worker(s) prêts : {pcs}")
    time.sleep(0.4)

    # 3) CaptureProxy
    print("\n--- Construction de CaptureProxy ---")
    try:
        proxy = CaptureProxy(entries)
        print(f"    pcid connus : {list(proxy.items.keys())}")
    except Exception:
        traceback.print_exc()
        _shutdown(workers, parent_rings)
        return

    # 4) Requêtes sur capture
    _try("proxy.stats()", proxy.stats)
    _try("proxy.metrics()", proxy.metrics)
    _try("proxy.dropped_packets()  (attr non callable)", proxy.dropped_packets)
    _try("proxy.snapshot()", proxy.snapshot)
    _try("proxy.add_src_ip_to_ignore('10.0.0.42')",
         lambda: proxy.add_src_ip_to_ignore("10.0.0.42"))
    _try("proxy.remove_src_ip_to_ignore('10.0.0.42')",
         lambda: proxy.remove_src_ip_to_ignore("10.0.0.42"))

    # 5) Cas limites
    _try("attribut inexistant sur capture",
         lambda: proxy._do_request(str(uuid4()), "n_existe_pas", "capture", False, [], {}))
    _try("attr_for inconnu",
         lambda: proxy._do_request(str(uuid4()), "x", "personne", False, [], {}))
    _try("attr interne '_pcid' sur self",
         lambda: proxy._do_request(str(uuid4()), "_pcid", "self", False, [], {}))

    # 6) ring / refit_queue via proxy
    _try("ring.stats() via proxy",
         lambda: proxy._do_request(str(uuid4()), "stats", "ring", True, [], {}))
    _try("refit_queue.stats() via proxy",
         lambda: proxy._do_request(str(uuid4()), "stats", "refit_queue", True, [], {}))

    # 7) Remplissage réel des rings
    print("\n--- Contenu des rings après ~1 s de capture ---")
    for r in parent_rings:
        n_write, n_read, w_pos, r_pos, used, free = r._all()
        print(f"    {r.name} : n_write={n_write} n_read={n_read} used={used} free={free}")

    # 8) Drain
    print(f"\n--- Drain du ring-{pcs[0]} ---")
    try:
        drained = _drain(parent_rings[0])
        print(f"    {drained} paquets lus dans ring-{pcs[0]}")
    except Exception:
        traceback.print_exc()

    # 9) get_pcid
    print("\n--- get_pcid sur chaque queue connue ---")
    for pcid, item in proxy.items.items():
        for label, q in (("cmd", item.cmd_queue), ("res", item.result_queue)):
            try:
                found = proxy.get_pcid(id(q))
                print(f"    {label}_queue de {pcid} -> get_pcid = {found!r}")
            except Exception:
                traceback.print_exc()

    _shutdown(workers, parent_rings)

    print("\n" + "=" * 78)
    print(" FIN")
    print("=" * 78)


if __name__ == "__main__":
    main()