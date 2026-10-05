#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Oct  5 09:27:08 2026

@author: hounsousamuel
"""


"""
test_complet_adapter_proxy.py

Suite complète pour ProcessCaptureAdapter <-> CaptureProxy.
Couvre : constructeur, thread de commandes, cas d'erreur, cas subtils,
proxy (do_request, found_result, get_pcid) et intégration multi-process.

Les fakes sont injectés AVANT tout import de ids_ips_ia.adapters.*.

Usage :
    python test_complet_adapter_proxy.py
    python test_complet_adapter_proxy.py --skip-integration
"""
import argparse
import sys
import threading
import multiprocessing as mp
import time
import traceback
import queue as _q
import importlib.util
from multiprocessing import shared_memory
from uuid import uuid4
import types


# ============================================================================
# 1) FAKES — INJECTÉS AVANT TOUT IMPORT ids_ips_ia.adapters.*
# ============================================================================
class FakeCapture:
    """Capture simulée. Le mode se règle via FakeCapture.MODE (class-level)."""
    MODE = "normal"   # "normal" | "noop" | "raises" | "bad_dropped"

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

    def capture(self, *args, **kwargs):
        if FakeCapture.MODE == "noop":
            return
        if FakeCapture.MODE == "raises":
            raise RuntimeError("fake capture boom")
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
        if FakeCapture.MODE == "bad_dropped":
            # Mauvais usage : on retourne une méthode au lieu d'un int.
            return lambda: self._dropped
        return self._dropped

    def snapshot(self):
        return {"packets": self._packets, "ignored": sorted(self._ignored_ips)}

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
        self._items = []
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False

    def start(self):
        if self._started:
            return
        self._started = True
        self.stop_event.clear()
        self._thread = threading.Thread(target=lambda: self.stop_event.wait(3600),
                                        daemon=True, name=f"FakeRefitQueue-{self.session_id}")
        self._thread.start()

    def stop(self, timeout=5.0):
        self._stopped = True
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def put(self, item):
        with self._lock:
            self._items.append(item)
        return True

    put_nowait = put

    def put_many(self, items):
        with self._lock:
            self._items.extend(items)
        return len(items)

    def get(self):
        with self._lock:
            return self._items.pop(0) if self._items else None

    def stats(self):
        with self._lock:
            n = len(self._items)
        return {"queued": n, "started": self._started, "stopped": self._stopped,
                "session_id": self.session_id, "tag": self.tag}


# --- Injection --------------------------------------------------------------
_fc = types.ModuleType("ids_ips_ia.core.capture")
_fc.Capture = FakeCapture
sys.modules["ids_ips_ia.core.capture"] = _fc

_fr = types.ModuleType("ids_ips_ia.refit_system.refit_queue")
_fr.RefitQueue = FakeRefitQueue
sys.modules["ids_ips_ia.refit_system.refit_queue"] = _fr


# ============================================================================
# 2) IMPORTS RÉELS (après les fakes)
# ============================================================================
import ids_ips_ia.memory_managers.ring as ring_mod
import ids_ips_ia.adapters.capture_proxy as proxy_mod
import ids_ips_ia.adapters.process_capture_adapter as adapter_mod

Ring = ring_mod.Ring
ProcessCaptureAdapter = adapter_mod.ProcessCaptureAdapter
CaptureProxy = proxy_mod.CaptureProxy

from ids_ips_ia.core.capture import Capture as _C
assert _C is FakeCapture, "Les fakes ont été injectés trop tard !"


# ============================================================================
# 3) HARNESS
# ============================================================================
_RESULTS = []
_SHM_COUNTER = [0]


def check(name, cond, detail=""):
    _RESULTS.append((name, bool(cond), detail))
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  \033[90m[{detail}]\033[0m" if detail else ""))


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
    return ok == total


def unique_name(prefix="ring"):
    _SHM_COUNTER[0] += 1
    return f"{prefix}_{_SHM_COUNTER[0]}_{uuid4().hex[:8]}"


def cleanup_shm(name):
    try:
        old = shared_memory.SharedMemory(name=name)
        old.close()
        old.unlink()
    except FileNotFoundError:
        pass


def make_ring(cap=4096):
    name = unique_name("tst")
    cleanup_shm(name)
    return Ring(name=name, cap=cap, create=True, role="P"), name, cap


def destroy_ring(ring):
    try:
        ring.close()
    except Exception:
        pass
    try:
        ring.unlink()
    except Exception:
        pass


class AdapterCtx:
    """Contexte : crée un adapter prêt à l'emploi, thread commande démarré manuellement."""
    def __init__(self, capture_mode="normal", start_cmd=True, start_capture=False):
        FakeCapture.MODE = capture_mode
        self.parent_ring, self.ring_name, self.ring_cap = make_ring()
        self.cmd_q = mp.Queue()
        self.res_q = mp.Queue()
        self.stop_ev = mp.Event()
        self.cap_ev = mp.Event()
        self.adapter = ProcessCaptureAdapter(
            pcid=f"test-{uuid4().hex[:6]}",
            ring_args={"name": self.ring_name, "cap": self.ring_cap},
            refit_args={"session_id": "s"},
            capture_kwargs={"interface": "eth0"},
            command_queue=self.cmd_q,
            result_queue=self.res_q,
            stop_event=self.stop_ev,
            capture_event=self.cap_ev,
            log_interval=1.0,
            sleep_time=0.005,
        )
        self._thread = None
        if start_cmd:
            self._thread = threading.Thread(
                target=self.adapter._run_cmd_thread, daemon=True)
            self._thread.start()
        if start_capture:
            self.adapter._start_capture()

    def request(self, attr, attr_for, is_callable=False, args=None, kwargs=None, timeout=2.0):
        rid = str(uuid4())
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
# 4) SUITE 1 : Validation du constructeur
# ============================================================================
def suite_constructor():
    section("1. Validation du constructeur")

    ring, name, cap = make_ring()
    try:
        # 1.1 ring_args non dict
        try:
            ProcessCaptureAdapter(
                pcid="x", ring_args="not a dict", refit_args={},
                capture_kwargs={},
                command_queue=mp.Queue(), result_queue=mp.Queue(),
                stop_event=mp.Event())
            check("1.1 ring_args non-dict rejeté", False)
        except TypeError:
            check("1.1 ring_args non-dict rejeté", True)

        # 1.2 command_queue non-Queue
        try:
            ProcessCaptureAdapter(
                pcid="x", ring_args={"name": name, "cap": cap}, refit_args={},
                capture_kwargs={},
                command_queue="pas une queue", result_queue=mp.Queue(),
                stop_event=mp.Event())
            check("1.2 command_queue non-Queue rejeté", False)
        except TypeError:
            check("1.2 command_queue non-Queue rejeté", True)

        # 1.3 stop_event non-Event
        try:
            ProcessCaptureAdapter(
                pcid="x", ring_args={"name": name, "cap": cap}, refit_args={},
                capture_kwargs={},
                command_queue=mp.Queue(), result_queue=mp.Queue(),
                stop_event="pas un event")
            check("1.3 stop_event non-Event rejeté", False)
        except TypeError:
            check("1.3 stop_event non-Event rejeté", True)

        # 1.4 ring_args role/create écrasés
        ring_args = {"name": name, "cap": cap, "role": "R", "create": True}
        a = ProcessCaptureAdapter(
            pcid="x", ring_args=ring_args, refit_args={}, capture_kwargs={},
            command_queue=mp.Queue(), result_queue=mp.Queue(),
            stop_event=mp.Event())
        check("1.4 role/create écrasés en W/False",
              ring_args["role"] == "W" and ring_args["create"] is False,
              f"role={ring_args['role']}, create={ring_args['create']}")
        a._ring.close()
    finally:
        destroy_ring(ring)


# ============================================================================
# 5) SUITE 2 : Thread de commandes — happy path
# ============================================================================
def suite_cmd_happy():
    section("2. Commandes — cas normaux")
    ctx = AdapterCtx(capture_mode="noop")
    try:
        # 2.1 attribut simple sur capture (property)
        r = ctx.request("dropped_packets", "capture", False)
        check("2.1 property sur capture", r is not None and r[-1] == 0,
              f"r={r}")

        # 2.2 méthode sans args
        r = ctx.request("stats", "capture", True)
        check("2.2 méthode sans args", r is not None and isinstance(r[-1], dict),
              f"r={r}")

        # 2.3 args positionnels
        r = ctx.request("add_src_ip_to_ignore", "capture", True,
                        args=["10.0.0.42"])
        check("2.3 args positionnels", r is not None and r[-1] is True)

        # 2.4 kwargs
        r = ctx.request("echo", "capture", True,
                        kwargs={"a": 1, "b": "x"})
        check("2.4 kwargs transmis",
              r is not None and r[-1] == {"args": [], "kwargs": {"a": 1, "b": "x"}},
              f"r={r}")

        # 2.5 args + kwargs mélangés
        r = ctx.request("echo", "capture", True, args=[1, 2], kwargs={"z": 3})
        check("2.5 args + kwargs",
              r is not None and r[-1] == {"args": [1, 2], "kwargs": {"z": 3}})

        # 2.6 attr_for="self"
        r = ctx.request("_pcid", "self", False)
        check("2.6 attr_for=self", r is not None and r[-1].startswith("test-"),
              f"r={r}")

        # 2.7 attr_for="ring" (attribut public)
        r = ctx.request("cap", "ring", False)
        check("2.7 attr_for=ring sur .cap", r is not None and r[-1] == 4096)

        # 2.8 attr_for="refit_queue"
        r = ctx.request("stats", "refit_queue", True)
        check("2.8 attr_for=refit_queue", r is not None and isinstance(r[-1], dict))
    finally:
        ctx.shutdown()


# ============================================================================
# 6) SUITE 3 : Thread de commandes — erreurs
# ============================================================================
def suite_cmd_errors():
    section("3. Commandes — cas d'erreur")
    ctx = AdapterCtx(capture_mode="noop")
    try:
        # 3.1 attr inexistant
        r = ctx.request("n_existe_pas", "capture", False)
        check("3.1 attr inexistant → ATTR_NOT_FOUND",
              r is not None and r[1] == "ATTR_NOT_FOUND" and r[2] is True,
              f"r={r}")

        # 3.2 attr_for inconnu
        r = ctx.request("x", "personne", False)
        check("3.2 attr_for inconnu → UNKNOW_VALUE_FOR_ATTR_FOR",
              r is not None and r[1] == "UNKNOW_VALUE_FOR_ATTR_FOR" and r[2] is True,
              f"r={r}")

        # 3.3 is_callable=True sur un non-callable (property int)
        r = ctx.request("dropped_packets", "capture", True)
        check("3.3 is_callable=True sur property → erreur",
              r is not None and r[2] is True
              and r[1] == "REQUEST_CALLABLE_ARG_WHO_IS_NOT_CALLABLE",
              f"r={r}")

        # 3.4 is_callable=False sur une méthode
        r = ctx.request("stats", "capture", False)
        check("3.4 is_callable=False sur méthode → erreur",
              r is not None and r[2] is True
              and r[1] == "REQUEST_NOT_CALLABLE_ARG_WHO_IS_CALLABLE",
              f"r={r}")

        # 3.5 message d'erreur non écrasé par les checks en cascade
        r = ctx.request("x", "personne", True)
        check("3.5 attr_for inconnu + is_callable → message correct",
              r is not None and r[1] == "UNKNOW_VALUE_FOR_ATTR_FOR",
              f"r={r}")

        # 3.6 exception dans la méthode appelée → le thread survit ? 
        r = ctx.request("capture", "capture", True, kwargs={})
        # On ne peut pas facilement faire lever FakeCapture.capture sans args,
        # mais on teste que la méthode existe bien
        check("3.6 capture() sur le FakeCapture → True/None",
              r is not None, f"r={r}")
    finally:
        ctx.shutdown()


# ============================================================================
# 7) SUITE 4 : Thread de commandes — lifecycle
# ============================================================================
def suite_cmd_lifecycle():
    section("4. Commandes — cycle de vie")

    # 4.1 le thread survit à une queue vide pendant plusieurs cycles
    ctx = AdapterCtx(capture_mode="noop")
    try:
        time.sleep(0.5)   # plusieurs timeout de 5 ms
        alive = ctx._thread.is_alive()
        check("4.1 thread survit à queue vide répétée", alive)

        # 4.2 requête fonctionne APRÈS plusieurs cycles vides
        r = ctx.request("dropped_packets", "capture", False)
        check("4.2 requête OK après silence", r is not None and r[-1] == 0)
    finally:
        ctx.shutdown()

    # 4.3 stop_event fait sortir le thread
    ctx = AdapterCtx(capture_mode="noop")
    try:
        ctx.stop_ev.set()
        ctx._thread.join(timeout=2.0)
        check("4.3 stop_event → thread sorti", not ctx._thread.is_alive())
    finally:
        ctx.shutdown()

    # 4.4 self._stop=True fait sortir le thread (via adapter.stop())
    ctx = AdapterCtx(capture_mode="noop")
    try:
        ctx.adapter._stop = True
        ctx._thread.join(timeout=2.0)
        check("4.4 self._stop=True → thread sorti", not ctx._thread.is_alive())
    finally:
        ctx.shutdown()


# ============================================================================
# 8) SUITE 5 : Proxy — constructeur
# ============================================================================
def suite_proxy_constructor():
    section("5. Proxy — constructeur")

    # 5.1 dict items correct
    entries = [
        ["a", mp.Queue(), mp.Queue(), mp.Event(), mp.Event()],
        ["b", mp.Queue(), mp.Queue(), mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    check("5.1 construction OK", set(p.items.keys()) == {"a", "b"})
    check("5.2 cmd_queues = 2", len(p.cmd_queues) == 2)
    check("5.3 result_queues = 2", len(p.result_queues) == 2)
    check("5.4 matching contient 2 pcids", len(p.matching) == 2)

    # 5.5 queue non-Queue → TypeError
    bad = [["a", "pas une queue", mp.Queue(), mp.Event(), mp.Event()]]
    try:
        CaptureProxy(bad)
        check("5.5 queue invalide rejetée", False)
    except TypeError:
        check("5.5 queue invalide rejetée", True)

    # 5.6 event invalide → TypeError
    bad = [["a", mp.Queue(), mp.Queue(), "pas un event", mp.Event()]]
    try:
        CaptureProxy(bad)
        check("5.6 event invalide rejeté", False)
    except TypeError:
        check("5.6 event invalide rejeté", True)

    # 5.7 même queue partagée entre 2 pcids → déduplication
    shared = mp.Queue()
    entries = [
        ["a", shared, mp.Queue(), mp.Event(), mp.Event()],
        ["b", shared, mp.Queue(), mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    check("5.7 command_queues dédupliquées",
          len(p.cmd_queues) == 1,
          f"len={len(p.cmd_queues)}")


# ============================================================================
# 9) SUITE 6 : Proxy — get_pcid
# ============================================================================
def suite_proxy_get_pcid():
    section("6. Proxy — get_pcid")

    q_cmd = mp.Queue()
    q_res = mp.Queue()
    entries = [["alpha", q_cmd, q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)

    check("6.1 get_pcid(cmd) = alpha", p.get_pcid(id(q_cmd)) == "alpha")
    check("6.2 get_pcid(res) = alpha", p.get_pcid(id(q_res)) == "alpha")
    check("6.3 get_pcid(inconnu) = None", p.get_pcid(999999) is None)


# ============================================================================
# 10) SUITE 7 : Proxy — _do_request et found_result
# ============================================================================
def suite_proxy_requests():
    section("7. Proxy — _do_request / found_result")

    # 7.1 queue vide → {} (rien reçu)
    entries = [["a", mp.Queue(), mp.Queue(), mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    r = p._do_request(str(uuid4()), "x", "capture", False, [], {})
    check("7.1 queue vide → {}", r == {}, f"r={r!r}")

    # 7.2 réponse directe dans la queue
    q_res = mp.Queue()
    entries = [["a", mp.Queue(), q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    rid = str(uuid4())
    # On pré-remplit la queue AVANT d'appeler
    q_res.put((rid, None, False, "valeur"))
    r = p._do_request(rid, "x", "capture", False, [], {})
    # Comportement attendu : soit "valeur" (branche early-return), soit {}
    # On ne fait pas d'assertion stricte, on rapporte le comportement.
    check("7.2 réponse immédiate — comportement cohérent",
          r == "valeur" or (isinstance(r, dict) and list(r.values()) == ["valeur"]),
          f"r={r!r}")

    # 7.3 réponse après un délai (le worker répond en différé)
    q_res = mp.Queue()
    entries = [["a", mp.Queue(), q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)

    def slow_responder(rid):
        time.sleep(0.05)
        q_res.put((rid, None, False, 42))

    rid = str(uuid4())
    threading.Thread(target=slow_responder, args=(rid,), daemon=True).start()
    r = p._do_request(rid, "x", "capture", False, [], {})
    check("7.3 réponse différée — valeur récupérée",
          r == 42 or (isinstance(r, dict) and list(r.values()) == [42]),
          f"r={r!r}")

    # 7.4 messages non concernés → remis en queue
    q_res = mp.Queue()
    entries = [["a", mp.Queue(), q_res, mp.Event(), mp.Event()]]
    p = CaptureProxy(entries)
    rid_target = str(uuid4())
    q_res.put(("autre_rid", None, False, "avant"))
    q_res.put((rid_target, None, False, "target"))
    q_res.put(("autre_rid2", None, False, "apres"))

    r = p._do_request(rid_target, "x", "capture", False, [], {})
    check("7.4 bon résultat trouvé",
          r == "target" or (isinstance(r, dict) and list(r.values()) == ["target"]),
          f"r={r!r}")

    # Vérifier que les autres messages sont revenus dans la queue
    time.sleep(0.05)
    remaining = []
    try:
        while True:
            remaining.append(q_res.get_nowait())
    except _q.Empty:
        pass
    ids_restants = {m[0] for m in remaining}
    check("7.4b messages non concernés remis en queue",
          "autre_rid" in ids_restants and "autre_rid2" in ids_restants,
          f"restants={ids_restants}")

    # 7.5 deux queues, une vide → comportement critique
    q_res_a, q_res_b = mp.Queue(), mp.Queue()
    entries = [
        ["a", mp.Queue(), q_res_a, mp.Event(), mp.Event()],
        ["b", mp.Queue(), q_res_b, mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    rid = str(uuid4())
    q_res_b.put((rid, None, False, "from_B"))
    # q_res_a est vide : si found_result s'arrête à la première vide, on perd B
    r = p._do_request(rid, "x", "capture", False, [], {}, )
    ok = False
    if isinstance(r, dict):
        ok = "from_B" in r.values()
    elif r == "from_B":
        ok = True
    check("7.5 une queue vide n'empêche pas l'autre",
          ok, f"r={r!r}  (comportement subtil : la 1re queue vide coupe la boucle)")

    # 7.6 toutes les queues pleines mais sans le bon rid → {}
    q1, q2 = mp.Queue(), mp.Queue()
    q1.put(("x", None, False, 1))
    q2.put(("y", None, False, 2))
    entries = [
        ["a", mp.Queue(), q1, mp.Event(), mp.Event()],
        ["b", mp.Queue(), q2, mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    r = p._do_request(str(uuid4()), "x", "capture", False, [], {})
    check("7.6 aucun match → {}", r == {}, f"r={r!r}")

    # 7.7 request sur plusieurs cmd_queues : un seul worker répond, ça marche
    cmd_a, cmd_b = mp.Queue(), mp.Queue()
    res_a, res_b = mp.Queue(), mp.Queue()
    entries = [
        ["a", cmd_a, res_a, mp.Event(), mp.Event()],
        ["b", cmd_b, res_b, mp.Event(), mp.Event()],
    ]
    p = CaptureProxy(entries)
    rid = str(uuid4())

    def responder_b():
        try:
            msg = cmd_b.get(timeout=1.0)
        except _q.Empty:
            return
        res_b.put((msg[0], None, False, "b_a_repondu"))

    threading.Thread(target=responder_b, daemon=True).start()
    r = p._do_request(rid, "x", "capture", False, [], {})
    ok = (r == "b_a_repondu") or (isinstance(r, dict) and "b_a_repondu" in r.values())
    check("7.7 seul worker B répond → valeur OK", ok, f"r={r!r}")


# ============================================================================
# 11) SUITE 8 : cas subtils
# ============================================================================
def suite_subtle():
    section("8. Cas subtils")

    # 8.1 dropped_packets en tant que méthode → l'adapter doit refuser
    ctx = AdapterCtx(capture_mode="bad_dropped")
    try:
        r = ctx.request("dropped_packets", "capture", False)
        check("8.1 property qui renvoie un callable → refusée",
              r is not None and r[2] is True
              and r[1] == "REQUEST_NOT_CALLABLE_ARG_WHO_IS_CALLABLE",
              f"r={r}")
    finally:
        ctx.shutdown()

    # 8.2 attr_for="self" sur un objet non-picklable (queue)
    #     → la requête va faire planter le put (pickle) côté adapter
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("_command_queue", "self", False, timeout=0.5)
        # On ne fait pas d'assertion stricte : on rapporte le comportement.
        check("8.2 attr non-picklable → pas de crash du thread",
              ctx._thread.is_alive(), f"r={r!r}")
    finally:
        ctx.shutdown()

    # 8.3 même rid demandé deux fois → deux résultats distincts
    ctx = AdapterCtx(capture_mode="noop")
    try:
        rid = str(uuid4())
        ctx.cmd_q.put((rid, "dropped_packets", "capture", False, [], {}))
        ctx.cmd_q.put((rid, "dropped_packets", "capture", False, [], {}))
        seen = 0
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                item = ctx.res_q.get(timeout=0.1)
            except _q.Empty:
                continue
            if item and item[0] == rid:
                seen += 1
            if seen >= 2:
                break
        check("8.3 même rid deux fois → 2 réponses", seen == 2, f"seen={seen}")
    finally:
        ctx.shutdown()

    # 8.4 args=None / kwargs=None → traités comme [] et {}
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("echo", "capture", True, args=None, kwargs=None)
        check("8.4 args/kwargs=None → OK",
              r is not None and r[-1] == {"args": [], "kwargs": {}})
    finally:
        ctx.shutdown()

    # 8.5 is_callable=True mais attr absent → erreur ATTR_NOT_FOUND (pas d'appel)
    ctx = AdapterCtx(capture_mode="noop")
    try:
        r = ctx.request("inexistant", "capture", True)
        check("8.5 is_callable+absent → ATTR_NOT_FOUND",
              r is not None and r[1] == "ATTR_NOT_FOUND", f"r={r}")
    finally:
        ctx.shutdown()

    # 8.6 rid en UUID (pas str) → comparé à une str dans la tuple → KO
    ctx = AdapterCtx(capture_mode="noop")
    try:
        rid_obj = uuid4()
        ctx.cmd_q.put((rid_obj, "dropped_packets", "capture", False, [], {}))
        try:
            item = ctx.res_q.get(timeout=1.0)
            got = item[0]
        except _q.Empty:
            got = None
        check("8.6 rid UUID traversé intact (pas de conversion silencieuse)",
              got == rid_obj, f"got={got!r} (type {type(got).__name__})")
    finally:
        ctx.shutdown()


# ============================================================================
# 12) SUITE 9 : intégration multi-process
# ============================================================================
def _worker(pcid, ring_name, ring_cap, refit_args, cmd_q, res_q, stop_ev, cap_ev, ready_ev):
    try:
        a = ProcessCaptureAdapter(
            pcid=pcid,
            ring_args={"name": ring_name, "cap": ring_cap},
            refit_args=refit_args,
            capture_kwargs={"interface": "eth0"},
            command_queue=cmd_q,
            result_queue=res_q,
            stop_event=stop_ev,
            capture_event=cap_ev,
            log_interval=2.0,
            sleep_time=0.005,
        )
        a.start()
        ready_ev.set()
        stop_ev.wait()
        a.stop(timeout=2.0)
    except Exception:
        print(f"\n[worker {pcid}] EXCEPTION:", flush=True)
        traceback.print_exc()
        ready_ev.set()


def suite_integration():
    section("9. Intégration multi-process")
    FakeCapture.MODE = "normal"
    if sys.platform.startswith("win"):
        check("9.0 fork + SHM disponible", False, "Windows détecté")
        return

    ctx = mp.get_context("fork")
    pcs = ["pc-1", "pc-2", "pc-3"]
    cap = 1 << 14
    parent_rings = []
    workers = []
    entries = []

    try:
        for pcid in pcs:
            name = unique_name(f"int_{pcid}")
            cleanup_shm(name)
            parent_rings.append(Ring(name=name, cap=cap, create=True, role="P"))

        for pcid, r in zip(pcs, parent_rings):
            cmd_q = ctx.Queue()
            res_q = ctx.Queue()
            stop_ev = ctx.Event()
            cap_ev = ctx.Event()
            ready_ev = ctx.Event()
            entries.append([pcid, cmd_q, res_q, stop_ev, cap_ev])
            p = ctx.Process(
                target=_worker,
                args=(pcid, r.name, cap, {"session_id": pcid, "tag": pcid},
                      cmd_q, res_q, stop_ev, cap_ev, ready_ev),
                name=f"w-{pcid}", daemon=True)
            p.start()
            workers.append((p, stop_ev, cap_ev, ready_ev))

        for _, _, _, rdy in workers:
            rdy.wait(timeout=5.0)

        proxy = CaptureProxy(entries)

        # 9.1 stats() sur les 3 workers
        r = proxy.stats()
        check("9.1 stats() → 3 pcids",
              isinstance(r, dict) and set(r.keys()) == set(pcs),
              f"r keys={list(r.keys()) if isinstance(r, dict) else type(r)}")

        # 9.2 metrics()
        r = proxy.metrics()
        check("9.2 metrics() → 3 pcids",
              isinstance(r, dict) and set(r.keys()) == set(pcs))

        # 9.3 snapshot()
        r = proxy.snapshot()
        check("9.3 snapshot() → 3 pcids",
              isinstance(r, dict) and set(r.keys()) == set(pcs))

        # 9.4 dropped_packets() — property non-callable
        r = proxy.dropped_packets()
        check("9.4 dropped_packets() → 3 int",
              isinstance(r, dict) and all(isinstance(v, int) for v in r.values()),
              f"r={r}")

        # 9.5 add_src_ip_to_ignore → True sur tous
        r = proxy.add_src_ip_to_ignore("10.0.0.1")
        check("9.5 add_src_ip_to_ignore → True", r is True)

        # 9.6 les rings se remplissent (Capture fait 50 pkt/s)
        time.sleep(0.5)
        for r in parent_rings:
            nw, nr, _, _, used, free = r._all()
            check(f"9.6 {r.name} a reçu des paquets", used > 0,
                  f"used={used}")

        # 9.7 séquences de requêtes indépendantes
        for _ in range(5):
            r = proxy.stats()
            if not (isinstance(r, dict) and set(r.keys()) == set(pcs)):
                break
        check("9.7 requêtes répétées OK",
              isinstance(r, dict) and set(r.keys()) == set(pcs))

    finally:
        for _, stop_ev, cap_ev, _ in workers:
            stop_ev.set()
            cap_ev.set()
        for p, *_ in workers:
            p.join(timeout=3.0)
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)
        for r in parent_rings:
            destroy_ring(r)


# ============================================================================
# 13) MAIN
# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-integration", action="store_true")
    args = ap.parse_args()

    print("\033[1m" + "=" * 78)
    print(" TEST COMPLET : ProcessCaptureAdapter <-> CaptureProxy")
    print("=" * 78 + "\033[0m")

    try:
        suite_constructor()
        suite_cmd_happy()
        suite_cmd_errors()
        suite_cmd_lifecycle()
        suite_proxy_constructor()
        suite_proxy_get_pcid()
        suite_proxy_requests()
        suite_subtle()
        if not args.skip_integration:
            suite_integration()
    except Exception:
        traceback.print_exc()

    ok = summarize()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()