#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 29 09:39:19 2026

@author: hounsousamuel
"""

"""
Tests du module de capture (capture_v2.py).

  python test_capture_v2.py            # exécution directe
  pytest -q test_capture_v2.py         # ou avec pytest

Variable d'environnement CAPTURE_MODULE = module à tester (défaut : capture_v2, placé à côté).
Si les dépendances de l'IDS (ids_ips_ia, dpkt, pcap, sklearn...) sont absentes, elles sont
remplacées par de faux modules : les tests n'ont besoin de rien d'autre que Python.

Le test AF_PACKET sur loopback ne tourne qu'en root sous Linux (sinon il est sauté).
"""
import glob
import importlib
import os
import pickle
import queue as pyq
import socket
import sys
import tempfile
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
NAME = os.environ.get("CAPTURE_MODULE", "capture")


# ------------------------------------------------------------ chargement

def _stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


def _load():
    try:
        return importlib.import_module(NAME)
    except ImportError as e:
        print(f"ℹ️  dépendances absentes ({e}) → faux modules pour les tests\n")

    class _Log:
        def print(self, *a, **k):
            pass

    for dep in ("dpkt", "pcap", "numpy", "sklearn"):
        try:
            importlib.import_module(dep)
        except ImportError:
            _stub(dep)
    if not hasattr(sys.modules["dpkt"], "ethernet"):
        ns = types.SimpleNamespace
        sys.modules["dpkt"].ethernet = ns(Ethernet=type("Ethernet", (), {}))
        sys.modules["dpkt"].ip = ns(IP=type("IP", (), {}))
        sys.modules["dpkt"].ip6 = ns(IP6=type("IP6", (), {}))
    if not hasattr(sys.modules["pcap"], "findalldevs"):
        sys.modules["pcap"].findalldevs = lambda: []
    try:
        import sklearn.preprocessing  # noqa: F401
    except ImportError:
        _stub("sklearn")
        _stub("sklearn.preprocessing", StandardScaler=object)

    for n in ("ids_ips_ia", "ids_ips_ia.ids_ips_utils", "ids_ips_ia.core",
              "ids_ips_ia.core._cython_module"):
        _stub(n)
    _stub("ids_ips_ia.ids_ips_utils.logger", get_logger=lambda: _Log())
    _stub("ids_ips_ia.ids_ips_utils.utils", _get_ip_type=lambda ip: "ok")
    _stub("ids_ips_ia.core.features_extractor", FeatureExtractor=object)
    _stub("ids_ips_ia.ids_ips_utils.signal_manager", signal_manager=lambda f: None)
    _stub("ids_ips_ia.core.config", BUFFER_SIZE=None, TIMEOUT_MS=40, FILTER="tcp or udp or icmp",
          SEQ_LENGTH=5, SRC_IGNORED_IP=set(), DST_IGNORED_IP=set())
    _stub("ids_ips_ia.ids_ips_utils.instance_id", INSTANCE_SUFFIX="test")
    sys.modules["ids_ips_ia.core._cython_module.extract_ip_cython"] = None   # force ImportError
    return importlib.import_module(NAME)


c = _load()
c.DATADIR = tempfile.mkdtemp(prefix="capture_test_")   # les tests n'écrivent jamais dans ton projet


# ----------------------------------------------------------------- trames

MACS = b"\xaa" * 6 + b"\xbb" * 6


def v4(proto):
    return (b"\x45\x00\x00\x14\x00\x00\x00\x00\x40" + bytes([proto]) + b"\x00\x00"
            + b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02")


def v6(nh):
    return (b"\x60\x00\x00\x00\x00\x00" + bytes([nh]) + b"\x40"
            + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            + socket.inet_pton(socket.AF_INET6, "2001:db8::2"))


FRAMES = {   # nom: (trame, doit passer le filtre ?)
    "ipv4_tcp":   (MACS + b"\x08\x00" + v4(6), True),
    "ipv4_udp":   (MACS + b"\x08\x00" + v4(17), True),
    "ipv4_icmp":  (MACS + b"\x08\x00" + v4(1), True),
    "ipv4_gre":   (MACS + b"\x08\x00" + v4(47), False),
    "ipv6_tcp":   (MACS + b"\x86\xdd" + v6(6), True),
    "ipv6_udp":   (MACS + b"\x86\xdd" + v6(17), True),
    "ipv6_icmp6": (MACS + b"\x86\xdd" + v6(58), True),
    "ipv6_hopby": (MACS + b"\x86\xdd" + v6(0), False),
    "arp":        (MACS + b"\x08\x06" + b"\x00" * 28, False),
    "vlan_tcp":   (MACS + b"\x81\x00\x00\x64\x08\x00" + v4(6), True),
    "qinq_udp":   (MACS + b"\x88\xa8\x00\x01\x81\x00\x00\x64\x08\x00" + v4(17), True),
    "tronquee":   (MACS + b"\x08\x00\x45\x00", False),
    "trop_courte": (b"\xaa" * 5, False),
    "vide":       (b"", False),
}


# ------------------------------------------------------------------ tests

def test_filtre_manuel():
    """_match_tcp_udp_icmp = équivalent de 'tcp or udp or icmp or icmp6' (l'IPv6 lisait le mauvais octet)."""
    for name, (frame, expected) in FRAMES.items():
        assert c._match_tcp_udp_icmp(frame) == expected, name


def test_ip_frame():
    assert c._is_ip_frame(FRAMES["ipv4_gre"][0]) and c._is_ip_frame(FRAMES["vlan_tcp"][0])
    assert not c._is_ip_frame(FRAMES["arp"][0]) and not c._is_ip_frame(b"")


def test_ip_ignorees():
    src, dst = c._pack_ips({"10.0.0.1"}), c._pack_ips({"10.0.0.2"})
    none = frozenset()
    assert c._is_ignored(FRAMES["ipv4_tcp"][0], src, none)
    assert c._is_ignored(FRAMES["ipv4_tcp"][0], none, dst)
    assert c._is_ignored(FRAMES["vlan_tcp"][0], src, none)                 # derrière un VLAN
    assert c._is_ignored(FRAMES["ipv6_tcp"][0], c._pack_ips({"2001:db8::1"}), none)
    other = c._pack_ips({"10.9.9.9"})
    assert not c._is_ignored(FRAMES["ipv4_tcp"][0], other, other)
    assert not c._is_ignored(FRAMES["arp"][0], src, dst)


def test_queue_producteurs_multiples_et_ordre():
    """4 producteurs, 3 workers : rien de perdu, rien de doublé, chunks écrits sans .tmp, fusion exacte."""
    q = c.BuffuredQueue(max_size=10_000, num_workers=3, queue_max=50)
    q.start()
    n, producers = 25_000, 4

    def prod():
        for i in range(n):
            while not q.put_nowait((float(i), b"x" * 60)):
                time.sleep(0.001)

    ths = [threading.Thread(target=prod) for _ in range(producers)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    q.make_finished()
    assert q.wait(timeout=30)
    q.stop()
    files = sorted(glob.glob(os.path.join(q.save_dir, "*.pkl")))
    total = sum(len(pickle.load(open(f, "rb"))) for f in files)
    assert total == n * producers == q.num_items, (total, q.num_items)
    assert not glob.glob(os.path.join(q.save_dir, "*.tmp"))
    out = os.path.join(c.DATADIR, "merged.pkl")
    assert c._merge_chunks(q.save_dir, out) == n * producers
    assert c._count_items(out) == n * producers
    assert not os.path.exists(q.save_dir)          # supprimé car le compte est exact


def test_ordre_chronologique_plus_de_10_chunks():
    """file_10 ne doit pas passer avant file_2 (tri alphabétique = ordre de capture)."""
    q = c.BuffuredQueue(max_size=10_000, num_workers=2, queue_max=50)
    q.start()
    for i in range(125_000):
        while not q.put_nowait((float(i), b"y")):
            time.sleep(0.001)
    q.make_finished()
    q.wait(timeout=30)
    q.stop()
    files = sorted(glob.glob(os.path.join(q.save_dir, "*.pkl")))
    assert len(files) >= 12
    seq = [ts for f in files for ts, _ in pickle.load(open(f, "rb"))]
    assert seq == sorted(seq) and len(seq) == 125_000
    c.shutil.rmtree(q.save_dir, ignore_errors=True)


def test_file_pleine_refuse_sans_bloquer():
    """Workers non démarrés : 1 deque + 2 chunks acceptés, le reste refusé (False), sans blocage."""
    q = c.BuffuredQueue(max_size=10_000, num_workers=1, queue_max=2)
    accepted = sum(q.put_nowait((1.0, b"z")) is True for _ in range(50_000))
    assert accepted == 30_000 == q.num_items


def test_workers_inactifs_ne_consomment_pas_de_cpu():
    """Régression : l'ancienne boucle get_nowait() tournait à 100 % CPU par worker."""
    q = c.BuffuredQueue(max_size=10_000, num_workers=4, queue_max=4)
    q.start()
    cpu0 = time.process_time()
    time.sleep(1.5)
    used = time.process_time() - cpu0
    q.make_finished()
    q.wait(timeout=10)
    q.stop()
    assert used < 0.3, f"{used:.2f}s de CPU pour 4 workers au repos"
    c.shutil.rmtree(q.save_dir, ignore_errors=True)


def test_capture_put_et_compteurs():
    """Capture._put ne doit pas planter quand la file est pleine (le paramètre 'queue' masquait le module)."""
    full = c.BuffuredQueue(max_size=10_000, num_workers=1, queue_max=2)
    for _ in range(30_000):
        full.put_nowait((1.0, b"z"))
    cap = c.Capture(queue=full, log_interval=0)
    assert cap._put(full, (1.0, b"z")) is False
    pq = pyq.Queue(maxsize=1)
    assert cap._put(pq, 1) is True and cap._put(pq, 2) is False
    loc = c._Local()
    loc.kept, loc.dropped = 5, 2
    cap._flush(loc, seen=7, drops=1)
    snap = cap.snapshot()
    assert cap.dropped_packets == 2 and snap["kept"] == 5 and snap["k_drops"] == 1
    assert "perdus" in cap._status_line(snap, 100.0, 65) and "🏁" in cap.summary()


def test_af_packet_loopback():
    """Vraie capture AF_PACKET sur lo, BPF attaché : tout ce qui est envoyé doit être vu, sans perte."""
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise unittest.SkipTest("root + Linux requis")
    q = c.BuffuredQueue(max_size=10_000, num_workers=1, queue_max=4)
    q.start()
    cap = c.Capture(queue=q, log_interval=0)
    cap.capture(ifaces=["lo"], in_process=False)
    time.sleep(1)
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 2000
    for _ in range(n):
        tx.sendto(b"hello", rx.getsockname())
    time.sleep(1.5)
    cap.stop()
    q.make_finished()
    q.wait(timeout=30)
    q.stop()
    snap = cap.snapshot()
    tx.close()
    rx.close()
    assert snap["kept"] >= n and snap["kept"] == snap["recv"], snap
    assert snap["dropped"] == 0 and snap["k_drops"] == 0, snap
    c.shutil.rmtree(q.save_dir, ignore_errors=True)


# ---------------------------------------------------------------- lanceur

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        t0 = time.time()
        try:
            fn()
            print(f"✅ {name}  ({time.time() - t0:.1f}s)")
        except unittest.SkipTest as e:
            print(f"⏭️  {name}  sauté : {e}")
        except Exception:
            failed += 1
            import traceback
            print(f"❌ {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} réussis")
    sys.exit(1 if failed else 0)