#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 29 09:26:42 2026

@author: hounsousamuel
"""

"""
Banc de test de la capture Python de l'IDS (root requis).

  charge : pktgen (noyau) pousse du trafic UDP par paliers sur une paire veth,
           on mesure pertes, CPU, RAM et disque.
           Si pktgen n'est pas disponible, un générateur AF_PACKET Python prend
           le relais automatiquement (débit plus faible, CPU plus élevé).

  filtre : scapy fabrique un pcap de cas variés, tcpreplay le rejoue, on vérifie
           ce que le filtre garde (BPF noyau) + la fonction de secours Python.

Pré-requis (Fedora) :
  sudo dnf install tcpreplay ethtool iproute
  pip install scapy
  sudo modprobe pktgen        # optionnel : sans lui, fallback Python

Usage :
  sudo -E $(which python) bench_capture.py --module ton.module filtre
  sudo -E $(which python) bench_capture.py --module ton.module charge --rates 50,100,250,500

--module : chemin pointé du fichier de capture (celui qui définit
           BuffuredQueue et Capture), ex. ids_ips_ia.core.capture
--rates  : paliers en Mbit/s (0 = pktgen à fond, ou Python à fond)
"""
import argparse
import glob
import importlib
import os
import pickle
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter

TX, RX = "bench_tx", "bench_rx"      # paire veth : pktgen émet sur TX, on capture sur RX
PG = "/proc/net/pktgen"
MARK = re.compile(rb"CASE:([a-z0-9_]+)")


# ------------------------------------------------------------------ outils

def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{cmd!r} a échoué : {r.stderr.strip()}")
    return r


def mac(dev):
    with open(f"/sys/class/net/{dev}/address") as f:
        return f.read().strip()


def rss_mb():
    pages = int(open("/proc/self/statm").read().split()[1])
    return pages * os.sysconf("SC_PAGE_SIZE") / 1e6


class Veth:
    """Crée la paire veth, et la supprime TOUJOURS à la sortie (même si ça plante)."""

    def __enter__(self):
        sh(f"ip link del {TX}", check=False)
        sh(f"ip link add {TX} type veth peer name {RX}")
        for d in (TX, RX):
            sh(f"sysctl -qw net.ipv6.conf.{d}.disable_ipv6=1", check=False)  # pas de bruit IPv6
            sh(f"nmcli dev set {d} managed no", check=False)                 # NetworkManager: hors jeu
            sh(f"ethtool -K {d} gro off gso off tso off", check=False)       # trames <= MTU
            sh(f"ip link set {d} up")
        time.sleep(0.5)
        return self

    def __exit__(self, *exc):
        sh(f"ip link del {TX}", check=False)


# ------------------------------------------------------------------ pktgen

def pktgen_available():
    return os.path.isdir(PG)


def pg_write(name, cmd):
    with open(f"{PG}/{name}", "w") as f:
        f.write(cmd + "\n")


def pktgen_setup(dev, size, mbps, dst_mac):
    pg_write("kpktgend_0", "rem_device_all")
    pg_write("kpktgend_0", f"add_device {dev}")
    cmds = [
        "count 0",                       # 0 = infini, on arrête avec "stop"
        f"pkt_size {size}",
        "delay 0",
        "clone_skb 0",                   # 0 car les champs sont randomisés
        f"dst_mac {dst_mac}",
        "src_min 10.0.1.1", "src_max 10.0.1.250",
        "dst_min 10.0.2.1", "dst_max 10.0.2.250",
        "udp_src_min 1024", "udp_src_max 65000",
        "udp_dst_min 1", "udp_dst_max 65000",
        "flag IPSRC_RND", "flag IPDST_RND", "flag UDPSRC_RND", "flag UDPDST_RND",
    ]
    if mbps:
        cmds.append(f"rate {mbps}")      # APRÈS pkt_size : le délai se calcule avec la taille
    for c in cmds:
        pg_write(dev, c)


def pktgen_start():
    # écrire "start" BLOQUE jusqu'à l'arrêt : on le fait dans un thread
    th = threading.Thread(target=lambda: pg_write("pgctrl", "start"), daemon=True)
    th.start()
    return th


def pktgen_sent(dev):
    with open(f"{PG}/{dev}") as f:
        m = re.search(r"pkts-sofar:\s*(\d+)", f.read())
    return int(m.group(1)) if m else 0


# ------------------------------------------- générateur de trafic Python (fallback)

class PyTrafficGen:
    """Générateur de trafic UDP brut via AF_PACKET/SOCK_RAW.

    Remplace pktgen quand /proc/net/pktgen n'est pas disponible.
    L'objectif n'est PAS de battre pktgen en débit, mais de permettre au banc
    de tourner pour valider le pipeline (capture, queue, workers, disque).
    """

    def __init__(self, dev, size, mbps, dst_mac, src_mac=None):
        self.dev = dev
        self.size = max(60, size)
        self.mbps = mbps
        self.dst_mac = dst_mac
        self.src_mac = src_mac or mac(dev)
        self.sent = 0
        self._stop = threading.Event()
        self._sock = None
        self._thread = None
        # Pool de payloads : évite os.urandom() à chaque trame
        self._payload_pool = [os.urandom(128) for _ in range(32)]

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def _build_frame(self):
        # Ethernet
        eth = (bytes.fromhex(self.dst_mac.replace(":", "")) +
               bytes.fromhex(self.src_mac.replace(":", "")) +
               struct.pack("!H", 0x0800))

        payload_len = max(0, self.size - 14 - 20 - 8)
        total_len = 20 + 8 + payload_len

        src_ip = socket.inet_aton(f"10.0.1.{random.randint(1, 250)}")
        dst_ip = socket.inet_aton(f"10.0.2.{random.randint(1, 250)}")

        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, random.randint(1, 65535), 0,
            64, 17, 0, src_ip, dst_ip,
        )
        ip_hdr = ip_hdr[:10] + struct.pack("!H", self._checksum(ip_hdr)) + ip_hdr[12:]

        udp_src = random.randint(1024, 65000)
        udp_dst = random.randint(1, 65000)
        udp_hdr = struct.pack("!HHHH", udp_src, udp_dst, 8 + payload_len, 0)

        payload = self._payload_pool[random.randrange(len(self._payload_pool))]
        payload = payload[:payload_len].ljust(payload_len, b"\x00")

        return eth + ip_hdr + udp_hdr + payload

    def start(self):
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._sock.bind((self.dev, 0))
        self._thread = threading.Thread(target=self._run, daemon=True, name="PyTrafficGen")
        self._thread.start()

    def _run(self):
        if self.mbps:
            pps = self.mbps * 1e6 / (self.size * 8)
            batch = max(1, int(pps / 100))     # 100 rafales/s
            interval = 0.01
        else:
            batch = 5000
            interval = 0.0

        next_t = time.perf_counter()
        while not self._stop.is_set():
            for _ in range(batch):
                try:
                    self._sock.send(self._build_frame())
                    self.sent += 1
                except OSError:
                    pass
                if self._stop.is_set():
                    break
            if interval:
                next_t += interval
                dt = next_t - time.perf_counter()
                if dt > 0:
                    time.sleep(dt)
                else:
                    next_t = time.perf_counter()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(5)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def packets_sent(self):
        return self.sent


# ----------------------------------------------- backends unifiés

class PktgenBackend:
    """Enveloppe pktgen derrière l'API setup/start/stop/packets_sent."""

    name = "pktgen"

    def __init__(self, dev, size, mbps, dst_mac):
        self.dev = dev
        self.size = size
        self.mbps = mbps
        self.dst_mac = dst_mac
        self._th = None

    def setup(self):
        pktgen_setup(self.dev, self.size, self.mbps, self.dst_mac)

    def start(self):
        self._th = pktgen_start()

    def stop(self):
        try:
            pg_write("pgctrl", "stop")
        except OSError:
            pass
        if self._th:
            self._th.join(10)

    def packets_sent(self):
        try:
            return pktgen_sent(self.dev)
        except OSError:
            return 0


class PyBackend:
    """Enveloppe PyTrafficGen derrière la même API."""

    name = "python"

    def __init__(self, dev, size, mbps, dst_mac):
        self.gen = PyTrafficGen(dev, size, mbps, dst_mac)

    def setup(self):
        pass

    def start(self):
        self.gen.start()

    def stop(self):
        self.gen.stop()

    def packets_sent(self):
        return self.gen.packets_sent()


# ------------------------------------------------------ harnais de capture

class Harness:
    """Démarre BuffuredQueue + Capture du module testé et relit les chunks."""

    def __init__(self, mod, workers, max_size):
        self.mod = mod
        self.q = mod.BuffuredQueue(max_size=max_size, num_workers=workers)
        self.cap = mod.Capture(queue=self.q)
        self.got = self.dropped = self.k_seen = self.k_drops = 0

    def start(self):
        self.q.start()
        self.cap.capture(ifaces=[RX], filter=self.mod.FILTER, in_process=False)
        time.sleep(0.5)                  # laisse le socket s'ouvrir

    def finish(self):
        # Capture agrège déjà les stats noyau en interne (rafraîchies chaque seconde par les
        # threads de capture) : on les lit via stats(), pas en retouchant le socket depuis ici.
        st = self.cap.stats()
        self.k_seen, self.k_drops = st.get("k_seen", 0), st.get("k_drops", 0)
        self.cap.stop()
        self.got = self.q.num_items
        self.dropped = self.cap.dropped_packets
        self.q.make_finished()
        for ev in list(self.q._end_event.values()):
            ev.wait(30)                  # pas de boucle active, et pas de blocage infini
        self.q.stop()

    def frames(self):
        for path in sorted(glob.glob(os.path.join(self.q.save_dir, "*.pkl"))):
            with open(path, "rb") as f:
                for _ts, raw in pickle.load(f):
                    yield raw

    def disk_mb(self):
        files = glob.glob(os.path.join(self.q.save_dir, "*.pkl"))
        return sum(os.path.getsize(p) for p in files) / 1e6

    def cleanup(self):
        shutil.rmtree(self.q.save_dir, ignore_errors=True)


# ------------------------------------------------------------- test charge

HEADER = (" cible | réel Mb/s |    pkt/s |  envoyés | capturés | rej.queue | rej.noyau | perte |  CPU | RAM Mo | disque Mo")


def run_level(mod, a, mbps, backend_cls):
    h = Harness(mod, a.workers, a.max_size)
    h.start()
    backend = backend_cls(TX, a.size, mbps, mac(RX))
    backend.setup()
    backend.start()
    t0, cpu0, peak = time.time(), time.process_time(), 0.0
    try:
        while time.time() - t0 < a.duration:
            time.sleep(1)
            peak = max(peak, rss_mb())
    finally:
        backend.stop()
    elapsed = time.time() - t0
    cpu = (time.process_time() - cpu0) / elapsed * 100
    sent = backend.packets_sent()
    time.sleep(1)                                          # laisse la capture vider le socket
    h.finish()
    disk = h.disk_mb()
    h.cleanup()
    loss = 100 * (sent - h.got) / sent if sent else 0.0
    cible = str(mbps) if mbps else "max"
    print(f"{cible:>6} | {sent * a.size * 8 / elapsed / 1e6:10.0f} | {sent / elapsed:8.0f} | "
          f"{sent:8d} | {h.got:8d} | {h.dropped:9d} | {h.k_drops:9d} | {loss:4.1f}% | {cpu:3.0f}% | {peak:6.0f} | {disk:9.0f}")


def load_mode(mod, a):
    # Charge pktgen si possible, sinon fallback Python
    sh("modprobe pktgen", check=False)
    if pktgen_available():
        backend_cls = PktgenBackend
        print("Backend : pktgen (noyau)")
    else:
        backend_cls = PyBackend
        print("⚠️  pktgen indisponible → backend Python (AF_PACKET)")
        print("   Débit plus faible et CPU plus élevé qu'avec pktgen.\n")

    print(f"Paquets de {a.size} octets, {a.duration}s par palier, {a.workers} workers, deque={a.max_size}")
    print("rej.noyau = paquets jetés par le NOYAU (buffer socket plein, avant même Python)")
    print("rej.queue = paquets jetés par BuffuredQueue (file de chunks pleine, ct app)")
    print("perte = envoyés - capturés (= rej.noyau + rej.queue + ce qui traîne encore en RAM)\n")
    print(HEADER)
    with Veth():
        try:
            for mbps in a.rates:
                run_level(mod, a, mbps, backend_cls)
        finally:
            if pktgen_available():
                try:
                    pg_write("kpktgend_0", "rem_device_all")
                except OSError:
                    pass


# ------------------------------------------------------------- test filtre

def build_cases():
    """nom -> (attendu, paquet). attendu: True=gardé, False=rejeté, None=informatif."""
    from scapy.all import (Ether, Dot1Q, Dot1AD, IP, IPv6, TCP, UDP, ICMP, ARP, GRE,
                           Raw, ICMPv6EchoRequest)
    e = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    v4 = lambda: IP(src="10.0.0.1", dst="10.0.0.2")
    v6 = lambda: IPv6(src="2001:db8::1", dst="2001:db8::2")
    m = lambda n: Raw(load=f"CASE:{n}".encode())      # marqueur pour reconnaître le paquet
    return {
        "ipv4_tcp":     (True,  e() / v4() / TCP() / m("ipv4_tcp")),
        "ipv4_udp":     (True,  e() / v4() / UDP() / m("ipv4_udp")),
        "ipv4_icmp":    (True,  e() / v4() / ICMP() / m("ipv4_icmp")),
        "ipv6_tcp":     (True,  e() / v6() / TCP() / m("ipv6_tcp")),
        "ipv6_udp":     (True,  e() / v6() / UDP() / m("ipv6_udp")),
        "ipv6_icmp6":   (True,  e() / v6() / ICMPv6EchoRequest() / m("ipv6_icmp6")),
        "ipv4_gre":     (False, e() / v4() / GRE() / m("ipv4_gre")),
        "arp":          (False, e() / ARP() / m("arp")),
        # VLAN : le noyau retire souvent l'étiquette avant ton filtre, donc résultat informatif
        "vlan_ipv4_tcp": (None, e() / Dot1Q(vlan=100) / v4() / TCP() / m("vlan_ipv4_tcp")),
        "qinq_ipv4_udp": (None, e() / Dot1AD(vlan=1) / Dot1Q(vlan=100) / v4() / UDP() / m("qinq_ipv4_udp")),
    }


def verdict(exp, got, total):
    if exp is None:
        return "ℹ️ "
    ok = (got == total) if exp else (got == 0)
    return "✅" if ok else "❌"


def label(exp):
    return {True: "gardé ", False: "rejeté", None: "info  "}[exp]


def test_fallback(mod, cases):
    print("\n== Fonction de secours _match_tcp_udp_icmp (sans réseau) ==")
    for name, (exp, pkt) in cases.items():
        got = bool(mod._match_tcp_udp_icmp(bytes(pkt)))
        v = "ℹ️ " if exp is None else ("✅" if got == exp else "❌")
        print(f"  {v} {name:<14} attendu={label(exp)} obtenu={'gardé' if got else 'rejeté'}")


def test_kernel(mod, cases, a, repeat=50):
    from scapy.all import wrpcap
    pcap = "/tmp/bench_cases.pcap"
    wrpcap(pcap, [p for _, p in cases.values()])
    h = Harness(mod, a.workers, a.max_size)
    with Veth():
        h.start()
        subprocess.run(["tcpreplay", "-q", "-i", TX, "--pps=2000", f"--loop={repeat}", pcap], check=True)
        time.sleep(1)
        h.finish()
    counts = Counter()
    for raw in h.frames():
        mk = MARK.search(raw)
        counts[mk.group(1).decode() if mk else "?"] += 1
    h.cleanup()
    print(f"\n== Filtre via le noyau (tcpreplay x{repeat}) ==")
    for name, (exp, _) in cases.items():
        n = counts.get(name, 0)
        print(f"  {verdict(exp, n, repeat)} {name:<14} attendu={label(exp)} reçu={n}/{repeat}")
    if counts.get("?"):
        print(f"  ℹ️  {counts['?']} trames sans marqueur (bruit réseau)")


def filter_mode(mod, a):
    if not shutil.which("tcpreplay"):
        sys.exit("tcpreplay manquant : sudo dnf install tcpreplay")
    cases = build_cases()
    test_fallback(mod, cases)
    test_kernel(mod, cases, a)


# -------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["charge", "filtre"])
    ap.add_argument("--module", required=True)
    ap.add_argument("--rates", default="50,100,250,500,1000,2000")
    ap.add_argument("--size", type=int, default=512)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-size", type=int, default=20_000)
    a = ap.parse_args()
    a.rates = [int(x) for x in a.rates.split(",")]
    if os.geteuid() != 0:
        sys.exit("Root requis : sudo -E $(which python) bench_capture.py ...")
    mod = importlib.import_module(a.module)
    (load_mode if a.mode == "charge" else filter_mode)(mod, a)


if __name__ == "__main__":
    main()