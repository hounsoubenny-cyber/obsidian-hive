#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 29 21:52:41 2026

@author: hounsousamuel
"""

"""
Générateur de trafic normal + attaque via Scapy + veth + tcpreplay.

- Génère deux PCAPs : normal.pcap (trafic varié légitime) et attack.pcap (scan, flood, malformed).
- Crée une paire veth (veth_tx <-> veth_rx).
- Lance tcpreplay à pleine vitesse sur veth_tx.
- Écoute stdin en permanence : sur "attack" -> bascule sur attack.pcap,
  sur "normal" -> rebascule sur normal.pcap.
"""

import os
import sys
import time
import random
import subprocess
import threading
import argparse

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
    Raw, DNS, DNSQR, ARP, GRE, wrpcap, fragment,
)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

VETH_TX = "veth_tx"
VETH_RX = "veth_rx"
PCAP_NORMAL = "/tmp/ids_normal.pcap"
PCAP_ATTACK = "/tmp/ids_attack.pcap"
NORMAL_PKT_COUNT = 10_000          # paquets dans le pcap normal
ATTACK_PKT_COUNT = 5_000           # paquets dans le pcap d'attaque
REPLAY_RATE = "--topspeed"         # ou "--pps=50000", "--mbps=1000"

# --------------------------------------------------------------------------
# Génération des paquets
# --------------------------------------------------------------------------

def _rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def _rand_ipv4():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_ipv6():
    return "2001:db8::%x" % random.randint(1, 0xffff)


def generate_normal_packets(count):
    """Trafic légitime varié : TCP établi, UDP, DNS, ICMP, IPv6."""
    packets = []
    src_mac = _rand_mac()
    dst_mac = _rand_mac()

    for _ in range(count):
        choice = random.random()
        eth = Ether(src=src_mac, dst=dst_mac)

        if choice < 0.35:
            # TCP avec flags variés (SYN, ACK, PSH...)
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                  TCP(sport=random.randint(1024, 65000),
                      dport=random.choice([80, 443, 22, 8080]),
                      flags=flags) / \
                  Raw(load=os.urandom(random.randint(64, 512)))
        elif choice < 0.60:
            # UDP avec payload aléatoire
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                  UDP(sport=random.randint(1024, 65000),
                      dport=random.choice([53, 123, 514])) / \
                  Raw(load=os.urandom(random.randint(64, 512)))
        elif choice < 0.75:
            # DNS query
            pkt = eth / IP(src=_rand_ipv4(), dst="8.8.8.8") / \
                  UDP(sport=random.randint(1024, 65000), dport=53) / \
                  DNS(rd=1, qd=DNSQR(qname="example.com"))
        elif choice < 0.90:
            # ICMP echo
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                  ICMP() / Raw(load=os.urandom(32))
        else:
            # IPv6 TCP
            pkt = eth / IPv6(src=_rand_ipv6(), dst=_rand_ipv6()) / \
                  TCP(sport=random.randint(1024, 65000), dport=443) / \
                  Raw(load=os.urandom(random.randint(64, 256)))

        packets.append(pkt)

    return packets


def generate_attack_packets(count):
    """Trafic anormal : scan SYN, flood UDP, malformed, GRE, ARP, fragments."""
    packets = []
    src_mac = _rand_mac()
    dst_mac = _rand_mac()

    for _ in range(count):
        choice = random.random()
        eth = Ether(src=src_mac, dst=dst_mac)

        if choice < 0.35:
            # SYN scan sur une plage de ports
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                  TCP(sport=random.randint(1024, 65000),
                      dport=random.randint(1, 1024),
                      flags="S")
        elif choice < 0.60:
            # UDP flood vers ports sensibles
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                  UDP(sport=random.randint(1, 1024),
                      dport=random.choice([53, 123, 161, 389])) / \
                  Raw(load=os.urandom(random.randint(1, 64)))
        elif choice < 0.75:
            # GRE tunneling (souvent bloqué)
            pkt = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / GRE() / \
                  Raw(load=os.urandom(128))
        elif choice < 0.85:
            # ARP spoofing-like
            pkt = eth / ARP(op=2, psrc=_rand_ipv4(), pdst=_rand_ipv4(),
                            hwsrc=src_mac, hwdst="ff:ff:ff:ff:ff:ff")
        elif choice < 0.95:
            # Fragments IP (petits, pour tester la réassemblage)
            base = eth / IP(src=_rand_ipv4(), dst=_rand_ipv4()) / \
                   UDP(sport=random.randint(1024, 65000), dport=53) / \
                   Raw(load=os.urandom(1024))
            frags = fragment(base, fragsize=random.choice([16, 32, 64]))
            packets.extend(frags)
            continue
        else:
            # ICMPv6 malformé / flood
            pkt = eth / IPv6(src=_rand_ipv6(), dst=_rand_ipv6()) / \
                  ICMPv6EchoRequest() / Raw(load=os.urandom(random.randint(0, 64)))

        packets.append(pkt)

    return packets


# --------------------------------------------------------------------------
# Gestion veth
# --------------------------------------------------------------------------

def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def veth_up():
    """Crée la paire veth et l'active. Idempotent (supprime d'abord si existant)."""
    run(f"ip link del {VETH_TX}", check=False)
    run(f"ip link add {VETH_TX} type veth peer name {VETH_RX}")
    for dev in (VETH_TX, VETH_RX):
        run(f"sysctl -qw net.ipv6.conf.{dev}.disable_ipv6=1", check=False)
        run(f"ethtool -K {dev} gro off gso off tso off", check=False)
        run(f"ip link set {dev} up")
    time.sleep(0.3)
    print(f"✅ veth prêt : {VETH_TX} <-> {VETH_RX}")


def veth_down():
    run(f"ip link del {VETH_TX}", check=False)
    print(f"🧹 veth supprimé : {VETH_TX}")


# --------------------------------------------------------------------------
# Lecteur stdin non bloquant
# --------------------------------------------------------------------------

class StdinReader(threading.Thread):
    """Lit stdin en permanence dans un thread séparé.

    Chaque ligne non vide est passée au callback `on_signal`.
    """

    def __init__(self, on_signal):
        super().__init__(daemon=True, name="StdinReader")
        self.on_signal = on_signal
        self._stop = threading.Event()

    def run(self):
        try:
            for line in sys.stdin:
                if self._stop.is_set():
                    break
                cmd = line.strip().lower()
                if cmd:
                    self.on_signal(cmd)
        except Exception:
            pass

    def stop(self):
        self._stop.set()


# --------------------------------------------------------------------------
# Replay tcpreplay
# --------------------------------------------------------------------------

class ReplayManager:
    """Lance tcpreplay en boucle sur un pcap, et permet de basculer entre pcaps."""

    def __init__(self, iface, pcap_normal, pcap_attack, rate=REPLAY_RATE):
        self.iface = iface
        self.pcap_normal = pcap_normal
        self.pcap_attack = pcap_attack
        self.rate = rate
        self._proc = None
        self._lock = threading.Lock()
        self._current = None

    def start(self, pcap_path):
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()

            cmd = ["tcpreplay", "-q", "-i", self.iface,
                   "--loop=0", "--topspeed", pcap_path]
            # Remplace --topspeed si un autre rate est fourni
            if self.rate != "--topspeed":
                cmd = [c for c in cmd if c != "--topspeed"]
                cmd.append(self.rate)

            print(f"🚀 tcpreplay lancé sur {self.iface} : {pcap_path} ({self.rate})")
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            self._current = pcap_path

    def switch(self, pcap_path):
        if self._current == pcap_path:
            print(f"ℹ️  Déjà en cours : {pcap_path}")
            return
        self.start(pcap_path)

    def stop(self):
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--normal-count", type=int, default=NORMAL_PKT_COUNT)
    ap.add_argument("--attack-count", type=int, default=ATTACK_PKT_COUNT)
    ap.add_argument("--rate", default=REPLAY_RATE,
                    help="--topspeed, --pps=N, ou --mbps=N")
    ap.add_argument("--no-veth", action="store_true",
                    help="Ne crée pas de veth (utilise l'existant)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Root requis : sudo -E $(which python) ce_script.py")

    # 1. Génération des pcaps
    print(f"📦 Génération du pcap normal ({a.normal_count} paquets)...")
    normal = generate_normal_packets(a.normal_count)
    wrpcap(PCAP_NORMAL, normal)
    print(f"   → {PCAP_NORMAL} ({len(normal)} paquets, "
          f"{os.path.getsize(PCAP_NORMAL) / 1e6:.1f} Mo)")
    del normal

    print(f"📦 Génération du pcap attaque ({a.attack_count} paquets)...")
    attack = generate_attack_packets(a.attack_count)
    wrpcap(PCAP_ATTACK, attack)
    print(f"   → {PCAP_ATTACK} ({len(attack)} paquets, "
          f"{os.path.getsize(PCAP_ATTACK) / 1e6:.1f} Mo)")
    del attack

    # 2. veth
    if not a.no_veth:
        veth_up()

    # 3. Replay
    mgr = ReplayManager(VETH_TX, PCAP_NORMAL, PCAP_ATTACK, a.rate)

    def on_signal(cmd):
        if cmd == "attack":
            mgr.switch(PCAP_ATTACK)
        elif cmd == "normal":
            mgr.switch(PCAP_NORMAL)
        elif cmd in ("quit", "exit", "q"):
            print("👋 Arrêt demandé")
            mgr.stop()
            raise SystemExit(0)
        elif cmd == "status":
            print(f"📊 État actuel : {mgr._current}")
        else:
            print(f"❓ Commande inconnue : {cmd!r} (essaie : normal, attack, status, quit)")

    reader = StdinReader(on_signal)
    reader.start()

    # 4. Boucle de vie
    mgr.start(PCAP_NORMAL)
    print("\n🎮 Commandes disponibles :")
    print("   attack   → bascule sur le trafic d'attaque")
    print("   normal   → revient au trafic normal")
    print("   status   → affiche le pcap en cours")
    print("   quit     → arrête tout\n")

    try:
        while True:
            time.sleep(1)
            if mgr._proc and mgr._proc.poll() is not None:
                # tcpreplay s'est arrêté (fin de boucle ou erreur)
                print("⚠️  tcpreplay s'est arrêté, redémarrage...")
                mgr.start(mgr._current)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        reader.stop()
        mgr.stop()
        if not a.no_veth:
            veth_down()
        print("🏁 Terminé")


if __name__ == "__main__":
    main()