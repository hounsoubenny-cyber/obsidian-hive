#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Created on Tue Sep 29 21:52:41 2026
# @author: hounsousamuel
"""
Générateur de trafic normal + attaque via Scapy + veth + tcpreplay.

- Génère deux PCAPs : normal.pcap (trafic varié légitime) et attack.pcap (scan, flood, malformed).
- Crée une paire veth (veth_tx <-> veth_rx).
- Lance tcpreplay en boucle sur veth_tx, au débit choisi (--rate).
- Écoute stdin en permanence :
    attack            -> bascule sur attack.pcap
    normal            -> rebascule sur normal.pcap
    rate <spec>       -> change le débit À CHAUD (ex. "rate pps=20000", "rate topspeed")
    rate              -> affiche le débit courant
    status | quit

Débit (--rate, ou commande "rate" sur stdin) :
    topspeed          pleine vitesse (défaut)
    pps=N             N paquets/s   (suffixes k / M : pps=50k, pps=1M)
    mbps=X            X mégabits/s  (1 Mo/s = 8 mbps)
    gbps=X            X gigabits/s
Le préfixe "--" est toléré : --rate=--pps=1000 et --rate pps=1000 sont équivalents.
"""

import os
import re
import sys
import time
import random
import shutil
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
REPLAY_RATE = "topspeed"           # ou "pps=50000", "mbps=1000" (voir --help)
TCPREPLAY_LOG = "/tmp/ids_tcpreplay.log"   # stderr de tcpreplay (avant : jeté dans /dev/null)

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
# Débit de replay (--rate / commande "rate")
# --------------------------------------------------------------------------

RATE_HELP = ("topspeed | pps=N (suffixes k/M : pps=50k) | mbps=X | gbps=X "
             "(le préfixe -- est toléré)")

_RATE_RE = re.compile(r"(pps|mbps|gbps)\s*[=:]\s*(\d+(?:\.\d+)?)\s*([km]?)")


def parse_rate(spec):
    """Normalise une spec de débit.

    Retourne ('topspeed',) | ('pps', int) | ('mbps', float).
    Accepte : topspeed, pps=10000, pps=50k, mbps=100, gbps=1, "pps 1000",
    avec ou sans '--' devant. Lève ValueError avec un message clair sinon.
    """
    s = str(spec).strip().lower().lstrip("-")
    s = re.sub(r"^(pps|mbps|gbps)\s+(?=\d)", r"\1=", s)       # "pps 1000" -> "pps=1000"
    if s in ("topspeed", "top", "max"):
        return ("topspeed",)
    if s in ("pps", "mbps", "gbps"):
        raise ValueError(f"« {s} » sans valeur : écris {s}=<nombre> (ex. {s}=1000)")
    m = _RATE_RE.fullmatch(s)
    if not m:
        raise ValueError(f"débit invalide {spec!r}. Formats : {RATE_HELP}")
    kind, num, suffix = m.groups()
    value = float(num)
    if suffix:
        if kind != "pps":
            raise ValueError("le suffixe k/M n'est valable que pour pps (ex. pps=50k)")
        value *= 1_000 if suffix == "k" else 1_000_000
    if value <= 0:
        raise ValueError("le débit doit être > 0")
    if kind == "pps":
        return ("pps", int(round(value)))
    if kind == "gbps":
        value *= 1000
    return ("mbps", value)


def _fmt(x):
    """Nombre sans notation scientifique ni zéros inutiles (100.0 -> '100')."""
    return format(x, "f").rstrip("0").rstrip(".")


def rate_args(rate):
    """Arguments tcpreplay correspondant à un débit normalisé."""
    if rate[0] == "topspeed":
        return ["--topspeed"]
    if rate[0] == "pps":
        return [f"--pps={rate[1]}"]
    return [f"--mbps={_fmt(rate[1])}"]


def rate_label(rate):
    return "topspeed" if rate[0] == "topspeed" else f"{rate[0]}={_fmt(rate[1])}"


def _rate_arg(text):
    """Type argparse : valide --rate dès le parsing."""
    try:
        return parse_rate(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


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
        # NB : ne surtout pas l'appeler `_stop` -> ça écrase Thread._stop() de la stdlib
        self._stop_evt = threading.Event()

    def run(self):
        try:
            for line in sys.stdin:
                if self._stop_evt.is_set():
                    break
                cmd = line.strip().lower()
                if not cmd:
                    continue
                try:
                    self.on_signal(cmd)
                except Exception as e:           # une commande ratée ne doit pas tuer le lecteur
                    print(f"❌ commande {cmd!r} : {e}")
        except Exception:
            pass

    def stop(self):
        self._stop_evt.set()


# --------------------------------------------------------------------------
# Replay tcpreplay
# --------------------------------------------------------------------------

def _err_tail(n=5):
    try:
        with open(TCPREPLAY_LOG, encoding="utf-8", errors="replace") as f:
            return "\n".join(f.read().strip().splitlines()[-n:])
    except OSError:
        return ""


class ReplayManager:
    """Lance tcpreplay en boucle sur un pcap ; permet de changer de pcap ET de débit à chaud."""

    def __init__(self, iface, pcap_normal, pcap_attack, rate=("topspeed",)):
        self.iface = iface
        self.pcap_normal = pcap_normal
        self.pcap_attack = pcap_attack
        self.rate = rate                       # tuple normalisé (voir parse_rate)
        self._proc = None
        self._err = None
        self._lock = threading.Lock()
        self._current = None
        self._started_at = 0.0

    # -- interne (verrou déjà pris) ------------------------------------------
    def _kill_locked(self):
        p = self._proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if self._err:
            self._err.close()
            self._err = None

    def _launch_locked(self, pcap_path):
        self._kill_locked()
        # Les options AVANT le fichier pcap (tcpreplay lit le pcap en dernier)
        cmd = ["tcpreplay", "-q", "-i", self.iface, "--loop=0",
               *rate_args(self.rate), pcap_path]
        print(f"🚀 tcpreplay sur {self.iface} : {pcap_path} ({rate_label(self.rate)})")
        self._err = open(TCPREPLAY_LOG, "w", encoding="utf-8")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=self._err)
        self._current = pcap_path
        self._started_at = time.monotonic()

    # -- API -----------------------------------------------------------------
    def start(self, pcap_path):
        with self._lock:
            self._launch_locked(pcap_path)

    def switch(self, pcap_path):
        with self._lock:
            if self._current == pcap_path:
                print(f"ℹ️  Déjà en cours : {pcap_path}")
                return
            self._launch_locked(pcap_path)

    def set_rate(self, rate):
        """Change le débit à chaud (relance tcpreplay sur le pcap courant)."""
        with self._lock:
            if rate == self.rate:
                print(f"ℹ️  Débit déjà à {rate_label(rate)}")
                return
            self.rate = rate
            if self._current:
                self._launch_locked(self._current)
            print(f"🎚️  Débit → {rate_label(rate)}")

    def poll(self):
        """None si tcpreplay tourne ; sinon (code_retour, durée_de_vie_s, fin_de_stderr)."""
        with self._lock:
            p = self._proc
            if p is None:
                return None
            rc = p.poll()
            if rc is None:
                return None
            return rc, time.monotonic() - self._started_at, _err_tail()

    def restart(self):
        with self._lock:
            if self._current:
                self._launch_locked(self._current)

    def stop(self):
        with self._lock:
            self._kill_locked()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--normal-count", type=int, default=NORMAL_PKT_COUNT)
    ap.add_argument("--attack-count", type=int, default=ATTACK_PKT_COUNT)
    ap.add_argument("--rate", type=_rate_arg, default=REPLAY_RATE, metavar="SPEC",
                    help="débit initial : " + RATE_HELP + ". Défaut : topspeed")
    ap.add_argument("--no-veth", action="store_true",
                    help="Ne crée pas de veth (utilise l'existant)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Root requis : sudo -E $(which python) ce_script.py")
    if not shutil.which("tcpreplay"):
        sys.exit("tcpreplay introuvable : sudo apt install tcpreplay")

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
    stop_evt = threading.Event()

    def on_signal(cmd):
        verb, _, arg = cmd.partition(" ")
        arg = arg.strip()
        if verb == "attack":
            mgr.switch(PCAP_ATTACK)
        elif verb == "normal":
            mgr.switch(PCAP_NORMAL)
        elif verb == "rate":
            if not arg:
                print(f"🎚️  Débit actuel : {rate_label(mgr.rate)}")
                return
            try:
                new_rate = parse_rate(arg)
            except ValueError as e:
                print(f"❌ {e}")
                return
            mgr.set_rate(new_rate)
        elif verb in ("quit", "exit", "q"):
            print("👋 Arrêt demandé")
            stop_evt.set()      # (avant : SystemExit dans le thread stdin => ne quittait pas le programme)
        elif verb == "status":
            print(f"📊 pcap : {mgr._current} | débit : {rate_label(mgr.rate)}")
        else:
            print(f"❓ Commande inconnue : {cmd!r} "
                  f"(essaie : normal, attack, rate <spec>, status, quit)")

    reader = StdinReader(on_signal)
    reader.start()

    # 4. Boucle de vie
    mgr.start(PCAP_NORMAL)
    # NB : profile_run.py attend la chaîne « Commandes disponibles » pour savoir que tout est prêt
    print("\n🎮 Commandes disponibles :")
    print("   attack        → bascule sur le trafic d'attaque")
    print("   normal        → revient au trafic normal")
    print("   rate <spec>   → change le débit à chaud (topspeed | pps=N | mbps=X)")
    print("   status        → affiche le pcap et le débit en cours")
    print("   quit          → arrête tout\n")

    failed = False
    try:
        while not stop_evt.wait(1):
            dead = mgr.poll()
            if dead is None:
                continue
            rc, lived, err = dead
            if lived < 2:
                # Mort immédiate = mauvaise option / interface absente : inutile de boucler
                print(f"❌ tcpreplay quitte aussitôt (code {rc}) :\n{err or '(stderr vide)'}")
                print(f"   (détail : {TCPREPLAY_LOG})")
                failed = True
                break
            print(f"⚠️  tcpreplay s'est arrêté (code {rc}), redémarrage...")
            mgr.restart()
    except KeyboardInterrupt:
        pass
    finally:
        reader.stop()
        mgr.stop()
        if not a.no_veth:
            veth_down()
        print("🏁 Terminé")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()