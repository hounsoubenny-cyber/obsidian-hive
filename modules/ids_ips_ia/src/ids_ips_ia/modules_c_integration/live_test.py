#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 15 10:37:13 2026

@author: hounsousamuel
"""

"""
live_test.py — Démo live du moteur IDS/IPS (v2).

Crée de VRAIS flux réseau (pas des paquets isolés) :
  - flux UDP longs      : 1 socket source, N paquets espacés → 1 flux de N paquets
  - flux TCP riches     : sessions avec plusieurs allers-retours (ping/pong)
  - flux parallèles     : plusieurs flux simultanés (réaliste)
  - port scan           : 40 flux courts depuis la même source (détection)
  - TCP long            : session maintenue ouverte plusieurs secondes

Usage:
    cd python
    python3 setup.py build_ext --inplace
    sudo python3 live_test.py

Options:
    sudo python3 live_test.py --iface eth0
    sudo python3 live_test.py --duration 30
    sudo python3 live_test.py --readers 4
    sudo python3 live_test.py --scenario full|udp|tcp|scan|parallel
"""
import argparse
import os
import socket
import sys
import threading
import time
from collections import Counter
from datetime import datetime
try:
    from ids_ips_ia.modules_c_integration.ids_ips_core_c import (
        Engine, EngineError, FLOW_DTYPE, flow_addresses,
        RULE_IDS, RULE_NAMES, END_REASONS, STATES,
    )
except ImportError as e:
    print("❌ Impossible d'importer ids_ips_core_c.")
    print("   Compile d'abord :  python3 setup.py build_ext --inplace")
    print("   Erreur :", e)
    sys.exit(1)


# ─── Couleurs ANSI ─────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag, msg, color=C.WHITE):
    print(f"{C.DIM}{ts()}{C.RESET} {color}{C.BOLD}[{tag}]{C.RESET} {msg}", flush=True)


# ─── Générateur de VRAIS flux ──────────────────────────────────────────────
class FlowGenerator:
    """Génère de vrais flux réseau (pas des paquets isolés).

    Principe : un flux = une 5-tuple (src_ip, src_port, dst_ip, dst_port, proto).
    Pour créer UN flux, on garde le MÊME socket source et on envoie
    PLUSIEURS paquets vers la MÊME destination.
    """

    def __init__(self):
        self.stop = threading.Event()
        self.counters = Counter()
        self.threads = []
        self._lock = threading.Lock()

    def _inc(self, key, n=1):
        with self._lock:
            self.counters[key] += n

    # ─── Sinks (récepteurs) ────────────────────────────────────────────────
    @staticmethod
    def _sink_udp(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.settimeout(0.2)
        return s

    @staticmethod
    def _sink_tcp(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(16)
        s.settimeout(0.5)
        return s

    # ─── 1. Flux UDP LONG : 1 socket, N paquets espacés ────────────────────
    def udp_long_flow(self, base_port, n_packets=100, delay=0.05):
        """Crée UN SEUL flux UDP de n_packets paquets, étalé dans le temps.

        Le socket source garde le même port → même 5-tuple → même flux.
        Avec delay=0.05 et n=100, le flux dure ~5 secondes.
        """
        sink = self._sink_udp(base_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))  # port source attribué une fois = flux stable
        src_port = s.getsockname()[1]
        log("UDP", f"flux long : 127.0.0.1:{src_port} → :{base_port} "
                   f"({n_packets} paquets, {delay*1000:.0f}ms d'intervalle)", C.MAGENTA)

        # Thread qui consomme les paquets côté récepteur
        def drain():
            while not self.stop.is_set():
                try:
                    sink.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
        threading.Thread(target=drain, daemon=True).start()

        for i in range(n_packets):
            if self.stop.is_set():
                break
            try:
                s.sendto(f"paquet {i}".encode(), ("127.0.0.1", base_port))
                self._inc("udp_pkt")
            except OSError:
                break
            time.sleep(delay)

        s.close()
        sink.close()
        log("UDP", f"flux long terminé ({src_port} → {base_port})", C.DIM)

    # ─── 2. Flux TCP RICHE : plusieurs allers-retours ──────────────────────
    def tcp_rich_flow(self, base_port, n_rounds=20):
        """Une session TCP avec n_rounds allers-retours ping/pong.

        Ça donne un flux avec pkts_ltr ≈ n_rounds et pkts_rtl ≈ n_rounds,
        et des octets dans les deux sens.
        """
        sink = self._sink_tcp(base_port)
        log("TCP", f"flux riche : 20 allers-retours vers :{base_port}", C.MAGENTA)

        def server():
            try:
                conn, _ = sink.accept()
                conn.settimeout(1.0)
                while not self.stop.is_set():
                    try:
                        data = conn.recv(1024)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    conn.send(b"pong " * 8)
                    self._inc("tcp_rtl")
                conn.close()
            except OSError:
                pass
            finally:
                try:
                    sink.close()
                except OSError:
                    pass

        srv = threading.Thread(target=server, daemon=True)
        srv.start()
        time.sleep(0.1)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", base_port))
            for i in range(n_rounds):
                if self.stop.is_set():
                    break
                s.send(f"ping {i}".encode())
                self._inc("tcp_ltr")
                try:
                    s.recv(256)
                except socket.timeout:
                    pass
                time.sleep(0.03)
            s.close()
        except OSError as e:
            log("TCP", f"erreur : {e}", C.RED)

        srv.join(timeout=1.0)
        log("TCP", f"flux riche terminé (:{base_port}, {n_rounds} allers-retours)", C.DIM)

    # ─── 3. Flux PARALLÈLES : N flux UDP simultanés ────────────────────────
    def parallel_udp_flows(self, base_port, n_flows=10, packets_each=50, delay=0.03):
        """Crée n_flows flux UDP EN PARALLÈLE, chacun avec packets_each paquets.

        Chaque flux a sa propre 5-tuple (port source et destination différents).
        Total : n_flows × packets_each paquets, n_flows flux distincts.
        """
        log("PAR", f"{n_flows} flux UDP parallèles × {packets_each} paquets "
                   f"(ports {base_port}..{base_port + n_flows - 1})", C.MAGENTA)

        sinks = {}
        for i in range(n_flows):
            try:
                sinks[base_port + i] = self._sink_udp(base_port + i)
            except OSError:
                pass

        # Drain global
        def drain_all():
            while not self.stop.is_set():
                for sk in list(sinks.values()):
                    try:
                        sk.recvfrom(2048)
                    except socket.timeout:
                        pass
                    except OSError:
                        pass
        threading.Thread(target=drain_all, daemon=True).start()

        def one_flow(idx):
            port = base_port + idx
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            for i in range(packets_each):
                if self.stop.is_set():
                    break
                try:
                    s.sendto(f"f{idx}p{i}".encode(), ("127.0.0.1", port))
                    self._inc("par_pkt")
                except OSError:
                    break
                time.sleep(delay)
            s.close()

        ths = [threading.Thread(target=one_flow, args=(i,), daemon=True)
               for i in range(n_flows)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()

        for sk in sinks.values():
            try:
                sk.close()
            except OSError:
                pass
        log("PAR", f"{n_flows} flux parallèles terminés", C.DIM)

    # ─── 4. Port scan : 40 flux courts depuis la même source ───────────────
    def port_scan(self, base_port, n_ports=40):
        """Simule un port scan : N tentatives TCP vers N ports différents.

        Chaque tentative = 1 flux court (1 paquet SYN, pas de réponse).
        C'est la signature que la règle 'port_scan' doit détecter.
        """
        log("SCAN", f"port scan : {n_ports} ports depuis 127.0.0.1 "
                    f"({base_port}..{base_port + n_ports - 1})", C.YELLOW)

        # Un socket source unique : même IP source pour toutes les tentatives
        for i in range(n_ports):
            if self.stop.is_set():
                break
            port = base_port + i
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect_ex(("127.0.0.1", port))
                s.close()
                self._inc("scan_port")
            except OSError:
                pass
            time.sleep(0.01)
        log("SCAN", f"port scan terminé ({n_ports} tentatives)", C.DIM)

    # ─── 5. TCP long : session maintenue ouverte ───────────────────────────
    def tcp_long_session(self, base_port, duration=5.0, interval=0.2):
        """Une session TCP maintenue ouverte `duration` secondes avec
        des échanges réguliers → un flux TCP de longue durée."""
        sink = self._sink_tcp(base_port)
        log("TCPL", f"session TCP longue : :{base_port} pendant {duration:.0f}s", C.MAGENTA)

        def server():
            try:
                conn, _ = sink.accept()
                conn.settimeout(1.0)
                t0 = time.time()
                while not self.stop.is_set() and time.time() - t0 < duration:
                    try:
                        data = conn.recv(1024)
                        if data:
                            conn.send(b"ack")
                            self._inc("tcpl_rtl")
                    except socket.timeout:
                        continue
                conn.close()
            except OSError:
                pass
            finally:
                try:
                    sink.close()
                except OSError:
                    pass

        srv = threading.Thread(target=server, daemon=True)
        srv.start()
        time.sleep(0.1)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", base_port))
            t0 = time.time()
            i = 0
            while not self.stop.is_set() and time.time() - t0 < duration:
                s.send(f"keepalive {i}".encode())
                self._inc("tcpl_ltr")
                try:
                    s.recv(64)
                except socket.timeout:
                    pass
                time.sleep(interval)
                i += 1
            s.close()
        except OSError as e:
            log("TCPL", f"erreur : {e}", C.RED)

        srv.join(timeout=1.0)
        log("TCPL", f"session longue terminée (:{base_port})", C.DIM)

    # ─── Lancement selon le scénario ───────────────────────────────────────
    def start(self, scenario="full"):
        jobs = []

        if scenario in ("full", "udp"):
            jobs.append(threading.Thread(
                target=self.udp_long_flow, args=(45001, 200, 0.03), daemon=True))
            jobs.append(threading.Thread(
                target=self.udp_long_flow, args=(45002, 150, 0.04), daemon=True))

        if scenario in ("full", "tcp"):
            jobs.append(threading.Thread(
                target=self.tcp_rich_flow, args=(45101, 25), daemon=True))
            jobs.append(threading.Thread(
                target=self.tcp_rich_flow, args=(45102, 15), daemon=True))

        if scenario in ("full", "parallel"):
            jobs.append(threading.Thread(
                target=self.parallel_udp_flows, args=(45200, 10, 60, 0.03), daemon=True))

        if scenario in ("full", "tcp"):
            jobs.append(threading.Thread(
                target=self.tcp_long_session, args=(45300, 6.0, 0.25), daemon=True))

        if scenario in ("full", "scan"):
            jobs.append(threading.Thread(
                target=self.port_scan, args=(45400, 50), daemon=True))

        for j in jobs:
            j.start()
            self.threads.append(j)

        log("TRAFIC", f"scénario '{scenario}' : {len(jobs)} générateurs lancés", C.MAGENTA)

    def stop_all(self):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=3)


# ─── Lecteur de flux en parallèle ──────────────────────────────────────────
class FlowReader:
    def __init__(self, engine, ifname, reader_id, stop_event):
        self.engine = engine
        self.ifname = ifname
        self.reader_id = reader_id
        self.stop = stop_event
        self.total = 0
        self.flows = []
        self.errors = []
        self._lock = threading.Lock()

    def run(self):
        while not self.stop.is_set():
            try:
                arr = self.engine.read(self.ifname, max=256)
                if len(arr):
                    log(f"R{self.reader_id}", f"Lu {len(arr)}", C.BLUE)
                    with self._lock:
                        self.total += len(arr)
                        for f in arr:
                            self.flows.append(f)
                    for f in arr:
                        self._print_flow(f)
            except EngineError as e:
                with self._lock:
                    self.errors.append(str(e))
                log(f"R{self.reader_id}", f"erreur : {e}", C.RED)
                break
            except Exception as e:
                with self._lock:
                    self.errors.append(str(e))
                break
            time.sleep(0.05)

    def _print_flow(self, f):
        try:
            ini, pi, rec, pr = flow_addresses(f)
        except Exception:
            ini, pi, rec, pr = "?", 0, "?", 0
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(f["proto"]), str(f["proto"]))
        verdict = {0: "—", 1: "ALERTE", 2: "BLOQUÉ"}.get(int(f["verdict"]), str(f["verdict"]))
        rule = RULE_NAMES.get(int(f["rule_reason"]), "?")
        reason = END_REASONS.get(int(f["reason"]), "?")
        dur_ms = (int(f["end_time"]) - int(f["start_time"]))

        vcolor = C.GREEN
        if verdict == "ALERTE":
            vcolor = C.YELLOW
        elif verdict == "BLOQUÉ":
            vcolor = C.RED

        print(
            f"  {C.CYAN}R{self.reader_id}{C.RESET} "
            f"{C.BOLD}{proto:4}{C.RESET} "
            f"{ini}:{pi} → {rec}:{pr} "
            f"{C.DIM}pkts={int(f['n_pkt_ltr'])}/{int(f['n_pkt_rtl'])} "
            f"oct={int(f['octets_ltr'])}/{int(f['octets_rtl'])} "
            f"dur={dur_ms}ms "
            f"fin={reason}{C.RESET} "
            f"{vcolor}{verdict}{C.RESET}"
            + (f" {C.MAGENTA}rule={rule}{C.RESET}" if rule != "none" else ""),
            flush=True,
        )


# ─── Stats ─────────────────────────────────────────────────────────────────
def stats_line(st, delta):
    parts = [
        f"{C.BLUE}in{C.RESET}={st['frames_in']}(+{delta.get('frames_in', 0)})",
        f"{C.GREEN}ok{C.RESET}={st['frames_ok']}(+{delta.get('frames_ok', 0)})",
        f"{C.YELLOW}ign{C.RESET}={st['frames_ignored']}(+{delta.get('frames_ignored', 0)})",
        f"{C.RED}fail{C.RESET}={st['frames_failed']}(+{delta.get('frames_failed', 0)})",
        f"{C.MAGENTA}flux{C.RESET}={st['flows_exported']}(+{delta.get('flows_exported', 0)})",
        f"{C.RED}perdus{C.RESET}={st['flows_lost']}",
        f"{C.CYAN}actifs{C.RESET}={st['active_flows']}",
        f"{C.YELLOW}bloqués{C.RESET}={st['blocked_flows']}",
        f"{C.DIM}ring {st['ring_used']}/{st['ring_size']}{C.RESET}",
        f"{C.DIM}drop={st['ring_dropped']}{C.RESET}",
        f"{C.WHITE}état={st['state']}{C.RESET}",
    ]
    return "  ".join(parts)


# ─── Main ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Démo live du moteur IDS/IPS (v2)")
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--duration", type=float, default=25)
    ap.add_argument("--readers", type=int, default=3)
    ap.add_argument("--scenario", default="full",
                    choices=["full", "udp", "tcp", "parallel", "scan"])
    ap.add_argument("--no-traffic", action="store_true")
    ap.add_argument("--scan-threshold", type=int, default=10,
                    help="seuil port_scan (défaut: 10, pour déclencher plus facilement)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print(f"{C.RED}❌ Il faut root (ou CAP_NET_RAW).{C.RESET}")
        print(f"   sudo python3 {sys.argv[0]}")
        sys.exit(1)

    print(f"\n{C.BOLD}{'=' * 78}{C.RESET}")
    print(f"{C.BOLD}  DÉMO LIVE IDS/IPS — v2 (vrais flux){C.RESET}")
    print(f"{C.BOLD}{'=' * 78}{C.RESET}")
    print(f"  Interface    : {C.CYAN}{args.iface}{C.RESET}")
    print(f"  Durée        : {C.CYAN}{args.duration}s{C.RESET}")
    print(f"  Lecteurs     : {C.CYAN}{args.readers} threads{C.RESET}")
    print(f"  Scénario     : {C.CYAN}{args.scenario}{C.RESET}")
    print(f"{C.BOLD}{'=' * 78}{C.RESET}\n")

    log("INIT", "Création du moteur...", C.BLUE)
    eng = Engine()
    log("INIT", f"FLOW_DTYPE = {FLOW_DTYPE.itemsize} octets, {len(FLOW_DTYPE.names)} champs", C.BLUE)

    ring_prefix = f"live{os.getpid() % 10000}"
    log("START", f"Capture sur {args.iface} (ring={ring_prefix})", C.GREEN)
    eng.start(
        args.iface,
        ring_prefix=ring_prefix,
        idle_ms=1000,          # inactif après 1s (assez pour les flux longs)
        max_ms=15000,          # ferme après 15s max
        ring_size=8 << 20,     # 8 Mo
        poll_ms=100,
        batch_size=256,
    )
    ring = eng.ring_name(args.iface)
    log("START", f"Ring : {C.CYAN}{ring}{C.RESET} ({'/dev/shm' + ring})", C.GREEN)

    # Baisse le seuil port_scan pour déclencher la règle facilement
    try:
        eng.rules_set("port_scan", threshold=args.scan_threshold)
        log("RULES", f"port_scan threshold = {args.scan_threshold}", C.YELLOW)
        r = eng.rules_get()
        for name, cfg in r.items():
            log("RULES", f"  {name:12} enabled={cfg['enabled']} threshold={cfg['threshold']}", C.DIM)
    except Exception as e:
        log("RULES", f"impossible de régler : {e}", C.RED)

    # Threads lecteurs
    stop_readers = threading.Event()
    readers = [FlowReader(eng, args.iface, i + 1, stop_readers) for i in range(args.readers)]
    for r in readers:
        threading.Thread(target=r.run, daemon=True).start()
    log("READ", f"{args.readers} threads lecteurs lancés", C.CYAN)

    # Trafic
    gen = None
    if not args.no_traffic:
        gen = FlowGenerator()
        gen.start(args.scenario)

    # Monitoring
    log("STATS", "Monitoring (Ctrl+C pour arrêter)", C.WHITE)
    print()
    t0 = time.time()
    prev_st = None
    last_print = 0
    try:
        while time.time() - t0 < args.duration:
            time.sleep(0.5)
            now = time.time()
            if now - last_print < 1.0:
                continue
            last_print = now
            try:
                st = eng.stats(args.iface)
                delta = {}
                if prev_st:
                    for k, v in st.items():
                        if isinstance(v, int) and isinstance(prev_st.get(k), int):
                            delta[k] = v - prev_st[k]
                prev_st = st
                elapsed = int(now - t0)
                print(f"{C.DIM}[{elapsed:3d}s]{C.RESET} {stats_line(st, delta)}", flush=True)
            except EngineError as e:
                log("STATS", f"Erreur : {e}", C.RED)
                break
    except KeyboardInterrupt:
        print()
        log("STOP", "Interruption clavier", C.YELLOW)

    print()
    log("STOP", "Arrêt du trafic...", C.YELLOW)
    if gen:
        gen.stop_all()

    log("STOP", "Arrêt des lecteurs...", C.YELLOW)
    stop_readers.set()
    time.sleep(0.3)

    log("STOP", "Arrêt capture (flush des flux restants)...", C.YELLOW)
    try:
        eng.stop(args.iface)
    except EngineError as e:
        log("STOP", f"Erreur stop : {e}", C.RED)

    # Lecture finale
    log("FLUSH", "Lecture des flux restants...", C.CYAN)
    time.sleep(0.5)
    final_flows = []
    try:
        for _ in range(30):
            arr = eng.read(args.iface, max=512)
            if not len(arr):
                break
            final_flows.append(arr)
            for f in arr:
                readers[0]._print_flow(f)
            time.sleep(0.1)
    except EngineError as e:
        log("FLUSH", f"Erreur : {e}", C.RED)

    # Résumé
    print()
    print(f"{C.BOLD}{'=' * 78}{C.RESET}")
    print(f"{C.BOLD}  RÉSUMÉ{C.RESET}")
    print(f"{C.BOLD}{'=' * 78}{C.RESET}")

    all_flows = []
    for r in readers:
        all_flows.extend(r.flows)
    for arr in final_flows:
        all_flows.extend(arr)

    try:
        st = eng.stats(args.iface)
        print(f"\n  {C.BOLD}Compteurs moteur :{C.RESET}")
        for k, v in st.items():
            print(f"    {k:20} = {v}")
    except EngineError:
        pass

    if gen:
        print(f"\n  {C.BOLD}Trafic généré :{C.RESET}")
        for k, v in sorted(gen.counters.items()):
            print(f"    {k:20} = {v}")

    print(f"\n  {C.BOLD}Flux collectés : {len(all_flows)}{C.RESET}")
    if all_flows:
        protos = Counter(int(f["proto"]) for f in all_flows)
        reasons = Counter(int(f["reason"]) for f in all_flows)
        verdicts = Counter(int(f["verdict"]) for f in all_flows)
        rules = Counter(int(f["rule_reason"]) for f in all_flows)

        print("    Protocoles : " + ", ".join(
            f"{ {6:'TCP',17:'UDP',1:'ICMP'}.get(k, k) }={v}" for k, v in protos.most_common()))
        print("    Verdicts   : " + ", ".join(
            f"{ {0:'—',1:'ALERTE',2:'BLOQUÉ'}.get(k, k) }={v}" for k, v in verdicts.most_common()))
        print("    Fins       : " + ", ".join(
            f"{END_REASONS.get(k, k)}={v}" for k, v in reasons.most_common()))
        print("    Règles     : " + ", ".join(
            f"{RULE_NAMES.get(k, k)}={v}" for k, v in rules.most_common()))

        # Distribution du nombre de paquets par flux
        pkts = [int(f["n_pkt_ltr"]) + int(f["n_pkt_rtl"]) for f in all_flows]
        if pkts:
            print(f"\n  {C.BOLD}Paquets par flux :{C.RESET}")
            print(f"    min={min(pkts)}  max={max(pkts)}  "
                  f"moy={sum(pkts)/len(pkts):.1f}  total={sum(pkts)}")
            multi = sum(1 for p in pkts if p > 1)
            print(f"    flux multi-paquets : {multi}/{len(pkts)} "
                  f"({100*multi/len(pkts):.0f}%)")

        print(f"\n  {C.BOLD}Par lecteur :{C.RESET}")
        for r in readers:
            print(f"    Lecteur {r.reader_id} : {r.total} flux lus"
                  + (f" {C.RED}({len(r.errors)} erreurs){C.RESET}" if r.errors else ""))

    all_errors = [e for r in readers for e in r.errors]
    if all_errors:
        print(f"\n  {C.RED}{C.BOLD}Erreurs :{C.RESET}")
        for e in all_errors[:5]:
            print(f"    {e}")

    print()
    log("RELEASE", f"Suppression du ring {ring}...", C.YELLOW)
    try:
        eng.release(args.iface)
    except EngineError as e:
        log("RELEASE", f"Erreur : {e}", C.RED)

    if os.path.exists("/dev/shm" + ring):
        log("WARN", f"Le ring existe encore : /dev/shm{ring}", C.YELLOW)
    else:
        log("RELEASE", "Ring supprimé ✓", C.GREEN)

    eng.close()
    log("DONE", f"Terminé. {len(all_flows)} flux au total.", C.GREEN)
    print()


if __name__ == "__main__":
    main()