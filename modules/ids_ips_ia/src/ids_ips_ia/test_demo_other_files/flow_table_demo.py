#!/usr/bin/env python3
"""
flow_table_demo.py — comment coder une TABLE DE FLUX en Python (exemple pédagogique, autonome).

Idée : au lieu de noter chaque PAQUET avec du ML, on regroupe les paquets d'une même connexion en un
FLUX (quelques dizaines de compteurs) et on note le flux. Ce fichier montre les 5 briques :

  1. parse_eth()      trame brute -> tuple léger (ts, src, dst, sport, dport, proto, longueur, flags)
  2. FlowTable        table bornée : clé 5-tuple bidirectionnelle, stats incrémentales (Welford), timeouts
  3. agrégats         par SOURCE (scans) et par DESTINATION (floods) sur une fenêtre de 10 s
  4. règles niveau 1  O(1), toujours actives (scan, SYN flood)
  5. features()       vecteur par flux -> ML niveau 2 (IsolationForest ici, tes AE/IF/LOF chez toi)

Lancer :
    python3 flow_table_demo.py              # trafic synthétique : normal + scan + SYN flood, avec benchmark
    python3 flow_table_demo.py --pcap x.pcap # pcap classique (pas pcapng) -> flux + alertes

Dépendances : aucune (numpy + scikit-learn en option pour la démo ML de niveau 2).

⚠️ Python pur = ~quelques centaines de milliers de paquets/s par cœur au mieux (voir le benchmark affiché).
   1 Gb/s ≈ 120 kpps, 10 Gb/s ≈ 1,2 Mpps : pour la prod, la table de flux doit être NATIVE (Cython/Rust)
   ou venir de Suricata ; ce fichier sert à comprendre et à valider les features/règles AVANT de les porter.
"""
import heapq
import math
import random
import struct
import sys
import time
from collections import OrderedDict, defaultdict

# ----------------------------------------------------------------------------------------------
# Paramètres
# ----------------------------------------------------------------------------------------------
MAX_FLOWS = 200_000        # taille max de la table (au-delà : on évince le plus ancien)
MAX_FLOWS_PER_SRC = 5_000  # plafond par IP source : une IP (même usurpée) ne peut pas noyer la table
IDLE_TIMEOUT = 15.0        # flux inactif depuis N s -> émis puis supprimé
ACTIVE_TIMEOUT = 60.0      # flux très long -> émis périodiquement
EARLY_PKTS = 10            # évaluation PRÉCOCE après N paquets (détecter vite, sans attendre la fin)
HEAD = 5                   # on garde la taille signée des N premiers paquets (+ = aller, - = retour)
WINDOW = 10.0              # fenêtre des agrégats source/destination (secondes)
SCAN_PORTS, SCAN_HOSTS = 100, 50    # règle scan : >= N ports ou N hôtes distincts en une fenêtre
FLOOD_NEW_FLOWS = 2_000             # règle flood : >= N nouveaux flux vers UNE destination en une fenêtre
SET_CAP = 512                       # on arrête de compter les ports/hôtes distincts au-delà (mémoire bornée)

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# ----------------------------------------------------------------------------------------------
# 1) Parsing : trame Ethernet brute -> tuple léger. Des tuples d'entiers sont bien plus rapides
#    que des objets (dpkt/scapy) : c'est le chemin chaud, chaque microseconde compte.
# ----------------------------------------------------------------------------------------------
def parse_eth(ts, data):
    """Retourne (ts, src_ip, dst_ip, sport, dport, proto, longueur, flags_tcp) ou None (non-IPv4/TCP/UDP/ICMP)."""
    if len(data) < 34 or data[12] != 0x08 or data[13] != 0x00:      # ethertype IPv4 uniquement (pas de VLAN ici)
        return None
    ihl = (data[14] & 0x0F) * 4
    proto = data[23]
    src, dst = struct.unpack_from("!II", data, 26)
    sport = dport = flags = 0
    off = 14 + ihl
    if proto == 6 and len(data) >= off + 14:                          # TCP
        sport, dport = struct.unpack_from("!HH", data, off)
        flags = data[off + 13]
    elif proto == 17 and len(data) >= off + 4:                        # UDP
        sport, dport = struct.unpack_from("!HH", data, off)
    elif proto != 1:                                                  # ICMP garde ports = 0
        return None
    return (ts, src, dst, sport, dport, proto, len(data), flags)


def read_pcap(path):
    """Lit un pcap CLASSIQUE (pas pcapng) et rend (timestamp, octets)."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        endian, nano = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
                        b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}.get(magic, (None, None))
        if endian is None:
            raise ValueError("format non supporté (pcapng ? convertis avec : editcap -F pcap in.pcapng out.pcap)")
        fh.read(20)                                                   # reste de l'en-tête global
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", hdr)
            yield sec + frac / (1e9 if nano else 1e6), fh.read(caplen)


# ----------------------------------------------------------------------------------------------
# 2) Le flux : compteurs mis à jour paquet par paquet, SANS garder les paquets.
#    Moyenne/écart-type incrémentaux (algorithme de Welford) : O(1) mémoire et temps par paquet.
# ----------------------------------------------------------------------------------------------
class Flow:
    __slots__ = ("key", "init", "proto", "start", "last", "pkts", "bytes", "syn", "ack", "fin", "rst", "psh", "urg",
                 "n", "sz_mean", "sz_m2", "sz_min", "sz_max", "iat_mean", "iat_m2", "iat_max", "head", "early")

    def __init__(self, key, init, proto, ts):
        self.key, self.init, self.proto, self.start, self.last = key, init, proto, ts, ts
        self.pkts, self.bytes = [0, 0], [0, 0]                         # [aller, retour]
        self.syn = self.ack = self.fin = self.rst = self.psh = self.urg = 0
        self.n = 0
        self.sz_mean = self.sz_m2 = 0.0
        self.sz_min, self.sz_max = 1 << 30, 0
        self.iat_mean = self.iat_m2 = self.iat_max = 0.0
        self.head = []
        self.early = False

    def update(self, ts, d, length, flags):
        """d = 0 si le paquet va dans le sens de l'initiateur (premier paquet vu), 1 sinon."""
        self.pkts[d] += 1
        self.bytes[d] += length
        self.n += 1
        delta = length - self.sz_mean                                  # Welford sur la taille des paquets
        self.sz_mean += delta / self.n
        self.sz_m2 += delta * (length - self.sz_mean)
        if length < self.sz_min:
            self.sz_min = length
        if length > self.sz_max:
            self.sz_max = length
        if self.n > 1:                                                 # Welford sur l'intervalle entre paquets
            iat = ts - self.last
            delta = iat - self.iat_mean
            self.iat_mean += delta / (self.n - 1)
            self.iat_m2 += delta * (iat - self.iat_mean)
            if iat > self.iat_max:
                self.iat_max = iat
        self.last = ts
        if flags:
            self.syn += flags & SYN > 0
            self.ack += flags & ACK > 0
            self.fin += flags & FIN > 0
            self.rst += flags & RST > 0
            self.psh += flags & PSH > 0
            self.urg += flags & URG > 0
        if len(self.head) < HEAD:
            self.head.append(length if d == 0 else -length)


# ----------------------------------------------------------------------------------------------
# 3) La table : OrderedDict = dict + ordre LRU. Le flux le plus ancien est toujours en tête -> les
#    expirations sont O(1) amorti (on s'arrête au premier flux encore frais).
# ----------------------------------------------------------------------------------------------
class FlowTable:
    def __init__(self, on_flow=None, on_alert=None):
        self.flows = OrderedDict()
        self.per_src = defaultdict(int)          # nb de flux ouverts par IP source (anti-saturation)
        self.on_flow = on_flow or (lambda kind, f: None)       # kind : "early" | "end" | "idle" | "active" | "evicted"
        self.on_alert = on_alert or (lambda a: None)
        self.src_win, self.dst_win = {}, defaultdict(int)       # agrégats de la fenêtre courante
        self.win_start = None
        self.last_sweep = 0.0
        self.counters = defaultdict(int)

    # ---- chemin chaud : appelé pour chaque paquet --------------------------------------------
    def add(self, pkt):
        ts, src, dst, sport, dport, proto, length, flags = pkt
        a, b = (src, sport), (dst, dport)
        key = (a, b, proto) if a <= b else (b, a, proto)          # même clé dans les DEUX sens
        f = self.flows.get(key)
        if f is None:
            self._roll_window(ts)
            self._count_new_flow(src, dst, dport, flags)           # agrégats source/destination
            if self.per_src[src] >= MAX_FLOWS_PER_SRC:             # trop de flux pour cette source : on ne crée pas
                self.counters["refused_new_flows"] += 1
                return
            if len(self.flows) >= MAX_FLOWS:                       # table pleine : on évince le plus ancien
                _, old = self.flows.popitem(last=False)
                self.per_src[old.init[0]] -= 1
                self.counters["evictions"] += 1
                self.on_flow("evicted", old)
            f = self.flows[key] = Flow(key, a, proto, ts)
            self.per_src[src] += 1
        else:
            self.flows.move_to_end(key)                            # le plus récemment vu passe en queue
        f.update(ts, 0 if a == f.init else 1, length, flags)

        if f.n == EARLY_PKTS and not f.early:                      # évaluation précoce (détecter vite)
            f.early = True
            self.on_flow("early", f)
        if flags & (FIN | RST):                                    # fin de connexion
            self._close(key, "end")
        elif ts - f.start > ACTIVE_TIMEOUT:                        # flux très long : on l'émet et on repart de zéro
            self._close(key, "active")
        if ts - self.last_sweep > 1.0:
            self.expire(ts)

    def _close(self, key, kind):
        f = self.flows.pop(key)
        self.per_src[f.init[0]] -= 1
        self.on_flow(kind, f)

    def expire(self, now):
        """Supprime les flux inactifs. Grâce à l'ordre LRU, on s'arrête au premier flux encore frais."""
        self.last_sweep = now
        while self.flows:
            key = next(iter(self.flows))
            if now - self.flows[key].last <= IDLE_TIMEOUT:
                break
            self._close(key, "idle")

    def flush(self):
        """Fin de capture : on émet tout ce qui reste."""
        for key in list(self.flows):
            self._close(key, "end")
        self._roll_window(float("inf"))

    # ---- agrégats par source et par destination (scans / floods) ---------------------------
    def _count_new_flow(self, src, dst, dport, flags):
        st = self.src_win.get(src)
        if st is None:
            st = self.src_win[src] = [0, set(), set()]              # [nouveaux flux, ports distincts, hôtes distincts]
        st[0] += 1
        if len(st[1]) < SET_CAP:
            st[1].add(dport)
        if len(st[2]) < SET_CAP:
            st[2].add(dst)
        self.dst_win[dst] += 1

    def _roll_window(self, ts):
        if self.win_start is None:
            self.win_start = ts
        if ts - self.win_start < WINDOW:
            return
        # ---- 4) règles de niveau 1 : O(1), évaluées une fois par fenêtre -----------------------
        for src, (n, ports, hosts) in self.src_win.items():
            if len(ports) >= SCAN_PORTS or len(hosts) >= SCAN_HOSTS:
                self.on_alert({"type": "SCAN", "src": src, "ports": len(ports), "hosts": len(hosts), "flows": n,
                               "t": self.win_start})
        for dst, n in self.dst_win.items():
            if n >= FLOOD_NEW_FLOWS:
                self.on_alert({"type": "FLOOD", "dst": dst, "new_flows": n, "t": self.win_start})
        self.src_win, self.dst_win, self.win_start = {}, defaultdict(int), ts


# ----------------------------------------------------------------------------------------------
# 5) Features : le vecteur donné au ML. On N'utilise PAS les IP/MAC bruts (le modèle apprendrait
#    des adresses, pas des comportements) ; l'IP reste la CLÉ du flux pour attribuer l'alerte.
# ----------------------------------------------------------------------------------------------
FEATURE_NAMES = (["dur", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "sz_mean", "sz_std", "sz_min", "sz_max",
                  "iat_mean", "iat_std", "iat_max", "pps", "bps", "syn", "ack", "fin", "rst", "psh", "urg",
                  "bwd_fwd_ratio", "proto", "port_class"] + [f"head{i}" for i in range(HEAD)])


def features(f):
    dur = max(f.last - f.start, 1e-6)
    n = f.n
    sz_std = math.sqrt(f.sz_m2 / n) if n > 1 else 0.0
    iat_std = math.sqrt(f.iat_m2 / (n - 1)) if n > 2 else 0.0
    resp_port = (f.key[1] if f.key[0] == f.init else f.key[0])[1]       # port côté « serveur »
    port_class = 0 if resp_port < 1024 else (1 if resp_port < 49152 else 2)
    head = f.head + [0] * (HEAD - len(f.head))
    return ([dur, f.pkts[0], f.pkts[1], f.bytes[0], f.bytes[1], f.sz_mean, sz_std, f.sz_min if n else 0, f.sz_max,
             f.iat_mean, iat_std, f.iat_max, n / dur, (f.bytes[0] + f.bytes[1]) / dur,
             f.syn, f.ack, f.fin, f.rst, f.psh, f.urg, f.bytes[1] / max(f.bytes[0], 1), f.proto, port_class] + head)


# ----------------------------------------------------------------------------------------------
# Démo : trafic synthétique (normal + scan + SYN flood), sans pcap ni réseau
# ----------------------------------------------------------------------------------------------
def ip(a, b, c, d):
    return (a << 24) | (b << 16) | (c << 8) | d


def ip_str(x):
    return ".".join(str((x >> s) & 255) for s in (24, 16, 8, 0))


def synth_traffic(seed=1, normal_flows=30_000, duration=60.0, with_attacks=True):
    """Liste de paquets (tuples) triés par temps."""
    rnd, pk = random.Random(seed), []
    servers = [(ip(192, 168, 1, i), p) for i in range(1, 11) for p in (80, 443, 22)]
    for _ in range(normal_flows):                                     # flux TCP « web » : poignée de main + échanges + FIN
        t = rnd.uniform(0, duration)
        c, (s, port), cp = ip(10, 0, rnd.randint(0, 3), rnd.randint(2, 250)), rnd.choice(servers), rnd.randint(32768, 60999)
        pk.append((t, c, s, cp, port, 6, 74, SYN))
        pk.append((t + 0.001, s, c, port, cp, 6, 74, SYN | ACK))
        pk.append((t + 0.002, c, s, cp, port, 6, 66, ACK))
        t += 0.002
        for _ in range(rnd.randint(2, 12)):
            t += rnd.expovariate(30)
            pk.append((t, c, s, cp, port, 6, rnd.randint(150, 700), PSH | ACK))
            t += rnd.expovariate(200)
            pk.append((t, s, c, port, cp, 6, rnd.randint(300, 1514), ACK))
        pk.append((t + 0.01, c, s, cp, port, 6, 66, FIN | ACK))
    for _ in range(normal_flows // 4):                                # DNS : 2 paquets UDP
        t, c, cp = rnd.uniform(0, duration), ip(10, 0, rnd.randint(0, 3), rnd.randint(2, 250)), rnd.randint(32768, 60999)
        pk.append((t, c, ip(192, 168, 1, 53), cp, 53, 17, 82, 0))
        pk.append((t + 0.01, ip(192, 168, 1, 53), c, 53, cp, 17, 140, 0))
    if with_attacks:
        att, victim = ip(203, 0, 113, 9), ip(10, 0, 0, 5)
        for i in range(1, 1025):                                      # scan de ports vertical : 1 SYN par port, RST en retour
            t = 35 + i * 0.001
            pk.append((t, att, victim, 40000, i, 6, 60, SYN))
            pk.append((t + 0.0005, victim, att, i, 40000, 6, 54, RST | ACK))
        for i in range(25_000):                                       # SYN flood : sources usurpées -> une seule cible
            pk.append((45 + i * 0.0002, rnd.getrandbits(32) | 0x01000000, ip(10, 0, 0, 80), rnd.randint(1024, 65000), 80, 6, 60, SYN))
    pk.sort(key=lambda p: p[0])
    return pk


def run(packets, label=""):
    flows_out, alerts, kinds = [], [], defaultdict(int)

    def on_flow(kind, f):
        kinds[kind] += 1
        flows_out.append((kind, features(f), f.init))

    table = FlowTable(on_flow=on_flow, on_alert=alerts.append)
    t0 = time.perf_counter()
    for p in packets:
        table.add(p)
    dt = time.perf_counter() - t0
    table.flush()
    print(f"\n=== {label} ===")
    print(f"{len(packets):,} paquets en {dt:.2f} s -> {len(packets) / dt / 1000:.0f} kpps, {dt / len(packets) * 1e9:.0f} ns/paquet "
          f"(1 cœur, Python pur)".replace(",", " "))
    print(f"flux émis : {dict(kinds)} | table : {dict(table.counters)}")
    return flows_out, alerts


def main():
    if "--pcap" in sys.argv:
        path = sys.argv[sys.argv.index("--pcap") + 1]
        pkts = [p for p in (parse_eth(ts, d) for ts, d in read_pcap(path)) if p]
        flows, alerts = run(pkts, f"pcap {path}")
        for a in alerts:
            print("ALERTE", {k: (ip_str(v) if k in ("src", "dst") else v) for k, v in a.items()})
        return

    # --- phase 1 : trafic NORMAL seul -> on entraîne le niveau 2 dessus ---------------------------
    normal = synth_traffic(seed=1, with_attacks=False)
    flows_n, alerts_n = run(normal, "trafic normal seul (référence / entraînement)")
    print(f"alertes niveau 1 sur le trafic normal : {len(alerts_n)} (doit être 0)")

    # --- phase 2 : trafic avec attaques -----------------------------------------------------------
    mixed = synth_traffic(seed=2, with_attacks=True)
    flows_m, alerts_m = run(mixed, "trafic normal + scan de ports + SYN flood")
    print("\nNIVEAU 1 — règles O(1) sur les agrégats :")
    for a in alerts_m:
        print("  🚨", {k: (ip_str(v) if k in ("src", "dst") else (round(v, 1) if k == "t" else v)) for k, v in a.items()})

    # --- niveau 2 : ML sur les flux (optionnel, nécessite numpy + scikit-learn) -------------------
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print("\n(numpy/scikit-learn absents : niveau 2 ignoré. pip install numpy scikit-learn)")
        return
    X_train = np.array([f for _, f, _ in flows_n])
    scaler = StandardScaler().fit(X_train)
    model = IsolationForest(n_estimators=100, contamination=0.001, random_state=0).fit(scaler.transform(X_train))
    X = np.array([f for _, f, _ in flows_m])
    score = model.decision_function(scaler.transform(X))             # plus bas = plus anormal
    flagged = score < np.percentile(model.decision_function(scaler.transform(X_train)), 0.5)
    print(f"\nNIVEAU 2 — IsolationForest sur {len(X):,} flux (batch, vectorisé) : {int(flagged.sum())} flux jugés anormaux".replace(",", " "))
    by_src = defaultdict(int)
    for (kind, _, init), bad in zip(flows_m, flagged):
        if bad:
            by_src[init[0]] += 1
    for src, n in sorted(by_src.items(), key=lambda kv: -kv[1])[:5]:
        print(f"  sources les plus représentées parmi les flux anormaux : {ip_str(src)} ({n} flux)")
    print("\n💡 Les flux du scan (1 SYN + 1 RST) sont repérés par le ML sur leur FORME (2 paquets, 0 octet de données) ;\n"
          "   le flood usurpé se voit surtout par la règle « destination » : chaque faux flux est trop banal seul.")


if __name__ == "__main__":
    main()
