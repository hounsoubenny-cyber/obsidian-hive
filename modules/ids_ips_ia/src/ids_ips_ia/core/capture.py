#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 16:07:03 2026

@author: hounsousamuel
"""

import os
import time
import dpkt
import pcap
import glob
import queue
import shutil
import select
import socket
import struct
import ctypes
import pickle
import asyncio
import platform
import threading
import traceback
import numpy as np
import multiprocessing as mp
from uuid import uuid4
from datetime import datetime
from collections import deque
from typing import Union, Any
from sklearn.preprocessing import StandardScaler
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.ids_ips_utils.utils import _get_ip_type
from ids_ips_ia.core.features_extractor import FeatureExtractor
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.core.config import (
    BUFFER_SIZE, TIMEOUT_MS, FILTER,
    SEQ_LENGTH, SRC_IGNORED_IP,
    DST_IGNORED_IP, SEQ_STRIDE_FIT, n_windows
)

logger = get_logger()

try:
    from ids_ips_ia.core._cython_module.extract_ip_cython import (
        extract_ip as _extract_ip_cython,
    )
    _USE_CYTHON = True
except ImportError:
    _USE_CYTHON = False
    logger.print("⚠️ Cython non disponible, utilisation de Python pur")


from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX
BASEDIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(BASEDIR, "data", INSTANCE_SUFFIX)
os.makedirs(DATADIR, exist_ok=True)


# 1e6 = Mb decimal
FIT_MAX_SIZE = 20_000         # paquets par chunk (taille d'un deque)
FIT_WORKERS = 4               # threads qui écrivent les chunks sur disque
EST_PKT_BYTES = 1200          # estimation RAM par paquet, sert à traduire max_size en octets
PKT_OVERHEAD = 120            # octets Python d'un paquet en plus du payload (tuple + float + objet bytes)
MIN_CHUNK_BYTES = 256_000     # plancher d'un chunk : en dessous, trop de petits fichiers

# En AF_PACKET, garde seulement les trames IPv4/IPv6 (ARP, STP, LLDP... ignorés),
# comme le fait déjà le filtre BPF 'tcp or udp or icmp' du mode pcap.
AF_PACKET_IP_ONLY = True


# ---------------------------------------------------------------- formatage

def _fmt_n(n) -> str:
    return f"{int(n):,}".replace(",", " ")

def _fmt_dur(seconds) -> str:
    s = max(0, int(seconds))
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"

def _rss_mb() -> float:
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6
    except Exception:
        return 0.0


# ------------------------------------------------- lecture rapide des trames

_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)  # 802.1Q, QinQ (802.1ad), ancien QinQ
_L4_V4 = (1, 6, 17)   # ICMP, TCP, UDP
_L4_V6 = (6, 17, 58)  # TCP, UDP, ICMPv6


def _l3(raw: bytes) -> tuple:
    """(EtherType, offset du début de l'en-tête IP) en sautant les étiquettes VLAN.
    (0, 0) si la trame est trop courte."""
    off = 12
    n = len(raw)
    while n >= off + 2:
        et = (raw[off] << 8) | raw[off + 1]
        if et in _VLAN_TYPES:
            off += 4
            continue
        return et, off + 2
    return 0, 0


def _is_ip_frame(raw: bytes) -> bool:
    """Vrai si la trame Ethernet transporte de l'IPv4 ou de l'IPv6 (VLAN empilés gérés)."""
    et, _ = _l3(raw)
    return et == 0x0800 or et == 0x86DD


def _match_tcp_udp_icmp(raw: bytes) -> bool:
    """Équivalent manuel de 'tcp or udp or icmp or icmp6' sur une trame Ethernet."""
    et, ip = _l3(raw)
    if et == 0x0800:   # IPv4 : protocole à l'octet 9 (20 octets min)
        return len(raw) >= ip + 20 and raw[ip + 9] in _L4_V4
    if et == 0x86DD:   # IPv6 : next header à l'octet 6 (40 octets fixes)
        return len(raw) >= ip + 40 and raw[ip + 6] in _L4_V6
    return False       # ARP, STP, LLDP...


def _pack_ips(ips) -> frozenset:
    """IP texte -> octets bruts (4 octets IPv4, 16 octets IPv6) pour comparer sans parser."""
    out = set()
    for ip in ips:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                out.add(socket.inet_pton(fam, ip))
                break
            except (OSError, ValueError, TypeError):
                continue
    return frozenset(out)


def _is_ignored(raw: bytes, src_set: frozenset, dst_set: frozenset) -> bool:
    """Vrai si la source ou la destination est dans les IP ignorées. Aucun parsing dpkt."""
    et, ip = _l3(raw)
    if et == 0x0800 and len(raw) >= ip + 20:
        return raw[ip + 12: ip + 16] in src_set or raw[ip + 16: ip + 20] in dst_set
    if et == 0x86DD and len(raw) >= ip + 40:
        return raw[ip + 8: ip + 24] in src_set or raw[ip + 24: ip + 40] in dst_set
    return False


def detect_all_ifaces() -> list:
    """Détecte TOUTES les interfaces sauf loopback"""
    faces = pcap.findalldevs()
    excluded = ['lo', 'bluetooth', 'usbmon', 'any', 'bluetooth-monitor', 'nfqueue', 'nflog']
    interfaces = [p for p in faces if not any(str(p).startswith(x) for x in excluded)]
    interfaces = interfaces or ['wlp1s0']
    logger.print('Interfaces de captures : ', interfaces)
    return interfaces


def _extract_ip(data: tuple | dpkt.ethernet.Ethernet) -> tuple:
    if isinstance(data, tuple):
        eth = dpkt.ethernet.Ethernet(data[1])
    else:
        eth = data

    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        src = ip.src
        dst = ip.dst
        if isinstance(src, str):
            src = bytes(src.encode())
        if isinstance(dst, str):
            dst = bytes(dst.encode())
        src = str(socket.inet_ntop(socket.AF_INET, src) or '0.0.0.0')
        dst = str(socket.inet_ntop(socket.AF_INET, dst) or '0.0.0.0')
        return src, dst

    elif isinstance(ip, dpkt.ip6.IP6):
        src = ip.src
        dst = ip.dst
        if isinstance(src, str):
            src = bytes(src.encode())
        if isinstance(dst, str):
            dst = bytes(dst.encode())
        src = str(socket.inet_ntop(socket.AF_INET6, src) or '::::')
        dst = str(socket.inet_ntop(socket.AF_INET6, dst) or '::::')
        return src, dst

    return None, None


def extract_ip(data: tuple | dpkt.ethernet.Ethernet) -> tuple:
    if not _USE_CYTHON:
        return _extract_ip(data)

    return _extract_ip_cython(data)

def _read_int(path: str) -> int | None:
    try:
        with open(path) as f:
            txt = f.read().strip()
        return None if txt == "max" else int(txt)
    except (OSError, ValueError):
        return None


def available_ram() -> int:
    """RAM réellement disponible (octets), en respectant la limite cgroup v2 (Docker, systemd)."""
    try:
        with open("/proc/meminfo") as f:
            avail = next(int(l.split()[1]) * 1024 for l in f if l.startswith("MemAvailable"))
    except (OSError, StopIteration):
        return 2 * 1024 ** 3          # mesure impossible (pas Linux) : valeur prudente
    limit, used = _read_int("/sys/fs/cgroup/memory.max"), _read_int("/sys/fs/cgroup/memory.current")
    if limit is not None and used is not None:
        avail = min(avail, limit - used)
    return max(avail, 0)


def plan_memory(max_size: int, workers: int, budget: int, allow_over_budget: bool = False) -> dict:
    """Décide de la taille des chunks et de la file pour que la RAM max tienne dans `budget` (octets).

    Le budget est la contrainte dure : si besoin on RÉDUIT le chunk, on ne lève jamais d'erreur.
    Avec allow_over_budget=True l'appelant impose sa taille de chunk : rien n'est réduit,
    mais `warning` est renseigné si la RAM max dépasse le budget.

    Places en mémoire : 1 chunk se remplit + `workers` en cours d'écriture + `queue_max` en attente.
    """
    wanted = int(max_size) * EST_PKT_BYTES                   # taille de chunk voulue (octets)
    slots = workers + 1 + 2                                  # minimum : 2 chunks en attente
    if allow_over_budget:
        chunk = wanted
    else:
        chunk = max(MIN_CHUNK_BYTES, min(wanted, budget // slots))
    queue_max = max(2, budget // chunk - workers - 1)
    ram_max = (queue_max + workers + 1) * chunk
    warning = None
    if ram_max > budget:
        warning = f"RAM max {ram_max / 1e6:.1f} Mo > budget {budget / 1e6:.1f} Mo"
    return {
        "max_size": max(100, chunk // EST_PKT_BYTES),        # paquets par chunk réellement appliqués
        "chunk_bytes": int(chunk),
        "queue_max": int(queue_max),
        "ram_max": int(ram_max),
        "budget": int(budget),
        "warning": warning,
    }


def _item_bytes(item) -> int:
    """Poids mémoire approximatif d'un paquet (ts, octets)."""
    try:
        return len(item[1]) + PKT_OVERHEAD
    except Exception:
        return EST_PKT_BYTES


# ------------------------------------------------------------ socket / BPF

# sortie de tcpdump -dd "tcp or udp or icmp or icmp6"
BPF_PROG = [
    ( 0x28, 0, 0, 0x0000000c ),
    ( 0x15, 0, 4, 0x00000800 ),
    ( 0x30, 0, 0, 0x00000017 ),
    ( 0x15, 10, 0, 0x00000006 ),
    ( 0x15, 9, 0, 0x00000011 ),
    ( 0x15, 8, 9, 0x00000001 ),
    ( 0x15, 0, 8, 0x000086dd ),
    ( 0x30, 0, 0, 0x00000014 ),
    ( 0x15, 5, 0, 0x00000006 ),
    ( 0x15, 0, 2, 0x0000002c ),
    ( 0x30, 0, 0, 0x00000036 ),
    ( 0x15, 2, 0, 0x00000006 ),
    ( 0x15, 1, 0, 0x00000011 ),
    ( 0x15, 0, 1, 0x0000003a ),
    ( 0x6, 0, 0, 0x00040000 ),
    ( 0x6, 0, 0, 0x00000000 ),
]
SO_ATTACH_FILTER = 26
SO_RCVBUFFORCE = 33 # pas SO_RCV qui peut siclencieusement être remplcé par le noyau
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_STATISTICS = 6


def attach_bpf(sock, prog=BPF_PROG):
    raw = b"".join(struct.pack("HBBI", *ins) for ins in prog)
    buf = ctypes.create_string_buffer(raw)   # doit rester vivant jusqu'au setsockopt
    fprog = struct.pack("HL", len(prog), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def _set_rcvbuf(sock, size: int) -> int:
    """Demande un tampon de réception de `size` octets et renvoie la valeur réelle.
    SO_RCVBUFFORCE (root) ignore le plafond net.core.rmem_max, sinon on retombe sur SO_RCVBUF."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, size)
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)


def _kernel_stats(sock) -> tuple:
    """(paquets vus par le socket après filtre, paquets jetés par le noyau).
    ATTENTION : la lecture remet les compteurs du noyau à zéro, donc ce sont des deltas."""
    try:
        seen, drops = struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        return seen, drops
    except (OSError, struct.error):
        return 0, 0


# --------------------------------------------------------------- fichiers

def _save(data, path):
    """Écriture atomique : fichier .tmp puis os.replace, jamais de chunk tronqué."""
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)


def _cum_save(data, path):
    with open(path, "ab") as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)


def load_pkt_file(path: str):
    with open(path, "rb") as f:
        while True:
            try:
                yield pickle.load(f)  # un chunk
            except EOFError:
                break


class QueueEmpty(Exception):
    pass


class BuffuredQueue:
    """Deque bornée -> quand elle est pleine, elle part (sans copie) dans une file de chunks
    que des threads écrivent sur disque.

    RAM max ~ (queue_max + num_workers + 1) x max_size x EST_PKT_BYTES.
    """
    DT_FORMAT = "%Y_%m_%d_%H_%M_%S"

    def __init__(
        self,
        max_size: int = 10_000,
        num_workers: int = 4,
        queue_max: int | None = None,
        mem_budget_mb: int | None = None,
        mem_frac: float = 0.18,
        allow_over_budget: bool = False,
        max_n_paquets: int | None = None,
    ):
        """
        max_size          : paquets par chunk VOULUS (peut être réduit pour respecter le budget)
        queue_max         : chunks en attente ; None = déduit du budget
        mem_budget_mb     : budget RAM en Mo ; None = mem_frac x RAM disponible (cgroups pris en compte)
        allow_over_budget : True = on garde max_size tel quel même si ça dépasse le budget (avertissement)
        """
        if max_n_paquets is None or max_n_paquets == 0:
            max_n_paquets = float("inf")
        
        self.max_n_paquets = max_n_paquets
        self.workers = []
        self.num_workers = int(num_workers) or 4
        budget = int(mem_budget_mb * 1e6) if mem_budget_mb else int(available_ram() * mem_frac)
        plan = plan_memory(int(max_size), self.num_workers, budget, allow_over_budget)
        self.max_size = plan["max_size"]            # paquets par chunk réellement appliqués
        self.chunk_bytes = plan["chunk_bytes"]      # plafond d'octets d'un chunk (garantit le budget)
        self.queue_max = int(min(100, max(2, queue_max or plan["queue_max"])))
        self.budget = budget
        self.ram_max = (self.queue_max + self.num_workers + 1) * self.chunk_bytes
        if self.ram_max > budget:
            logger.print(
                f"⚠️ BuffuredQueue : RAM max {self.ram_max / 1e6:.1f} Mo > budget "
                f"{budget / 1e6:.1f} Mo (allow_over_budget={allow_over_budget})"
            )
        elif self.max_size < int(max_size):
            logger.print(
                f"ℹ️ BuffuredQueue : chunks réduits de {int(max_size)} à {self.max_size} paquets "
                f"pour tenir dans le budget de {budget / 1e6:.0f} Mo"
            )

        self._deque = deque(maxlen=self.max_size)
        self._deque_bytes = 0                   # poids estimé du deque en cours de remplissage
        self._dt = datetime.now().strftime(BuffuredQueue.DT_FORMAT)
        self._save_dir = os.path.abspath(os.path.join(
            DATADIR, f"captures_file_{self._dt}"
        ))
        self._lock = threading.Lock()          # protège deque, compteur de fichiers, num_items
        self._stats_lock = threading.Lock()    # protège les compteurs des workers
        self._stop_event = threading.Event()
        self._finish_event = threading.Event()
        self._end_event: dict[str, threading.Event] = {}
        self._queue = queue.Queue(maxsize=self.queue_max)
        self._current_number = 0
        self._started = False
        self._finished = False

        self.num_items = 0
        self.saved_files = 0
        self.saved_items = 0
        self.failed_chunks = 0
        self.failed_items = 0
        os.makedirs(self._save_dir, exist_ok=True)

    def set_max_n_paquets(self, max_n_paquets: int | None = None):
        with self._lock:
            if max_n_paquets is None or max_n_paquets == 0:
                max_n_paquets = float("inf")
            
            self.max_n_paquets = max_n_paquets
        
        return
    
    @property
    def save_dir(self):
        return self._save_dir

    @property
    def current_number(self):
        return self._current_number

    def qsize(self):
        return self.num_items

    def stats(self) -> dict:
        with self._stats_lock:
            return {
                "queued": self._queue.qsize(),
                "in_deque": len(self._deque),
                "saved_files": self.saved_files,
                "saved_items": self.saved_items,
                "failed_chunks": self.failed_chunks,
                "failed_items": self.failed_items,
            }

    def _next_filename(self):
        # appelé sous self._lock ; zéro-paddé pour que le tri alphabétique = ordre chronologique
        filename = os.path.join(
            self._save_dir,
            f"file_{self._current_number:08d}.pkl"
        )
        self._current_number += 1
        return filename

    def _worker(self, worker_id: str):
        try:
            while not self._stop_event.is_set():
                try:
                    item = self._queue.get(timeout=0.2)   # attente passive, 0 % CPU au repos
                except queue.Empty:
                    # on revérifie empty() : le dernier chunk a pu arriver juste avant finish
                    if self._finish_event.is_set() and self._queue.empty():
                        break
                    continue

                if item is None:
                    continue

                data, filename = item
                try:
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
                    _save(list(data), filename)
                    with self._stats_lock:
                        self.saved_files += 1
                        self.saved_items += len(data)
                except Exception as e:
                    with self._stats_lock:
                        self.failed_chunks += 1
                        self.failed_items += len(data)
                    logger.print(
                        f"❌ [{worker_id}] échec d'écriture de {os.path.basename(filename)} "
                        f"({len(data)} paquets perdus) : {e!r}"
                     )
        finally:
            self._end_event[worker_id].set()

    def is_full(self):
        return len(self._deque) >= self.max_size or self._deque_bytes >= self.chunk_bytes

    def build_new_deque(self):
        with self._lock:
            self._deque = deque(maxlen=self.max_size)
            self._deque_bytes = 0

    def _put(self, data: Any, put_method: str = "put") -> bool:
        """put = bloquant si la file de chunks est pleine ; put_nowait = refuse et renvoie False."""
        block = put_method == "put"
        chunk = None
        max_n_paquets_reached = False
        try:
            with self._lock:
                if self._finished:
                    return True
                
                if self.num_items >= self.max_n_paquets:
                    max_n_paquets_reached = True
                    logger.info(
                        f"Nombre max de paquets demandé atteint: (demandé={self.max_n_paquets}, actuel={self.num_items})"
                    )
                    return True
                
                size = _item_bytes(data)
                # le chunk part quand il a max_size paquets OU quand le prochain le ferait dépasser chunk_bytes
                if (
                    self._deque and (
                        len(self._deque) >= self.max_size
                        or self._deque_bytes + size > self.chunk_bytes
                    )
                ):
                    if not block and self._queue.full():
                        return False           # tout est plein : le paquet est refusé (l'appelant le compte)
                    
                    item = (self._deque, self._next_filename())
                    if block:
                        chunk = item
                        
                    else:
                        try:
                            self._queue.put_nowait(item)
                        except queue.Full:
                            return False
                        
                    self._deque = deque(maxlen=self.max_size)
                    self._deque_bytes = 0
                self._deque.append(data)
                self._deque_bytes += size
                self.num_items += 1
                
        finally:
            if max_n_paquets_reached:
                self.make_finished()
                
        if chunk is not None:
            self._queue.put(chunk)         # bloquant, hors verrou
        return True

    def _get(self):
        with self._lock:
            try:
                item = self._deque.popleft()
            except IndexError as e:
                raise QueueEmpty(*e.args) from e
            self._deque_bytes = max(0, self._deque_bytes - _item_bytes(item))
            return item

    def put(self, data: Any):
        return self._put(data, "put")

    def put_nowait(self, data: Any):
        return self._put(data, "put_nowait")

    def get(self):
        return self._get()

    def get_nowait(self):
        return self._get()

    def make_finished(self):
        """Envoie le dernier chunk partiel et prévient les workers qu'il n'y aura plus rien."""
        with self._lock:
            if self._finished:
                return True
            self._finished = True
            chunk = None
            if self._deque:
                chunk = (self._deque, self._next_filename())
                self._deque = deque(maxlen=self.max_size)
                self._deque_bytes = 0
        if chunk is not None:
            self._queue.put(chunk)
        self._finish_event.set()
        return True

    def start(self):
        if self._started:
            return
        uuid = str(uuid4())[:8]
        self._stop_event.clear()
        self._finish_event.clear()
        self._finished = False
        for i in range(self.num_workers):
            wid = f"worker_{uuid}##{i}"
            self._end_event[wid] = threading.Event()
            th = threading.Thread(
                target=self._worker,
                args=(wid,),
                daemon=True,
                name=wid,
            )
            th.start()
            self.workers.append(th)
        self._started = True
        logger.print(
            f"💾 BuffuredQueue prête : chunks de {_fmt_n(self.max_size)} paquets max "
            f"(≤ {self.chunk_bytes / 1e6:.1f} Mo), {self.queue_max} chunks en attente max, "
            f"{self.num_workers} workers, RAM max ≈ {self.ram_max / 1e6:.0f} Mo "
            f"(budget {self.budget / 1e6:.0f} Mo) → {self._save_dir}"
        )

    def wait(self, timeout: float | None = None, log_every: float = 2.0) -> bool:
        """Attend que les workers aient tout écrit. Log de progression, sans boucle active."""
        t0 = time.time()
        for ev in list(self._end_event.values()):
            while not ev.wait(log_every):
                st = self.stats()
                logger.print(
                    f"⏳ [{_fmt_dur(time.time() - t0)}] écriture des derniers chunks : "
                    f"{st['queued']} en attente, {st['saved_files']} écrits "
                    f"({_fmt_n(st['saved_items'])} paquets)"
                )
                if timeout and time.time() - t0 > timeout:
                    return False
        return True

    def stop(self, timeout: int | float = 5):
        self._stop_event.set()
        for th in list(self.workers):
            try:
                if th:
                    th.join(timeout)
                    if not th.is_alive():
                        self.workers.remove(th)
            except Exception:
                pass


class _Local:
    """Compteurs locaux d'un thread de capture (pas de verrou dans la boucle chaude)."""
    __slots__ = ("recv", "kept", "ignored", "filtered", "dropped", "errors")

    def __init__(self):
        self.reset()

    def reset(self):
        self.recv = self.kept = self.ignored = self.filtered = self.dropped = self.errors = 0


class Capture:
    def __init__(
        self,
        queue: Union[BuffuredQueue, queue.Queue],
        backup_queue=None,
        src_ignored_ip: set = None,
        dst_ignored_ip: set = None,
        log_interval: float = 5.0,
    ):
        self.queue = queue
        self.event = threading.Event()
        self.threads = []
        self.save_task = None
        self.backup_queue = backup_queue
        self.use_af_packet = "linux" in platform.system().lower()
        self.log_interval = log_interval
        self.expected_duration = None       # renseigné par start_capture pour afficher "reste"
        self._t0 = None
        self._reporter_thread = None
        self._summary_logged = False
        self._stats_lock = threading.Lock()
        self._stats = dict.fromkeys(
            ("recv", "kept", "ignored", "filtered", "dropped", "errors", "k_seen", "k_drops"), 0
        )
        self.src_ignored_ip = src_ignored_ip or SRC_IGNORED_IP or {}
        self.src_ignored_ip = set(ip for ip in self.src_ignored_ip if _get_ip_type(ip) != "error")
        self.dst_ignored_ip = dst_ignored_ip or DST_IGNORED_IP or {}
        self.dst_ignored_ip = set(ip for ip in self.dst_ignored_ip if _get_ip_type(ip) != "error")
        self._refresh_ignored()

    def stats(self) -> dict:
        """Copie thread-safe des compteurs cumulés (recv, kept, dropped, k_seen, k_drops...)."""
        with self._stats_lock:
            return dict(self._stats)

        if self.use_af_packet:
            logger.print("🐧 Linux détecté → AF_PACKET activé (performance maximale)")
        else:
            logger.print(f"🍎 {platform.system()} détecté → fallback pcap")

    # ----------------------------------------------------------- IP ignorées

    def _refresh_ignored(self):
        self._src_packed = _pack_ips(self.src_ignored_ip)
        self._dst_packed = _pack_ips(self.dst_ignored_ip)

    def add_dst_ip_to_ignore(self, ip: str):
        if _get_ip_type(ip) != "error":
            self.dst_ignored_ip.add(str(ip))
            self._refresh_ignored()
            return True

        return False

    def remove_dst_ip_to_ignore(self, ip: str):
        try:
            self.dst_ignored_ip.remove(ip)
            self._refresh_ignored()
            return True
        except KeyError:
            pass

        return False

    def add_src_ip_to_ignore(self, ip: str):
        if _get_ip_type(ip) != "error":
            self.src_ignored_ip.add(str(ip))
            self._refresh_ignored()
            return True

        return False

    def remove_src_ip_to_ignore(self, ip: str):
        try:
            self.src_ignored_ip.remove(ip)
            self._refresh_ignored()
            return True
        except KeyError:
            pass

        return False

    def detect_all_ifaces(self) -> list:
        """Détecte TOUTES les interfaces sauf loopback"""
        return detect_all_ifaces()

    # ------------------------------------------------------------ statistiques

    @property
    def dropped_packets(self) -> int:
        return self._stats["dropped"]

    def _add(self, **kw):
        with self._stats_lock:
            for k, v in kw.items():
                self._stats[k] += v

    def _flush(self, loc: _Local, seen: int = 0, drops: int = 0):
        self._add(
            recv=loc.recv, kept=loc.kept, ignored=loc.ignored, filtered=loc.filtered,
            dropped=loc.dropped, errors=loc.errors, k_seen=seen, k_drops=drops,
        )
        loc.reset()

    def snapshot(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def _status_line(self, s: dict, rate: float, elapsed: float, new_loss: int = 0) -> str:
        lost = s["k_drops"] + s["dropped"]
        seen = s["k_seen"] or (s["recv"] + s["dropped"])
        pct = 100 * lost / seen if seen else 0.0
        parts = [
            f"{'⚠️' if new_loss else '📊'} [{_fmt_dur(elapsed)}]",
            f"{_fmt_n(s['kept'])} pkt ({_fmt_n(rate)}/s)",
            f"perdus : noyau {_fmt_n(s['k_drops'])} · app {_fmt_n(s['dropped'])} ({pct:.2f} %)",
        ]
        if s["ignored"] or s["filtered"]:
            parts.append(f"écartés : {_fmt_n(s['ignored'])} ignorés · {_fmt_n(s['filtered'])} filtrés")
        if s["errors"]:
            parts.append(f"erreurs : {_fmt_n(s['errors'])}")
        if hasattr(self.queue, "stats"):
            st = self.queue.stats()
            parts.append(f"file : {st['queued']} chunk(s) · disque : {st['saved_files']} fichier(s) "
                         f"/ {_fmt_n(st['saved_items'])} pkt")
            if st["failed_chunks"]:
                parts.append(f"❌ {st['failed_chunks']} chunk(s) en échec")
        if self.expected_duration:
            parts.append(f"reste {_fmt_dur(self.expected_duration - elapsed)}")
        parts.append(f"RAM {_rss_mb():.0f} Mo")
        return " | ".join(parts)

    def _reporter(self, interval: float = 1):
        prev, prev_t = self.snapshot(), time.monotonic()
        while not self.event.wait(interval):
            now = time.monotonic()
            cur = self.snapshot()
            dt = max(now - prev_t, 1e-9)
            rate = (cur["kept"] - prev["kept"]) / dt
            new_loss = (cur["k_drops"] - prev["k_drops"]) + (cur["dropped"] - prev["dropped"])
            logger.print(self._status_line(cur, rate, now - self._t0, new_loss))
            prev, prev_t = cur, now

    def summary(self) -> str:
        s = self.snapshot()
        elapsed = (time.monotonic() - self._t0) if self._t0 else 0.0
        lost = s["k_drops"] + s["dropped"]
        seen = s["k_seen"] or (s["recv"] + s["dropped"])
        pct = 100 * lost / seen if seen else 0.0
        avg = s["kept"] / elapsed if elapsed > 0 else 0.0
        return (
            f"🏁 Capture terminée en {_fmt_dur(elapsed)} : {_fmt_n(s['kept'])} paquets gardés "
            f"({_fmt_n(avg)}/s en moyenne) | perdus : noyau {_fmt_n(s['k_drops'])} + "
            f"app {_fmt_n(s['dropped'])} = {_fmt_n(lost)} ({pct:.2f} %) | "
            f"ignorés {_fmt_n(s['ignored'])}, filtrés {_fmt_n(s['filtered'])}, "
            f"erreurs {_fmt_n(s['errors'])}"
        )

    # ------------------------------------------------------------------ arrêt

    def stop(self, timeout: int | float = 1):
        self.event.set()
        tasks = list(self.threads)
        if self.save_task:
            tasks.append(self.save_task)
        if self._reporter_thread:
            tasks.append(self._reporter_thread)

        for th in tasks:
            try:
                if th:
                    th.join(timeout)
            except Exception:
                pass

        alive = [th for th in tasks if th and th.is_alive()]
        for th in alive:
            logger.print(f"⚠️ {th.name} tourne encore après {timeout}s")

        if not self._summary_logged:
            self._summary_logged = True
            logger.print(self.summary())
        return not alive     # True = tous les threads sont arrêtés

    def _put(self, q, item: Any) -> bool:
        """Dépose un paquet sans jamais bloquer. False = refusé (file pleine)."""
        try:
            ok = q.put_nowait(item)
        except queue.Full:
            return False
        return ok is None or ok is True  # queue.Queue renvoie None, BuffuredQueue renvoie True/False

    # ------------------------------------------------------------------- pcap

    def _pcap_capture(
        self,
        iface: str,
        filter: str = FILTER,
        thread_name: str = "_capture"
    ):
        opts = dict(
            snaplen=65535, immediate=True, promisc=True,
            buffer_size=BUFFER_SIZE or 64 * 1024 * 1024
        )
        try:
            pc = pcap.pcap(name=iface, timeout_ms=TIMEOUT_MS or 40, **opts)
        except Exception as e:
            logger.print(f"⚠️ [{thread_name}] ouverture de {iface} impossible ({e!r}) → interface par défaut")
            pc = pcap.pcap(name=None, timeout_ms=TIMEOUT_MS or 30, **opts)
        pc.setfilter(filter or 'tcp or udp or icmp')
        loc = _Local()
        last_flush = time.monotonic()
        last_stats = (0, 0)

        def flush():
            nonlocal last_stats
            seen = drops = 0
            try:
                recv, drop, ifdrop = pc.stats()
                seen = recv - last_stats[0]
                drops = (drop + ifdrop) - last_stats[1]
                last_stats = (recv, drop + ifdrop)
            except Exception:
                pass
            self._flush(loc, seen, drops)

        logger.print(f"🚀 Capture pcap démarrée sur {iface}")
        try:
            while not self.event.is_set():
                for ts, pkt in pc:
                    if self.event.is_set():
                        break

                    try:
                        loc.recv += 1
                        item = (ts, pkt)
                        if self._src_packed or self._dst_packed:
                            if _is_ignored(pkt, self._src_packed, self._dst_packed):
                                loc.ignored += 1
                                continue

                        if self._put(self.queue, item):
                            loc.kept += 1
                        else:
                            loc.dropped += 1
                        if self.backup_queue:
                            self._put(self.backup_queue, item)
                    except Exception as e:
                        loc.errors += 1
                        if loc.errors == 1:
                            logger.print(f"⚠️ [{thread_name}] erreur traitement paquet : {e!r}")

                    now = time.monotonic()
                    if now - last_flush >= 1.0:
                        flush()
                        last_flush = now
                flush()
        except Exception as e:
            logger.print(f"❌ [{thread_name}] erreur globale : {e!r}")
            logger.print(traceback.format_exc())
            
        finally:
            flush()
            pc.close()
            logger.print(f"🛑 Capture pcap arrêtée sur {iface}")

    # ------------------------------------------------------------- AF_PACKET

    def _socket_capture(
        self,
        iface: str,
        filter: str = FILTER,
        thread_name: str = "_capture",
        batch_size: int = 256
    ):
        """
        Capture AF_PACKET.

        Args:
            iface: Interface réseau (ex: "wlp1s0")
            filter: Filtre BPF (non utilisé ici, le bytecode BPF_PROG est attaché au socket)
            thread_name: Nom du thread pour les logs
            batch_size: Nombre max de paquets lus d'affilée avant de les traiter
        """
        sock = None
        loc = _Local()
        try:
            # protocole 0 : le socket ne reçoit RIEN tant qu'on n'a pas fait bind().
            # On attache donc le BPF d'abord, puis on bind : aucun paquet non filtré au démarrage.
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
            wanted = BUFFER_SIZE or 64 * 1024 * 1024
            actual = _set_rcvbuf(sock, wanted)
            if actual < wanted:
                logger.print(
                    f"⚠️ [{thread_name}] tampon socket plafonné à {actual / 1e6:.1f} Mo "
                    f"(demandé {wanted / 1e6:.0f} Mo). Débloque-le : "
                    f"sudo sysctl -w net.core.rmem_max={wanted}"
                )

            bpf_attached = False
            try:
                attach_bpf(sock, prog=BPF_PROG)
                bpf_attached = True
            except Exception as e:
                logger.print(f"⚠️ [{thread_name}] BPF non attaché ({e!r}) → filtre Python de secours")

            sock.bind((iface, 0x0003))       # ETH_P_ALL
            sock.setblocking(False)
            poller = select.poll()
            poller.register(sock, select.POLLIN)

            logger.print(
                f"🚀 Capture AF_PACKET démarrée sur {iface} | BPF noyau : "
                f"{'oui' if bpf_attached else 'non (filtre Python)'} | "
                f"tampon {actual / 1e6:.0f} Mo | lots de {batch_size}"
            )

            buf = bytearray(65536)           # tampon réutilisé : pas de malloc de 64 Ko par paquet
            mv = memoryview(buf)
            batch = []
            consecutive_err = 0
            last_flush = time.monotonic()

            while not self.event.is_set():
                if poller.poll(TIMEOUT_MS or 40):    # attend jusqu'à TIMEOUT_MS(40 ms), 1 seul appel pour tout un lot
                    batch.clear()
                    while len(batch) < batch_size:
                        try:
                            n = sock.recv_into(buf)
                        except BlockingIOError:
                            break            # socket vidé
                            
                        except OSError as e:
                            loc.errors += 1
                            consecutive_err += 1
                            if consecutive_err == 1 or consecutive_err % 500 == 0:
                                logger.print(f"⚠️ [{thread_name}] erreur recv ({consecutive_err} de suite) : {e!r}")
                                
                            time.sleep(min(1.0, 0.01 * consecutive_err))   # recul progressif (interface tombée...)
                            break
                        
                        consecutive_err = 0
                        batch.append((time.time(), bytes(mv[:n])))
                    loc.recv += len(batch)

                    try:
                        ip_only = AF_PACKET_IP_ONLY and not bpf_attached
                        src_set, dst_set = self._src_packed, self._dst_packed
                        check_ignored = bool(src_set or dst_set)
                        for item in batch:
                            raw = item[1]
                            if ip_only and not _match_tcp_udp_icmp(raw):
                                loc.filtered += 1
                                continue
                            if check_ignored and _is_ignored(raw, src_set, dst_set):
                                loc.ignored += 1
                                continue

                            if self._put(self.queue, item):
                                loc.kept += 1
                            else:
                                loc.dropped += 1
                            if self.backup_queue:
                                self._put(self.backup_queue, item)
                    except Exception as e:
                        loc.errors += 1
                        logger.print(f"⚠️ Erreur traitement paquet dans {thread_name}: {e!r}")

                now = time.monotonic()
                if now - last_flush >= 1.0:  # publie les compteurs + pertes du noyau
                    seen, drops = _kernel_stats(sock)
                    self._flush(loc, seen, drops)
                    last_flush = now

        except Exception as e:
            logger.print(
                f"❌ Erreur globale dans _socket_capture, thread_name={thread_name} : "
                f"{type(e).__name__}: {e}"
            )
            logger.print(traceback.format_exc())

        finally:
            if sock is not None:
                seen, drops = _kernel_stats(sock)
                self._flush(loc, seen, drops)
                try:
                    sock.close()
                except Exception:
                    pass
            logger.print(f"🛑 Capture AF_PACKET arrêtée sur {iface}")

    # ---------------------------------------------------------------- lancement

    def _capture(
        self,
        ifaces: list[str] = None,
        filter: str = FILTER,
        save_interval: int | None = None,
        path: str | None = None
    ):
        ifaces = ifaces or self.detect_all_ifaces()
        if isinstance(ifaces, str):
            ifaces = [ifaces]

        tasks = []
        capture_method = self._socket_capture if self.use_af_packet else self._pcap_capture
        self._t0 = time.monotonic()

        for iface in ifaces:
            th = threading.Thread(
                target=capture_method,
                args=(iface, filter, f"Capture-{iface}"),
                daemon=True, name=f"Capture-{iface}"
            )
            th.start()
            tasks.append(th)

        # for t in tasks:
        #     logger.print(t.name, t.is_alive(), self.event.is_set())
        self.threads = tasks

        if self.log_interval:
            self._reporter_thread = threading.Thread(
                target=self._reporter, args=(self.log_interval,),
                daemon=True, name="Capture-Reporter"
            )
            self._reporter_thread.start()

        if save_interval and path:
            if not isinstance(self.queue, queue.Queue):
                logger.print("L'objet queue passé ne permet pas une sauvegarde périodique !")
                return tasks

            def save_task():
                while not self.event.wait(save_interval):
                    try:
                        _save(list(self.queue.queue), path)
                    except Exception as e:
                        logger.print("Erreur sauvegarde :", str(e))

            self.save_task = threading.Thread(target=save_task, daemon=True, name="Save-Thread")
            self.save_task.start()
        return tasks

    def capture(
        self,
        ifaces: list[str],
        filter: str = FILTER,
        in_process: bool = False,
        save_interval: int | None = None,
        path: str | None = None
    ) -> mp.Process | None:

        if in_process:
            process = mp.Process(
                target=self._capture,
                args=(ifaces, filter, save_interval, path), 
                daemon=True, 
                name="Capture-Process"
            )
            process.start()
            return process

        self._capture(ifaces, filter, save_interval=save_interval, path=path)
        return


# ------------------------------------------------------------- fusion des chunks

def _count_items(path: str) -> int:
    if not os.path.exists(path):
        return 0
    return sum(len(c) for c in load_pkt_file(path))


def _merge_chunks(save_dir: str, path: str, delete: bool = False) -> int:
    """Fusionne les chunks (dans l'ordre) à la fin de `path`, un chunk en RAM à la fois.
    Ne supprime les chunks que si le nombre de paquets relu est exact."""
    files = sorted(glob.glob(os.path.join(save_dir, "*.pkl")))
    if not files:
        logger.print("ℹ️ Aucun chunk à fusionner")
        return 0
    
    if delete:
        if os.path.exists(path):
            try:
                os.unlink(path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
            except Exception:
                pass
    before = _count_items(path)          # `path` peut déjà contenir des données : on ajoute à la suite
    t0, total = time.time(), 0
    for i, file in enumerate(files, 1):
        with open(file, "rb") as f:
            data = pickle.load(f)
        _cum_save(data, path)
        total += len(data)
        if i % 5 == 0 or i == len(files):
            logger.print(
                f"🔗 Fusion {i}/{len(files)} chunks ({_fmt_n(total)} paquets, "
                f"{_fmt_dur(time.time() - t0)})"
            )

    after = _count_items(path)
    if after == before + total or after == total:
        shutil.rmtree(save_dir, ignore_errors=True)
        logger.print(f"✅ Plein succès lors du merge : {_fmt_n(total)} paquets → {path}")
    else:
        logger.print(f"❌ Merge incomplet : attendu {_fmt_n(before + total)}, trouvé {_fmt_n(after)}. "
                     f"Chunks conservés dans {save_dir}")
    return total


def start_capture(
    queue: BuffuredQueue,
    duration: int,
    path: str,
    save_interval: int | None = None,
    ifaces: list[str] = None,
    max_n_paquets: int | None = None,
):
    if max_n_paquets is None or max_n_paquets == 0:
        max_n_paquets = float("inf")

    queue.set_max_n_paquets(max_n_paquets)
    queue.start()
    ifaces = ifaces or []
    cap_obj = Capture(queue=queue)
    cap_obj.expected_duration = duration
    cap_obj.capture(
        ifaces=ifaces,
        filter=FILTER,
        save_interval=save_interval,
        path=path,
        in_process=False
    )
    start_time = time.time()
    logger.print(
        f"▶️ Collecte lancée pour {_fmt_dur(duration)}"
        + (f" ou {_fmt_n(max_n_paquets)} paquets" if max_n_paquets != float("inf") else "")
     )

    def _stop(*args, **kwargs):
        cap_obj.stop()

    if threading.current_thread() is threading.main_thread():
        signal_manager(_stop)

    try:
        while (
            time.time() < start_time + duration
            and queue.num_items < max_n_paquets
            and not cap_obj.event.is_set()
       ):
            time.sleep(0.5)

        if queue.num_items >= max_n_paquets:
            logger.print("🎯 Nombre de paquets demandé atteint")
            
        elif time.time() >= start_time + duration:
            logger.print("⏱️ Durée de collecte atteinte")

    except KeyboardInterrupt:
        logger.print("\n[INFO] Capture interrompue par l'utilisateur")

    except Exception as e:
        logger.print("\n[INFO, start_capture] Erreur : ", str(e))

    finally:
        stopped = cap_obj.stop(timeout=2)               # 1. plus aucun nouveau paquet
        if not stopped:
            cap_obj.stop(timeout=5)
        queue.make_finished()                           # 2. le dernier chunk partiel part sur disque
        queue.wait()                                    # 3. les workers vident la file (avec logs)
        queue.stop(timeout=1)
        st = queue.stats()
        if st["failed_chunks"]:
            logger.print(f"❌ {st['failed_chunks']} chunk(s) non écrits ({_fmt_n(st['failed_items'])} paquets perdus)")
        _merge_chunks(queue.save_dir, path, delete=True)
        return


def build_capture_filename(filename: str):
    return os.path.join(DATADIR, str(filename))


def _unpack_packet(el):
    if isinstance(el, dpkt.ethernet.Ethernet):
        return getattr(el, "ts", time.time()), bytes(el)

    elif isinstance(el, tuple):
        return el[0], el[1]

    raise ValueError("Type non supporté")


def _iter_packets(path: str, add_data_path: str = ""):
    """Flux (ts, octets) : d'abord la capture, puis les données à ajouter. Un chunk en RAM à la fois."""
    for chunk in load_pkt_file(path):
        for item in chunk:
            yield item[0], item[1]

    if add_data_path and os.path.exists(add_data_path):
        for chunk in load_pkt_file(add_data_path):
            for el in chunk:
                try:
                    pkt = _unpack_packet(el)
                except (ValueError, IndexError):
                    continue
                yield pkt


async def collect_and_process(
    duration: int = 7 * 24 * 3600,
    filename: str = "capture.pkl",
    add_data_path: str = "",
    save_interval: int = 36000,   # ignoré : la sauvegarde périodique est faite par les chunks
    ifaces: list[str] = None,
    max_size: int = FIT_MAX_SIZE,
    n_workers: int = FIT_WORKERS,
    max_n_paquets: int | None = None,
    budget_mb: int | None = None,
    mem_frac: float = 0.15,
    allow_over_budget: bool = False,
    *args, **kwargs
):
    try:
        ifaces = ifaces or []
        cap_queue = BuffuredQueue(
            max_size=max_size,
            num_workers=n_workers,
            mem_budget_mb=budget_mb,
            mem_frac=mem_frac,
            allow_over_budget=allow_over_budget,
            max_n_paquets=max_n_paquets
        )
        path = build_capture_filename(filename)
        start_capture(
            queue=cap_queue,
            duration=duration,
            path=path,
            ifaces=ifaces,
            max_n_paquets=max_n_paquets,
        )
        logger.print(f"Fin de la capture, {_fmt_n(cap_queue.qsize())} paquets enregistrés dans la durée !")
        if cap_queue.qsize() == 0:
            raise ValueError("Aucun paquet collecté !")

        # ---- extraction des features en flux : on ne garde JAMAIS tous les paquets en RAM
        extractor = FeatureExtractor()
        feats, bad, t0 = [], 0, time.time()
        for n, (ts, raw) in enumerate(_iter_packets(path, add_data_path), 1):
            try:
                el = dpkt.ethernet.Ethernet(raw)
                el.ts = ts
                feats.append(extractor.extract_pack_features(el))
            except Exception:
                bad += 1
            if n % 50_000 == 0:
                logger.print(
                    f"⚙️ Features : {_fmt_n(n)} paquets ({n / (time.time() - t0):,.0f}/s, "
                    f"RAM {_rss_mb():.0f} Mo)".replace(",", " ")
                 )

        if bad:
            logger.print(f"⚠️ {_fmt_n(bad)} paquets illisibles ignorés")
        logger.print(
            f"Nombre total finale de packet : {_fmt_n(len(feats))} "
            f"(features en {_fmt_dur(time.time() - t0)})"
        )

        X_packets = np.array(feats)
        del feats
        n_seq = n_windows(X_packets.shape[0], SEQ_LENGTH, SEQ_STRIDE_FIT)  # (N - L) // stride + 1
        if n_seq <= 0:
            raise ValueError("Pas assez de paquets pour une séquence !")

        t0 = time.time()
        seq_lis = []
        # Extraire les features de séquences (fenêtre glissante, pas = SEQ_STRIDE_FIT)
        for k in range(n_seq):
            i = k * SEQ_STRIDE_FIT
            try:
                seq_lis.append(extractor.extract_seq_features(X_packets[i: i + SEQ_LENGTH]))
            except Exception as e:
                logger.print("Erreur extraction sequence :", str(e))
            if (k + 1) % 50_000 == 0:
                logger.print(f"⚙️ Séquences : {_fmt_n(k + 1)}/{_fmt_n(n_seq)}")
        if not seq_lis:
            raise ValueError("Aucune séquence exploitable !")
        logger.print(f"Séquences prêtes : {_fmt_n(len(seq_lis))} en {_fmt_dur(time.time() - t0)}")

        X_sequences = np.array(seq_lis)
        del seq_lis
        logger.print("[DEBUG] Avant nettoyage:")
        logger.print(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")
        logger.print(f"  Inf dans séquences: {np.isinf(X_sequences).sum()}")
        logger.print(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")

        # Nettoyer
        X_sequences = np.nan_to_num(X_sequences, nan=0.0, posinf=1.0, neginf=-1.0)
        X_packets = np.nan_to_num(X_packets, nan=0.0, posinf=1.0, neginf=-1.0)

        logger.print("[DEBUG] Après nettoyage:")
        logger.print(f"  NaN dans séquences: {np.isnan(X_sequences).sum()}")  # Doit être 0
        logger.print(f"  Min/Max: {X_sequences.min():.2f} / {X_sequences.max():.2f}")

        scaler_pkt = StandardScaler()
        scaler_seq = StandardScaler()
        X_flat_seq = X_sequences.reshape(-1, X_sequences.shape[2])  # -1, 2 car la dim 2 = nombre de features de sequences
        X_packets_scaled = scaler_pkt.fit_transform(X_packets)
        scaler_seq.fit(X_flat_seq)
        X_sequences_scaled = np.array([scaler_seq.transform(seq) for seq in X_sequences])

        logger.print("[DEBUG] Après normalisation :")
        logger.print(f"  NaN dans séquences: {np.isnan(X_sequences_scaled).sum()}")
        logger.print(f"  Inf dans séquences: {np.isinf(X_sequences_scaled).sum()}")
        logger.print(f"  Min/Max: {X_sequences_scaled.min():.2f} / {X_sequences_scaled.max():.2f}")

        return X_sequences_scaled, scaler_seq, scaler_pkt, X_packets_scaled

    except Exception as e:
        traceback.print_exc()
        logger.print("Erreur globale collect_and_process :", str(e))
        return None, None, None, None


if __name__ == "__main__":
    from nest_asyncio import apply
    apply()
    try:
        inp = int(input("Durée apprentissage (s) : "))
        X_seq, scaler_seq, scaler_pkt, X_pkt = asyncio.run(collect_and_process(
            duration=inp,
            add_data_path="/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/core/data/capture_2026-04-14T06:47:18.102521.pkl",
        ))
        if X_seq is not None:
            logger.print("Extraction terminée, shapes :", X_seq.shape, X_pkt.shape)
        else:
            logger.print("Erreur lors de la collecte ou du traitement")
    except Exception as e:
        logger.print("Erreur main collect_and_process :", e)