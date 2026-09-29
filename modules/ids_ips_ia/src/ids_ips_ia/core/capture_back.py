#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 16:07:03 2026

@author: hounsousamuel
"""

import os
import sys
import time
import dpkt
import pcap
import glob
import queue
import socket
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
    DST_IGNORED_IP
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


FIT_MAX_SIZE = 20_000         # taille d'une queue
FIT_WORKERS = 4               # threads qui extraient les features / écrivent sur disque

# En AF_PACKET, garde seulement les trames IPv4/IPv6 (ARP, STP, LLDP... ignorés),
# comme le fait déjà le filtre BPF 'tcp or udp or icmp' du mode pcap.
AF_PACKET_IP_ONLY = True

def _is_ip_frame(raw: bytes) -> bool:
    """Vrai si la trame Ethernet transporte de l'IPv4 ou de l'IPv6 (VLAN 802.1Q / QinQ géré).
    Ne parse rien : lit seulement 2 octets."""
    n = len(raw)
    if n < 14:
        return False
    et = (raw[12] << 8) | raw[13]
    if et == 0x8100 or et == 0x88A8:
        if n < 18:
            return False
        et = (raw[16] << 8) | raw[17]
    return et == 0x0800 or et == 0x86DD

_VLAN_TYPES = (0x8100, 0x88A8, 0x9100) # 802.1Q, QinQ (802.1ad), ancien QinQ
_L4_V4 = (1, 6, 17)  # ICMP, TCP, UDP
_L4_V6 = (6, 17, 58) # TCP, UDP, ICMPV6

def _match_tcp_udp_icmp(raw: bytes):
    """Equivalent manuel a 'tcp or udp or icmp or icmp6' sur trame Ethernet"""
    off = 12  # position de l'EtherType
    while len(raw) >= off + 2:
        et = int.from_bytes(raw[off : off + 2], "big")
        if et in _VLAN_TYPES:
            off += 4  # saute l'étiquette VLAN
            continue
        
        ip = off + 2 # début de l'en-tête IP
        if et == 0x0800:  # IPv4 (20 octets min)
            return len(raw) >= ip + 20 and raw[ip + 9] in _L4_V4
        if et == 0x86DD:  # IPv6 (40 octets fixes)
            return len(raw) >= ip + 40 and raw[ip + 9] in _L4_V6
        return False  # ARP, STP, LLDP
    return False  # trame trop courte
        
def detect_all_ifaces() -> list:
    """Détecte TOUTES les interfaces sauf loopback"""
    faces = pcap.findalldevs()
    interfaces = []
    excluded = ['lo', 'bluetooth', 'usbmon', 'any', 'bluetooth-monitor', 'nfqueue', 'nflog']
    interfaces = [ p for p in faces if not p in excluded and not any(str(p).startswith(i) for i in excluded) ]
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

def attach_bpf(sock, prog=BPF_PROG):
    import struct, ctypes
    raw = b"".join(struct.pack("HBBI", *ins) for ins in prog)
    buf = ctypes.create_string_buffer(raw)
    fprog = struct.pack("HL", len(prog), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    
def extract_ip(data: tuple | dpkt.ethernet.Ethernet) -> tuple:
    if not _USE_CYTHON:
        return _extract_ip(data)
    
    return _extract_ip_cython(data)

def _save(data, path):
    with open(path, "wb") as f:
        pickle.dump(data, f)

def _cum_save(data, path):
    with open(path, "ab") as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

def load_pkt_file(path: str):
    with open(path, "rb") as f:
        while True:
            try:
                yield pickle.load(f) # un chunck
            except EOFError:
                break
            
class QueueEmpty(Exception):
    pass

class BuffuredQueue:
    DT_FORMAT = "%Y_%m_%d_%H_%M_%s"
    
    def __init__(
        self,
        max_size: int = 10_000,
        compress: int = 9,
        num_workers: int = 4,
    ):
        if max_size < 10_000:
            raise ValueError("max_size doit être suéprieur ou égal à 10_000")
        
        self.workers = []
        self._current_number = 0
        self.max_size = int(max_size)
        self._deque = deque(maxlen=max_size)
        self._dt = datetime.now().strftime(BuffuredQueue.DT_FORMAT)
        self._save_dir = os.path.abspath(os.path.join(
            DATADIR, f"captures_file_{self._dt}"
        ))
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._finish_event = threading.Event()
        self._end_event: dict[str, threading.Event] = {}
        self._queue = queue.Queue(maxsize=100)
        self.compress = int(compress)
        self.num_workers = int(num_workers) or 4
        self.num_items = 0
        self._started = False
        os.makedirs(self._save_dir, exist_ok=True)
    
    @property
    def save_dir(self):
        return self._save_dir
    
    @property
    def current_number(self):
        return self._current_number
    
    def qsize(self):
        return self.num_items
    
    def _get_filename(self):
        filename = os.path.join(
            self._save_dir,
            f"file_{self._current_number}.pkl"
        )
        self._current_number += 1
        return filename
    
    def _worker(self, worker_id: str):
        while True:
            if self._stop_event.is_set():
                self._end_event[worker_id].set()
                break
        
            try:
                item: tuple = self._queue.get_nowait()
                if item is None:
                    continue
                
                data, filename = item
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                _save(list(data), filename)
            except queue.Empty:
                if self._finish_event.is_set():
                    self._end_event[worker_id].set()
                    break
            
            except Exception as e:
                print(f"Erreur dans worker {worker_id}: {e!r}")
    
    def is_full(self):
        return len(self._deque) >= self.max_size
        
    def build_new_deque(self):
        self._deque = deque(maxlen=self.max_size)
        
    def _put(
        self,
        data: Any,
        put_method: str = "put", # put | put_nowait
    ):
        if self.is_full():
            item = (deque(self._deque), self._get_filename())
            put_method = "put_nowait" if not put_method in ("put", "put_nowait") else put_method
            method = getattr(self._queue, put_method)
            method(item)
            self.build_new_deque()
        
        self.num_items += 1
        return self._deque.append(data)
    
    def _get(
        self, 
    ):
        try:
            return self._deque.popleft()
        except IndexError as e:
            raise QueueEmpty(*e.args) from e
    
    def put(self, data: Any):
        return self._put(data, "put")
    
    def put_nowait(self, data: Any):
        return self._put(data, "put_nowait")
    
    def get(self):
        return self._get()
    
    def get_nowait(self):
        return self._get()
    
    def make_finished(self, make_empty: bool = False):
        item = (deque(self._deque), self._get_filename())
        self._queue.put(item)
        if make_empty:
            self.build_new_deque()
        self._finish_event.set()
        return True
    
    def start(self):
        if self._started:
            return
        uuid = str(uuid4())[:8]
        self._stop_event.clear()
        self._finish_event.clear()
        for i in range(self.num_workers):
            wid = f"worker_{uuid}##{i}"
            th = threading.Thread(
                target=self._worker, 
                args=(wid,),
                daemon=True
            )
            self._end_event[wid] = threading.Event()
            th.start()
            self.workers.append(th)
        self._started = True
        return
    
    def wait(self):
        events = self._end_event.values()
        st = time.time()
        for event in events:
            while not event.is_set():
                print(f"En attente ({time.time() - st:.2f})", end="\r")
        
        return 
    
    def stop(self, timeout: int = 5):
        self._stop_event.set()
        for th in list(self.workers):
            try:
                th.join(5)
                self.workers.remove(th)
            except Exception:
                pass
            
class Capture:
    def __init__(
        self, 
        queue:Union[BuffuredQueue, queue.Queue], 
        backup_queue = None, 
        src_ignored_ip: set = None,
        dst_ignored_ip: set = None,
    ):
        self.queue = queue
        self.event = threading.Event()
        self.threads = []
        self.save_task = None
        self.backup_queue = backup_queue
        self.use_af_packet = "linux" in platform.system().lower()
        self.dropped_packets = 0
        self.src_ignored_ip = src_ignored_ip or SRC_IGNORED_IP or {}
        self.src_ignored_ip = set(ip for ip in self.src_ignored_ip if _get_ip_type(ip) != "error")
        self.dst_ignored_ip = dst_ignored_ip or DST_IGNORED_IP or {}
        self.dst_ignored_ip = set(ip for ip in self.dst_ignored_ip if _get_ip_type(ip) != "error")
        
        if self.use_af_packet:
            logger.print("🐧 Linux détecté → AF_PACKET activé (performance maximale)")
        else:
            logger.print(f"🍎 {platform.system()} détecté → fallback pcap")
    
    def add_dst_ip_to_ignore(self, ip: str):
        if _get_ip_type(ip) != "error":
            self.dst_ignored_ip.add(str(ip))
            return True
        
        return False
    
    def remove_dst_ip_to_ignore(self, ip: str):
        try:
            self.dst_ignored_ip.remove(ip)
            return True
        except KeyError:
            pass
        
        return False
    
    def add_src_ip_to_ignore(self, ip: str):
        if _get_ip_type(ip) != "error":
            self.src_ignored_ip.add(str(ip))
            return True
        
        return False
    
    def remove_src_ip_to_ignore(self, ip: str):
        try:
            self.src_ignored_ip.remove(ip)
            return True
        except KeyError:
            pass
        
        return False
    
    def detect_all_ifaces(self) -> list:
        """Détecte TOUTES les interfaces sauf loopback"""
        return detect_all_ifaces()
    
    def stop(self, timeout: int | float = 1):
        self.event.set()
        if self.save_task:
            tasks = self.threads + [self.save_task]
        else:
            tasks = self.threads
        for th in tasks:
            try:
                th.join(timeout)
            except Exception:
                pass
        
        if self.save_task:
            try:
                self.save_task.join(timeout)
            except Exception:
                pass
        
        for th in tasks:
            logger.print(th.name, "is alive ? ", th.is_alive())
    
    def _put(self, queue: queue.Queue, item: Any, count_dropped: bool = True):
        try:
            queue.put_nowait(item)
        except queue.Full:
            if count_dropped:
                self.dropped_packets += 1
                
    def _pcap_capture(
        self, 
        iface: str, 
        filter: str = FILTER,
        thread_name: str = "_capture"
    ):
        try:
            pc = pcap.pcap(
                name=iface,
                snaplen=65535, #262144,
                immediate=True,
                timeout_ms=TIMEOUT_MS or 40,
                promisc=True,
                buffer_size=BUFFER_SIZE or 64*1024*1024
            )
        except Exception:
            pc = pcap.pcap(
                name=None,
                snaplen=65535, #262144,
                immediate=True,
                timeout_ms=TIMEOUT_MS or 30,
                promisc=True,
                buffer_size=BUFFER_SIZE or 64*1024*1024
            )
        pc.setfilter(filter or 'tcp or udp or icmp')
        try:
            while not self.event.is_set():
                for ts, pkt in pc:
                    if self.event.is_set():
                        break
                    
                    try:
                        item = (ts, pkt)
                        if self.src_ignored_ip or self.dst_ignored_ip:
                            src, dst = extract_ip(item)
                            if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                continue
                        
                        self._put(self.queue, item, True)
                        if self.backup_queue:
                            self._put(self.backup_queue, item, False)
                    
                        # logger.print(eth)
                    except Exception as e:
                        logger.print('Erreur dans _capture , thread_name = ', thread_name, "erreur :", e)
            pc.close()
        except Exception as e:
            logger.print('Erreur globale dans _capture , thread_name = ', thread_name, "erreur :", e)
            pc.close()
    
    def _socket_capture(
        self, 
        iface: str,
        filter: str = FILTER, 
        thread_name: str = "_capture", 
        batch_size: int = 64
    ):
        """
        Capture ultra-performante avec AF_PACKET.
        
        Args:
            iface: Interface réseau (ex: "wlp1s0")
            filter: Filtre BPF (non utilisé ici, mais gardé pour compatibilité)
            thread_name: Nom du thread pour les logs
            batch_size: Nombre de paquets à lire par lot
        """
       
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
            sock.settimeout(0.04)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE or 64*1024*1024)
            bpf_attached = False
            try:
                attach_bpf(sock, prog=BPF_PROG)
                bpf_attached = True
            except Exception as e:
                print(f"BPF non attaché: {e!r}")
                bpf_attached = False
                
            logger.print(f"🚀 Capture AF_PACKET démarrée sur {iface}")
            try:
                packets = [None for _ in range(batch_size)]
                # Ethernet = dpkt.ethernet.Ethernet
                while not self.event.is_set():
                    pkt_count = 0
                    for i in range(batch_size):
                        try:
                            raw_packet = sock.recv(65535) 
                            packets[i] = (time.time(), raw_packet)
                            pkt_count = i + 1 
                        except socket.timeout:
                            break
                        
                        except Exception:
                            continue
                        
                    if self.event.is_set():
                        break
                    
                    try:
                        ip_only = AF_PACKET_IP_ONLY
                        check_ignored = bool(self.src_ignored_ip or self.dst_ignored_ip)
                        for i in range(pkt_count):
                            item = packets[i]
                            packets[i] = None
                            if not bpf_attached:
                                if ip_only and not _match_tcp_udp_icmp(item[1]):
                                    continue
                            if check_ignored:
                                src, dst = extract_ip(item)
                                if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                    continue
                                
                            self._put(self.queue, item, True)
                            if self.backup_queue:
                                self._put(self.backup_queue, item, False)
                    except Exception as e:
                        logger.print(f'⚠️ Erreur traitement paquet dans {thread_name}: {e}')
                            
            except Exception as e:
                logger.print(f'❌ Erreur globale dans _socket_capture, thread_name={thread_name} : {e}')
                traceback.print_exc()
                
            finally:
                sock.close()
                logger.print(f"🛑 Capture AF_PACKET arrêtée sur {iface}")
                
        except Exception as e:
            sys.stderr.write(f"[{thread_name}] ERREUR : {type(e).__name__}: {e}\n")
            sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
            
        finally:
            try: sock.close()
            except NameError:
                sys.stderr.write(f"[{thread_name}] sock jamais créé\n"); sys.stderr.flush()
            except Exception as e:
                sys.stderr.write(f"[{thread_name}] finally erreur: {e}\n"); sys.stderr.flush()
                
    
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
    
        for iface in ifaces:
            th = threading.Thread(
                target=capture_method,
                args=(iface, filter, f"Capture-{iface}"),
                daemon=True, name=f"Capture-{iface}"
            )
            th.start()
            tasks.append(th)
        
        for t in tasks:
            logger.print(t.name, t.is_alive(), self.event.is_set())
        self.threads = tasks
        
        if save_interval and path:
            if not isinstance(self.queue, queue.Queue):
                logger.print("L'objet queue passé ne permet pas une sauvegarde périodique !")
                return tasks
            
            def save_task():
                while not self.event.is_set():
                    try:
                        time.sleep(save_interval)
                        _save(list(self.queue.queue), path)
                        if self.event.is_set():
                            break
                    except Exception as e:
                        logger.print("Erreur sauvegarde :", str(e))
                        
            self.save_task = threading.Thread(target=save_task, daemon=True, name="Save-Thread") 
            self.save_task.start()
        return tasks
    
    def capture(
        self, 
        ifaces:list[str], 
        filter:str = FILTER, 
        in_process:bool = False, 
        save_interval:int|None = None, 
        path:str|None = None
    ) -> mp.Process|None:
        
        logger.print("Capture reçu")
        if in_process:
            process = mp.Process(target=self._capture, args=(ifaces, filter, save_interval, path), daemon=True, name="Capture-Process")
            process.start()
            return process
        
        self._capture(ifaces, filter, save_interval=save_interval, path=path)
        return 
            
def start_capture(
    queue: BuffuredQueue,
    duration: int, 
    path: str,
    save_interval: int = 36000, 
    ifaces: list[str] = None,
    max_n_paquets: int | None = None,
):
    if max_n_paquets is None or max_n_paquets == 0:
        max_n_paquets = float("inf")
    
    queue.start()
    ifaces = ifaces or []
    cap_obj = Capture(queue=queue)
    cap_obj.capture(
        ifaces=ifaces,
        filter=FILTER,
        save_interval=save_interval,
        path=path,
        in_process=False
    )
    start_time = time.time()
    
    def _stop(*args, **kwargs):
        cap_obj.stop()
    
    if threading.current_thread() is threading.main_thread():
        signal_manager(_stop)
        
    try:
        while time.time() <= start_time + duration and queue.num_items < max_n_paquets:
            time.sleep(1)
            msg = (
                f"Collecte en cours, reste {int(duration + start_time - time.time())}s "
                f"| {queue.num_items} packet(s) | {cap_obj.dropped_packets} perdu(s)"
            )
            print(msg, end="\r")
            if time.time() > start_time + duration or queue.num_items >= max_n_paquets:
                break
        
        queue.make_finished()
        queue.wait()
    except KeyboardInterrupt:
        logger.print("\n[INFO] Capture interrompue par l'utilisateur")
        
    except Exception as e:
        logger.print("\n[INFO, start_capture] Erreur : ", str(e))
    
    finally:
        cap_obj.stop()
        queue.stop(timeout=1)
        files = list(sorted(glob.glob(os.path.join(queue.save_dir, "*.pkl"))))
        alen = 0
        if files:
            for file in files:
                with open(file, "rb") as f:
                    data = pickle.load(f)
                alen += len(data)
                _cum_save(data, path)
                
            if alen == sum(len(c) for c in load_pkt_file(path)):
                print("Plein succès lors du merge !")
                import shutil
                shutil.rmtree(queue.save_dir, onerror=None)
        
        return

def build_capture_filename(filename: str):
    return os.path.join(DATADIR, str(filename))

async def collect_and_process(
    duration: int = 7 * 24 * 3600, 
    filename: str = "capture.pkl",
    add_data_path: str = "",
    save_interval: int = 36000, 
    ifaces: list[str] = None,
    max_size: int = FIT_MAX_SIZE,
    n_workers: int = FIT_WORKERS,
    max_n_paquets: int | None = None,
    *args, **kwargs
):
    try:
        if max_n_paquets is None or max_n_paquets == 0:
            max_n_paquets = float("inf")
        ifaces = ifaces or []
        cap_queue = BuffuredQueue(
            max_size=FIT_MAX_SIZE,
            num_workers=FIT_WORKERS,
        )
        cap_queue.start()
        path = build_capture_filename(filename)
        start_capture(
            queue=cap_queue, 
            duration=duration, 
            path=path,
            ifaces=ifaces,
            save_interval=save_interval if not isinstance(cap_queue, BuffuredQueue) else None,
        )
        logger.print(f"Fin de la capture, {cap_queue.qsize()} packets enrégistré dans la durée !")
        data_to_add = []
        def _unpack(el):
            if isinstance(el, dpkt.ethernet.Ethernet):
                return getattr(el, "ts", time.time()), bytes(el)
            
            elif isinstance(el, tuple):
                return el[0], el[1]
            
            raise ValueError("Type non supporté")
            
        if os.path.exists(add_data_path or ""):
            for data in load_pkt_file(add_data_path):
                try:
                    data_to_add.extend([_unpack(el) for el in data])
                except (ValueError, IndexError):
                    pass
                
            if not isinstance(data_to_add, list):
                logger.print("Les données à ajouté ne respecte pas le format, ils sont donc rejetés !")
                data_to_add = []
        
        data = []
        for chunck in load_pkt_file(path):
            for item in chunck:
                el = dpkt.ethernet.Ethernet(item[1])
                el.ts = item[0]
                data.append(el)
            
        if data_to_add:
            for item in data_to_add:
                el = dpkt.ethernet.Ethernet(item[1])
                el.ts = item[0]
                data.append(el)
                
        logger.print("Nombre total finale de packet :", len(data))
        if cap_queue.qsize() == 0:
            raise ValueError("Aucun paquet collecté !")
        
        extractor = FeatureExtractor()
        X_packets = np.array([extractor.extract_pack_features(pkt) for pkt in data])
        n_seq = X_packets.shape[0] - SEQ_LENGTH + 1 # Comme nombre d'éléments, fin - debut + 1
        if n_seq <= 0:
            raise ValueError("Pas assez de paquets pour une séquence !")
        seq_pkt = [X_packets[i : i + SEQ_LENGTH] for i in range(n_seq)]
        seq_lis = []
        #Extraire les features de sequances
        for seq in seq_pkt:
            try:
                seq_fea = extractor.extract_seq_features(seq)
                seq_lis.append(seq_fea)
            except Exception as e:
                logger.print("Erreur extraction sequence :", str(e))
                
        X_sequences = np.array(seq_lis)
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
        X_flat_seq = X_sequences.reshape(-1, X_sequences.shape[2]) # -1, 2 car la dim 2 = nombre de features de sequences
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
        inp1 = int(input("Durée sauvegarde périodique (s) : "))
        X_seq, scaler_seq, scaler_pkt, X_pkt = asyncio.run(collect_and_process(
            maxsize=0,
            duration=inp,
            add_data_path="/home/hounsousamuel/PROJET/obsidian_hive/modules/ids_ips_ia/src/ids_ips_ia/core/data/capture_2026-04-14T06:47:18.102521.pkl",
            save_interval=inp1
        ))
        if X_seq is not None:
            logger.print("Extraction terminée, shapes :", X_seq.shape, X_pkt.shape)
        else:
            logger.print("Erreur lors de la collecte ou du traitement")
    except Exception as e:
        logger.print("Erreur main collect_and_process :", e)
        
        