#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 16:07:03 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import dpkt
import pcap
import socket
import platform
import threading
import queue
import time
import joblib
import asyncio
import numpy as np
import multiprocessing as mp
import multiprocessing.queues as mpq
from typing import Union
from nest_asyncio import apply
from ids_ips_ia.core.config import BUFFER_SIZE, TIMEOUT_MS, FILTER, SEQ_LENGTH, SRC_IGNORED_IP, DST_IGNORED_IP
from ids_ips_ia.ids_ips_utils.signal_manager import signal_manager
from ids_ips_ia.core.features_extractor import FeatureExtractor
from sklearn.preprocessing import StandardScaler
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.memory_managers.shared_memory_packet_manager import MemoryManager
from ids_ips_ia.ids_ips_utils.utils import _get_ip_type
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

def detect_all_ifaces() -> list:
    """Détecte TOUTES les interfaces sauf loopback"""
    faces = pcap.findalldevs()
    interfaces = []
    excluded = ['lo', 'bluetooth', 'usbmon', 'any', 'bluetooth-monitor', 'nfqueue', 'nflog']
    interfaces = [ p for p in faces if not p in excluded and not any(str(p).startswith(i) for i in excluded)]
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
        dst = str(socket.inet_ntop(socket.AF_INET6, src) or '::::')
        return src, dst
    
    return None, None
        
def extract_ip(data: tuple | dpkt.ethernet.Ethernet) -> tuple:
    if not _USE_CYTHON:
        return _extract_ip(data)
    
    return _extract_ip_cython(data)
        
class Capture:
    def __init__(
        self, 
        queue:Union[MemoryManager, queue.Queue], 
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
    
    def stop(self, timeout:int|float = 1):
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
            
    def _pcap_capture(self, iface:str, filter:str = FILTER, thread_name = "_capture"):
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
                        if isinstance(self.queue, mpq.Queue):
                            mp.queues
                            src, dst = extract_ip((ts, pkt))
                            if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                continue
                            self.queue.put_nowait((ts, pkt))
                            # if self.backup_queue:
                            #     self.backup_queue.put_nowait((ts, pkt))
                            
                        else:
                            eth = dpkt.ethernet.Ethernet(pkt)
                            src, dst = extract_ip(eth)
                            if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                continue
                            eth.ts = ts
                            self.queue.put_nowait(eth)
                        if self.backup_queue:
                            self.backup_queue.put_nowait(eth)
                        # logger.print(eth)
                    except Exception as e:
                        logger.print('Erreur dans _capture , thread_name = ', thread_name, "erreur :", e)
            pc.close()
        except Exception as e:
            logger.print('Erreur globale dans _capture , thread_name = ', thread_name, "erreur :", e)
            pc.close()
    
    def _socket_capture(self, iface: str, filter: str = FILTER, thread_name: str = "_capture", batch_size: int = 64):
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
            logger.print(f"🚀 Capture AF_PACKET démarrée sur {iface}")
            try:
                packets = [None for _ in range(batch_size)]
                Ethernet = dpkt.ethernet.Ethernet
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
                        if isinstance(self.queue, mpq.Queue):
                            for i in range(pkt_count):
                                src, dst = extract_ip(packets[i])
                                if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                    packets[i] = None
                                    continue
                                
                                self.queue.put_nowait(packets[i])
                                packets[i] = None
                        else:
                            for i in range(pkt_count):
                                ts, pkt = packets[i]
                                packets[i] = None
                                eth = Ethernet(pkt)
                                src, dst = extract_ip(eth)
                                if src in self.src_ignored_ip or dst in self.dst_ignored_ip:
                                    continue
                                eth.ts = ts
                                self.queue.put_nowait(eth)
                                
                                if self.backup_queue:
                                    self.backup_queue.put_nowait(eth)
                                
                    except Exception as e:
                        logger.print(f'⚠️ Erreur traitement paquet dans {thread_name}: {e}')
                            
            except Exception as e:
                logger.print(f'❌ Erreur globale dans _socket_capture, thread_name={thread_name} : {e}')
                import traceback
                traceback.print_exc()
                
            finally:
                sock.close()
                logger.print(f"🛑 Capture AF_PACKET arrêtée sur {iface}")
                
        except Exception as e:
            import traceback
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
        self, ifaces:list[str] = [], 
        filter:str = FILTER, save_interval:int|None = None, 
        path:str|None = None
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
                        joblib.dump(list(self.queue.queue), path, compress=9)
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
        
        self._capture(ifaces, filter)
        return 

def start_capture(
    queue: queue.Queue,
    duration: int, 
    path: str,
    save_interval: int = 36000, 
    ifaces: list[str] = [],
):
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
        while time.time() <= start_time + duration:
            time.sleep(1)
            print(f"Collecte en cours, reste {int(duration + start_time - time.time())} s", end="\r")
            if time.time() > start_time + duration : 
                break
        
    except KeyboardInterrupt:
        logger.print("\n[INFO] Capture interrompue par l'utilisateur")
        
    except Exception as e:
        logger.print("\n[INFO, start_capture] Erreur : ", str(e))
    
    finally:
        cap_obj.stop()
        try:
            joblib.dump(list(queue.queue), path, compress=9)
        except Exception as e:
            logger.print("Erreur finale de sauvegarde :", str(e))
        return
    
async def collect_and_process(
    maxsize: int = 0,
    duration: int = 7*24*3600, 
    filename: str = "capture.pkl",
    add_data_path: str = "",
    save_interval: int = 36000, 
    ifaces: list[str] = []
):
    try:
        cap_queue = queue.Queue(maxsize=maxsize)
        path = os.path.join(DATADIR, filename)
        start_capture(
            queue=cap_queue, 
            duration=duration, 
            path=path,
            ifaces=ifaces,
            save_interval=save_interval,
        )
        
        logger.print(f"Fin de la capture, {cap_queue.qsize()} packets enrégistré dans la durée !")
        data_to_add = []
        if os.path.exists(add_data_path):
            data_to_add = joblib.load(add_data_path)
            if not isinstance(data_to_add, list):
                logger.print("Les données à ajouté ne respecte pas le format, ils sont donc rejetés !")
                data_to_add = []
                
        if data_to_add:
            for pkt in data_to_add:
                try:
                    cap_queue.put_nowait(pkt)
                except queue.Full:
                    break
                
        logger.print("Nombre total finale de packet :", cap_queue.qsize())
        if cap_queue.qsize() == 0:
            raise ValueError("Aucun paquet collecté !")
        
        extractor = FeatureExtractor()
        X_packets = np.array([extractor.extract_pack_features(pkt) for pkt in cap_queue.queue])
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
        X_flat_seq = X_sequences.reshape(-1, X_sequences.shape[2]) #-1, 2 car la dim 2 = nombre de features de sequences
        X_packets_scaled = scaler_pkt.fit_transform(X_packets)
        scaler_seq.fit(X_flat_seq)
        X_sequences_scaled = np.array([scaler_seq.transform(seq) for seq in X_sequences])
        
        logger.print("[DEBUG] Après normalisation :")
        logger.print(f"  NaN dans séquences: {np.isnan(X_sequences_scaled).sum()}")
        logger.print(f"  Inf dans séquences: {np.isinf(X_sequences_scaled).sum()}")
        logger.print(f"  Min/Max: {X_sequences_scaled.min():.2f} / {X_sequences_scaled.max():.2f}")
    
        return X_sequences_scaled, scaler_seq, scaler_pkt, X_packets_scaled
    
    except Exception as e:
        logger.print("Erreur globale collect_and_process :", str(e))
        return None, None, None, None


if __name__ == "__main__":
    try:
        inp = int(input("Durée apprentissage (s) : "))
        inp1 = int(input("Durée sauvegarde périodique (s) : "))
        X_seq, scaler_seq, scaler_pkt, X_pkt = asyncio.run(collect_and_process(
            maxsize=0,
            duration=inp,
            add_data_path="/home/hounsousamuel/PROJET/ShieldIA_v2/ids_ips_ia/core/data/capture_backup.pkl",
            save_interval=inp1
            ))
        if X_seq is not None:
            logger.print("Extraction terminée, shapes :", X_seq.shape, X_pkt.shape)
        else:
            logger.print("Erreur lors de la collecte ou du traitement")
    except Exception as e:
        logger.print("Erreur main collect_and_process :", e)
    
    
    
    
    
        
    
    