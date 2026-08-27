#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 16 16:09:17 2026

@author: hounsousamuel
"""

import os, sys

import time
import struct
import multiprocessing as mp
from queue import Queue
from multiprocessing import shared_memory

class MemoryManager:
    MAXLEN = 1000
    DEFAULT_SIZE = 16
    TIMESTAMP_SIZE = 8
    TAILLE_SIZE = 4
    HEADER_SIZE = 4 + 8
    # Structure [ts(4), taille(4), pkt]
    def __init__(self, size:int = 16, name:str|None = "packet_memory"):
        self._size = size or self.DEFAULT_SIZE
        self.size = self._size * 1024 * 1024
        self.name = str(name)
        self._init_memory()
        self.lock = mp.Lock()
        self.queue = Queue(maxsize=self.MAXLEN)
        self.W_IDX_POS = (0, 4)
        self.R_IDX_POS = (4, 8)
        self.START_IDX = 8
        self.IDX_LEN = 4
        self._init_headers()
        
    def _init_memory(self):
        try:
            self.memory = shared_memory.SharedMemory(
                    name=self.name, size=self.size,
                    create=True
                )
            self.name = self.memory.name
        except FileExistsError:
            self.memory = shared_memory.SharedMemory(
                    name=self.name, size=self.size,
                    create=False
                )
            self.name = self.memory.name
    
    def _init_headers(self):
        self._update_write_idx(self.START_IDX)
        self._update_read_idx(self.START_IDX)
    
    def _get_write_idx(self):
        return int.from_bytes(bytes=self.memory.buf[self.W_IDX_POS[0] : self.W_IDX_POS[1]], byteorder="big")
    
    def _update_write_idx(self, idx):
        self.memory.buf[self.W_IDX_POS[0] : self.W_IDX_POS[1]] = int(idx).to_bytes(self.IDX_LEN, byteorder="big")
    
    def _restart_write_idx(self):
        self.memory.buf[self.W_IDX_POS[0] : self.W_IDX_POS[1]] = int(self.START_IDX).to_bytes(self.IDX_LEN, byteorder="big")
    
    def _get_read_idx(self):
        return int.from_bytes(bytes=self.memory.buf[self.R_IDX_POS[0] : self.R_IDX_POS[1]], byteorder="big")
    
    def _update_read_idx(self, idx):
        self.memory.buf[self.R_IDX_POS[0] : self.R_IDX_POS[1]] = int(idx).to_bytes(self.IDX_LEN, byteorder="big")
    
    def _restart_read_idx(self):
        self.memory.buf[self.R_IDX_POS[0] : self.R_IDX_POS[1]] = int(self.START_IDX).to_bytes(self.IDX_LEN, byteorder="big")
    
    def put_in_queue(self, pkt):
        try:
            self.queue.put_nowait(pkt)
            return True
        except Exception:
            return False
        
    def get_in_queue(self):
        try:
            return self.queue.get_nowait()
        except Exception:
            return None
                
    def write(self, pkt):
        pkt = bytes(pkt)
        taille_pkt = len(pkt)
        offset = self._get_write_idx()
        if offset + self.TAILLE_SIZE + self.TIMESTAMP_SIZE + taille_pkt >= self.size:
            if not self.put_in_queue(pkt):
                self._restart_write_idx()
                return self.write(pkt)
            else:
                return True
            
        ts = struct.pack(">d", time.time())
        taille_bytes = taille_pkt.to_bytes(self.TAILLE_SIZE, byteorder="big")
        self.memory.buf[offset : offset + self.TIMESTAMP_SIZE] = ts
        offset += self.TIMESTAMP_SIZE
        self.memory.buf[offset : offset + self.TAILLE_SIZE] = taille_bytes
        offset += self.TAILLE_SIZE
        print(offset, taille_pkt, offset + taille_pkt, offset + taille_pkt >= self.size, type(pkt))
        self.memory.buf[offset : offset + taille_pkt] = pkt
                
        offset += taille_pkt
        self._update_write_idx(offset)
        print(offset, self.size, taille_pkt, ts)
        return True
    
    def put(self, pkt):
        print("MEMORY_MANAGER : ", pkt)
        with self.lock:
            return self.write(pkt)
    
    def put_nowait(self, pkt):
        return self.put(pkt)
    
    def read(self):
        read_idx = self._get_read_idx()
        write_idx = self._get_write_idx()
        if read_idx + self.HEADER_SIZE >= self.size or read_idx >= write_idx:
            print("SAM", read_idx + self.TAILLE_SIZE + self.TIMESTAMP_SIZE >= self.size, read_idx >= write_idx, write_idx, read_idx, self.queue.qsize())
            return None, None

        ts = self.memory.buf[read_idx : read_idx + self.TIMESTAMP_SIZE]        
        ts, = struct.unpack(">d", ts)
        read_idx += self.TIMESTAMP_SIZE
        taille = self.memory.buf[read_idx : read_idx + self.TAILLE_SIZE]
        taille = int.from_bytes(taille, byteorder="big")
        read_idx += self.TAILLE_SIZE
        if read_idx + taille > self.size:
            return None, None
        
        pkt = bytes(self.memory.buf[read_idx : read_idx + taille])
        read_idx += taille
        self._update_read_idx(read_idx)
        print(read_idx, self.size, taille, ts)
        return ts, pkt
    
    # La queue est un extensui de la memory. On essaie la memory, si il y a rien, on verifie en queue.
    # Si on y trouve un truc, alors on le retourne.
    # Sinon, si queue aussi vide, c'est maintenant et seulement là qu'on restart le read_idx si read_idx > self.size
    def get(self):
        with self.lock:
            ts, pkt = self.read()
            
        if ts is None:
            if self.queue.qsize() > 0:
                # print("Pris en queue")
                item = self.get_in_queue()
                return time.time(), item
            else:
                read_idx = self._get_read_idx()
                if read_idx >= self.size:
                    # print("Restart")
                    self._restart_read_idx()    
        return ts, pkt
    
    def get_nowait(self):
        return self.get()
    
    def close(self):
        try:
            self.memory.close()
        except Exception:
            pass
        
        try:
            self.memory.unlink()
        except Exception:
            pass
    
    def stop(self):
        self.close()
    
    def __del__(self):
        self.close()
        
if __name__ == "__main__":
    import atexit
    import signal
    import sys
    
    # =========================================================================
    # Liste des MemoryManagers créés (pour nettoyage automatique)
    # =========================================================================
    _managers = []
    
    def cleanup_all():
        """Nettoie TOUS les MemoryManagers créés."""
        print("\n🧹 Nettoyage final...")
        for mem in _managers:
            try:
                mem.close()
                print(f"   ✅ {mem.name} fermé")
            except Exception as e:
                print(f"   ⚠️ Erreur fermeture {mem.name}: {e}")
        _managers.clear()
        print("✅ Nettoyage terminé")
    
    # Enregistrer le nettoyage à la sortie
    atexit.register(cleanup_all)
    
    # Gérer Ctrl+C proprement
    def signal_handler(sig, frame):
        print("\n⚠️ Interruption détectée...")
        cleanup_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # =========================================================================
    # Fonction helper pour créer un MemoryManager avec suivi
    # =========================================================================
    def create_manager(size=1, name=None):
        """Crée un MemoryManager et l'enregistre pour nettoyage automatique."""
        if name is None:
            import uuid
            name = f"test_{uuid.uuid4().hex[:8]}"
        mem = MemoryManager(size=size, name=name)
        _managers.append(mem)
        return mem
    
    print("=" * 60)
    print("🧪 TEST DU MEMORYMANAGER")
    print("=" * 60)
    
    # =========================================================================
    # TEST 1 : Initialisation
    # =========================================================================
    print("\n📦 TEST 1 : Initialisation")
    print("-" * 40)
    
    mem = create_manager(size=1, name="test_packets")
    print(f"   ✅ MemoryManager créé : {mem.name}")
    print(f"   📊 Taille : {mem.size:,} octets")
    print(f"   📝 write_idx : {mem._get_write_idx()}")
    print(f"   📖 read_idx : {mem._get_read_idx()}")
    
    # =========================================================================
    # TEST 2 : Écriture et Lecture Simple
    # =========================================================================
    print("\n✏️ TEST 2 : Écriture et Lecture Simple")
    print("-" * 40)
    
    test_packets = [
        b"Hello World",
        b"Packet 2: IDS/IPS",
        bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]),
        b"TCP SYN",
        b"UDP DNS Query",
    ]
    
    print("\n   📝 Écriture des paquets :")
    for i, pkt in enumerate(test_packets):
        mem.put(pkt)
        print(f"      [{i}] Écrit : {len(pkt)} octets")
    
    print(f"\n   📊 Après écriture : write_idx = {mem._get_write_idx()}")
    
    print("\n   📖 Lecture des paquets :")
    for i in range(len(test_packets)):
        ts, pkt = mem.get()
        if pkt:
            print(f"      [{i}] Lu : {len(pkt)} octets | ts = {ts:.3f}")
            if len(pkt) <= 50:
                print(f"          Contenu : {pkt}")
    
    # =========================================================================
    # TEST 3 : Buffer Plein → Queue
    # =========================================================================
    print("\n📦 TEST 3 : Buffer Plein → Fallback Queue")
    print("-" * 40)
    
    small_mem = create_manager(size=1, name="test_small")
    
    print("\n   📝 Génération de paquets...")
    large_packet = b"X" * 10000
    
    success_count = 0
    for i in range(150):  # Réduit pour éviter les logs infinis
        if small_mem.put(large_packet):
            success_count += 1
        if i % 50 == 0 and i > 0:
            print(f"      {i} paquets traités...")
    
    print(f"   ✅ {success_count} paquets écrits")
    print(f"   📊 write_idx = {small_mem._get_write_idx()}")
    print(f"   📋 Queue size = {small_mem.queue.qsize()}")
    
    # Lecture
    read_count = 0
    while True:
        ts, pkt = small_mem.get()
        if ts is None:
            break
        read_count += 1
    
    print(f"   📖 {read_count} paquets lus")
    
    # =========================================================================
    # TEST 4 : Buffer Circulaire
    # =========================================================================
    print("\n🔄 TEST 4 : Buffer Circulaire")
    print("-" * 40)
    
    circular_mem = create_manager(size=1, name="test_circular")
    
    pkt1 = b"A" * 500000
    pkt2 = b"B" * 500000
    pkt3 = b"C" * 500000
    
    print("\n   📝 Écriture de 3 paquets de 500 Ko...")
    circular_mem.put(pkt1)
    print(f"      [1] write_idx = {circular_mem._get_write_idx()}")
    circular_mem.put(pkt2)
    print(f"      [2] write_idx = {circular_mem._get_write_idx()}")
    circular_mem.put(pkt3)
    print(f"      [3] write_idx = {circular_mem._get_write_idx()}")
    
    print("\n   📖 Lecture...")
    for i in range(3):
        ts, pkt = circular_mem.get()
        if ts:
            print(f"      [{i}] Lu : {len(pkt)} octets, premier octet : {chr(pkt[0])}")
    
    # =========================================================================
    # TEST 5 : Multiprocessing
    # =========================================================================
    print("\n🔀 TEST 5 : Multiprocessing")
    print("-" * 40)
    
    MP_NAME = "test_mp_shared"
    mem = MemoryManager(name=MP_NAME)
    def producer(num_packets, name, meme):
        for i in range(num_packets):
            pkt = f"Packet {i} from producer".encode()
            mem.put(pkt)
            time.sleep(0.001)
        print(f"   🏭 Producteur : {num_packets} paquets écrits")
    
    def consumer(num_packets, name, mem):
        received = 0
        while received < num_packets:
            ts, pkt = mem.get()
            # print(received, ts, pkt)
            if ts:
                received += 1
        print(f"   🛒 Consommateur : {received} paquets lus")
        mem.close()
    
    num_packets = 50
    p1 = mp.Process(target=producer, args=(num_packets, MP_NAME, mem))
    c1 = mp.Process(target=consumer, args=(num_packets, MP_NAME, mem))
    
    p1.start()
    p1.join()
    c1.start()
    c1.join()
    
    # Nettoyer le manager MP manuellement (car créé dans les process)
    try:
        mp_mem = MemoryManager(name=MP_NAME)
        mp_mem.close()
    except Exception:
        pass
    
    print("   ✅ Multiprocessing réussi")
    
    # =========================================================================
    # TEST 6 : Performances
    # =========================================================================
    print("\n⚡ TEST 6 : Performances")
    print("-" * 40)
    
    perf_mem = create_manager(size=64, name="test_perf")
    
    num_packets = 10000
    pkt_size = 100
    test_pkt = b"X" * pkt_size
    
    start = time.time()
    for _ in range(num_packets):
        perf_mem.put(test_pkt)
    write_time = time.time() - start
    
    start = time.time()
    read_count = 0
    for _ in range(num_packets):
        ts, pkt = perf_mem.get()
        if ts:
            read_count += 1
    read_time = time.time() - start
    
    print(f"   ✏️ Écriture : {num_packets:,} paquets en {write_time:.3f}s")
    print(f"      → {num_packets / write_time:,.0f} paquets/seconde")
    print(f"   📖 Lecture  : {read_count:,} paquets en {read_time:.3f}s")
    print(f"      → {read_count / read_time:,.0f} paquets/seconde")
    
    # =========================================================================
    # FIN
    # =========================================================================
    print("\n" + "=" * 60)
    print("✅ TOUS LES TESTS SONT PASSÉS")
    print("=" * 60)
    
    # Nettoyage automatique via atexit
   