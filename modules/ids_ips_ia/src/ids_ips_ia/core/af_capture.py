#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 20:07:49 2026

@author: hounsousamuel
"""

import socket
import dpkt
import time
import threading

class AFPacketCapture:
    def __init__(self, iface, queue, event, filter_=None, batch_size=64):
        self.iface = iface
        self.q = queue
        self.event = event
        self.batch_size = batch_size
        self.sock = None

    def start(self):
        """Démarre la capture sur l'interface."""
        # Création du socket AF_PACKET
        # socket.AF_PACKET, socket.SOCK_RAW -> Capture brute couche 2
        # socket.htons(0x0003) -> Capture tous les protocoles
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((self.iface, 0))
        # Optionnel : augmenter la taille du buffer pour éviter les pertes
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        sock.settimeout(0.03)
        print(f"🚀 Capture AF_PACKET démarrée sur {self.iface}")

        while not self.event.is_set():
            try:
                # Lecture en lot pour l'efficacité
                packets = []
                for _ in range(self.batch_size):
                    try:
                        raw_packet = self.sock.recv(65535)
                        packets.append(raw_packet)
                    except socket.timeout:
                        break
                
                # Traitement du lot avec dpkt
                for raw_packet in packets:
                    eth = dpkt.ethernet.Ethernet(raw_packet)
                    eth.ts = time.time()  # Ajout d'un timestamp personnalisé
                    self.q.put_nowait(eth)
                    
            except Exception as e:
                print(f"⚠️ Erreur capture AF_PACKET: {e}")

        self.sock.close()
        print(f"🛑 Capture AF_PACKET arrêtée sur {self.iface}")