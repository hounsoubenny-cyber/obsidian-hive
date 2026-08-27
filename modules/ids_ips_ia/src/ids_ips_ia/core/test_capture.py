#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 22:37:30 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
"""Test minimal de capture AF_PACKET"""

import socket
import time
import sys

def test_capture(iface="wlp1s0", max_packets=5):
    print(f"🔧 Test de capture sur {iface}...")
    
    try:
        # Créer socket AF_PACKET
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((iface, 0))
        sock.settimeout(2.0)  # 2 secondes timeout
        print(f"✅ Socket créé et bindé à {iface}")
        
    except Exception as e:
        print(f"❌ Erreur création socket : {e}")
        return
    
    packets = 0
    try:
        while packets < max_packets:
            try:
                raw_packet = sock.recv(65535)
                packets += 1
                print(f"📦 PAQUET #{packets} : {len(raw_packet)} bytes")
                print(f"   Premiers octets : {raw_packet[:20].hex()}")
            except socket.timeout:
                print("⏱️ Timeout - pas de paquet reçu")
                break
            except KeyboardInterrupt:
                break
                
    finally:
        sock.close()
        print(f"🛑 Capture terminée. {packets} paquets reçus.")

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlp1s0"
    test_capture(iface)