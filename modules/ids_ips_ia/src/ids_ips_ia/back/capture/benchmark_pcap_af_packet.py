#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 15 01:37:13 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
"""
Comparaison équitable : AF_PACKET (socket) vs libpcap (pcap)
Capture 100 000 paquets et mesure le temps.
"""

import socket
import pcap
import time
import sys
import os

# =============================================================================
# CONFIGURATION
# =============================================================================
INTERFACE = "lo"  # Changer pour wlp1s0, eth0, etc.
NUM_PACKETS = 100_000
SNAPLEN = 65535
TIMEOUT_MS = 40

def generate_test_traffic():
    """Génère du trafic de test sur loopback."""
    print("📡 Génération de trafic test...")
    # Lancer un ping flood en arrière-plan
    import subprocess
    subprocess.Popen(["ping", "-f", "-c", str(NUM_PACKETS), "127.0.0.1"], 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

# =============================================================================
# TEST 1 : PCAP
# =============================================================================
def test_pcap():
    print("\n" + "="*60)
    print("🧪 TEST 1 : PCAP (libpcap)")
    print("="*60)
    
    # Créer le sniffer
    sniffer = pcap.pcap(
        name=INTERFACE,
        snaplen=SNAPLEN,
        immediate=True,
        timeout_ms=TIMEOUT_MS
    )
    sniffer.setfilter("icmp")  # Seulement les pings
    
    packets = 0
    bytes_total = 0
    start = time.perf_counter()
    
    print(f"📊 Capture de {NUM_PACKETS} paquets...")
    
    for timestamp, pkt in sniffer:
        packets += 1
        bytes_total += len(pkt)
        
        if packets >= NUM_PACKETS:
            break
    
    elapsed = time.perf_counter() - start
    
    print(f"   ✅ {packets} paquets capturés")
    print(f"   📦 {bytes_total / 1024:.1f} KB")
    print(f"   ⏱️  {elapsed:.4f} secondes")
    print(f"   🚀 {packets / elapsed:.0f} paquets/seconde")
    print(f"   📈 {bytes_total * 8 / elapsed / 1e6:.2f} Mbps")
    
    del sniffer
    return elapsed, packets, bytes_total

# =============================================================================
# TEST 2 : AF_PACKET (socket)
# =============================================================================
def test_af_packet():
    print("\n" + "="*60)
    print("🧪 TEST 2 : AF_PACKET (socket)")
    print("="*60)
    
    # Créer socket AF_PACKET
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((INTERFACE, 0))
    
    # Configurer ring buffer (si supporté)
    try:
        from socket import PACKET_RX_RING
        sock.setsockopt(socket.SOL_PACKET, PACKET_RX_RING, 
                       (4096 * 1024, 2048, 2048))
        print("   ✅ Ring buffer activé (4MB)")
    except (ImportError, AttributeError, OSError):
        print("   ⚠️ Ring buffer non supporté, mode standard")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024 * 1024)
    
    sock.settimeout(TIMEOUT_MS / 1000.0)
    
    packets = 0
    bytes_total = 0
    start = time.perf_counter()
    
    print(f"📊 Capture de {NUM_PACKETS} paquets...")
    
    # Batch reading
    BATCH_SIZE = 64
    
    while packets < NUM_PACKETS:
        try:
            # Lecture batch
            for _ in range(BATCH_SIZE):
                raw = sock.recv(65535)
                packets += 1
                bytes_total += len(raw)
                
                if packets >= NUM_PACKETS:
                    break
        except socket.timeout:
            continue
        except Exception as e:
            print(f"   ⚠️ Erreur: {e}")
            break
    
    elapsed = time.perf_counter() - start
    
    print(f"   ✅ {packets} paquets capturés")
    print(f"   📦 {bytes_total / 1024:.1f} KB")
    print(f"   ⏱️  {elapsed:.4f} secondes")
    print(f"   🚀 {packets / elapsed:.0f} paquets/seconde")
    print(f"   📈 {bytes_total * 8 / elapsed / 1e6:.2f} Mbps")
    
    sock.close()
    return elapsed, packets, bytes_total

# =============================================================================
# MAIN
# =============================================================================
def main():
    print("="*60)
    print("🔬 COMPARATEUR DE PERFORMANCE : PCAP vs AF_PACKET")
    print("="*60)
    
    if os.geteuid() != 0:
        print("❌ Ce script doit être exécuté en root (sudo)")
        sys.exit(1)
    
    print(f"🌐 Interface : {INTERFACE}")
    print(f"📦 Paquets à capturer : {NUM_PACKETS}")
    
    # Générer trafic en arrière-plan
    generate_test_traffic()
    
    # Test 1 : PCAP
    pcap_time, pcap_pkts, pcap_bytes = test_pcap()
    
    # Pause
    print("\n⏸️  Pause de 2 secondes...")
    time.sleep(2)
    
    # Générer nouveau trafic
    generate_test_traffic()
    
    # Test 2 : AF_PACKET
    af_time, af_pkts, af_bytes = test_af_packet()
    
    # Comparaison
    print("\n" + "="*60)
    print("📊 RÉSULTATS COMPARATIFS")
    print("="*60)
    
    speedup = pcap_time / af_time
    pps_pcap = pcap_pkts / pcap_time
    pps_af = af_pkts / af_time
    
    print(f"\n   PCAP      : {pcap_time:.4f}s | {pps_pcap:.0f} pps")
    print(f"   AF_PACKET : {af_time:.4f}s | {pps_af:.0f} pps")
    print(f"\n   🚀 AF_PACKET est {speedup:.2f}x plus rapide !")
    
    if speedup > 1.5:
        print(f"   ✅ Gain SIGNIFICATIF ({((speedup-1)*100):.0f}%)")
    elif speedup > 1.1:
        print(f"   👍 Gain MODÉRÉ ({((speedup-1)*100):.0f}%)")
    else:
        print(f"   ⚠️ Gain NÉGLIGEABLE (vérifiez si ring buffer est activé)")
    
    print("\n" + "="*60)
    print("✅ Test terminé")
    print("="*60)

if __name__ == "__main__":
    main()