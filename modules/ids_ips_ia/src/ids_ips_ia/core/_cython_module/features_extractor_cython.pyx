# cython: boundscheck=False
# cython: wraparound=False
# cython: initializedcheck=False
# cython: cdivision=True
# cython: language_level=3

"""
Fonctions d'extraction de caractéristiques optimisées en Cython.
Compilation : python setup.py build_ext --inplace
"""

import numpy as np
cimport numpy as np
import dpkt
import socket
import hashlib

# =============================================================================
# CONSTANTES
# =============================================================================
cdef double MAX_MAC = 281474976710655.0  # 2^48 - 1

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================
cdef inline double mac_to_double(bytes mac):
    """Convertit une adresse MAC bytes en double normalisé."""
    cdef unsigned long long val = 0
    cdef int i
    cdef const unsigned char* data = <const unsigned char*> mac
    for i in range(6):
        val = (val << 8) | data[i]
    return <double>val / MAX_MAC


# =============================================================================
# FONCTION D'EXTRACTION DE PAQUET
# =============================================================================
def extract_pack_features(object eth):
    """
    Extrait les caractéristiques d'un paquet.
    Retourne un np.ndarray de 25 features (float64).
    """
    cdef np.ndarray[double, ndim=1] features = np.zeros(25, dtype=np.float64)
    cdef bytes src_bytes, dst_bytes
    cdef object ip, transport
    cdef int i, flags
    cdef list src_parts, dst_parts
    cdef double ts = 0.0
    cdef int length = 0
    cdef bytes src = b'', dst = b''
    
    try:
        if eth is None:
            return features
        
        # Extraction timestamp (si tuple)
        if isinstance(eth, tuple):
            ts = eth[0]
            eth = dpkt.ethernet.Ethernet(eth[1])
        else:
            ts = getattr(eth, 'ts', 0.0)
        
        length = len(eth)
        src = eth.src
        dst = eth.dst
        
        # Features de base
        features[0] = <double>length      # length
        features[1] = ts                  # time
        features[2] = mac_to_double(src)  # src_mac
        features[3] = mac_to_double(dst)  # dst_mac
        
        # Couche IP
        ip = eth.data
        
        if isinstance(ip, dpkt.ip.IP):
            features[4] = <double>ip.ttl     # ttl
            features[5] = <double>ip.p       # protocol
            
            src_bytes = socket.inet_ntop(socket.AF_INET, ip.src).encode()
            dst_bytes = socket.inet_ntop(socket.AF_INET, ip.dst).encode()
            src_parts = src_bytes.decode().split('.')
            dst_parts = dst_bytes.decode().split('.')
            
            for i in range(4):
                try:
                    features[6 + i] = <double>int(src_parts[i])
                except:
                    features[6 + i] = 0.0
                try:
                    features[10 + i] = <double>int(dst_parts[i])
                except:
                    features[10 + i] = 0.0
                    
        elif isinstance(ip, dpkt.ip6.IP6):
            features[4] = <double>ip.hlim    # ttl
            features[5] = <double>ip.nxt     # protocol
            
            src_bytes = socket.inet_ntop(socket.AF_INET6, ip.src).encode()
            dst_bytes = socket.inet_ntop(socket.AF_INET6, ip.dst).encode()
            
            # Hash MD5 pour IPv6
            hash_src = hashlib.md5(src_bytes)
            hash_dst = hashlib.md5(dst_bytes)
            hash_bytes_src = hash_src.digest()
            hash_bytes_dst = hash_dst.digest()
            
            for i in range(min(4, len(hash_bytes_src))):
                features[6 + i] = <double>hash_bytes_src[i]
            for i in range(min(4, len(hash_bytes_dst))):
                features[10 + i] = <double>hash_bytes_dst[i]
        
        # Couche transport
        transport = ip.data
        
        if isinstance(transport, dpkt.tcp.TCP):
            features[14] = <double>transport.sport   # sport
            features[15] = <double>transport.dport   # dport
            features[24] = <double>len(transport.data)  # payload_len
            
            flags = transport.flags
            features[16] = 1.0 if (flags & 0x02) else 0.0  # SYN
            features[17] = 1.0 if (flags & 0x10) else 0.0  # ACK
            features[18] = 1.0 if (flags & 0x01) else 0.0  # FIN
            features[19] = 1.0 if (flags & 0x04) else 0.0  # RST
            features[20] = 1.0 if (flags & 0x08) else 0.0  # PSH
            features[21] = 1.0 if (flags & 0x20) else 0.0  # URG
            
        elif isinstance(transport, dpkt.udp.UDP):
            features[14] = <double>transport.sport
            features[15] = <double>transport.dport
            features[24] = <double>len(transport.data)
            
        elif isinstance(transport, dpkt.icmp.ICMP):
            features[22] = <double>transport.type   # icmp_type
            features[23] = <double>transport.code   # icmp_code
            
    except Exception as e:
        print(f"Erreur extraction features: {e}")
    
    return features


# =============================================================================
# FONCTION D'EXTRACTION DE SÉQUENCE
# =============================================================================
def extract_seq_features(object seq_dicts):
    """
    Ajoute les features de séquence à chaque paquet.
    """
    cdef np.ndarray data
    cdef int n_packets, i
    cdef double seq_length_mean, seq_length_max, seq_payload_mean
    cdef double seq_SYN_count, seq_ACK_count, seq_FIN_count
    cdef double seq_RST_count, seq_PSH_count, seq_URG_count, seq_ICMP_count
    cdef np.ndarray seq_feats, result
    cdef int idx_length, idx_payload, idx_SYN, idx_ACK, idx_FIN
    cdef int idx_RST, idx_PSH, idx_URG, idx_icmp
    
    try:
        if isinstance(seq_dicts, list) :
            if len(seq_dicts) > 0:
                if isinstance(seq_dicts[0], dict):
                    keys = list(seq_dicts[0].keys())
                    data = np.array([[pkt[k] for k in keys] for pkt in seq_dicts], dtype=np.float64)
                else:
                    data = np.asarray(seq_dicts, dtype=np.float64)
            else:
                return np.array([])
        else:
            data = np.asarray(seq_dicts, dtype=np.float64)
        
        n_packets = data.shape[0]
        
        # Indices des colonnes (ordre fixe)
        idx_length = 0
        idx_payload = 24
        idx_SYN = 16
        idx_ACK = 17
        idx_FIN = 18
        idx_RST = 19
        idx_PSH = 20
        idx_URG = 21
        idx_icmp = 22
        
        # Calculs vectorisés
        seq_length_mean = np.mean(data[:, idx_length])
        seq_length_max = np.max(data[:, idx_length])
        seq_payload_mean = np.mean(data[:, idx_payload])
        seq_SYN_count = np.sum(data[:, idx_SYN])
        seq_ACK_count = np.sum(data[:, idx_ACK])
        seq_FIN_count = np.sum(data[:, idx_FIN])
        seq_RST_count = np.sum(data[:, idx_RST])
        seq_PSH_count = np.sum(data[:, idx_PSH])
        seq_URG_count = np.sum(data[:, idx_URG])
        seq_ICMP_count = np.sum(data[:, idx_icmp] > 0)
        
        # Création des features de séquence
        seq_feats = np.zeros((n_packets, 10), dtype=np.float64)
        for i in range(n_packets):
            seq_feats[i, 0] = seq_length_mean
            seq_feats[i, 1] = seq_length_max
            seq_feats[i, 2] = seq_payload_mean
            seq_feats[i, 3] = seq_SYN_count
            seq_feats[i, 4] = seq_ACK_count
            seq_feats[i, 5] = seq_FIN_count
            seq_feats[i, 6] = seq_RST_count
            seq_feats[i, 7] = seq_PSH_count
            seq_feats[i, 8] = seq_URG_count
            seq_feats[i, 9] = seq_ICMP_count
        
        result = np.concatenate([data, seq_feats], axis=1)
        return result
        
    except Exception as e:
        print(f"Erreur extraction seq_features: {e}")
        return np.asarray(seq_dicts)