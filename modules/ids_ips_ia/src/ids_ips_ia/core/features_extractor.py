#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 17:17:18 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import numpy as np
import dpkt
from typing import Any
import socket
import hashlib
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()

try:
    from ids_ips_ia.core._cython_module.features_extractor_cython import (
        extract_pack_features as _extract_pack_cython,
        extract_seq_features as _extract_seq_cython
    )
    _USE_CYTHON = True
except ImportError:
    _USE_CYTHON = False
    logger.print("⚠️ Cython non disponible, utilisation de Python pur")



class FeatureExtractor:
    _USE_CYTHON = _USE_CYTHON
    @staticmethod
    def get_feature_name(to:str = "pkt"):
        if to == "pkt":
            return \
                ['length',
                 'time',
                 'src_mac',
                 'dst_mac',
                 'ttl',
                 'protocol',
                 'src_ip0',
                 'src_ip1',
                 'src_ip2',
                 'src_ip3',
                 'dst_ip0',
                 'dst_ip1',
                 'dst_ip2',
                 'dst_ip3',
                 'sport',
                 'dport',
                 'SYN',
                 'ACK',
                 'FIN',
                 'RST',
                 'PSH',
                 'URG',
                 'icmp_type',
                 'icmp_code',
                 'payload_len']
        else:
            return \
                ['length',
                 'time',
                 'src_mac',
                 'dst_mac',
                 'ttl',
                 'protocol',
                 'src_ip0',
                 'src_ip1',
                 'src_ip2',
                 'src_ip3',
                 'dst_ip0',
                 'dst_ip1',
                 'dst_ip2',
                 'dst_ip3',
                 'sport',
                 'dport',
                 'SYN',
                 'ACK',
                 'FIN',
                 'RST',
                 'PSH',
                 'URG',
                 'icmp_type',
                 'icmp_code',
                 'payload_len'] + \
                    ['seq_length_mean',
                     'seq_length_max',
                     'seq_payload_mean',
                     'seq_SYN_count',
                     'seq_ACK_count',
                     'seq_FIN_count',
                     'seq_RST_count',
                     'seq_PSH_count',
                     'seq_URG_count',
                     'seq_ICMP_count']
                
        
    @staticmethod
    def _extract_pack_features(eth:tuple[float, Any]|dpkt.ethernet.Ethernet):
        try:
            features = {
            'length': 0,
            'time': 0.0,
            'src_mac': 0,
            'dst_mac': 0,
            'ttl': 0,
            'protocol': 0,
            'src_ip0': 0, 'src_ip1': 0, 'src_ip2': 0, 'src_ip3': 0,
            'dst_ip0': 0, 'dst_ip1': 0, 'dst_ip2': 0, 'dst_ip3': 0,
            'sport': 0, 'dport': 0,
            'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0,
            'icmp_type': 0, 'icmp_code': 0,
            'payload_len': 0
        }
            if not eth:
                return np.array(list(features.values()))
            if isinstance(eth, tuple):
                ts = eth[0]
                eth = dpkt.ethernet.Ethernet(eth[1])
                eth.ts = ts
                
            src_ip_bytes = []
            dst_ip_bytes = []
            features['time'] = getattr(eth, 'ts', 0.0)
            features['length'] = len(eth)
            max_mac = 281474976710655  # 2^48 - 1
            # features['src_mac'] = features['src_mac'] / max_mac
            # features['dst_mac'] = features['dst_mac'] / max_mac
            src = eth.src
            dst = eth.dst
            if isinstance(src, bytes):
                features['src_mac'] = int.from_bytes(eth.src, 'big') / max_mac
            if isinstance(dst, bytes):
                features['dst_mac'] = int.from_bytes(eth.dst, 'big') / max_mac
            
            ip = eth.data
            ipv6 = False
            if isinstance(ip, dpkt.ip.IP):
                features['ttl'] = ip.ttl
                features['protocol'] = ip.p
                src = ip.src
                dst = ip.dst
                if isinstance(src, str):
                    src = bytes(src.encode())
                if isinstance(dst, str):
                    dst = bytes(dst.encode())
                src_ip_bytes = str(socket.inet_ntop(socket.AF_INET, src) or '0.0.0.0').split('.')
                dst_ip_bytes = str(socket.inet_ntop(socket.AF_INET, dst) or '0.0.0.0').split('.')
                
            
            elif isinstance(ip, dpkt.ip6.IP6):
                ipv6 = True
                features['ttl'] = ip.hlim
                features['protocol'] = ip.nxt
                src = ip.src
                dst = ip.dst
                if isinstance(src, str):
                    src = bytes(src.encode())
                if isinstance(dst, str):
                    dst = bytes(dst.encode())
                src_ip_bytes = str(socket.inet_ntop(socket.AF_INET6, src) or '::::')
                dst_ip_bytes = str(socket.inet_ntop(socket.AF_INET6, dst) or '::::')
                
            if not ipv6:
                for i in range(4):
                    if i < len(src_ip_bytes):
                        if src_ip_bytes[i]:
                            try:
                                features[f'src_ip{i}'] = int(src_ip_bytes[i])
                            except Exception:
                                features[f'src_ip{i}'] = src_ip_bytes[i]
                                
                    if i < len(dst_ip_bytes):
                        if dst_ip_bytes[i]:
                            try:
                                features[f'dst_ip{i}'] = int(dst_ip_bytes[i])
                            except Exception:
                                features[f'dst_ip{i}'] = dst_ip_bytes[i]
            else:
                hash_obj_src = hashlib.md5(src_ip_bytes.encode())
                hash_obj_dst = hashlib.md5(dst_ip_bytes.encode())
                hash_bytes_src = hash_obj_src.digest()
                hash_bytes_dst = hash_obj_dst.digest()
                hash_bytes_src = [p for p in hash_bytes_src if p]
                hash_bytes_dst = [p for p in hash_bytes_dst if p]
                for i in range(4):
                    try:
                        if hash_bytes_src[i]:
                            try:
                                features[f'src_ip{i}'] = int(hash_bytes_src[i])
                            except Exception:
                                features[f'src_ip{i}'] = hash_bytes_src[i]
                    except Exception:
                        pass
                    
                    try:
                        if hash_bytes_dst[i]:
                            try:
                                features[f'dst_ip{i}'] = int(hash_bytes_dst[i])
                            except Exception:
                                features[f'dst_ip{i}'] = hash_bytes_dst[i]
                    except Exception:
                        pass
            # else:
            #     return features
            
            transport = ip.data

            if isinstance(transport, dpkt.tcp.TCP):
                features['sport'] = transport.sport
                features['dport'] = transport.dport
                features['payload_len'] = len(transport.data)
            
                flags = transport.flags
                features['SYN'] = 1 if (flags & 0x02) else 0   # SYN
                features['ACK'] = 1 if (flags & 0x10) else 0   # ACK
                features['FIN'] = 1 if (flags & 0x01) else 0   # FIN
                features['RST'] = 1 if (flags & 0x04) else 0   # RST
                features['PSH'] = 1 if (flags & 0x08) else 0   # PSH
                features['URG'] = 1 if (flags & 0x20) else 0   # URG
            
            elif isinstance(transport, dpkt.udp.UDP):
                features['sport'] = transport.sport
                features['dport'] = transport.dport
                features['payload_len'] = len(transport.data)
            
            elif isinstance(transport, dpkt.icmp.ICMP):
                features['icmp_type'] = transport.type
                features['icmp_code'] = transport.code 
            
            return np.array(list(features.values()))
        
        except Exception as e:
            logger.print(f"Erreur extraction features: {e}")
            # Retourner des features par défaut en cas d'erreur
            return np.array(list(features.values()))

    @staticmethod
    def _extract_seq_features(seq_dicts:np.ndarray|list[dict]):
        """
        Prend une liste de dictionnaires (une séquence de paquets) et
        ajoute à chaque paquet les features calculées sur toute la séquence.

        Args:
            seq_dicts : liste de dicts, chaque dict = features d'un paquet, ou np.ndarray

        Returns:
            nouvelle array enrichie avec les features de la séquence
        """
        
        if isinstance(seq_dicts[0], dict):
            keys = list(seq_dicts[0].keys())
            
            # Convertir en array pour faciliter les calculs
            data = np.array([[pkt[k] for k in keys] for pkt in seq_dicts])
            # logger.print(data.dtype)
            # input()
        else:
            keys = FeatureExtractor.get_feature_name()
            data = np.asarray(seq_dicts)
            

        # Calcul des features par séquence
        seq_features = {
            "seq_length_mean": np.mean(data[:, keys.index("length")], dtype=np.int64),
            "seq_length_max": np.max(data[:, keys.index("length")]),
            "seq_payload_mean": np.mean(data[:, keys.index("payload_len")], dtype=np.int64),
            "seq_SYN_count": np.sum(data[:, keys.index("SYN")], dtype=np.int64),
            "seq_ACK_count": np.sum(data[:, keys.index("ACK")], dtype=np.int64),
            "seq_FIN_count": np.sum(data[:, keys.index("FIN")], dtype=np.int64),
            "seq_RST_count": np.sum(data[:, keys.index("RST")], dtype=np.int64),
            "seq_PSH_count": np.sum(data[:, keys.index("PSH")], dtype=np.int64),
            "seq_URG_count": np.sum(data[:, keys.index("URG")], dtype=np.int64),
            "seq_ICMP_count": np.sum(data[:, keys.index("icmp_type")] > 0, dtype=np.int64)
        }

        seq_features_arr = np.array([list(seq_features.values()) for _ in range(data.shape[0])])
        seq_dicts = np.concatenate([data, seq_features_arr], axis=1)
        return seq_dicts
    
    @staticmethod
    def extract_pack_features(eth):
        if FeatureExtractor._USE_CYTHON:
            return _extract_pack_cython(eth)
        else:
            return FeatureExtractor._extract_pack_features(eth)
    
    @staticmethod
    def extract_seq_features(seq_dicts):
        if FeatureExtractor._USE_CYTHON:
            return _extract_seq_cython(seq_dicts)
        else:
            return FeatureExtractor._extract_seq_features(seq_dicts)
        
if __name__ == "__main__":
    logger.print(len(FeatureExtractor.get_feature_name()))

    