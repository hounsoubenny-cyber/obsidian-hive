# cython: boundscheck=False
# cython: wraparound=False
# cython: initializedcheck=False
# cython: cdivision=True
# cython: language_level=3

import socket
import dpkt

def extract_ip(data):
    """
    Extrait les adresses IP source et destination d'un paquet.
    
    Args:
        data: tuple (ts, bytes) ou dpkt.ethernet.Ethernet
        
    Returns:
        tuple: (src_ip, dst_ip) ou (None, None)
    """
    cdef object eth, ip
    cdef bytes src_bytes, dst_bytes
    cdef str src_str, dst_str
    
    try:
        # Extraction du paquet Ethernet
        if isinstance(data, tuple):
            eth = dpkt.ethernet.Ethernet(data[1])
        else:
            eth = data
        
        if eth is None:
            return None, None
        
        # Couche IP
        ip = eth.data
        
        # IPv4
        if isinstance(ip, dpkt.ip.IP):
            src_bytes = ip.src
            dst_bytes = ip.dst
            
            if isinstance(src_bytes, str):
                src_bytes = src_bytes.encode()
            if isinstance(dst_bytes, str):
                dst_bytes = dst_bytes.encode()
            
            src_str = socket.inet_ntop(socket.AF_INET, src_bytes)
            dst_str = socket.inet_ntop(socket.AF_INET, dst_bytes)
            
            if src_str is None:
                src_str = '0.0.0.0'
            if dst_str is None:
                dst_str = '0.0.0.0'
            
            return src_str, dst_str
        
        # IPv6
        elif isinstance(ip, dpkt.ip6.IP6):
            src_bytes = ip.src
            dst_bytes = ip.dst
            
            if isinstance(src_bytes, str):
                src_bytes = src_bytes.encode()
            if isinstance(dst_bytes, str):
                dst_bytes = dst_bytes.encode()
            
            src_str = socket.inet_ntop(socket.AF_INET6, src_bytes)
            dst_str = socket.inet_ntop(socket.AF_INET6, dst_bytes)
            
            if src_str is None:
                src_str = '::'
            if dst_str is None:
                dst_str = '::'
            
            return src_str, dst_str
        
        return None, None
        
    except Exception:
        return None, None