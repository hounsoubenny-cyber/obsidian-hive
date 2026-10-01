#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct  1 00:07:44 2026

@author: hounsousamuel
"""

"""
blocked_skip.py — Fast-path : ignorer les paquets dont l'IP source est déjà bloquée.

Pourquoi : la capture AF_PACKET voit les paquets AVANT netfilter. Une IP bloquée par nftables
continue donc d'arriver dans la queue, et détect() la ré-analyse (dpkt + features + 4 modèles +
scorer + re-blocage nft) pour rien. Ici on lit l'IP source directement dans les octets bruts
(~1 µs, sans dpkt) et on regarde React.blocked. Si bloquée -> on saute le paquet.

Branchement (2 lignes + 1 init) dans detection/detection_module.py :

    # 1) en haut du fichier
    from ids_ips_ia.detection.blocked_skip import BlockedSkipper

    # 2) dans Detector.__init__, APRÈS self.React = React(...)
    self.skipper = BlockedSkipper(self.React)

    # 3) dans detect(), juste après l'item sorti de la queue :
    item = self.q.get_nowait()
    if self.skipper.should_skip(item):
        continue                      # sort AVANT dpkt / features / modèles
    self.pkt_proccessed += 1

Règles (volontairement prudentes) :
  - on ne skippe QUE les blocages entrants (input=True) : l'IP source est alors l'attaquant ;
  - par défaut, seulement les blocages "drop" (les IP en rate_limit continuent d'être analysées ;
    passer skip_rate_limited=True pour les skipper aussi) ;
  - les alertes Suricata (tuple (fake_pkt, alert)) ne sont jamais skippées ;
  - IP whitelistée, IP illisible, paquet non IP -> jamais skippé ;
  - l'expiration des blocages temporaires est gérée par React.is_blocked() (purge paresseuse).

Effet de bord à connaître : un paquet skippé n'entre plus dans buffer_fea, donc les séquences de
60 paquets ne contiennent plus de trafic d'IP bloquées. En pratique c'est plutôt mieux.
"""

import time
import socket
from ids_ips_ia.reaction.reaction_module import React

_ntoa = socket.inet_ntoa
_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_VLAN = (0x8100, 0x88A8)


def src_ip_from_raw(raw) -> "str | None":
    """IP source depuis une trame Ethernet brute (bytes). None si non IP ou trame trop courte."""
    n = len(raw)
    if n < 34:
        return None
    ethertype = (raw[12] << 8) | raw[13]
    off = 14
    while ethertype in _ETH_VLAN and n >= off + 4 + 20:      # 802.1Q / QinQ
        ethertype = (raw[off + 2] << 8) | raw[off + 3]
        off += 4
    try:
        if ethertype == _ETH_IPV4:
            return _ntoa(bytes(raw[off + 12:off + 16]))
        if ethertype == _ETH_IPV6 and n >= off + 40:
            return _ntop(_AF_INET6, bytes(raw[off + 8:off + 24]))
    except (ValueError, OSError):
        pass
    return None


def extract_src_ip(item) -> "str | None":
    """
    IP source d'un item de la queue de détection, ou None si on ne sait pas
    (None => l'appelant ne doit JAMAIS skipper).
    Formats gérés : (ts, bytes) | objet déjà parsé type dpkt Ethernet | (fake_pkt, alert) -> None.
    """
    if isinstance(item, tuple):
        if len(item) == 2 and isinstance(item[1], (bytes, bytearray, memoryview)):
            return src_ip_from_raw(item[1])
        return None                                          # alerte Suricata : on traite toujours
    src = getattr(getattr(item, "data", None), "src", None)  # Ethernet.data.src (IP / IP6)
    if isinstance(src, (bytes, bytearray)):
        try:
            if len(src) == 4:
                return _ntoa(bytes(src))
            if len(src) == 16:
                return _ntop(_AF_INET6, bytes(src))
        except (ValueError, OSError):
            return None
    return None


class BlockedSkipper:
    """Décide si un paquet doit être ignoré parce que son IP source est déjà bloquée."""

    def __init__(self, react: React, skip_rate_limited: bool = False):
        self.react = react
        self.skip_rate_limited = skip_rate_limited
        self.checked = 0
        self.skipped = 0
        self._t0 = time.monotonic()

    def _is_blocked_inbound(self, ip: str) -> bool:
        entry = self.react.blocked.get(ip)        # lecture atomique (GIL) : pas de lock sur le chemin courant
        if entry is None:
            return False
        if not entry.get("input", False):
            return False                          # blocage sortant : la source n'est pas l'attaquant
        if entry.get("rule", "drop") != "drop" and not self.skip_rate_limited:
            return False
        if ip in self.react.whitelist:
            return False
        return self.react.is_blocked(ip)          # vérifie l'expiration (purge paresseuse, avec lock)

    def should_skip(self, item) -> bool:
        ip = extract_src_ip(item)
        if ip is None:
            return False
        self.checked += 1
        if self._is_blocked_inbound(ip):
            self.skipped += 1
            return True
        return False

    def stats(self) -> dict:
        dt = max(time.monotonic() - self._t0, 1e-9)
        return {
            "checked": self.checked,
            "skipped": self.skipped,
            "skip_ratio": self.skipped / self.checked if self.checked else 0.0,
            "skipped_per_s": self.skipped / dt,
        }


if __name__ == "__main__":
    # Mini auto-test : python3 blocked_skip.py
    import struct

    def eth_ipv4(src: str, vlan: bool = False) -> bytes:
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 6
        ip[12:16] = socket.inet_aton(src)
        ip[16:20] = socket.inet_aton("10.0.0.1")
        eth = b"\x02" * 6 + b"\x04" * 6
        eth += (struct.pack("!HH", 0x8100, 5) if vlan else b"") + struct.pack("!H", 0x0800)
        return eth + bytes(ip) + b"\x00" * 20

    def eth_ipv6(src: str) -> bytes:
        ip = bytearray(40)
        ip[0] = 0x60
        ip[6] = 6
        ip[8:24] = socket.inet_pton(socket.AF_INET6, src)
        return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", 0x86DD) + bytes(ip) + b"\x00" * 20

    class FakeReact:
        whitelist = ["9.9.9.9"]

        def __init__(self):
            self.blocked = {
                "1.2.3.4": {"input": True, "rule": "drop", "duration": None},
                "5.6.7.8": {"input": True, "rule": "rate_limit", "duration": 60, "unit": "m",
                            "blocked_at": time.time()},
                "8.8.4.4": {"input": False, "rule": "drop", "duration": None},
                "2001:db8::1": {"input": True, "rule": "drop", "duration": None},
            }

        def is_blocked(self, ip):
            return ip in self.blocked

    s = BlockedSkipper(FakeReact())
    ts = time.time()
    assert s.should_skip((ts, eth_ipv4("1.2.3.4")))                 # drop entrant -> skip
    assert s.should_skip((ts, eth_ipv4("1.2.3.4", vlan=True)))      # avec VLAN -> skip
    assert s.should_skip((ts, eth_ipv6("2001:db8::1")))             # IPv6 -> skip
    assert not s.should_skip((ts, eth_ipv4("5.6.7.8")))             # rate_limit -> on analyse
    assert not s.should_skip((ts, eth_ipv4("8.8.4.4")))             # blocage sortant -> on analyse
    assert not s.should_skip((ts, eth_ipv4("7.7.7.7")))             # inconnue -> on analyse
    assert not s.should_skip((object(), {"alert": 1}))              # alerte Suricata -> on analyse
    assert not s.should_skip((ts, b"\x00" * 10))                    # trame trop courte
    assert BlockedSkipper(FakeReact(), skip_rate_limited=True).should_skip((ts, eth_ipv4("5.6.7.8")))
    t = time.perf_counter()
    raw = eth_ipv4("7.7.7.7")
    for _ in range(200_000):
        s.should_skip((ts, raw))
    print(f"✅ tests OK — {(time.perf_counter() - t) / 200_000 * 1e6:.2f} µs / paquet (chemin 'non bloqué')")
    print(s.stats())
