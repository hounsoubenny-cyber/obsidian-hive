#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  7 06:17:41 2026

@author: hounsousamuel

mocks.py

Données mock pour tester l'interface sans backend réel.
Extrait de detection_module.py — utilisé uniquement pour le dev/frontend,
n'a aucune dépendance sur le reste du pipeline de détection.

"""

import time
from datetime import datetime


def _get_list_blocked_ip_mocked():
    """Génère des données mock pour tester l'interface sans backend."""
    import random
    from datetime import timedelta

    repeat_offenders = [
        "45.155.205.233",     # 1000+ tentatives
        "185.130.5.253",      # 500+ tentatives
        "94.102.61.78",       # 300+ tentatives
        "91.121.86.55",       # 250+ tentatives
        "185.165.29.108",     # 200+ tentatives
        "46.166.139.111",     # 150+ tentatives
        "5.188.86.45",        # 120+ tentatives
        "185.244.210.55",     # 100+ tentatives
    ]

    countries = ["RU", "NL", "CN", "FR", "DE", "US", "UA", "GB", "XX"]

    DATA = {}
    now = datetime.now()

    for i, ip in enumerate(repeat_offenders):
        base_score = 250 - (i * 20) + random.randint(-15, 15)
        score = max(50, min(290, base_score))

        first_seen_days = random.randint(1, 30)
        first_seen = (now - timedelta(days=first_seen_days)).strftime('%d/%m/%Y à %H:%M:%S')

        last_update_minutes = random.randint(0, 120)
        last_update = (now - timedelta(minutes=last_update_minutes)).strftime('%d/%m/%Y à %H:%M:%S')

        if score >= 230:
            level = "block_perm"
            action = "block_perm"
            duration = None
        elif score >= 180:
            level = "block_temp"
            action = "block_temp"
            duration = 24 * 3600
        elif score >= 125:
            level = "rate_limit"
            action = "rate_limit"
            duration = 4 * 3600
        elif score >= 75:
            level = "rate_limit_data"
            action = "rate_limit_data"
            duration = 2 * 3600
        else:
            level = "log_only"
            action = "log_only"
            duration = None

        resolutions = [
            None,
            f"host-{ip.replace('.', '-')}.example.com",
            f"vps-{random.randint(1000, 9999)}.hostingprovider.com",
            f"scan-{random.randint(100, 999)}.security-scanner.net",
        ]
        resolution = random.choice(resolutions)

        ports = [22, 23, 80, 443, 3389, 445, 8080, 8443, random.randint(10000, 60000)]
        port = random.choice(ports)

        ip_data = {
            'score': score,
            'anomaly_count': random.randint(1, 50),
            'last_update': last_update,
            'last_update_timestamp': time.time() - (last_update_minutes * 60),
            'geoloc': countries[i % len(countries)],
            'blocked_count': random.randint(0, 15),
            'fisrt_seen': first_seen,
            "resolution": resolution,
            "input": random.choice([True, False]),
            "port": port,
            "ip": ip,
            "decision": {
                "level": level,
                "action": action,
                "duration": duration,
                "score": score
            }
        }

        DATA[ip] = ip_data

    x = random.randint(1, len(DATA))
    return dict(list(DATA.items())[:x])