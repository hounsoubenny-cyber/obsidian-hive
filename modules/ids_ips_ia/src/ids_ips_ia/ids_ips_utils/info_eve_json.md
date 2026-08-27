#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 09:20:18 2026

@author: hounsousamuel
"""

Le fichier `eve.json` de Suricata est un **flux JSON continu** où **chaque ligne** est un objet JSON indépendant représentant un événement. Tous les événements partagent une structure de base avec un champ `event_type` qui détermine les champs supplémentaires présents.

### Structure de base (commune à tous les événements)

```json
{
  "timestamp": "2026-04-13T10:30:45.123456+0200",
  "flow_id": 1234567890123456,
  "pcap_cnt": 42,
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "8.8.8.8",
  "dest_port": 53,
  "proto": "UDP",
  "community_id": "1:abcdef123456",
  "in_iface": "eth0"
}
```

### Types d'événements principaux

| `event_type` | Contient | Intérêt pour toi |
|:-------------|:---------|:-----------------|
| `alert` | `alert` (signature, severity, category) | **Détection de menaces** → déclenche ton `react.block()` |
| `http` | `http` (hostname, url, method, status) | Analyse trafic web suspect |
| `dns` | `dns` (query, rcode, answers) | Détection domaines malveillants |
| `tls` | `tls` (sni, version, ja3) | Détection certificats/JA3 suspects |
| `flow` | `flow` (bytes, packets, age) | Statistiques de flux |
| `stats` | `stats` (uptime, packets, memory) | Monitoring Suricata |

### Structure d'une alerte (`event_type: "alert"`)

C'est le plus important pour ton IDS/IPS :

```json
{
  "timestamp": "2026-04-13T10:30:45.123456+0200",
  "event_type": "alert",
  "src_ip": "203.0.113.42",
  "src_port": 12345,
  "dest_ip": "192.168.1.10",
  "dest_port": 22,
  "proto": "TCP",
  "direction": "to_server",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 4,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "app_proto": "ssh",
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 60,
    "bytes_toclient": 0,
    "start": "2026-04-13T10:30:45.123456+0200"
  }
}
```

### Structure HTTP (`event_type: "http"`)

```json
{
  "event_type": "http",
  "src_ip": "192.168.1.100",
  "dest_ip": "142.251.185.14",
  "http": {
    "hostname": "example.com",
    "url": "/malicious/path",
    "http_user_agent": "Mozilla/5.0 (suspicious)",
    "http_method": "GET",
    "status": 200,
    "length": 1234
  }
}
```

### Structure DNS (`event_type: "dns"`)

```json
{
  "event_type": "dns",
  "src_ip": "192.168.1.100",
  "dest_ip": "8.8.8.8",
  "dns": {
    "type": "query",
    "id": 12345,
    "rrname": "malicious-domain.com",
    "rrtype": "A",
    "rcode": "NOERROR",
    "answers": [
      {
        "rrname": "malicious-domain.com",
        "rrtype": "A",
        "rdata": "203.0.113.99"
      }
    ]
  }
}
```

### Champs essentiels pour ton script Python

```python
import json

def parse_eve_line(line: str):
    try:
        event = json.loads(line)
        
        # Champs toujours présents
        event_type = event.get("event_type")
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        proto = event.get("proto")
        direction = event.get("direction", "N/A")
        
        # Spécifique aux alertes
        if event_type == "alert":
            alert_info = event.get("alert", {})
            signature = alert_info.get("signature")
            severity = alert_info.get("severity")
            category = alert_info.get("category")
            action = alert_info.get("action")
            
            return {
                "type": "alert",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "signature": signature,
                "severity": severity,
                "direction": direction
            }
        
        # Spécifique HTTP
        elif event_type == "http":
            http_info = event.get("http", {})
            return {
                "type": "http",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "hostname": http_info.get("hostname"),
                "url": http_info.get("url"),
                "method": http_info.get("http_method")
            }
            
        return None
        
    except json.JSONDecodeError:
        return None
```

### Comment activer tous ces champs dans `suricata.yaml`

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - flow
```

Le champ `direction` (`to_server` / `to_client`) est particulièrement utile pour savoir si l'IP source est l'initiateur de la connexion.