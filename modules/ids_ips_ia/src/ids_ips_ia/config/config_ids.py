#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 11:14:28 2026

@author: hounsousamuel
"""

import os
from dotenv import load_dotenv
from ids_ips_ia.auth.auth import auth
from ids_ips_ia.config.config_manager import * # noqa
from ids_ips_ia.config.config_manager import (
    _config_path, Config, GLOBAL_CONFIG_KEY,
    CAPTURE_CONFIG_KEY, ANOMALY_CONFIG_KEY
)
from ids_ips_ia.ids_ips_utils.logger import get_logger
logger = get_logger()
load_dotenv()

THREAT_LEVELS = {
    'log_only': {
        'score_range': (0, 75),
        'action': 'log_only',
        'description': 'Activité normale - Surveillance uniquement',
    },
    'rate_limit_data': {
        'score_range': (75, 125),
        'action': 'rate_limit_data',
        'description': 'Limitation du volume de données (bande passante)',
        'duration': 2 * 3600  # 2 heures
    },
    'rate_limit': {
        'score_range': (125, 180),
        'action': 'rate_limit',
        'description': 'Limitation du nombre de connexions',
        'duration': 4 * 3600  # 4 heures
    },
    'block_temp': {
        'score_range': (180, 230),
        'action': 'block_temp',
        'description': 'Blocage temporaire (24 heures)',
        'duration': 24 * 3600,  # 24 heures
    },
    'block_perm': {
        'score_range': (230, 301),
        'action': 'block_perm',
        'description': 'Blocage permanent',
        'duration': None,  # None = infini pour nftables
    }
}

CONFIG = Config(config_path=os.environ.get("IDS_CONFIG_PATH", _config_path))
GLOBAL_CONFIG = CONFIG.CONFIG[GLOBAL_CONFIG_KEY]
CAPTURE_CONFIG = CONFIG.CONFIG[CAPTURE_CONFIG_KEY]
SEQ_LENGTH =  CONFIG.CONFIG.get(ANOMALY_CONFIG_KEY, {}).get('seq_length', 60)


def _positive_int(value, default: int) -> int:
    """Entier >= 1, sinon la valeur par défaut (une config cassée ne doit pas planter la détection)."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


_ANOMALY_CFG = CONFIG.CONFIG.get(ANOMALY_CONFIG_KEY, {})
# Pas de la fenêtre glissante : nb de paquets entre deux séquences évaluées (live) / construites (fit, refit)
SEQ_STRIDE = _positive_int(_ANOMALY_CFG.get('seq_stride', 20), 20)
SEQ_STRIDE_FIT = _positive_int(_ANOMALY_CFG.get('seq_stride_fit', 1), 1)
# Nb max de paquets scorés en un seul appel modèle côté détection
DETECT_BATCH_SIZE = _positive_int(_ANOMALY_CFG.get('detect_batch_size', 256), 256)
MODEL_ERROR_THRESHOLD = _positive_int(_ANOMALY_CFG.get('model_error_threshold', 5), 5)

def n_windows(n_items: int, length: int = SEQ_LENGTH, stride: int = 1) -> int:
    """Nombre de fenêtres de taille `length` avec un pas `stride` sur `n_items` éléments."""
    if n_items < length:
        return 0
    return (n_items - length) // stride + 1

CAPTURE_FILENAME = GLOBAL_CONFIG.get("capture_filename", "capture.pkl")
ADD_DATA_TO_CAPTURE_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "data", "capture_backup.pkl"))
ADD_DATA_TO_CAPTURE_PATH = GLOBAL_CONFIG.get("add_data_to_capture_path") or ADD_DATA_TO_CAPTURE_PATH

FILTER = CAPTURE_CONFIG.get("FILTER", "tcp or udp or icmp")
TIMEOUT_MS = CAPTURE_CONFIG.get("TIMEOUT_MS", 40)
BUFFER_SIZE = int(CAPTURE_CONFIG.get("BUFFER_SIZE", "64")) * 1024 * 1024
# Débloquer avec sudo sysctl -w net.core.rmem_max=wanted * 1024 * 1024
SRC_IGNORED_IP = CAPTURE_CONFIG.get("SRC_IGNORED_IP", [])
DST_IGNORED_IP = CAPTURE_CONFIG.get("DST_IGNORED_IP", [])
N_TRIAl = GLOBAL_CONFIG.get("N_TRIALS", 10)
GRAPH = GLOBAL_CONFIG.get("GRAPH", True)
REQUEST_LIMIT = GLOBAL_CONFIG.get("REQUEST_LIMIT", 30)
API_CONFIG = GLOBAL_CONFIG.get("API_CONFIG", {"port": 8080, "host": "0.0.0.0"})

ALLOWED_ORIGINS = ["*"]
ADMIN_DATA = {
    "username": "",
    "key": "",
    "password": "",
    "is_exec": False
}

try:
    ADMIN_DATA = auth()
except Exception as e:
    logger.print('Erreur auth : ', e)

NOT_BEFORE = 1
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

COMPLIANCE_CONFIG = {
    'cvss_mapping': {
        'log_only': 'CVSS 0.0-3.9 (Low)',
        'monitor': 'CVSS 4.0-6.9 (Medium)',
        'add_delay': 'CVSS 7.0-8.9 (High)',
        'suspicious': 'CVSS 9.0-9.8 (Critical)',
        'danger': 'CVSS 9.9-10.0 (Critical+)',
        'critical': 'CVSS 10.0+ (RCE/0day)'
    },
    'standards': ['PCI-DSS', 'NIST 800-53', 'ISO 27001'],
    'audit_retention_days': 90,
    'report_frequency': 'daily'
}
 


