#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration centrale pour l'application Anti-Phishing.

Ce module contient toutes les constantes de configuration utilisées
par l'API, le CLI, et les différents composants du système.

Variables principales :
- HOST, PORT : Configuration du serveur API
- REQUEST : Limite de requêtes par minute (rate limiting)
- REACT_EXISTS : Détection automatique du build React
- DATA : Configuration par défaut pour l'analyse

Auteur: HOUNSOU Samuel
Date: Décembre 2025
Version: 1.0.0
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from anti_phishing_ia.ml_model.phishing_ia import features_name as FEATURES_NAME

# ============================================================================
# CONFIGURATION RÉSEAU DE L'API
# ============================================================================

PORT = 8000
"""int: Port d'écoute par défaut pour l'API FastAPI."""

HOST = '0.0.0.0'
"""str: Hôte d'écoute par défaut ('0.0.0.0' pour toutes les interfaces)."""

REQUEST = 30
"""int: Nombre maximum de requêtes par minute (rate limiting)."""

# ============================================================================
# CONFIGURATION REACT (FRONTEND)
# ============================================================================

PATH_REACT = "/static"
"""str: Chemin URL pour les fichiers statiques React."""

REACT_URL = 'http://localhost:3000'
"""str: URL de développement React (pour CORS)."""

DIRECTORY_REACT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "build", "static")
"""str: Chemin absolu vers le dossier des fichiers statiques React."""

BUILD_URL = "/build"
"""str: Chemin URL pour le build React."""

BUILD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "build")
"""str: Chemin absolu vers le dossier de build React."""

INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "build", "index.html")
"""str: Chemin absolu vers le fichier index.html de React."""

REACT_EXISTS = os.path.exists(DIRECTORY_REACT)
"""bool: True si le build React est présent, False sinon."""

ALLOWED_ORIGINS = ["*"]
"""list: Origines autorisées pour CORS ('*' = toutes)."""

# ============================================================================
# CONFIGURATION PAR DÉFAUT DE L'ANALYSE
# ============================================================================

DATA = {
    # ──────────────────────────────────────────────
    # CONFIG MODÈLE ML
    # ──────────────────────────────────────────────
    'model_dir':               'model',
    'model_path':              'model_phish.pkl',
    'features_name':           FEATURES_NAME,
    'n_features':              len(FEATURES_NAME),

    # ──────────────────────────────────────────────
    # CONFIG REFIT AUTO (ML)
    # ──────────────────────────────────────────────
    'refit_time':              10000,    # nb requêtes avant refit
    'refit':                   False,    # forcer refit au démarrage
    'backup_models':           True,     # sauvegarder avant écrasement
    'comparison_threshold':    0.03,     # amélioration min pour update (3%)
    '_all_':                   False,    # mode complet (learning curve etc.)
    'path_to_original_dataset': os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "ml_model", "data", "datasets", "dataset.pkl"
    ),

    # ──────────────────────────────────────────────
    # CONFIG ANALYSE PAR DÉFAUT
    # ──────────────────────────────────────────────
    'check_blacklist':         False,    # vérifier PhishDestroy
    'check_right_click':       False,    # vérifier désactivation clic droit
    'explain':                 False,    # retourner les flags passifs

    # ──────────────────────────────────────────────
    # CONFIG MODÈLE BERT (MAIL)
    # ──────────────────────────────────────────────
    'mail_model_dir':          'mail_model',
    'mail_model_type':         'fast',   # 'fast' | 'full'
}
"""
dict: Configuration par défaut pour les requêtes d'analyse.

Ces paramètres peuvent être surchargés :
- Via l'API (body JSON)
- Via le CLI (arguments --model-path, --refit, etc.)
- Via l'endpoint POST /api/settings
"""