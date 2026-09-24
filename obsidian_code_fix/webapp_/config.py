#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration de l'application de test.

Fichier corrigé — secrets via variables d'environnement, DEBUG désactivé,
CORS restreint.
"""

import os

# --- Secrets via variables d'environnement (ne jamais coder en dur) --------
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")

# --- Mode debug désactivé par défaut ---------------------------------------
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

# --- CORS restreint (liste explicite de domaines autorisés) -----------------
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if os.environ.get("CORS_ALLOWED_ORIGINS") else []

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")
