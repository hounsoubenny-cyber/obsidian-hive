#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration de l'application de test.

/!\\ Ce fichier doit être chargé depuis un fichier .env ou des variables
d'environnement en production. Ne jamais versionner les vrais secrets.
"""

import os


def _load_secret(name: str, default: str = "") -> str:
    """
    Charge un secret depuis une variable d'environnement.
    Retourne la valeur de l'environnement ou la valeur par défaut
    (qui est elle-même un placeholder — pas un vrai secret).
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return value


# --- Secrets chargés depuis les variables d'environnement ---------------
# En production, ces variables doivent être définies dans un fichier .env
# ou via le secret manager de l'infrastructure.
STRIPE_SECRET_KEY = _load_secret("STRIPE_SECRET_KEY")
AWS_ACCESS_KEY_ID = _load_secret("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = _load_secret("AWS_SECRET_ACCESS_KEY")
JWT_SECRET = _load_secret("JWT_SECRET")

# --- Configuration de sécurité ------------------------------------------
DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

# --- CORS restreint par défaut (à ajuster selon les besoins) -------------
CORS_ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "https://example.com,https://app.example.com",
).split(",")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")
