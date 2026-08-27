#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration de l'application de test.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
"""

import os


def _get_env(key: str, default: str = "") -> str:
    """Retourne la valeur d'une variable d'environnement, avec un fallback."""
    return os.environ.get(key, default)


# --- Fix : les secrets ne sont plus codés en dur dans le code source ---
# Ils doivent être fournis via des variables d'environnement au moment du
# déploiement (ex: .env, fichier de configuration serveur, secret manager).
STRIPE_SECRET_KEY = _get_env("STRIPE_SECRET_KEY", "")
AWS_ACCESS_KEY_ID = _get_env("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = _get_env("AWS_SECRET_ACCESS_KEY", "")
JWT_SECRET = _get_env("JWT_SECRET", "")

# --- Fix : mode debug désactivé par défaut en production ---
# Déployer en DEBUG=True expose les stacktraces et les chemins serveurs.
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")

# --- Fix : CORS restreint aux origines explicites ---
# "*" ouvre l'application à n'importe quel domaine — vulnérabilité XSS cross-site.
CORS_ALLOWED_ORIGINS = _get_env("CORS_ALLOWED_ORIGINS", "").split(",") if os.environ.get("CORS_ALLOWED_ORIGINS") else []

DATABASE_URL = "sqlite:///app.db"
