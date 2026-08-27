#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration sécurisée de l'application.

Ce fichier a été corrigé par Alex (Obsidian) pour éliminer les vulnérabilités
identifiées lors du scan de sécurité.

IMPORTANT : Tous les secrets doivent être configurés via des variables d'environnement
ou un gestionnaire de secrets (Vault, AWS Secrets Manager, etc.)
"""

import os

# --- Configuration sécurisée (secrets externalisés) ------------------------
# Les clés API et secrets doivent être définis via des variables d'environnement
# Exemple d'utilisation :
#   export STRIPE_SECRET_KEY="sk_live_..."
#   export AWS_ACCESS_KEY_ID="AKIA..."
#   export JWT_SECRET="votre_secret_aleatoire_secure"

STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
JWT_SECRET = os.getenv('JWT_SECRET')

# --- Configuration de sécurité ---------------------------------------------
# Mode debug désactivé par défaut pour éviter les fuites d'informations
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

# CORS restreint aux origines autorisées uniquement
# En production, définir une liste explicite d'origines autorisées
CORS_ALLOWED_ORIGINS = [
    os.getenv('FRONTEND_URL', 'http://localhost:3000'),
    os.getenv('FRONTEND_URL_ALT', 'https://monapp.com')
]

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///app.db')

# --- Vérification des secrets critiques ------------------------------------
def validate_config():
    """
    Vérifie que les secrets critiques sont bien configurés.
    
    En production, lever une exception si un secret obligatoire est manquant.
    """
    required_secrets = ['JWT_SECRET']
    missing = [secret for secret in required_secrets if not os.getenv(secret)]
    
    if missing:
        raise EnvironmentError(
            f"Secrets manquants : {', '.join(missing)}. "
            "Veuillez les définir via des variables d'environnement."
        )

# Valider la configuration au démarrage
validate_config()