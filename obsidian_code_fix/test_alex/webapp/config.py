#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration de l'application de test.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
"""

# --- Vulnérabilité 1 : secrets codés en dur dans le code source --------
STRIPE_SECRET_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "changeme"

# --- Vulnérabilité 2 : mode debug actif par défaut ---------------------
# Si ce fichier est déployé tel quel en prod, Flask/Django afficheront
# la stacktrace complète (chemins serveurs, variables, parfois secrets)
# à la moindre exception non gérée.
DEBUG = True

# --- Vulnérabilité 3 : CORS totalement ouvert --------------------------
CORS_ALLOWED_ORIGINS = ["*"]

DATABASE_URL = "sqlite:///app.db"
