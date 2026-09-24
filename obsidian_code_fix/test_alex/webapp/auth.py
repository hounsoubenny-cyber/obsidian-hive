#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'authentification de l'application de test.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
Ne JAMAIS utiliser ce code en production.
"""

import hashlib
import os
import sqlite3

# --- Identifiants admin depuis les variables d'environnement -------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

DB_PATH = "app.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> str:
    """
    Hasher un mot de passe avec bcrypt (cost factor 12).
    bcrypt inclut un sel aléatoire par appel, ce qui le rend résistant
    aux attaques par rainbow tables et au brute-force.
    """
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """
    Vérifie un mot de passe contre un hash bcrypt stocké.
    Utilise bcrypt.checkpw qui gère correctement les sels.
    """
    import bcrypt
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def authenticate(username: str, password: str) -> bool:
    """
    Vérifie les identifiants d'un utilisateur en base.
    """
    conn = get_connection()
    cursor = conn.cursor()

    hashed = hash_password(password)

    # Requête paramétrée — l'input utilisateur n'est JAMAIS concaténé
    # dans le SQL, ce qui empêche toute injection SQL.
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password_hash = ?",
        (username, hashed),
    )
    row = cursor.fetchone()
    conn.close()

    return row is not None


def is_admin(username: str, password: str) -> bool:
    """
    Vérifie que l'utilisateur est l'admin.
    Utilise hmac.compare_digest pour éviter les timing attacks.
    """
    import hmac
    return hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD)
