#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'authentification de l'application de test.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
Ne JAMAIS utiliser ce code en production.
"""

import hashlib
import hmac
import os
import sqlite3

# --- Identifiants admin codés en dur (à retirer en production) ----------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SuperSecret123!"  # noqa: jamais de mot de passe en clair

DB_PATH = "app.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> str:
    # Fix : utilisation de PBKDF2 avec un sel aléatoire (au lieu de MD5 sans sel)
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt.hex() + ":" + key.hex()


def authenticate(username: str, password: str) -> bool:
    """
    Vérifie les identifiants d'un utilisateur en base.
    Fix : requête paramétrée (pas de f-string dans la requête SQL).
    """
    conn = get_connection()
    cursor = conn.cursor()

    hashed = hash_password(password)

    # Requête paramétrée — l'attaquant ne peut plus injecter du SQL via username
    query = "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, hashed))
    row = cursor.fetchone()
    conn.close()

    return row is not None


def is_admin(username: str, password: str) -> bool:
    # Fix : utilisation de hmac.compare_digest pour éviter les timing attacks
    return hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD)
