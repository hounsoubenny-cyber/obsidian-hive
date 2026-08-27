#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'authentification de l'application de test.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
Ne JAMAIS utiliser ce code en production.
"""

import hashlib
import sqlite3

# --- Vulnérabilité 1 : identifiants admin codés en dur -----------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SuperSecret123!"  # noqa: jamais de mot de passe en clair

DB_PATH = "app.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> str:
    # --- Vulnérabilité 2 : MD5 pour hasher un mot de passe -------------
    # MD5 est cassé depuis longtemps pour ce type d'usage (pas de sel,
    # collisions faciles, brute-force trivial avec des rainbow tables).
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def authenticate(username: str, password: str) -> bool:
    """
    Vérifie les identifiants d'un utilisateur en base.
    """
    conn = get_connection()
    cursor = conn.cursor()

    hashed = hash_password(password)

    # --- Vulnérabilité 3 : injection SQL --------------------------------
    # Concaténation directe de l'input utilisateur dans la requête SQL.
    # Un attaquant peut injecter via username, ex:
    #   username = "admin' --"
    # pour contourner totalement le contrôle du mot de passe.
    query = f"SELECT id FROM users WHERE username = '{username}' AND password_hash = '{hashed}'"

    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    return row is not None


def is_admin(username: str, password: str) -> bool:
    # --- Vulnérabilité 4 : comparaison de mots de passe non constante --
    # Comparaison directe avec ==, vulnérable à une timing attack
    # (devrait utiliser hmac.compare_digest).
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD
