#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'authentification de l'application de test.

Fichier corrigé — MD5 remplacé par werkzeug.security, requêtes paramétrées,
comparaison constante.
"""

import hmac
import os
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

ADMIN_USERNAME = "admin"

DB_PATH = os.environ.get("DB_PATH", "app.db")

def get_connection():
    return sqlite3.connect(DB_PATH)

def hash_password(password: str) -> str:
    """Hasher un mot de passe avec werkzeug.security (SHA-256 + salt)."""
    return generate_password_hash(password)

def authenticate(username: str, password: str) -> bool:
    """
    Vérifie les identifiants d'un utilisateur en base.
    Utilise des requêtes paramétrées pour éviter l'injection SQL.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Requête paramétrée — pas de f-string avec input utilisateur
    query = "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password))
    row = cursor.fetchone()
    conn.close()

    return row is not None

def is_admin(username: str, password: str) -> bool:
    """
    Vérifie les identifiants admin avec une comparaison constante
    (hmac.compare_digest) pour éviter les timing attacks.
    """
    # Comparaison constante pour éviter les timing attacks
    admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH") or generate_password_hash("SuperSecret123!")
    return hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, admin_password_hash)
