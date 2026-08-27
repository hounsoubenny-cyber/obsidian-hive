#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'authentification sécurisé de l'application.

Ce fichier a été corrigé par Alex (Obsidian) pour éliminer les vulnérabilités
identifiées lors du scan de sécurité.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Optional

# --- Configuration sécurisée -------------------------------------------------
DB_PATH = "app.db"

# --- Suppression des identifiants admin codés en dur ------------------------
# Les identifiants doivent être configurés via variables d'environnement

def get_connection():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash un mot de passe avec bcrypt (simulé ici par un hash sécurisé avec sel aléatoire).
    
    Retourne un tuple (hash_hex, salt_hex) pour stockage en base.
    
    Note : En production, utiliser une bibliothèque dédiée comme bcrypt,
    scrypt ou Argon2. Cet exemple utilise HMAC-SHA256 pour la démonstration.
    """
    # Générer un sel aléatoire de 16 octets
    salt = secrets.token_bytes(16)
    
    # Configuration du hash : 100 000 itérations pour ralentir les attaques par force brute
    iterations = 100000
    
    # Utiliser PBKDF2 avec HMAC-SHA256
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    
    return hash_bytes.hex(), salt.hex()


def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    """
    Vérifie un mot de passe contre un hash stocké avec son sel.
    
    Utilise la même fonction de hash pour recalculer et comparer.
    """
    try:
        iterations = 100000
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            bytes.fromhex(stored_salt),
            iterations
        )
        return hmac.compare_digest(new_hash.hex(), stored_hash)
    except Exception:
        # En cas d'erreur, refuser l'authentification pour éviter les fuites d'information
        return False


def authenticate(username: str, password: str) -> bool:
    """
    Vérifie les identifiants d'un utilisateur en base de manière sécurisée.
    
    Utilise des requêtes paramétrées pour éviter l'injection SQL.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Utiliser la fonction de vérification sécurisée
    query = "SELECT password_hash, salt FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        # Utilisateur non trouvé
        return False
    
    stored_hash, stored_salt = row
    return verify_password(stored_hash, stored_salt, password)


def is_admin(username: str, password: str) -> bool:
    """
    Vérifie si les identifiants correspondent à un compte administrateur.
    
    Utilise hmac.compare_digest pour éviter les timing attacks.
    """
    # Récupérer les identifiants admin depuis les variables d'environnement
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    if admin_password is None:
        # Si le mot de passe admin n'est pas configuré, refuser l'accès
        return False
    
    # Comparaison sécurisée avec hmac.compare_digest
    return (hmac.compare_digest(username.encode('utf-8'), admin_username.encode('utf-8')) and
            hmac.compare_digest(password.encode('utf-8'), admin_password.encode('utf-8')))