#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Widget d'affichage de commentaires utilisateurs sécurisé.

Ce fichier a été corrigé par Alex (Obsidian) pour éliminer les vulnérabilités
identifiées lors du scan de sécurité.
"""

import html
import os
import sqlite3
from typing import List, Tuple

# --- Configuration sécurisée -------------------------------------------------
DB_PATH = os.getenv('DATABASE_URL', 'sqlite:///app.db').replace('sqlite:///', '')

def get_connection():
    return sqlite3.connect(DB_PATH)


def escape_html(text: str) -> str:
    """
    Échappe les caractères HTML spéciaux pour prévenir les attaques XSS.
    
    Utilise la bibliothèque standard html.escape pour une implémentation fiable.
    """
    return html.escape(text)


def render_comment(author: str, comment_text: str) -> str:
    """
    Affiche un commentaire de manière sécurisée.
    
    Échappe à la fois le nom de l'auteur et le texte du commentaire pour
    prévenir toute injection XSS.
    """
    escaped_author = escape_html(author)
    escaped_text = escape_html(comment_text)
    
    return f"<div class='comment'><b>{escaped_author}</b>: {escaped_text}</div>"


def list_recent_comments(article_id: int) -> List[Tuple[str, str]]:
    """
    Liste les commentaires récents pour un article de manière sécurisée.
    
    Utilise des requêtes paramétrées pour éviter l'injection SQL.
    
    Retourne une liste de tuples (author, comment_text) avec les données
    déjà échappées pour affichage direct.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Utilisation de requêtes paramétrées pour éviter l'injection SQL
    query = """
        SELECT author, comment_text 
        FROM comments 
        WHERE article_id = ? 
        ORDER BY created_at DESC
    """
    cursor.execute(query, (article_id,))
    rows = cursor.fetchall()
    conn.close()

    # Échapper les résultats pour affichage direct
    return [(escape_html(author), escape_html(comment_text)) for author, comment_text in rows]


# --- Documentation sur les bonnes pratiques ----------------------------------
#
# Pour prévenir les attaques XSS :
# - Toujours échapper les données utilisateur avant de les afficher dans du HTML
# - Utiliser des bibliothèques dédiées (html.escape en Python) plutôt que des
#   méthodes maison vulnérables
# - Éviter de construire du HTML avec des f-strings ou du formatage direct
#   depuis des données utilisateur
#
# Pour prévenir les injections SQL :
# - Toujours utiliser des requêtes paramétrées (placeholders ?)
# - Ne jamais concaténer directement des variables utilisateur dans les requêtes
# - Utiliser des ORMs ou des bibliothèques sécurisées pour les requêtes SQL
#
# Pour prévenir les prompt injections (dans ce contexte) :
# - Ne jamais exécuter ou interpréter du code contenu dans des données utilisateur
# - Toujours valider et nettoyer les entrées utilisateur
# - Utiliser des patterns de parsing stricts plutôt que des évaluations dynamiques