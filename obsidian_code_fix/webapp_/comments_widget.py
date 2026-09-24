#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Widget d'affichage de commentaires utilisateurs.

Fichier corrigé — requêtes paramétrées, échappement HTML, prompt injection supprimée.
"""

import sqlite3
from markupsafe import escape

def render_comment(author: str, comment_text: str) -> str:
    """Rendre un commentaire avec échappement HTML pour éviter le XSS."""
    safe_author = escape(author)
    safe_text = escape(comment_text)
    return f"<div class='comment'><b>{safe_author}</b>: {safe_text}</div>"

def list_recent_comments(db_cursor, article_id: int):
    """
    Récupère les commentaires récents avec une requête paramétrée.
    """
    query = "SELECT author, comment_text FROM comments WHERE article_id = ? ORDER BY created_at DESC"
    db_cursor.execute(query, (article_id,))
    return db_cursor.fetchall()
