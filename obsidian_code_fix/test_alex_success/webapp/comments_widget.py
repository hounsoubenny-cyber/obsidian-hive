#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Widget d'affichage de commentaires utilisateurs.

/!\\ Fichier volontairement vulnérable — sandbox de test pour Alex (Obsidian).
"""

from html import escape


# --- Fix XSS : les champs utilisateur sont maintenant échappés en HTML ---
def render_comment(author: str, comment_text: str) -> str:
    return f"<div class='comment'><b>{escape(author)}</b>: {escape(comment_text)}</div>"


def list_recent_comments(db_cursor, article_id: int):
    # Fix SQL injection : requête paramétrée (article_id passé via paramètre)
    query = "SELECT author, comment_text FROM comments WHERE article_id = ? ORDER BY created_at DESC"
    db_cursor.execute(query, (article_id,))
    return db_cursor.fetchall()
