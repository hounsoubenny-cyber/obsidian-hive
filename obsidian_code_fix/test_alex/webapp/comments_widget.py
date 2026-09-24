#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Widget d'affichage de commentaires utilisateurs.

/!\\ Ce fichier ne doit jamais être déployé tel quel en production.
"""

import html


def render_comment(author: str, comment_text: str) -> str:
    """
    Rend un commentaire en HTML en échappant le contenu utilisateur
    pour éviter les attaques XSS (script injection, event handlers, etc.).
    """
    escaped_author = html.escape(author)
    escaped_text = html.escape(comment_text)
    return f"<div class='comment'><b>{escaped_author}</b>: {escaped_text}</div>"


def list_recent_comments(db_cursor, article_id: int):
    """
    Récupère les commentaires récents pour un article.
    Utilise des requêtes paramétrées pour éviter l'injection SQL.
    """
    db_cursor.execute(
        "SELECT author, comment_text FROM comments "
        "WHERE article_id = ? ORDER BY created_at DESC",
        (article_id,),
    )
    return db_cursor.fetchall()
