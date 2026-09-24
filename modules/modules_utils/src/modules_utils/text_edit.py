#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 21 10:30:12 2026

@author: hounsousamuel
"""


"""
text_edit.py — édition de texte EXACTE et sûre, partagée par :
  - le tool hôte `str_replace_file_content` d'Alex (mode historique) ;
  - `Workspace.str_replace` / le tool `sandbox_str_replace` (mode workspace).

Un seul algorithme => un seul comportement, testé une fois.

Principe (le même que l'outil d'édition de Claude) : on remplace un texte EXACT qui doit être
UNIQUE dans le fichier. Zéro correspondance ou plusieurs => on REFUSE, sans rien modifier, avec
un message qui dit quoi corriger. Pas de numéros de ligne, pas de regex, pas d'échappement shell :
c'est ce qui rend l'édition fiable pour un petit modèle.

Module volontairement sans dépendance (stdlib uniquement).
"""

import os
import shutil
import tempfile


class TextEditError(ValueError):
    """Erreur 'attendue' d'édition : le message est écrit pour être lu par l'agent."""


# ─────────────────────────────────────────────────────────────────────────────
# STR_REPLACE
# ─────────────────────────────────────────────────────────────────────────────

def _line_of(text: str, index: int) -> int:
    """Numéro de ligne (1-indexé) du caractère à la position `index`."""
    return text.count("\n", 0, index) + 1


def _occurrence_lines(text: str, needle: str, limit: int = 8) -> list[int]:
    lines, start = [], 0
    while len(lines) < limit:
        i = text.find(needle, start)
        if i == -1:
            break
        lines.append(_line_of(text, i))
        start = i + max(len(needle), 1)
    return lines


def _not_found_message(text: str, old: str) -> str:
    first = next((ln.strip() for ln in old.splitlines() if ln.strip()), "")
    if first:
        hits = [i for i, ln in enumerate(text.splitlines(), 1) if first in ln]
        if hits:
            return (
                f"old_str est introuvable tel quel. Sa première ligne non vide ({first[:60]!r}) existe "
                f"aux lignes {hits[:5]}, mais la suite (ou l'indentation / les espaces) diffère. "
                "Relis le fichier avec les numéros de ligne et recopie le texte EXACT."
            )
    return (
        "old_str est introuvable : aucune de ses lignes n'apparaît dans le fichier. "
        "Relis le fichier (avec les numéros de ligne) avant de réessayer."
    )


def apply_str_replace(text: str, old: str, new: str, replace_all: bool = False) -> tuple[str, int, int]:
    """
    Remplace `old` par `new` dans `text`.

    Retourne (nouveau_texte, nombre_de_remplacements, première_ligne_modifiée).
    Lève TextEditError (et ne modifie rien) si `old` est vide, identique à `new`, introuvable,
    ou ambigu (plusieurs occurrences sans replace_all).

    Tolérance CRLF : si le fichier est en fins de ligne Windows et que `old` (écrit par un LLM)
    utilise des \\n, on retente avec des \\r\\n — sinon un fichier CRLF serait inéditable.
    """
    if not old:
        raise TextEditError("old_str est vide : indique le texte EXACT à remplacer.")
    if old == new:
        raise TextEditError("old_str et new_str sont identiques : il n'y a rien à changer.")

    count = text.count(old)
    if count == 0 and "\r\n" in text and "\r" not in old:
        old_crlf, new_crlf = old.replace("\n", "\r\n"), new.replace("\n", "\r\n")
        if text.count(old_crlf):
            old, new, count = old_crlf, new_crlf, text.count(old_crlf)

    if count == 0:
        raise TextEditError(_not_found_message(text, old))
        
    if count > 1 and not replace_all:
        raise TextEditError(
            f"old_str apparaît {count} fois (lignes {_occurrence_lines(text, old)}) : c'est ambigu. "
            "Ajoute quelques lignes de contexte autour pour le rendre unique, ou mets replace_all=true "
            "pour remplacer toutes les occurrences."
        )

    first_line = _line_of(text, text.find(old))
    if replace_all:
        return text.replace(old, new), count, first_line
    return text.replace(old, new, 1), 1, first_line


def numbered_context(text: str, first_line: int, span: int = 1, radius: int = 3, max_lines: int = 15) -> str:
    """Extrait numéroté (1-indexé) autour d'un changement, pour que l'agent vérifie le résultat
    sans relire tout le fichier. `span` = nombre de lignes du nouveau texte."""
    lines = text.split("\n")
    start = max(1, first_line - radius)
    end = min(len(lines), first_line + max(span, 1) - 1 + radius)
    end = min(end, start + max_lines - 1)
    return "\n".join(f"{i}\t{lines[i - 1].rstrip(chr(13))}" for i in range(start, end + 1))


# ─────────────────────────────────────────────────────────────────────────────
# FINS DE LIGNE + ÉCRITURE ATOMIQUE
# ─────────────────────────────────────────────────────────────────────────────

def match_newlines(original: str, new: str) -> str:
    """Si `original` est en CRLF pur et que `new` n'a aucun \\r, convertit `new` en CRLF : une
    réécriture complète par un LLM ne doit pas changer silencieusement le style du fichier."""
    if "\r\n" in original and "\n" not in original.replace("\r\n", "") and "\r" not in new:
        return new.replace("\n", "\r\n")
    return new


def atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    """
    Écrit `text` dans `path` de façon ATOMIQUE (fichier temporaire dans le même dossier, fsync,
    os.replace) : un crash ou un disque plein ne laisse jamais un fichier tronqué. Les fins de
    ligne sont écrites telles quelles (newline=""), les permissions du fichier existant conservées.
    Si `path` est un lien symbolique, c'est sa cible qui est réécrite (le lien reste un lien).
    """
    path = os.path.realpath(path)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".alex-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            shutil.copymode(path, tmp)
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
