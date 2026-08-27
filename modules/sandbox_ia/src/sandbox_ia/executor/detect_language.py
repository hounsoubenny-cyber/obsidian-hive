#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May  9 12:20:39 2026

@author: hounsousamuel

Module de détection de langage pour le Sandbox ShieldAI V2.
Identifie le langage de programmation d'un fichier de code source
via trois stratégies successives : extension, shebang, analyse de contenu.
Fournit également les commandes d'exécution pour chaque langage supporté.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from sandbox_ia.configs.detect_language_config import (
    SHEBANG_MAP, LANGUAGES, LANGUAGE_MAP,
    LANGUAGE_RUNNERS, CONTENT_PATTERNS, 
    COMPILED_LANGUAGES
    
)
from sandbox_ia.sandbox_utils.logger import get_logger
logger = get_logger()

# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def detect_language(filename: str, content: str) -> str:
    """
    Détecte le langage de programmation d'un fichier de code source.

    Applique trois stratégies successives dans l'ordre de fiabilité :

    1. **Extension** : compare l'extension du fichier avec LANGUAGE_MAP.
       C'est la méthode la plus fiable — si un fichier s'appelle "code.py",
       c'est du Python.

    2. **Shebang** : analyse la première ligne du fichier.
       Si elle commence par "#!", on cherche un mot-clé connu dans SHEBANG_MAP.
       Exemple : "#!/usr/bin/env python3" → "python3" → "python"

    3. **Analyse de contenu** : compte les patterns caractéristiques de chaque
       langage dans CONTENT_PATTERNS. Le langage avec le plus de matches gagne.
       Si aucun pattern ne matche (score = 0), None est retourné.

    Parameters
    ----------
    filename : str
        Nom ou chemin du fichier. Peut être une chaîne vide ou None si
        le fichier n'a pas de nom connu — dans ce cas l'extension est ignorée.
    content : str
        Contenu complet du fichier source à analyser.

    Returns
    -------
    str
        Nom du langage détecté parmi les valeurs de LANGUAGES.
        "bash" par défaut si aucune stratégie n'a abouti.
    """
    # Stratégie 1 — Extension
    ext = None
    if filename:
        ext = os.path.splitext(filename)[1].strip().lower()
    if ext and LANGUAGE_MAP.get(ext):
        logger.print(f"🔍 Langage détecté par extension '{ext}': {LANGUAGE_MAP[ext]}")
        return LANGUAGE_MAP[ext]

    # Stratégie 2 — Shebang (première ligne)
    first_line = content.split("\n")[0] if content else ""
    for keyword, language in SHEBANG_MAP.items():
        if keyword in first_line:
            logger.print(f"🔍 Langage détecté par shebang '{keyword}': {language}")
            return language

    # Stratégie 3 — Analyse de contenu (comptage de patterns)
    language_pattern_count = {
        lang: sum(pattern in content for pattern in patterns)
        for lang, patterns in CONTENT_PATTERNS.items()
    }

    most_probable = sorted(
        language_pattern_count,
        key=lambda lang: language_pattern_count[lang],
        reverse=True
    )

    best = most_probable[0] if most_probable else None
    if best and language_pattern_count[best] > 0:
        logger.print(f"🔍 Langage détecté par contenu ({language_pattern_count[best]} patterns): {best}")
        return best

    # Fallback — aucune stratégie n'a abouti, None
    return None


def get_supported_languages() -> list[str]:
    """
    Retourne la liste des langages supportés par le sandbox.

    Returns
    -------
    list[str]
        Liste des 14 langages supportés.
    """
    return LANGUAGES


def get_language_cmd(file: str, language: str) -> tuple[str | None, str | None, str | None]:
    """
    Retourne l'extension, le nom de fichier complété et la commande d'exécution
    pour un fichier et un langage donnés.

    Utilise LANGUAGE_RUNNERS pour générer automatiquement le nom de fichier
    avec la bonne extension si elle est manquante, ainsi que la commande
    shell complète pour exécuter le fichier dans le container sandbox.

    Parameters
    ----------
    file : str
        Nom ou chemin du fichier à exécuter.
        Exemple : "code", "code.py", "/sandbox/work/script.js"
    language : str
        Langage de programmation du fichier.
        Doit être une valeur présente dans LANGUAGES.

    Returns
    -------
    tuple[str | None, str | None, str | None]
        - str : Extension du fichier complété (ex: ".py")
        - str : Nom du fichier avec extension garantie (ex: "code.py")
        - str : Commande shell d'exécution complète (ex: "python3 code.py")
        Retourne (None, None, None) si file est vide ou langage non supporté.

    Examples
    --------
    >>> get_language_cmd("code", "python")
    ('.py', 'code.py', 'python3 code.py')

    >>> get_language_cmd("prog", "c")
    ('.c', 'prog.c', 'gcc prog.c -o /tmp/c_out && /tmp/c_out')

    >>> get_language_cmd("script.rs", "rust")
    ('.rs', 'script.rs', 'rustc script.rs -o /tmp/rust_out && /tmp/rust_out')
    """
    if not file:
        return None, None, None

    if language not in LANGUAGES:
        logger.print(f"❌ Langage non supporté: {language}")
        return None, None, None

    file_completed, cmd = LANGUAGE_RUNNERS[language](file)
    ext = os.path.splitext(file_completed)[1].strip().lower()

    logger.print(f"⚙️  [{language}] fichier: {file_completed} | cmd: {cmd}")
    return ext, file_completed, cmd

if __name__ == "__main__":
    
    # Test stratégie 1 — extension
    print("=== Test extension ===")
    print(detect_language("code.py", ""))           # → python
    print(detect_language("script.js", ""))         # → javascript
    print(detect_language("programme.R", ""))       # → r

    # Test stratégie 2 — shebang
    print("\n=== Test shebang ===")
    print(detect_language("", "#!/usr/bin/env python3\nprint('hello')"))   # → python
    print(detect_language("", "#!/bin/bash\necho hello"))                   # → bash
    print(detect_language("", "#!/usr/bin/perl\nprint 'hello'"))            # → perl

    # Test stratégie 3 — contenu
    print("\n=== Test contenu ===")
    print(detect_language("", "package main\nfunc main() {\nimport (\n"))  # → go
    print(detect_language("", "public class Main {\npublic static void main")) # → java
    print(detect_language("", "fn main() {\nlet mut x = 5;\nprintln!(x)")) # → rust

    # Test fallback
    print("\n=== Test fallback ===")
    print(detect_language("", ""))                  # → bash
    print(detect_language("", "zzz qqq xxx"))       # → bash

    # Test get_language_cmd
    print("\n=== Test get_language_cmd ===")
    print(get_language_cmd("code", "python"))       # → (.py, code.py, python3 code.py)
    print(get_language_cmd("prog", "c"))            # → (.c, prog.c, gcc prog.c ...)
    print(get_language_cmd("", "python"))           # → (None, None, None)
    print(get_language_cmd("code", "cobol"))        # → (None, None, None)