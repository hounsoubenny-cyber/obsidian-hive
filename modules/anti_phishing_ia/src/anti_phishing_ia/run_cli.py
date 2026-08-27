#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface en ligne de commande (CLI) pour l'Anti-Phishing.

Ce script est un simple wrapper qui importe AntiPhishing et utilise
ses méthodes de classe from_cli() et phishing_cli().

Il permet d'analyser des URLs, lancer l'API, exécuter des tests,
et gérer le cache directement depuis le terminal.

Utilisation:
    python run_cli.py -u https://google.com
    python run_cli.py --url https://paypal-verify.tk --check-blacklist
    python run_cli.py --test
    python run_cli.py --api --port 8080
    python run_cli.py --clear-cache

Auteur: HOUNSOU Samuel
Version: 2.0.0
"""

import sys
import os

# Ajout du chemin parent pour permettre les imports absolus
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anti_phishing_ia.main_phish import AntiPhishing


def main():
    """
    Point d'entrée principal du CLI.
    
    Cette fonction :
    1. Crée une instance d'AntiPhishing via la méthode de classe from_cli()
       qui parse automatiquement les arguments de ligne de commande
    2. Exécute l'action correspondante (analyse URL, API, tests, etc.)
    
    Returns:
        None
    
    Examples:
        >>> # Depuis le terminal:
        >>> python run_cli.py -u https://google.com
        >>> python run_cli.py --api --port 8080
        >>> python run_cli.py --test --verbose
    """
    # Création de l'instance avec parsing automatique des arguments
    ap = AntiPhishing.from_cli()
    
    # Exécution de l'action correspondante
    ap.phishing_cli()


if __name__ == '__main__':
    main()