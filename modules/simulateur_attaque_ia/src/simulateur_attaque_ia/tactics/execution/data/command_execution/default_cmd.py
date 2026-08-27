#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 27 10:58:09 2026

@author: hounsousamuel
"""

DEFAULT_COMMANDS = {

    # ─────────────────────────────────────────────
    # SYSTEM INFO — T1082
    # ─────────────────────────────────────────────
    "system_info": [
        "uname -a",                          # OS + kernel complet
        "uname -r",                          # kernel version
        "uname -m",                          # architecture
        "hostname",                          # nom machine
        "hostname -I",                       # toutes les IPs
        "cat /etc/os-release",              # distro + version
        "cat /proc/version",                # version kernel détaillée
        "uptime",                            # temps de fonctionnement
        "date",                              # date + heure
        "timedatectl",                       # timezone
    ],

    # ─────────────────────────────────────────────
    # USERS — T1087.001
    # ─────────────────────────────────────────────
    "users": [
        "whoami",                            # user actuel
        "id",                                # uid/gid/groups
        "cat /etc/passwd",                  # tous les users
        "cat /etc/group",                   # tous les groupes
        "w",                                 # users connectés
        "who",                               # users connectés simple
        "last",                              # historique connexions
        "lastlog",                           # dernière connexion par user
        "sudo -l",                           # permissions sudo
    ],

    # ─────────────────────────────────────────────
    # NETWORK — T1016
    # ─────────────────────────────────────────────
    "network": [
        "netstat -tuln",                     # ports en écoute
        "netstat -antp",                     # toutes connexions + PID
        "ss -tuln",                          # ports en écoute (moderne)
        "ss -antp",                          # toutes connexions
        "ip addr",                           # interfaces réseau
        "ip route",                          # table de routage
        "cat /etc/hosts",                   # fichier hosts
        "cat /etc/resolv.conf",             # DNS config
        "arp -a",                            # table ARP
        "iptables -L",                       # règles firewall
        "nft list ruleset",                  # règles NFTables
    ],

    # ─────────────────────────────────────────────
    # PROCESSES — T1057
    # ─────────────────────────────────────────────
    "processes": [
        "ps aux",                            # tous les processus
        "ps aux --forest",                  # arbre des processus
        "top -bn1",                          # snapshot top
        "pstree",                            # arbre processus
        "lsof -i",                           # fichiers réseau ouverts
        "lsof -i :22",                       # qui utilise le port 22
    ],

    # ─────────────────────────────────────────────
    # CREDENTIALS — T1552
    # ─────────────────────────────────────────────
    "credentials": [
        "cat /etc/shadow",                  # hashes passwords (root only)
        "cat ~/.bash_history",              # historique bash
        "cat ~/.zsh_history",               # historique zsh
        "cat ~/.ssh/id_rsa",                # clé privée SSH
        "cat ~/.ssh/authorized_keys",       # clés autorisées
        "env",                               # variables environnement
        "printenv",                          # variables environnement
        "cat ~/.aws/credentials",           # credentials AWS
        "find / -name '*.env' 2>/dev/null", # fichiers .env
        "find / -name 'config.php' 2>/dev/null", # configs PHP
    ],

    # ─────────────────────────────────────────────
    # FILES — T1005
    # ─────────────────────────────────────────────
    "files": [
        "ls -la /home",                     # dossiers home
        "ls -la /root",                     # dossier root
        "ls -la /tmp",                      # dossier tmp
        "ls -la /var/www",                  # serveur web
        "ls -la /etc/cron.d",              # crons système
        "crontab -l",                        # crons user actuel
        "cat /etc/crontab",                 # crons système
        "find / -perm -4000 2>/dev/null",  # binaires SUID
        "find / -perm -2000 2>/dev/null",  # binaires SGID
        "find / -writable 2>/dev/null",    # fichiers writables
    ],

    # ─────────────────────────────────────────────
    # SERVICES — T1518
    # ─────────────────────────────────────────────
    "services": [
        "systemctl list-units --type=service --state=running", # services actifs
        "systemctl list-unit-files",        # tous les services
        "service --status-all",             # services (ancien style)
        "cat /etc/apache2/apache2.conf",   # config Apache
        "cat /etc/nginx/nginx.conf",       # config Nginx
        "mysql -V",                          # version MySQL
        "php -v",                            # version PHP
        "python3 --version",                # version Python
    ],

    # ─────────────────────────────────────────────
    # HARDWARE — T1082
    # ─────────────────────────────────────────────
    "hardware": [
        "nproc",                             # nombre de CPUs
        "cat /proc/cpuinfo",                # info CPU détaillée
        "free -h",                           # RAM disponible
        "df -h",                             # espace disque
        "lsblk",                             # disques
        "lspci",                             # périphériques PCI
        "lsusb",                             # périphériques USB
    ],

    # ─────────────────────────────────────────────
    # LOGS — T1070.002
    # ─────────────────────────────────────────────
    "logs": [
        "cat /var/log/auth.log",            # logs authentification
        "cat /var/log/syslog",              # logs système
        "cat /var/log/apache2/access.log", # logs Apache
        "cat /var/log/nginx/access.log",   # logs Nginx
        "journalctl -n 100",                # 100 dernières lignes journal
        "dmesg | tail -50",                 # logs kernel
    ],
}

# Flat list pour usage direct
ALL_COMMANDS = [cmd for cmds in DEFAULT_COMMANDS.values() for cmd in cmds]

# Commandes rapides pour recon initiale
QUICK_RECON = [
    "whoami", "id", "uname -a", "hostname -I",
    "cat /etc/os-release", "ps aux", "netstat -tuln",
    "cat /etc/passwd", "sudo -l", "env", "cat /etc/shadow",
]