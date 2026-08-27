#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 10:23:45 2026

@author: hounsousamuel
"""

from modules_utils.safe_subprocess import CommandPolicy

SERVER_ALLOWED_COMMANDS: dict[str, CommandPolicy] = {
    "cat":  CommandPolicy(),
    "tail": CommandPolicy(forbidden_flags={"-f", "--follow"}),  # -f bloquerait le process indéfiniment
    "head": CommandPolicy(),
    "grep": CommandPolicy(),
    "wc":   CommandPolicy(),
    "ls":   CommandPolicy(),
    "stat": CommandPolicy(),
    "df":   CommandPolicy(),
    "du":   CommandPolicy(),
    "ps":   CommandPolicy(),
    "uptime": CommandPolicy(),
    "whoami": CommandPolicy(),
    # systemctl : lecture seule uniquement — status/is-active/is-enabled/list-units.
    # Toute action de modification (restart/stop/start/enable/disable/mask)
    # doit être un tool séparé avec sa propre politique de confirmation
    # forcée, jamais atteignable via ce chemin générique.
    "systemctl": CommandPolicy(
        subcommands={"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files"}
    ),
    "ss":     CommandPolicy(),  # ports en écoute / connexions — lecture seule par nature
    "who":    CommandPolicy(),
    "last":   CommandPolicy(forbidden_flags={"-f", "--follow"}),
    "lsblk":  CommandPolicy(),
    # ip a un mode "netns exec" qui permet d'exécuter n'importe quoi dans un
    # namespace réseau — danger équivalent à un shell arbitraire si on
    # l'autorisait. On restreint donc aux sous-commandes purement lecture.
    "ip": CommandPolicy(subcommands={"addr", "route", "link"}),
}