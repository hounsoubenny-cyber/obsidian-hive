#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 18 21:26:32 2026

@author: hounsousamuel
"""

"""
services_manager_config.py

Détection des process "GUI desktop" à exclure de la capture de services
(ServiceManager.capture_services) — ce ne sont jamais des services réseau
pertinents à répliquer dans un container cible.

CHANGEMENTS vs version précédente :
  - GUI_NAMES devient "strict" : match exact, exclusion garantie même si
    le process a des ports ouverts (cas des navigateurs avec ports de
    debug locaux — ce n'est toujours pas un "service" pertinent).
  - Ajout de GUI_NAME_PREFIXES / GUI_NAME_SUBSTRINGS pour couvrir des
    familles entières (plasma-*, kde-*, gnome-*, xdg-desktop-portal-*)
    sans avoir à lister chaque variante individuellement.
  - exe peut être None pour beaucoup de process (observé sur dbus-broker,
    avahi-daemon, php-fpm...) — fallback sur cmdline[0] pour le matching
    de préfixe quand exe est vide.
  - GUI_ENV_SIGNALS élargi : FLATPAK_ID et SNAP en plus de
    DISPLAY/WAYLAND_DISPLAY/XDG_CURRENT_DESKTOP — signaux fiables
    d'application desktop sandboxée.
  - Comparaison de noms insensible à la casse/espaces superflus.
"""

GUI_PREFIXES = (
    '/usr/lib64/firefox/',
    '/usr/lib/firefox/',
    '/usr/libexec/',
    '/usr/lib64/speech-dispatcher',
    '/usr/local/share/flatpak/',
    '/var/lib/flatpak/',
    '/usr/lib64/thunderbird/',
    '/usr/lib/thunderbird/',
)

# Match exact — exclusion garantie, même si le process a des ports ouverts.
# Réservé aux vrais binaires desktop dont on est certain qu'ils ne sont
# jamais un "service" pertinent pour la simulation.
GUI_NAMES = {
    'firefox', 'plasmashell', 'kwin_wayland', 'kded6', 'kwalletd6',
    'kaccess', 'dolphin', 'plasma-emojier', 'xwaylandvideobridge',
    'QtWebEngineProcess', 'gnome-terminal-server', 'xembedsniproxy',
    'gmenudbusmenuproxy', 'xdg-desktop-portal-kde', 'xdg-desktop-portal-gtk',
    'obexd', 'ksystemstats', 'kactivitymanagerd', 'knighttimed',
    'at-spi2-registryd', 'dconf-service', 'ksecretd', 'kdeconnectd',
    'DiscoverNotifier', 'abrt-applet', 'abrt-dbus', 'xsettingsd',
    'speech-dispatcher', 'sd_espeak-ng', 'sd_dummy', 'org_kde_powerdevil',
    'polkit-kde-authentication-agent-1', 'kunifiedpush-distributor',
    'gvfsd-metadata', 'konsole', 'nautilus', 'gnome-shell', 'mutter',
    'thunderbird', 'gvfsd', 'gvfs-udisks2-volume-monitor', 'tracker-miner-fs',
}

# Préfixes de noms couvrant des familles entières sans énumération exhaustive.
GUI_NAME_PREFIXES = (
    'plasma-', 'kde-', 'kwin', 'kwalletd', 'ksecretd', 'kactivitymanagerd',
    'xdg-desktop-portal-', 'gnome-', 'gsd-', 'evolution-',
)

# Sous-chaînes complémentaires pour les noms tronqués/composés (ex: cmdline
# multi-mots comme "gnome-terminal-server").
GUI_NAME_SUBSTRINGS = (
    'desktop-portal', 'session-manager', 'notification-daemon',
)

GUI_ENV_SIGNALS = {
    'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_CURRENT_DESKTOP',
    'FLATPAK_ID', 'SNAP',
}


def _matches_gui_name(name: str) -> bool:
    n = (name or '').strip().lower()
    if not n:
        return False
    if n in {g.lower() for g in GUI_NAMES}:
        return True
    if any(n.startswith(p.lower()) for p in GUI_NAME_PREFIXES):
        return True
    if any(s in n for s in GUI_NAME_SUBSTRINGS):
        return True
    return False


def _effective_exe_path(entry: dict) -> str:
    """exe si présent, sinon fallback sur cmdline[0] (souvent équivalent,
    notamment pour les process où psutil ne peut pas résoudre le symlink
    /proc/{pid}/exe — permissions, process zombie, etc.)."""
    exe = entry.get('exe') or ''
    if exe:
        return exe
    cmdline = entry.get('cmdline') or []
    return cmdline[0] if cmdline else ''


def is_gui_process(entry: dict) -> bool:
    """
    True si le process est un composant desktop/GUI à exclure de la
    capture de services — jamais un service réseau pertinent à répliquer.
    """
    if _matches_gui_name(entry.get('name', '')):
        return True

    exe = _effective_exe_path(entry)
    if any(exe.startswith(p) for p in GUI_PREFIXES):
        return True

    environ = entry.get('environ') or {}
    has_gui_env = any(k in environ for k in GUI_ENV_SIGNALS)
    has_ports = bool(entry.get('ports'))

    # Un process lancé depuis une session desktop (DISPLAY/WAYLAND_DISPLAY
    # présents) mais SANS port ouvert est presque certainement un utilitaire
    # GUI, pas un service réseau — on l'exclut. S'il a un port, on le garde
    # (ex: un serveur de test lancé depuis un terminal desktop reste un
    # vrai candidat service).
    if has_gui_env and not has_ports:
        return True

    return False