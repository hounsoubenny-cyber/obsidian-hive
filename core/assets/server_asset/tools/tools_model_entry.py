#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 09:56:56 2026

@author: hounsousamuel
"""

from pydantic import BaseModel, Field


class GetSystemInfoEntry(BaseModel):
    """Aucun paramètre — récupère juste l'état de la machine hôte."""
    pass


class CheckServiceStatusEntry(BaseModel):
    service_name: str = Field(description="Nom du service systemd à vérifier, ex: 'nginx', 'sshd'")


class ReadLogEntry(BaseModel):
    path: str = Field(description="Chemin absolu du fichier à lire, ex: '/var/log/nginx/error.log'")
    lines: int | None = Field(default=None, description="Nombre de dernières lignes à retourner")

class ListDirectoryEntry(BaseModel):
    path: str = Field(description="Chemin absolu du répertoire à lister, ex: '/var/log'")


class DiskUsageEntry(BaseModel):
    path: str = Field(default="/", description="Point de montage ou chemin à inspecter")


class ListProcessesEntry(BaseModel):
    """Aucun paramètre — liste tous les processus en cours (ps aux)."""
    pass


class SearchInFileEntry(BaseModel):
    path: str = Field(description="Chemin absolu du fichier à parcourir, ex: '/var/log/auth.log'")
    pattern: str = Field(description="Motif à rechercher (grep -n)")


class CheckOpenPortsEntry(BaseModel):
    """Aucun paramètre — liste les ports en écoute et connexions actives (ss -tulnp)."""
    pass


class ListLoggedInUsersEntry(BaseModel):
    """Aucun paramètre — liste les utilisateurs actuellement connectés (who)."""
    pass


class LastLoginsEntry(BaseModel):
    limit: int = Field(default=20, ge=1, le=200, description="Nombre d'entrées récentes à retourner")


class NetworkInterfacesEntry(BaseModel):
    """Aucun paramètre — liste les interfaces réseau et leurs adresses (ip addr)."""
    pass


class ListBlockDevicesEntry(BaseModel):
    """Aucun paramètre — liste les disques/partitions (lsblk)."""
    pass