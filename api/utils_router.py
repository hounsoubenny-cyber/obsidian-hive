#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 30 11:22:38 2026

@author: hounsousamuel
"""

import os
import socket
import asyncio
from fastapi import APIRouter, Request, status, Query
from modules_utils.limiter import limiter
from obsidian_hive.api.ap_config import LIMITE

router = APIRouter()


@limiter.limit(f"{LIMITE + 10}/minute")
@router.get("/path_exists")
async def _path_exists(request: Request, path: str = Query(...)):
    """
    Vérifie si un chemin existe sur le système de fichiers.

    Args:
        request (Request): La requête FastAPI.
        path (str): Chemin à vérifier (paramètre de requête).

    Returns:
        dict: {"exists": bool} - True si le chemin existe, False sinon.
    """
    return {"exists": os.path.exists(path) if path else False}


@limiter.limit(f"{LIMITE + 10}/minute")
@router.get("/check_port")
async def _check_port(
    request: Request,
    host: str = Query(..., description="IP ou nom d'hôte"),
    port: int = Query(..., ge=1, le=65535, description="Port à vérifier"),
    timeout: float = Query(2.0, ge=0.1, description="Timeout en secondes")
):
    """
    Vérifie si un port est accessible sur une IP ou un nom d'hôte.
    
    Args:
        request (Request): La requête FastAPI.
        host (str): IP ou nom d'hôte à vérifier.
        port (int): Port à vérifier (1-65535).
        timeout (float): Timeout en secondes (>= 0.1).

    Returns:
        dict: Résultat de la vérification avec :
            - available: True si le port est libre (connexion refusée)
            - available: False si le port est occupé (connexion réussie)
            - available: None si timeout ou erreur
            - reachable: True si l'hôte est résolu
            - message: Message descriptif
    """
    result = {
        "host": host,
        "port": port,
        "available": None,
        "reachable": None,
        "message": "",
        "timeout": timeout
    }
    
    def check():
        try:
            # Résoudre le nom d'hôte
            ip = socket.gethostbyname(host)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()
            
            # Connexion réussie → port occupé
            return ip, "occupied"
            
        except socket.gaierror:
            return None, "dns_error"
        
        except ConnectionRefusedError:
            # Connexion refusée → port libre
            return ip, "available"
        except socket.timeout:
            return ip, "timeout"
        except Exception as e:
            return ip, f"error: {str(e)}"
    
    ip, status_ = await asyncio.to_thread(check)
    
    if ip:
        result["resolved_ip"] = ip
        result["reachable"] = True
        
    else:
        result["reachable"] = False
    
    if status_ == "occupied":
        result["available"] = False
        result["message"] = f"Port {port} OCCUPÉ sur {host}"
        
    elif status_ == "available":
        result["available"] = True
        result["message"] = f"Port {port} LIBRE sur {host}"
        
    elif status_ == "timeout":
        result["message"] = f"Timeout sur {host}:{port} (IP: {ip})"
        
    elif status_ == "dns_error":
        result["message"] = f"Nom d'hôte irrésolu: {host}"
        
    else:
        result["message"] = status
    
    return result