#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tools CrewAI pour l'agent IDS/IPS ShieldAI.
Basé sur le vrai code : AnomalyDetector, AnomalyScorer, React
Auteur: HOUNSOU Samuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import json
import asyncio
import time
from datetime import datetime
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ids_ips_ia.detection.detection_module import AnomalyDetector
from ids_ips_ia.main.orchestrator import IDS_IPS

_detector: AnomalyDetector = None
_IDS_IPS: IDS_IPS = None

def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        raise RuntimeError("AnomalyDetector non initialisé. Appelle set_detector_instance() au démarrage.")
    return _detector

def set_detector_instance(instance: AnomalyDetector):
    global _IDS_IPS
    _IDS_IPS = instance

def get_ids_ids() -> IDS_IPS:
    global _detector
    if _detector is None:
        raise RuntimeError("AnomalyDetector non initialisé. Appelle set_detector_instance() au démarrage.")
    return _detector

def set_ids_ips_instance(instance: IDS_IPS):
    global _IDS_IPS
    _IDS_IPS = instance
    
# ============================================================================
# INPUT SCHEMAS
# ============================================================================

class GetBlockedIpsInput(BaseModel):
    limit: int = Field(
        default=50,
        description="Nombre maximum d'IPs à retourner (défaut: 50)"
    )


class GetStatsInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class GetWhitelistInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


class GetIpInfoInput(BaseModel):
    ip: str = Field(
        description="L'adresse IP à inspecter. Exemple: '192.168.1.45'"
    )


class BlockIpInput(BaseModel):
    ip: str = Field(
        description="L'adresse IP à bloquer. Exemple: '192.168.1.45'"
    )
    rule: str = Field(
        default="drop",
        description="Règle NFTables: 'drop' (blocage total) | 'rate_limit' (limite connexions) | 'rate_limit_data' (limite bande passante)"
    )
    input: bool = Field(
        default=True,
        description="True = bloquer trafic entrant (attaquant externe), False = bloquer trafic sortant (insider threat)"
    )
    timeout: int = Field(
        default=3600,
        description="Durée du blocage en secondes (défaut: 3600 = 1h). 0 = utilise le timeout NFT par défaut."
    )
    unit: str = Field(
        default="s",
        description="Unité du timeout: 's' (secondes) | 'm' (minutes) | 'h' (heures)"
    )


class UnlockIpInput(BaseModel):
    ip: str = Field(
        description="L'adresse IP à débloquer."
    )
    rule: str = Field(
        default="drop",
        description="Règle utilisée lors du blocage: 'drop' | 'rate_limit' | 'rate_limit_data'"
    )
    input: bool = Field(
        default=True,
        description="True = trafic entrant, False = trafic sortant"
    )


class ManageWhitelistInput(BaseModel):
    ip: str = Field(
        description="L'adresse IP à ajouter ou retirer de la whitelist."
    )
    add: bool = Field(
        default=True,
        description="True = ajouter à la whitelist, False = retirer de la whitelist"
    )


class ChangeModeInput(BaseModel):
    mode: str = Field(
        description="Mode de fonctionnement: 'ids' (détection seule) | 'ips' (détection + blocage automatique)"
    )


class GeolocateIpInput(BaseModel):
    ip: str = Field(
        description="L'adresse IP à géolocaliser."
    )


class ClearSetsInput(BaseModel):
    placeholder: str = Field(default="", description="Paramètre factice")


# ============================================================================
# TOOL 1: GET BLOCKED IPS
# ============================================================================

class GetBlockedIps(BaseTool):
    name: str = "get_blocked_ips"
    description: str = """
Retourne la liste des IPs actuellement bloquées avec leurs données complètes.

Utilise quand: tu veux auditer les IPs bloquées, vérifier si une IP est déjà bloquée,
ou avoir un aperçu des menaces actives.

RETOUR (dict JSON) :
{
    "total": int,
    "blocked": {
        "ip_address": {
            "ip": str,
            "rule": str,            // "drop" | "rate_limit" | "rate_limit_data"
            "set_name": str,        // Nom du set NFTables
            "duration": int|null,   // Durée en secondes
            "input": bool           // True = entrant, False = sortant
        }
    }
}

Ne pas utiliser pour: obtenir le score ou l'historique d'anomalies d'une IP (utilise get_ip_info).
"""
    args_schema: type[BaseModel] = GetBlockedIpsInput

    def _run(self, limit: int = 50):
        detector = get_detector()
        blocked = detector.React.blocked
        items = list(blocked.items())[:limit]
        return {
            "total": len(blocked),
            "blocked": dict(items)
        }

    async def _arun(self, limit: int = 50):
        return self._run(limit)


# ============================================================================
# TOOL 2: GET IP INFO
# ============================================================================

class GetIpInfo(BaseTool):
    name: str = "get_ip_info"
    description: str = """
Retourne toutes les informations connues sur une IP spécifique.
Score d'anomalie, historique des blocages, géolocalisation, décision actuelle.

Utilise quand: tu analyses une IP suspecte spécifique avant de décider d'une action.

RETOUR (dict JSON) :
{
    "ip": str,
    "score": float,                 // Score de dangerosité (0-300)
    "anomaly_count": int,           // Nombre d'anomalies détectées
    "blocked_count": int,           // Nombre de fois bloquée
    "geoloc": str,                  // Code pays (ex: "RU", "CN")
    "last_update": str,             // Dernière mise à jour
    "fisrt_seen": str,              // Première détection
    "resolution": str|null,         // Nom de domaine résolu
    "input": bool,                  // Direction du trafic
    "port": int|null,               // Port destination
    "decision": {
        "level": str,               // "log_only" | "rate_limit" | "block_temp" | "block_perm"
        "action": str,
        "duration": int|null,
        "score": float
    }
}

ou {"found": false, "ip": str} si IP inconnue.
"""
    args_schema: type[BaseModel] = GetIpInfoInput

    def _run(self, ip: str):
        detector = get_detector()
        ip_data = detector.AnomalyScorer.ip_data.get(ip)
        if ip_data is None:
            return {"found": False, "ip": ip}
        return {"found": True, **ip_data}

    async def _arun(self, ip: str):
        return self._run(ip)


# ============================================================================
# TOOL 3: GET ALL IPS SCORES
# ============================================================================

class GetAllIpsScores(BaseTool):
    name: str = "get_all_ips_scores"
    description: str = """
Retourne le scoring complet de toutes les IPs surveillées.
Équivalent de la liste principale du dashboard IDS.

Utilise quand: tu veux un aperçu global de toutes les menaces détectées,
ou identifier les IPs avec les scores les plus élevés.

RETOUR (dict JSON) :
{
    "total": int,
    "ips": {
        "ip_address": { ...données complètes par IP... }
    }
}
"""
    args_schema: type[BaseModel] = GetStatsInput

    def _run(self, *args, **kwargs):
        detector = get_detector()
        data = detector.AnomalyScorer.get_list_blocked_ip()
        return {
            "total": len(data),
            "ips": data
        }

    async def _arun(self, *args, **kwargs):
        return self._run()


# ============================================================================
# TOOL 4: GET WHITELIST
# ============================================================================

class GetWhitelist(BaseTool):
    name: str = "get_whitelist"
    description: str = """
Retourne la liste des IPs en whitelist (jamais bloquées par l'IPS).

Utilise quand: tu veux vérifier si une IP est protégée avant de la bloquer,
ou auditer les IPs de confiance.

RETOUR (dict JSON) :
{
    "total": int,
    "whitelist": list[str]      // Liste des IPs/CIDRs whitelistées
}
"""
    args_schema: type[BaseModel] = GetWhitelistInput

    def _run(self, *args, **kwargs):
        detector = get_detector()
        whitelist = detector.React.whitelist
        return {
            "total": len(whitelist),
            "whitelist": whitelist
        }

    async def _arun(self, *args, **kwargs):
        return self._run()


# ============================================================================
# TOOL 5: GET MODE
# ============================================================================

class GetMode(BaseTool):
    name: str = "get_mode"
    description: str = """
Retourne le mode de fonctionnement actuel de l'IDS/IPS.

RETOUR (dict JSON) :
{
    "mode": "ids" | "ips",
    "description": str      // Explication du mode actif
}

ids = détection seule, aucun blocage automatique.
ips = détection + blocage automatique selon les scores.
"""
    args_schema: type[BaseModel] = GetStatsInput

    def _run(self, *args, **kwargs):
        detector = get_detector()
        mode = detector.mode
        return {
            "mode": mode,
            "description": (
                "Mode IDS : surveillance uniquement, aucun blocage automatique."
                if mode == "ids" else
                "Mode IPS : détection + blocage automatique selon les scores de dangerosité."
            )
        }

    async def _arun(self, *args, **kwargs):
        return self._run()


# ============================================================================
# TOOL 6: BLOCK IP
# ============================================================================

class BlockIp(BaseTool):
    name: str = "block_ip"
    description: str = """
Bloque une adresse IP via NFTables. Action effective immédiatement.

IMPORTANT: Vérifie d'abord avec get_whitelist que l'IP n'est pas whitelistée.
Utilise get_ip_info pour évaluer le score avant de bloquer.

Règles disponibles:
- "drop": blocage total (score >= 180)
- "rate_limit": limite les connexions (score 125-180)
- "rate_limit_data": limite la bande passante (score 75-125)

RETOUR (dict JSON) :
{
    "status": "success" | "error" | "whitelisted" | "invalid_ip",
    "ip": str,
    "message": str,
    "timestamp": str
}

Ne pas utiliser pour: les IPs en whitelist ou les IPs locales.
"""
    args_schema: type[BaseModel] = BlockIpInput

    def _run(
        self, ip: str, rule: str = "drop",
        input: bool = True, timeout: int = 3600, unit: str = "s"
    ):
        detector = get_detector()

        # Vérification whitelist
        if ip in detector.React.whitelist:
            return {
                "status": "whitelisted",
                "ip": ip,
                "message": f"IP {ip} est en whitelist — blocage refusé",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

        # Validation IP
        if detector.React.get_ip_type(ip) == "error":
            return {
                "status": "invalid_ip",
                "ip": ip,
                "message": f"IP {ip} invalide",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

        try:
            success = detector.React.block(
                ip=ip,
                rule=rule,
                input=input,
                timeout=timeout if timeout > 0 else None,
                unit=unit
            )
            return {
                "status": "success" if success else "error",
                "ip": ip,
                "message": f"IP {ip} {'bloquée' if success else 'blocage échoué'} (règle: {rule}, direction: {'entrant' if input else 'sortant'})",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }
        except Exception as e:
            return {
                "status": "error",
                "ip": ip,
                "message": str(e),
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

    async def _arun(self, ip: str, rule: str = "drop", input: bool = True, timeout: int = 3600, unit: str = "s"):
        return self._run(ip, rule, input, timeout, unit)


# ============================================================================
# TOOL 7: UNLOCK IP
# ============================================================================

class UnlockIp(BaseTool):
    name: str = "unlock_ip"
    description: str = """
Débloque une IP et supprime son score d'anomalie (reset complet).

Utilise quand: faux positif confirmé, demande admin, ou IP réhabilitée.

RETOUR (dict JSON) :
{
    "status": "success" | "error" | "not_found",
    "ip": str,
    "message": str,
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = UnlockIpInput

    def _run(self, ip: str, rule: str = "drop", input: bool = True):
        detector = get_detector()
        try:
            success = detector.React.unlock(ip=ip, rule=rule, input=input)
            already_unlocked = not success and ip not in detector.React.blocked
            # Reset du score dans AnomalyScorer comme dans l'API /unlock
            if success or already_unlocked:
                if ip in detector.AnomalyScorer.ip_data:
                    detector.AnomalyScorer.ip_data.pop(ip)

            return {
                "status": "success" if success else "error",
                "ip": ip,
                "message": f"IP {ip} {'débloquée et score réinitialisé' if success else 'déblocage échoué (soit IP inconnue, soit non bloqué)'}",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }
        except Exception as e:
            return {
                "status": "error",
                "ip": ip,
                "message": str(e),
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

    async def _arun(self, ip: str, rule: str = "drop", input: bool = True):
        return self._run(ip, rule, input)


# ============================================================================
# TOOL 8: MANAGE WHITELIST
# ============================================================================

class ManageWhitelist(BaseTool):
    name: str = "manage_whitelist"
    description: str = """
Ajoute ou retire une IP de la whitelist NFTables.

Utilise quand: 
- add=True : IP interne critique (serveur, passerelle) à ne jamais bloquer
- add=False : IP whitelistée devenue suspecte à surveiller

RETOUR (dict JSON) :
{
    "status": "success" | "error",
    "ip": str,
    "action": "added" | "removed",
    "message": str,
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = ManageWhitelistInput

    def _run(self, ip: str, add: bool = True):
        detector = get_detector()
        try:
            if add:
                success = detector.React.add_to_whitelist(ip)
                action = "added"
                msg = f"IP {ip} ajoutée à la whitelist"
            else:
                success = detector.React.remove_from_whitelist(ip)
                action = "removed"
                msg = f"IP {ip} retirée de la whitelist"

            return {
                "status": "success" if success else "error",
                "ip": ip,
                "action": action,
                "message": msg if success else f"Opération échouée sur {ip}",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }
        except Exception as e:
            return {
                "status": "error",
                "ip": ip,
                "action": "added" if add else "removed",
                "message": str(e),
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

    async def _arun(self, ip: str, add: bool = True):
        return self._run(ip, add)


# ============================================================================
# TOOL 9: CHANGE MODE
# ============================================================================

class ChangeMode(BaseTool):
    name: str = "change_mode"
    description: str = """
Change le mode de fonctionnement de l'IDS/IPS à chaud, sans redémarrage.

Utilise quand:
- Passer en "ips" : activer le blocage automatique (réponse active)
- Passer en "ids" : désactiver le blocage automatique (surveillance seule)

RETOUR (dict JSON) :
{
    "status": "success" | "error",
    "mode": str,                // Nouveau mode actif
    "message": str,
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = ChangeModeInput

    def _run(self, mode: str):
        mode = mode.lower().strip()
        if mode not in ("ids", "ips"):
            return {
                "status": "error",
                "mode": mode,
                "message": "Mode invalide. Valeurs acceptées: 'ids' | 'ips'",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

        success = get_ids_ids().change_mode(mode)
        return {
            "status": "success" if success else "error",
            "mode": mode,
            "message": f"Mode changé vers '{mode}'" if success else f"Échec changement vers '{mode}'",
            "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        }

    async def _arun(self, mode: str):
        return self._run(mode)


# ============================================================================
# TOOL 10: GEOLOCATE IP
# ============================================================================

class GeolocateIp(BaseTool):
    name: str = "geolocate_ip"
    description: str = """
Géolocalise une adresse IP et indique si elle est suspecte (pays à risque).

Utilise quand: tu veux évaluer le contexte géographique d'une IP avant de décider
d'une action, ou enrichir une alerte.

RETOUR (dict JSON) :
{
    "ip": str,
    "country_code": str,        // Code ISO pays (ex: "RU", "CN", "FR")
    "is_suspicious": bool,      // True si pays à risque (RU, CN, KP, IR)
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = GeolocateIpInput

    def _run(self, ip: str):
        detector = get_detector()
        country = detector.AnomalyScorer.GeoLocator.locate(ip)
        is_suspicious = detector.AnomalyScorer.GeoLocator.is_suspicious(ip)
        return {
            "ip": ip,
            "country_code": country,
            "is_suspicious": is_suspicious,
            "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        }

    async def _arun(self, ip: str):
        return self._run(ip)


# ============================================================================
# TOOL 11: CLEAR NFT SETS
# ============================================================================

class ClearNftSets(BaseTool):
    name: str = "clear_nft_sets"
    description: str = """
Vide tous les sets NFTables — débloque toutes les IPs bloquées d'un coup.
ACTION CRITIQUE — utilise uniquement sur demande explicite de l'admin
ou en cas de faux positifs massifs.

RETOUR (dict JSON) :
{
    "status": "success" | "error",
    "message": str,
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = ClearSetsInput

    def _run(self, *args, **kwargs):
        detector = get_detector()
        try:
            success = detector.React.clear_sets()
            return {
                "status": "success" if success else "error",
                "message": "Tous les sets NFTables vidés" if success else "Échec vidage des sets",
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
            }

    async def _arun(self, *args, **kwargs):
        return self._run()


# ============================================================================
# TOOL 12: REDIRECT TO HONEYPOT (placeholder)
# ============================================================================

class RedirectToHoneypot(BaseTool):
    name: str = "redirect_to_honeypot"
    description: str = """
Redirige une IP suspecte vers le honeypot au lieu de la bloquer.
L'attaquant croit cibler le vrai système — on collecte ses actions.

Utilise quand: l'IP est suspecte mais pas encore confirmée comme malveillante,
ou quand on veut analyser les techniques d'un attaquant (APT, nouvelle méthode).

RETOUR (dict JSON) :
{
    "status": "success" | "honeypot_unavailable" | "error",
    "ip": str,
    "message": str,
    "timestamp": str
}
"""
    args_schema: type[BaseModel] = GeolocateIpInput  # même schema — juste ip

    def _run(self, ip: str):
        # Le module honeypot n'est pas encore buildé
        # Quand je build le honeypot, je vais implémentes la logique ici
        return {
            "status": "honeypot_unavailable",
            "ip": ip,
            "message": "Module honeypot pas encore disponible. Utilise block_ip en fallback.",
            "timestamp": datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
        }

    async def _arun(self, ip: str):
        return self._run(ip)


# ============================================================================
# ALL TOOLS
# ============================================================================

ALL_IDS_TOOLS = [
    GetBlockedIps(),
    GetIpInfo(),
    GetAllIpsScores(),
    GetWhitelist(),
    GetMode(),
    BlockIp(),
    UnlockIp(),
    ManageWhitelist(),
    ChangeMode(),
    GeolocateIp(),
    ClearNftSets(),
    RedirectToHoneypot(),
]