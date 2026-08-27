#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tools pour Agent IA - Détection de phishing.
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
from anti_phishing_ia.main_phish import get_ap_instance, HISTORY_FILE, clear
from anti_phishing_ia.phishing_utils.mail_extractor_utils import extract_urls
from modules_utils.loop_utils import _run_async
# ============================================================================
# INPUT SCHEMAS
# ============================================================================

class AnalyzeUrlInput(BaseModel):
    url: str = Field(
        description="L'URL à analyser pour détecter du phishing. Exemple: 'https://paypal-verify.tk/login'"
    )
    check_blacklist: bool = Field(
        default=False,
        description="Active la vérification auprès des blacklists externes (PhishDestroy). Utile pour les URLs très suspectes."
    )
    explain: bool = Field(
        default=False,
        description="Retourne les détails complets de l'analyse (flags, typosquatting, âge domaine, etc.)"
    )
    check_right_click: bool = Field(
        default=False,
        description="Vérifie si la page web désactive le clic droit (technique anti-inspection souvent utilisée par les sites de phishing)"
    )


class AnalyzeEmailInput(BaseModel):
    email_content: str = Field(
        default=None,
        description="Le contenu brut de l'email à analyser (texte complet de l'email)"
    )
    email_file: str = Field(
        default=None,
        description="Chemin vers un fichier .eml à analyser. Alternative à email_content."
    )
    check_blacklist: bool = Field(
        default=False,
        description="Active la vérification des URLs extraites auprès des blacklists externes"
    )


class ExtractUrlsInput(BaseModel):
    text: str = Field(
        description="Le texte (email, message, page web) dans lequel extraire les URLs"
    )


class GetPhishingStatsInput(BaseModel):
    limit: int = Field(
        default=10,
        description="Nombre maximum d'entrées d'historique à retourner (défaut: 10)"
    )

class AnalyzeUrlIAOnlyInput(BaseModel):
    url: str = Field(
        description="L'URL à analyser avec le modèle IA uniquement"
    )
    
class AnalyzeUrlPassiveOnlyInput(BaseModel):
    url: str = Field(
        description="L'URL à analyser avec l'analyse passive uniquement"
    )
    check_blacklist: bool = Field(
        default=False,
        description="Active la vérification des blacklists externes"
    )
    check_right_click: bool = Field(
        default=False,
        description="Vérifie si le clic droit est désactivé"
    )
    explain: bool = Field(
        default=False,
        description="Retourne les détails complets de l'analyse (flags, typosquatting, âge domaine, etc.)"
    )

class CheckUrlBlacklistInput(BaseModel):
    url: str = Field(
        description="L'URL à vérifier dans les blacklists externes"
    )

class ClearCacheInput(BaseModel):
    placeholder: str = Field(
        default="",
        description="Paramètre factice (le tool n'a pas de paramètres)"
    )

class AnalyzeUrlBatchInput(BaseModel):
    urls: list[str] = Field(
        description="Liste d'URLs à analyser en parallèle. Exemple: ['https://paypal.com', 'https://fake-bank.tk']"
    )
    check_blacklist: bool = Field(
        default=False,
        description="Active la vérification blacklist pour chaque URL"
    )
    explain: bool = Field(
        default=False,
        description="Retourne les détails complets pour chaque URL"
    )

class GetRecentThreatsInput(BaseModel):
    limit: int = Field(
        default=10,
        description="Nombre maximum de menaces récentes à retourner (défaut: 10)"
    )
    include_suspicious: bool = Field(
        default=True,
        description="Inclure les URLs/emails suspects en plus des phishing confirmés"
    )


class ReloadModelInput(BaseModel):
    what: str = Field(
        default="all",
        description="Quel modèle recharger: 'all' (les deux), 'phishing' (modèle URL), 'mail' (modèle email)"
    )
    
class AnalyzeEmailBatchInput(BaseModel):
    emails: list[str] = Field(
        default=None,
        description="Liste d'emails (contenu texte brut) à analyser en parallèle"
    )
    email_files: list[str] = Field(
        default=None,
        description="Liste de chemins vers des fichiers .eml à analyser en parallèle"
    )
    check_blacklist: bool = Field(
        default=False,
        description="Active la vérification des URLs extraites auprès des blacklists externes"
    )
    
# ============================================================================
# TOOL 1: ANALYSE URL
# ============================================================================

class AnalyzeUrl(BaseTool):
    name: str = "analyze_url"
    description: str = """
Analyse une URL pour détecter si elle est frauduleuse (phishing) ou légitime ou suspect (cas mitigée).

RETOUR (dict JSON) :
{
    "final_decision": str,      // "safe" | "suspicious" | "phishing"
    "confidence": float,        // Score de confiance (0.0 à 1.0)
    "source": str,              // Source: "whitelist" | "ia_prediction" | "passive_analyse" | "url_critique"
    "date": str,                // Date de l'analyse (format: DD/MM/YYYY à HH:MM:SS)
    "elapsed": float,           // Temps d'analyse en secondes
    "breakdown": {              // Détails (si explain=True)
        "ia_pred_proba": float,     // Probabilité donnée par l'IA (0-1)
        "ia_pred": str,             // Prédiction de l'IA ("safe" ou "phishing")
        "passive_analyze_prob": float,  // Score de risque passif (0-1)
        "passive_analyze_level": str    // Niveau: "CRITIQUE" | "ÉLEVÉ" | "MOYEN" | "FAIBLE" | "NÉGLIGEABLE"
    }
}

Exemple:
    URL phishing: "https://paypal-verify.tk/login"
    → {"final_decision": "phishing", "confidence": 0.86, "source": "ia_prediction"}

Utilise cet outil quand l'utilisateur fournit une URL ou demande si un site est sûr.
"""
    args_schema: type[BaseModel] = AnalyzeUrlInput
    description_updated: bool = True
    
    async def _arun(
        self,
        url: str,
        check_blacklist: bool = False,
        explain: bool = False,
        features_func=None,
        check_right_click: bool = False
    ):
        return await get_ap_instance().predict_url_async(
            url=url,
            check_blacklist=check_blacklist,
            check_right_click=check_right_click,
            explain=explain,
            features_func=features_func
        )
    
    def _run(
        self,
        url: str,
        check_blacklist: bool = False,
        explain: bool = False,
        features_func=None,
        check_right_click: bool = False
    ):
        return get_ap_instance().predict_url(
            url=url,
            check_blacklist=check_blacklist,
            check_right_click=check_right_click,
            explain=explain,
            features_func=features_func
        )


# ============================================================================
# TOOL 2: ANALYSE EMAIL
# ============================================================================

class AnalyzeEmail(BaseTool):
    name: str = "analyze_email"
    description: str = """
Analyse un email complet pour détecter une tentative de phishing.

INPUT:
    - Soit email_content: le texte brut de l'email
    - Soit email_file: le chemin vers un fichier .eml

RETOUR (dict JSON) :
{
    "final_decision": str,      // "safe" | "suspicious" | "phishing"
    "confidence": float,        // Score de confiance (0.0 à 1.0)
    "source": str,              // Source: "url_critique" | "bert_haut_confiance" | "headers_compromis" | "passive_eleve" | ...
    "sender": str,              // Expéditeur (From header)
    "subject": str,             // Sujet de l'email
    "nb_urls_total": int,       // Nombre total d'URLs trouvées dans l'email
    "nb_urls_phishing": int,    // Nombre d'URLs classées comme phishing
    "spf": str,                 // Statut SPF: "pass" | "fail" | "neutral" | "absent"
    "dkim": str,                // Statut DKIM: "present" | "absent"
    "date": str,                // Date de l'analyse (format: DD/MM/YYYY à HH:MM:SS)
    "elapsed": float,           // Temps d'analyse en secondes
    "breakdown": {              // Détails complets (toujours inclus)
        "bert_prob": {              // Probabilités du modèle BERT
            "phishing": float,
            "safe": float
        },
        "mail_passive_score": float,    // Score passif global (0-1)
        "ratio_urls_phishing": float,   // Proportion d'URLs classées phishing
        "max_url_score": float,         // Score maximum parmi toutes les URLs
        "header_risk": float,           // Score de risque des headers (SPF/DKIM/Reply-To)
        "urls_summary": [               // Liste détaillée des URLs analysées
            {
                "url": str,
                "decision": "safe" | "suspicious" | "phishing",
                "confidence": float
            }
        ]
    }
}

ou (dict JSON)
{
 "error": True,
 "message": "..."
 } Si erreur

Exemple d'email phishing:
    "final_decision": "phishing",
    "sender": "support@paypa1.tk",
    "nb_urls_phishing": 2,
    "spf": "fail",
    "dkim": "absent",
    "breakdown": {
        "bert_prob": {"phishing": 0.92, "safe": 0.08},
        "mail_passive_score": 0.78,
        "ratio_urls_phishing": 0.66
    }

Utilise cet outil quand l'utilisateur reçoit un email suspect et veut savoir s'il s'agit d'une arnaque.
"""
    args_schema: type[BaseModel] = AnalyzeEmailInput
    description_updated: bool = True
    
    def _get_email_content(self, email_content: str, email_file: str | None = None) -> str:
        """Récupère le contenu de l'email depuis le texte ou le fichier."""
        if email_file:
            if not os.path.exists(email_file):
                raise FileNotFoundError(f"Fichier non trouvé: {email_file}")
            with open(email_file, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        elif email_content:
            return email_content
        else:
            raise ValueError("Fournir soit email_content soit email_file")
    
    async def _arun(
        self,
        email_content: str = None,
        email_file: str = None,
        check_blacklist: bool = False
    ):
        try:
            content = self._get_email_content(email_content, email_file)
        except Exception as e:
            return {
                "error": True,
                "message": str(e)
            }
        ap = get_ap_instance()
        return await ap.predict_email_async(content, check_blacklist)
    
    def _run(
        self,
        email_content: str = None,
        email_file: str = None,
        check_blacklist: bool = False
    ):
        try:
            content = self._get_email_content(email_content, email_file)
        except Exception as e:
            return {
                "error": True,
                "message": str(e)
            }
        ap = get_ap_instance()
        return ap.predict_email(content, check_blacklist)


# ============================================================================
# TOOL 3: EXTRAIRE URLs
# ============================================================================

class ExtractUrls(BaseTool):
    name: str = "extract_urls"
    description: str = """
Extrait toutes les URLs (http://, https://, www.) d'un texte.

RETOUR (list[str]) :
    Liste des URLs uniques trouvées dans le texte, dédoublonnées.

Exemple:
    Input: "Cliquez ici: https://paypal-verify.tk et là http://fake-bank.com/login"
    Output: ["https://paypal-verify.tk", "http://fake-bank.com/login"]

Utilise cet outil pour prétraiter un message avant analyse.
"""
    args_schema: type[BaseModel] = ExtractUrlsInput
    description_updated: bool = True
    
    async def _arun(self, text: str):
        return self._run(text)
    
    def _run(self, text: str):
        return extract_urls(text, unique=True)


# ============================================================================
# TOOL 4: STATISTIQUES PHISHING
# ============================================================================

class GetPhishingStats(BaseTool):
    name: str = "get_phishing_stats"
    description: str = """
Récupère les statistiques des analyses récentes (URLs ET emails).

RETOUR (dict JSON) :
{
    "urls": {
        "total": int,           // Nombre total d'URLs analysées
        "safe": int,            // URLs classées "safe"
        "suspicious": int,      // URLs classées "suspicious"
        "phishing": int,        // URLs classées "phishing"
        "recent": [             // Dernières URLs (max 'limit')
            {
                "url": str,
                "final_decision": str,
                "confidence": float,
                "date": str
            }
        ]
    },
    "emails": {
        "total": int,           // Nombre total d'emails analysés
        "safe": int,            // Emails classés "safe"
        "suspicious": int,      // Emails classés "suspicious"
        "phishing": int,        // Emails classés "phishing"
        "recent": [             // Derniers emails (max 'limit')
            {
                "sender": str,
                "subject": str,
                "final_decision": str,
                "confidence": float,
                "date": str
            }
        ]
    }
}

Exemple:
    {
        "urls": {"total": 150, "phishing": 45, "safe": 95, ...},
        "emails": {"total": 50, "phishing": 20, "safe": 25, ...}
    }

Utilise cet outil pour donner un aperçu global des activités de détection.
"""
    args_schema: type[BaseModel] = GetPhishingStatsInput
    description_updated: bool = True
    
    def _get_email_stats(self, limit: int) -> dict:
        """Récupère les stats des emails en lisant le fichier JSON"""
        history_file = os.path.join(HISTORY_FILE, "history_mail.json")
        
        if not os.path.exists(history_file):
            return {'total': 0, 'safe': 0, 'suspicious': 0, 'phishing': 0, 'recent': []}
        
        with open(history_file, 'r', encoding='utf-8') as f:
            analyses = json.load(f)
        
        return {
            'total': len(analyses),
            'safe': sum(1 for a in analyses if a.get('final_decision') == 'safe'),
            'suspicious': sum(1 for a in analyses if a.get('final_decision') == 'suspicious'),
            'phishing': sum(1 for a in analyses if a.get('final_decision') == 'phishing'),
            'recent': [
                {
                    'sender': a.get('sender', 'N/A'),
                    'subject': a.get('subject', 'N/A')[:50],
                    'final_decision': a.get('final_decision', 'unknown'),
                    'confidence': a.get('confidence', 0),
                    'date': a.get('date', 'N/A')
                }
                for a in analyses[-limit:]
            ]
        }

    def _run(self, limit: int = 10):
        ap = get_ap_instance()
        history = ap.get_history("json")
        analyses = history.get('json', [])
        
        url_stats = {
            'total': len(analyses),
            'safe': sum(1 for a in analyses if a.get('final_decision') == 'safe'),
            'suspicious': sum(1 for a in analyses if a.get('final_decision') == 'suspicious'),
            'phishing': sum(1 for a in analyses if a.get('final_decision') == 'phishing'),
            'recent': [
                {
                    'url': a.get('url', 'N/A'),
                    'final_decision': a.get('final_decision', 'unknown'),
                    'confidence': a.get('confidence', 0),
                    'date': a.get('date', 'N/A')
                }
                for a in analyses[-limit:]
            ]
        }
        
        email_stats = self._get_email_stats(limit)
        
        return {
            "urls": url_stats,
            "emails": email_stats
        }
    
    async def _arun(self, limit: int = 10):
        return self._run(limit)


# ============================================================================
# TOOL 5: VIDER CACHE
# ============================================================================

class ClearCache(BaseTool):
    name: str = "clear_cache"
    description: str = """
Vide le cache des analyses.

RETOUR (dict JSON) :
{
    "status": str,              // "success" ou "error"
    "message": str              // Message de confirmation ou d'erreur
}

Exemple:
    {"status": "success", "message": "Cache vidé"}

Utile pour forcer une réanalyse d'URLs ou d'emails déjà vus.
"""
    description_updated: bool = True
    args_schema: type[BaseModel] = ClearCacheInput
    
    async def _arun(self, *args, **kwargs):
        return self._run()
    
    def _run(self, *args, **kwargs):
        clear()
        return {"status": "success", "message": "Cache vidé"}


# ============================================================================
# TOOL 6: ANALYSE IA SEULE
# ============================================================================

class AnalyzeUrlIAOnly(BaseTool):
    name: str = "analyze_url_ia_only"
    description: str = """
Analyse une URL en utilisant UNIQUEMENT le modèle d'IA (PhishingIA), sans l'analyse passive.

RETOUR (dict JSON) :
{
    "predict_proba": {          // Probabilités détaillées
        "safe": float,
        "phishing": float
    },
    "predict": {                // Prédiction
        "0": "safe" | "phishing"
    },
    "error": str                // En cas d'erreur
}

Utilise cet outil quand l'utilisateur veut une analyse rapide sans les heuristiques passives.
"""
    args_schema: type[BaseModel] = AnalyzeUrlIAOnlyInput
    description_updated: bool = True
    
    async def _arun(self, url: str):
        return await get_ap_instance().predict_with_ia_async(url)
    
    def _run(self, url: str):
        return get_ap_instance().predict_with_ia(url)


# ============================================================================
# TOOL 7: ANALYSE PASSIVE SEULE 
# ============================================================================

class AnalyzeUrlPassiveOnly(BaseTool):
    name: str = "analyze_url_passive_only"
    description: str = """
Analyse une URL en utilisant UNIQUEMENT l'analyse passive (18 critères), sans le modèle IA.

RETOUR (dict JSON) :
{
    "risk_level": str,          // "NÉGLIGEABLE" | "FAIBLE" | "MOYEN" | "ÉLEVÉ" | "CRITIQUE"
    "risk_score": int,          // Score de risque (0-100)
    "is_phishing": bool,        // True si considéré comme phishing
    "flags": [                  // Liste des flags détectés (si explain=True)
        {
            "message": str,
            "points": int
        }
    ],
    "error": str                // En cas d'erreur
}

Exemple:
    URL avec IP: "http://192.168.1.1/login"
    → {"risk_level": "CRITIQUE", "risk_score": 65, "is_phishing": true}

Utilise cet outil pour voir les heuristiques sans l'influence du modèle IA.
"""
    args_schema: type[BaseModel] = AnalyzeUrlPassiveOnlyInput
    description_updated: bool = True
    
    async def _arun(self, url: str, check_blacklist: bool = False, check_right_click: bool = False, explain: bool = False):
        return await get_ap_instance().predict_passive_analyze_async(
            url,
            check_blacklist=check_blacklist,
            check_right_click=check_right_click,
            explain=explain
        )
    
    def _run(self, url: str, check_blacklist: bool = False, check_right_click: bool = False, explain: bool = False):
        return get_ap_instance().predict_passive_analyze(
            url,
            check_blacklist=check_blacklist,
            check_right_click=check_right_click,
            explain=explain
        )


# ============================================================================
# TOOL 8: VÉRIFIER BLACKLIST URL
# ============================================================================

class CheckUrlBlacklist(BaseTool):
    name: str = "check_url_blacklist"
    description: str = """
Vérifie si une URL est présente dans les blacklists externes (PhishDestroy).

RETOUR (dict JSON) :
{
    "phishing": bool,           // True si l'URL est blacklistée
    "source": str,              // Source de la blacklist ("PhishDestroy")
    "risk_score": int,          // Score de risque (0-100)
    "severity": str,            // "none" | "low" | "medium" | "high"
    "error": str                // En cas d'erreur
}

Exemple:
    URL malveillante: "https://paypal-verify.tk"
    → {"phishing": true, "risk_score": 85, "severity": "high"}

Utilise cet outil pour une vérification rapide sans analyse complète.
"""
    args_schema: type[BaseModel] = CheckUrlBlacklistInput
    description_updated: bool = True
    
    async def _arun(self, url: str):
        return await get_ap_instance().PassiveAnalyzer.verify_black_list(url)
    
    def _run(self, url: str):
        return _run_async(
            self._arun,
            url
        )

class AnalyzeUrlBatch(BaseTool):
    name: str = "analyze_url_batch"
    description: str = """
Analyse plusieurs URLs en parallèle (asyncio.gather) en une seule opération.
Plus efficace que d'appeler analyze_url plusieurs fois.

RETOUR (dict JSON) :
{
    "total": int,               // Nombre total d'URLs analysées
    "safe": int,                // Nombre d'URLs sûres
    "suspicious": int,          // Nombre d'URLs suspectes
    "phishing": int,            // Nombre d'URLs phishing
    "elapsed": float,           // Temps total d'analyse en secondes
    "results": [                // Détails par URL
        {
            "url": str,
            "final_decision": "safe" | "suspicious" | "phishing",
            "confidence": float,
            "source": str,
            "error": str        // Présent uniquement en cas d'erreur
        }
    ]
}

Exemple:
    urls: ["https://google.com", "https://paypal-verify.tk/login"]
    → {"total": 2, "phishing": 1, "safe": 1, "results": [...]}

Utilise cet outil quand l'orchestrateur envoie une liste d'assets ou quand un email
contient plusieurs liens à analyser simultanément.
"""
    args_schema: type[BaseModel] = AnalyzeUrlBatchInput
    description_updated: bool = True

    async def _arun(
        self,
        urls: list[str],
        check_blacklist: bool = False,
        explain: bool = False
    ):
        ap = get_ap_instance()
        start = time.time()

        tasks = [
            ap.predict_url_async(
                url=url,
                check_blacklist=check_blacklist,
                explain=explain
            )
            for url in urls
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        for url, res in zip(urls, raw_results):
            if isinstance(res, Exception):
                results.append({
                    "url": url,
                    "final_decision": "error",
                    "confidence": 0.0,
                    "source": "error",
                    "error": str(res)
                })
            else:
                results.append({
                    "url": url,
                    "final_decision": res.get("final_decision", "unknown"),
                    "confidence": res.get("confidence", 0.0),
                    "source": res.get("source", "unknown"),
                    **({"breakdown": res["breakdown"]} if explain and "breakdown" in res else {})
                })

        return {
            "total": len(urls),
            "safe": sum(1 for r in results if r["final_decision"] == "safe"),
            "suspicious": sum(1 for r in results if r["final_decision"] == "suspicious"),
            "phishing": sum(1 for r in results if r["final_decision"] == "phishing"),
            "elapsed": round(time.time() - start, 3),
            "results": results
        }

    def _run(
        self,
        urls: list[str],
        check_blacklist: bool = False,
        explain: bool = False
    ):
        return _run_async(
            self._arun,
            urls, check_blacklist, explain
        )


# ============================================================================
# TOOL 10: MENACES RÉCENTES
# ============================================================================

class GetRecentThreats(BaseTool):
    name: str = "get_recent_threats"
    description: str = """
Retourne uniquement les menaces actives récentes (phishing + suspicious).
Filtré — sans le noise des URLs/emails safe.
Idéal pour l'orchestrateur qui veut les alertes actives sans tout l'historique.

RETOUR (dict JSON) :
{
    "total_threats": int,       // Nombre total de menaces (phishing + suspicious)
    "phishing_count": int,      // Phishing confirmés
    "suspicious_count": int,    // Suspects
    "urls": [                   // Menaces sur URLs
        {
            "url": str,
            "final_decision": "phishing" | "suspicious",
            "confidence": float,
            "source": str,
            "date": str
        }
    ],
    "emails": [                 // Menaces sur emails
        {
            "sender": str,
            "subject": str,
            "final_decision": "phishing" | "suspicious",
            "confidence": float,
            "date": str
        }
    ]
}

Utilise cet outil quand l'orchestrateur veut connaître l'état des menaces actives
ou quand il faut décider d'une action (blocage, alerte admin).
"""
    args_schema: type[BaseModel] = GetRecentThreatsInput
    description_updated: bool = True

    def _get_email_threats(self, limit: int, include_suspicious: bool) -> list[dict]:
        """Lit l'historique emails et filtre les menaces."""
        history_file = os.path.join(HISTORY_FILE, "history_mail.json")
        if not os.path.exists(history_file):
            return []

        with open(history_file, 'r', encoding='utf-8') as f:
            analyses = json.load(f)

        targets = ["phishing", "suspicious"] if include_suspicious else ["phishing"]
        threats = [a for a in analyses if a.get("final_decision") in targets]

        return [
            {
                "sender": t.get("sender", "N/A"),
                "subject": t.get("subject", "N/A")[:60],
                "final_decision": t.get("final_decision"),
                "confidence": t.get("confidence", 0.0),
                "date": t.get("date", "N/A")
            }
            for t in threats[-limit:]
        ]

    def _run(self, limit: int = 10, include_suspicious: bool = True):
        ap = get_ap_instance()
        history = ap.get_history("json")
        all_urls = history.get("json", [])

        targets = ["phishing", "suspicious"] if include_suspicious else ["phishing"]
        url_threats = [a for a in all_urls if a.get("final_decision") in targets]

        url_list = [
            {
                "url": t.get("url", "N/A"),
                "final_decision": t.get("final_decision"),
                "confidence": t.get("confidence", 0.0),
                "source": t.get("source", "N/A"),
                "date": t.get("date", "N/A")
            }
            for t in url_threats[-limit:]
        ]

        email_list = self._get_email_threats(limit, include_suspicious)

        total = len(url_list) + len(email_list)
        phishing_count = sum(1 for t in url_list + email_list if t["final_decision"] == "phishing")
        suspicious_count = sum(1 for t in url_list + email_list if t["final_decision"] == "suspicious")

        return {
            "total_threats": total,
            "phishing_count": phishing_count,
            "suspicious_count": suspicious_count,
            "urls": url_list,
            "emails": email_list
        }

    async def _arun(self, limit: int = 10, include_suspicious: bool = True):
        return self._run(limit, include_suspicious)

# ============================================================================
# TOOL 11: RELOAD MODÈLE
# ============================================================================

class ReloadModel(BaseTool):
    name: str = "reload_model"
    description: str = """
Force le rechargement du modèle ML anti-phishing ou Email sans redémarrer le service.
À utiliser après un refit déclenché par l'orchestrateur ou un autre agent.
INPUT:
    what: "all" | "phishing" | "mail"
    - "all" → recharge le modèle URL + le modèle email
    - "phishing" → recharge uniquement le modèle URL (PhishingIA)
    - "mail" → recharge uniquement le modèle email (MailPhishingPredict)
    
RETOUR (dict JSON) :
{
    "status": "success" | "error",
    "message": str,             // Confirmation ou message d'erreur
    "timestamp": str            // Heure du rechargement
}

Exemple:
    → {"status": "success", "message": "Modèle rechargé", "timestamp": "11/06/2026 à 14:32:10"}

Utilise cet outil après avoir déclenché un refit pour que les nouvelles
prédictions utilisent le modèle mis à jour.
"""
    args_schema: type[BaseModel] = ReloadModelInput
    description_updated: bool = True

    def _run(self, what: str, *args, **kwargs):
        return _run_async(
            self._arun,
            what,
            *args,
            **kwargs
        )

    async def _arun(self, what: str, *args, **kwargs):
        try:
            ap = get_ap_instance()
            await ap.load_models(what)
            return {
                "status": "success",
                "message": "Modèle rechargé avec succès",
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
            }

class AnalyzeEmailBatch(BaseTool):
    name: str = "analyze_email_batch"
    description: str = """
Analyse plusieurs emails en parallèle (asyncio.gather) en une seule opération.
Plus efficace que d'appeler analyze_email plusieurs fois.

INPUT:
    - Soit emails: liste de textes bruts d'emails
    - Soit email_files: liste de chemins vers des fichiers .eml

RETOUR (dict JSON) :
{
    "total": int,               // Nombre total d'emails analysés
    "safe": int,                // Nombre d'emails sûrs
    "suspicious": int,          // Nombre d'emails suspects
    "phishing": int,            // Nombre d'emails phishing
    "error": int,               // Nombre d'erreurs
    "elapsed": float,           // Temps total d'analyse en secondes
    "results": [                // Détails par email
        {
            "index": int,           // Position dans la liste
            "source": str,          // "text" ou "file: chemin"
            "final_decision": "safe" | "suspicious" | "phishing" | "error",
            "confidence": float,
            "sender": str,          // Uniquement si succès
            "subject": str,         // Uniquement si succès
            "nb_urls_total": int,
            "nb_urls_phishing": int,
            "spf": str,
            "dkim": str,
            "error": str            // Présent uniquement en cas d'erreur
        }
    ]
}

Exemple:
    emails: ["Objet: Urgent Vérifiez votre compte...", "Objet: Newsletter..."]
    → {"total": 2, "phishing": 1, "safe": 1, "results": [...]}

Utilise cet outil quand l'orchestrateur envoie une liste d'emails suspects
ou un dossier contenant plusieurs fichiers .eml à analyser.
"""
    args_schema: type[BaseModel] = AnalyzeEmailBatchInput
    description_updated: bool = True

    def _get_email_content(self, email_content: str = None, email_file: str = None) -> tuple[str, str]:
        """Récupère le contenu d'un email depuis texte ou fichier.
        
        Returns:
            tuple: (source_description, content)
        """
        if email_file:
            if not os.path.exists(email_file):
                raise FileNotFoundError(f"Fichier non trouvé: {email_file}")
            with open(email_file, 'r', encoding='utf-8', errors='replace') as f:
                return f"file: {email_file}", f.read()
        elif email_content:
            return "text", email_content
        else:
            raise ValueError("Fournir soit email_content soit email_file")
    
    async def _analyse_one(self, task_type, source, content, ap, check_blacklist):
        if task_type == "error":
            return "error", source, Exception(content)
        
        return ("success", source, await ap.predict_email_async(content, check_blacklist))
                
    async def _arun(
        self,
        emails: list[str] = None,
        email_files: list[str] = None,
        check_blacklist: bool = False
    ):
        ap = get_ap_instance()
        start = time.time()

        email_sources = [] 
        
        if emails:
            for content in emails:
                if content and content.strip():
                    email_sources.append(("text", content))
        
        if email_files:
            for filepath in email_files:
                if filepath:
                    try:
                        source, content = self._get_email_content(email_file=filepath)
                        email_sources.append((source, content, None))
                    except Exception as e:
                        email_sources.append((f"file: {filepath}", None, str(e)))
        
        if not email_sources:
            return {
                "total": 0,
                "safe": 0,
                "suspicious": 0,
                "phishing": 0,
                "error": 0,
                "elapsed": 0.0,
                "results": [],
                "message": "Aucun email fourni"
            }

        tasks = []
        for source, content, err in email_sources:
            if content is None and err is not None:
                tasks.append(("error", source, err))
            else:
                tasks.append(("analyze", source, content))
        
        raw_results = await asyncio.gather(
            *[
                self._analyse_one(task_type, source, content, ap, check_blacklist)
                for task_type, source, content in tasks
            ],
            return_exceptions=True
        )
        results = []
        for i, result in enumerate(raw_results):
            if isinstance(result, Exception):
                results.append({
                    "index": i,
                    "source": "unknown",
                    "final_decision": "error",
                    "confidence": 0.0,
                    "error": str(result)
                })
                continue
            
            task_type, source, res = result
            if task_type == "error":
                results.append({
                    "index": i,
                    "source": source,
                    "final_decision": "error",
                    "confidence": 0.0,
                    "error": str(result)
                })
            else:
                results.append({
                    "index": i,
                    "source": source,
                    "final_decision": res.get("final_decision", "unknown"),
                    "confidence": res.get("confidence", 0.0),
                    "sender": res.get("sender", ""),
                    "subject": res.get("subject", ""),
                    "nb_urls_total": res.get("nb_urls_total", 0),
                    "nb_urls_phishing": res.get("nb_urls_phishing", 0),
                    "spf": res.get("spf", ""),
                    "dkim": res.get("dkim", ""),
                })

        return {
            "total": len(results),
            "safe": sum(1 for r in results if r["final_decision"] == "safe"),
            "suspicious": sum(1 for r in results if r["final_decision"] == "suspicious"),
            "phishing": sum(1 for r in results if r["final_decision"] == "phishing"),
            "error": sum(1 for r in results if r["final_decision"] == "error"),
            "elapsed": round(time.time() - start, 3),
            "results": results
        }

    def _run(
        self,
        emails: list[str] = None,
        email_files: list[str] = None,
        check_blacklist: bool = False
    ):
        return _run_async(
            self._arun,
            emails, email_files, check_blacklist
        )
    
# ============================================================================
# LISTE DE TOUS LES TOOLS
# ============================================================================

ALL_TOOLS = [
    AnalyzeUrl(),
    AnalyzeEmail(),
    ExtractUrls(),
    GetPhishingStats(),
    ClearCache(),
    AnalyzeUrlIAOnly(),
    AnalyzeUrlPassiveOnly(),
    CheckUrlBlacklist(),
    AnalyzeUrlBatch(),
    GetRecentThreats(),
    ReloadModel(),
    AnalyzeEmailBatch()
]