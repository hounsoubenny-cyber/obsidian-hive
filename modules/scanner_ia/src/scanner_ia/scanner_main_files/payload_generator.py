#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 20:16:59 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))

import json
import copy
import html
import base64
import traceback
import time
import random
import string
import asyncio
from urllib.parse import parse_qs, urlparse, urlunparse, quote, urlencode
# from loguru import logger as logger_payload_generator
from scanner_utils.logger import get_logger
from base_class.payloads_base_class import Payload, Payloads, PayloadResult
from base_class.analyser_helper_base_class import OneAnalyzerHelperResult
from base_class.parser_base_class import ParseElementResult
from fuzzer.config import PAYLOADS_FILE, DEFAULT_FORM_VALUES
from fuzzer.query_resolver import resolve_query_params, set_known_params_dir
from nest_asyncio import apply

apply()

logger_payload_generator = get_logger()
# logger_payload_generator.remove()
# logger_payload_generator.add(
#     sys.stdout,
#     format=(
#         "<yellow>{time:HH:mm:ss}</yellow> | "
#         "<level>{level: <8}</level> | "
#         "<magenta>{name}</magenta>:<cyan>{function}</cyan>:<cyan>{line}</cyan>\n"
#         "└─ <level>{message}</level>"
#     ),
#     level="DEBUG",
#     colorize=True
# )
# logger_payload_generator.add(
#     "logs/payload_generator.log",
#     rotation="10 MB",
#     retention="30 days",
#     level="DEBUG",
#     format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
#     encoding="utf-8"
# )

# ─── Vulnérabilités envoyées en XML ──────────────────────────────────────────
_XML_VULNS = {"XXE"}

# ─── Vulnérabilités envoyées en JSON ─────────────────────────────────────────
_JSON_VULNS = {"NoSQLi", "GraphQLi", "InsecDeser", "Prototype_Pollution", "SSRF"}

# ─── Clés JSON génériques si l'endpoint n'est pas connu ──────────────────────
_DEFAULT_JSON_KEYS = [
    "username", "password", "email", "query",
    "url", "data", "input", "value", "search", "filter",
]


class PayloadGenerator:
    """
    Générateur de payloads pour tests d'intrusion.
    
    Cette classe permet de générer des variantes de payloads pour différents
    points d'injection : URL (path, query), headers, cookies, formulaires.
    
    Attributes:
        debug (bool): Mode debug avec logs détaillés
        limit (int): Nombre maximum de payloads à générer
        encoding_mapping (dict): Fonctions d'encodage disponibles
        payloads (dict): Payloads chargés depuis le fichier de configuration
    """
    
    def __init__(
        self, debug:bool = True, limit:int|None = None, 
        known_params_dir:str = None, 
        use_arjun: bool = False,
        arjun_timeout: int = 30,
    ):
        """
        Initialise le générateur de payloads.
        
        Args:
            debug: Active le mode debug (logs détaillés)
            limit: Nombre maximum de payloads à générer (None = illimité)
            known_params_dir: Dossier contenant le fichier known_params.json
                              Si None, utilise le dossier du résolveur
            use_arjun: Active la détection automatique des paramètres query via Arjun
                       (nécessite d'avoir Arjun installé: pip install arjun)
            arjun_timeout: Timeout en secondes pour Arjun (défaut: 30s)
        
        Example:
            >>> pg = PayloadGenerator(debug=True, limit=100)
            >>> pg = PayloadGenerator(known_params_dir="/path/to/config", use_arjun=True)
        """
        self.encoding_mapping = {
            "url": lambda x: quote(x),
            "html": lambda x: html.escape(x, quote=True),
            "base64": lambda x: (
                    base64.b64encode(str(x).encode()).decode() 
                    if not isinstance(x, bytes) 
                    else base64.b64encode(str(x)).decode()
                ),
            "null_byte": lambda x: "%00.".join(str(x).rsplit(".", 1)),
            "default": lambda x: x,
            }
        self.debug = debug
        self.payloads = {}
        self.limit = limit
        self.load_payload()
        self.known_params_dir = known_params_dir
        if not self.known_params_dir:
            self.known_params_dir = os.path.join(os.path.dirname(__file__), "know_params_dir")
        
        os.makedirs(self.known_params_dir, exist_ok=True)
        self.use_arjun = use_arjun
        self.arjun_timeout = arjun_timeout
        set_known_params_dir(self.known_params_dir)
            
                
    def load_payload(self) -> None:
        """
        Charge les payloads depuis le fichier de configuration.
        """
        try:
            with open(PAYLOADS_FILE, "r") as f:
                self.payloads = json.load(f)
            logger_payload_generator.success(f"✅ {len(self.payloads.get('payloads', {}))} types de payloads chargés")
                
        except Exception as e:
            logger_payload_generator.error(f"Erreur dans le chargement des payloads : {str(e)}")
            if self.debug:
                logger_payload_generator.error(traceback.format_exc())
    
    def encode(self, text:str, enc_type:str|None = None) -> str:
        """
        Encode un texte selon le type spécifié.
        
        Args:
            text: Texte à encoder
            enc_type: Type d'encodage ('url', 'html', 'base64', 'null_byte')
            
        Returns:
            str: Texte encodé
        """
        if enc_type is None:
            return text
        return self.encoding_mapping.get(enc_type, self.encoding_mapping["default"])(text)
    
    def _get_payload(self, payload: dict) -> str:
        """
        Retourne le payload encodé selon le type spécifié.
        
        Args:
            payload: Dictionnaire contenant 'payload' et optionnellement 'encoding'
            
        Returns:
            str: Payload encodé
        """
        if payload.get("encoding"):
            return self.encode(payload["payload"], payload["encoding"])
        return payload["payload"]

    def _inject_payloads_in_path(
            self, 
            url:str, 
            vuln_name:str="", 
            payloads:list[dict[str, str]] = [],
            path_limit:int = None
        ) -> Payloads:
        """
        Injecte des payloads dans le chemin d'une URL.
        
        Args:
            url: URL de base
            vuln_name: Nom de la vulnérabilité
            payloads: Liste des payloads à injecter
            path_limit: Limite de segments de chemin à tester
            
        Returns:
            Payloads: Collection de payloads générés
        """
        result = Payloads()
        result.payload_type = "path_injection"
        url = url.strip()
        if not url:
            return result
        
        parsed = urlparse(url, allow_fragments=True)
        paths = parsed.path
        
        if not paths:
            return result
        
        seen = set()
        paths = paths.removeprefix("/").split("/")
        for payload in payloads:
            for i, path in enumerate(paths[:len(paths) if not path_limit else path_limit]):
                if self.limit:
                    if self.limit and len(result.payloads) >= self.limit:
                        result.n_payloads = len(result.payloads)
                        return result
                
                key = f"{payload['payload']}|{i}|{path}"
                if key in seen:
                    continue
                
                seen.add(key)
                new_path = copy.copy(paths)
                if payload.get("encoding"):
                    p =  self.encode(payload["payload"].lstrip("/"), payload["encoding"])
                else:
                    p = payload["payload"]
                    
                new_path[i] = p
                new_path = "/" + "/".join(new_path)
                new_url = urlunparse(
                    (parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment)
                )
                new_variant = Payload()
                new_variant.update_from_dict({
                    "base_element": url,
                    "new_element": new_url,
                    "element_type": "str",
                    "payload_injected": p,
                    "vuln_name": vuln_name
                    })
                result.payloads.append(new_variant)
                
        result.n_payloads = len(result.payloads)
        return result
    
    def _inject_payloads_in_query(
            self,
            url:str,
            vuln_name:str="", 
            limit_per_key:int|None = 2,
            max_keys:int|None = 5,
            payloads:list[dict[str, str]] = [],
        ) -> Payloads:
        """
        Injecte des payloads dans les paramètres query d'une URL.
        
        Args:
            url: URL de base
            vuln_name: Nom de la vulnérabilité
            limit_per_key: Nombre max de valeurs par paramètre à tester
            max_keys: Nombre max de paramètres à tester
            payloads: Liste des payloads à injecter
            
        Returns:
            Payloads: Collection de payloads générés
        """
        result = Payloads()
        result.payload_type = "query_injection"
        url = url.strip()
        if not url:
            return result
        
        parsed = urlparse(url)
        params = resolve_query_params(url=url, use_arjun=self.use_arjun, arjun_timeout=self.arjun_timeout)
        seen = set()                                                   
        params_copy = copy.deepcopy(params) 
        if max_keys:
            params_copy = {k: v for k, v in list(params_copy.items())[:max_keys]}
            
        if limit_per_key:
            params_copy = {k: list(v)[:limit_per_key] for k, v in params_copy.items()}
        
        for payload in payloads:
            for k, v in params_copy.items():
                for i, _  in enumerate(v):
                    if self.limit:
                        if self.limit and len(result.payloads) >= self.limit:
                            result.n_payloads = len(result.payloads)
                            return result
                    
                    key = f"{payload['payload']}|{k}|{v}|{i}"
                    if key in seen:
                        continue
                    
                    seen.add(key)
                    new_params = copy.deepcopy(params) 
                    p = self._get_payload(payload)
                        
                    new_params[k][i] = p
                    new_params_str = urlencode(new_params, doseq=True)
                    new_url = urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_params_str, parsed.fragment)
                    )
                    new_variant = Payload()
                    new_variant.update_from_dict({
                        "base_element": url,
                        "new_element": new_url,
                        "element_type": "str",
                        "payload_injected": p,
                        "vuln_name": vuln_name
                        })
                    result.payloads.append(new_variant)
    
        result.n_payloads = len(result.payloads)                
        return result       
    
    def _inject_payload_in_headers(
            self,
            headers:dict = {},
            vuln_name:str="", 
            payloads:list[dict[str, str]] = [],
            max_keys:int = 3
        ) -> Payloads:
        """
        Injecte des payloads dans les en-têtes HTTP.
        
        Args:
            headers: Dictionnaire des en-têtes
            vuln_name: Nom de la vulnérabilité
            payloads: Liste des payloads à injecter
            max_keys: Nombre max d'en-têtes à tester
            
        Returns:
            Payloads: Collection de payloads générés
        """
        if not headers:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'fr-FR,fr;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                }
                    
        result = Payloads()
        result.payload_type = "header_injection"
        keys = list(headers.keys())[:max_keys]
        seen = set()
        for payload in payloads:
            for k in keys:
                if self.limit:
                    if self.limit and len(result.payloads) >= self.limit:
                        result.n_payloads = len(result.payloads)
                        return result
                
                p = self._get_payload(payload)
                
                key = f"{payload['payload']}|{k}"
                if key in seen:
                    continue
                
                seen.add(key)
                header_copy = copy.deepcopy(headers)  
                header_copy[k] = p
                
                new_variant = Payload()
                new_variant.update_from_dict({
                    "base_element": headers,
                    "new_element": header_copy,
                    "element_type": "dict",
                    "payload_injected": p,
                    "vuln_name": vuln_name
                    })
                result.payloads.append(new_variant)
                
        result.n_payloads = len(result.payloads)
        return result
    
    def _inject_payload_in_cookies(
            self,
            cookies:dict = {},
            vuln_name:str="", 
            payloads:list[dict[str, str]] = [],
            max_keys:int = 3
        ) -> Payloads:
        """
        Injecte des payloads dans les cookies.
        
        Args:
            cookies: Dictionnaire des cookies
            vuln_name: Nom de la vulnérabilité
            payloads: Liste des payloads à injecter
            max_keys: Nombre max de cookies à tester
            
        Returns:
            Payloads: Collection de payloads générés
        """
        if not cookies:
            cookies = {
                'session_id': 'abc123',         
                'user_pref': 'dark_mode=true',  
                'lang': 'fr',                   
                'consent': 'GDPR_accepted',     
            }
        else:
            if isinstance(cookies, list):
                cookies = {p["key"]:p["value"] for p in cookies}
        result = Payloads()
        result.payload_type = "cookies_injection"
        keys = list(cookies.keys())[:max_keys]
        seen = set()
        for payload in payloads:
            for k in keys:
                if self.limit:
                    if self.limit and len(result.payloads) >= self.limit:
                        result.n_payloads = len(result.payloads)
                        return result
                
                p = self._get_payload(payload)
                
                key = f"{payload['payload']}|{k}"
                if key in seen:
                    continue
                
                seen.add(key)
                cookies_copy = copy.deepcopy(cookies)
                cookies_copy[k] = p
                
                new_variant = Payload()
                new_variant.update_from_dict({
                    "base_element": cookies,
                    "new_element": cookies_copy,
                    "element_type": "dict",
                    "payload_injected": p,
                    "vuln_name": vuln_name
                    })
                result.payloads.append(new_variant)
                
        result.n_payloads = len(result.payloads)
        return result

    def _get_default_value(self, champ:dict, marker_id:str) -> str:
        ch_type = champ.get("type", "text").lower()
        ch_name = champ.get("name", "").lower()
        for key in list(DEFAULT_FORM_VALUES.keys())[:-1]:
            if str(key).lower() in str(ch_type).lower() or str(key).lower() in str(ch_name).lower():
                return DEFAULT_FORM_VALUES[key](marker_id)
            
        return DEFAULT_FORM_VALUES["default"](marker_id)
                
        
            
    def _inject_payload_in_forms(
            self,
            forms:ParseElementResult,
            vuln_name:str="", 
            payloads:list[dict[str, str]] = [],
        ) -> Payloads:
        """
        Injecte des payloads dans les formulaires.
        
        Args:
            forms: Résultat du parsing des formulaires
            vuln_name: Nom de la vulnérabilité
            payloads: Liste des payloads à injecter
            
        Returns:
            Payloads: Collection de payloads générés
        """
        forms = forms.elements
        result = Payloads()
        result.payload_type = "form_injection"
        for payload in payloads:
            for form in forms:
                if self.limit:
                    if self.limit and len(result.payloads) >= self.limit:
                        result.n_payloads = len(result.payloads)
                        return result
                
                p = self._get_payload(payload)
                marker_id = payload.get("_marker_id", "1234AAAA")
                
                champs = [
                        ch 
                        for ch in form["champs"] 
                        if ch["tag"].lower() != 'button' 
                        and ch["type"].lower() != "submit" 
                        and ch["name"]
                    ]
                if not champs:
                    continue
                
                data = copy.deepcopy(form)
                
                # Stratégie A — toutes les clés simultanément
                data["champs"] = [
                        {
                            ch["name"]: p
                            for ch in champs
                        }
                    ]
                
                new_variant = Payload()
                new_variant.update_from_dict({
                    "base_element": form,
                    "new_element": data,
                    "element_type": "dict",
                    "payload_injected": p,
                    "vuln_name": vuln_name
                    })
                result.payloads.append(new_variant)
                
                # Stratégie B — une clé à la fois
                modified = {ch["name"]: self._get_default_value(ch, marker_id) for ch in champs}
                
                for key in modified:
                    if self.limit and len(result.payloads) >= self.limit:
                        break
                    
                    modified_copy = copy.copy(modified)
                    modified_copy[key] = p
                
                    data["champs"] = [modified_copy]
                    
                    new_variant = Payload()
                    new_variant.update_from_dict({
                        "base_element": form,
                        "new_element": data,
                        "element_type": "dict",
                        "payload_injected": p,
                        "vuln_name": vuln_name
                        })
                    result.payloads.append(new_variant)
                
        result.n_payloads = len(result.payloads)
        return result
    
    def _inject_payload_in_body(
        self,
        vuln_name: str = "",
        payloads: list[dict] = [],
        content_type: str = "",
        json_keys: list[str] | None = None,
    ) -> Payloads:
        result = Payloads()
        result.payload_type = "body_injection"

        ct_lower = content_type.lower()
        use_xml  = (
            vuln_name in _XML_VULNS
            or "xml" in ct_lower
            or "soap" in ct_lower
        )

        keys = json_keys if json_keys else _DEFAULT_JSON_KEYS

        for payload in payloads:
            if self.limit and len(result.payloads) >= self.limit:
                break

            p = self._get_payload(payload)
            if use_xml:
                v = Payload()
                v.update_from_dict({
                    "base_element":    {},
                    "new_element":     {
                        "content_type": "application/xml",
                        "data": p,
                        "raw": True,  # xml = True
                    },
                    "element_type": "body",
                    "payload_injected": p,
                    "vuln_name": vuln_name,
                })
                result.payloads.append(v)
                
            else:
                try:
                    parsed_payload = json.loads(p)  # Car certains element sont des dicts en string, json.loads les transforme
                except (json.JSONDecodeError, ValueError):
                    parsed_payload = p
                
                # Stratégie A — une clé à la fois
                for key in keys:
                    if self.limit and len(result.payloads) >= self.limit:
                        break
                    v = Payload()
                    v.update_from_dict({
                        "base_element": {key: ""},
                        "new_element": {
                            "content_type": "application/json",
                            "data": {key: parsed_payload},
                            "raw": False,
                        },
                        "element_type": "body",
                        "payload_injected": p,
                        "vuln_name": vuln_name,
                    })
                    result.payloads.append(v)

                # Stratégie B — toutes les clés simultanément
                if keys and not (self.limit and len(result.payloads) >= self.limit):
                    v = Payload()
                    v.update_from_dict({
                        "base_element": {k: "" for k in keys},
                        "new_element": {
                            "content_type": "application/json",
                            "data": {k: parsed_payload for k in keys},
                            "raw": False,
                        },
                        "element_type": "body",
                        "payload_injected": p,
                        "vuln_name": vuln_name,
                    })
                    result.payloads.append(v)
                    
        result.n_payloads = len(result.payloads)
        if self.debug:
            logger_payload_generator.debug(
                f"_inject_payload_in_body [{vuln_name}] "
                f"{'XML' if use_xml else 'JSON'} : {result.n_payloads} payloads"
            )
        return result
    
    def _resolve_marker(self, payload_str: str) -> tuple[str, str]:
        """Remplace {{MARKER}} par un ID unique et retourne (payload_résolu, marker_id)"""
        marker_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        resolved = payload_str.replace("{{MARKER}}", marker_id)
        return resolved, marker_id
    
    def _prepare_payloads(self, raw_payloads: list[dict]) -> list[dict]:
        """
        Prépare la liste complète des payloads prêts à l'envoi à partir du
        format v3.1 (champ ``encodings: list[str]``).

        Pour chaque entrée brute, cette méthode :

        1. **Expand les encodings** — crée une variante par valeur présente
           dans le champ ``encodings`` (ex. ``["none", "url", "base64"]``
           → 3 variantes indépendantes).
        2. **Résout ``{{MARKER}}``** — remplace le marqueur par un identifiant
           aléatoire de 8 caractères (A-Z + 0-9) unique à chaque variante.
        3. **Applique l'encodage** — encode le payload selon le type de la
           variante (``"url"``, ``"html"``, ``"base64"``, ``"null_byte"``).
           La valeur ``"none"`` laisse le payload tel quel.
        4. **Applique ``repeat``** — si l'entrée contient un champ ``repeat``,
           répète le payload encodé ``repeat // 4`` fois (division par 4 pour
           garder une taille raisonnable en mémoire). Les erreurs
           ``MemoryError`` sont interceptées et loggées.

        Args:
            raw_payloads: Liste des entrées brutes chargées depuis le fichier
                JSON v3.1 (chaque entrée possède ``payload``, ``encodings``,
                ``type``, et optionnellement ``repeat``).

        Returns:
            Liste de dicts prêts à l'emploi, chacun contenant :
            - ``payload``     : chaîne finale (marqueur résolu + encodé + répété)
            - ``encoding``    : encodage appliqué (``str``)
            - ``type``        : type de payload d'origine (``str``)
            - ``_marker_id``  : identifiant unique injecté à la place de
                                ``{{MARKER}}`` (utile pour la corrélation OOB)
            - tous les autres champs de l'entrée originale (``repeat``,
              ``note``, etc.) sont propagés.

        Example:
            Entrée JSON::

                {
                    "payload": "; echo SHLD{{MARKER}}-$(id)",
                    "encodings": ["none", "url", "base64"],
                    "type": "unix_echo_marker"
                }

            Sortie (3 variantes)::

                [
                    {"payload": "; echo SHLDA1B2C3D4-$(id)", "encoding": "none",   "type": "unix_echo_marker", "_marker_id": "A1B2C3D4"},
                    {"payload": "%3B+echo+SHLDA1B2C3D4...",  "encoding": "url",    "type": "unix_echo_marker", "_marker_id": "A1B2C3D4"},
                    {"payload": "OyBlY2hvIFNITE...",          "encoding": "base64", "type": "unix_echo_marker", "_marker_id": "A1B2C3D4"},
                ]
        """
        prepared: list[dict] = []

        for entry in raw_payloads:
            # ── récupère la liste des encodings (rétro-compat: ancien champ "encoding") ──
            encodings: list[str] = entry.get(
                "encodings",
                [entry.get("encoding", "none")]
            )

            for enc in encodings:
                # ── 1. Copie indépendante de l'entrée ────────────────────────
                variant = copy.deepcopy(entry)

                # ── 2. Résolution du marqueur ─────────────────────────────────
                resolved, marker_id = self._resolve_marker(variant["payload"])
                variant["_marker_id"] = marker_id

                # ── 3. Encodage du payload ────────────────────────────────────
                enc_type = None if enc == "none" else enc
                encoded  = self.encode(resolved, enc_type)
                variant["payload"]  = encoded
                variant["encoding"] = enc   # champ attendu par _get_payload()

                # ── 4. Répétition (ex: buffer overflow) ───────────────────────
                if "repeat" in variant:
                    try:
                        variant["payload"] = encoded * (variant["repeat"] // 4)
                    except MemoryError:
                        logger_payload_generator.error(
                            f"MemoryError repeat={variant['repeat']} "
                            f"pour {encoded[:30]!r}"
                        )
                        if self.debug:
                            logger_payload_generator.error(traceback.format_exc())

                # ── Nettoyage du champ "encodings" (remplacé par "encoding") ──
                variant.pop("encodings", None)

                prepared.append(variant)

        if self.debug:
            logger_payload_generator.debug(
                f"_prepare_payloads : {len(prepared)} variantes générées "
                f"depuis {len(raw_payloads)} entrées de base"
            )

        return prepared
    
    def inject_payloads(
            self, 
            data: OneAnalyzerHelperResult,
            vuln_name: str = "",
            max_keys_h: int = 3,
            max_keys_c: int = 3,
            max_keys_query: int|None = 5,
            limit_per_key_query: int|None = 2,
            path_limit: int|None = 5,
            json_keys: list[str] | None = None,
        ) -> PayloadResult:
        """
        Injecte des payloads dans tous les points d'injection disponibles.
        
        Args:
            data: Résultat de l'analyseur helper contenant la page à tester
            vuln_name: Nom de la vulnérabilité à tester
            max_keys_h: Nombre max d'en-têtes à tester
            max_keys_c: Nombre max de cookies à tester
            max_keys_query: Nombre max de paramètres query à tester
            limit_per_key_query: Nombre max de valeurs par paramètre query
            path_limit: Nombre max de segments de chemin à tester
            json_keys: Clés json pour body, optionnel
            
        Returns:
            PayloadResult: Résultat contenant tous les payloads générés
            
        Raises:
            ValueError: Si les payloads n'ont pas été chargés correctement
        """
       
        if not self.payloads:
            raise ValueError("Payloads non chargés")

        payloads = self.payloads["payloads"]
        vuln_list = [payloads[p] for p in payloads if p == vuln_name]
        result = PayloadResult()
        result.url = data.fetched.url

        if not vuln_list:
            logger_payload_generator.warning(f"'{vuln_name}' non supporté")
            logger_payload_generator.info(f"Supportés : {list(payloads.keys())}")
            return result

        vp = vuln_list[0]
        injection_points = vp["injection_points"]
        result.vuln_name = vuln_name
        result.vuln_full_name = vp["name_full"]
        result.vuln_abbr_name = vp["name_abbr"]
        if "cvss_base" in vp:
            result.cvss = vp["cvss_base"]

        prepared    = self._prepare_payloads(vp["payloads"])
        endpoint_ct = (data.fetched.headers or {}).get("Content-Type", "")
        
        mapping = {
            "query": lambda p: self._inject_payloads_in_query(
                url=data.fetched.url, vuln_name=vuln_name, payloads=p,
                limit_per_key=limit_per_key_query, max_keys=max_keys_query,
            ),
            "form": lambda p: self._inject_payload_in_forms(
                forms=data.parsed.form, payloads=p, vuln_name=vuln_name,
            ),
            "header": lambda p: self._inject_payload_in_headers(
                headers=data.fetched.headers, vuln_name=vuln_name,
                max_keys=max_keys_h, payloads=p,
            ),
            "cookie": lambda p: self._inject_payload_in_cookies(
                cookies=data.fetched.cookies, payloads=p,
                vuln_name=vuln_name, max_keys=max_keys_c,
            ),
            "path": lambda p: self._inject_payloads_in_path(
                payloads=p, vuln_name=vuln_name,
                url=data.fetched.url, path_limit=path_limit,
            ),
            "body": lambda p: self._inject_payload_in_body(
                vuln_name=vuln_name, payloads=p,
                content_type=endpoint_ct, json_keys=json_keys,
            ),
        }

        for ip in injection_points:
            if ip in mapping:
                result.set_payload(payload=mapping[ip](prepared), key=ip)

        logger_payload_generator.debug(f"✅ {result.n_payloads} payloads générés pour {vuln_name}")
        return result
    
    async def test(self, urls: list = None) -> None:
        """
        Teste le générateur de payloads sur des URLs.
        
        Args:
            urls: Liste d'URLs à tester (par défaut: localhost)
        """
        logger_payload_generator.info("\n" + "🔥"*60)
        logger_payload_generator.info("🔥 TEST PAYLOAD GENERATOR")
        logger_payload_generator.info("🔥"*60)
        
        if urls is None:
            urls = ["http://localhost:5000"]
        
        from core.analyzer_helper import AnalyzerHelper
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            helper = AnalyzerHelper(session, use_cache=True)
            
            all_stats = {}
            total_start = time.time()
            
            for url in urls:
                logger_payload_generator.info(f"\n📌 Test sur {url}")
                logger_payload_generator.info("-"*50)
                
                # Récupérer les données de la page
                page_result = await helper.analyse_and_parse_all(
                    url=url,
                    verify_reachability=True,
                    restore=True,
                    fetch=True
                )
                
                if not page_result.elements:
                    logger_payload_generator.warning(f"  ⚠️ Aucune donnée récupérée pour {url}")
                    continue
                
                # Prendre la première page
                first_page = list(page_result.elements.values())[0]
                
                # Tester chaque type de vulnérabilité
                url_stats = {}
                for vuln_name in ["XSS", "SQLi", "LFI", "CMDI", "OPEN_REDIRECT", "BufOvr"]:
                    if vuln_name not in self.payloads.get("payloads", {}):
                        continue
                    
                    logger_payload_generator.info(f"\n  🔍 Test {vuln_name}")
                    
                    start = time.time()
                    payload_result = self.inject_payloads(
                        data=first_page,
                        vuln_name=vuln_name,
                        max_keys_h=2,
                        max_keys_c=2,
                        max_keys_query=3,
                        limit_per_key_query=1,
                        path_limit=2
                    )
                    elapsed = time.time() - start
                    
                    total = payload_result.n_payloads
                    url_stats[vuln_name] = total
                    
                    logger_payload_generator.info(f"    ⏱️  {elapsed:.3f}s")
                    logger_payload_generator.info(f"    📊 Total: {total}")
                    
                
                all_stats[url] = url_stats
            
            # Résumé final
            total_time = time.time() - total_start
            logger_payload_generator.info("\n" + "★"*60)
            logger_payload_generator.info("📊 RÉSUMÉ DES TESTS")
            logger_payload_generator.info("★"*60)
            
            for url, stats in all_stats.items():
                logger_payload_generator.info(f"\n{url}:")
                for vuln, count in stats.items():
                    logger_payload_generator.info(f"  {vuln}: {count} payloads")
            
            logger_payload_generator.info(f"\n⏱️  Temps total: {total_time:.2f}s")
            logger_payload_generator.info("★"*60)
            
            await helper.close()


if __name__ == "__main__":
    # Test avec le nouveau format
    pg = PayloadGenerator(debug=True)
    
    # Vérifier que XSS a toujours 24 payloads après expansion
    xss_payloads = pg.payloads["payloads"]["XSS"]["payloads"]
    prepared = pg._prepare_payloads(xss_payloads)
    
    print("\n📊 Résultat du test:")
    print(f"   Payloads XSS bruts: {len(xss_payloads)}")
    print(f"   Payloads XSS préparés: {len(prepared)}")
    
    if len(prepared) == 24:
        print("   ✅ Test passé : 24 payloads générés")
    else:
        print(f"   ⚠️ Attention: {len(prepared)} payloads (attendu: 24)")
    
    # Test avec un payload qui a repeat
    test_payload = {
        "payload": "A",
        "encodings": ["none", "url"],
        "repeat": 1000,
        "type": "test"
    }
    result = pg._prepare_payloads([test_payload])
    print(f"\n   Test repeat: {len(result)} payloads générés")
    print(f"   Taille du payload: {len(result[0]['payload'])} caractères")