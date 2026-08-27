#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 20:17:12 2026

@author: hounsousamuel

Changelog v2:
  - BUG FIX  : per_indicator — formule corrigée, suppression du *2 aberrant
  - BUG FIX  : score_ind passe en non-linéaire (diminishing returns)
                1 regex fort = preuve, pas 1/N d'une preuve
  - NOUVEAU  : _compute_reflection_score() — détecte la réflexion brute du
               payload dans le body (XSS, CMDi, DirTrav, SSTI, ...)
  - BUG FIX  : _analyse_body_size() — threshold adaptatif par vuln
                (20% fixe = aveugle aux erreurs SQL/LDAP courtes)
  - BUG FIX  : doublons d'indicateurs dédupliqués avant scoring
  - BUG FIX  : _analyse_contexte() — fenêtre JSON élargie (le { peut être loin)
  - AMÉLIO   : variantes encodées (base64/url/html) cherchées pour les
               string-indicators quand le payload était envoyé encodé
"""

import os
import json
import html
import math
import re
import csv
import base64
import threading
import traceback
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import quote as url_quote
from scanner_ia.fuzzer.config import WEIGTHS_FILE, WEIGTHS_FILE_WITH_SEMANTIC
from scanner_ia.base_class.fuzzer_base_class import WorkerFuzzerResult, pformat
from scanner_ia.base_class.response_analyzer_base_class import ResponseAnalyzerResult
from scanner_ia.fuzzer.config import CRITICAL_HEADERS, SIMILARITY_MODEL_DIR, N_FEATURES_SIM
# from fuzzer.similarity import CosineSimilarityTFIDF as SimilarityModel
from scanner_ia.fuzzer.similarity_bert import CosineSimilarityBERT as SimilarityModel
from cachetools import TTLCache
from scanner_ia.scanner_utils.logger import get_logger

TTL_CACHE_SIZE = 10000
TTL = 100 * 60
logger_response_analyzer = get_logger()

# ─── Vulns où la réflexion brute du payload est une preuve forte ──────────────
_REFLECTION_VULNS = {
    "XSS", "SSTI", "CRLF_Injection", "OpenRedirect",
    "CMDi", "DirTrav", "XXE", "SSRF"
}

# ─── Threshold body_size adaptatif par vuln (fraction de len(baseline)) ──────
# Ancienne valeur fixe : 0.20 — trop haute pour les erreurs courtes (SQL/LDAP)
_BODY_THRESHOLD = {
    # Error-based : messages courts (ex: "You have an error in your SQL syntax")
    "SQLi":             0.03,
    "NoSQLi":           0.03,
    "LDAPi":            0.03,
    "XPATH_Injection":  0.03,
    "GraphQLi":         0.03,
    # Output système : peut être court (id, hostname, ...)
    "CMDi":             0.04,
    # Réflexion directe : taille ≈ payload injecté
    "XSS":              0.04,
    "SSTI":             0.04,
    "CRLF_Injection":   0.03,
    # Contenu fichier : peut être long
    "DirTrav":          0.08,
    "XXE":              0.08,
    # Défaut tous les autres
    "__default__":      0.12,
}

# ─── Fragments dangereux par vuln pour _compute_reflection_score ─────────────
_REFLECTION_PATTERNS = {
    "XSS": [
        r'<script[\s>]', r'onerror\s*=', r'onload\s*=', r'onfocus\s*=',
        r'onclick\s*=', r'ontoggle\s*=', r'alert\s*\(', r'eval\s*\(',
        r'fetch\s*\(', r'document\.', r'javascript\s*:', r'<svg[\s/]',
        r'<iframe[\s>]', r'srcdoc\s*=', r'formaction\s*=',
    ],
    "SSTI": [
        r'\{\{.*?\}\}', r'\{%.*?%\}', r'#\{.*?\}',
        r'jinja2\.', r'TemplateSyntaxError', r'UndefinedError',
    ],
    "CMDi": [
        r'uid=\d+', r'gid=\d+', r'root:x:0', r'/bin/bash',
        r'whoami', r'hostname', r'SHLD[A-Z0-9]{4,16}',
    ],
    "DirTrav": [
        r'root:x:0:0', r'daemon:x:', r'\[extensions\]',
        r'BEGIN RSA PRIVATE KEY', r'\[boot loader\]',
    ],
    "OpenRedirect": [
        r'location\s*:', r'shld\.io', r'attacker\.com',
    ],
    "CRLF_Injection": [
        r'set-cookie\s*:', r'location\s*:', r'x-injected',
    ],
    "XXE": [
        r'root:x:0:0', r'<!ENTITY',
        r'file://', r'SAXParseException',
    ],
    "SSRF": [
        r'ami-id', r'instance-id', r'169\.254\.169\.254',
        r'computeMetadata', r'iam/security-credentials',
    ],
}


class ResponseAnalyzer:
    """
    Analyseur de réponses HTTP pour détecter des vulnérabilités.
    
    Cette classe compare une réponse de test avec une baseline pour déterminer
    si un payload a réussi à exploiter une vulnérabilité.
    
    Attributes:
        debug (bool)           : Mode debug.
        weights (dict)         : Poids chargés depuis weights_v2.json.
        SAFE_JSON_KEYS (list)  : Clés JSON considérées comme contextes sûrs.
        CRITICAL_HEADERS (set) : En-têtes critiques à surveiller.
        _cache (TTLCache)      : Cache TTL des résultats déjà analysés.
        _diag_path (str)       : Chemin du fichier CSV de diagnostic.
        
    """

    def __init__(self, debug: bool = True, use_semantic: bool = True):
        self.debug = debug
        self.weights: dict = {}
        self.use_semantic = use_semantic
        if not use_semantic:
            self.WEIGTHS_FILE = WEIGTHS_FILE
        else:
            self.WEIGTHS_FILE = WEIGTHS_FILE_WITH_SEMANTIC
        self.load_weights()
        self.SAFE_JSON_KEYS = [
            'error', 'message', 'debug', 'warning',
            'info', 'detail', 'status', 'log', 'output',
            'description', 'response', 'notification', 'alert'
        ]
        self.CRITICAL_HEADERS = CRITICAL_HEADERS
        self._cache = TTLCache(maxsize=TTL_CACHE_SIZE, ttl=TTL)
        self._cache_lock = threading.Lock()
        self._diag_path = "logs/analyzer_diag.csv"
        # self._create_diag_file()
        self.similarity_model = SimilarityModel(model_dir=SIMILARITY_MODEL_DIR, n_features=N_FEATURES_SIM) if use_semantic else None

    # ─── Init helpers ─────────────────────────────────────────────────────────

    def _create_diag_file(self):
        os.makedirs("logs", exist_ok=True)
        with open(self._diag_path, 'w', newline='') as f:
            csv.writer(f).writerow([
                'timestamp', 'url', 'vuln', 'payload', "payload_type",
                'score_ind', 'score_status', 'score_delay', 'score_headers', 'score_body',
                'total', 'prob', 'is_vuln', 'indicators_found'
            ])

    def load_weights(self) -> None:
        """
        Charge les poids depuis le fichier de configuration.
        
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            json.JSONDecodeError: Si le JSON est invalide
        """
        try:
            with open(self.WEIGTHS_FILE, "r") as f:
                self.weights = json.load(f)
            logger_response_analyzer.success(f"✅ {len(self.weights.get('vulnerability_weights', {}))} poids chargés")
        except Exception as e:
            logger_response_analyzer.error(f"Erreur dans le chargement des poids : {str(e)}")
            if self.debug:
                logger_response_analyzer.error(traceback.format_exc())

    # ─── Contexte sûr ─────────────────────────────────────────────────────────

    def _analyse_contexte(self, body: str, indicator: str) -> bool:
        """
        Vérifie si un indicateur est dans un contexte sûr (commentaire, data-attr, etc.)
        
        Args:
            body: Corps de la réponse
            indicator: Indicateur à rechercher
            
        Returns:
            True si l'indicateur est dans un contexte sûr (faux positif)

        FIX v2: le regex JSON accepte maintenant jusqu'à 300 chars entre { et l'indicateur
                (l'ancien pattern ratait les cas où le { est loin dans l'extrait)
        """
        join = '|'.join(re.escape(k) for k in self.SAFE_JSON_KEYS)

        # FIX: {0,300} au lieu de * pour capturer le { même s'il est loin
        json_regex = (
            r'\{[^{}]{0,300}"(?:' + join +
            r')"[^{}]{0,100}' + re.escape(indicator) + r'[^{}]{0,100}\}'
        )

        safe_patterns = [
            r'(?<!["\']|\w)<!--.*?' + re.escape(indicator) + r'.*?-->(?!["\'])',   # Commentaires HTML
            r'/\*.*?' + re.escape(indicator) + r'.*?\*/',                           # Commentaires CSS/JS
            r'//.*?' + re.escape(indicator),                                        # Commentaires ligne JS
            json_regex,                                                             # JSON error key
            r'data-\w+\s*=\s*[\'"].*?' + re.escape(indicator) + r'.*?[\'"]',       # Attributs data-
        ]

        for pattern in safe_patterns:
            try:
                if re.search(pattern, body, re.DOTALL | re.IGNORECASE):
                    logger_response_analyzer.debug(f"Contexte sûr détecté: {pattern[:50]}...")
                    return True
            except re.error as e:
                logger_response_analyzer.warning(f"Erreur regex: {e}")
                continue

        return False

    # ─── Variantes encodées d'un string-indicator ─────────────────────────────

    @staticmethod
    def _encoded_variants(indicator: str) -> List[Tuple[str, str]]:
        """
        Retourne les variantes encodées d'un indicateur string.
        Utilisé quand le payload a été envoyé encodé : le serveur peut
        refléter l'indicateur encodé tel quel dans la réponse.

        Returns:
            Liste de tuples (variante_encodée, label)
        """
        variants = []

        # URL encoding
        url_enc = url_quote(indicator, safe='')
        if url_enc != indicator:
            variants.append((url_enc, "url"))

        # URL encoding partiel (espaces → +)
        url_plus = indicator.replace(' ', '+')
        if url_plus != indicator and url_plus != url_enc:
            variants.append((url_plus, "url_plus"))

        # Base64
        try:
            b64 = base64.b64encode(indicator.encode('utf-8')).decode('ascii')
            variants.append((b64, "base64"))
            b64url = base64.urlsafe_b64encode(indicator.encode('utf-8')).decode('ascii')
            if b64url != b64:
                variants.append((b64url, "base64url"))
        except Exception:
            pass

        # HTML entities
        html_esc = html.escape(indicator, quote=True)
        if html_esc != indicator:
            variants.append((html_esc, "html"))

        return variants

    # ─── Score non-linéaire des indicateurs ───────────────────────────────────

    @staticmethod
    def _nonlinear_indicator_score(regex_count: int, string_count: int) -> float:
        """
        Score à rendements décroissants.

        Logique: en sécu, UN indicateur bien ciblé = une PREUVE,
        pas 1/N d'une preuve comme le faisait l'ancienne formule linéaire.
        Les indicateurs suivants ajoutent de la certitude mais moins.

        Barème:
            1er regex  → 55 pts
            2e  regex  → 36 pts  (×0.65)
            3e  regex  → 23 pts  ...
            1er string → 38 pts  (après les regex, décroissance continue)
            2e  string → 25 pts  ...
        """
        score = 0.0
        decay = 0.55
        i = 0

        for _ in range(regex_count):
            score += 55.0 * (decay ** i)
            i += 1

        for _ in range(string_count):
            score += 38.0 * (decay ** i)
            i += 1

        return min(100.0, score)

    # ─── Analyse des indicateurs ──────────────────────────────────────────────

    def _analyse_indicators(self, indicators: List[dict], body: str, test_body: str, context_size: int = 200, payload_encoding: Optional[str] = None) -> Tuple[Dict[str, str], float]:
        """
        Analyse une liste d'indicateurs dans le corps.
        
        Supporte deux formats d'indicateurs :
          - Ancien format (str)  : "root:x:0:0:"
          - Nouveau format (dict): {"type": "regex"|"string", "value": "..."}

        Améliorations v2 :
          - Déduplication (SHLD* et shld.io étaient en double dans XSS → double-compte)
          - Score non-linéaire via _nonlinear_indicator_score()
          - Variantes encodées cherchées si payload_encoding fourni
        
        Args:
            indicators: Liste des indicateurs à rechercher
            body: Corps de la baseline
            test_body: Corps de la réponse test
            context_size: Taille du contexte (FIX v2: 200 au lieu de 100)
            payload_encoding: Encodage du payload envoyé ("base64", "url", ...)
        
        Returns:
            Tuple[Dict[str, str], float]: (indicateurs trouvés → contexte, score 0-100)
        """
        baseline_body = str(body)
        test_body     = str(test_body)

        baseline_lower    = baseline_body.lower()
        test_lower        = test_body.lower()
        baseline_unescape = html.unescape(baseline_body).lower()
        test_unescape     = html.unescape(test_body).lower()

        found_indicators = {}
        regex_found   = 0
        string_found  = 0

        # déduplication — évite de compter deux fois le même indicateur
        seen_values = set()

        for item in indicators:
            if isinstance(item, dict):
                ind_type  = item.get("type", "string")
                indicator = item.get("value", "")
            else:
                ind_type  = "string"
                indicator = item

            # ── Déduplication ────────────────────────────────────────────────
            dedup_key = f"{ind_type}:{indicator}"
            if dedup_key in seen_values:
                if self.debug:
                    logger_response_analyzer.debug(f"⊘ [dedup] Indicateur dupliqué ignoré: {indicator!r}")
                continue
            seen_values.add(dedup_key)

            # ── Regex ────────────────────────────────────────────────────────
            if ind_type == "regex":
                try:
                    pattern = re.compile(indicator, re.IGNORECASE | re.DOTALL | re.MULTILINE)
                    baseline_count = len(pattern.findall(baseline_body)) + len(pattern.findall(baseline_unescape))
                    test_count     = len(pattern.findall(test_body))     + len(pattern.findall(test_unescape))

                    if test_count > baseline_count and test_count != 0:
                        m = pattern.search(test_body)
                        source = test_body
                        if not m:
                            m      = pattern.search(test_unescape)
                            source = test_unescape
                        if not m:
                            continue

                        start    = max(0, m.start() - context_size // 2)
                        end      = min(len(source), m.end() + context_size // 2)
                        contexte = source[start:end]

                        is_safe = self._analyse_contexte(contexte, m.group(0))
                        if not is_safe:
                            found_indicators[indicator] = contexte
                            regex_found += 1
                            if self.debug:
                                logger_response_analyzer.debug(f"✓ [regex]  Indicator '{indicator[:60]}' NOUVEAU (baseline:{baseline_count}, test:{test_count})")
                        else:
                            if self.debug:
                                logger_response_analyzer.debug(f"⊘ [regex]  Indicator '{indicator[:60]}' dans contexte sûr")
                    else:
                        if self.debug:
                            if baseline_count != 0:
                                logger_response_analyzer.debug(f"⊘ [regex] Indicator '{indicator[:60]}' déjà présent en baseline (baseline:{baseline_count}, test:{test_count})")
                            elif baseline_count != 0 and test_count > 0:
                                logger_response_analyzer.debug(f"⊘ [regex] Indicator '{indicator[:60]}' absent en baseline mais présent après test (baseline:{baseline_count}, test:{test_count})")
                            else:
                                logger_response_analyzer.debug(f"⊘ [regex] Indicator '{indicator[:60]}' absent des deux")

                except re.error as e:
                    logger_response_analyzer.warning(f"Regex indicateur invalide: {indicator!r} → {e}")
                    continue

            # ── String ───────────────────────────────────────────────────────
            else:
                indicator_lower = str(indicator).lower()
                baseline_count  = baseline_lower.count(indicator_lower) + baseline_unescape.count(indicator_lower)
                test_count      = test_lower.count(indicator_lower)     + test_unescape.count(indicator_lower)

                matched_variant = None
                match_label     = "clear"

                if test_count > baseline_count and test_count != 0:
                    matched_variant = indicator
                else:
                    # chercher les variantes encodées si le payload était encodé
                    if payload_encoding and payload_encoding not in ("none", "default", "null_byte"):
                        for variant, label in self._encoded_variants(indicator):
                            v_lower = variant.lower()
                            bc_v = baseline_lower.count(v_lower) + baseline_unescape.count(v_lower)
                            tc_v = test_lower.count(v_lower)     + test_unescape.count(v_lower)
                            if tc_v > bc_v:
                                matched_variant = variant
                                match_label     = label
                                if self.debug:
                                    logger_response_analyzer.debug(f"✓ [string-enc:{label}] '{indicator}' trouvé encodé ({variant[:40]!r})")
                                break

                if matched_variant is not None:
                    mv_lower = matched_variant.lower()
                    pos    = test_lower.find(mv_lower)
                    source = test_body
                    if pos == -1:
                        pos    = test_unescape.find(mv_lower)
                        source = test_unescape

                    if pos != -1:
                        start    = max(0, pos - context_size // 2)
                        end      = min(len(source), pos + len(matched_variant) + context_size // 2)
                        contexte = source[start:end]

                        is_safe = self._analyse_contexte(contexte, matched_variant)
                        if not is_safe:
                            found_indicators[indicator] = contexte
                            string_found += 1
                            if self.debug:
                                logger_response_analyzer.debug(f"✓ [string:{match_label}] Indicator '{indicator}' NOUVEAU (baseline:{baseline_count}, test:{test_count})")
                        else:
                            if self.debug:
                                logger_response_analyzer.debug(f"⊘ [string] Indicator '{indicator}' dans contexte sûr")
                    else:
                        if self.debug:
                            logger_response_analyzer.debug(f"⊘ [string] '{indicator}' variant trouvée mais pos introuvable")
                else:
                    if self.debug:
                        logger_response_analyzer.debug(f"⊘ [string] Indicator '{indicator}' non trouvé (baseline:{baseline_count}, test:{test_count})")

        score = self._nonlinear_indicator_score(regex_found, string_found)
        return found_indicators, score

    # ─── Réflexion brute du payload ───────────────────────────────────────────

    def _compute_reflection_score(self, payload_injected: str, baseline_body: str, test_body: str, vuln_name: str) -> float:
        """
        Détecte la réflexion non-échappée du payload dans le body test.

        Pertinent pour XSS, SSTI, CMDi, DirTrav, XXE, SSRF, CRLF, OpenRedirect.
        Pour XSS: la réflexion RAW (non html-échappée) = preuve directe.
        Un serveur qui échappe &lt;script&gt; n'est PAS vulnérable → body brut testé.

        Retourne un score 0-95 fusionné avec le score indicateur dans
        _compute_indicator_score() — pas un composant séparé, poids inchangés.
        """
        if vuln_name not in _REFLECTION_VULNS:
            return 0.0
        if not payload_injected or not test_body:
            return 0.0

        p_low    = str(payload_injected).lower()
        base_raw = baseline_body.lower()
        test_raw = test_body.lower()   # RAW intentionnel — pas de html.unescape

        # 1. Match exact non-échappé dans le HTML brut
        if p_low in test_raw and p_low not in base_raw:
            if self.debug:
                logger_response_analyzer.debug("✓ [reflection:exact_raw] payload non-échappé dans test_body")
            return 95.0

        # 2. Match exact après unescape (valide pour CMDi/DirTrav, pas XSS)
        test_unesc = html.unescape(test_body).lower()
        base_unesc = html.unescape(baseline_body).lower()
        if vuln_name not in {"XSS"} and p_low in test_unesc and p_low not in base_unesc:
            if self.debug:
                logger_response_analyzer.debug(f"✓ [reflection:exact_unesc] payload trouvé après unescape ({vuln_name})")
            return 80.0

        # 3. Fragments dangereux selon la vuln
        frags = _REFLECTION_PATTERNS.get(vuln_name, [])
        if not frags:
            return 0.0

        hits = 0
        for frag in frags:
            try:
                in_test = bool(re.search(frag, test_raw, re.IGNORECASE))
                in_base = bool(re.search(frag, base_raw, re.IGNORECASE))
                if in_test and not in_base:
                    hits += 1
            except re.error:
                continue

        if hits == 0:
            return 0.0

        score = 60.0 if hits == 1 else 75.0 if hits == 2 else min(90.0, 75.0 + (hits - 2) * 5)
        if self.debug:
            logger_response_analyzer.debug(f"✓ [reflection:fragments] {vuln_name} — {hits} fragment(s) → score={score:.1f}")
        return score

    # ─── Analyse du status code ───────────────────────────────────────────────

    def _analyse_status_code(self, base_code: Optional[int], test_code: Optional[int]) -> Tuple[bool, float]:
        """
        Compare les codes HTTP de la baseline et du test.
        
        Args:
            base_code: Code HTTP de la baseline
            test_code: Code HTTP du test
            
        Returns:
            Tuple[bool, float]: (changement, score)
        """
        if base_code is None or test_code is None:
            return False, 0.0

        if base_code == test_code:
            return False, 0.0

        base_str, test_str = str(base_code), str(test_code)

        changes = {
            # (base_class, test_class): (score, description)
            ('2', '5'): (95, "2xx → 5xx: Erreur serveur probable"),
            ('2', '4'): (80, "2xx → 4xx: Accès refusé"),
            ('2', '3'): (50, "2xx → 3xx: Redirection"),
            ('4', '2'): (95, "4xx → 2xx: Contournement auth ! CRITIQUE"),
            ('5', '2'): (95, "5xx → 2xx: Contournement ! CRITIQUE"),
            ('3', '2'): (60, "3xx → 2xx: Redirection contournée"),
            ('4', '3'): (40, "4xx → 3xx: Changement de redirection"),
            ('5', '3'): (40, "5xx → 3xx: Erreur → redirection"),
            ('4', '5'): (30, "4xx → 5xx: Type d'erreur différent"),
        }

        base_class = base_str[0]
        test_class = test_str[0]

        if (base_class, test_class) in changes:
            score, desc = changes[(base_class, test_class)]
            logger_response_analyzer.debug(f"Status code: {desc} ({base_code}→{test_code})")
            return True, score

        # Changements dans la même classe (ex: 404→403)
        if base_class == test_class:
            return True, 20.0

        return True, 40.0

    # ─── Analyse du body size ─────────────────────────────────────────────────

    def _analyse_body_size(self, body_baseline: str, body_test: str, vuln_name: str = "__default__") -> Tuple[bool, float]:
        """
        Compare la taille des corps de réponse.

        Threshold adaptatif par vuln via _BODY_THRESHOLD.
        L'ancien 20% fixe était aveugle aux erreurs courtes (SQL/LDAP).
        Score plafonné à 60 — preuve secondaire, les indicateurs restent la preuve principale.
        
        Args:
            body_baseline: Corps de la baseline
            body_test: Corps du test
            vuln_name: Nom de la vuln pour le threshold adaptatif
            
        Returns:
            Tuple[bool, float]: (changement, score)
        """
        if not body_baseline or not body_test:
            return False, 0.0

        len_base = len(body_baseline)
        len_test = len(body_test)
        diff     = len_test - len_base

        threshold_pct = _BODY_THRESHOLD.get(vuln_name, _BODY_THRESHOLD["__default__"])
        threshold_abs = max(20, int(threshold_pct * len_base))  # minimum absolu 20 chars

        if diff > threshold_abs:
            ratio = diff / max(len_base, 1)
            score = min(60.0, ratio * 200)   # plafonné à 60, preuve secondaire
            logger_response_analyzer.debug(f"Body size augmenté: +{diff} chars (seuil={threshold_abs}) → score={score:.1f}")
            return True, score

        elif -diff > threshold_abs:
            ratio = (-diff) / max(len_base, 1)
            score = min(30.0, ratio * 100)
            logger_response_analyzer.debug(f"Body size diminué: {diff} chars ({score:.1f}%)")
            return True, score

        return False, 0.0

    # ─── Analyse du délai ─────────────────────────────────────────────────────

    def _analyse_delay(self, time_baseline: float, time_test: float, time_indicator: float = -1) -> Tuple[bool, float]:
        """
        Analyse les délais de réponse (pour time-based injections).
        
        Args:
            time_baseline: Temps de réponse baseline
            time_test: Temps de réponse test
            time_indicator: Temps indicateur (ex: SLEEP(5))
            
        Returns:
            Tuple[bool, float]: (changement, score)
        """
        if time_indicator == -1 or time_baseline < 0 or time_test < 0:
            return False, 0.0

        # Seul un RALENTISSEMENT compte comme preuve (pas abs()) : une réponse
        # plus rapide n'est jamais une preuve d'injection time-based. Avec
        # abs(), un pic de latence ponctuel sur la baseline suivi d'une
        # réponse test simplement "normale" (donc plus rapide) pouvait
        # produire un score proche de 100 — l'inverse de ce que signifie
        # une injection SLEEP(n) réussie.
        delay = time_test - time_baseline
        if delay <= 0:
            return False, 0.0
        indicator_delay = abs(time_indicator - time_baseline)

        if indicator_delay == 0:
            return False, 0.0

        return True, min(100, (delay / indicator_delay) * 100)

    # ─── Analyse des headers ──────────────────────────────────────────────────

    def _analyse_headers(self, base_headers: Dict, test_headers: Dict, normalize: bool = True, payload_str: str = "") -> Tuple[int, float]:
        """
        Analyse les changements dans les en-têtes critiques.
        
        Args:
            base_headers: En-têtes de la baseline
            test_headers: En-têtes du test
            normalize: Normaliser les clés en minuscules
            payload_str: payload injecté, utile pour CORS
        Returns:
            Tuple[int, float]: (nombre de changements, score)
        """
        if normalize:
            base_headers = {str(k).lower(): v for k, v in base_headers.items()}
            test_headers = {str(k).lower(): v for k, v in test_headers.items()}

        critical_base = {k: v for k, v in base_headers.items() if k in self.CRITICAL_HEADERS}
        critical_test = {k: v for k, v in test_headers.items() if k in self.CRITICAL_HEADERS}

        changes = 0
        for key in critical_base:
            if key not in critical_test:
                changes += 1
                logger_response_analyzer.debug(f"En-tête {key} supprimé")
            elif critical_base[key] != critical_test[key]:
                changes += 1
                logger_response_analyzer.debug(f"En-tête {key} modifié")

        acao_test  = test_headers.get("access-control-allow-origin", "")
        acao_base  = base_headers.get("access-control-allow-origin", "")
        acac_test  = test_headers.get("access-control-allow-credentials", "").lower()
        cors_score = 0.0
        base_score = min(100.0, changes * (100.0 / max(len(self.CRITICAL_HEADERS), 1)))

        base_values = list(critical_base.values())
        for v in critical_test.values():
            if payload_str and payload_str in v and payload_str not in base_values:
                base_score += 50
                changes    += 1

        if acao_test:
            # a) La valeur reflète une partie de l'origine envoyée dans le payload
            if payload_str and acao_test.lower() not in ("*", "null", ""):
                origin_frags = re.findall(r"https?://([a-zA-Z0-9\.\-]+)", payload_str)
                for frag in origin_frags:
                    if frag.lower() in acao_test.lower():
                        cors_score = max(cors_score, 90.0)
                        changes   += 1
                        logger_response_analyzer.debug(f"CORS [ORIGIN REFLECTION] ACAO reflète '{frag}' → {acao_test!r}")
                        break

            # b) ACAO passe de wildcard/absent à une valeur spécifique
            if acao_test.lower() not in ("*", "") and acao_base.lower() in ("*", ""):
                cors_score = max(cors_score, 80.0)
                changes   += 1
                logger_response_analyzer.debug(f"CORS [WILDCARD→SPECIFIC] ACAO: {acao_base!r} → {acao_test!r}")

            # c) ACAO=null accepté (sandbox bypass)
            if acao_test.lower() == "null" and acao_base.lower() != "null":
                cors_score = max(cors_score, 85.0)
                changes   += 1
                logger_response_analyzer.debug("CORS [NULL ORIGIN] ACAO: null accepté")

            # d) ACAO non-wildcard + ACAC: true (combinaison dangereuse)
            if acao_test.lower() not in ("*", "") and acac_test == "true":
                cors_score = max(cors_score, 95.0)
                changes   += 1
                logger_response_analyzer.debug(f"CORS [CREDS+SPECIFIC ORIGIN] ACAO={acao_test!r} + ACAC=true")

        score = max(base_score, cors_score)
        return changes, score

    # ─── Semantic ─────────────────────────────────────────────────────────────

    def semantic_analyze(self, base_body: str, test_body: str) -> float:
        if self.similarity_model is not None:
            return (1.0 - self.similarity_model([base_body], [test_body])) * 100
        return 0.0

    # ─── Sigmoid & score total ────────────────────────────────────────────────

    def sigmoid(self, x: float, center: float = 0.5, k: float = 8.0) -> float:
        """
        Calcule la fonction sigmoïde pour normaliser les scores.
        
        Args:
            x: Valeur d'entrée (0-100)
            center: Point central (0.5 = 50%)
            k: Pente de la courbe
            Pour normaliser entre 0 et 100, réduire le k a 1e-2 et multiplié la sortie par 100
        Returns:
            float: Valeur normalisée entre 0 et 1
        """
        return 1 / (1 + math.exp(-k * (x - center)))

    def calculate_total_score(self, weights: list, component_scores: list, **kwargs) -> Tuple[float, float, float]:
        """
        Calcule score total
        
        weights: [0.60, 0.15, 0.00, 0.20, 0.05]
        component_scores: [80, 50, 00, 30, 10]
        """
        total = sum(w * s for w, s in zip(weights, component_scores))
        bonus = sum(i * j for i, j in list(kwargs.values())) or 0
        if bonus:
            total += bonus
            total  = self.sigmoid(total, k=8, center=50) * 100
        normalized = total / 100
        prob = self.sigmoid(normalized, center=0.5, k=8)
        return round(total, 2), round(100 - total, 2), prob

    def _headers_to_str(self, headers: dict) -> str:
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])

    # ─── Méthode principale ───────────────────────────────────────────────────

    def analyse(self, worker_result: WorkerFuzzerResult, payloads: Dict, seuil: float = 0.65) -> ResponseAnalyzerResult:
        """Analyse une réponse pour détecter une vulnérabilité."""

        result    = ResponseAnalyzerResult()
        vuln_name = worker_result.vuln_name

        # 1. Vérifications préliminaires
        if not self._validate_inputs(vuln_name, result):
            return result

        # 2. Vérification cache
        cache_key = self._get_cache_key(worker_result, vuln_name)
        if self._check_cache(cache_key, result):
            return result

        # 3. Récupération configuration
        weights, detection = self._get_vuln_config(vuln_name, payloads)
        if not weights:
            result.error = f"Vuln '{vuln_name}' non trouvée"
            return result

        # 4. Analyse des composants
        scores = self._compute_all_scores(worker_result, detection, vuln_name)

        # 5. Calcul du score total
        total, note, prob = self._calculate_total_score(weights, scores)

        # 6. Construction du résultat
        self._build_result(result, scores, total, note, prob, seuil)

        # 7. Mise en cache
        self._cache_result(cache_key, result)

        # 8. Logging debug
        self._log_debug(worker_result, scores, total, prob, seuil)

        return result

    # ─── Sous-méthodes de analyse() ───────────────────────────────────────────

    def _validate_inputs(self, vuln_name: str, result: ResponseAnalyzerResult) -> bool:
        """Valide les entrées de base."""
        if not vuln_name:
            result.error = "Nom de vulnérabilité absent"
            return False
        return True

    def _get_cache_key(self, worker_result: WorkerFuzzerResult, vuln_name: str) -> str:
        """Génère la clé de cache."""
        import hashlib
        url         = worker_result.url
        new_element = pformat(worker_result.payload.new_element)
        digest = hashlib.sha256(new_element.encode(errors="ignore")).hexdigest()
        return f"{url}|{vuln_name}|{digest}"
        # return f"{url}|{vuln_name}|{new_element}"

    def _check_cache(self, cache_key: str, result: ResponseAnalyzerResult) -> bool:
        """Vérifie le cache et met à jour le résultat si trouvé."""
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached:
            result.update_from_dict(cached)
            logger_response_analyzer.debug(f"Cache hit pour {result.vuln_name}")
            return True
        return False

    def _get_vuln_config(self, vuln_name: str, payloads: Dict) -> Tuple[List, Dict]:
        """Récupère les poids et détection pour une vulnérabilité."""
        vuln_weights = self.weights.get('vulnerability_weights', {})
        weights   = vuln_weights.get(vuln_name, {}).get("weights", [])
        detection = payloads.get(vuln_name, {}).get('detection', {})
        return weights, detection

    def _compute_all_scores(self, worker_result: WorkerFuzzerResult, detection: Dict, vuln_name: str) -> Dict[str, Any]:
        """Calcule tous les scores composants."""
        return {
            'indicators': self._compute_indicator_score(worker_result, detection, vuln_name),
            'status':     self._compute_status_score(worker_result),
            'delay':      self._compute_delay_score(worker_result, detection),
            'headers':    self._compute_headers_score(worker_result),
            'body':       self._compute_body_score(worker_result, vuln_name),
            'semantic':   self._compute_semantic_score(worker_result)
        }

    def _compute_indicator_score(self, worker_result: WorkerFuzzerResult, detection: Dict, vuln_name: str) -> Dict:
        """
        Calcule le score basé sur les indicateurs.
        
          - Passe payload_encoding à _analyse_indicators (variantes encodées)
          - Fusionne le score_reflection dans le score indicateur :
              ind + refl  → score combiné (deux signaux convergent)
              refl seul   → 90% max (pas de confirmation indicateur)
              ind seul    → score tel quel
        """
        indicators = detection.get("indicators", [])

        # Récupérer l'encodage du payload (attribut selon la version)
        payload_enc = getattr(worker_result.payload, 'encoding', None) or \
                      getattr(worker_result.payload, 'payload_encoding', None)

        # Score indicateurs dans le body
        found, score = self._analyse_indicators(
            indicators=indicators,
            body=worker_result.baseline.body or "",
            test_body=worker_result.payload_result.body or "",
            payload_encoding=payload_enc
        )

        # Score indicateurs dans les headers
        bh_str = self._headers_to_str(worker_result.baseline.headers or {})
        th_str = self._headers_to_str(worker_result.payload_result.headers or {})
        h_found, h_score = self._analyse_indicators(
            indicators=indicators,
            body=bh_str,
            test_body=th_str,
            payload_encoding=payload_enc
        )

        raw_ind_score = min(100.0, score + h_score)

        # Score réflexion
        refl_score = self._compute_reflection_score(
            payload_injected=str(worker_result.payload.payload_injected or ""),
            baseline_body=worker_result.baseline.body or "",
            test_body=worker_result.payload_result.body or "",
            vuln_name=vuln_name
        )

        # Fusion : max pondéré
        if refl_score > 0 and raw_ind_score > 0:
            combined = raw_ind_score * 0.45 + refl_score * 0.75
            final_score = min(100.0, max(combined, raw_ind_score, refl_score))
        elif refl_score > 0:
            final_score = refl_score * 0.90
        else:
            final_score = raw_ind_score

        if self.debug and refl_score > 0:
            logger_response_analyzer.debug(
                f"[indicator+reflection] vuln={vuln_name} "
                f"ind_raw={raw_ind_score:.1f} refl={refl_score:.1f} final={final_score:.1f}"
            )

        return {
            'found': {**found, **h_found},
            'score': final_score
        }

    def _compute_status_score(self, worker_result: WorkerFuzzerResult) -> Dict:
        """Calcule le score basé sur le changement de status code."""
        changed, score = self._analyse_status_code(
            worker_result.baseline.status_code,
            worker_result.payload_result.status_code
        )
        return {'changed': changed, 'score': score}

    def _compute_delay_score(self, worker_result: WorkerFuzzerResult, detection: Dict) -> Dict:
        """Calcule le score basé sur le délai de réponse."""
        time_indicator = detection.get("delay_based", False)
        min_delay      = detection.get("min_delay_seconds", -1) if time_indicator else -1

        changed, score = self._analyse_delay(
            worker_result.baseline.delay or -1,
            worker_result.payload_result.delay or -1,
            min_delay
        )
        return {'changed': changed, 'score': score}

    def _compute_headers_score(self, worker_result: WorkerFuzzerResult) -> Dict:
        """Calcule le score basé sur les changements de headers."""
        payload_str    = str(worker_result.payload.payload_injected)
        changed, score = self._analyse_headers(
            base_headers=worker_result.baseline.headers or {},
            test_headers=worker_result.payload_result.headers or {},
            payload_str=payload_str,
            normalize=True
        )
        return {'changed': changed, 'score': score}

    def _compute_body_score(self, worker_result: WorkerFuzzerResult, vuln_name: str = "__default__") -> Dict:
        """Calcule le score basé sur la taille du body. FIX v2: passe vuln_name."""
        changed, score = self._analyse_body_size(
            worker_result.baseline.body or "",
            worker_result.payload_result.body or "",
            vuln_name=vuln_name
        )
        return {'changed': changed, 'score': score}

    def _compute_semantic_score(self, worker_result: WorkerFuzzerResult) -> float:
        """Calcule le score de similarité sémantique."""
        return self.semantic_analyze(
            worker_result.baseline.body or "",
            worker_result.payload_result.body or ""
        )

    def _calculate_total_score(self, weights: List, scores: Dict) -> Tuple[float, float, float]:
        """Calcule le score total, la note et la probabilité."""
        component_scores = [
            scores['indicators']['score'],
            scores['status']['score'],
            scores['delay']['score'],
            scores['headers']['score'],
            scores['body']['score'],
            scores['semantic']
        ]
        total, note, prob = self.calculate_total_score(weights, component_scores)
        return total, note, prob

    def _build_result(self, result: ResponseAnalyzerResult, scores: Dict, total: float, note: float, prob: float, seuil: float):
        """Construit l'objet résultat."""
        result.delay_detected      = scores['delay']['changed']
        result.headers_changed     = scores['headers']['changed']
        result.status_changed      = scores['status']['changed']
        result.body_length_changed = scores['body']['changed']
        result.found_indicators    = scores['indicators']['found']
        result.score               = total
        result.note                = note
        result.prob                = prob
        result.is_vulnerable       = prob > seuil

    def _cache_result(self, cache_key: str, result: ResponseAnalyzerResult):
        """Met le résultat en cache."""
        with self._cache_lock:
            self._cache[cache_key] = result.to_dict()

    def _log_debug(self, worker_result: WorkerFuzzerResult, scores: Dict, total: float, prob: float, seuil: float):
        """Log de debug."""
        if not self.debug:
            return

        logger_response_analyzer.debug(
            f"\n{'─'*60}\n"
            f"  Vuln     : {worker_result.vuln_name}\n"
            f"  URL      : {worker_result.url}\n"
            f"Payload Type : {worker_result.payload_type}\n"
            f"  Scores   : ind={scores['indicators']['score']:.0f} | "
            f"status={scores['status']['score']:.0f} | "
            f"delay={scores['delay']['score']:.0f} | "
            f"headers={scores['headers']['score']:.0f} | "
            f"body={scores['body']['score']:.0f} | "
            f"sem={scores['semantic']:.0f}\n"
            f"  Indicateurs trouvés: {list(scores['indicators']['found'].keys())}\n"
            f"  Total    : {total:.1f}/100 | Prob: {prob:.3f} | "
            f"{'✅ VULN' if prob > seuil else '⊘ clean'}\n"
            f"{'─'*60}"
        )

    # ─── Tests unitaires ──────────────────────────────────────────────────────

    def test_analyse_contexte_cas_limites(self) -> None:
        """
        Tests unitaires pour _analyse_contexte avec cas limites.
        
        Vérifie que la détection des contextes sûrs fonctionne correctement.
        """
        logger_response_analyzer.info("\n" + "="*60)
        logger_response_analyzer.info("🧪 TEST ANALYSE CONTEXTE - CAS LIMITES")
        logger_response_analyzer.info("="*60)

        tests = [
            # CAS 1: JSON avec espaces et sauts de ligne
            {
                'name': 'JSON multiligne',
                'body': '{\n    "error": "SQL syntax \n    near SELECT"\n}',
                'indicator': 'SELECT',
                'expected': True
            },

            # CAS 2: Commentaire avec caractères spéciaux
            {
                'name': 'Commentaire avec regex chars',
                'body': '<!-- .*+?{} test -->',
                'indicator': '.*+?{}',
                'expected': True
            },

            # CAS 3: Data- avec caractères d'échappement
            {
                'name': 'Data- avec guillemets',
                'body': 'data-info="test \\"alert\\" example"',
                'indicator': 'alert',
                'expected': True
            },

            # CAS 4: Faux négatifs à éviter
            {
                'name': 'JSON dangerous key',
                'body': '{"code": "alert(\'xss\')"}',
                'indicator': 'alert',
                'expected': False  # "code" n'est pas une clé safe
            },

            # CAS 5: Échappement HTML
            {
                'name': 'HTML escaped',
                'body': '&lt;!-- SQL error --&gt;',
                'indicator': 'SQL error',
                'expected': False
            },

            # CAS 6: Commentaire dans une string JS
            {
                'name': 'Faux commentaire',
                'body': 'var msg = "<!-- not a real comment -->";',
                'indicator': 'comment',
                'expected': False
            },

            # CAS 7: JSON avec clé imbriquée
            {
                'name': 'JSON nested key',
                'body': '{"response": {"error": "SQL failed"}}',
                'indicator': 'SQL failed',
                'expected': False  # Pattern ne capture pas les clés imbriquées
            },

            # CAS 8: Commentaire mal formé
            {
                'name': 'Commentaire mal formé',
                'body': '<!-- SQL error -- >',  # Espace avant >
                'indicator': 'SQL error',
                'expected': False
            },

            # CAS 9: Data- sans guillemets
            {
                'name': 'Data- sans guillemets',
                'body': 'data-info=alert(1)',
                'indicator': 'alert',
                'expected': False  # Pattern attend des guillemets
            },

            # CAS 10: JSON avec simple quotes
            {
                'name': 'JSON simple quotes',
                'body': "{'error': 'SQL test'}",
                'indicator': 'SQL test',
                'expected': False  # Pattern attend des doubles quotes
            },

            # CAS 11: VRAI danger (doit retourner False)
            {
                'name': 'Vrai danger - HTML brut',
                'body': '<div>SQL error occurred</div>',
                'indicator': 'SQL error',
                'expected': False  # Pas dans un contexte sûr
            },

            # CAS 12: VRAI danger - script tag
            {
                'name': 'Vrai danger - script',
                'body': '<script>alert("xss")</script>',
                'indicator': 'alert',
                'expected': False  # Pas dans un contexte sûr
            },
        ]

        stats = {'total': len(tests), 'passed': 0, 'failed': 0}

        for test in tests:
            try:
                result  = self._analyse_contexte(test['body'], test['indicator'])
                success = result == test['expected']

                if success:
                    stats['passed'] += 1
                    status = '✅'
                else:
                    stats['failed'] += 1
                    status = '❌'

                logger_response_analyzer.info(f"{status} {test['name']}")
                if not success:
                    logger_response_analyzer.warning(f"   Attendu: {test['expected']}, Obtenu: {result}")

            except Exception as e:
                stats['failed'] += 1
                logger_response_analyzer.error(f"💥 {test['name']}: Exception - {e}")

        logger_response_analyzer.info("\n" + "★"*60)
        logger_response_analyzer.info("📊 RÉSUMÉ DES TESTS")
        logger_response_analyzer.info("★"*60)
        logger_response_analyzer.info(f"✅ Passés: {stats['passed']}/{stats['total']}")
        logger_response_analyzer.info(f"❌ Échoués: {stats['failed']}/{stats['total']}")
        logger_response_analyzer.info(f"📈 Taux: {stats['passed']/stats['total']*100:.1f}%")
        logger_response_analyzer.info("★"*60)


# ─── __main__ ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ra = ResponseAnalyzer(debug=True)
    print(f"Poids chargés : {len(ra.weights.get('vulnerability_weights', {}))} vulnérabilités")

    # ── Test _analyse_indicators ──────────────────────────────────────────────
    found, score = ra._analyse_indicators(
        indicators=[
            {"type": "regex",  "value": r"root:x:\d+:\d+:"},
            {"type": "string", "value": "SHLD12345"},
            {"type": "string", "value": "www-data"},
        ],
        body="Page normale",
        test_body="root:x:0:0: root:/root:/bin/bash\nSHLD12345\nwww-data:x:33:33:",
    )
    print(f"\n[Test indicators] Trouvés: {len(found)}  Score: {score:.1f}")
    for k, ctx in found.items():
        print(f"  • {k!r}  →  {ctx[:60]!r}")

    # ── Test déduplication ────────────────────────────────────────────────────
    found2, score2 = ra._analyse_indicators(
        indicators=[
            {"type": "regex",  "value": r"SHLD[A-Z0-9]{4,16}"},
            {"type": "string", "value": "shld.io"},
            {"type": "regex",  "value": r"SHLD[A-Z0-9]{4,16}"},  # doublon
            {"type": "string", "value": "shld.io"},               # doublon
        ],
        body="page propre",
        test_body="SHLDABCD1234 found on shld.io",
    )
    print(f"\n[Test dédup] Trouvés: {len(found2)}  Score: {score2:.1f}  (attendu: 2 uniques)")

    # ── Test réflexion XSS ────────────────────────────────────────────────────
    refl_xss = ra._compute_reflection_score(
        payload_injected="<script>alert('XSS')</script>",
        baseline_body="<html><body><p>Name:</p></body></html>",
        test_body="<html><body><p>Hello <script>alert('XSS')</script></p></body></html>",
        vuln_name="XSS"
    )
    print(f"\n[Test reflection XSS] Score: {refl_xss:.1f}  (attendu ≥ 90)")

    refl_xss_safe = ra._compute_reflection_score(
        payload_injected="<script>alert(1)</script>",
        baseline_body="<html><body></body></html>",
        test_body="<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
        vuln_name="XSS"
    )
    print(f"[Test reflection XSS échappé] Score: {refl_xss_safe:.1f}  (attendu = 0)")

    # ── Test body_size adaptatif ──────────────────────────────────────────────
    baseline = "A" * 5000
    sql_error = baseline + " You have an error in your SQL syntax"
    changed, bs = ra._analyse_body_size(baseline, sql_error, vuln_name="SQLi")
    print(f"\n[Test body_size SQLi] changed={changed} score={bs:.1f}  (attendu: True, >0)")

    changed_def, bs_def = ra._analyse_body_size(baseline, sql_error, vuln_name="HTTP_Request_Smuggling")
    print(f"[Test body_size défaut]  changed={changed_def} score={bs_def:.1f}  (attendu: False)")

    # ── Test indicateurs encodés ──────────────────────────────────────────────
    import base64 as b64mod
    indicator_b64 = b64mod.b64encode(b"root:x:0:0:").decode()
    found_enc, score_enc = ra._analyse_indicators(
        indicators=[{"type": "string", "value": "root:x:0:0:"}],
        body="page propre",
        test_body=f"Réponse encodée: {indicator_b64}",
        payload_encoding="base64"
    )
    print(f"\n[Test ind encodés] Trouvés: {len(found_enc)}  Score: {score_enc:.1f}  (attendu: 1)")

    # ── Test CORS ─────────────────────────────────────────────────────────────
    changes, cors_score = ra._analyse_headers(
        base_headers={"content-type": "application/json"},
        test_headers={
            "content-type": "application/json",
            "access-control-allow-origin": "https://shld-ABCD.io",
            "access-control-allow-credentials": "true",
        },
        payload_str="Origin: https://shld-ABCD.io",
    )
    print(f"\n[Test CORS] Changes: {changes}  Score: {cors_score:.1f}  (attendu ≥ 90)")

    ra.test_analyse_contexte_cas_limites()
    print(ra.weights["vulnerability_weights"].keys())