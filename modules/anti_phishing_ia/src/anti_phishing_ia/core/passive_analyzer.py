#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyseur passif pour la détection de phishing.

Ce module implémente un analyseur statique qui examine les caractéristiques
d'une URL (longueur, présence d'IP, âge du domaine, mots suspects, etc.)
pour évaluer son risque de phishing sans interagir avec le site cible.

Auteur: HOUNSOU Samuel
Version: 2.0.0 — completion, bugfixes, test method
"""

import os 
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import requests
import aiohttp
import asyncio
import difflib
import rapidfuzz
import brotli
import json
from lxml import html
from tldextract import extract
from itertools import product, combinations
from nest_asyncio import apply
from urllib.parse import urlparse
from anti_phishing_ia.phishing_utils.utils import _get_domain, _clean_url, _get_domain_age, _verify_ip_in_url, _verify_rigth_click
from anti_phishing_ia.phishing_utils.legit_domain import _get_legitimate_domain
from anti_phishing_ia.core.features_extractor import SUSPICIOUS_TLDS, SUSPICIOUS_WORDS
from cachetools import TTLCache
from anti_phishing_ia.core.config import AWAIT_TIME
from diskcache import Cache
from rapidfuzz.distance import Levenshtein as Lev


COMPARE_CACHE_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "var", "compare_domain_cache")
os.makedirs(COMPARE_CACHE_DIR, exist_ok=True)
COMPARE_CACHE = Cache(directory=COMPARE_CACHE_DIR)
COMPARE_CACHE_EXPIRE = None
# ============================================================================
# CONSTANTES POUR LA DÉTECTION D'ATTAQUES HOMOGLYPHES
# ============================================================================

SUSPICIOUS_CHARS = {
    'à', 'á', 'â', 'ã', 'ä', 'å', 'æ',
    'ç', 'è', 'é', 'ê', 'ë',
    'ì', 'í', 'î', 'ï', 'ð', 'ñ',
    'ò', 'ó', 'ô', 'õ', 'ö', 'ø',
    'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ'
}

COMMON_TYPOS = {
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's',
    '6': 'b', '7': 't', '8': 'b', '9': 'g', '€': 'e', '$': 's',
    '|': 'l', '!': 'i', '@': 'a', '#': 'h', '&': 'e', '=': 'e',
    '+': 't', '§': 's', 'µ': 'u', '¶': 'p', '¿': '?', '×': 'x',
    '÷': '+', '`': "'", '´': "'", '\u2018': "'", '\u2019': "'", '\u201c': '"',
    '\u201d': '"', '‹': '<', '›': '>', '·': '.', '•': '.', '…': '...',
    '‐': '-', '–': '-', '—': '-', '―': '-', '\u00a0': ' ', '⁄': '/',
    '≈': '~', '≠': '!=', '≤': '<=', '≥': '>=', 'À': 'a', 'Á': 'a',
    'Â': 'a', 'Ã': 'a', 'Ä': 'a', 'Å': 'a', 'à': 'a', 'á': 'a',
    'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'È': 'e', 'É': 'e',
    'Ê': 'e', 'Ë': 'e', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
    'Ì': 'i', 'Í': 'i', 'Î': 'i', 'Ï': 'i', 'ì': 'i', 'í': 'i',
    'î': 'i', 'ï': 'i', 'Ò': 'o', 'Ó': 'o', 'Ô': 'o', 'Õ': 'o',
    'Ö': 'o', 'ò': 'o', 'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o',
    'Ù': 'u', 'Ú': 'u', 'Û': 'u', 'Ü': 'u', 'ù': 'u', 'ú': 'u',
    'û': 'u', 'ü': 'u', 'Ý': 'y', 'ý': 'y', 'ÿ': 'y', 'Ç': 'c',
    'ç': 'c', 'Ñ': 'n', 'ñ': 'n', '|': 'l', '#': 'h', '+': 't',
    'ø': 'o'
}

LESS_USEFUL_TYPOS = {
    '1': 'l', '%': 'x', '*': 'x', '?': 'p', '^': 'n', '~': 'n',
    '¤': 'o', '¥': 'y', '¸': ',', 'º': 'o', '′': "'", '″': '"',
    '∂': 'd', '∆': 'D', '∏': 'P', '∑': 'S', '√': 'v', '∞': 'oo',
    '∫': 'f', '⌘': 'cmd', '⏎': 'enter', '⌫': 'backspace', '⌦': 'delete',
    '␣': 'space', '⎋': 'esc', '⇧': 'shift', '⌥': 'alt', '⌃': 'ctrl',
    '↩': 'return', '⇪': 'caps', '⏏': 'eject', '♠': 'spade', '♣': 'club',
    '♥': 'heart', '♦': 'diamond', '♩': 'note', '♪': 'note', '♫': 'notes',
    '♬': 'notes', '☀': 'sun', '☁': 'cloud', '☂': 'umbrella', '☃': 'snowman',
    '☄': 'comet', '★': 'star', '☆': 'star', '☇': 'lightning', '☈': 'thunder',
    '☉': 'sun', '☊': 'ascending', '☋': 'descending', '☌': 'conjunction',
    '☍': 'opposition', '☎': 'phone', '☏': 'phone', '☐': 'checkbox',
    '☑': 'checkbox', '☒': 'checkbox', '☓': 'x', '☔': 'umbrella',
    '☕': 'coffee', '☘': 'shamrock', '☙': 'flower', '☚': 'hand', '☛': 'hand',
    '☜': 'hand', '☝': 'hand', '☞': 'hand', '☟': 'hand', '☠': 'skull',
    '☡': 'warning', '☢': 'radioactive', '☣': 'biohazard', '☤': 'caduceus',
    '☥': 'ankh', '☦': 'cross', '☧': 'chi-rho', '☨': 'cross', '☩': 'cross',
    '☪': 'star-crescent', '☫': 'farsi', '☬': 'khanda', '☭': 'hammer-sickle',
    '☮': 'peace', '☯': 'yin-yang', '☰': 'trigram', '☱': 'trigram',
    '☲': 'trigram', '☳': 'trigram', '☴': 'trigram', '☵': 'trigram',
    '☶': 'trigram', '☷': 'trigram', '☸': 'dharma', '☹': 'frown',
    '☺': 'smile', '☻': 'smile', '☼': 'sun', '☽': 'moon', '☾': 'moon',
    '☿': 'mercury', '♀': 'female', '♁': 'earth', '♂': 'male', '♃': 'jupiter',
    '♄': 'saturn', '♅': 'uranus', '♆': 'neptune', '♇': 'pluto', '♈': 'aries',
    '♉': 'taurus', '♊': 'gemini', '♋': 'cancer', '♌': 'leo', '♍': 'virgo',
    '♎': 'libra', '♏': 'scorpio', '♐': 'sagittarius', '♑': 'capricorn',
    '♒': 'aquarius', '♓': 'pisces', '€': 'e', '™': 'tm', '⅓': '1/3',
    '⅔': '2/3', '⅛': '1/8', '⅜': '3/8', '⅝': '5/8', '⅞': '7/8', '←': '<-',
    '↑': '^', '→': '->', '↓': 'v', '↔': '<->', '↕': 'v', 'ø': 'O'
}

# Regroupement des deux dictionnaires pour la correction de typos
TYPOS = [COMMON_TYPOS, LESS_USEFUL_TYPOS]


# ============================================================================
# FONCTIONS DE COMPARAISON DE DOMAINES (TYPOSQUATTING)
# ============================================================================

def product_combine(uniques, multiples, n):
    """
    Génère des combinaisons de corrections pour les caractères typographiques.

    Cette fonction est utilisée par _character_similarity pour essayer
    toutes les combinaisons possibles de remplacement de caractères
    lorsqu'un domaine contient plusieurs caractères suspects.

    Args:
        uniques (list): Liste de tuples (caractère_incorrect, caractère_correct)
                        pour les caractères qui apparaissent une seule fois
        multiples (list): Liste de tuples pour les caractères apparaissant
                          plusieurs fois dans le domaine
        n (int): Nombre de caractères à corriger parmi 'multiples'

    Yields:
        tuple: Combinaison de corrections (caractère_incorrect, caractère_correct)

    Example:
        >>> list(product_combine([('0','o')], [('1','i'),('1','i')], 2))
        # Génère des combinaisons pour remplacer les '1' par 'i'
    """
    for u, combo in product(uniques, combinations(multiples, n-1)):
        yield (u, *combo)


def _character_similarity(domain: str, legit_domain: str) -> float:
    """
    Calcule la similarité entre deux domaines en corrigeant les typos courants.

    Cette fonction tente de remplacer les caractères typographiques
    (comme '0' → 'o', '1' → 'l', caractères accentués, etc.) pour voir
    si le domaine suspect peut être ramené à un domaine légitime.

    Args:
        domain (str): Domaine suspect à analyser
        legit_domain (str): Domaine légitime de référence

    Returns:
        float: 1.0 si les domaines sont identiques après correction,
               0.0 sinon (ou si aucune correction n'est possible)

    Examples:
        >>> _character_similarity('g00gle.com', 'google.com')
        1.0
        >>> _character_similarity('paypa1.com', 'paypal.com')
        1.0
        >>> _character_similarity('google.com', 'google.com')
        0.0
    """
    if domain == legit_domain:
        return 0.0
    
    LIS = []
    LIS_ = []
    for typos in TYPOS:
        _li = [k for k in typos.keys() if k in domain]
        tup = [(k, typos[k]) for k in _li]
        LIS.extend(tup)
        LIS_ = [k for k, _ in LIS]
    one = [k for k in LIS if LIS_.count(k[0]) == 1]
    multiple = [k for k in LIS if LIS_.count(k[0]) > 1]

    if one and multiple:
        modified = domain
        for wrong, true in one:
            modified = modified.replace(wrong, true)
            if modified == legit_domain:
                return 1.0
        for r in range(1, len(multiple) + 2):
            for combi in product_combine(one, multiple, r):
                modified = domain
                for wrong, true in combi:
                    modified = modified.replace(wrong, true)
                if modified == legit_domain:
                    return 1.0

    elif one and not multiple:
        modified = domain
        for wrong, true in one:
            modified = modified.replace(wrong, true)
            if modified == legit_domain:
                return 1.0
        for r in range(1, len(one) + 2):
            for combi in combinations(one, r):
                modified = domain
                for wrong, true in combi:
                    modified = modified.replace(wrong, true)
                if modified == legit_domain:
                    return 1.0

    elif multiple and not one:
        for r in range(1, len(multiple) + 1):
            for combi in combinations(multiple, r):
                modified = domain
                for wrong, true in combi:
                    modified = modified.replace(wrong, true)
                if modified == legit_domain:
                    return 1.0
    return 0.0


def _compare(domain: str, candidates: list):
    best_score = 0
    _dom = ""
    for dom in candidates:
        if dom == domain:
            return 0.0, dom
        ratio_difflib = difflib.SequenceMatcher(None, dom, domain).ratio()
        ratio_chars = _character_similarity(domain, dom)
        ratio_lev = Lev.normalized_similarity(domain, dom)
        ratio_fuzz = rapidfuzz.fuzz.ratio(domain, dom) / 100.0
        # ratio = 0.2 * ratio_difflib + 0.4 * ratio_chars + 0.4 * ratio_fuzz
        ratio = sum((0.8 / 3) * x for x in (ratio_chars, ratio_fuzz, ratio_lev)) + 0.2 * ratio_difflib 
        if ratio > best_score:
            best_score = ratio
            _dom = dom
    return best_score, _dom

def compare(url: str) -> tuple:
    """
    Compare une URL suspecte avec la liste des domaines légitimes.

    Utilise une combinaison de trois métriques :
    - difflib (similarité séquentielle)
    - correction de typos (caractères typographiques)
    - rapidfuzz (algorithme de similarité rapide)

    Args:
        url (str): URL à analyser (peut être suspecte)

    Returns:
        tuple: (score, domaine_le_plus_proche)
            - score (float): entre 0 et 1, plus il est élevé plus l'URL
              ressemble à un domaine légitime. 0 = correspondance exacte.
            - domaine_le_plus_proche (str): Domaine légitime le plus proche

    Examples:
        >>> compare('https://gooogle.com/login')
        (0.85, 'google.com')
        >>> compare('https://google.com')
        (0.0, 'google.com')
    """
    url = _clean_url(url)
    if not url or not isinstance(url, str):
        return 0.0, "", True
    
    url = url.strip()
    domain = _get_domain(url, False)
    if COMPARE_CACHE.get(domain, default=None):
        return tuple(COMPARE_CACHE.get(domain))
    
    SAME_LEN = _get_legitimate_domain().get_similar_length_domains(domain, ratio=0.3, method="sqlmodel")
    
    best_score, _dom = _compare(domain, SAME_LEN)
    COMPARE_CACHE.set(
        key=domain,
        value=[best_score, _dom],
        expire=COMPARE_CACHE_EXPIRE,
    )
    return best_score, _dom


# ============================================================================
# CLASSE PRINCIPALE : PassiveAnalyzer
# ============================================================================

class PassiveAnalyzer:
    """
    Analyseur passif pour la détection de phishing.

    Cette classe examine les caractéristiques statiques d'une URL
    (longueur, présence d'IP, âge du domaine, mots suspects, TLDs bizarres,
    etc.) pour évaluer son risque de phishing sans interagir avec le site.

    L'analyse se fait en plusieurs étapes :
    1. Vérification en whitelist (domaine connu légitime → safe direct)
    2. Vérification en blacklist externe (optionnelle)
    3. Analyse de 18 critères différents (âge, typosquatting, mots suspects, etc.)
    4. Calcul d'un score de risque (0-100+)
    5. Décision finale avec seuils

    Attributes:
        SUSPICIOUS_WORDS (list): Mots clés suspects (login, verify, account, etc.)
        SUSPICIOUS_TLDS (list): TLDs souvent utilisés pour le phishing
        SUSPICIOUS_CHARS (set): Caractères Unicode pouvant servir d'homoglyphes
        LEGITIMATE_DOMAINS (list): Base de domaines légitimes connus
        BRAND_KEYWORDS (list): Noms de marques surveillées pour usurpation
        black_cache (TTLCache): Cache pour les résultats de blacklist

    Example:
        >>> analyzer = PassiveAnalyzer()
        >>> import asyncio
        >>> result = asyncio.run(analyzer.analyze('https://paypal-verify.tk'))
        >>> print(result[0])  # Niveau de risque
        '⚠️ MOYEN'
        >>> print(result[1])  # Score
        45
    """

    __author__ = "Samuel HOUNSOU, 17 ans"
    __version__ = "2.0.0"

    BRAND_KEYWORDS = ['paypal', 'microsoft', 'apple', 'amazon',
                      'netflix', 'facebook', 'google', 'instagram',
                      'twitter', 'linkedin', 'whatsapp', 'telegram']
    
    def __init__(self):
        """
        Initialise l'analyseur passif.

        Configure les listes de mots suspects, TLDs suspects,
        caractères homoglyphes, et initialise le cache pour la blacklist.
        """
        self.SUSPICIOUS_WORDS = SUSPICIOUS_WORDS
        self.SUSPICIOUS_TLDS = SUSPICIOUS_TLDS
        self.SUSPICIOUS_CHARS = SUSPICIOUS_CHARS
        self.LEGITIMATE_DOMAINS = _get_legitimate_domain()
        self.black_cache = TTLCache(maxsize=1000, ttl=60 * 10)  # Cache 10 minutes

    def compare(self, url: str) -> tuple:
        """
        Alias de la fonction compare pour compatibilité avec l'API.

        Compare une URL suspecte avec la liste des domaines légitimes.

        Args:
            url (str): URL à analyser

        Returns:
            tuple: (score, domaine_le_plus_proche) où score est entre 0 et 1
        """
        return compare(url)

    async def get_domain_age(self, url: str, *args, **kwargs) -> int:
        """
        Récupère l'âge du domaine en jours de manière asynchrone.

        Args:
            url (str): URL à analyser
            *args, **kwargs: Arguments passés à _get_domain_age

        Returns:
            int: Âge en jours, -1 si non trouvé, -2 si erreur
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_get_domain_age, url, *args, **kwargs),
                AWAIT_TIME
            )
        except Exception:
            return -2

    async def verify_black_list(self, url: str) -> dict:
        """
        Vérifie si un domaine est présent dans une blacklist externe.

        Utilise l'API PhishDestroy (https://api.destroy.tools) pour
        vérifier si le domaine est connu comme malveillant.

        Les résultats sont mis en cache pendant 10 minutes.

        Args:
            url (str): URL à vérifier

        Returns:
            dict: Contenant les clés :
                - phishing (bool): True si le domaine est blacklisté
                - source (str): Nom de la source (toujours "PhishDestroy")
                - risk_score (int): Score de risque (0-100)
                - severity (str): Niveau de sévérité ("none", "low", "medium", "high")

        Example:
            >>> async def test():
            ...     analyzer = PassiveAnalyzer()
            ...     result = await analyzer.verify_black_list('https://paypal-verify.tk')
            ...     print(result['phishing'])
            True
        """
        cached = self.black_cache.get(url)
        if cached:
            return cached
    
        result = {"phishing": False, "source": "PhishDestroy"}
        domain = _get_domain(url, clean=False)
        if not domain:
            return result
    
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.destroy.tools/v1/check",
                    params={"domain": domain},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        raw = await response.read()
                        # json_result = await response.json()
                        ce = response.headers.get('Content-Encoding', response.headers.get('content-encoding'))
                        if ce == 'br':
                            raw = brotli.decompress(raw)
                        json_result = json.loads(raw)
                        result = {
                            "phishing": bool(json_result.get("threat", False)),
                            "source": "PhishDestroy",
                            "risk_score": json_result.get("risk_score", 0),
                            "severity": json_result.get("severity", "none"),
                        }
                        self.black_cache[url] = result
        except Exception as e:
            print("Erreur dans verify_black_list :", str(e))
    
        return result

    async def analyze(
        self,
        url: str,
        check_blacklist: bool = False,
        check_right_click: bool = False
    ) -> tuple:
        """
        Analyse complète d'une URL pour détecter le phishing.

        Cette méthode examine 18 critères différents :
        1. Âge du domaine
        2. Usurpation de marque
        3. Punycode/homoglyphes
        4. Caractère @
        5. Adresse IP dans l'URL
        6. Hostname invalide
        7. Clic droit désactivé
        8. Typosquatting
        9. Mots suspects
        10. Sous-domaines excessifs
        11. Port non standard
        12. TLD suspect
        13. Tirets multiples
        14. Double slash suspect
        15. URL trop longue
        16. Redirections excessives
        17. Frames avec frameborder=0
        18. Caractères suspects dans le domaine

        Args:
            url (str): URL à analyser
            check_blacklist (bool): Si True, vérifie les blacklists externes
            check_right_click (bool): Si True, vérifie si le clic droit est désactivé

        Returns:
            tuple: (label, risk_score, is_phishing, flags)
                - label (str): Niveau de risque
                    "✅ NÉGLIGEABLE" | "📊 FAIBLE" | "📊 MOYEN" | "⚠️ ÉLEVÉ" | "🚨 CRITIQUE"
                - risk_score (int): Score brut (0-100+, peut dépasser 100)
                - is_phishing (bool): True si considéré comme phishing
                - flags (list): Liste de tuples (message, points_attribués)

        Example:
            >>> import asyncio
            >>> analyzer = PassiveAnalyzer()
            >>> label, score, is_phish, flags = asyncio.run(
            ...     analyzer.analyze('https://paypal-verify.tk')
            ... )
            >>> print(f"Score: {score}, Phishing: {is_phish}")
            Score: 45, Phishing: False
        """
        url = _clean_url(url)
        if not url:
            return "📊 FAIBLE", 0, False, []

        domain = _get_domain(url, clean=False)

        # Domaine parfaitement connu → safe immédiatement
        domain_is_safe = domain in self.LEGITIMATE_DOMAINS
        if domain_is_safe:
            return "📊 FAIBLE", 0, False, []

        # Blacklist check en priorité (retour immédiat si positif)
        if check_blacklist:
            v_result = await self.verify_black_list(url)
            if v_result['phishing']:
                return "🚨 CRITIQUE", 200, True, [
                    (f"🚨 Blacklisté par source fiable ({v_result['source']})", 200)
                ]

        risk_score = 0
        flags = []
        extracted = extract(url)
        parse = urlparse(url)

        # Fetch HTTP (body nécessaire pour plusieurs checks)
        body = ""
        response_obj = None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=AWAIT_TIME),
                    allow_redirects=True
                ) as resp:
                    body = await resp.text()
                    # on reconstruit un objet minimal pour garder response_obj.history
                    response_obj = resp
        except Exception:
            flags.append(("📊 Impossible de joindre l'URL (timeout/erreur réseau)", 0))
        
        def add(msg: str, risk_points: int, level: str = "⚠️"):
            """
            Ajoute un flag et incrémente le score de risque.

            Args:
                msg (str): Message descriptif du flag
                risk_points (int): Points à ajouter au score
                level (str): Niveau d'importance ("✅", "📊", "⚠️", "🚨")
            """
            nonlocal risk_score
            risk_score += risk_points
            flags.append((f"{level} {msg}", risk_points))

        # ── 1. AGE DU DOMAINE ───────────────────────────────────────────────
        age = await self.get_domain_age(url, is_domain=False, clean=False)
        if age is not None and age != -2:
            if age == 0:
                add("DOMAINE INEXISTANT - risque très élevé", 35, "🚨")
            elif age > 730:
                add("Domaine ancien (> 2 ans) - forte confiance", -20, "✅")
            elif age > 365:
                add("Domaine établi (> 1 an)", -15, "✅")
            elif age > 180:
                add("Domaine mature (> 6 mois)", -8, "✅")
            elif age < 7:
                add("Domaine créé il y a moins d'1 SEMAINE", 35, "🚨")
            elif age < 30:
                add("Domaine TRÈS RÉCENT (< 1 mois)", 28, "🚨")
            elif age < 90:
                add("Domaine récent (< 3 mois)", 18, "⚠️")
        # ── 2. USURPATION DE MARQUE ─────────────────────────────────────────
        for brand in self.BRAND_KEYWORDS:
            if brand in domain.lower() and not domain_is_safe:
                add(f"Utilisation suspecte de la marque '{brand}'", 25, "🚨")
                break

        # ── 3. PUNYCODE / HOMOGLYPHE ─────────────────────────────────────────
        if "xn--" in domain.lower():
            add("PUNICODE - Attaque homoglyphe confirmée", 52, "🚨")

        # ── 4. CARACTÈRE @ ──────────────────────────────────────────────────
        if "@" in url:
            add("CARACTÈRE @ - Technique d'obfuscation", 52, "🚨")

        # ── 5. IP DANS L'URL ─────────────────────────────────────────────────
        if _verify_ip_in_url(url, False):
            add("ADRESSE IP DANS L'URL - Masquage avancé", 55, "🚨")

        # ── 6. HOSTNAME INVALIDE ─────────────────────────────────────────────
        if parse.hostname is None:
            add("URL sans hostname valide - Structure suspecte", 25, "⚠️")

        # ── 7. CLIC DROIT DÉSACTIVÉ ──────────────────────────────────────────
        if check_right_click and body:
            if _verify_rigth_click(body, True):
                add("Clic droit désactivé - technique anti-inspection courante", 18, "⚠️")

        # ── 8. SIMILARITÉ TYPOSQUATTING ──────────────────────────────────────
        if not domain_is_safe:
            result_compare = compare(url)
            score_sim, legit_match = result_compare[0], result_compare[1]
            if score_sim >= 0.48:
                add(
                    f"Domaine ressemblant ({score_sim:.2f}) à un domaine connu "
                    f"({domain} (suspect) vs {legit_match} (légitime))",
                    60, "⚠️"
                )

        # ── 9. MOTS SUSPECTS ─────────────────────────────────────────────────
        suspicious_words_found = []
        if not domain_is_safe:
            for word in self.SUSPICIOUS_WORDS:
                if word in url.lower():
                    suspicious_words_found.append(word)

        if suspicious_words_found:
            count = len(suspicious_words_found)
            if count >= 4:
                add(
                    f"COMBINAISON CRITIQUE: {count} mots suspects "
                    f"({', '.join(suspicious_words_found[:3])}...)",
                    35, "🚨"
                )
            elif count >= 3:
                add(f"Multiples mots suspects: {count} termes détectés", 25, "⚠️")
            elif count >= 2:
                add(f"Plusieurs mots suspects: {count} termes", 18, "⚠️")
            else:
                add(f"Mot suspect détecté: '{suspicious_words_found[0]}'", 10, "📊")

        # ── 10. SOUS-DOMAINES EXCESSIFS ──────────────────────────────────────
        subdomain_count = len([sd for sd in extracted.subdomain.split('.') if sd])
        if subdomain_count > 4:
            add(
                f"Structure COMPLEXE: {subdomain_count} sous-domaines - possible déguisement",
                20, "⚠️"
            )
        elif subdomain_count > 2:
            add(f"Structure multiple: {subdomain_count} sous-domaines", 12, "📊")

        # ── 11. PORT NON STANDARD ────────────────────────────────────────────
        if parse.port is not None and parse.port not in [80, 443]:
            add(
                f"Port non standard ({parse.port}) - comportement inhabituel",
                15, "⚠️"
            )

        # ── 12. TLD SUSPECT ──────────────────────────────────────────────────
        if any(tld in domain for tld in self.SUSPICIOUS_TLDS):
            add("TLD suspect (.tk, .ml, .cf, .ga, .gq) - souvent abusé", 30, "⚠️")

        # ── 13. TIRETS MULTIPLES ─────────────────────────────────────────────
        if domain.count("-") >= 2 and not domain_is_safe:
            add("Tirets multiples dans le domaine - possible typosquatting", 8, "📊")

        # ── 14. DOUBLE SLASH SUSPECT ─────────────────────────────────────────
        if url.find('//') >= 7:
            add("Double slash suspect dans l'URL - structure anormale", 6, "📊")

        # ── 15. URL TROP LONGUE ──────────────────────────────────────────────
        url_len = len(url)
        if url_len >= 100:
            add(f"URL très longue ({url_len} caractères) - dissimulation probable", 20, "⚠️")
        elif url_len >= 72:
            add(f"URL longue ({url_len} caractères) - structure suspecte", 10, "📊")

        # ── 16. REDIRECTIONS EXCESSIVES ──────────────────────────────────────
        if response_obj is not None:
            n_redirects = len(response_obj.history)
            if n_redirects > 5:
                add(f"Redirections excessives ({n_redirects}) - masquage de destination", 25, "🚨")
            elif n_redirects > 3:
                add(f"Redirections multiples ({n_redirects}) - comportement suspect", 15, "⚠️")
            elif n_redirects > 1:
                add(f"Redirections détectées ({n_redirects})", 5, "📊")

        # ── 17. FRAMES AVEC FRAMEBORDER=0 ────────────────────────────────────
        if body:
            try:
                tree = html.fromstring(body)
                frames = tree.xpath("//frame | //iframe")
                suspicious_frames = [
                    f for f in frames
                    if str(f.get("frameBorder", f.get("frameborder", "1"))) == "0"
                ]
                if suspicious_frames:
                    add(
                        f"Frame(s) avec frameBorder=0 détectée(s) ({len(suspicious_frames)}) "
                        "- technique de clonage de page",
                        22, "⚠️"
                    )
            except Exception:
                pass

        # ── 18. CARACTÈRES SUSPECTS DANS LE DOMAINE ──────────────────────────
        suspicious_chars_found = [c for c in domain if c in self.SUSPICIOUS_CHARS]
        if suspicious_chars_found:
            add(
                f"Caractères suspects dans le domaine: {set(suspicious_chars_found)} "
                "- possible attaque homoglyphe",
                30, "🚨"
            )

        # ── LABEL FINAL (seuils de décision) ─────────────────────────────────
        risk_score = max(0, min(100, risk_score))

        # Seuils de décision
        if risk_score >= 55:
            risk_level = "🚨 CRITIQUE"
            is_phishing = True
        elif risk_score >= 35:
            risk_level = "⚠️ ÉLEVÉ"
            is_phishing = True
        elif risk_score >= 20:
            risk_level = "📊 MOYEN"
            is_phishing = False
        elif risk_score >= 10:
            risk_level = "📊 FAIBLE"
            is_phishing = False
        else:
            risk_level = "✅ NÉGLIGEABLE"
            is_phishing = False
            
        return risk_level, risk_score, is_phishing, flags

    # ═══════════════════════════════════════════════════════════════════════════
    # MÉTHODE DE TEST STATIQUE
    # ═══════════════════════════════════════════════════════════════════════════

    @staticmethod
    async def test(urls: list[tuple] | None = None, verbose: bool = True) -> dict:
        """
        Teste le PassiveAnalyzer sur une liste d'URLs avec labels attendus.

        Cette méthode statique permet de valider les performances de
        l'analyseur passif en calculant les métriques de classification :
        - True Positives (TP)
        - False Positives (FP)
        - True Negatives (TN)
        - False Negatives (FN)
        - Précision, Rappel, F1-Score, Accuracy

        Args:
            urls (list[tuple] | None): Liste de tuples (url, label_attendu)
                label_attendu : "phishing" | "safe"
                Si None, utilise le jeu de test interne (50+ URLs)
            verbose (bool): Affiche le détail de chaque analyse

        Returns:
            dict: Métriques de performance contenant :
                - tp (int): True Positives
                - fp (int): False Positives
                - tn (int): True Negatives
                - fn (int): False Negatives
                - precision (float): Précision (TP / (TP + FP))
                - recall (float): Rappel (TP / (TP + FN))
                - f1 (float): Score F1 (moyenne harmonique)
                - accuracy (float): Exactitude ((TP + TN) / Total)
                - results (list): Détails de chaque test

        Example:
            >>> import asyncio
            >>> results = asyncio.run(PassiveAnalyzer.test(verbose=False))
            >>> print(f"F1-Score: {results['f1']:.2%}")
            F1-Score: 94.5%
        """
        DEFAULT_TEST_URLS = [
            # ── 🚨 CLAIREMENT MALVEILLANTES ──────────────────────────────────
            ("http://paypa1-secure-login.tk/account/verify",            "phishing"),
            ("http://192.168.1.1/login.php",                            "phishing"),
            ("http://xn--pple-43d.com/signin",                          "phishing"),
            ("http://secure-amazon-account.ml/update",                  "phishing"),
            ("http://login.microsoft.secure-verify.xyz/password",       "phishing"),
            ("http://g00gle-support.cf/authenticate",                   "phishing"),
            ("http://paypal.com.evil-domain.net/signin",                "phishing"),
            ("http://145.236.15.12/login.php",                          "phishing"),
            ("https://paypal-verification-security.com/account/update", "phishing"),
            ("http://0xDEADBEEF.malicious-site.net/auth",               "phishing"),
            ("https://facebook.com@phishing-domain.ru/login",           "phishing"),
            ("https://xn--mcrosoft-8g0a.com/security/",                 "phishing"),
            ("https://apple-id-verification.center/",                   "phishing"),
            # ── ⚠️ ZONES GRISES (suspectes) ──────────────────────────────────
            ("https://secure-login-bank-account.xyz/",                  "phishing"),
            ("http://password-reset-verification.tk/",                  "phishing"),
            ("https://microsoft-account-confirm.cf/",                   "phishing"),
            ("https://amazon-payment-update.gq/",                       "phishing"),
            ("https://netflix-billing-info.ml/",                        "phishing"),
            # ── 🔍 LÉGITIMES ATYPIQUES ────────────────────────────────────────
            ("https://client-login.entreprise-locale.fr/",              "safe"),
            ("http://sso.internal-company.net/",                        "safe"),
            ("https://auth.staging-startup.io/",                        "safe"),
            ("https://verify.new-fintech-app.com/",                     "safe"),
            # ── ✅ CLAIREMENT LÉGITIMES ───────────────────────────────────────
            ("https://www.google.com",                                  "safe"),
            ("https://www.github.com/login",                            "safe"),
            ("https://wikipedia.org/wiki/Phishing",                     "safe"),
            ("https://www.amazon.com/",                                 "safe"),
            ("https://stackoverflow.com/questions",                     "safe"),
            ("https://login.microsoftonline.com/",                      "safe"),
            ("https://accounts.google.com/",                            "safe"),
            ("https://www.paypal.com/signin/",                          "safe"),
            ("https://github.com/login",                                "safe"),
            ("https://www.linkedin.com/checkpoint/lg/login/",           "safe"),
            # ── 🌐 IDN / INTERNATIONALES ─────────────────────────────────────
            ("https://сайт-банка.рф/",                                  "phishing"),
            ("https://支付宝-验证.中国/",                                   "phishing"),
            ("https://bücher.example.com/",                             "safe"),
            # ── 🔧 TECHNIQUES LÉGITIMES ──────────────────────────────────────
            ("https://api.stripe.com/v1/oauth/authorize",               "safe"),
            ("https://auth0.com/login/",                                 "safe"),
            ("https://dashboard.heroku.com/oauth/authorize",            "safe"),
            # ── 📱 MOBILES / SERVICES LÉGITIMES ──────────────────────────────
            ("https://m.facebook.com/login.php",                        "safe"),
            ("https://mobile.twitter.com/login",                        "safe"),
            ("https://booking.hotel-bellevue.fr/secure/payment",        "safe"),
        ]

        test_set = urls or DEFAULT_TEST_URLS
        analyzer = PassiveAnalyzer()

        tp = fp = tn = fn = 0
        results = []

        print("\n" + "=" * 70)
        print("  🔬 TEST PassiveAnalyzer")
        print("=" * 70)

        for url, expected in test_set:
            try:
                label, score, is_phishing, flaglist = await analyzer.analyze(
                    url,
                    check_blacklist=True,
                    check_right_click=False
                )
                predicted = "phishing" if is_phishing else "safe"
                correct = predicted == expected

                if expected == "phishing" and predicted == "phishing":
                    tp += 1
                    status = "✅ TP"
                elif expected == "safe" and predicted == "safe":
                    tn += 1
                    status = "✅ TN"
                elif expected == "safe" and predicted == "phishing":
                    fp += 1
                    status = "❌ FP"
                else:
                    fn += 1
                    status = "❌ FN"

                results.append({
                    "url": url,
                    "expected": expected,
                    "predicted": predicted,
                    "label": label,
                    "score": score,
                    "correct": correct,
                    "status": status,
                    "flags": flaglist
                })

                if verbose:
                    print(f"\n{'─'*70}")
                    print(f"  URL      : {url[:65]}{'...' if len(url) > 65 else ''}")
                    print(f"  Attendu  : {expected:<10} | Prédit : {predicted:<10} | {status}")
                    print(f"  Score    : {score} | Label : {label}")
                    if flaglist:
                        print(f"  Flags ({len(flaglist)}):")
                        for msg, pts in flaglist:
                            print(f"    {msg}  [{'+' if pts >= 0 else ''}{pts}]")

            except Exception as e:
                print(f"\n  ⚠️ Erreur sur {url} : {e}")

        # ── MÉTRIQUES ────────────────────────────────────────────────────────
        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy  = (tp + tn) / total if total > 0 else 0.0

        print(f"\n{'=' * 70}")
        print("  📊 RÉSULTATS")
        print(f"{'=' * 70}")
        print(f"  Total    : {total} URLs")
        print(f"  TP       : {tp}  |  TN : {tn}  |  FP : {fp}  |  FN : {fn}")
        print(f"  Accuracy : {accuracy * 100:.1f}%")
        print(f"  Precision: {precision * 100:.1f}%")
        print(f"  Recall   : {recall * 100:.1f}%")
        print(f"  F1 Score : {f1 * 100:.1f}%")
        print("=" * 70 + "\n")

        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "results": results
        }


if __name__ == "__main__":
    apply()
    import time
    asyncio.run(PassiveAnalyzer.test(verbose=True))
    # st = time.time()
    # print(compare('https://kagGGle.com/login'))
    # print("Elapsed", time.time() - st)
    