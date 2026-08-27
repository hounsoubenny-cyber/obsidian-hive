#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilities pour l'analyse anti-phishing.

Ce module contient les fonctions de base pour le nettoyage d'URL,
l'extraction de domaine, la vérification IP, l'analyse WHOIS,
et le parsing de formulaires HTML.

Auteur: HOUNSOU Samuel
Version: 2.0.0
"""

import os 
import sys
import math
import ssl
import whois
import socket
import aiohttp
import re
from tldextract import extract
from datetime import datetime, timezone
from collections import Counter
from urllib.parse import urlparse
from lxml import html

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
from modules_utils.ip_type_utils import get_ip_type as __get_ip_type


def _clean_url(url: str) -> str:
    """
    Nettoie et normalise une URL brute.

    Cette fonction supprime les espaces, guillemets et caractères parasites,
    puis ajoute le protocole https:// si absent.

    Args:
        url (str): URL brute potentiellement mal formatée

    Returns:
        str: URL nettoyée avec protocole, ou chaîne vide si entrée invalide

    Examples:
        >>> _clean_url('  "google.com"  ')
        'https://google.com'
        >>> _clean_url('https://paypal.com/login')
        'https://paypal.com/login'
        >>> _clean_url('')
        ''
    """
    if url is None:
        return ""
    url = url.strip().strip("'\",;").strip()
    if not url.startswith(('http://', 'https://')):
        if url.startswith(':/'):
            url = 'https' + url
        else:
            url = 'https://' + url
    return url


def _get_domain(url: str, clean: bool = False) -> str:
    """
    Extrait le nom de domaine principal d'une URL.

    Args:
        url (str): URL à analyser
        clean (bool): Si True, nettoie l'URL avec _clean_url() d'abord

    Returns:
        str: Domaine extrait (ex: 'google.com'), ou chaîne vide si échec

    Examples:
        >>> _get_domain('https://mail.google.com/login')
        'google.com'
        >>> _get_domain('http://192.168.1.1/login')
        '192.168.1.1'
        >>> _get_domain('https://www.paypal.com/signin', clean=True)
        'paypal.com'
    """
    if clean:
        url = _clean_url(url)
        
    if not url:
        return ""
    
    parse = urlparse(url)
    extracted = extract(url)
    hostname = parse.hostname or ""
    
    if hostname and all(c.isdigit() for c in hostname if c not in ":."):
        return hostname  # IP address
    
    domain = f"{extracted.domain}{('.' + extracted.suffix) if extracted.suffix else ''}"
    return domain or None

def _get_domain_age(url_or_domain: str, is_domain: bool = False, clean: bool = False) -> int:
    """
    Calcule l'âge d'un domaine en jours depuis sa création.

    Utilise l'API WHOIS pour récupérer la date de création du domaine.

    Args:
        url_or_domain (str): URL complète ou nom de domaine
        is_domain (bool): Si True, l'entrée est déjà un domaine (pas besoin d'extraire)
        clean (bool): Si True, nettoie l'URL avant extraction

    Returns:
        int: Âge en jours, -1 si non trouvé, -2 si erreur réseau/WHOIS

    Examples:
        >>> _get_domain_age('google.com', is_domain=True)  # retourne ~8000
        8000
        >>> _get_domain_age('https://site-récent.fr')  # retourne ~30
        30
        >>> _get_domain_age('domaine-inexistant.xyz')  # retourne -1
        -1
    """
    try:
        if not is_domain:
            domain = _get_domain(url_or_domain, clean)
        else:
            domain = url_or_domain
        
        if not domain:
            return -1
        
        domain_age = whois.query(domain)
        if domain_age:
            cdate = domain_age.creation_date
            if not cdate:
                return -1
            if isinstance(cdate, list):
                cdate = cdate[0]
            return (datetime.now().astimezone(tz=timezone.utc) - cdate.astimezone(tz=timezone.utc)).days
    
    except Exception as e:
        print("Erreur dans _get_domain_age :", str(e))
        return -2


def _get_ip(url_or_domain: str, is_domain: bool = False, clean: bool = False) -> str:
    """
    Résout un domaine ou une URL en adresse IP.

    Args:
        url_or_domain (str): URL ou nom de domaine
        is_domain (bool): Si True, l'entrée est déjà un domaine
        clean (bool): Si True, nettoie l'URL avant extraction

    Returns:
        str: Adresse IP au format string, ou '-1.-1.-1.-1' si erreur

    Examples:
        >>> _get_ip('google.com', is_domain=True)
        '142.250.185.46'
        >>> _get_ip('https://paypal.com')
        '64.18.0.4'
    """
    try:
        if not is_domain:
            domain = _get_domain(url_or_domain, clean)
        else:
            domain = url_or_domain
        
        if not domain:
            return "-1.-1.-1.-1"
        
        return socket.gethostbyname(domain)
    
    except Exception as e:
        print("Erreur dans _get_ip :", str(e))
        return "-2.-2.-2.-2"


def _get_ip_type(url_or_domain: str, is_domain: bool = False, clean: bool = False) -> str:
    """
    Détermine le type d'adresse IP (IPv4 ou IPv6) d'un domaine.

    Args:
        url_or_domain (str): URL ou nom de domaine
        is_domain (bool): Si True, l'entrée est déjà un domaine
        clean (bool): Si True, nettoie l'URL avant extraction

    Returns:
        str: 'ipv4', 'ipv6', ou 'error' si non résolu

    Examples:
        >>> _get_ip_type('google.com', is_domain=True)
        'ipv4'
    """
    ip = _get_ip(url_or_domain, is_domain, clean)
    return __get_ip_type(ip)


def _get_tls(url: str, clean: bool = False, timeout: int = 5) -> dict:
    """
    Récupère les informations TLS/SSL d'une URL (certificat, expiration, SAN).

    Établit une connexion socket sécurisée pour extraire les métadonnées
    du certificat SSL.

    Args:
        url (str): URL à analyser
        clean (bool): Si True, nettoie l'URL d'abord
        timeout (int): Timeout de connexion en secondes

    Returns:
        dict: Informations TLS avec les clés:
            - hostname (str): Nom d'hôte
            - port (int): Port utilisé (443 par défaut)
            - cert_subject (dict): Sujet du certificat
            - notAfter (str): Date d'expiration
            - notBefore (str): Date de début de validité
            - age (int): Âge du certificat en jours
            - days_before_expiration (int): Jours avant expiration
            - san (list): Subject Alternative Names

    Examples:
        >>> _get_tls('https://google.com')
        {'hostname': 'google.com', 'port': 443, 'age': 365, ...}
    """
    if clean:
        url = _clean_url(url)
    
    info = {
        'hostname': None, 
        'port': None, 
        'cert_subject': None,
        'notAfter': None,
        "notBefore": None,
        "age": -1,
        "days_before_expiration": -1,
        'san': []
        }
    
    if not url: 
        return {}
    
    timeout = timeout or 5
    parsed = urlparse(url)
    port = parsed.port or 443
    host = _get_domain(url)
    info["hostname"] = host
    info["port"] = port
    
    if not host:
        return info
    
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                info['cert_subject'] = dict(x[0] for x in cert.get("subject", ()))
                info['notAfter'] = cert.get('notAfter')
                info['notBefore'] = cert.get('notBefore')
                san = cert.get('subjectAltName', ())
                info['san'] = [v for (typ, v) in san if typ.lower() in ('dns',)]
                if info["notBefore"]:
                    notBefore = datetime.strptime(info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    info["age"] = (datetime.now().astimezone(tz=timezone.utc) - notBefore.astimezone(tz=timezone.utc)).days
                
                if info["notAfter"]:
                    notBefore = datetime.strptime(info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    info["days_before_expiration"] = (notBefore.astimezone(tz=timezone.utc) - datetime.now().astimezone(tz=timezone.utc)).days
                
    except Exception as e:
        print('[get_tls] Erreur : ', e)
    return info


def _verify_ip_in_url(url: str, clean: bool = False) -> bool:
    """
    Vérifie si une URL utilise une adresse IP à la place d'un nom de domaine.

    Args:
        url (str): URL à analyser
        clean (bool): Si True, nettoie l'URL d'abord

    Returns:
        bool: True si l'URL contient une adresse IP, False sinon

    Examples:
        >>> _verify_ip_in_url('http://192.168.1.1/login')
        True
        >>> _verify_ip_in_url('https://google.com')
        False
        >>> _verify_ip_in_url('http://0x7f000001')  # Hex IP
        True
    """
    if clean:
        url = _clean_url(url)
        
    if not url:
        return False
    
    try:
        host = urlparse(url).hostname or ''
        if host.startswith("0x"):
            return True
        if all(c.isdigit() for c in host if c not in ":."):
            return True
        for type_ip in [socket.AF_INET, socket.AF_INET6]:
            is_ip = socket.inet_pton(type_ip, host)
            if is_ip:
                return True
        return False
    except Exception:
        return False


def calculate_entropy(string: str) -> float:
    """
    Calcule l'entropie de Shannon d'une chaîne de caractères.

    L'entropie mesure le degré de désordre/d'aléatoire d'une chaîne.
    Une entropie élevée indique une chaîne aléatoire (potentiellement
    générée automatiquement), une entropie faible indique une chaîne
    prévisible/répétitive.

    Args:
        string (str): Chaîne à analyser

    Returns:
        float: Entropie entre 0 et log2(longueur). 0 si chaîne vide.

    Examples:
        >>> calculate_entropy('aaaaaa')
        0.0
        >>> calculate_entropy('a1b2c3d4')
        3.0
    """
    if not string:
        return 0

    counter = Counter(string)
    length = len(string)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())

    return entropy


def _verify_rigth_click(body: str, simple: bool = True):
    """
    Vérifie si une page HTML désactive le clic droit (oncontextmenu).

    Cette technique est couramment utilisée par les sites de phishing
    pour empêcher les utilisateurs d'inspecter le code source.

    Args:
        body (str): Code HTML de la page
        simple (bool): Si True, retourne un booléen.
                       Si False, retourne la liste des patterns trouvés.

    Returns:
        bool or list: Si simple=True, True si clic droit désactivé.
                      Si simple=False, liste des patterns trouvés.

    Examples:
        >>> _verify_rigth_click('<body oncontextmenu="return false">')
        True
        >>> _verify_rigth_click('<body>Normal page</body>')
        False
    """
    patterns = [
            (r'oncontextmenu\s*=\s*["\']?return\s+false', "inline_return_false"),
            (r'oncontextmenu\s*=\s*["\']?preventdefault', "inline_prevent_default"),
            (r'oncontextmenu\s*=\s*["\']?[^"\']*false', "inline_false"),
            (r'addEventListener\s*\(\s*[\'"]contextmenu[\'"]', "js_listener"),
            (r'\.on\s*\(\s*[\'"]contextmenu[\'"]', "jquery_on"),
            (r'\.bind\s*\(\s*[\'"]contextmenu[\'"]', "jquery_bind"),
            (r'preventDefault\(\s*\)\s*;?\s*return\s+false', "prevent_return"),
            (r'return\s+false\s*;?\s*\}', "return_false"),
            (r'e\.button\s*===\s*2', "button_check"),
            (r'which\s*===\s*3', "which_check"),
            (r'contextmenu.*preventDefault', "context_prevent"),
        ]
        
    matches = []
    for pattern, name in patterns:
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(name)
    
    # Vérification spécifique des scripts inline
    if 'oncontextmenu' in body and 'return false' in body:
        matches.append("inline_contextmenu")
    
    return len(matches) > 0 if simple else matches


async def fetch_get(url: str, session: aiohttp.ClientSession, params: dict = None) -> dict:
    """
    Effectue une requête GET asynchrone et retourne les métadonnées de la réponse.

    Args:
        url (str): URL cible
        session (aiohttp.ClientSession): Session HTTP réutilisable
        params (dict): Paramètres de requête optionnels

    Returns:
        dict: Contenant les clés:
            - url (str): URL originale
            - url_finale (str): URL après redirections
            - status_code (int): Code HTTP
            - body (str): Contenu HTML
            - redirections (list): Historique des redirections

    Examples:
        >>> async with aiohttp.ClientSession() as session:
        ...     result = await fetch_get('https://google.com', session)
        ...     print(result['status_code'])
        200
    """
    params = params or {}
    result = {
        'url': url,
        'url_finale': '',
        'status_code': 200,
        'body': "<body></body>",
        'redirections': [],
    }
    try:
        timeout = aiohttp.ClientTimeout(total=1.5)
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            max_redirects=3,
        ) as response:
            result['url_finale'] = str(response.url)
            result['status_code'] = response.status
            try:
                result['body'] = await response.text()
            except Exception:
                result['body'] = "<body></body>"
            result['redirections'] = [{'url': str(r.url), 'status_code': r.status} for r in response.history]
            return result
        
    except Exception:
        return result


async def parse_form(url: str, body: str = None) -> list:
    """
    Extrait et parse les formulaires HTML d'une page.

    Args:
        url (str): URL de la page (utilisée pour résoudre les actions relatives)
        body (str, optional): Corps HTML. Si None, télécharge la page.

    Returns:
        list: Liste des formulaires, chaque formulaire est un dict avec:
            - action (str): URL cible du formulaire
            - method (str): Méthode HTTP ('get' ou 'post')

    Examples:
        >>> async def demo():
        ...     forms = await parse_form('https://example.com/login')
        ...     for form in forms:
        ...         print(form['action'], form['method'])
    """
    async def get_inputs(url, form):
        try:
            formulaire = {}
            action = form.get('action', '') if form.get('action') is not None else ''
            method = form.get('method', 'get').lower() if form.get('method') is not None else 'get'
            formulaire['action'], formulaire['method'] = action, method
            return formulaire
        except Exception:
            return {}
    
    try:
        result = []
        if body is None:
            async with aiohttp.ClientSession() as session:
                response = await fetch_get(url, session)
                body = response["body"]
        tree = html.fromstring(body)
        
        if tree is None:
            return []
        
        else:
            balises_form = tree.xpath("//form")
            if balises_form:
                for form in balises_form:
                    form_data = await get_inputs(url, form)
                    result.append(form_data)
                return result
            
        return result
    
    except Exception as e:
        print(f"Erreur parse_form: {e}")
        return []


if __name__ == "__main__":
    print(_verify_ip_in_url("http://111.222.333.444/secure/login", clean=True))
    print(_get_domain("https://webmail.company-update.com/login?ref=paypal"))
    print(_get_domain_age("gooogle.com", is_domain=True))