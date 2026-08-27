#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generator V3 - Anti-Phishing URLs
Sam Hounsou / Obsidian Hive

- generate_phishing_urls() accepte un LegitDomainDBManager (domaines réels comme base)
- generate_legitimate_urls() itère sur LegitDomainDBManager via __iter__() paginé
- Vise 3M+ par catégorie
- Nouvelle technique 'lookalike' (la plus trompeuse)
- Fusion propre avec URLs téléchargées (PhishTank, etc.)
- Sauvegarde Parquet ou CSV
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
import random
import string
import base64
from urllib.parse import quote
from typing import List, Set, Optional

# ============================================================================
# HOMOGLYPHES UNICODE
# ============================================================================

HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', 'ä', 'â', 'à'],
    'b': ['Ь', 'ƅ', 'ḃ'],
    'c': ['с', 'ϲ', 'ć', 'č'],
    'd': ['ԁ', 'ɗ', 'đ'],
    'e': ['е', 'ė', 'ę', 'ê', 'é'],
    'g': ['ɡ', 'ġ', 'ģ'],
    'i': ['і', 'ɪ', 'ï', 'î', '1', 'l'],
    'l': ['I', '1', 'ɩ', 'ĺ', 'ļ'],
    'm': ['rn', 'ṁ', 'ɱ'],
    'n': ['ń', 'ņ', 'ɲ'],
    'o': ['о', '0', 'ο', 'ö', 'ô', 'ọ'],
    'p': ['р', 'ρ'],
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ɾ', 'ŕ'],
    's': ['ѕ', 'ś', 'š', '5'],
    't': ['ţ', 'ț', 'ƭ'],
    'u': ['υ', 'ü', 'ú', 'ū'],
    'v': ['ν', 'ṿ'],
    'w': ['ω', 'ẁ', 'vv'],
    'x': ['х', 'χ'],
    'y': ['у', 'ý', 'ÿ'],
    'z': ['ź', 'ż', 'ž'],
}

# ============================================================================
# CIBLES (fallback si pas de LegitDomainDBManager)
# ============================================================================

POPULAR_TARGETS = {
    'finance': [
        'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'westernunion',
        'moneygram', 'citibank', 'chase', 'bankofamerica', 'wellsfargo',
        'barclays', 'hsbc', 'bnpparibas', 'societegenerale', 'creditagricole',
        'revolut', 'wise', 'cashapp', 'zelle', 'venmo', 'binance', 'coinbase',
        'kraken', 'etoro', 'robinhood', 'fidelity', 'schwab',
    ],
    'tech': [
        'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta',
        'instagram', 'whatsapp', 'twitter', 'linkedin', 'dropbox',
        'github', 'gitlab', 'adobe', 'netflix', 'spotify', 'discord',
        'zoom', 'slack', 'notion', 'figma', 'cloudflare', 'aws',
        'salesforce', 'hubspot', 'mailchimp', 'sendgrid', 'twilio',
        'digitalocean', 'heroku', 'vercel', 'netlify', 'firebase',
    ],
    'ecommerce': [
        'ebay', 'aliexpress', 'alibaba', 'etsy', 'shopify', 'walmart',
        'target', 'bestbuy', 'cdiscount', 'fnac', 'leboncoin', 'rakuten',
        'wish', 'shein', 'temu', 'zalando', 'asos',
    ],
    'gov_logistics': [
        'irs', 'impots', 'ameli', 'caf', 'urssaf', 'dgfip',
        'dhl', 'fedex', 'ups', 'laposte', 'chronopost', 'colissimo',
    ],
    'telecom': [
        'orange', 'sfr', 'bouygues', 'free', 'att', 'verizon', 'tmobile',
        'mtn', 'moov', 'airtel', 'glo', 'vodafone', 'o2',
    ],
    'africa': [
        'mtn', 'moov', 'airtel', 'orange-money', 'wave', 'flooz',
        'celtiis', 'togocel', 'onatel', 'sonatel',
    ],
}

ALL_TARGETS = list({t for targets in POPULAR_TARGETS.values() for t in targets})

# ============================================================================
# TLDs
# ============================================================================

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.online', '.site', '.website', '.space', '.live', '.tech',
    '.info', '.biz', '.work', '.click', '.link', '.download',
    '.win', '.stream', '.review', '.science', '.party',
    '.racing', '.trade', '.date', '.faith', '.loan',
    '.men', '.accountant', '.cricket', '.bid', '.webcam', '.icu',
]

# ============================================================================
# PATHS ET PARAMS
# ============================================================================

LEGIT_PATHS_BY_SECTOR = {
    'auth': [
        '/login', '/signin', '/signup', '/register', '/auth',
        '/oauth/callback', '/sso', '/verify', '/confirm',
        '/reset-password', '/forgot-password', '/2fa', '/mfa',
        '/auth/login', '/user/login', '/account/signin',
    ],
    'account': [
        '/account', '/profile', '/dashboard', '/settings',
        '/billing', '/subscription', '/security', '/privacy',
        '/notifications', '/api-keys', '/sessions', '/account/overview',
        '/user/profile', '/me', '/account/security',
    ],
    'content': [
        '/blog', '/news', '/articles', '/docs', '/help',
        '/support', '/faq', '/about', '/contact', '/pricing',
        '/blog/post', '/news/latest', '/press', '/media',
    ],
    'ecommerce': [
        '/shop', '/products', '/cart', '/checkout', '/orders',
        '/shipping', '/returns', '/categories', '/search',
        '/products/new', '/sale', '/wishlist', '/order/track',
    ],
    'api': [
        '/api/v1/users', '/api/v2/auth', '/api/v1/payments',
        '/api/v1/webhooks', '/graphql', '/api/v1/notifications',
        '/api/v2/orders', '/api/v1/products', '/api/v3/auth',
    ],
    'mobile': [
        '/app', '/mobile', '/download', '/install',
        '/app/ios', '/app/android', '/get-app',
    ],
    'legal': [
        '/terms', '/privacy-policy', '/cookies', '/legal',
        '/gdpr', '/compliance', '/terms-of-service',
    ],
}

ALL_LEGIT_PATHS = [p for paths in LEGIT_PATHS_BY_SECTOR.values() for p in paths]

LEGIT_PARAMS_REALISTIC = {
    'tracking': [
        'utm_source=google', 'utm_medium=email', 'utm_campaign=promo2025',
        'ref=homepage', 'utm_source=newsletter', 'utm_medium=social',
        'ref=search', 'source=organic',
    ],
    'nav': [
        'redirect=/dashboard', 'next=/account', 'return_to=home',
        'lang=fr', 'lang=en', 'lang=de', 'locale=fr_FR', 'locale=en_US',
    ],
    'filter': [
        'page=1', 'page=2', 'limit=25', 'sort=newest',
        'category=all', 'q=search', 'filter=active', 'offset=0',
    ],
    'session': [
        'session=active', 'state=active', 'mode=dark', 'theme=light',
    ],
    'misc': ['', 'v=2', 'beta=true', 'preview=1', 'dark=1'],
}

ALL_LEGIT_PARAMS = [p for params in LEGIT_PARAMS_REALISTIC.values() for p in params]


# ============================================================================
# TECHNIQUES PHISHING
# ============================================================================

def _homoglyph_attack(target: str, n_chars: int = 2) -> str:
    result = list(target)
    candidates = [(i, c) for i, c in enumerate(result) if c in HOMOGLYPHS]
    if not candidates:
        return target
    chosen = random.sample(candidates, min(n_chars, len(candidates)))
    for i, c in chosen:
        result[i] = random.choice(HOMOGLYPHS[c])
    return ''.join(result)


def _typosquatting(target: str) -> str:
    if len(target) < 3:
        return target + random.choice(['s', '1', '-online'])
    ops = [
        lambda t: t[:len(t)//2] + t[random.randint(0, len(t)-1)] + t[len(t)//2:],
        lambda t: (lambda lst, i: ''.join(lst[:i] + [lst[i+1], lst[i]] + lst[i+2:]))(list(t), random.randint(0, max(0, len(t)-2))),
        lambda t: ''.join({'o':'0','i':'1','e':'3','a':'4','s':'5','t':'7','b':'8'}.get(c, c) if random.random() < 0.5 else c for c in t),
        lambda t: t[:max(1, random.randint(1, len(t)-2))] + t[min(len(t)-1, random.randint(2, len(t)-1)):] if len(t) > 4 else t,
        lambda t: t[:len(t)//2] + '-' + t[len(t)//2:],
        lambda t: t + random.choice(['s', '1', '-web', '-app', '-co']),
    ]
    return random.choice(ops)(target)


def _open_redirect(target: str) -> str:
    evil = random.choice([
        'evil-site.tk', 'steal-creds.xyz', 'phish-now.top',
        'malicious.online', 'cred-harvest.site', 'login-fake.xyz'
    ])
    patterns = [
        f"https://www.{target}.com/redirect?url=https://{evil}",
        f"https://accounts.{target}.com/oauth?redirect_uri=http://{evil}/callback",
        f"https://{target}.com/login?next=//evil.{random.choice(['tk','xyz','top'])}",
        f"https://{target}.com/auth/callback?returnTo=https%3A%2F%2F{evil}",
        f"https://{target}.com/signout?post_logout_redirect_uri=https://{evil}",
    ]
    return random.choice(patterns)


def _base64_payload(target: str) -> str:
    evil_url = f"https://steal.{random.choice(['tk','xyz','top'])}/{target}/creds"
    b64 = base64.b64encode(evil_url.encode()).decode()
    patterns = [
        f"https://cdn-{target}.com/redirect?r={b64}",
        f"https://secure-{target}.net/go?dest={quote(evil_url)}",
        f"https://links.{target}-email.com/click?data={b64[:20]}",
    ]
    return random.choice(patterns)


def _subdomain_abuse(target: str) -> str:
    evil_tld = random.choice(SUSPICIOUS_TLDS).replace('.', '')
    patterns = [
        f"https://{target}.com-secure-verify.{evil_tld}/login",
        f"https://secure.{target}.com.{evil_tld}/account",
        f"https://accounts.{target}.com.{evil_tld}/oauth",
        f"https://{target}.verify-account.{evil_tld}/confirm",
        f"http://www.{target}.com.verify-{random.randint(100,999)}.{evil_tld}/",
        f"https://login.{target}-portal.{evil_tld}/signin",
    ]
    return random.choice(patterns)


def _punycode_attack(target: str) -> str:
    modified = _homoglyph_attack(target, n_chars=random.randint(1, 2))
    try:
        puny = modified.encode('idna').decode('ascii')
    except Exception:
        puny = f"xn--{target}-{random.randint(10, 999)}"
    path = random.choice(ALL_LEGIT_PATHS[:8])
    return f"https://{puny}.com{path}"


def _combo_attack(target: str) -> str:
    evil_tld = random.choice(SUSPICIOUS_TLDS).replace('.', '')
    prefix = random.choice(['secure-', 'my-', 'account-', 'login-', 'verify-', 'support-', 'help-'])
    suffix = random.choice(['-login', '-secure', '-verify', '-account', '-portal', ''])
    path = random.choice(['/login', '/signin', '/verify', '/confirm', '/account/security', '/suspended'])
    param = random.choice([
        '?suspended=true&action=verify',
        '?alert=unusual_activity',
        f'?confirm=identity&token={"".join(random.choices(string.hexdigits, k=16))}',
        '?security_check=required',
        '?locked=true&verify=now',
    ])
    typo = _typosquatting(target)
    patterns = [
        f"https://{prefix}{typo}{suffix}.{evil_tld}{path}{param}",
        f"https://{target}.com.{prefix}{random.randint(1,99)}.{evil_tld}{path}",
        f"https://www.{typo}{suffix}.com{path}{param}",
        f"https://{prefix}{target}.{evil_tld}{path}{param}",
    ]
    return random.choice(patterns)


def _fake_https(target: str) -> str:
    evil_tld = random.choice(SUSPICIOUS_TLDS).replace('.', '')
    patterns = [
        f"http://https-{target}.{evil_tld}/login",
        f"http://{target}-ssl-secure.{evil_tld}/",
        f"https://{target}-encrypted.{evil_tld}/account",
        f"http://ssl-{target}-login.{evil_tld}/signin",
    ]
    return random.choice(patterns)


def _ip_with_path(target: str) -> str:
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    paths = [
        f'/{target}/login', f'/{target}/verify',
        f'/secure/{target}', f'/{target}.com/account',
        f'/gate/{target}', f'/panel/{target}/auth',
    ]
    port = random.choice([8080, 8443, 9090, 3000, 5000, ''])
    port_str = f":{port}" if port else ''
    return f"http://{ip}{port_str}{random.choice(paths)}"


def _lookalike_domain(target: str) -> str:
    """Domaine lookalike avec TLD légitime — le plus trompeur."""
    legit_tlds = ['.com', '.net', '.org', '.co', '.io']
    variations = [
        f"{target}-secure", f"{target}-account", f"my{target}",
        f"{target}web", f"get{target}", f"{target}app",
        f"login{target}", f"{_typosquatting(target)}",
        f"{target}-help", f"support{target}",
    ]
    domain = random.choice(variations)
    tld = random.choice(legit_tlds)
    path = random.choice(ALL_LEGIT_PATHS[:12])
    param = random.choice(['', '?verify=true', '?action=confirm', '?alert=1'])
    return f"https://{domain}{tld}{path}{param}"


def _data_harvest(target: str) -> str:
    sid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    patterns = [
        f"http://malware-dropper.tk/gate?brand={target}&s={sid}",
        f"https://credential-harvest.xyz/phish/{target}/{sid}",
        f"https://track-{target}.top/collect?uid={sid}",
    ]
    return random.choice(patterns)


# ============================================================================
# MAPPING + POIDS
# ============================================================================

PHISHING_TECHNIQUES = {
    'typosquatting':   lambda t: f"https://{_typosquatting(t)}.com{random.choice(ALL_LEGIT_PATHS[:10])}",
    'homoglyph':       _punycode_attack,
    'subdomain_abuse': _subdomain_abuse,
    'open_redirect':   _open_redirect,
    'base64_payload':  _base64_payload,
    'combo_attack':    _combo_attack,
    'fake_https':      _fake_https,
    'ip_direct':       _ip_with_path,
    'lookalike':       _lookalike_domain,
    'suspicious_tld':  lambda t: f"https://{t}{random.choice(SUSPICIOUS_TLDS)}{random.choice(ALL_LEGIT_PATHS[:8])}",
    'prefix_suffix':   lambda t: f"https://{random.choice(['secure-','verify-','account-','my-','login-'])}{t}{random.choice(['-login','','-secure','-portal'])}.com/",
    'data_harvest':    _data_harvest,
    'long_domain':     lambda t: f"https://{t}-{''.join(random.choices(string.ascii_lowercase, k=random.randint(6,14)))}.com/",
    'at_symbol':       lambda t: f"https://{t}.com@{random.choice(['evil','steal','phish'])}.{random.choice(['tk','xyz','top'])}/",
    'port_abuse':      lambda t: f"http://{t}.com:{random.choice([8080,8888,9090,3000,4443])}/login",
}

TECHNIQUE_WEIGHTS = {
    'typosquatting':   10,
    'homoglyph':        6,
    'subdomain_abuse': 14,
    'open_redirect':   14,
    'base64_payload':   7,
    'combo_attack':    18,
    'fake_https':       5,
    'ip_direct':        7,
    'lookalike':       12,
    'suspicious_tld':   7,
    'prefix_suffix':    5,
    'data_harvest':     3,
    'long_domain':      4,
    'at_symbol':        3,
    'port_abuse':       5,
}

_TECHNIQUES = list(PHISHING_TECHNIQUES.keys())
_WEIGHTS = [TECHNIQUE_WEIGHTS[t] for t in _TECHNIQUES]


# ============================================================================
# EXTRACT BASE NAME (domaine → nom de base pour phishing)
# ============================================================================

def _extract_base_name(domain: str) -> str:
    """
    'google.com' → 'google', 'www.amazon.co.uk' → 'amazon'
    Utilisé pour convertir les domaines legit en targets phishing.
    """
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    base = domain.split('.')[0]
    base = ''.join(c for c in base if c.isalnum() or c == '-')
    return base if len(base) >= 3 else ''


# ============================================================================
# GENERATE PHISHING V3
# ============================================================================

def generate_phishing_urls(
        n: int = 3_000_000,
        db=None,
        db_sample_size: int = 100_000,
        extra_targets: Optional[List[str]] = None,
        seed: int = 42,
) -> List[str]:
    """
    Génère n URLs phishing modernes.

    Args:
        n             : Nombre d'URLs cible (ex: 3_000_000)
        db            : LegitDomainDBManager — si fourni, on sample des domaines
                        réels pour les utiliser comme bases des attaques.
                        Plus réaliste que les cibles hardcodées seules.
        db_sample_size: Nb de domaines à lire depuis la DB (paginé via __iter__)
                        50K-100K suffisent, pas besoin de charger les 10M.
        extra_targets : Targets supplémentaires (liste de strings)
        seed          : Random seed

    Returns:
        List[str]: URLs phishing uniques, shufflées
    """
    random.seed(seed)

    # --- Construire les targets ---
    targets = list(ALL_TARGETS)

    if db is not None:
        print(f"📂 Sampling {db_sample_size:,} domaines depuis DB pour targets phishing...")
        sampled = []
        for i, domain in enumerate(db):
            if i >= db_sample_size:
                break
            base = _extract_base_name(domain)
            if base:
                sampled.append(base)
        random.shuffle(sampled)
        targets.extend(sampled)
        print(f"  → {len(sampled):,} noms extraits depuis la DB")

    if extra_targets:
        targets.extend(extra_targets)

    targets = list(set(t for t in targets if t and len(t) >= 3))
    print(f"🎯 {len(targets):,} targets uniques disponibles")

    # --- Génération ---
    urls: Set[str] = set()
    stats = {t: 0 for t in _TECHNIQUES}
    max_attempts = n * 6
    attempts = 0

    print(f"🎣 Génération de {n:,} URLs phishing...")

    while len(urls) < n and attempts < max_attempts:
        attempts += 1
        target = random.choice(targets)
        technique = random.choices(_TECHNIQUES, weights=_WEIGHTS, k=1)[0]
        try:
            url = PHISHING_TECHNIQUES[technique](target)
            if url and len(url) > 15 and url not in urls:
                urls.add(url)
                stats[technique] += 1
                if len(urls) % 500_000 == 0 and len(urls) > 0:
                    print(f"  → {len(urls):,} URLs générées...")
        except Exception:
            continue

    result = list(urls)[:n]
    random.shuffle(result)
    print(f"\n✅ {len(result):,} URLs phishing générées ({attempts:,} tentatives)")
    _print_technique_stats(stats)
    return result


# ============================================================================
# GENERATE SAFE V3
# ============================================================================

def generate_legitimate_urls(
        n: int = 3_000_000,
        db=None,
        extra_domains: Optional[List[str]] = None,
        urls_per_domain: int = 4,
        seed: int = 42,
) -> List[str]:
    """
    Génère n URLs légitimes depuis LegitDomainDBManager.

    Stratégie mémoire-friendly :
    - On a besoin de n // urls_per_domain domaines
    - On itère via db.__iter__() qui est déjà paginé (LEGIT_BATCH_SIZE)
    - Pour chaque domaine, on génère urls_per_domain URLs variées
    - On n'a jamais tout en RAM en même temps

    Args:
        n              : Nombre d'URLs cible (ex: 3_000_000)
        db             : LegitDomainDBManager — source principale
        extra_domains  : Domaines bruts supplémentaires (Tranco CSV, etc.)
                         Utile pour les domaines téléchargés qui sont juste
                         des noms de domaine, pas des URLs complètes
        urls_per_domain: 4 = bon ratio diversité/vitesse pour atteindre 3M
        seed           : Random seed

    Returns:
        List[str]: URLs légitimes uniques, shufflées
    """
    random.seed(seed)
    protocols = ['https://', 'https://www.']
    urls: Set[str] = set()
    domains_seen = 0

    domains_needed = (n // urls_per_domain) + 1
    print(f"✅ Génération de {n:,} URLs légitimes")
    print(f"   → Besoin ~{domains_needed:,} domaines ({urls_per_domain} URLs/domaine)")

    def _urls_for_domain(domain: str) -> List[str]:
        """Génère urls_per_domain URLs pour un domaine, sectors différents."""
        generated = []
        sectors = random.sample(
            list(LEGIT_PATHS_BY_SECTOR.keys()),
            min(urls_per_domain, len(LEGIT_PATHS_BY_SECTOR))
        )
        for sector in sectors:
            protocol = random.choice(protocols)
            path = random.choice(LEGIT_PATHS_BY_SECTOR[sector])
            param = ''
            if random.random() < 0.6:
                cat = random.choice(list(LEGIT_PARAMS_REALISTIC.keys()))
                val = random.choice(LEGIT_PARAMS_REALISTIC[cat])
                if val:
                    param = ('?' + val) if not val.startswith('?') else val
            generated.append(f"{protocol}{domain}{path}{param}")
        return generated

    # Source 1 : LegitDomainDBManager (paginé via __iter__)
    if db is not None:
        print("📂 Itération sur LegitDomainDBManager (paginée)...")
        for domain in db:
            if len(urls) >= n:
                break
            for url in _urls_for_domain(domain):
                urls.add(url)
            domains_seen += 1
            if domains_seen % 100_000 == 0:
                print(f"  → {domains_seen:,} domaines | {len(urls):,} URLs")

    # Source 2 : Domaines extra (Tranco CSV téléchargé, etc.)
    if extra_domains and len(urls) < n:
        print(f"📂 Domaines extra : {len(extra_domains):,}")
        random.shuffle(extra_domains)
        for domain in extra_domains:
            if len(urls) >= n:
                break
            domain = domain.strip().lower()
            if not domain:
                continue
            for url in _urls_for_domain(domain):
                urls.add(url)
            domains_seen += 1

    result = list(urls)[:n]
    random.shuffle(result)
    print(f"\n✅ {len(result):,} URLs légitimes depuis {domains_seen:,} domaines")
    return result


# ============================================================================
# FUSION AVEC URLs TÉLÉCHARGÉES
# ============================================================================

def merge_with_downloaded(
        generated_phishing: List[str],
        generated_safe: List[str],
        downloaded_phishing: Optional[List[str]] = None,
        downloaded_safe_domains: Optional[List[str]] = None,
        db=None,
        target_per_class: int = 3_000_000,
        seed: int = 42,
) -> tuple:
    """
    Fusionne URLs générées + URLs téléchargées.

    - downloaded_phishing      : URLs complètes (PhishTank, OpenPhish, URLhaus)
                                  → ajout direct dans le set phishing
    - downloaded_safe_domains  : Domaines bruts (Tranco 1M, Majestic 1M)
                                  → on génère des URLs dessus via generate_legitimate_urls()

    Returns:
        (phishing_list, safe_list) dédupliquées
    """
    print("\n🔀 Fusion des sources...")

    # Phishing : URLs complètes → ajout direct
    all_phishing = set(generated_phishing)
    if downloaded_phishing:
        clean = [u.strip() for u in downloaded_phishing if u.strip()]
        all_phishing.update(clean)
        print(f"  + {len(clean):,} URLs phishing téléchargées")

    # Safe : domaines → générer des URLs
    all_safe = set(generated_safe)
    if downloaded_safe_domains and len(all_safe) < target_per_class:
        remaining = target_per_class - len(all_safe)
        print(f"  + Génération {remaining:,} URLs safe depuis domaines téléchargés...")
        extra = generate_legitimate_urls(
            n=remaining,
            db=None,
            extra_domains=downloaded_safe_domains,
            seed=seed + 1,
        )
        all_safe.update(extra)

    random.seed(seed)
    phishing_final = list(all_phishing)
    safe_final = list(all_safe)
    random.shuffle(phishing_final)
    random.shuffle(safe_final)

    print("\n📊 Résultat fusion :")
    print(f"   Phishing : {len(phishing_final):,}")
    print(f"   Safe     : {len(safe_final):,}")
    return phishing_final, safe_final


# ============================================================================
# SAUVEGARDE
# ============================================================================

def save_to_parquet(phishing: List[str], safe: List[str], path: str = './datasets/urls_v3.parquet') -> None:
    try:
        import pandas as pd
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        df = pd.DataFrame({
            'url': phishing + safe,
            'label': ['phishing'] * len(phishing) + ['safe'] * len(safe),
        }).sample(frac=1, random_state=42).reset_index(drop=True)
        df.to_parquet(path, index=False, compression='snappy')
        size_mb = os.path.getsize(path) / (1024**2)
        print(f"💾 Parquet : {path} ({size_mb:.1f} MB, {len(df):,} lignes)")
    except ImportError:
        print("❌ pip install pyarrow")


def save_to_csv(phishing: List[str], safe: List[str], path: str = './datasets/urls_v3.csv') -> None:
    import csv
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for url in phishing:
            writer.writerow([url, 'phishing'])
        for url in safe:
            writer.writerow([url, 'safe'])
    size_mb = os.path.getsize(path) / (1024**2)
    print(f"💾 CSV : {path} ({size_mb:.1f} MB)")


# ============================================================================
# UTILS
# ============================================================================

def _print_technique_stats(stats: dict) -> None:
    total = sum(stats.values())
    if not total:
        return
    print("📊 Distribution des techniques :")
    for tech, count in sorted(stats.items(), key=lambda x: -x[1]):
        if count > 0:
            bar = '█' * int(count / total * 30)
            print(f"   {tech:<18} : {count:>8,}  ({count/total*100:4.1f}%)  {bar}")


def get_stats(phishing: List[str], safe: List[str]) -> None:
    print("\n" + "=" * 60)
    print("📊 STATS FINALES")
    print("=" * 60)
    ratio = len(safe) / max(len(phishing), 1)
    print(f"  Phishing  : {len(phishing):>12,}")
    print(f"  Safe      : {len(safe):>12,}")
    print(f"  Total     : {len(phishing)+len(safe):>12,}")
    print(f"  Ratio S/P : {ratio:.2f}", "✅" if 0.8 <= ratio <= 1.5 else "⚠️ déséquilibré")
    if phishing:
        print(f"  Avg len phishing : {sum(len(u) for u in phishing)//len(phishing)} chars")
    if safe:
        print(f"  Avg len safe     : {sum(len(u) for u in safe)//len(safe)} chars")
    print("=" * 60)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    from anti_phishing_ia.core.legitimate_db_manager import LegitDomainDBManager
    
    db = LegitDomainDBManager()
    import argparse

    parser = argparse.ArgumentParser(description='Generator V3 Anti-Phishing')
    parser.add_argument('--phishing', type=int, default=3_000_000)
    parser.add_argument('--safe', type=int, default=3_000_000)
    parser.add_argument('--db-sample', type=int, default=100_000)
    parser.add_argument('--output', type=str, default='./datasets/urls_v3.parquet')
    parser.add_argument('--format', choices=['parquet', 'csv'], default='parquet')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    # --- Standalone (sans LegitDomainDBManager) ---
    phishing = generate_phishing_urls(n=args.phishing, seed=args.seed, db=db)
    safe = generate_legitimate_urls(n=args.safe, seed=args.seed, db=db)

    get_stats(phishing, safe)

    out = args.output
    if args.format == 'parquet':
        save_to_parquet(phishing, safe, out)
    else:
        save_to_csv(phishing, safe, out.replace('.parquet', '.csv'))

    # =========================================================
    # Exemple AVEC LegitDomainDBManager (dans ton projet)
    # =========================================================
    # sys.path.insert(0, '/path/to/anti_phishing_ia')
    # from anti_phishing_ia.core.legitimate_domain_manager import LegitDomainDBManager
    #
    # db = LegitDomainDBManager()
    #
    # # Phishing : les domaines de ta DB deviennent des targets d'attaque
    # phishing = generate_phishing_urls(
    #     n=3_000_000,
    #     db=db,
    #     db_sample_size=100_000,  # lit 100K domaines depuis la DB (paginé)
    # )
    #
    # # Safe : on génère des URLs depuis tous les domaines de ta DB
    # safe = generate_legitimate_urls(
    #     n=3_000_000,
    #     db=db,               # itère en mémoire via __iter__()
    #     urls_per_domain=4,
    # )
    #
    # # Fusion avec URLs téléchargées
    # import pandas as pd
    # phish_dl  = pd.read_csv('phishtank.csv')['url'].tolist()
    # safe_doms = pd.read_csv('tranco_1m.csv')['domain'].tolist()
    #
    # phishing_final, safe_final = merge_with_downloaded(
    #     generated_phishing=phishing,
    #     generated_safe=safe,
    #     downloaded_phishing=phish_dl,
    #     downloaded_safe_domains=safe_doms,
    #     target_per_class=3_000_000,
    # )
    # save_to_parquet(phishing_final, safe_final, './datasets/final_v3.parquet')
    # get_stats(phishing_final, safe_final)