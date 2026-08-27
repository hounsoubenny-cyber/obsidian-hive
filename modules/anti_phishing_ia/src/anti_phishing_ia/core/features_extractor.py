#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extracteur de caractéristiques (features) pour URLs.
Auteur: HOUNSOU Samuel
Date: Juin 2026
Version: 2.0.0
"""

import os
import sys
import aiohttp
import asyncio
import random
import joblib as jb
import pandas as pd
import nest_asyncio
from tldextract import extract
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", '..'))
from anti_phishing_ia.core.generator import generate_legitimate_urls, generate_phishing_urls
from anti_phishing_ia.phishing_utils.utils import parse_form, fetch_get
from anti_phishing_ia.phishing_utils.utils import (
    _get_domain as get_domain, _get_domain_age,
    calculate_entropy, _verify_ip_in_url as verify_ip_in_url,
    _clean_url
)
from anti_phishing_ia.phishing_utils.legit_domain import _get_legitimate_domain
from anti_phishing_ia.core.config import AWAIT_TIME

# ============================================================================
# CONSTANTES
# ============================================================================

SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify-account', 'secure', 'account', 'update', 'banking',
    'payment', 'confirm', 'ebay', 'paypal', 'support', 'security',
    'validate', 'authenticate', 'password', 'credit', 'card', 'click'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.gq', '.cf', '.icu', '.top', '.xyz',
    '.club', '.download', '.win', '.center'
]

KNOWN_BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple',
    'facebook', 'netflix', 'ebay'
]

STANDARD_PORTS = [80, 443, None]

# Configurables
BATCH_SIZE = 250    # Semaphore : requêtes HTTP simultanées
SAVE_EVERY = 100_000  # Checkpoint tous les N URLs traités
CHUNK_SIZE = 50_000   # Taille des chunks pour économiser RAM

# ============================================================================
# FONCTIONS RÉSEAU
# ============================================================================

async def get_domain_age(url: str) -> int | None:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_get_domain_age, url), AWAIT_TIME)
    except Exception:
        return None


async def get_all(url: str) -> dict:
    """
    Récupère num_form, actions et redirections en une seule requête.
    Retourne des -1 si le réseau échoue (pas 0, pour distinguer 'pas de form' de 'pas de réponse').
    """
    try:
        async with aiohttp.ClientSession() as session:
            fetch = await fetch_get(url, session)
            form = await parse_form(url, body=fetch["body"])
            action = [i.get("action") for i in form]
            num_form = len(form)
        return {
            "num_form": num_form,
            "action": action,
            "fetch": fetch,
            "network_ok": True,
        }
    except Exception:
        return {
            "num_form": -1,      # -1 = non mesuré (réseau KO)
            "action": None,      # None = non mesuré
            "fetch": None,       # None = non mesuré
            "network_ok": False,
        }

# ============================================================================
# FEATURES NAMES
# ============================================================================

def get_features_names() -> list[str]:
    return [
        'url', 'is_know_domain', 'url_length', 'domain_length',
        'num_dots_domain', 'num_dots_in_host', 'has_ip', 'ip_as_domain',
        'domain_age', 'has_creation_date', 'pos_slash', 'has_at_sign',
        'num_dash', 'dash_in_domain', 'has_https', 'has_punycode',
        'num_query_params', 'num_suspicious_words', 'num_subdomain',
        'suspicious_tld', 'num_form', 'path_length', 'has_port',
        'n_redirects', 'actions_valid', 'digits_ratio_domain',
        'special_chars_domain', 'has_unicode', 'contains_percent_in_url',
        'path_depth', 'domain_entropy', 'brand_in_subdomain', 'has_nonstandard_port'
    ]

# ============================================================================
# FEATURE EXTRACTOR PRINCIPAL
# ============================================================================

async def _features_extractor_from_url(url: str) -> dict:
    """
    Extrait les 33 features d'une URL.

    FIX V2 :
    - legit_db chargé UNE FOIS via _get_legitimate_domain() (singleton)
      puis passé en variable locale → pas de requête SQL répétée
    - Fallback réseau cohérent : num_form=-1, n_redirects=-1, actions_valid=-1
      quand l'URL ne répond pas (distingue "0 form" de "pas de réponse")
    """
    url = str(url)
    url_ = _clean_url(url)

    if not url_:
        result = {"url": url}
        for k in get_features_names():
            result.setdefault(k, -1)
        result["label"] = "safe"
        return result

    legit_db = _get_legitimate_domain()

    domain = get_domain(url_)
    parse = urlparse(url_)
    subdomain = extract(url_).subdomain.lower()
    port = parse.port

    is_known = legit_db.includes(domain)
    digits_in_domain = sum(c.isdigit() for c in domain)
    special_chars = sum(not c.isalnum() and c not in '.-' for c in domain)
    num_suspicious_words = (
        sum(url.lower().count(k) for k in SUSPICIOUS_WORDS)
        if not is_known else 0
    )

    age = await get_domain_age(url_)
    data = await get_all(url_)
    network_ok = data["network_ok"]

    if network_ok:
        num_form = data["num_form"]
        action = data["action"]
        fetch = data["fetch"]
        ac = int(any(a in ['', 'about:blank'] for a in action))
        n_redirects = len(fetch.get('redirections', []))
    else:
        num_form = -1
        ac = -1
        n_redirects = -1

    return {
        'url': url,
        'is_know_domain': int(is_known),
        'url_length': len(url),
        'domain_length': len(domain),
        'num_dots_domain': domain.count('.'),
        'num_dots_in_host': (parse.hostname or '').count('.'),
        'has_ip': verify_ip_in_url(url_),
        'ip_as_domain': int(verify_ip_in_url(url_)),
        'domain_age': age if age is not None else -1,
        'has_creation_date': 1 if age else 0,
        'pos_slash': url.find('//'),
        'has_at_sign': int('@' in url),
        'num_dash': url.count('-'),
        'dash_in_domain': int('-' in domain),
        'has_https': int(url.startswith('https://')),
        'has_punycode': int('xn--' in url),
        'num_query_params': len(parse_qs(parse.query)),
        'num_suspicious_words': num_suspicious_words,
        'num_subdomain': len(subdomain.split('.')) if subdomain else 0,
        'suspicious_tld': int(extract(url_).suffix in SUSPICIOUS_TLDS),
        'num_form': num_form,
        'path_length': len(parse.path),
        'has_port': int(port is not None),
        'n_redirects': n_redirects,
        'actions_valid': ac,
        'digits_ratio_domain': digits_in_domain,
        'special_chars_domain': special_chars,
        'has_unicode': int(any(ord(c) > 127 for c in domain)),
        'contains_percent_in_url': int('%' in parse.query or '%' in parse.path),
        'path_depth': len([p for p in parse.path.split('/') if p]),
        'domain_entropy': calculate_entropy(domain),
        'brand_in_subdomain': int(any(brand in subdomain for brand in KNOWN_BRANDS)),
        'has_nonstandard_port': int(port not in STANDARD_PORTS),
        'label': 'safe',
    }


def features_extractor_from_url(url: str) -> dict:
    """Wrapper synchrone pour usage API/CLI."""
    return asyncio.run(_features_extractor_from_url(url))


# ============================================================================
# BATCH PROCESSING
# ============================================================================

async def _traite_batch(urls: list, labels: list) -> list:
    """
    Traite un chunk d'URLs en vrai parallèle avec Semaphore.

    BATCH_SIZE=250 → 250 requêtes HTTP simultanées max.
    Stable sur 16GB RAM. Monter à 350-400 si ta connexion le permet.
    """
    sem = asyncio.Semaphore(BATCH_SIZE)

    async def _one(url, label):
        async with sem:
            try:
                features = await _features_extractor_from_url(url)
                features['label'] = label
                return features
            except Exception:
                return None

    tasks = [_one(url, label) for url, label in zip(urls, labels)]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return [r for r in results if r is not None]


# ============================================================================
# GENERATE DATASET
# ============================================================================

async def generate_dataset():
    """
    Génère le dataset complet depuis toutes les sources.

    Sources :
    1. dataset3.csv       (11K URLs labellisées)
    2. dataset4.csv       (235K URLs labellisées)
    3. URLs safe générées (2.5M+)
    4. URLs phishing générées (2.5M)
    5. phishing_final.txt (URLs phishing réelles téléchargées)

    Améliorations V2 :
    - Traitement par chunks de CHUNK_SIZE (économise RAM)
    - Checkpoint tous les SAVE_EVERY URLs
    - Progression claire avec stats
    - Sauvegarde finale shufflée
    """
    pd.set_option("display.max_row", 111)
    pd.set_option('display.max_columns', 111)

    # --- Chemins ---
    path1 = os.path.join(".", "datasets", "dataset3.csv")
    path2 = os.path.join(".", "datasets", "dataset4.csv")
    phish_txt = os.path.join(".", "datasets", "phishing_final.txt")
    output_dir = os.path.join(".", "datasets", "generated")
    output_file = os.path.join(output_dir, "dataset_generated2.pkl")
    os.makedirs(output_dir, exist_ok=True)

    # --- Chargement CSV ---
    dataset1 = pd.read_csv(path1)
    dataset2 = pd.read_csv(path2)
    with open(phish_txt) as f:
        phishing_link = [
            l.strip() for l in f.read().split("\n")
            if l.strip() and not l.startswith("#")
        ]

    print(f"📊 dataset3 : {dataset1.shape[0]:,} URLs")
    print(f"📊 dataset4 : {dataset2.shape[0]:,} URLs")
    print(f"📊 phishing_final.txt : {len(phishing_link):,} URLs")

    urls1 = list(dataset1['url'])
    labels1 = list(dataset1['status'].map({"legitimate": "safe", "phishing": "phishing"}))
    urls2 = list(dataset2['URL'])
    labels2 = list(dataset2["label"].map(lambda x: 'safe' if x == 0 else 'phishing'))

    legit_db = _get_legitimate_domain()

    to_append = 33905 + len(phishing_link)
    base = 2_500_000 # 900_000

    print(f"\n🔄 Génération {base + to_append:,} URLs safe...")
    urls_safe = list(set(generate_legitimate_urls(base + to_append, db=legit_db, seed=1)))
    labels_safe = ['safe'] * len(urls_safe)

    print(f"🔄 Génération {base:,} URLs phishing...")
    urls_phish = list(set(generate_phishing_urls(base, seed=1, db=legit_db)))
    labels_phish = ['phishing'] * len(urls_phish)

    labels_phish_link = ['phishing'] * len(phishing_link)

    # --- Sources dans l'ordre de traitement ---
    all_sources = [
        ("dataset3",       urls1,         labels1),
        ("dataset4",       urls2,         labels2),
        ("safe_generated", urls_safe,     labels_safe),
        ("phish_generated",urls_phish,    labels_phish),
        ("phish_download", phishing_link, labels_phish_link),
    ]

    # --- Traitement par chunks ---
    dataset = []
    total_processed = 0
    last_checkpoint = 0

    for source_name, urls, labels in all_sources:
        n = len(urls)
        print(f"\n{'='*55}")
        print(f"📂 Source : {source_name} | {n:,} URLs")
        print(f"{'='*55}")

        for i in range(0, n, CHUNK_SIZE):
            chunk_urls = urls[i:i + CHUNK_SIZE]
            chunk_labels = labels[i:i + CHUNK_SIZE]

            print(f"  Chunk {i//CHUNK_SIZE + 1}/{(n-1)//CHUNK_SIZE + 1} "
                  f"| {len(chunk_urls):,} URLs | total traité : {total_processed:,}")

            results = await _traite_batch(chunk_urls, chunk_labels)
            dataset.extend(results)
            total_processed += len(results)

            if total_processed - last_checkpoint >= SAVE_EVERY:
                jb.dump(dataset, output_file)
                last_checkpoint = total_processed
                print(f"  💾 Checkpoint : {total_processed:,} URLs sauvegardées → {output_file}")

    # --- Sauvegarde finale ---
    print(f"\n🔀 Shuffle final de {len(dataset):,} URLs...")
    random.shuffle(dataset)
    jb.dump(dataset, output_file)

    df = pd.DataFrame(dataset)
    print("\n✅ Dataset final :")
    print(f"   Shape  : {df.shape}")
    print(f"   Labels :\n{df['label'].value_counts()}")
    print(f"   Fichier : {output_file}")

    return dataset


if __name__ == '__main__':
    nest_asyncio.apply()
    asyncio.run(generate_dataset())
    print(asyncio.run((_features_extractor_from_url("google.com"))))