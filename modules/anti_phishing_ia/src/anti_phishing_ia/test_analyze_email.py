#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 22 11:24:43 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test de l'API ShieldAI - Endpoint /api/analyze_mail
"""

import asyncio
import aiohttp
import json
import os
from typing import List, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

API_BASE = "http://localhost:8000"  # Adapte selon ton serveur
ENDPOINT = f"{API_BASE}/api/analyze_mail"

# Exemples d'emails à tester
TEST_EMAILS = [
    # Phishing
    {
        "text": """From: support@paypal-securite.tk
Subject: URGENT: Vérification requise

Bonjour,

Votre compte PayPal a été limité pour des raisons de sécurité.
Pour le débloquer, cliquez sur le lien ci-dessous :

https://paypal-verification-securisee.tk/login

Cordialement,
L'équipe PayPal""",
        "expected": "phishing"
    },
    # Safe
    {
        "text": """From: newsletter@lemonde.fr
Subject: Le Monde - Newsletter du jour

Bonjour,

Voici les actualités du jour :
- Article 1
- Article 2
- Article 3

Bonne lecture,
L'équipe du Monde""",
        "expected": "safe"
    },
]

# ============================================================================
# FONCTIONS DE TEST
# ============================================================================

async def analyze_email(
    session: aiohttp.ClientSession,
    email_text: str,
    check_blacklist: bool = False,
    filename: Optional[str] = None,
) -> dict:
    """
    Envoie un email à l'API pour analyse.
    
    Args:
        session: Session aiohttp
        email_text: Contenu brut de l'email
        check_blacklist: Vérifier les blacklists
        filename: Nom du fichier (optionnel)
    
    Returns:
        dict: Résultat de l'analyse
    """
    # Préparer les données pour multipart/form-data
    data = aiohttp.FormData()
    
    # Ajouter le texte en tant que mail
    if email_text:
        data.add_field('mails', email_text)
    
    # Ajouter un nom de fichier pour l'affichage
    if filename:
        data.add_field('filename', filename)
    
    # Paramètres supplémentaires
    data.add_field('check_blacklist', str(check_blacklist).lower())
    
    async with session.post(ENDPOINT, data=data) as response:
        result = await response.json()
        return {
            'status': response.status,
            'data': result
        }


async def analyze_email_file(
    session: aiohttp.ClientSession,
    filepath: str,
    check_blacklist: bool = False,
) -> dict:
    """Analyse un fichier .eml."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    return await analyze_email(
        session,
        email_text=content,
        check_blacklist=check_blacklist,
        filename=os.path.basename(filepath),
    )


async def test_analyze_email():
    """Test complet de l'endpoint /analyze_mail."""
    print("=" * 70)
    print("🧪 TEST DE L'API /api/analyze_mail")
    print("=" * 70)
    print(f"📡 Endpoint: {ENDPOINT}")
    print("-" * 70)
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Email phishing (texte brut)
        print("\n📧 Test 1: Email phishing (texte brut)")
        print("-" * 40)
        
        phishing_email = TEST_EMAILS[0]['text']
        result = await analyze_email(session, phishing_email, check_blacklist=True)
        
        print(f"  Statut HTTP: {result['status']}")
        if result['status'] == 200:
            data = result['data']
            print(f"  Total emails analysés: {data.get('total', 0)}")
            if data.get('results'):
                first = data['results'][0]
                print(f"  Décision: {first.get('final_decision', 'unknown')}")
                print(f"  Confiance: {first.get('confidence', 0):.2%}")
                print(f"  Expéditeur: {first.get('sender', 'N/A')}")
                print(f"  URLs: {first.get('nb_urls_total', 0)} total, {first.get('nb_urls_phishing', 0)} phishing")
                print(f"  SPF: {first.get('spf', 'N/A')} | DKIM: {first.get('dkim', 'N/A')}")
        else:
            print(f"  ❌ Erreur: {result.get('data', {}).get('detail', 'Unknown error')}")
        
        # Test 2: Email safe (texte brut)
        print("\n📧 Test 2: Email safe (texte brut)")
        print("-" * 40)
        
        safe_email = TEST_EMAILS[1]['text']
        result = await analyze_email(session, safe_email)
        
        print(f"  Statut HTTP: {result['status']}")
        if result['status'] == 200:
            data = result['data']
            print(f"  Total emails analysés: {data.get('total', 0)}")
            if data.get('results'):
                first = data['results'][0]
                print(f"  Décision: {first.get('final_decision', 'unknown')}")
                print(f"  Confiance: {first.get('confidence', 0):.2%}")
        else:
            print(f"  ❌ Erreur: {result.get('data', {}).get('detail', 'Unknown error')}")
        
        # Test 3: Batch d'emails (liste)
        print("\n📧 Test 3: Batch d'emails (2 emails)")
        print("-" * 40)
        
        data = aiohttp.FormData()
        data.add_field('mails', TEST_EMAILS[0]['text'])
        data.add_field('mails', TEST_EMAILS[1]['text'])
        data.add_field('check_blacklist', 'true')
        
        async with session.post(ENDPOINT, data=data) as response:
            result = await response.json()
            print(f"  Statut HTTP: {response.status}")
            if response.status == 200:
                print(f"  Total: {result.get('total', 0)}")
                print(f"  Phishing: {result.get('phishing_count', 0)}")
                print(f"  Safe: {result.get('safe_count', 0)}")
                print(f"  Suspicious: {result.get('suspicious_count', 0)}")
                for i, r in enumerate(result.get('results', [])):
                    print(f"    Email {i+1}: {r.get('final_decision', 'unknown')}")
            else:
                print(f"  ❌ Erreur: {result.get('detail', 'Unknown error')}")
    
    print("\n" + "=" * 70)
    print("✅ Tests terminés")
    print("=" * 70)


async def test_with_eml_file(filepath: str):
    """Test avec un fichier .eml spécifique."""
    print("=" * 70)
    print(f"📧 Analyse du fichier: {filepath}")
    print("=" * 70)
    
    if not os.path.exists(filepath):
        print(f"❌ Fichier non trouvé: {filepath}")
        return
    
    async with aiohttp.ClientSession() as session:
        result = await analyze_email_file(session, filepath, check_blacklist=True)
        
        print(f"  Statut HTTP: {result['status']}")
        if result['status'] == 200:
            data = result['data']
            if data.get('results'):
                first = data['results'][0]
                print(f"  Décision: {first.get('final_decision', 'unknown')}")
                print(f"  Confiance: {first.get('confidence', 0):.2%}")
                print(f"  Expéditeur: {first.get('sender', 'N/A')}")
                print(f"  Sujet: {first.get('subject', 'N/A')}")
                print(f"  URLs: {first.get('nb_urls_total', 0)} total, {first.get('nb_urls_phishing', 0)} phishing")
                print(f"  SPF: {first.get('spf', 'N/A')} | DKIM: {first.get('dkim', 'N/A')}")
        else:
            print(f"  ❌ Erreur: {result.get('data', {}).get('detail', 'Unknown error')}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    # Vérifier que le serveur tourne
    import requests
    try:
        requests.get(f"{API_BASE}/api/health", timeout=2)
        print("✅ Serveur accessible\n")
    except Exception:
        print(f"❌ Serveur inaccessible sur {API_BASE}")
        print("   Assure-toi que le serveur est lancé :")
        print("   python run_cli.py --api --port 8000")
        exit(1)
    
    # Lancer les tests
    asyncio.run(test_analyze_email())
    
    # Si tu as un fichier .eml spécifique à tester :
    # asyncio.run(test_with_eml_file("chemin/vers/email.eml"))