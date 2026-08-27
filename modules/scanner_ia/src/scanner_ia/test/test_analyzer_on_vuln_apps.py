#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar  6 19:45:44 2026

@author: hounsousamuel
"""

# test_analyzer_on_vuln_apps.py
import asyncio
import aiohttp
from scanner_ia.core.analyzer_helper import AnalyzerHelper

async def test_analyzer_on_vuln_apps():
    """Test l'AnalyzerHelper sur les applications vulnérables"""
    
    # Configuration des apps vulnérables
    vuln_apps = [
        {
            "name": "DVWA",
            "url": "http://localhost:8080",
            "login": {
                "url": "http://localhost:8080/login.php",
                "data": {"username": "admin", "password": "password", "Login": "Login"}
            }
        },
        {
            "name": "Juice Shop",
            "url": "http://localhost:8082"
        },
        {
            "name": "bWAPP",
            "url": "http://localhost:8083"
        }
    ]
    
    session = aiohttp.ClientSession()
    
    for app in vuln_apps:
        print("\n" + "🔥"*60)
        print(f"🔥 TEST SUR {app['name']}")
        print("🔥"*60)
        
        # Login si nécessaire (pour DVWA)
        if "login" in app:
            async with session.post(app["login"]["url"], 
                                   data=app["login"]["data"]) as resp:
                print(f"✅ Login {app['name']}: {resp.status}")
        
        analyzer = AnalyzerHelper(session=session, use_cache=False)
        # Configurer l'AnalyzerHelper
        analyzer.config.MAX_WORKERS = 5
        analyzer.config.MAX_URL = 1000
        analyzer.config.GET_TIMEOUT = 2.0
        
        # Tester différentes pages
        pages_to_test = []
        
        if app["name"] == "DVWA":
            pages_to_test = [
                f"{app['url']}/vulnerabilities/sqli/",
                f"{app['url']}/vulnerabilities/xss_r/",
                f"{app['url']}/vulnerabilities/exec/",
                f"{app['url']}/vulnerabilities/csrf/",
            ]
        elif app["name"] == "Juice Shop":
            pages_to_test = [
                f"{app['url']}/",
                f"{app['url']}/#/search",
                f"{app['url']}/rest/products/search",
            ]
        elif app["name"] == "bWAPP":
            pages_to_test = [
                f"{app['url']}/sqli_1.php",
                f"{app['url']}/xss_get.php",
                f"{app['url']}/commandi.php",
            ]
        
        for page in pages_to_test:
            print(f"\n📌 Test page: {page}")
            try:
                result = await analyzer.analyse_and_parse_all(
                    url=page,
                    verify_reachability=True,
                    restore=False,
                    fetch=True,
                    semaphore=50
                )
                
                # Afficher les stats
                n_elements = len(result.elements)
                n_fetched = sum(1 for e in result.elements if e.fetched and not e.fetched.error)
                n_parsed = sum(1 for e in result.elements if e.parsed and e.parsed.a.elements)
                
                print(f"  ✅ Temps: {result.elapsed:.2f}s")
                print(f"  📊 Éléments: {n_elements}")
                print(f"  ├─ Fetched OK: {n_fetched}")
                print(f"  └─ Parsed OK: {n_parsed}")
                
                # Aperçu des liens trouvés
                if result.elements and result.elements[0].parsed:
                    a_links = result.elements[0].parsed.a.elements
                    if a_links:
                        print(f"  🔗 Premiers liens: {[l.get('abs_link', '')[:50] for l in a_links[:3]]}")
                        
            except Exception as e:
                print(f"  ❌ Erreur: {e}")
        
        await analyzer.close()
    
    await session.close()
    print("\n✅ Tests terminés!")

if __name__ == "__main__":
    asyncio.run(test_analyzer_on_vuln_apps())