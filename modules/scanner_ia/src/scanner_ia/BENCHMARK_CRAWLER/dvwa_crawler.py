#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 20 22:46:48 2026

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crawler DVWA simple — Pour debugger le problème de crawl.
Ne dépend pas du scanner, juste aiohttp + BeautifulSoup.
"""

import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

class DvwaCrawler:
    def __init__(self, base_url: str, username: str = "admin", password: str = "password"):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = None
        self.visited = set()
        self.to_visit = []
        self.results = []
        
    async def login(self):
        """Login à DVWA avec récupération du token CSRF"""
        print(f"🔐 Login sur {self.base_url}")
        
        # 1. Récupérer la page de login pour le token
        async with self.session.get(f"{self.base_url}/login.php") as resp:
            html = await resp.text()
            soup = BeautifulSoup(html, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            user_token = token_input['value'] if token_input else ''
        
        # 2. POST login
        data = {
            'username': self.username,
            'password': self.password,
            'Login': 'Login',
            'user_token': user_token
        }
        
        async with self.session.post(f"{self.base_url}/login.php", data=data) as resp:
            html = await resp.text()
            if 'Login failed' in html:
                raise Exception("❌ Échec login DVWA")
            print("✅ Login réussi")
            return True
    
    async def crawl_page(self, url: str, depth: int = 0, max_depth: int = 3):
        """Crawl une page et extrait les liens"""
        if url in self.visited or depth > max_depth:
            return
        
        print(f"  Crawl: {url} (depth={depth})")
        self.visited.add(url)
        
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    print(f"    ❌ Status {resp.status}")
                    return
                
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Extraire les liens
                links = []
                for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                    if tag.name == 'a' and tag.get('href'):
                        href = tag.get('href')
                        if href and not href.startswith('#') and not href.startswith('javascript:'):
                            links.append(href)
                    elif tag.name == 'link' and tag.get('href'):
                        links.append(tag.get('href'))
                    elif tag.name == 'script' and tag.get('src'):
                        links.append(tag.get('src'))
                    elif tag.name == 'img' and tag.get('src'):
                        links.append(tag.get('src'))
                    elif tag.name == 'form' and tag.get('action'):
                        links.append(tag.get('action'))
                
                # Filtrer et normaliser les liens
                page_results = {
                    'url': url,
                    'depth': depth,
                    'status': resp.status,
                    'links': [],
                    'forms': [],
                    'scripts': []
                }
                
                for link in links:
                    full_url = urljoin(url, link)
                    # Garder uniquement les URLs du même domaine
                    if full_url.startswith(self.base_url):
                        # Exclure les fichiers statiques
                        if not any(ext in full_url for ext in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.js']):
                            if full_url not in self.visited:
                                page_results['links'].append(full_url)
                                self.to_visit.append((full_url, depth + 1))
                
                # Extraire les formulaires
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    fields = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        fields.append({
                            'name': inp.get('name', ''),
                            'type': inp.get('type', 'text'),
                            'value': inp.get('value', '')
                        })
                    page_results['forms'].append({
                        'action': urljoin(url, action),
                        'method': method,
                        'fields': fields
                    })
                
                # Extraire les scripts inline (pour analyse XSS)
                for script in soup.find_all('script'):
                    if script.string:
                        page_results['scripts'].append(script.string[:200])
                
                self.results.append(page_results)
                
                # Afficher un résumé
                print(f"    ✅ {len(page_results['links'])} liens, {len(page_results['forms'])} formulaires")
                
        except Exception as e:
            print(f"    ❌ Erreur: {e}")
    
    async def run(self, max_depth: int = 2, max_pages: int = 20):
        """Lance le crawl"""
        print(f"\n🚀 Crawl DVWA sur {self.base_url}")
        print("=" * 60)
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Login
            await self.login()
            print(f"  Cookies: {list(self.session.cookie_jar)}")
            # Ajouter la page d'accueil
            self.to_visit.append((self.base_url, 0))
            
            # Crawl les pages
            count = 0
            while self.to_visit and count < max_pages:
                url, depth = self.to_visit.pop(0)
                if url not in self.visited:
                    await self.crawl_page(url, depth, max_depth)
                    count += 1
                    await asyncio.sleep(0.1)  # Petite pause
            
            # Résumé
            print("\n" + "=" * 60)
            print("📊 RÉSULTATS DU CRAWL")
            print("=" * 60)
            print(f"  Pages crawlées: {len(self.results)}")
            print(f"  URLs uniques: {len(self.visited)}")
            
            # Lister les pages vulnérables trouvées
            vuln_pages = []
            for page in self.results:
                url = page['url']
                if any(x in url for x in ['vulnerabilities', 'sqli', 'xss', 'exec', 'csrf', 'upload']):
                    vuln_pages.append(url)
            
            if vuln_pages:
                print(f"\n  🎯 Pages vulnérables trouvées:")
                for url in vuln_pages:
                    print(f"    - {url}")
            else:
                print("\n  ⚠️ Aucune page vulnérable trouvée")
                print("  Vérifie que DVWA est bien configuré avec security_level=low")
            
            # Afficher les détails par page
            print("\n  📄 Détails:")
            for page in self.results:
                print(f"    - {page['url']} (depth={page['depth']})")
                if page['forms']:
                    print(f"      Formulaires: {len(page['forms'])}")
                if page['scripts']:
                    print(f"      Scripts inline: {len(page['scripts'])}")
            
            return self.results


async def main():
    """Test rapide"""
    import sys
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    
    crawler = DvwaCrawler(base_url)
    results = await crawler.run(max_depth=2, max_pages=20)
    
    # Vérifier que les pages vulnérables sont accessibles
    print("\n" + "=" * 60)
    print("🔍 VÉRIFICATION D'ACCÈS")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Vérifier que les cookies sont présents
        print(f"  Cookies: {list(session.cookie_jar)}")
        
        test_urls = [
            f"{base_url}/vulnerabilities/sqli/",
            f"{base_url}/vulnerabilities/xss_r/",
            f"{base_url}/vulnerabilities/exec/",
            f"{base_url}/vulnerabilities/csrf/",
            f"{base_url}/vulnerabilities/upload/",
        ]
        
        for url in test_urls:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        print(f"  ✅ {url} → {resp.status}")
                    else:
                        print(f"  ❌ {url} → {resp.status}")
            except Exception as e:
                print(f"  ❌ {url} → Erreur: {e}")
    
    print("\n✅ Test terminé")

if __name__ == "__main__":
    asyncio.run(main())