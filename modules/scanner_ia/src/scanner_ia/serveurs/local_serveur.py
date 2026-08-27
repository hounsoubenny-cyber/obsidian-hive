#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 02:13:04 2026

@author: hounsousamuel
"""

"""
Serveur de test local pour crawler
Génère un site avec des milliers de pages et liens imbriqués
"""

import os
import random
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import time
import socket

# Configuration
PORT = 8080
BASE_DIR = "test_site"
NUM_LEVELS = 5  # Profondeur
PAGES_PER_LEVEL = 10  # Pages par niveau
MAX_LINKS_PER_PAGE = 15  # Liens max par page

class LinkGenerator:
    """Génère une structure de liens complexe"""
    
    def __init__(self):
        self.pages = {}  # {path: {"title":, "links": []}}
        self.all_urls = []
        self._generate_structure()
    
    def _generate_structure(self):
        """Génère une structure arborescente de pages"""
        
        # Page d'accueil
        self.pages["/"] = {
            "title": "Accueil - Site de test",
            "links": []
        }
        self.all_urls.append("/")
        
        # Générer les pages par niveau
        for level in range(1, NUM_LEVELS + 1):
            for page_num in range(PAGES_PER_LEVEL):
                # Créer un chemin unique
                path = f"/level{level}/page{page_num}.html"
                
                # Générer des titres aléatoires
                titles = [
                    f"Page {page_num} - Niveau {level}",
                    f"Article {page_num} - Section {level}",
                    f"Document {page_num} - Profondeur {level}",
                    f"Test {page_num} - Niveau {level}",
                    f"Démonstration {page_num}"
                ]
                
                self.pages[path] = {
                    "title": random.choice(titles),
                    "links": []
                }
                self.all_urls.append(path)
        
        # Générer les liens entre les pages
        self._generate_links()
    
    def _generate_links(self):
        """Crée des liens entre les pages (certains cycliques)"""
        
        for path, page in self.pages.items():
            # Combien de liens pour cette page ?
            num_links = random.randint(5, MAX_LINKS_PER_PAGE)
            
            for _ in range(num_links):
                # Choisir une page cible aléatoire
                target = random.choice(self.all_urls)
                
                # Parfois, créer des liens vers des pages inexistantes (404)
                if random.random() < 0.1:  # 10% de chances
                    target = f"/missing/page{random.randint(1,100)}.html"
                
                # Parfois, créer des liens externes
                # if random.random() < 0.05:  # 5% de chances
                #     external_sites = [
                #         "https://example.com",
                #         "https://httpbin.org/",
                #         "https://www.google.com",
                #         "https://www.wikipedia.org",
                #         "https://github.com",
                #         "https://stackoverflow.com"
                #     ]
                #     target = random.choice(external_sites)
                
                # Parfois, créer des ancres internes
                if random.random() < 0.15:  # 15% de chances
                    target += f"#section{random.randint(1,5)}"
                
                # Éviter les liens vers soi-même
                while target == path and not target.startswith("http"):
                    target = random.choice(self.all_urls)
                
                # Texte du lien
                link_texts = [
                    f"Lien vers {target}",
                    "Cliquez ici",
                    "En savoir plus",
                    f"Page {random.randint(1,100)}",
                    "Suite...",
                    "Détails",
                    "Lire l'article",
                    "Documentation",
                    "Exemple",
                    "Test"
                ]
                
                page["links"].append({
                    "url": target,
                    "text": random.choice(link_texts),
                    "nofollow": random.random() < 0.1  # 10% nofollow
                })

class TestSiteGenerator:
    """Génère les fichiers HTML du site de test"""
    
    def __init__(self, base_dir=BASE_DIR):
        self.base_dir = base_dir
        self.links = LinkGenerator()
    
    def generate_all(self):
        """Génère tous les fichiers HTML"""
        
        print(f"🧪 Génération du site de test dans {self.base_dir}/")
        print(f"   {len(self.links.pages)} pages à générer...")
        
        # Créer le répertoire de base
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Générer chaque page
        for path, page_data in self.links.pages.items():
            self._generate_page(path, page_data)
        
        # Générer le sitemap
        self._generate_sitemap()
        
        print(f"✅ Site généré avec succès !")
        print(f"   Pages: {len(self.links.pages)}")
        print(f"   Liens totaux: {sum(len(p['links']) for p in self.links.pages.values())}")
        print(f"   URL du site: http://localhost:{PORT}")
    
    def _generate_page(self, path, page_data):
        """Génère un fichier HTML"""
        
        # Gérer la page d'accueil
        if path == "/":
            full_path = os.path.join(self.base_dir, "index.html")
        else:
            # Créer les sous-répertoires si nécessaire
            full_path = os.path.join(self.base_dir, path.lstrip('/'))
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        # Générer le contenu HTML
        html = self._generate_html(path, page_data)
        
        # Écrire le fichier
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_html(self, path, page_data):
        """Génère le contenu HTML d'une page"""
        
        title = page_data["title"]
        links = page_data["links"]
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <meta name="description" content="Page de test pour crawler - {title}">
    <meta name="keywords" content="test, crawler, python, scraping">
    
    <!-- Meta tags avec URLs -->
    <meta property="og:url" content="http://localhost:{PORT}{path}">
    <meta property="og:image" content="http://localhost:{PORT}/images/test.jpg">
    <meta property="og:video" content="http://localhost:{PORT}/videos/test.mp4">
    
    <!-- Liens canoniques et alternates -->
    <link rel="canonical" href="http://localhost:{PORT}{path}">
    <link rel="alternate" href="http://localhost:{PORT}{path}?lang=en">
    
    <!-- Styles et scripts -->
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/script.js" defer></script>
    
    <!-- Favicon -->
    <link rel="icon" href="/favicon.ico">
</head>
<body>
    <header>
        <h1>{title}</h1>
        <nav>
            <ul>
                <li><a href="/">Accueil</a></li>
                <li><a href="/about.html">À propos</a></li>
                <li><a href="/contact.html">Contact</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <section class="content">
            <h2>Contenu de la page</h2>
            <p>Ceci est une page de test générée automatiquement pour le crawler.</p>
            <p>Page générée le {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </section>
        
        <section class="links">
            <h2>Liens ({len(links)})</h2>
            <ul>
"""
        
        # Ajouter les liens
        for link in links:
            rel = " rel='nofollow'" if link["nofollow"] else ""
            html += f'                <li><a href="{link["url"]}"{rel}>{link["text"]}</a></li>\n'
        
        # Ajouter des data-attributes
        data_attrs = ""
        for i in range(random.randint(3, 8)):
            data_attrs += f' data-test-{i}="/data/value{i}.json"'
        
        html += f"""            </ul>
        </section>
        
        <section class="images" {data_attrs}>
            <h2>Images avec data-src</h2>
            <img src="/images/placeholder.jpg" data-src="/images/real-image1.jpg" alt="Image 1">
            <img src="/images/placeholder.jpg" data-src="/images/real-image2.jpg" alt="Image 2" data-srcset="/images/small.jpg 300w, /images/large.jpg 600w">
            <img src="/images/placeholder.jpg" data-src="/images/real-image3.jpg" alt="Image 3" data-href="/details/image3.html">
        </section>
        
        <section class="forms">
            <h2>Formulaires</h2>
            <form action="/submit" method="post">
                <input type="text" name="name" placeholder="Nom">
                <input type="email" name="email" placeholder="Email">
                <button type="submit" formaction="/api/submit">Envoyer</button>
            </form>
        </section>
        
        <section class="iframe">
            <h2>Iframe</h2>
            <iframe src="/frame.html" width="300" height="200"></iframe>
        </section>
    </main>
    
    <footer>
        <p>&copy; 2026 - Site de test pour crawler</p>
        <ul>
            <li><a href="/privacy.html">Privacy</a></li>
            <li><a href="/terms.html">Terms</a></li>
            <li><a href="/sitemap.xml">Sitemap</a></li>
        </ul>
    </footer>
    
    <!-- Commentaires avec URLs cachées -->
    <!-- Lien caché: http://hidden.local/page.html -->
    <!-- API endpoint: /api/v1/data -->
</body>
</html>"""
        
        return html
    
    def _generate_sitemap(self):
        """Génère un sitemap.xml"""
        
        sitemap = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"""
        
        for path in self.links.all_urls:
            sitemap += f"""  <url>
    <loc>http://localhost:{PORT}{path}</loc>
    <lastmod>{time.strftime('%Y-%m-%d')}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
"""
        
        sitemap += "</urlset>"
        
        with open(os.path.join(self.base_dir, "sitemap.xml"), 'w', encoding='utf-8') as f:
            f.write(sitemap)

def run_server():
    """Lance le serveur HTTP"""
    
    os.chdir(BASE_DIR)
    handler = SimpleHTTPRequestHandler
    
    # Trouver un port libre
    port = PORT
    while True:
        try:
            server = HTTPServer(('', port), handler)
            print(f"🚀 Serveur démarré sur http://localhost:{port}")
            print(f"📁 Racine: {os.path.abspath('.')}")
            print("🔧 Appuyez sur Ctrl+C pour arrêter")
            server.serve_forever()
            break
        except OSError:
            print(f"⚠️  Port {port} occupé, essai du port {port+1}")
            port += 1

def main():
    """Fonction principale"""
    
    print("="*60)
    print("🔧 GÉNÉRATEUR DE SITE DE TEST POUR CRAWLER")
    print("="*60)
    
    # Générer le site
    generator = TestSiteGenerator()
    generator.generate_all()
    
    # Lancer le serveur
    print("\n" + "="*60)
    run_server()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Serveur arrêté")