#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ShieldAI — Serveur de données d'entraînement pour CosineSimilarityTFIDF  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Génère des body HTTP NORMAUX et VARIÉS :                                   ║
║  HTML (e-commerce, blog, admin, landing, docs), JSON API, XML, erreurs      ║
║  standard. Pas de payload injecté — uniquement des réponses saines.         ║
║                                                                             ║
║  Usage : python train_server.py → http://localhost:7000                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
Author  : Samuel — ShieldAI
"""

import random, time, json, os
from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Données fictives ──────────────────────────────────────────────────────────
PRODUCTS = [
    {"id": i, "name": f"Produit {i}", "price": round(random.uniform(5, 500), 2),
     "category": random.choice(["electronics", "clothing", "books", "food", "sports"]),
     "stock": random.randint(0, 100), "rating": round(random.uniform(1, 5), 1),
     "description": f"Description détaillée du produit {i}. Qualité garantie.",
     "brand": random.choice(["BrandA", "BrandB", "BrandC", "ShieldBrand"]),
     "sku": f"SKU-{i:05d}"}
    for i in range(1, 51)
]

USERS = [
    {"id": i, "username": f"user{i}", "email": f"user{i}@example.com",
     "created_at": "2025-01-01", "role": "user", "active": True}
    for i in range(1, 21)
]

ARTICLES = [
    {"id": i, "title": f"Article {i} — Guide complet",
     "author": f"Auteur {i % 5 + 1}", "category": random.choice(["tech", "lifestyle", "news", "tutorial"]),
     "tags": ["python", "web", "security"][:random.randint(1, 3)],
     "published_at": "2025-03-01", "views": random.randint(100, 10000),
     "body": f"Ceci est le contenu complet de l'article {i}. " * 10}
    for i in range(1, 31)
]

COMMENTS = [
    {"id": i, "user_id": random.randint(1, 20), "article_id": random.randint(1, 30),
     "content": f"Commentaire {i} : excellent article, merci pour le partage.",
     "likes": random.randint(0, 50), "created_at": "2025-03-15"}
    for i in range(1, 41)
]

CATEGORIES = ["electronics", "clothing", "books", "food", "sports", "home", "beauty", "toys"]
TAGS = ["python", "javascript", "web", "security", "linux", "docker", "api", "machine-learning"]


# ── HOME & NAVIGATION ─────────────────────────────────────────────────────────
@app.route('/')
def home():
    return """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="ShieldAI Training Server — Données normales pour entraînement">
<title>ShieldAI Training Server</title>
<link rel="stylesheet" href="/static/css/main.css">
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
</head>
<body>
<header>
  <nav>
    <div class="logo"><a href="/">ShieldAI Store</a></div>
    <ul>
      <li><a href="/shop">Boutique</a></li>
      <li><a href="/blog">Blog</a></li>
      <li><a href="/about">À propos</a></li>
      <li><a href="/contact">Contact</a></li>
      <li><a href="/login">Connexion</a></li>
    </ul>
    <div class="search-bar">
      <input type="text" placeholder="Rechercher un produit...">
      <button>🔍</button>
    </div>
  </nav>
</header>
<main>
  <section class="hero">
    <h1>Bienvenue sur ShieldAI Store</h1>
    <p>Découvrez notre sélection de produits de qualité au meilleur prix.</p>
    <a href="/shop" class="cta-button">Voir nos produits</a>
  </section>
  <section class="featured">
    <h2>Produits en vedette</h2>
    <div class="product-grid">
      <div class="product-card"><h3>Produit Premium</h3><p class="price">€29.99</p><button>Ajouter au panier</button></div>
      <div class="product-card"><h3>Édition Limitée</h3><p class="price">€99.99</p><button>Ajouter au panier</button></div>
      <div class="product-card"><h3>Best Seller</h3><p class="price">€14.99</p><button>Ajouter au panier</button></div>
    </div>
  </section>
  <section class="categories">
    <h2>Catégories populaires</h2>
    <ul>
      <li><a href="/shop?category=electronics">Électronique</a></li>
      <li><a href="/shop?category=clothing">Vêtements</a></li>
      <li><a href="/shop?category=books">Livres</a></li>
      <li><a href="/shop?category=sports">Sport</a></li>
    </ul>
  </section>
  <section class="newsletter">
    <h2>Newsletter</h2>
    <form method="post" action="/newsletter/subscribe">
      <input type="email" name="email" placeholder="Votre adresse email">
      <button type="submit">S'inscrire</button>
    </form>
  </section>
</main>
<footer>
  <p>&copy; 2026 ShieldAI Store. Tous droits réservés.</p>
  <ul>
    <li><a href="/privacy">Confidentialité</a></li>
    <li><a href="/terms">CGU</a></li>
    <li><a href="/sitemap.xml">Sitemap</a></li>
  </ul>
</footer>
</body></html>"""


@app.route('/about')
def about():
    return """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>À propos — ShieldAI</title></head>
<body>
<header><nav><a href="/">Accueil</a> | <a href="/shop">Boutique</a> | <a href="/about">À propos</a></nav></header>
<main>
  <h1>À propos de nous</h1>
  <section>
    <h2>Notre mission</h2>
    <p>ShieldAI est une entreprise spécialisée dans la sécurité informatique et le développement logiciel.
    Fondée en 2022, nous accompagnons nos clients dans leur transformation numérique.</p>
  </section>
  <section>
    <h2>Notre équipe</h2>
    <div class="team-grid">
      <div class="team-member"><img src="/images/team1.jpg" alt="Samuel"><h3>Samuel</h3><p>CEO &amp; Fondateur</p></div>
      <div class="team-member"><img src="/images/team2.jpg" alt="Alice"><h3>Alice</h3><p>CTO</p></div>
      <div class="team-member"><img src="/images/team3.jpg" alt="Bob"><h3>Bob</h3><p>Lead Developer</p></div>
    </div>
  </section>
  <section>
    <h2>Nos valeurs</h2>
    <ul>
      <li>Innovation</li>
      <li>Transparence</li>
      <li>Excellence technique</li>
      <li>Sécurité avant tout</li>
    </ul>
  </section>
</main>
<footer><p>&copy; 2026 ShieldAI</p></footer>
</body></html>"""


@app.route('/contact')
def contact():
    return """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Contact — ShieldAI</title></head>
<body>
<h1>Contactez-nous</h1>
<form method="post" action="/contact/send">
  <label>Nom :<input type="text" name="name" required></label><br>
  <label>Email :<input type="email" name="email" required></label><br>
  <label>Sujet :
    <select name="subject">
      <option value="support">Support technique</option>
      <option value="sales">Ventes</option>
      <option value="partnership">Partenariat</option>
      <option value="other">Autre</option>
    </select>
  </label><br>
  <label>Message :<textarea name="message" rows="5" cols="40" required></textarea></label><br>
  <button type="submit">Envoyer</button>
</form>
<div class="contact-info">
  <p>📧 contact@shieldai.io</p>
  <p>📞 +33 1 23 45 67 89</p>
  <p>📍 123 Rue de la Sécurité, Paris, France</p>
</div>
</body></html>"""


@app.route('/contact/send', methods=['POST'])
def contact_send():
    name = request.form.get('name', 'Visiteur')
    return f"""<html><body>
<h1>Message envoyé</h1>
<p>Merci {name}, votre message a bien été reçu. Nous vous répondrons sous 24h.</p>
<a href="/">Retour à l'accueil</a>
</body></html>"""


# ── E-COMMERCE ────────────────────────────────────────────────────────────────
@app.route('/shop')
def shop():
    category = request.args.get('category', '')
    page = int(request.args.get('page', 1))
    per_page = 12
    filtered = [p for p in PRODUCTS if not category or p['category'] == category]
    start = (page - 1) * per_page
    items = filtered[start:start + per_page]
    total_pages = (len(filtered) + per_page - 1) // per_page
    
    cards = ""
    for p in items:
        cards += f"""
        <div class="product-card" data-id="{p['id']}" data-category="{p['category']}">
          <img src="/images/products/{p['id']}.jpg" alt="{p['name']}" loading="lazy">
          <h3><a href="/shop/product/{p['id']}">{p['name']}</a></h3>
          <p class="brand">{p['brand']}</p>
          <p class="price">€{p['price']}</p>
          <p class="rating">{'⭐' * int(p['rating'])} ({p['rating']})</p>
          <p class="stock">{'En stock' if p['stock'] > 0 else 'Rupture'}</p>
          <button onclick="addToCart({p['id']})">Ajouter au panier</button>
        </div>"""
    
    pagination = "".join(f'<a href="/shop?page={i}" class="{"active" if i==page else ""}">{i}</a>'
                         for i in range(1, total_pages + 1))
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>Boutique — {category or "Tous les produits"}</title>
<script>function addToCart(id){{fetch('/api/cart/add',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{product_id:id,qty:1}})}});}} </script>
</head><body>
<h1>Boutique {f'— {category}' if category else ''}</h1>
<div class="filters">
  <a href="/shop">Tous</a>
  {''.join(f'<a href="/shop?category={c}">{c}</a>' for c in CATEGORIES)}
</div>
<p>{len(filtered)} produit(s) trouvé(s)</p>
<div class="product-grid">{cards}</div>
<div class="pagination">{pagination}</div>
</body></html>"""


@app.route('/shop/product/<int:pid>')
def product_detail(pid):
    p = next((x for x in PRODUCTS if x['id'] == pid), None)
    if not p:
        return "<html><body><h1>404 — Produit non trouvé</h1><a href='/shop'>Retour boutique</a></body></html>", 404
    related = random.sample([x for x in PRODUCTS if x['category'] == p['category'] and x['id'] != pid], min(3, 4))
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<meta property="og:title" content="{p['name']}">
<meta property="og:description" content="{p['description']}">
<title>{p['name']} — ShieldAI Store</title>
</head><body>
<nav><a href="/">Accueil</a> &gt; <a href="/shop">Boutique</a> &gt; {p['name']}</nav>
<div class="product-detail">
  <div class="product-images"><img src="/images/products/{p['id']}.jpg" alt="{p['name']}"></div>
  <div class="product-info">
    <h1>{p['name']}</h1>
    <p class="sku">Référence : {p['sku']}</p>
    <p class="brand">Marque : {p['brand']}</p>
    <p class="price">€{p['price']}</p>
    <p class="rating">Note : {p['rating']}/5 ({random.randint(10,200)} avis)</p>
    <p class="stock">Disponibilité : {'En stock ({} unités)'.format(p['stock']) if p['stock'] > 0 else 'Rupture de stock'}</p>
    <p class="description">{p['description']}</p>
    <form method="post" action="/api/cart/add">
      <input type="hidden" name="product_id" value="{p['id']}">
      <label>Quantité : <input type="number" name="qty" value="1" min="1" max="{p['stock']}"></label>
      <button type="submit">Ajouter au panier</button>
    </form>
  </div>
</div>
<section class="related">
  <h2>Produits similaires</h2>
  {''.join(f'<div><a href="/shop/product/{r["id"]}">{r["name"]}</a> — €{r["price"]}</div>' for r in related)}
</section>
</body></html>"""


@app.route('/shop/cart')
def cart():
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Panier — ShieldAI Store</title></head>
<body>
<h1>Votre panier</h1>
<table>
  <thead><tr><th>Produit</th><th>Prix</th><th>Quantité</th><th>Total</th><th>Action</th></tr></thead>
  <tbody>
    <tr><td>Produit 1</td><td>€29.99</td><td><input type="number" value="2" min="1"></td><td>€59.98</td><td><button>Supprimer</button></td></tr>
    <tr><td>Produit 5</td><td>€14.99</td><td><input type="number" value="1" min="1"></td><td>€14.99</td><td><button>Supprimer</button></td></tr>
  </tbody>
</table>
<div class="cart-summary">
  <p>Sous-total : €74.97</p>
  <p>Livraison : €5.00</p>
  <p><strong>Total : €79.97</strong></p>
  <a href="/shop/checkout">Passer la commande</a>
</div>
</body></html>"""


@app.route('/shop/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        return """<html><body>
<h1>Commande confirmée !</h1>
<p>Merci pour votre commande. Vous recevrez un email de confirmation.</p>
<p>Numéro de commande : #ORD-2026-00123</p>
<a href="/">Retour à l'accueil</a>
</body></html>"""
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Paiement — ShieldAI Store</title></head>
<body>
<h1>Paiement sécurisé</h1>
<form method="post">
  <fieldset>
    <legend>Adresse de livraison</legend>
    <input type="text" name="firstname" placeholder="Prénom" required>
    <input type="text" name="lastname" placeholder="Nom" required>
    <input type="text" name="address" placeholder="Adresse" required>
    <input type="text" name="city" placeholder="Ville" required>
    <input type="text" name="zip" placeholder="Code postal" required>
    <select name="country"><option value="FR">France</option><option value="BE">Belgique</option></select>
  </fieldset>
  <fieldset>
    <legend>Paiement</legend>
    <input type="text" name="card_number" placeholder="Numéro de carte" pattern="[0-9]{16}" required>
    <input type="text" name="expiry" placeholder="MM/AA" required>
    <input type="text" name="cvv" placeholder="CVV" pattern="[0-9]{3}" required>
  </fieldset>
  <button type="submit">Confirmer la commande</button>
</form>
</body></html>"""


# ── BLOG ──────────────────────────────────────────────────────────────────────
@app.route('/blog')
def blog():
    page = int(request.args.get('page', 1))
    tag = request.args.get('tag', '')
    per_page = 5
    filtered = [a for a in ARTICLES if not tag or tag in a['tags']]
    items = filtered[(page-1)*per_page:page*per_page]
    posts = "".join(f"""
    <article class="post-card">
      <h2><a href="/blog/{a['id']}">{a['title']}</a></h2>
      <p class="meta">Par {a['author']} | {a['published_at']} | {a['views']} vues</p>
      <p class="category">Catégorie : {a['category']}</p>
      <p class="tags">Tags : {', '.join(f'<a href="/blog?tag={t}">{t}</a>' for t in a['tags'])}</p>
      <p class="excerpt">{a['body'][:200]}...</p>
      <a href="/blog/{a['id']}">Lire la suite</a>
    </article>""" for a in items)
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Blog — ShieldAI</title></head>
<body>
<h1>Blog ShieldAI</h1>
<div class="tag-cloud">
  Filtrer par tag : {''.join(f'<a href="/blog?tag={t}">{t}</a> ' for t in TAGS)}
</div>
<div class="posts">{posts}</div>
<div class="pagination">
  {f'<a href="/blog?page={page-1}">Précédent</a>' if page > 1 else ''}
  Page {page}
  {f'<a href="/blog?page={page+1}">Suivant</a>' if len(filtered) > page*per_page else ''}
</div>
</body></html>"""


@app.route('/blog/<int:aid>')
def blog_post(aid):
    a = next((x for x in ARTICLES if x['id'] == aid), None)
    if not a:
        return "<html><body><h1>404 — Article non trouvé</h1></body></html>", 404
    comments = [c for c in COMMENTS if c['article_id'] == aid]
    comment_html = "".join(f"""
    <div class="comment">
      <p class="comment-author">Utilisateur {c['user_id']} — {c['created_at']}</p>
      <p>{c['content']}</p>
      <p>👍 {c['likes']} likes</p>
    </div>""" for c in comments)
    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="author" content="{a['author']}">
<meta property="article:published_time" content="{a['published_at']}">
<title>{a['title']} — ShieldAI Blog</title>
</head><body>
<nav><a href="/">Accueil</a> &gt; <a href="/blog">Blog</a> &gt; {a['title']}</nav>
<article>
  <h1>{a['title']}</h1>
  <p class="meta">Par <strong>{a['author']}</strong> | {a['published_at']} | {a['views']} vues</p>
  <div class="tags">{''.join(f'<span class="tag">{t}</span>' for t in a['tags'])}</div>
  <div class="content">{a['body']}</div>
</article>
<section class="share">
  <h3>Partager</h3>
  <a href="https://twitter.com/share?url=/blog/{aid}">Twitter</a>
  <a href="https://linkedin.com/share?url=/blog/{aid}">LinkedIn</a>
</section>
<section class="comments">
  <h2>{len(comments)} commentaire(s)</h2>
  {comment_html}
  <form method="post" action="/blog/{aid}/comment">
    <h3>Laisser un commentaire</h3>
    <textarea name="content" rows="4" placeholder="Votre commentaire..." required></textarea>
    <button type="submit">Publier</button>
  </form>
</section>
</body></html>"""


@app.route('/blog/<int:aid>/comment', methods=['POST'])
def blog_comment(aid):
    return f"""<html><body>
<p>Merci pour votre commentaire sur l'article {aid}. Il sera publié après modération.</p>
<a href="/blog/{aid}">Retour à l'article</a>
</body></html>"""


# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return """<html><body>
<h1>Connexion réussie</h1>
<p>Bienvenue sur votre espace personnel.</p>
<a href="/dashboard">Accéder au tableau de bord</a>
</body></html>"""
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Connexion — ShieldAI</title></head>
<body>
<main class="auth-container">
  <h1>Connexion</h1>
  <form method="post" class="auth-form">
    <div class="form-group">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autocomplete="email">
    </div>
    <div class="form-group">
      <label for="password">Mot de passe</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
    </div>
    <div class="form-options">
      <label><input type="checkbox" name="remember"> Se souvenir de moi</label>
      <a href="/forgot-password">Mot de passe oublié ?</a>
    </div>
    <button type="submit" class="btn-primary">Se connecter</button>
  </form>
  <p>Pas encore de compte ? <a href="/register">S'inscrire</a></p>
  <div class="social-login">
    <p>Ou se connecter avec :</p>
    <button class="btn-google">Google</button>
    <button class="btn-github">GitHub</button>
  </div>
</main>
</body></html>"""


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        return """<html><body><h1>Compte créé !</h1>
<p>Votre compte a été créé avec succès. Vérifiez votre email pour l'activer.</p>
<a href="/login">Se connecter</a></body></html>"""
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Inscription — ShieldAI</title></head>
<body>
<h1>Créer un compte</h1>
<form method="post">
  <input type="text" name="firstname" placeholder="Prénom" required>
  <input type="text" name="lastname" placeholder="Nom" required>
  <input type="email" name="email" placeholder="Email" required>
  <input type="password" name="password" placeholder="Mot de passe" required minlength="8">
  <input type="password" name="confirm_password" placeholder="Confirmer le mot de passe" required>
  <label><input type="checkbox" name="terms" required> J'accepte les CGU</label>
  <button type="submit">S'inscrire</button>
</form>
</body></html>"""


@app.route('/dashboard')
def dashboard():
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Tableau de bord</title></head>
<body>
<h1>Tableau de bord</h1>
<div class="stats-grid">
  <div class="stat-card"><h3>Commandes</h3><p class="stat-value">42</p><p>+12% ce mois</p></div>
  <div class="stat-card"><h3>Chiffre d'affaires</h3><p class="stat-value">€12,450</p><p>+8% ce mois</p></div>
  <div class="stat-card"><h3>Nouveaux clients</h3><p class="stat-value">128</p><p>+23% ce mois</p></div>
  <div class="stat-card"><h3>Produits vus</h3><p class="stat-value">5,234</p><p>+5% ce mois</p></div>
</div>
<section class="recent-orders">
  <h2>Commandes récentes</h2>
  <table>
    <thead><tr><th>ID</th><th>Client</th><th>Montant</th><th>Statut</th><th>Date</th></tr></thead>
    <tbody>
      <tr><td>#001</td><td>Jean Dupont</td><td>€89.99</td><td><span class="badge success">Livré</span></td><td>2026-03-18</td></tr>
      <tr><td>#002</td><td>Marie Martin</td><td>€234.50</td><td><span class="badge warning">En transit</span></td><td>2026-03-19</td></tr>
      <tr><td>#003</td><td>Pierre Bernard</td><td>€45.00</td><td><span class="badge info">En préparation</span></td><td>2026-03-19</td></tr>
    </tbody>
  </table>
</section>
</body></html>"""


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        return "<html><body><p>Email de réinitialisation envoyé si le compte existe.</p></body></html>"
    return """<html><body><h1>Mot de passe oublié</h1>
<form method="post"><input type="email" name="email" placeholder="Votre email" required><button>Envoyer</button></form>
</body></html>"""


# ── JSON API REST ─────────────────────────────────────────────────────────────
@app.route('/api/v1/products')
def api_products():
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 10)), 50)
    category = request.args.get('category', '')
    search = request.args.get('search', '').lower()
    sort = request.args.get('sort', 'id')
    
    filtered = PRODUCTS.copy()
    if category:
        filtered = [p for p in filtered if p['category'] == category]
    if search:
        filtered = [p for p in filtered if search in p['name'].lower() or search in p['description'].lower()]
    if sort in ('price', 'rating', 'id'):
        filtered.sort(key=lambda x: x[sort])
    
    total = len(filtered)
    items = filtered[(page-1)*limit:page*limit]
    return jsonify({
        "status": "success",
        "data": items,
        "meta": {
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": (total + limit - 1) // limit,
            "has_next": page * limit < total,
            "has_prev": page > 1
        }
    })


@app.route('/api/v1/products/<int:pid>')
def api_product(pid):
    p = next((x for x in PRODUCTS if x['id'] == pid), None)
    if not p:
        return jsonify({"status": "error", "message": "Product not found", "code": 404}), 404
    return jsonify({"status": "success", "data": p})


@app.route('/api/v1/users')
def api_users():
    return jsonify({
        "status": "success",
        "data": USERS[:10],
        "meta": {"total": len(USERS)}
    })


@app.route('/api/v1/users/<int:uid>')
def api_user(uid):
    u = next((x for x in USERS if x['id'] == uid), None)
    if not u:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "data": u})


@app.route('/api/v1/articles')
def api_articles():
    category = request.args.get('category', '')
    tag = request.args.get('tag', '')
    filtered = ARTICLES.copy()
    if category:
        filtered = [a for a in filtered if a['category'] == category]
    if tag:
        filtered = [a for a in filtered if tag in a['tags']]
    return jsonify({"status": "success", "data": filtered[:10], "meta": {"total": len(filtered)}})


@app.route('/api/v1/search')
def api_search():
    q = request.args.get('q', '').lower()
    if not q:
        return jsonify({"status": "error", "message": "Query parameter 'q' is required"}), 400
    results = {
        "products": [p for p in PRODUCTS if q in p['name'].lower()][:5],
        "articles": [a for a in ARTICLES if q in a['title'].lower()][:3],
    }
    return jsonify({"status": "success", "query": q, "results": results,
                    "total": sum(len(v) for v in results.values())})


@app.route('/api/v1/categories')
def api_categories():
    stats = {c: len([p for p in PRODUCTS if p['category'] == c]) for c in CATEGORIES}
    return jsonify({"status": "success", "data": stats})


@app.route('/api/v1/stats')
def api_stats():
    return jsonify({
        "status": "success",
        "data": {
            "total_products": len(PRODUCTS),
            "total_users": len(USERS),
            "total_articles": len(ARTICLES),
            "total_comments": len(COMMENTS),
            "categories": len(CATEGORIES),
            "avg_price": round(sum(p['price'] for p in PRODUCTS) / len(PRODUCTS), 2),
            "avg_rating": round(sum(p['rating'] for p in PRODUCTS) / len(PRODUCTS), 2),
            "timestamp": time.time()
        }
    })


@app.route('/api/v1/health')
def api_health():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "uptime": time.time(),
        "services": {"database": "ok", "cache": "ok", "storage": "ok"}
    })


@app.route('/api/cart/add', methods=['POST'])
def api_cart_add():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "success", "message": "Produit ajouté au panier",
                    "cart_total": random.randint(1, 10), "product_id": data.get('product_id')})


@app.route('/api/cart', methods=['GET'])
def api_cart():
    return jsonify({"status": "success", "items": [], "total": 0.0, "count": 0})


@app.route('/api/v1/newsletter/subscribe', methods=['POST'])
def api_newsletter():
    data = request.get_json(silent=True) or request.form
    return jsonify({"status": "success", "message": "Inscription réussie", "email": data.get('email', '')})


# ── XML / RSS ─────────────────────────────────────────────────────────────────
@app.route('/feed.rss')
def rss_feed():
    items = "".join(f"""
    <item>
      <title>{a['title']}</title>
      <link>http://localhost:7000/blog/{a['id']}</link>
      <description>{a['body'][:200]}</description>
      <author>{a['author']}</author>
      <pubDate>{a['published_at']}</pubDate>
      <category>{a['category']}</category>
    </item>""" for a in ARTICLES[:10])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>ShieldAI Blog</title>
    <link>http://localhost:7000</link>
    <description>Les derniers articles de ShieldAI</description>
    <language>fr-FR</language>
    <lastBuildDate>{time.strftime('%a, %d %b %Y %H:%M:%S +0000')}</lastBuildDate>
    <atom:link href="http://localhost:7000/feed.rss" rel="self" type="application/rss+xml"/>
    {items}
  </channel>
</rss>"""
    return Response(xml, content_type='application/rss+xml; charset=utf-8')


@app.route('/sitemap.xml')
def sitemap():
    urls = ["/", "/shop", "/blog", "/about", "/contact", "/login", "/register"] + \
           [f"/shop/product/{p['id']}" for p in PRODUCTS[:20]] + \
           [f"/blog/{a['id']}" for a in ARTICLES[:10]]
    entries = "".join(f"""
  <url>
    <loc>http://localhost:7000{u}</loc>
    <lastmod>2026-03-19</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>""" for u in urls)
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{entries}
</urlset>"""
    return Response(xml, content_type='application/xml; charset=utf-8')


@app.route('/api/v1/export/products.xml')
def export_xml():
    items = "".join(f"""
  <product id="{p['id']}">
    <name>{p['name']}</name>
    <price currency="EUR">{p['price']}</price>
    <category>{p['category']}</category>
    <brand>{p['brand']}</brand>
    <sku>{p['sku']}</sku>
    <stock>{p['stock']}</stock>
    <rating>{p['rating']}</rating>
  </product>""" for p in PRODUCTS[:20])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<catalog version="1.0">
  <generated_at>{time.strftime('%Y-%m-%dT%H:%M:%S')}</generated_at>
  <total_products>{len(PRODUCTS)}</total_products>
  <products>{items}
  </products>
</catalog>"""
    return Response(xml, content_type='application/xml; charset=utf-8')


# ── PAGES STATIQUES & UTILITAIRES ────────────────────────────────────────────
@app.route('/privacy')
def privacy():
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Politique de confidentialité</title></head>
<body>
<h1>Politique de confidentialité</h1>
<p>Dernière mise à jour : 19 mars 2026</p>
<h2>1. Collecte des données</h2>
<p>Nous collectons les données suivantes : nom, adresse email, adresse de livraison lors de vos commandes.</p>
<h2>2. Utilisation des données</h2>
<p>Vos données sont utilisées uniquement pour traiter vos commandes et vous envoyer les communications liées à votre compte.</p>
<h2>3. Conservation</h2>
<p>Vos données sont conservées 3 ans après votre dernière commande conformément à la législation en vigueur.</p>
<h2>4. Vos droits</h2>
<p>Conformément au RGPD, vous disposez d'un droit d'accès, de rectification et de suppression de vos données.</p>
<h2>5. Contact</h2>
<p>Pour exercer vos droits : privacy@shieldai.io</p>
</body></html>"""


@app.route('/terms')
def terms():
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Conditions Générales d'Utilisation</title></head>
<body>
<h1>Conditions Générales d'Utilisation</h1>
<h2>Article 1 — Objet</h2>
<p>Les présentes CGU régissent l'utilisation du site ShieldAI Store.</p>
<h2>Article 2 — Accès au service</h2>
<p>Le service est accessible 24h/24 et 7j/7, sous réserve de maintenances.</p>
<h2>Article 3 — Propriété intellectuelle</h2>
<p>L'ensemble du contenu est protégé par le droit d'auteur.</p>
<h2>Article 4 — Responsabilité</h2>
<p>ShieldAI ne saurait être tenu responsable des dommages indirects.</p>
</body></html>"""


@app.route('/faq')
def faq():
    faqs = [
        ("Comment passer une commande ?", "Ajoutez les produits au panier, puis validez en cliquant sur Commander."),
        ("Quels sont les délais de livraison ?", "Livraison en 2-5 jours ouvrés selon votre zone géographique."),
        ("Comment retourner un produit ?", "Vous disposez de 30 jours pour retourner un produit non utilisé."),
        ("Le paiement est-il sécurisé ?", "Oui, nous utilisons le protocole SSL et 3D Secure."),
        ("Puis-je modifier ma commande ?", "Oui, dans les 2h suivant la passation de commande."),
    ]
    items = "".join(f"<details><summary>{q}</summary><p>{a}</p></details>" for q, a in faqs)
    return f"""<html><head><meta charset="UTF-8"><title>FAQ</title></head>
<body><h1>Questions fréquentes</h1>{items}</body></html>"""


@app.route('/newsletter/subscribe', methods=['POST'])
def newsletter_subscribe():
    email = request.form.get('email', '')
    return f"""<html><body>
<h1>Inscription confirmée !</h1>
<p>L'adresse {email} a bien été ajoutée à notre newsletter.</p>
<a href="/">Retour à l'accueil</a>
</body></html>"""


@app.route('/search')
def search():
    q = request.args.get('q', '')
    if not q:
        return """<html><body>
<h1>Recherche</h1>
<form method="get"><input type="text" name="q" placeholder="Rechercher..."><button>Rechercher</button></form>
</body></html>"""
    results_p = [p for p in PRODUCTS if q.lower() in p['name'].lower()][:5]
    results_a = [a for a in ARTICLES if q.lower() in a['title'].lower()][:3]
    total = len(results_p) + len(results_a)
    return f"""<html><head><meta charset="UTF-8"><title>Résultats pour "{q}"</title></head>
<body>
<h1>{total} résultat(s) pour "{q}"</h1>
<section>
  <h2>Produits ({len(results_p)})</h2>
  {''.join(f'<div><a href="/shop/product/{p["id"]}">{p["name"]}</a> — €{p["price"]}</div>' for p in results_p)}
</section>
<section>
  <h2>Articles ({len(results_a)})</h2>
  {''.join(f'<div><a href="/blog/{a["id"]}">{a["title"]}</a></div>' for a in results_a)}
</section>
</body></html>"""


# ── ERREURS STANDARD ─────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept:
        return jsonify({"status": "error", "message": "Resource not found", "code": 404}), 404
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>404 — Page non trouvée</title></head>
<body>h
<h1>404 — Page non trouvée</h1>
<p>La page que vous recherchez n'existe pas ou a été déplacée.</p>
<ul>
  <li><a href="/">Retour à l'accueil</a></li>
  <li><a href="/shop">Boutique</a></li>
  <li><a href="/search">Recherche</a></li>
</ul>
</body></html>""", 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error", "code": 500}), 500


@app.errorhandler(403)
def forbidden(e):
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>403 — Accès refusé</title></head>
<body>
<h1>403 — Accès refusé</h1>
<p>Vous n'avez pas les droits pour accéder à cette page.</p>
<a href="/login">Se connecter</a>
</body></html>""", 403


if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════╗
║  ShieldAI Training Server — Données normales            ║
║  URL : http://localhost:7000                             ║
║  Routes : ~45 endpoints HTML + JSON + XML               ║
╚══════════════════════════════════════════════════════════╝
""")
    app.run(host='0.0.0.0', port=7000, debug=False, threaded=True)
