#!/usr/bin/env python3
"""
Mini SPA de test — simule une vraie Single Page Application.
Routes JS dynamiques, fetch API, formulaires générés par JS.
Lance avec : python spa_server.py
"""

from flask import Flask, jsonify

app = Flask(__name__)

# ── HTML Shell — vide, tout est généré par JS ─────────────────────────────────
@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>ShieldAI Test SPA</title>
</head>
<body>
    <div id="root">Chargement...</div>

    <script>
    // ── Router SPA simple ────────────────────────────────────────────────────
    const routes = {
        "/":          homePage,
        "/login":     loginPage,
        "/dashboard": dashboardPage,
        "/profile":   profilePage,
        "/admin":     adminPage,
        "/settings":  settingsPage,
        "/api/users": null,  // API endpoint, pas de page
    };

    function navigate(path) {
        window.history.pushState({}, "", path);
        render(path);
    }

    function render(path) {
        const fn = routes[path];
        if (fn) fn();
    }

    // ── Pages ────────────────────────────────────────────────────────────────
    function homePage() {
        document.getElementById("root").innerHTML = `
            <h1>Accueil</h1>
            <nav>
                <a href="/login"     onclick="navigate('/login');     return false;">Login</a>
                <a href="/dashboard" onclick="navigate('/dashboard'); return false;">Dashboard</a>
                <a href="/profile"   onclick="navigate('/profile');   return false;">Profile</a>
                <a href="/admin"     onclick="navigate('/admin');     return false;">Admin</a>
                <a href="/settings"  onclick="navigate('/settings');  return false;">Settings</a>
            </nav>
            <form id="search-form">
                <input type="text" name="q" placeholder="Recherche...">
                <button type="submit">Chercher</button>
            </form>
        `;

        // Fetch dynamique vers l'API
        fetch("/api/users")
            .then(r => r.json())
            .then(data => {
                const ul = document.createElement("ul");
                ul.id = "users-list";
                data.users.forEach(u => {
                    const li = document.createElement("li");
                    li.innerHTML = `<a href="/profile?id=${u.id}"
                        onclick="navigate('/profile?id=${u.id}'); return false;">${u.name}</a>`;
                    ul.appendChild(li);
                });
                document.getElementById("root").appendChild(ul);
            });
    }

    function loginPage() {
        document.getElementById("root").innerHTML = `
            <h1>Connexion</h1>
            <form id="login-form" action="/api/login" method="POST">
                <input type="text"     name="username" placeholder="Utilisateur">
                <input type="password" name="password" placeholder="Mot de passe">
                <button type="submit">Se connecter</button>
            </form>
            <a href="/" onclick="navigate('/'); return false;">Retour</a>
        `;
    }

    function dashboardPage() {
        document.getElementById("root").innerHTML = `
            <h1>Dashboard</h1>
            <div id="stats">
                <div class="stat"><span id="total-scans">0</span> scans</div>
                <div class="stat"><span id="total-vulns">0</span> vulnérabilités</div>
            </div>
            <a href="/settings" onclick="navigate('/settings'); return false;">Paramètres</a>
            <a href="/"         onclick="navigate('/');         return false;">Accueil</a>
        `;
        // Fetch stats dynamiques
        fetch("/api/stats")
            .then(r => r.json())
            .then(data => {
                document.getElementById("total-scans").textContent = data.scans;
                document.getElementById("total-vulns").textContent = data.vulns;
            });
    }

    function profilePage() {
        const params = new URLSearchParams(window.location.search);
        const userId = params.get("id") || "me";
        document.getElementById("root").innerHTML = `
            <h1>Profil #${userId}</h1>
            <form id="profile-form" action="/api/profile/update" method="POST">
                <input type="text"  name="name"  placeholder="Nom">
                <input type="email" name="email" placeholder="Email">
                <input type="hidden" name="user_id" value="${userId}">
                <button type="submit">Sauvegarder</button>
            </form>
            <a href="/dashboard" onclick="navigate('/dashboard'); return false;">Dashboard</a>
        `;
    }

    function adminPage() {
        document.getElementById("root").innerHTML = `
            <h1>Administration</h1>
            <ul>
                <li><a href="/admin/users"   onclick="navigate('/admin/users');   return false;">Gérer utilisateurs</a></li>
                <li><a href="/admin/reports" onclick="navigate('/admin/reports'); return false;">Rapports</a></li>
                <li><a href="/admin/config"  onclick="navigate('/admin/config');  return false;">Configuration</a></li>
            </ul>
            <form id="admin-search" action="/api/admin/search" method="GET">
                <input type="text" name="query" placeholder="Recherche admin...">
                <button type="submit">Chercher</button>
            </form>
        `;
    }

    function settingsPage() {
        document.getElementById("root").innerHTML = `
            <h1>Paramètres</h1>
            <form id="settings-form" action="/api/settings/save" method="POST">
                <select name="theme">
                    <option value="dark">Sombre</option>
                    <option value="light">Clair</option>
                </select>
                <input type="text" name="api_key" placeholder="Clé API">
                <button type="submit">Sauvegarder</button>
            </form>
        `;
    }

    // ── Popstate (bouton retour navigateur) ──────────────────────────────────
    window.addEventListener("popstate", () => render(window.location.pathname));

    // ── Init ─────────────────────────────────────────────────────────────────
    render(window.location.pathname);
    </script>
</body>
</html>"""


# ── API endpoints ─────────────────────────────────────────────────────────────
@app.route("/api/users")
def api_users():
    return jsonify({"users": [
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"},
        {"id": 3, "name": "Charlie"},
    ]})

@app.route("/api/stats")
def api_stats():
    return jsonify({"scans": 42, "vulns": 7})

@app.route("/api/login",          methods=["POST"])
def api_login():       return jsonify({"status": "ok"})

@app.route("/api/profile/update", methods=["POST"])
def api_profile():     return jsonify({"status": "updated"})

@app.route("/api/admin/search",   methods=["GET"])
def api_admin_search():return jsonify({"results": []})

@app.route("/api/settings/save",  methods=["POST"])
def api_settings():    return jsonify({"status": "saved"})

# Routes JS additionnelles (accessibles seulement via navigation JS)
@app.route("/admin/users")
@app.route("/admin/reports")
@app.route("/admin/config")
def admin_sub(): return index()  # SPA — retourne toujours le shell

@app.route("/dashboard")
@app.route("/profile")
@app.route("/login")
@app.route("/admin")
@app.route("/settings")
def spa_routes(): return index()


if __name__ == "__main__":
    print("🚀 SPA de test lancée sur http://localhost:5000")
    print("\nRoutes existantes :")
    routes = [
        "/ (accueil)",
        "/login",
        "/dashboard",
        "/profile",
        "/admin",
        "/settings",
        "/admin/users",
        "/admin/reports",
        "/admin/config",
        "/api/users",
        "/api/stats",
        "/api/login",
        "/api/profile/update",
        "/api/admin/search",
        "/api/settings/save",
    ]
    for r in routes:
        print(f"  ✓ {r}")
    app.run(port=5000, debug=False)
