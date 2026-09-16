"""
Générateur de routes pour le serveur vulnérable.

- Routes MONO-vuln : un Unit d'un seul moteur.
- Routes MULTI-vuln : plusieurs Units de moteurs différents combinés dans le
  même handler HTTP (combinaisons réalistes curées à la main).
- Un manifest.json est produit en parallèle, mappant chaque route à :
  méthode, vulns présentes, paramètres/contextes d'injection, difficulté.
"""

import json
from flask import Flask, jsonify, request

from engines import ENGINES
from engines.base import Unit, UnitCtx, context_needs

# Un tiers des routes rendent une vraie page HTML (structure variée :
# balises, formulaire, script, iframe...) plutôt que du JSON pur — pour
# que le dataset de features reflète la diversité réelle des cibles
# scannées (API JSON ET pages web classiques). Le reste continue de
# renvoyer du JSON, comme avant.
HTML_RATIO_MOD = 2  # 1 route sur HTML_RATIO_MOD rend du HTML


def _should_render_html(route_counter: int) -> bool:
    return route_counter % HTML_RATIO_MOD == 0


def _fragment_to_text(frag) -> str:
    """Convertit un fragment de résultat de moteur en texte affichable."""
    if isinstance(frag, dict):
        for key in ("output", "message", "body", "result", "value"):
            if key in frag and isinstance(frag[key], str):
                return frag[key]
        return json.dumps(frag, ensure_ascii=False, default=str)
    return str(frag)


def _render_html(merged: dict, path_template: str, resource: str, units) -> str:
    """
    Construit une vraie page HTML (structure variée : liens, formulaire,
    images, script, iframe, meta) qui reflète les sorties des moteurs de
    vuln — pour que l'extracteur de features ML ait du vrai contenu HTML
    à analyser sur une partie du dataset.
    """
    sections = []
    for u in units:
        frag = merged.get(u.vuln_id)
        sections.append(
            f'<section class="vuln-block" data-vuln="{u.vuln_id}">'
            f'<h2>{u.vuln_id} — {u.variant}</h2>'
            f'<div class="output">{_fragment_to_text(frag)}</div>'
            f'</section>'
        )

    form_field = ""
    if any(u.context in ("form", "body") for u in units):
        form_field = (
            '<form method="post" action="">'
            '<input type="text" name="q" placeholder="search">'
            '<input type="password" name="pwd">'
            '<input type="hidden" name="csrf_token" value="tok_placeholder">'
            '<input type="file" name="upload">'
            '<button type="submit">Envoyer</button>'
            '</form>'
        )

    return f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{resource} - {path_template}</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <nav><a href="/">Accueil</a> <a href="/{resource}">{resource}</a></nav>
    <main>
        <h1>{resource}</h1>
        {form_field}
        {''.join(sections)}
        <img src="/static/placeholder.png" alt="illustration">
        <iframe src="about:blank" title="preview"></iframe>
    </main>
    <script>console.log("route", "{path_template}");</script>
    <footer><cite>Genere par vulnserver</cite></footer>
</body>
</html>'''

# ---------------------------------------------------------------------
# Ressources (noms métier utilisés pour nommer routes / données factices)
# ---------------------------------------------------------------------

NOUNS = [
    "products", "users", "orders", "invoices", "comments", "files", "images",
    "reports", "tickets", "messages", "projects", "tasks", "payments",
    "accounts", "sessions", "documents", "reviews", "articles", "events",
    "bookings", "subscriptions", "notifications", "logs", "backups",
    "exports", "imports", "profiles", "settings", "teams", "organizations",
]
PREFIXES = ["", "api/v1/", "api/v2/"]

RESOURCE_COMBOS = [(p, n) for p in PREFIXES for n in NOUNS]  # 90 combos

# Combinaisons multi-vuln curées : réalistes (des vulns qui coexistent
# souvent sur une même page en vrai) plutôt qu'aléatoires.
MULTI_COMBOS = [
    ("XSS", "CSRF"),
    ("SQLi", "InfoDisc"),
    ("IDOR", "InsecPerm"),
    ("SSRF", "CredsExpose"),
    ("JWT", "BrokenAuth"),
    ("CORS", "CredsExpose"),
    ("XSS", "InsecCrypto"),
    ("SQLi", "BrokenAuth"),
    ("DirTrav", "InfoDisc"),
    ("InsecUpload", "DirTrav"),
    ("NoSQLi", "BrokenAuth"),
    ("CSRF", "OpenRedirect"),
    ("XXE", "SSRF"),
    ("SSTI", "InfoDisc"),
    ("IDOR", "CSRF"),
    ("RateLimit", "BrokenAuth"),
    ("JWT", "InsecCrypto"),
    ("LDAPi", "BrokenAuth"),
    ("XPATH_Injection", "InfoDisc"),
    ("GraphQLi", "RateLimit"),
    ("Prototype_Pollution", "InsecPerm"),
    ("HTTP_Request_Smuggling", "CredsExpose"),
    ("CRLF_Injection", "OpenRedirect"),
    ("RaceCondition", "InsecPerm"),
    ("CMDi", "InfoDisc"),
    ("InsecDeser", "CredsExpose"),
    ("BufOvr", "InfoDisc"),
    ("SessFix", "BrokenAuth"),
    ("SQLi", "XSS"),
    ("IDOR", "InfoDisc", "CredsExpose"),
    ("SSRF", "XXE", "InfoDisc"),
    ("XSS", "CSRF", "OpenRedirect"),
    ("SQLi", "BrokenAuth", "InfoDisc"),
    ("JWT", "InsecPerm", "IDOR"),
    ("CORS", "JWT", "CredsExpose"),
]


def build_app():
    app = Flask(__name__)
    manifest = []
    route_counter = 0

    def register(path_template, methods, units, page_type, resource):
        nonlocal route_counter
        route_counter += 1
        endpoint_name = f"ep_{route_counter}"
        render_html = _should_render_html(route_counter)

        def view(**path_kwargs):
            merged = {}
            for u in units:
                ctx = UnitCtx(unit=u, path_kwargs=path_kwargs)
                try:
                    frag = u.handler(ctx)
                except Exception as e:
                    frag = {"handler_error": str(e)}
                merged[u.vuln_id] = frag
            merged["_meta"] = {
                "route": path_template,
                "page_type": page_type,
                "vulns": [u.vuln_id for u in units],
            }
            if render_html:
                return _render_html(merged, path_template, resource, units)
            return jsonify(merged)

        view.__name__ = endpoint_name
        app.add_url_rule(path_template, endpoint=endpoint_name, view_func=view, methods=methods)

        manifest.append({
            "route": path_template,
            "method": methods[0] if len(methods) == 1 else methods,
            "page_type": page_type,
            "resource": resource,
            "vulns": [u.vuln_id for u in units],
            "response_format": "html" if render_html else "json",
            "details": [
                {
                    "vuln": u.vuln_id,
                    "variant": u.variant,
                    "context": u.context,
                    "param": u.param,
                    "description": u.description,
                    "difficulty": u.difficulty,
                }
                for u in units
            ],
        })

    def path_for(prefix, resource, tag, units):
        p = f"/{prefix}{resource}/{tag}"
        for u in units:
            if u.context == "path":
                p += f"/<{u.param}>"
        return p

    def methods_for(units):
        needs_post = any(context_needs(u.context) == "POST" for u in units)
        return ["POST"] if needs_post else ["GET"]

    # ---------------- MONO-VULN ROUTES ----------------
    for prefix, resource in RESOURCE_COMBOS:
        for vuln_id, module in ENGINES.items():
            units = module.make_units(resource)
            for unit in units:
                tag = f"{vuln_id.lower()}-{unit.variant}"
                path = path_for(prefix, resource, tag, [unit])
                register(path, methods_for([unit]), [unit], "mono", resource)

    # ---------------- MULTI-VULN ROUTES ----------------
    for combo_idx, combo in enumerate(MULTI_COMBOS):
        for prefix, resource in RESOURCE_COMBOS:
            units = []
            skip = False
            for vuln_id in combo:
                variants = ENGINES[vuln_id].make_units(resource)
                if not variants:
                    skip = True
                    break
                unit = variants[combo_idx % len(variants)]
                units.append(unit)
            if skip:
                continue
            tag = "multi-" + "-".join(v.lower() for v in combo)
            path = path_for(prefix, resource, tag, units)
            # évite les collisions de nom de path param si plusieurs units path-based
            seen_params = set()
            dedup_units = []
            for u in units:
                if u.context == "path" and u.param in seen_params:
                    continue
                if u.context == "path":
                    seen_params.add(u.param)
                dedup_units.append(u)
            register(path, methods_for(dedup_units), dedup_units, "multi", resource)
    
    @app.route("/", methods=["GET"])
    def home():
        return jsonify({"app": "Vuln server", "owner": "Samuel"})
    return app, manifest


if __name__ == "__main__":
    app, manifest = build_app()
    with open("manifest.json", "w") as f:
        json.dump({"total_routes": len(manifest), "routes": manifest}, f, indent=2)
    print(f"Routes générées : {len(manifest)}")
    mono = sum(1 for r in manifest if r["page_type"] == "mono")
    multi = sum(1 for r in manifest if r["page_type"] == "multi")
    print(f"  mono : {mono}")
    print(f"  multi: {multi}")
    app.run(host="0.0.0.0", port=6000, debug=False)