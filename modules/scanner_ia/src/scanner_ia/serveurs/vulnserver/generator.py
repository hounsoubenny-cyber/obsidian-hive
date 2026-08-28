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
            return jsonify(merged)

        view.__name__ = endpoint_name
        app.add_url_rule(path_template, endpoint=endpoint_name, view_func=view, methods=methods)

        manifest.append({
            "route": path_template,
            "method": methods[0] if len(methods) == 1 else methods,
            "page_type": page_type,
            "resource": resource,
            "vulns": [u.vuln_id for u in units],
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
    app.run(host="0.0.0.0", port=5000, debug=False)
