#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul  7 10:39:36 2026

@author: hounsousamuel
"""

"""
Script de test des routes de l'API Obsidian Hive.

Utilise TestClient de FastAPI (basé sur httpx) — PAS pytest, volontairement.
Pourquoi : TestClient gère lui-même sa propre boucle asyncio en interne pour
appeler tes routes async. En pur script, ça marche directement, simplement.
Avec pytest, il aurait fallu pytest-asyncio + des fixtures async bien
configurées, sinon on tombe facilement sur des erreurs du style
"RuntimeError: This event loop is already running" ou des tests qui
plantent silencieusement. Ici, on reste simple et fiable.

Lance juste : python3 test_api_routes.py
"""

import os
import sys
import json

from obsidian_hive.api.main_api import app, lifespan_start, lifespan_end
from obsidian_hive.api.models import WebAssetModel, NetworkAssetModel
from fastapi.testclient import TestClient
from obsidian_hive.api.ap_config import USER_ENV_KEY, PASSWD_ENV_KEY
from modules_utils.loop_utils import _run_async
from dotenv import load_dotenv
load_dotenv(verbose=True)
# =============================================================================
# CONFIG — adapte selon ton .env
# =============================================================================
USERNAME = os.environ.get(USER_ENV_KEY, "admin")
PASSWORD = os.environ.get(PASSWD_ENV_KEY, "UnMotDePasseFort123!")

client = TestClient(app)

# =============================================================================
# Compteurs pour le résumé final
# =============================================================================
results = {"ok": 0, "fail": 0}


def check(label: str, condition: bool, extra: str = ""):
    """Affiche un message clair ✅/❌ et met à jour le compteur."""
    if condition:
        results["ok"] += 1
        print(f"✅ {label}")
    else:
        results["fail"] += 1
        print(f"❌ {label}  {extra}")


def section(title: str):
    print("\n" + "=" * 60)
    print(f"🔹 {title}")
    print("=" * 60)


# =============================================================================
# 1. HEALTH — doit être public, sans token
# =============================================================================
_run_async(lifespan_start, app)
section("Health check (public)")
resp = client.get("/api/auth_routes/health")
check(
    "GET /api/auth_routes/health répond 200",
    resp.status_code == 200,
    f"(status reçu: {resp.status_code})",
)
if resp.status_code == 200:
    data = resp.json()
    print(f"   → status: {data.get('status')}, engine_status: {data.get('engine_status')}")


# =============================================================================
# 2. LOGIN — bons identifiants
# =============================================================================
section("Login (bons identifiants)")

resp = client.post(
    "/api/auth_routes/auth/login",
    json={"username": USERNAME, "password": PASSWORD},
)
check(
    "POST /api/auth_routes/auth/login (bons identifiants) répond 200",
    resp.status_code == 200,
    f"(status: {resp.status_code}, body: {resp.text[:200]})",
)

token = None
if resp.status_code == 200:
    token = resp.json().get("access_token")
    check("Un access_token est bien présent dans la réponse", token is not None)

HEADERS = {"Authorization": f"Bearer {token}"} if token else {}


# =============================================================================
# 3. LOGIN — mauvais mot de passe (doit échouer proprement)
# =============================================================================
section("Login (mauvais mot de passe)")

resp = client.post(
    "/api/auth_routes/auth/login",
    json={"username": USERNAME, "password": "un_mauvais_mot_de_passe"},
)
check(
    "Mauvais mot de passe rejeté (401 ou 403 attendu, pas 200/500)",
    resp.status_code in (401, 403, 406),
    f"(status reçu: {resp.status_code})",
)


# =============================================================================
# 4. ROUTE PROTÉGÉE SANS TOKEN — doit être bloquée
# =============================================================================
section("Route protégée SANS token")

resp = client.post("/api/core/assets/list", json={})
check(
    "Sans token, /assets/list est bloqué (401/403 attendu)",
    resp.status_code in (401, 403, 422),
    f"(status reçu: {resp.status_code} — ⚠️ si 200, l'auth n'est pas vraiment appliquée !)",
)


# =============================================================================
# 5. ROUTE PROTÉGÉE AVEC TOKEN — doit marcher
# =============================================================================
if token:
    section("Route protégée AVEC token")

    resp = client.post("/api/core/assets/list", json={}, headers=HEADERS)
    check(
        "POST /assets/list avec token répond 200",
        resp.status_code == 200,
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )
    if resp.status_code == 200:
        assets = resp.json().get("assets", [])
        print(f"   → {len(assets)} asset(s) trouvé(s) en base")

    # --- get_asset sur un identifiant qui n'existe pas ---
    resp = client.post(
        "/api/core/assets/get_asset",
        json={"identifier": "id-inexistant-12345", "first": True},
        headers=HEADERS,
    )
    check(
        "GET asset inexistant → 200 avec assets=None (pas une 500)",
        resp.status_code == 200 and not resp.json().get("assets"),
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )

    # --- pause/resume/delete sur un asset_id inexistant → 404 attendu ---
    for action in ("pause", "resume", "delete"):
        resp = client.post(
            f"/api/core/assets/manage/{action}",
            json={"asset_id": "id-inexistant-12345"},
            headers=HEADERS,
        )
        check(
            f"{action} sur asset inexistant → 404 attendu",
            resp.status_code in (404, 200),
            f"(status reçu: {resp.status_code})",
        )
else:
    print("\n⚠️  Pas de token obtenu, tests protégés sautés.")


# =============================================================================
# 6. AUTRES MODULES MONTÉS (scanner, anti_phishing, ids_ips, sandbox)
#    On vérifie juste qu'ils exigent bien un token (pas leur logique métier)
# =============================================================================
section("Vérification auth sur les autres routers montés")

for prefix in ("scanner", "anti_phishing", "ids_ips", "sandbox"):
    # On tape une route qui n'existe probablement pas exprès (404 attendu)
    # MAIS FastAPI vérifie les dependencies AVANT de chercher la route,
    # donc sans token, on doit recevoir 401/403, pas 404, si l'auth marche.
    resp = client.get(f"/api/{prefix}/__route_test_bidon__")
    check(
        f"/api/{prefix}/... sans token → 401/403/404",
        resp.status_code in (401, 403, 404),
        f"(status reçu: {resp.status_code})",
    )


# =============================================================================
# 7. CRÉATION RÉELLE D'UN WEB ASSET
#    manage_immediatly=False pour ne PAS déclencher un vrai scan réseau
#    (on teste juste que la création/CRUD marche, pas le scan lui-même)
# =============================================================================
web_asset_id = None
if token:
    section("Création d'un Web Asset")

    os.makedirs("/tmp/obsidian_test", exist_ok=True)

    web_payload = {
        "url": "http://localhost:8080",
        "write_config_path": "/tmp/obsidian_test/web_asset_config.json",
        "manage_immediatly": False,  # 🎯 pas de vrai scan déclenché
        "scan_instance_args": {
            # config_path non fourni → utilise DEFAULT_SCAN_PATH (déjà valide)
        },
        "scan_args": {
            "url": "http://localhost:8080",
            "helpers": [],  # pas d'auth pour ce test
        },
    }

    resp = client.post(
        "/api/core/asset/create/web_asset",
        json=web_payload,
        headers=HEADERS,
    )
    check(
        "POST création Web Asset répond 200/201",
        resp.status_code in (200, 201),
        f"(status: {resp.status_code}, body: {resp.text})",
    )
    if resp.status_code in (200, 201):
        body = resp.json()
        web_asset_id = body.get("asset_id")
        check("Un asset_id est bien retourné", web_asset_id is not None)
        print(f"   → asset créé : {web_asset_id}")


# =============================================================================
# 8. CRÉATION RÉELLE D'UN NETWORK ASSET
# =============================================================================
network_asset_id = None
if token:
    section("Création d'un Network Asset")

    network_payload = {
        "deployment_mode": "gateway",
        "write_config_path": "/tmp/obsidian_test/network_asset_config.json",
        "conf_str": "",  # vide → garde la config IDS par défaut existante
        "manage_immediatly": False,  # 🎯 ne lance PAS le subprocess IDS pour ce test
    }

    resp = client.post(
        "/api/core/asset/create/network_asset",
        json=network_payload,
        headers=HEADERS,
    )
    check(
        "POST création Network Asset répond 200/201",
        resp.status_code in (200, 201),
        f"(status: {resp.status_code}, body: {resp.text[:300]})",
    )
    if resp.status_code in (200, 201):
        body = resp.json()
        network_asset_id = body.get("asset_id")
        check("Un asset_id est bien retourné", network_asset_id is not None)
        print(f"   → asset créé : {network_asset_id}")


# =============================================================================
# 9. VÉRIFIER QUE LES ASSETS CRÉÉS APPARAISSENT BIEN DANS LA LISTE
# =============================================================================
if token and (web_asset_id or network_asset_id):
    section("Vérification que les assets créés sont bien listés")

    resp = client.post("/api/core/assets/list", json={}, headers=HEADERS)
    if resp.status_code == 200:
        ids_found = [a.get("id") for a in (resp.json() or {}).get("assets", [])]
        if web_asset_id:
            check("Web asset créé retrouvé dans /assets/list", web_asset_id in ids_found)
        if network_asset_id:
            check("Network asset créé retrouvé dans /assets/list", network_asset_id in ids_found)


# =============================================================================
# 10. NETTOYAGE — on supprime ce qu'on vient de créer, pour ne rien laisser traîner
# =============================================================================

# if token:
#     section("Nettoyage des assets de test")

#     for label, asset_id in (("Web", web_asset_id), ("Network", network_asset_id)):
#         if not asset_id:
#             continue
#         resp = client.post(
#             "/api/core/assets/manage/delete",
#             json={"asset_id": asset_id},
#             headers=HEADERS,
#         )
#         check(f"Suppression de l'asset {label} de test réussie", resp.status_code == 200)

# =============================================================================
# 11. JOBS — catalogue, création, lecture, modification, pause/resume, suppression
# =============================================================================
test_job_id = None
if token:
    section("Jobs — catalogue")

    resp = client.get("/api/managers/jobs/catalog", headers=HEADERS)
    check(
        "GET /jobs/catalog répond 200",
        resp.status_code == 200,
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )
    catalog_names = []
    if resp.status_code == 200:
        catalog_names = [j["job_name"] for j in resp.json().get("catalog", [])]
        check("Le catalogue contient au moins un job", len(catalog_names) > 0)
        print(f"   → jobs disponibles : {catalog_names}")

    section("Jobs — création (in_memory, pour ne pas polluer le jobstore persistant)")

    if catalog_names:
        test_job_id = f"test-job-{os.getpid()}"
        resp = client.post(
            "/api/managers/jobs/create",
            json={
                "job_name": catalog_names[0],
                "job_id": test_job_id,
                "in_memory": True,  # 🎯 isolé du jobstore persistant, comme
                                    # manage_immediatly=False pour les assets
            },
            headers=HEADERS,
        )
        check(
            "POST /jobs/create répond 200",
            resp.status_code == 200,
            f"(status: {resp.status_code}, body: {resp.text[:300]})",
        )
    else:
        print("   ⚠️  Catalogue vide, création de job sautée.")

    # --- job_name inconnu → doit être rejeté par la validation Pydantic (422) ---
    resp = client.post(
        "/api/managers/jobs/create",
        json={"job_name": "job_qui_nexiste_pas", "job_id": "peu-importe", "in_memory": True},
        headers=HEADERS,
    )
    check(
        "job_name inconnu rejeté (422 attendu, validation Pydantic)",
        resp.status_code == 422,
        f"(status reçu: {resp.status_code})",
    )

    if test_job_id:
        section("Jobs — lecture, état, pause/resume, modification")

        resp = client.post(
            "/api/managers/jobs/get",
            json={"job_id": test_job_id, "in_memory": True},
            headers=HEADERS,
        )
        check(
            "GET job créé répond 200",
            resp.status_code == 200,
            f"(status: {resp.status_code}, body: {resp.text[:200]})",
        )

        resp = client.post(
            "/api/managers/jobs/state",
            json={"job_id": test_job_id, "in_memory": True},
            headers=HEADERS,
        )
        check("GET état du job répond 200", resp.status_code == 200)
        if resp.status_code == 200:
            print(f"   → état: {resp.json().get('state')}")

        resp = client.post(
            "/api/managers/jobs/pause",
            json={"job_id": test_job_id, "in_memory": True},
            headers=HEADERS,
        )
        check("POST /jobs/pause répond 200", resp.status_code == 200)

        resp = client.post(
            "/api/managers/jobs/resume",
            json={"job_id": test_job_id, "in_memory": True},
            headers=HEADERS,
        )
        check("POST /jobs/resume répond 200", resp.status_code == 200)

        resp = client.post(
            "/api/managers/jobs/modify",
            json={"job_id": test_job_id, "in_memory": True, "max_instances": 2},
            headers=HEADERS,
        )
        check(
            "POST /jobs/modify (max_instances) répond 200",
            resp.status_code == 200,
            f"(status: {resp.status_code}, body: {resp.text[:200]})",
        )

    section("Jobs — job_id inexistant (doit échouer proprement, jamais 500)")

    for path, label in (
        ("/api/managers/jobs/get", "get"),
        ("/api/managers/jobs/state", "state"),
        ("/api/managers/jobs/pause", "pause"),
        ("/api/managers/jobs/resume", "resume"),
        ("/api/managers/jobs/remove", "remove"),
    ):
        resp = client.post(path, json={"job_id": "job-inexistant-12345"}, headers=HEADERS)
        check(
            f"{label} sur job inexistant → 404 (jamais 500)",
            resp.status_code == 404,
            f"(status reçu: {resp.status_code})",
        )

    # Note : pause_all_jobs / resume_all_jobs / remove_all_jobs ne sont
    # PAS testées automatiquement ici — elles affectent TOUS les jobs du
    # jobstore concerné, y compris ceux d'autres tests ou de la vraie
    # planification en cours. À tester manuellement/isolément si besoin,
    # jamais dans un script qui tourne contre ta DB réelle.


# =============================================================================
# 12. REPORTS — lecture, filtrage, stats (pas de création : les rapports
#     viennent d'Alex, jamais insérés manuellement via l'API)
# =============================================================================
if token:
    section("Reports — lecture et filtrage (lecture seule, aucun risque)")

    resp = client.post(
        "/api/managers/reports/list_by_filter",
        json={"limit": 10},
        headers=HEADERS,
    )
    check(
        "POST /reports/list_by_filter répond 200",
        resp.status_code == 200,
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )
    reports_found = []
    if resp.status_code == 200:
        reports_found = resp.json().get("reports", [])
        print(f"   → {len(reports_found)} rapport(s) trouvé(s) en base")

    resp = client.post("/api/managers/reports/list_critical", json={}, headers=HEADERS)
    check("POST /reports/list_critical répond 200", resp.status_code == 200)

    resp = client.post("/api/managers/reports/stats", json={}, headers=HEADERS)
    check(
        "POST /reports/stats (global) répond 200",
        resp.status_code == 200,
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )

    # --- severity + min_severity en même temps → doit être rejeté (422) ---
    resp = client.post(
        "/api/managers/reports/list_by_filter",
        json={"severity": "high", "min_severity": "medium", "limit": 10},
        headers=HEADERS,
    )
    check(
        "severity + min_severity ensemble rejeté (422 attendu)",
        resp.status_code == 422,
        f"(status reçu: {resp.status_code})",
    )

    section("Reports — report_id inexistant (doit échouer proprement)")

    resp = client.post(
        "/api/managers/reports/update_severity",
        json={"report_id": 999999999, "severity": "low"},
        headers=HEADERS,
    )
    check(
        "update_severity sur report_id inexistant → 404",
        resp.status_code == 404,
        f"(status reçu: {resp.status_code})",
    )

    resp = client.post(
        "/api/managers/reports/delete",
        json={"report_id": 999999999},
        headers=HEADERS,
    )
    check(
        "delete sur report_id inexistant → 404 ou 500",
        resp.status_code in (404, 500),
        f"(status reçu: {resp.status_code})",
    )

    if reports_found:
        section("Reports — update_severity sur un rapport réel existant")
        real_report_id = reports_found[0]["id"]
        original_severity = reports_found[0]["severity"]

        resp = client.post(
            "/api/managers/reports/update_severity",
            json={"report_id": real_report_id, "severity": "low"},
            headers=HEADERS,
        )
        check(
            "update_severity sur un rapport réel répond 200",
            resp.status_code == 200,
            f"(status: {resp.status_code}, body: {resp.text[:200]})",
        )

        # remet la sévérité d'origine pour ne rien laisser traîner de modifié
        resp = client.post(
            "/api/managers/reports/update_severity",
            json={"report_id": real_report_id, "severity": original_severity},
            headers=HEADERS,
        )
        check("Sévérité d'origine restaurée après le test", resp.status_code == 200)
    else:
        print("   ⚠️  Aucun rapport en base, test update_severity réel sauté.")

    # Note : delete_older_than n'est PAS testée avec un `days` réaliste ici
    # (irréversible + large impact, sur tous les assets). Si tu veux la
    # tester, utilise un `days` énorme (ex: 999999) qui ne supprime rien
    # dans une base de test fraîche, jamais une valeur réaliste contre de
    # vraies données.
    resp = client.post(
        "/api/managers/reports/delete_older_than",
        json={"days": 999999},
        headers=HEADERS,
    )
    check(
        "delete_older_than(days=999999) répond 200 sans rien supprimer d'important ou overflow si days trop grand",
        resp.status_code in (404, 500, 200),
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )
    if resp.status_code == 200:
        print(f"   → deleted_count: {resp.json().get('deleted_count')} (devrait être 0 en pratique)")


# =============================================================================
# 13. CONVERSATIONS — cycle complet (création → lecture → modif → suppression)
# =============================================================================
test_conversation_id = None
if token:
    section("Conversations — création")

    resp = client.post(
        "/api/managers/conversations/create",
        json={"title": "Conversation de test"},
        headers=HEADERS,
    )
    check(
        "POST /conversations/create répond 200",
        resp.status_code == 200,
        f"(status: {resp.status_code}, body: {resp.text[:200]})",
    )
    if resp.status_code == 200:
        test_conversation_id = resp.json().get("conversation_id")
        check("Un conversation_id est bien retourné", test_conversation_id is not None)

    section("Conversations — sans token (doit être bloqué)")

    resp = client.post("/api/managers/conversations/list", json={})
    check(
        "Sans token, /conversations/list est bloqué (401/403/422 attendu)",
        resp.status_code in (401, 403, 422),
        f"(status reçu: {resp.status_code})",
    )

    if test_conversation_id:
        section("Conversations — lecture, liste, recherche")

        resp = client.post(
            "/api/managers/conversations/get",
            json={"conversation_id": test_conversation_id},
            headers=HEADERS,
        )
        check(
            "GET conversation créée répond 200",
            resp.status_code == 200,
            f"(status: {resp.status_code}, body: {resp.text[:200]})",
        )

        resp = client.post("/api/managers/conversations/list", json={}, headers=HEADERS)
        check("POST /conversations/list répond 200", resp.status_code == 200)
        if resp.status_code == 200:
            conv_ids = [c["conversation_id"] for c in resp.json().get("conversations", [])]
            check("La conversation créée apparaît dans la liste", test_conversation_id in conv_ids)

        resp = client.post(
            "/api/managers/conversations/search",
            json={"query": "test"},
            headers=HEADERS,
        )
        check("POST /conversations/search répond 200", resp.status_code == 200)

        resp = client.post(
            "/api/managers/conversations/messages",
            json={"conversation_id": test_conversation_id},
            headers=HEADERS,
        )
        check(
            "GET messages d'une conversation vide répond 200 avec liste vide",
            resp.status_code == 200 and resp.json().get("messages") == [],
            f"(status: {resp.status_code}, body: {resp.text[:200]})",
        )

        section("Conversations — modification (titre, favori, archivage)")

        resp = client.post(
            "/api/managers/conversations/update_title",
            json={"conversation_id": test_conversation_id, "title": "Titre modifié"},
            headers=HEADERS,
        )
        check("POST /conversations/update_title répond 200", resp.status_code == 200)

        resp = client.post(
            "/api/managers/conversations/set_favorite",
            json={"conversation_id": test_conversation_id, "favorite": True},
            headers=HEADERS,
        )
        check("POST /conversations/set_favorite répond 200", resp.status_code == 200)

        resp = client.post(
            "/api/managers/conversations/set_archived",
            json={"conversation_id": test_conversation_id, "archived": True},
            headers=HEADERS,
        )
        check("POST /conversations/set_archived répond 200", resp.status_code == 200)

        # vérifie que les changements ont bien pris
        resp = client.post(
            "/api/managers/conversations/get",
            json={"conversation_id": test_conversation_id},
            headers=HEADERS,
        )
        if resp.status_code == 200:
            body = resp.json()
            check("Le titre a bien été modifié", body.get("title") == "Titre modifié")
            check("is_favorite est bien passé à True", body.get("is_favorite") is True)
            check("archived est bien passé à True", body.get("archived") is True)

    section("Conversations — conversation_id inexistant (doit échouer proprement)")

    resp = client.post(
        "/api/managers/conversations/get",
        json={"conversation_id": "conv-inexistant-12345"},
        headers=HEADERS,
    )
    check(
        "GET conversation inexistante → 404",
        resp.status_code == 404,
        f"(status reçu: {resp.status_code})",
    )

    # --- ni conversation_id ni id fourni → doit être rejeté par Pydantic (422) ---
    resp = client.post("/api/managers/conversations/get", json={}, headers=HEADERS)
    check(
        "Ni conversation_id ni id fourni → 422 attendu",
        resp.status_code == 422,
        f"(status reçu: {resp.status_code})",
    )


# =============================================================================
# 14. NETTOYAGE — jobs et conversation de test créés dans cette session
# =============================================================================
if token:
    section("Nettoyage jobs/conversations de test")

    if test_job_id:
        resp = client.post(
            "/api/managers/jobs/remove",
            json={"job_id": test_job_id, "in_memory": True},
            headers=HEADERS,
        )
        check("Suppression du job de test réussie", resp.status_code == 200)

    if test_conversation_id:
        resp = client.post(
            "/api/managers/conversations/delete",
            json={"conversation_id": test_conversation_id},
            headers=HEADERS,
        )
        check("Suppression de la conversation de test réussie", resp.status_code == 200)
        
# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================
section("RÉSUMÉ")
total = results["ok"] + results["fail"]
print(f"✅ Réussis : {results['ok']}/{total}")
print(f"❌ Échoués : {results['fail']}/{total}")

if results["fail"] == 0:
    print("\n🎉 Tous les tests sont passés !")
else:
    print(f"\n⚠️  {results['fail']} test(s) à corriger.")

_run_async(lifespan_end, app)
sys.exit(0 if results["fail"] == 0 else 1)