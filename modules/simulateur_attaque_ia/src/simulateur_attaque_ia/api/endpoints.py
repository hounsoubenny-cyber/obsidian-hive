#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Aug  4 07:42:44 2026

@author: hounsousamuel
"""

"""
Dictionnaire complet des endpoints de l'API du simulateur d'attaque.
"""

ENDPOINTS = {
    "title": "Simulateur d'Attaque IA — API",
    "version": "2.0.0",
    "base_url": "/api",
    "rate_limit": "100/minute",
    "documentation": {
        "swagger": "/api/docs",
        "redoc": "/api/redoc",
        "openapi": "/api/openapi.json",
    },
    "auth": {
        "type": "JWT Bearer",
        "header": "Authorization: Bearer <token>",
        "login_endpoint": "POST /api/auth/login",
    },
    "endpoints": {
        # ─── AUTH ────────────────────────────────────────────────────────
        "POST /api/auth/login": {
            "summary": "Authentification",
            "description": "Retourne un JWT Bearer à utiliser dans le header `Authorization: Bearer <token>`.",
            "auth": "none",
            "rate_limit": "100/minute",
            "request_body": {
                "username": "str (obligatoire)",
                "password": "str (obligatoire)",
            },
            "response": {
                "success": "bool",
                "token": "str",
                "message": "str",
            },
            "errors": {
                "401": "Identifiants incorrects",
                "422": "Validation error (champs manquants ou invalides)",
            },
            "example_request": {
                "username": "admin",
                "password": "ChangeMe123",
            },
            "example_response": {
                "success": True,
                "token": "eyJhbGciOiJIUzI1NiIs...",
                "message": "Authentification réussie.",
            },
        },

        # ─── SIMULATIONS ─────────────────────────────────────────────────
        "POST /api/sim/start": {
            "summary": "Lancer une simulation",
            "description": (
                "Lance une simulation (auto ou interactive) sur l'image Docker donnée.\n"
                "La simulation s'exécute en arrière-plan et communique via WebSocket."
            ),
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "image": "str (obligatoire) — Image Docker locale",
                "mode": "'auto' | 'interactive' (défaut: 'auto')",
                "services": "Dict[int, Dict] | None — services.json (optionnel, auto-capturé si absent)",
                "use_llm": "bool (défaut: False) — Active le LLM pour les décisions/suggestions",
                "llm_config": "dict | None — Configuration LLM",
                "sim_config": "dict | None — Paramètres fins de chaque tactic (tout optionnel)",
                "container_name": "str | None — Nom du container (auto-généré si absent)",
                "authorize_network": "bool (défaut: False) — Accès réseau externe",
                "network_caps": "bool (défaut: False) — Ajoute NET_RAW + NET_ADMIN",
                "default_services": "Dict[str, List[int]] | None — Services par défaut (clés: voir DEFAULT_SERVICE_REGISTRY)",
                "only_listening": "bool (défaut: False) — Ne capturer que les ports en écoute",
                "use_default_excludes": "bool (défaut: True) — Utiliser les exclusions par défaut",
                "capture_excluded_names": "List[str] | None — Noms de processus à exclure",
                "capture_excluded_ports": "List[int] | None — Ports à exclure",
                "capture_excluded_pids": "List[int] | None — PIDs à exclure",
                "auto_capture": "bool (défaut: True) — Scanner le host pour capturer les services",
            },
            "response": {
                "session_id": "str — Identifiant unique de la session",
                "status": "str — 'starting'",
                "message": "str",
            },
            "errors": {
                "400": "Paramètres invalides (ex: image inexistante)",
                "429": "Quota de simulations parallèles atteint",
                "500": "Erreur interne",
            },
            "example_request": {
                "image": "ubuntu:22.04",
                "mode": "auto",
                "use_llm": False,
                "authorize_network": False,
                "network_caps": True,
            },
            "example_response": {
                "session_id": "sim_a1b2c3d4",
                "status": "starting",
                "message": "Simulation démarrée — connectez-vous au WS /a1b2c3d4 pour suivre.",
            },
        },
        "POST /api/sim/{session_id}/stop": {
            "summary": "Arrêter une simulation",
            "description": "Arrête une simulation en cours.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"session_id": "str — Identifiant de la session"},
            "response": {
                "session_id": "str",
                "status": "'stopped'",
                "message": "str",
            },
            "errors": {
                "404": "Session introuvable",
            },
            "example_response": {
                "session_id": "sim_a1b2c3d4",
                "status": "stopped",
                "message": "Simulation arrêtée.",
            },
        },
        "GET /api/sim/{session_id}/status": {
            "summary": "Status d'une simulation active",
            "description": "Retourne l'état détaillé d'une simulation en cours.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"session_id": "str — Identifiant de la session"},
            "response": {
                "session_id": "str",
                "mode": "'auto' | 'interactive'",
                "image": "str",
                "status": "'starting' | 'running' | 'waiting' | 'completed' | 'stopped' | 'failed'",
                "started_at": "datetime (ISO 8601)",
                "ended_at": "datetime | None",
                "current_step": "str | None — Étape en cours (ex: 'reconnaissance')",
                "progress": "float (0.0 à 1.0)",
                "error": "str | None",
                "actions_done": "List[str] — Actions déjà exécutées",
            },
            "errors": {
                "404": "Session introuvable",
            },
        },
        "GET /api/sim/list": {
            "summary": "Liste des simulations actives",
            "description": "Retourne la liste des simulations en cours.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "response": {
                "sims": "List[dict] — Liste des simulations actives",
            },
        },
        "GET /api/sim/{session_id}/report": {
            "summary": "Rapport final d'une simulation",
            "description": "Retourne le rapport complet d'une simulation terminée.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"session_id": "str — Identifiant de la session"},
            "response": "dict — Rapport complet de la simulation",
            "errors": {
                "404": "Rapport introuvable (simulation non terminée ou inexistante)",
            },
        },
        "GET /api/sim/{session_id}/actions": {
            "summary": "Actions disponibles (mode interactif)",
            "description": "Retourne les actions disponibles pour une simulation en mode interactif.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"session_id": "str — Identifiant de la session"},
            "response": {
                "session_id": "str",
                "actions_available": "List[str] — Actions disponibles",
                "actions_available_with_details": "dict | None — Détails des actions",
                "actions_done": "List[str] — Actions déjà exécutées",
            },
            "errors": {
                "404": "Session introuvable",
                "409": "Mode interactif non disponible",
            },
        },
        "GET /api/sim/history": {
            "summary": "Historique de toutes les simulations",
            "description": "Retourne l'historique de toutes les simulations passées.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "response": {
                "history": "List[dict] — Historique des simulations",
            },
        },
        "GET /api/sim/history/{sim_id}": {
            "summary": "Détail d'une simulation passée",
            "description": "Retourne le détail complet d'une simulation historique.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"sim_id": "str — Identifiant de la simulation historique"},
            "response": "dict — Détail complet de la simulation",
            "errors": {
                "404": "Simulation introuvable dans l'historique",
            },
        },

        # ─── IMAGES ──────────────────────────────────────────────────────
        "GET /api/images/list": {
            "summary": "Lister les images Docker locales",
            "description": "Retourne la liste des images Docker disponibles localement.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "response": {
                "images": "List[str] — Liste des tags d'images",
            },
            "errors": {
                "500": "Erreur Docker",
            },
            "example_response": {
                "images": ["ubuntu:22.04", "ubuntu:20.04", "python:3.11-slim"],
            },
        },

        # ─── CLONAGE ────────────────────────────────────────────────────
        "POST /api/clone/start": {
            "summary": "Lancer un clonage système",
            "description": (
                "Clone le système host (ou une archive existante) dans un container Docker.\n"
                "Le clonage génère automatiquement un services.json via ServiceManager.capture_services()."
            ),
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "src": "str | None — Répertoire source (défaut: '/' sur Linux)",
                "dest": "str | None — Où stocker l'archive tar.gz temporaire",
                "archive_path": "str | None — tar.gz existant → skip la copie",
                "remove_back_up": "bool (défaut: True) — Supprimer l'archive après import",
                "container_name": "str | None — Nom du container (auto-généré si absent)",
                "network_caps": "bool (défaut: False) — Ajoute NET_RAW + NET_ADMIN",
                "authorize_network": "bool (défaut: False) — False → --network=isolated",
            },
            "response": {
                "clone_id": "str — Identifiant unique du clone",
                "status": "'running'",
                "message": "str",
            },
            "errors": {
                "500": "Erreur interne",
            },
            "example_request": {
                "src": "/home/user/project",
                "remove_back_up": True,
                "authorize_network": False,
                "network_caps": False,
            },
            "example_response": {
                "clone_id": "clone_a1b2c3d4",
                "status": "running",
                "message": "Clonage lancé en arrière-plan. Suivez avec GET /clone/clone_a1b2c3d4/status.",
            },
        },
        "GET /api/clone/{clone_id}/status": {
            "summary": "Status d'un clonage",
            "description": "Retourne l'état actuel d'une tâche de clonage.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"clone_id": "str — Identifiant du clone"},
            "response": {
                "clone_id": "str",
                "status": "'running' | 'completed' | 'failed' | 'stopped' | 'not_found'",
                "image": "str | None — Nom du container créé",
                "services": "dict | None — services.json capturé",
                "error": "str | None — Message d'erreur si échec",
                "started_at": "datetime | None (ISO 8601)",
                "ended_at": "datetime | None (ISO 8601)",
                "message": "str | None",
            },
            "errors": {
                "404": "Clone introuvable",
            },
        },
        "POST /api/clone/{clone_id}/stop": {
            "summary": "Arrêter un clonage en cours",
            "description": "Marque le clone comme arrêté et annule la tâche asyncio.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"clone_id": "str — Identifiant du clone"},
            "response": {
                "clone_id": "str",
                "status": "'stopped'",
                "message": "str",
            },
            "errors": {
                "404": "Clone introuvable",
                "409": "Clone déjà terminé",
            },
        },

        # ─── SERVICES ────────────────────────────────────────────────────
        "GET /api/services/capture": {
            "summary": "Capturer les services actuels du host",
            "description": "Lance ServiceManager.capture_services() et retourne le services.json correspondant au système actuel.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "response": {
                "services": "dict — Contenu du services.json",
            },
            "errors": {
                "500": "Erreur capture services",
            },
        },
        "POST /api/services/validate": {
            "summary": "Valider un services.json",
            "description": "Vérifie la structure d'un services.json avant de lancer une simulation.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "services": "Dict[str, Any] — Contenu du services.json à valider",
            },
            "response": {
                "valid": "bool",
                "errors": "List[str]",
                "warnings": "List[str]",
            },
            "example_request": {
                "services": {
                    "22": {
                        "name": "sshd",
                        "port": 22,
                        "protocol": "tcp",
                        "process_name": "sshd",
                    },
                },
            },
            "example_response": {
                "valid": True,
                "errors": [],
                "warnings": ["Port 22: service SSH détecté, vérifiez les credentials par défaut"],
            },
        },

        # ─── CONTAINERS ──────────────────────────────────────────────────
        "GET /api/containers/list": {
            "summary": "Lister les containers Docker",
            "description": "Retourne la liste des containers Docker avec filtres optionnels.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "query_params": {
                "running": "bool | None — Filtrer par statut running",
                "label": "str | None — Filtrer par label Docker",
            },
            "response": {
                "total": "int — Nombre total de containers",
                "containers": "List[ContainerInfo] — Liste des containers",
                "filters": "dict — Filtres appliqués",
            },
            "errors": {
                "500": "Erreur Docker",
            },
            "example_response": {
                "total": 3,
                "containers": [
                    {
                        "id": "abc123...",
                        "short_id": "abc123",
                        "name": "simatk_ubuntu_1",
                        "image": "ubuntu:22.04",
                        "status": "running",
                        "ip": "172.17.0.2",
                        "created": "2026-08-03T15:30:00Z",
                        "size": 12345678,
                        "size_human": "12.35 MB",
                        "labels": {"simatk": "true"},
                        "is_simatk": True,
                    },
                ],
                "filters": {"status": "running"},
            },
        },
        "GET /api/containers/list_my_own": {
            "summary": "Lister mes containers (utilisateur)",
            "description": "Retourne uniquement les containers créés par l'utilisateur (label simatk.owner=user).",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "query_params": {
                "running": "bool | None — Filtrer par statut running",
                "label": "str | None — Filtrer par label Docker",
            },
            "response": {
                "total": "int",
                "containers": "List[ContainerInfo]",
                "filters": "dict",
            },
        },
        "POST /api/containers/create": {
            "summary": "Créer ou réutiliser un container",
            "description": "Crée un nouveau container ou réutilise un container existant en cache.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "image": "str (obligatoire) — Image Docker",
                "name": "str | None — Nom du container (auto-généré si absent)",
                "network": "str (défaut: 'bridge') — Réseau Docker (bridge, none, host, ou nom personnalisé)",
                "cap_add": "List[Capability] | None — Capacités Linux (NET_ADMIN, NET_RAW, etc.)",
                "labels": "Dict[str, str] | None — Labels Docker",
                "environment": "Dict[str, str] | None — Variables d'environnement",
                "ports": "Dict[int, int] | None — Mapping ports {host: container}",
                "command": "str (défaut: 'sleep infinity') — Commande à exécuter",
            },
            "response": {
                "success": "bool",
                "container": "dict — Informations du container",
                "message": "str",
            },
            "errors": {
                "400": "Image ou réseau introuvable",
                "500": "Erreur création",
            },
            "example_request": {
                "image": "ubuntu:22.04",
                "network": "bridge",
                "cap_add": ["NET_RAW"],
                "command": "sleep infinity",
            },
            "example_response": {
                "success": True,
                "container": {
                    "name": "simatk_ubuntu_a1b2c3d4",
                    "image": "ubuntu:22.04",
                    "status": "running",
                    "ip": "172.17.0.3",
                    "created": "2026-08-03T15:30:00Z",
                },
                "message": "Container 'simatk_ubuntu_a1b2c3d4' prêt",
            },
        },
        "POST /api/containers/{name}/stop": {
            "summary": "Arrêter un container",
            "description": "Arrête et supprime un container.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"name": "str — Nom du container"},
            "response": {
                "success": "bool",
                "container": "str — Nom du container",
                "message": "str",
            },
            "errors": {
                "404": "Container introuvable",
            },
        },
        "POST /api/containers/{name}/exec": {
            "summary": "Exécuter une commande dans un container",
            "description": "Exécute une commande shell dans un container et retourne le résultat.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"name": "str — Nom du container"},
            "request_body": {
                "command": "str | list — Commande à exécuter (ex: 'whoami && ls -la')",
            },
            "response": {
                "success": "bool",
                "container": "str",
                "command": "str",
                "exit_code": "int — Code de retour",
                "stdout": "str | None — Sortie standard",
                "stderr": "str | None — Sortie erreur",
                "message": "str | None — Message d'erreur",
            },
            "errors": {
                "404": "Container introuvable",
                "500": "Erreur exécution",
            },
            "example_request": {
                "command": "whoami && ls -la /",
            },
            "example_response": {
                "success": True,
                "container": "simatk_ubuntu_1",
                "command": "whoami && ls -la /",
                "exit_code": 0,
                "stdout": "root\ntotal 72\ndrwxr-xr-x  1 root root 4096 Aug  3 15:30 .\n...",
                "stderr": None,
                "message": None,
            },
        },
        "GET /api/containers/cache": {
            "summary": "Lister les containers en cache",
            "description": "Retourne la liste des containers maintenus en cache pour réutilisation rapide.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "response": {
                "total": "int",
                "containers": "List[CachedContainerInfo]",
            },
            "example_response": {
                "total": 2,
                "containers": [
                    {
                        "name": "simatk_ubuntu_pool_1",
                        "status": "running",
                        "image": "ubuntu:22.04",
                        "last_used": 1722695400.123,
                    },
                ],
            },
        },

        # ─── NETWORK ─────────────────────────────────────────────────────
        "GET /api/network/list": {
            "summary": "Lister les réseaux Docker",
            "description": "Retourne la liste de tous les réseaux Docker (filtre simatk optionnel).",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "query_params": {
                "only_simatk": "bool (défaut: False) — Afficher uniquement les réseaux avec le label 'simatk'",
            },
            "response": {
                "total": "int — Nombre total de réseaux",
                "networks": "List[NetworkInfo] — Liste des réseaux",
            },
            "errors": {
                "500": "Erreur Docker",
            },
            "example_response": {
                "total": 2,
                "networks": [
                    {
                        "name": "simatk_net_1",
                        "id": "abc123...",
                        "short_id": "abc123",
                        "driver": "bridge",
                        "subnet": "172.30.0.0/24",
                        "internal": False,
                        "containers_count": 3,
                        "labels": {"simatk": "true"},
                        "created": "2026-08-03T15:00:00Z",
                    },
                ],
            },
        },
        "POST /api/network/create": {
            "summary": "Créer un réseau Docker",
            "description": "Crée un réseau Docker personnalisé avec labels simatk automatiques.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "name": "str (obligatoire) — Nom du réseau",
                "driver": "'bridge' | 'overlay' (défaut: 'bridge')",
                "subnet": "str | None — Sous-réseau CIDR (ex: '172.30.0.0/24')",
                "internal": "bool (défaut: False) — Réseau interne sans accès Internet",
                "labels": "Dict[str, str] | None — Labels supplémentaires",
            },
            "response": {
                "success": "bool",
                "network": "dict — Informations du réseau créé",
                "message": "str",
                "error": "str | None — Message d'erreur si échec",
            },
            "errors": {
                "400": "Réseau déjà existant",
                "500": "Erreur création réseau",
            },
            "example_request": {
                "name": "mon_reseau_test",
                "driver": "bridge",
                "subnet": "172.30.0.0/24",
                "internal": True,
                "labels": {"env": "test"},
            },
            "example_response": {
                "success": True,
                "network": {
                    "name": "mon_reseau_test",
                    "id": "def456...",
                    "short_id": "def456",
                    "driver": "bridge",
                    "subnet": "172.30.0.0/24",
                    "internal": True,
                },
                "message": "Réseau 'mon_reseau_test' créé avec succès",
                "error": None,
            },
        },
        "GET /api/network/{network_name}/containers": {
            "summary": "Lister les containers d'un réseau",
            "description": "Retourne la liste détaillée des containers connectés à un réseau spécifique.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"network_name": "str — Nom du réseau"},
            "response": {
                "network": "str — Nom du réseau",
                "network_id": "str — ID complet du réseau",
                "total": "int — Nombre de containers",
                "containers": "List[NetworkContainerInfo] — Liste des containers",
                "message": "str | None",
                "error": "str | None",
            },
            "errors": {
                "404": "Réseau introuvable",
                "500": "Erreur Docker",
            },
        },
        "POST /api/network/{network_name}/remove": {
            "summary": "Supprimer un réseau",
            "description": (
                "Supprime un réseau Docker.\n"
                "- force=false (défaut): ne supprime que si le réseau est vide\n"
                "- force=true: supprime TOUS les containers connectés + le réseau"
            ),
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"network_name": "str — Nom du réseau"},
            "query_params": {
                "force": "bool (défaut: False) — Forcer la suppression avec les containers",
            },
            "response": {
                "success": "bool",
                "network": "str — Nom du réseau",
                "message": "str",
                "containers": "List[str] | None — Containers restants si force=false",
                "removed_containers": "List[str] | None — Containers supprimés si force=true",
                "failed_containers": "List[dict] | None — Containers non supprimés",
                "error": "str | None",
            },
            "errors": {
                "404": "Réseau introuvable",
                "500": "Erreur suppression réseau",
            },
            "example_response": {
                "success": True,
                "network": "mon_reseau_test",
                "message": "Réseau 'mon_reseau_test' supprimé",
                "error": None,
            },
        },
        "POST /api/network/remove_all": {
            "summary": "Supprimer tous les réseaux simatk",
            "description": "Supprime TOUS les réseaux avec le label 'simatk'. Supprime aussi les containers connectés si force=true.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "query_params": {
                "force": "bool (défaut: False) — Forcer la suppression avec les containers",
            },
            "response": {
                "success": "bool",
                "total": "int — Nombre total de réseaux simatk",
                "removed": "List[str] — Réseaux supprimés",
                "failed": "List[dict] — Réseaux non supprimés avec raison",
                "message": "str | None",
                "error": "str | None",
            },
            "errors": {
                "500": "Erreur Docker",
            },
            "example_response": {
                "success": True,
                "total": 5,
                "removed": ["simatk_net_1", "simatk_net_2"],
                "failed": [],
                "message": "2 réseau(x) supprimé(s), 0 échec(s)",
                "error": None,
            },
        },
        "POST /api/network/{network_name}/connect": {
            "summary": "Connecter un container à un réseau",
            "description": "Connecte un container existant à un réseau spécifique. Optionnellement avec IP statique et alias DNS.",
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"network_name": "str — Nom du réseau"},
            "request_body": {
                "container_name": "str (obligatoire) — Nom du container à connecter",
                "ip": "str | None — IP statique à attribuer (ex: '172.30.0.10')",
                "aliases": "List[str] | None — Alias DNS pour le container sur ce réseau",
            },
            "response": {
                "success": "bool",
                "container": "str — Nom du container",
                "network": "str — Nom du réseau",
                "ip": "str | None — IP attribuée",
                "aliases": "List[str] | None — Alias DNS",
                "message": "str",
                "error": "str | None",
            },
            "errors": {
                "404": "Réseau ou container introuvable",
                "409": "Container déjà connecté",
                "500": "Erreur connexion",
            },
            "example_request": {
                "container_name": "pc1",
                "ip": "172.30.0.10",
                "aliases": ["web", "app1"],
            },
            "example_response": {
                "success": True,
                "container": "pc1",
                "network": "mon_reseau",
                "ip": "172.30.0.10",
                "aliases": ["web", "app1"],
                "message": "Container connecté au réseau 'mon_reseau'",
                "error": None,
            },
        },
        "POST /api/network/{network_name}/disconnect": {
            "summary": "Déconnecter un container d'un réseau",
            "description": (
                "Déconnecte un container d'un réseau spécifique.\n"
                "- force=false (défaut): refuse si c'est le dernier réseau du container\n"
                "- force=true: force la déconnexion"
            ),
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "path_params": {"network_name": "str — Nom du réseau"},
            "request_body": {
                "container_name": "str (obligatoire) — Nom du container à déconnecter",
                "force": "bool (défaut: False) — Forcer la déconnexion",
            },
            "response": {
                "success": "bool",
                "container": "str",
                "network": "str",
                "force": "bool",
                "remaining_networks": "List[str] — Réseaux restants",
                "message": "str",
                "error": "str | None",
            },
            "errors": {
                "404": "Réseau ou container introuvable",
                "409": "Container non connecté à ce réseau",
                "500": "Erreur déconnexion",
            },
            "example_response": {
                "success": True,
                "container": "pc1",
                "network": "mon_reseau",
                "force": False,
                "remaining_networks": ["bridge"],
                "message": "Container déconnecté de 'mon_reseau'",
                "error": None,
            },
        },
        "POST /api/network/move": {
            "summary": "Déplacer un container d'un réseau à un autre",
            "description": (
                "Déplace un container d'un réseau source vers un réseau destination.\n"
                "Si le container n'est pas sur le réseau source → erreur.\n"
                "Si le container est déjà sur le réseau destination → erreur."
            ),
            "auth": "JWT Bearer",
            "rate_limit": "100/minute",
            "request_body": {
                "container_name": "str (obligatoire) — Nom du container",
                "source_network": "str (obligatoire) — Réseau source",
                "destination_network": "str (obligatoire) — Réseau destination",
                "force": "bool (défaut: False) — Forcer le déplacement",
                "ip": "str | None — IP statique sur le réseau destination",
                "aliases": "List[str] | None — Alias DNS sur le réseau destination",
            },
            "response": {
                "success": "bool",
                "container": "str",
                "source_network": "str",
                "destination_network": "str",
                "ip": "str | None — IP sur le réseau destination",
                "aliases": "List[str] | None",
                "networks": "List[str] — Tous les réseaux après déplacement",
                "message": "str",
                "error": "str | None",
            },
            "errors": {
                "404": "Container, réseau source ou réseau destination introuvable",
                "409": "Container non connecté à la source ou déjà connecté à la destination",
                "500": "Erreur déplacement",
            },
            "example_request": {
                "container_name": "pc1",
                "source_network": "ancien_reseau",
                "destination_network": "nouveau_reseau",
                "ip": "172.30.0.10",
                "aliases": ["web"],
            },
            "example_response": {
                "success": True,
                "container": "pc1",
                "source_network": "ancien_reseau",
                "destination_network": "nouveau_reseau",
                "ip": "172.30.0.10",
                "aliases": ["web"],
                "networks": ["bridge", "nouveau_reseau"],
                "message": "Container déplacé de 'ancien_reseau' vers 'nouveau_reseau'",
                "error": None,
            },
        },

        # ─── WEBSOCKET ──────────────────────────────────────────────────
        "WS /api/ws/{session_id}?token=xxx": {
            "summary": "Communication WebSocket",
            "description": (
                "Bidirectionnel pour mode interactif, lecture seule pour mode auto.\n"
                "Connexion : ws://host:port/api/ws/{session_id}?token=jwt_token"
            ),
            "auth": "JWT Bearer (query parameter: ?token=xxx)",
            "path_params": {"session_id": "str — Identifiant de la session"},
            "query_params": {"token": "str — JWT token"},
            "protocol": {
                "Server → Client": {
                    "connected": {
                        "type": "connected",
                        "session_id": "str",
                        "mode": "'auto' | 'interactive'",
                        "status": "str",
                        "current_step": "str | None",
                        "actions_done": "List[str]",
                        "progress": "float",
                    },
                    "replay_start": {
                        "type": "replay_start",
                        "count": "int — Nombre de messages en attente",
                    },
                    "replay_end": {"type": "replay_end"},
                    "sim_status": {
                        "type": "sim_status",
                        "status": "str",
                        "message": "str",
                    },
                    "sim_ready": {
                        "type": "sim_ready",
                        "actions_available": "List[str]",
                        "actions_done": "List[str]",
                        "state_summary": "str",
                    },
                    "step_start": {
                        "type": "step_start",
                        "step": "str — Étape en cours (ex: 'reconnaissance')",
                        "message": "str",
                    },
                    "step_progress": {
                        "type": "step_progress",
                        "step": "str",
                        "message": "str",
                        "data": "dict | None",
                    },
                    "step_result": {
                        "type": "step_result",
                        "step": "str",
                        "result": "dict — Résultat de l'étape",
                        "actions_available": "List[str] | None",
                    },
                    "step_end": {"type": "step_end", "step": "str"},
                    "llm_suggest": {
                        "type": "llm_suggest",
                        "suggestion": "dict — Suggestion du LLM",
                    },
                    "llm_review": {
                        "type": "llm_review",
                        "action": "str",
                        "review": "dict",
                    },
                    "sim_state": {
                        "type": "sim_state",
                        "state": "dict — État complet de la simulation",
                    },
                    "sim_finished": {
                        "type": "sim_finished",
                        "report": "dict — Rapport final",
                    },
                    "error": {
                        "type": "error",
                        "message": "str",
                    },
                },
                "Client → Serveur (mode interactif uniquement)": {
                    "execute_action": {
                        "type": "execute_action",
                        "action": "str — Nom de l'action (ex: 'reconnaissance')",
                        "params": "dict — Paramètres spécifiques à l'action",
                    },
                    "request_llm_suggest": {
                        "type": "request_llm_suggest",
                    },
                    "request_llm_review": {
                        "type": "request_llm_review",
                        "action": "str",
                    },
                    "get_state": {
                        "type": "get_state",
                    },
                    "finish": {
                        "type": "finish",
                    },
                },
            },
            "errors": {
                "4001": "Token manquant",
                "4003": "Token invalide",
                "4004": "Session introuvable",
            },
        },

        # ─── HEALTH / UTILS ────────────────────────────────────────────
        "GET /health": {
            "summary": "Health check",
            "description": "Vérifie l'état de santé de l'API.",
            "auth": "none",
            "rate_limit": "none",
            "response": {
                "status": "str — 'ok'",
                "active_sims": "int — Nombre de simulations actives",
                "ws_sessions": "int — Nombre de sessions WebSocket actives",
            },
            "example_response": {
                "status": "ok",
                "active_sims": 2,
                "ws_sessions": 3,
            },
        },
        "GET /api/": {
            "summary": "Racine de l'API",
            "description": "Retourne la documentation des endpoints ou l'interface React si disponible.",
            "auth": "none",
            "rate_limit": "none",
            "response": "dict (liste des endpoints) ou HTML (React)",
        },
        "GET /": {
            "summary": "Racine",
            "description": "Redirige vers l'interface React ou la documentation des endpoints.",
            "auth": "none",
            "rate_limit": "none",
            "response": "dict ou HTML",
        },
        "GET /api/close": {
            "summary": "Fermer l'API (admin)",
            "description": "Arrête le serveur API proprement.",
            "auth": "none",
            "rate_limit": "none",
            "response": {
                "message": "str",
            },
            "example_response": {
                "message": "Serveur fermé.",
            },
        },
        "GET /api/test": {
            "summary": "Test de l'API",
            "description": "Endpoint de test simple.",
            "auth": "none",
            "rate_limit": "none",
            "response": {
                "message": "str",
            },
            "example_response": {
                "message": "Test de l'api !",
            },
        },
    },
    "websocket_actions": {
        "reconnaissance": {
            "params": {
                "timeout_socket": "float | None",
                "port_range": "List[int] | None",
                "port_range_mode": "'replace' | 'add' | 'keep'",
            },
        },
        "initial_access": {
            "params": {
                "ssh": {
                    "enabled": "bool",
                    "timeout": "float | None",
                    "total_timeout": "float | None",
                    "delay": "float | None",
                    "max_attempts": "int | None",
                    "add_common": "bool | None",
                    "usernames": "List[str] | None",
                    "usernames_mode": "'replace' | 'add' | 'keep'",
                    "passwords": "List[str] | None",
                    "passwords_mode": "'replace' | 'add' | 'keep'",
                    "ports": "List[int] | None",
                },
                "ftp": {
                    "enabled": "bool",
                    "timeout": "float | None",
                    "total_timeout": "float | None",
                    "max_attempts": "int | None",
                    "add_common": "bool | None",
                    "usernames": "List[str] | None",
                    "usernames_mode": "'replace' | 'add' | 'keep'",
                    "passwords": "List[str] | None",
                    "passwords_mode": "'replace' | 'add' | 'keep'",
                    "ports": "List[int] | None",
                },
                "http": {
                    "enabled": "bool",
                    "timeout": "float | None",
                    "preference": "str | None",
                    "add_common": "bool | None",
                    "paths": "List[str] | None",
                    "paths_mode": "'replace' | 'add' | 'keep'",
                    "ports": "List[int] | None",
                },
            },
        },
        "execution": {
            "params": {
                "timeout": "float | None",
                "exec_timeout": "float | None",
                "commands": "List[str] | None",
                "commands_mode": "'replace' | 'add' | 'keep'",
                "add_common": "bool | None",
                "quick": "bool | None",
                "credential_index": "int (défaut: 0)",
                "run_reverse_shell": "bool (défaut: False)",
                "reverse_shell": {
                    "attaquant_ip": "str | None",
                    "attaquant_port": "int | None",
                    "timeout": "float | None",
                    "exec_timeout": "float | None",
                    "listener_timeout": "float | None",
                    "total_timeout": "float | None",
                    "commands": "List[str] | None",
                },
            },
        },
        "persistence": {
            "params": {
                "run_ssh_key": "bool (défaut: True)",
                "ssh_key_algo": "str | None",
                "ssh_key_timeout": "float | None",
                "ssh_key_exec_timeout": "float | None",
                "run_cron": "bool (défaut: True)",
                "cron_script_path": "str | None",
                "cron_expression": "str | None",
                "cron_level": "'user' | 'root' | None",
            },
        },
        "privilege_escalation": {
            "params": {
                "timeout": "float | None",
                "exec_timeout": "float | None",
                "run_sudo": "bool (défaut: True)",
                "run_suid": "bool (défaut: True)",
            },
        },
        "credential_access": {
            "params": {
                "timeout": "float | None",
                "exec_timeout": "float | None",
                "run_dump": "bool (défaut: True)",
                "run_history": "bool (défaut: True)",
                "run_keys": "bool (défaut: True)",
            },
        },
        "lateral_movement": {
            "params": {
                "max_depth": "int | None",
                "max_workers": "int | None",
                "join_timeout": "float | None",
            },
        },
        "exfiltration": {
            "params": {
                "c2_url": "str | None",
                "timeout": "int | None",
            },
        },
        "defense_evasion": {
            "params": {
                "timeout": "float | None",
                "exec_timeout": "float | None",
                "run_clean": "bool (défaut: True)",
                "run_stomp": "bool (défaut: True)",
            },
        },
    },
}