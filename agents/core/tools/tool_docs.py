#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 13:22:31 2026

@author: hounsousamuel
"""

"""
Doc narrative des tools de Coralie (CoreTools) — use_case, impact, warnings,
examples. Curée à la main, complétée à chaque nouveau tool ajouté à
CoreTools. Fusionnée avec le schéma auto-généré via
agents/shared/tool_docs_utils.describe_tool.

Convention "impact" :
  - "lecture seule"                      → aucune conséquence, safe à tout moment
  - "non-destructif"                     → modifie un état mais réversible facilement
  - "destructif — confirmation requise"  → irréversible, jamais utilisé sans les 2 temps
"""

TOOL_DOCS = {

    "get_asset": {
        "use_case": "Récupérer un asset par son ID, item_id, ou nom.",
        "impact": "lecture seule",
        "warnings": [
            "Si include_name=True, plusieurs assets peuvent matcher. "
            "Utiliser first=True pour ne garder que le premier."
        ],
        "examples": [
            'get_asset(identifier="sh_as-...", first=True)',
            'get_asset(identifier="Site Vitrine", include_name=True, first=True)',
        ],
        "more_info": (
            "Cet outil cherche par ID, puis par item_id, puis par nom (si include_name=True). "
            "Pour lister plusieurs assets, préférer `list_asset`."
        ),
    },
    "get_asset_by_name": {
        "use_case": (
            "Rechercher des assets par leur nom, avec contrôle de la casse et possibilité "
            "de recherche partielle. Utile quand on connaît le nom d'un asset mais pas son ID."
        ),
        "impact": "lecture seule",
        "warnings": [
            "La recherche partielle peut retourner de nombreux résultats si le nom est court "
            "(ex: 'api' peut matcher 'API Backend', 'API Auth', 'API Gateway'...).",
            "La recherche insensible à la casse (case_sensitive=False) est la plus courante."
        ],
        "examples": [
            'get_asset_by_name(name="Site Vitrine")',
            'get_asset_by_name(name="vitrine", partial=True, first=False, limit=10)',
            'get_asset_by_name(name="API", case_sensitive=True, partial=True)',
        ],
        "more_info": (
            "Par défaut (case_sensitive=False, partial=False), la recherche est exacte mais insensible à la casse : "
            "'site vitrine' matchera 'Site Vitrine' et 'SITE VITRINE'. "
            "Pour une recherche exacte et sensible, passer case_sensitive=True. "
            "Pour une recherche partielle (ex: tous les assets contenant 'api' dans leur nom), passer partial=True. "
            "Si plusieurs assets matchent et que first=True, seul le premier est retourné."
        ),
    },
    
    "list_asset": {
        "use_case": "Lister/filtrer les assets par status, type, priority et/ou tags.",
        "impact": "lecture seule",
        "warnings": [
            "Tous les filtres sont en AND (status ET type ET priority...). "
            "Sauf tags qui sont en OR (match si au moins un tag).",
            "Aucun filtre = retourne TOUS les assets, potentiellement des milliers."
        ],
        "examples": [
            'list_asset(status="active", type_="web_site")',
            'list_asset(priority="high", tags=["prod"])',
        ],
        "more_info": (
            "Pour lister les assets ACTIFS, il faut explicitement passer status='active'. "
            "Par défaut, l'outil ne filtre PAS sur le statut, donc il retourne tous les assets "
            "quel que soit leur statut (active, inactive, suppressed). "
            "C'est un piège courant : si tu veux uniquement les actifs, n'oublie pas le filtre."
        ),
    },

    "list_assets_by_tags": {
        "use_case": "Chercher des assets par tags uniquement.",
        "impact": "lecture seule",
        "warnings": [
            "Correspondance OR : un asset est retourné s'il a au moins un tag demandé."
        ],
        "examples": [
            'list_assets_by_tags(tags=["prod", "critical"])',
        ],
        "more_info": (
            "Cet outil est un raccourci de list_asset avec tags uniquement. "
            "Si tu veux combiner tags + status, utilise list_asset avec les deux filtres."
        ),
    },

    "pause_asset": {
        "use_case": "Mettre un asset en pause (suspendre son workflow).",
        "impact": "non-destructif",
        "warnings": [
            "Passe l'asset en INACTIVE et annule ses tâches actives.",
            "Réversible via resume_asset."
        ],
        "examples": [
            'pause_asset(asset_id="sh_as-...")',
        ],
        "more_info": (
            "L'asset reste visible dans les listes, mais son workflow ne tourne plus. "
            "Le statut passe à 'inactive' et les scans périodiques sont stoppés."
        ),
    },

    "resume_asset": {
        "use_case": "Reprendre un asset précédemment mis en pause.",
        "impact": "non-destructif",
        "warnings": [
            "Relance le workflow immédiatement. Un scan long peut démarrer rapidement."
        ],
        "examples": [
            'resume_asset(asset_id="sh_as-...")',
        ],
        "more_info": (
            "Remet l'asset en ACTIVE et relance son workflow. "
            "Si l'asset a été arrêté en maintenance, vérifie que sa config est à jour avant de reprendre."
        ),
    },
    
    "resume_assets": {
        "use_case": "Reprendre plusieurs assets en pause d'un coup (tous, par type, ou une liste précise).",
        "impact": "non-destructif",
        "warnings": [
            "Relance les workflows immédiatement. Un scan long peut démarrer rapidement.",
            "Sans filtre (asset_type/asset_ids), agit sur TOUS les assets en pause.",
        ],
        "examples": [
            'resume_assets()',
            'resume_assets(asset_type="web_site")',
            'resume_assets(asset_ids=["sh_as-..."])',
        ],
        "more_info": (
            "Remet les assets ciblés en ACTIVE et relance leur workflow. "
            "Si un asset a été arrêté pour maintenance, vérifie que sa config est à jour avant de reprendre."
        ),
    },

    "pause_assets": {
        "use_case": "Mettre en pause plusieurs assets d'un coup (tous, par type, ou une liste précise) — utile en cas d'incident.",
        "impact": "non-destructif",
        "warnings": [
            "Sans filtre (asset_type/asset_ids), agit sur TOUS les assets actifs.",
            "Coupe la surveillance des assets ciblés — vérifie que ce n'est pas contre-productif en pleine investigation.",
        ],
        "examples": [
            'pause_assets()',
            'pause_assets(asset_type="network")',
            'pause_assets(asset_ids=["sh_as-..."])',
        ],
        "more_info": (
            "Met les assets ciblés en INACTIVE — leur workflow s'arrête proprement. "
            "Réversible via resume_assets."
        ),
    },
    
    "update_asset": {
        "use_case": "Modifier des attributs d'un asset (priority, tags, url, config...).",
        "impact": "non-destructif (sauf restart_workflow=True)",
        "warnings": [
            "attrs n'écrase que les clés fournies, le reste est inchangé.",
            "restart_workflow=True relance le scan immédiatement — à utiliser avec précaution."
        ],
        "examples": [
            'update_asset(asset_id="sh_as-...", attrs={"priority": "high"})',
            'update_asset(asset_id="sh_as-...", attrs={"url": "https://..."}, restart_workflow=True)',
        ],
        "more_info": (
            "Si tu changes l'url ou la source_code_dir, il faut passer restart_workflow=True "
            "pour que le changement soit pris en compte dans le prochain scan. "
            "Pour une simple mise à jour de priority ou tags, restart_workflow=False est suffisant."
        ),
    },

    "get_engine_status": {
        "use_case": "Voir si le moteur ShieldAI est démarré et les tâches actives.",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'get_engine_status()',
        ],
        "more_info": (
            "Un moteur 'démarré' ne signifie pas que tous les workflows tournent. "
            "Vérifie aussi les tasks actives pour voir si des scans sont en cours."
        ),
    },

    "get_report": {
        "use_case": "Récupérer un ou plusieurs rapports par ID de rapport OU par asset_id.",
        "impact": "lecture seule",
        "warnings": [
            "Si identifier matche un asset_id, first=False retourne une liste de rapports.",
            "Utiliser first=True si un seul résultat est attendu."
        ],
        "examples": [
            'get_report(identifier="42", first=True)',
            'get_report(identifier="sh_as-...", first=False, limit=10)',
        ],
        "more_info": (
            "identifier peut être un ID de rapport (entier) ou un asset_id (string). "
            "L'outil teste les deux. Si c'est un asset_id, il récupère tous les rapports de cet asset."
        ),
    },

    "get_latest_report": {
        "use_case": "Récupérer le dernier rapport d'un asset (le plus récent).",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'get_latest_report(asset_id="sh_as-...")',
        ],
        "more_info": (
            "Plus léger que get_report si tu veux juste le dernier état connu d'un asset."
        ),
    },

    "get_firstest_report": {
        "use_case": "Récupérer le premier rapport d'un asset (le plus ancien).",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'get_firstest_report(asset_id="sh_as-...")',
        ],
        "more_info": (
            "Utile pour savoir depuis quand un asset est suivi, ou voir l'historique depuis l'origine."
        ),
    },

    "list_reports_by_filter": {
        "use_case": "Filtrage complet des rapports (asset, source, sévérité, dates).",
        "impact": "lecture seule",
        "warnings": [
            "min_severity inclut tout ce qui est AU-DESSUS ou égal.",
            "severity et min_severity sont mutuellement exclusifs : utilise l'un ou l'autre."
        ],
        "examples": [
            'list_reports_by_filter(asset_id="sh_as-...", min_severity="high")',
            'list_reports_by_filter(source="ids_ips", start_date="2026-07-01T00:00:00Z")',
        ],
        "more_info": (
            "Pour lister tous les rapports récents, indépendamment de l'asset, passe uniquement start_date. "
            "Pour ne voir que les plus graves, utilise min_severity='high' (inclut high et critical)."
        ),
    },

    "list_critical_reports": {
        "use_case": "Raccourci pour voir tous les rapports critiques, tous assets.",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'list_critical_reports(limit=20)',
        ],
        "more_info": (
            "C'est un raccourci de list_reports_by_filter avec severity='critical'. "
            "Pratique pour un état des lieux rapide des urgences."
        ),
    },

    "list_assets_by_status": {
        "use_case": "Lister les assets par statut précis (active, inactive, suppressed).",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'list_assets_by_status(status="inactive")',
        ],
        "more_info": (
            "Raccourci de list_asset avec status fixé. "
            "Si tu veux ajouter d'autres filtres (type, priority, tags), utilise list_asset à la place."
        ),
    },

    "list_recent_reports": {
        "use_case": "Voir TOUS les rapports récents, tous assets, sur une fenêtre temporelle.",
        "impact": "lecture seule",
        "warnings": [
            "window_hours par défaut à 24h. Pour une période plus longue, augmenter avec précaution."
        ],
        "examples": [
            'list_recent_reports(window_hours=24)',
            'list_recent_reports(window_hours=72, limit=500)',
        ],
        "more_info": (
            "Cet outil est conçu pour la synthèse périodique. Il permet de détecter des tendances "
            "sur tous les assets confondus. Exemple : 10 alertes medium sur 10 assets différents "
            "en 2h peuvent indiquer une campagne coordonnée."
        ),
    },

    "get_report_stats": {
        "use_case": "Statistiques agrégées des rapports (total, répartition, has_fix).",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'get_report_stats()',
            'get_report_stats(asset_id="sh_as-...")',
        ],
        "more_info": (
            "has_fix compte les rapports où have_proposed_fix ou all_fix_applied est vrai. "
            "Pour un asset, cela donne une idée du taux de correction. "
            "Sans asset_id, les stats sont globales sur tout le système."
        ),
    },

    "get_info_about_tool": {
        "use_case": "Obtenir la documentation complète d'un tool précis.",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'get_info_about_tool(tool_name="update_asset")',
        ],
        "more_info": (
            "Si tu hésites sur l'impact d'un tool (destructif ou non), ou sur ses arguments, "
            "appelle cet outil d'abord. C'est le 'self-documentation' de Coralie."
        ),
    },
    
    "update_report_severity": {
        "use_case": "Reclasser la sévérité d'un rapport existant (requalifier un faux positif, escalader une découverte).",
        "impact": "non-destructif",
        "warnings": [
            "Seuls severity et has_fix sont modifiables — content et report_json restent intacts, impossible de les réécrire via ce tool.",
            "Reclasser n'efface rien : le rapport original reste consultable, seule sa sévérité change."
        ],
        "examples": [
            'update_report_severity(report_id=42, severity="low")',
            'update_report_severity(report_id=42, severity="critical", has_fix=True)',
        ],
        "more_info": (
            "Utile quand une analyse s'avère être un faux positif (descendre en 'low'/'info'), "
            "ou à l'inverse quand une découverte mérite d'être escaladée. "
            "Ne change jamais le contenu du rapport, seulement sa classification."
        ),
    },

    "delete_report": {
        "use_case": "Supprimer définitivement un rapport précis.",
        "impact": "destructif — confirmation requise",
        "warnings": [
            "Irréversible : le rapport n'est récupérable nulle part après suppression.",
            "Vérifier le report_id via get_report avant suppression pour éviter toute erreur de cible."
        ],
        "examples": [
            'delete_report(report_id=42)',
        ],
        "more_info": (
            "À utiliser pour nettoyer un rapport erroné, dupliqué, ou obsolète. "
            "Pour une purge en masse par ancienneté, préférer delete_old_reports."
        ),
    },

    "delete_old_reports": {
        "use_case": "Purger en masse tous les rapports plus vieux que N jours, tous assets confondus.",
        "impact": "destructif — confirmation requise",
        "warnings": [
            "LARGE IMPACT : affecte tous les assets d'un coup, pas un seul.",
            "Irréversible — aucun rapport supprimé n'est récupérable.",
            "Vérifier via list_reports_by_filter/get_report_stats l'ampleur avant de purger."
        ],
        "examples": [
            'delete_old_reports(days=90)',
        ],
        "more_info": (
            "Conçu pour la maintenance/rétention (ex: purge automatique via le job planifié "
            "'report_cleanup'). Ne cible pas un asset précis — days s'applique globalement."
        ),
    },

    "remove_asset": {
        "use_case": "Supprimer définitivement un asset (config, historique, tasks actives annulées).",
        "impact": "destructif — confirmation requise",
        "warnings": [
            "Irréversible : contrairement à pause_asset, aucun retour en arrière possible.",
            "Le source_code_dir (simple copie locale, si présent) est aussi nettoyé sur disque — sans conséquence en soi.",
            "Vérifier via get_asset que c'est bien la cible voulue avant suppression."
        ],
        "examples": [
            'remove_asset(asset_id="sh_as-...")',
        ],
        "more_info": (
            "Pour suspendre temporairement un asset sans le perdre, utiliser pause_asset à la place. "
            "remove_asset est réservé aux suppressions définitives (asset obsolète, doublon, erreur de création)."
        ),
    },

    "list_job_catalog": {
        "use_case": "Lister les jobs planifiables via add_job, avec leur description et configuration par défaut.",
        "impact": "lecture seule",
        "warnings": [],
        "examples": [
            'list_job_catalog()',
        ],
        "more_info": (
            "À appeler avant add_job si les noms de jobs disponibles ne sont pas déjà connus. "
            "Retourne pour chaque job son nom, sa description, son trigger et ses kwargs par défaut."
        ),
    },

    "add_job": {
        "use_case": "Planifier un nouveau job à partir du catalogue prédéfini (jamais une fonction arbitraire).",
        "impact": "non-destructif",
        "warnings": [
            "job_name doit être une valeur du catalogue (voir list_job_catalog) — impossible de planifier une fonction inconnue.",
            "Un job_id déjà utilisé provoquera une erreur ou un remplacement selon la config du scheduler — vérifier via list_jobs avant."
        ],
        "examples": [
            'add_job(job_name="scan_daily", job_id="scan_daily_asset-042")',
            'add_job(job_name="report_cleanup", job_id="cleanup_weekly", trigger={"type": "cron", "day_of_week": "sun", "hour": 2})',
        ],
        "more_info": (
            "trigger et kwargs sont optionnels : si omis, les valeurs par défaut du catalogue "
            "sont utilisées (voir list_job_catalog). Réversible via remove_job si le job planifié ne convient pas."
        ),
    },
}