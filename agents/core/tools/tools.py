#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul 12 11:01:17 2026

@author: hounsousamuel
"""

import os
import asyncio
import functools
import inspect
from datetime import datetime, timedelta
from modules_utils.pydantic_utils import entry_model
from modules_utils.agent_utils import timer
from obsidian_hive.agents.analyst.tools.tools import (
    read_file, list_directory, path_exists
)
from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.managers.job_manager import JobManager
from obsidian_hive.core.managers.report_manager import ReportManager
from modules_utils.safe_subprocess import safe_run, CommandNotAllowedError
from obsidian_hive.agents.core.tools.tools_model_entry import (
    GetAssetEntry, GetAssetByNameEntry, ListAssetEntry, ListAssetByTagsEntry,
    PauseAssetEntry, ResumeAssetEntry, UpdateAssetEntry, GetEngineStatusEntry,
    GetReportEntry, GetLatestReportEntry, ListReportsByFilterEntry,
    ListCriticalReportsEntry, ListRecentReportsEntry, GetReportStatsEntry,
    GetInfoAboutToolEntry, GetFirstestReportEntry, ListAssetsByStatusEntry,
    ListJobsEntry, GetJobEntry, GetJobStateEntry, PauseJobEntry, ResumeJobEntry,
    ModifyJobEntry, RemoveJobEntry, RemoveAllJobsEntry, PauseAllJobsEntry,
    ResumeAllJobsEntry, UpdateReportSeverityEntry, DeleteReportEntry,
    DeleteOldReportsEntry, RemoveAssetEntry, AddJobEntry, ListJobCatalogEntry,
    PauseAssetsEntry, ResumeAssetsEntry
)
from obsidian_hive.agents.shared.human_in_loop import confirm_self, confirm_self_dynamic, Confirmer
from obsidian_hive.core.managers.job_catalog import JOB_CATALOG, describe_catalog
from obsidian_hive.agents.core.tools.tool_docs import TOOL_DOCS
from obsidian_hive.agents.shared.tool_docs_utils import describe_tool, list_available_tools
from obsidian_hive.core.assets.asset_types import (
    AssetStatus, AssetType, Priority, Source, Severity, utcnow,
    PRIORITY_MAPPING
)

from obsidian_hive.agents.analyst.tools.tools import get_info_about_tool as analyst_get_info_about_tool
from modules_utils.keyed_lock import resource_lock

class CoreTools:
    """
    Tools de Coralie (agent décisionnaire) : vue d'ensemble et actions sur
    les assets ShieldAI, consultation des rapports d'Alex, introspection des
    tools eux-mêmes. Toute méthode dont le nom se termine par '_core_tool'
    est automatiquement exposée dans self.tools (nom exposé = nom réel sans
    le suffixe '_core_tool').
    """
    
    def __init__(
        self,
        job_manager: JobManager,
        engine: ObsidianEngine,
        report_manager: ReportManager,
        confirmer: Confirmer
    ):
        if any(obj is None for obj in (job_manager, engine, report_manager, confirmer)):
            raise RuntimeError("Entrée invalide pour le constructeur de CoreTools")
        self.engine = engine
        self.job_manager = job_manager
        self.report_manager = report_manager
        self.confirmer = confirmer
        self._tool_suffix = "_core_tool"
        self.tools = {
            str(name).removesuffix(self._tool_suffix): getattr(
                self, name
            ) for name in dir(self) if str(name).endswith(self._tool_suffix)
        }
        self._analyst_tools = ["list_directory", "read_file", "path_exits"]
        self.tools.update({
            "list_directory": list_directory,
            "read_file": read_file,
            "path_exits": path_exists,
        })
        
    def _return_asset_generic(self, kwargs_dump: dict, result):
        """Normalise le retour d'un tool sur les assets (0, 1 ou N résultats)."""
        if result is None:
            return {
                "success": True,
                "find": False,
                "result": []
            }
        
        result = [result] if not isinstance(result, list) else result
        return {
            "success": True,
            "find": bool(result),
            "entry_kwargs": kwargs_dump,
            "result": [r.model_dump(mode="json") for r in result],
            "priority_mapping": PRIORITY_MAPPING
        }

    def _return_report_generic(self, kwargs_dump: dict, result):
        """
        Symétrique à _return_asset_generic, pour les résultats renvoyés par
        ReportManager (AnalysisReport, déjà décompressés via @decompress_wrapper).
        """
        if result is None:
            return {
                "success": True,
                "find": False,
                "result": []
            }

        result = [result] if not isinstance(result, list) else result
        return {
            "success": True,
            "find": bool(result),
            "entry_kwargs": kwargs_dump,
            "result": [r.model_dump(mode="json") for r in result]
        }

    def _return_job_generic(self, kwargs_dump: dict, result):
        """
        Symétrique à _return_asset_generic/_return_report_generic, pour les
        résultats renvoyés par JobManager (déjà des dicts JSON-safe via
        job_to_dict, pas des modèles pydantic — donc pas de .model_dump ici).
        """
        if result is None:
            return {
                "success": True,
                "find": False,
                "result": []
            }

        result = [result] if not isinstance(result, list) else result
        return {
            "success": True,
            "find": bool(result),
            "entry_kwargs": kwargs_dump,
            "result": result
        }

    
    # =============================================================================
    #     Asset Tools (AssetManager)
    # =============================================================================
    
    @entry_model(GetAssetEntry)
    @timer
    async def get_asset_core_tool(
        self,
        identifier: str,
        include_name: bool = False,
        first: bool = False
    ):
        """
        Récupère un ou plusieurs assets par identifiant (ID interne, item_id,
        ou nom si include_name=True).

        Args:
            identifier: ID, item_id, ou nom de l'asset recherché
            include_name: Si True, permet aussi la recherche par nom exact
            first: Si True, ne retourne que le premier asset trouvé

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un asset a été trouvé
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des assets trouvés (dicts complets)

        Example:
            >>> get_asset(identifier="sh_as-4ae622a6...", first=True)
            {"success": True, "find": True, "result": [{"name": "Site Vitrine", ...}]}
        """
        kwargs = GetAssetEntry(
            identifier=identifier,
            include_name=include_name,
            first=first
        )
        result = await self.engine.asset_manager.get_by_identifier(
            identifier=kwargs.identifier,
            include_name=kwargs.include_name,
            first=kwargs.first
        )
        final_result = self._return_asset_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )
        return final_result
    
    # =============================================================================
    #     Asset Tools (AssetManager)
    # =============================================================================
    @entry_model(GetAssetByNameEntry)
    @timer
    async def get_asset_by_name_core_tool(
        self,
        name: str,
        case_sensitive: bool = False,
        partial: bool = False,
        first: bool = True,
        limit: int = 500
    ):
        """
        Recherche un ou plusieurs assets par leur nom, avec contrôle de la casse
        et de la partialité.
        """
        kwargs = GetAssetByNameEntry(
            name=name,
            case_sensitive=case_sensitive,
            partial=partial,
            first=first,
            limit=limit
        )
        result = await self.engine.asset_manager.get_asset_by_name(
            name=kwargs.name,
            case_sensitive=kwargs.case_sensitive,
            partial=kwargs.partial,
            first=kwargs.first,
            limit=kwargs.limit
        )
        final_result = self._return_asset_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )
        return final_result

    @entry_model(ListAssetEntry)
    @timer
    async def list_asset_core_tool(
        self,
        status: AssetStatus | None = None,
        type_: AssetType | None = None,
        priority: Priority | None = None,
        tags: list | None = None
    ):
        """
        Liste/filtre les assets par status, type, priority et/ou tags,
        combinables entre eux (AND global, OR interne sur les tags).
        Aucun filtre fourni = retourne tous les assets.

        Args:
            status: Filtrer par status (active, inactive, suppressed)
            type_: Filtrer par type d'asset (web_site, web_app, network, ...)
            priority: Filtrer par priorité (low, medium, high, critical)
            tags: Filtrer par tags (au moins un tag matché)

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un asset matche
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des assets trouvés (dicts complets)

        Example:
            >>> list_asset(status="active", type_="web_site")
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListAssetEntry(
            status=status,
            type_=type_,
            priority=priority,
            tags=tags,
        )
        result = await self.engine.asset_manager.list_by_filter(
            status=kwargs.status,
            type_=kwargs.type_,
            priority=kwargs.priority,
            tags=kwargs.tags
        )
        final_result = self._return_asset_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )
        return final_result

    @entry_model(ListAssetsByStatusEntry)
    @timer
    async def list_assets_by_status_core_tool(
        self,
        status: AssetStatus
    ):
        """
        Liste tous les assets ayant un statut précis. Raccourci pratique
        pour un état des lieux rapide (ex: "quels assets sont en pause ?"),
        sans avoir à combiner d'autres filtres via list_asset.

        Args:
            status: Statut recherché (active, inactive, suppressed)

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un asset a ce statut
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des assets trouvés (dicts complets)

        Example:
            >>> list_assets_by_status(status="inactive")
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListAssetsByStatusEntry(status=status)
        result = await self.engine.asset_manager.list_by_status(kwargs.status)
        return self._return_asset_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(ListAssetByTagsEntry)
    @timer
    async def list_assets_by_tags_core_tool(
        self,
        tags: list[str]
    ):
        """
        Recherche des assets par tags seuls (correspondance OR : un asset
        est retourné dès qu'il possède au moins un des tags demandés).

        Args:
            tags: Liste de tags à rechercher, ex: ["prod", "critique"]

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un asset matche
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des assets trouvés (dicts complets)

        Example:
            >>> list_assets_by_tags(tags=["prod", "api"])
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListAssetByTagsEntry(tags=tags)
        result = await self.engine.asset_manager.list_by_tags(kwargs.tags)
        final_result = self._return_asset_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )
        return final_result

    @entry_model(PauseAssetEntry)
    @timer
    async def pause_asset_core_tool(
        self,
        asset_id: str
    ):
        """
        Met un asset en pause (status -> INACTIVE) sans le supprimer, via le
        moteur (arrête proprement le workflow associé). Réversible via
        resume_asset.

        Args:
            asset_id: item_id de l'asset à mettre en pause

        Returns:
            Dict avec:
                - success: True si l'opération a réussi
                - status: "ok" ou "error"
                - asset_id: l'asset concerné
                - error: message d'erreur si échec

        Example:
            >>> pause_asset(asset_id="sh_as-4ae622a6...")
            {"success": True, "status": "ok", "asset_id": "sh_as-4ae622a6..."}
        """
        kwargs = PauseAssetEntry(asset_id=asset_id)
        async with resource_lock.acquire(f"asset:{kwargs.asset_id}"):
            result = await self.engine.pause_asset(kwargs.asset_id)
        return {
            "success": result.get("status") == "ok",
            "entry_kwargs": kwargs.model_dump(mode="json"),
            **result
        }

    @entry_model(ResumeAssetEntry)
    @timer
    async def resume_asset_core_tool(
        self,
        asset_id: str
    ):
        """
        Reprend un asset précédemment mis en pause (status -> ACTIVE), via
        le moteur (relance le workflow associé).

        Args:
            asset_id: item_id de l'asset à reprendre

        Returns:
            Dict avec:
                - success: True si l'opération a réussi
                - status: "ok" ou "error"
                - asset_id: l'asset concerné
                - error: message d'erreur si échec

        Example:
            >>> resume_asset(asset_id="sh_as-4ae622a6...")
            {"success": True, "status": "ok", "asset_id": "sh_as-4ae622a6..."}
        """
        kwargs = ResumeAssetEntry(asset_id=asset_id)
        async with resource_lock.acquire(f"asset:{kwargs.asset_id}"):
            result = await self.engine.resume_asset(kwargs.asset_id)
        return {
            "success": result.get("status") == "ok",
            "entry_kwargs": kwargs.model_dump(mode="json"),
            **result
        }
    
   
    @entry_model(PauseAssetsEntry)
    @timer
    async def pause_assets_core_tool(
        self,
        asset_type: str | None = None,
        asset_ids: list[str] | None = None,
        priority: Priority | None = None,
        tags: list[str] | None = None,
    ):
        """
        Met en pause plusieurs assets d'un coup (status -> INACTIVE), avec
        filtre optionnel par type et/ou par liste d'ids précise. Sans
        filtre, agit sur TOUS les assets actifs — utile en cas d'incident
        (ex: "on subit une attaque, coupe tout").
    
        Args:
            asset_type: Ne cibler que les assets de ce type. None = tous types.
            asset_ids: Ne cibler que ces assets précis. None = pas de filtre.
    
        Returns:
            Dict avec:
                - success: True si l'appel s'est exécuté correctement
                - all_ok: True si TOUS les assets ciblés ont bien été mis en pause
                - results: dict {asset_id: résultat individuel}
    
        Example:
            >>> pause_assets()  # tout mettre en pause
            >>> pause_assets(asset_type="web_site")  # que les sites web
            >>> pause_assets(asset_ids=["sh_as-...", "sh_as-..."])
        """
        kwargs = PauseAssetsEntry(
            asset_type=asset_type,
            asset_ids=asset_ids,
            tags=tags,
            priority=priority,
        )
        results = await self.engine.pause_assets(
            asset_type=kwargs.asset_type,
            asset_ids=kwargs.asset_ids,
            tags=kwargs.tags,
            priority=kwargs.priority
        )
        all_ok = all(r.get("status") == "ok" for r in results.values()) if results else True
        return {
            "success": True,
            "all_ok": all_ok,
            "entry_kwargs": kwargs.model_dump(mode="json"),
            "results": results,
        }
    
    @entry_model(ResumeAssetsEntry)
    @timer
    async def resume_assets_core_tool(
        self,
        asset_type: str | None = None,
        asset_ids: list[str] | None = None,
        priority: Priority | None = None,
        tags: list[str] | None = None,
    ):
        """
        Reprend plusieurs assets d'un coup (status -> ACTIVE), avec filtre
        optionnel par type et/ou par liste d'ids précise. Sans filtre, agit
        sur TOUS les assets en pause.
    
        Args:
            asset_type: Ne cibler que les assets de ce type. None = tous types.
            asset_ids: Ne cibler que ces assets précis. None = pas de filtre.
    
        Returns:
            Dict avec:
                - success: True si l'appel s'est exécuté correctement
                - all_ok: True si TOUS les assets ciblés ont bien repris
                - results: dict {asset_id: résultat individuel}
    
        Example:
            >>> resume_assets()
            >>> resume_assets(asset_type="network")
        """
        kwargs = ResumeAssetsEntry(
            asset_type=asset_type, 
            asset_ids=asset_ids,
            tags=tags,
            priority=priority,
        )
        results = await self.engine.resume_assets(
            asset_type=kwargs.asset_type,
            asset_ids=kwargs.asset_ids,
            tags=kwargs.tags,
            priority=kwargs.priority
        )
        all_ok = all(r.get("status") == "ok" for r in results.values()) if results else True
        return {
            "success": True,
            "all_ok": all_ok,
            "entry_kwargs": kwargs.model_dump(mode="json"),
            "results": results,
        }

    def _update_asset_risk(**kwargs) -> str:
        return "high" if kwargs.get("restart_workflow") else "medium"

    @confirm_self_dynamic(risk_fn=_update_asset_risk, timeout=120)
    @entry_model(UpdateAssetEntry)
    @timer
    async def update_asset_core_tool(
        self,
        asset_id: str,
        attrs: dict,
        restart_workflow: bool = False
    ):
        """
        Met à jour des attributs d'un asset existant (priority, tags, url,
        config...), via le moteur. attrs n'écrase que les clés fournies, le
        reste de l'asset reste inchangé.

        Args:
            asset_id: item_id de l'asset à mettre à jour
            attrs: attributs à modifier, ex: {"priority": "high", "tags": ["prod"]}
            restart_workflow: Si True, redémarre le workflow avec la nouvelle
                config (nécessaire si url/config_path/source_code_dir changent,
                mais peut relancer un scan immédiatement)

        Returns:
            Dict avec:
                - success: True si la mise à jour a réussi
                - status: "ok" ou "error"
                - asset_id: l'asset concerné
                - error: message d'erreur si échec

        Example:
            >>> update_asset(asset_id="sh_as-...", attrs={"priority": "high"})
            {"success": True, "status": "ok", "asset_id": "sh_as-..."}
        """
        kwargs = UpdateAssetEntry(
            asset_id=asset_id,
            attrs=attrs,
            restart_workflow=restart_workflow
        )
        async with resource_lock.acquire(f"asset:{kwargs.asset_id}"):
            result = await self.engine.update_asset(
                asset_id=kwargs.asset_id,
                attrs=kwargs.attrs,
                restart_workflow=kwargs.restart_workflow,
            )
        return {
            "success": result.get("status") == "ok",
            "entry_kwargs": kwargs.model_dump(mode="json"),
            **result
        }

    @entry_model(GetEngineStatusEntry)
    @timer
    def get_engine_status_core_tool(self):
        """
        Retourne l'état global du moteur ShieldAI : démarré ou non, nombre
        et détail des tasks actives. Bonne première étape pour une question
        type "est-ce que tout tourne bien en ce moment ?".

        Returns:
            Dict avec:
                - success: True
                - started: True si le moteur est démarré
                - active_tasks: nombre de tasks actives
                - tasks: détail des tasks actives (par task_id)

        Example:
            >>> get_engine_status()
            {"success": True, "started": True, "active_tasks": 2, "tasks": {...}}
        """
        result = self.engine.status()
        return {
            "success": True,
            **result
        }
    
    # Je marque
    @confirm_self(risk="critical", timeout=180)
    @entry_model(RemoveAssetEntry)
    @timer
    async def remove_asset_core_tool(self, asset_id: str):
        """
        ⚠️ Destructif et irréversible : supprime définitivement l'asset de
        la base (config, historique) et annule ses tasks actives. Si un
        source_code_dir existe (simple copie locale du code, fournie par
        un admin), il est aussi nettoyé sur disque -- sans conséquence en
        soi puisque ce n'est qu'une copie. Le vrai motif du risque
        "critical" est la suppression DB, pas ce nettoyage de fichiers.
        Contrairement à pause_asset (réversible via resume_asset), aucun
        retour en arrière n'est possible après cet appel.

        Args:
            asset_id: item_id de l'asset à supprimer.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "asset_id": str}

        Example:
            >>> remove_asset(asset_id="sh_as-4ae622a6...")
            {"success": True, "asset_id": "sh_as-4ae622a6..."}
        """
        entry = RemoveAssetEntry(asset_id=asset_id)
        async with resource_lock.acquire(f"asset:{entry.asset_id}"):
            result = await self.engine.remove_asset(asset_id=entry.asset_id, delete=True)
        return {
            "success": result.get("status") == "ok",
            "entry_kwargs": entry.model_dump(mode="json"),
            **result,
        }
    
    # Marqué

    # =========================================================================
    # Rapports (ReportManager)
    # =========================================================================

    @entry_model(GetReportEntry)
    @timer
    async def get_report_core_tool(
        self,
        identifier: str,
        first: bool = False,
        limit: int = 50
    ):
        """
        Récupère un ou plusieurs rapports par ID de rapport OU par asset_id
        (identifier flexible, les deux sont testés).

        Args:
            identifier: ID du rapport (ex: "42") ou asset_id concerné
            first: Si True, ne retourne que le rapport le plus récent trouvé
            limit: Nombre maximum de résultats si first=False

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un rapport a été trouvé
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des rapports trouvés (dicts complets, JSON-safe)

        Example:
            >>> get_report(identifier="sh_as-...", first=False, limit=10)
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = GetReportEntry(identifier=identifier, first=first, limit=limit)
        result = await self.report_manager.get_by_identifier(
            identifier=kwargs.identifier,
            first=kwargs.first,
            limit=kwargs.limit,
        )
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(GetFirstestReportEntry)
    @timer
    async def get_firstest_report_core_tool(
        self,
        asset_id: str
    ):
        """
        Récupère le tout premier rapport (le plus ancien) d'un asset — utile
        pour situer depuis quand un problème est suivi ou voir l'historique
        depuis l'origine de l'asset.

        Args:
            asset_id: item_id de l'asset concerné

        Returns:
            Dict avec:
                - success: True
                - find: True si un rapport a été trouvé
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste contenant le rapport le plus ancien (0 ou 1 élément)

        Example:
            >>> get_firstest_report(asset_id="sh_as-...")
            {"success": True, "find": True, "result": [{"created_at": "2026-06-01T...", ...}]}
        """
        kwargs = GetFirstestReportEntry(asset_id=asset_id)
        result = await self.report_manager.get_firstest_by_asset(kwargs.asset_id)
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(GetLatestReportEntry)
    @timer
    async def get_latest_report_core_tool(
        self,
        asset_id: str
    ):
        """
        Récupère le dernier rapport en date d'un asset — plus léger que
        get_report quand seul le dernier état connu importe.

        Args:
            asset_id: item_id de l'asset concerné

        Returns:
            Dict avec:
                - success: True
                - find: True si un rapport a été trouvé
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste contenant le rapport le plus récent (0 ou 1 élément)

        Example:
            >>> get_latest_report(asset_id="sh_as-...")
            {"success": True, "find": True, "result": [{"created_at": "2026-07-12T...", ...}]}
        """
        kwargs = GetLatestReportEntry(asset_id=asset_id)
        result = await self.report_manager.get_latest_by_asset(kwargs.asset_id)
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(ListReportsByFilterEntry)
    @timer
    async def list_reports_by_filter_core_tool(
        self,
        asset_id: str | None = None,
        source: Source | None = None,
        severity: Severity | None = None,
        min_severity: Severity | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ):
        """
        Filtrage complet et combiné des rapports (asset, source, sévérité
        exacte ou minimale, plage de dates). Le tool le plus puissant pour
        une recherche précise dans l'historique des rapports.

        Args:
            asset_id: Filtrer sur un asset précis
            source: Filtrer sur un module d'origine (scanner_web, ids_ips, ...)
            severity: Filtrer sur une sévérité exacte
            min_severity: Filtrer sur une sévérité minimale (ex: "high"
                inclut aussi "critical")
            start_date: Borne de date de début (incluse)
            end_date: Borne de date de fin (incluse)
            limit: Nombre maximum de résultats

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un rapport matche
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des rapports trouvés (dicts complets, JSON-safe)

        Example:
            >>> list_reports_by_filter(asset_id="sh_as-...", min_severity="high")
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListReportsByFilterEntry(
            asset_id=asset_id,
            source=source,
            severity=severity,
            min_severity=min_severity,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        result = await self.report_manager.list_by_filter(
            asset_id=kwargs.asset_id,
            source=kwargs.source,
            severity=kwargs.severity.value if kwargs.severity else None,
            min_severity=kwargs.min_severity.value if kwargs.min_severity else None,
            start_date=kwargs.start_date,
            end_date=kwargs.end_date,
            limit=kwargs.limit,
        )
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(ListCriticalReportsEntry)
    @timer
    async def list_critical_reports_core_tool(
        self,
        limit: int = 100
    ):
        """
        Liste tous les rapports de sévérité critique, tous assets confondus
        — bon point de départ pour un état des lieux rapide des urgences.

        Args:
            limit: Nombre maximum de résultats

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un rapport critique existe
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des rapports critiques (dicts complets, JSON-safe)

        Example:
            >>> list_critical_reports(limit=20)
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListCriticalReportsEntry(limit=limit)
        result = await self.report_manager.list_critical(limit=kwargs.limit)
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(ListRecentReportsEntry)
    @timer
    async def list_recent_reports_core_tool(
        self,
        window_hours: float = 24,
        limit: int = 200
    ):
        """
        Liste tous les rapports récents (tous assets confondus) sur une
        fenêtre glissante. C'est LE tool à utiliser pour la synthèse
        périodique/cross-module : détecter qu'une série d'alertes séparées
        sur des assets différents dessine en fait une campagne coordonnée.

        Args:
            window_hours: Fenêtre temporelle en heures à considérer (défaut: 24h)
            limit: Nombre maximum de résultats

        Returns:
            Dict avec:
                - success: True
                - find: True si au moins un rapport tombe dans la fenêtre
                - entry_kwargs: les paramètres effectivement utilisés
                - result: liste des rapports trouvés (dicts complets, JSON-safe)

        Example:
            >>> list_recent_reports(window_hours=24)
            {"success": True, "find": True, "result": [...]}
        """
        kwargs = ListRecentReportsEntry(window_hours=window_hours, limit=limit)
        start_date = utcnow() - timedelta(hours=kwargs.window_hours)
        result = await self.report_manager.list_by_filter(
            start_date=start_date,
            limit=kwargs.limit,
        )
        return self._return_report_generic(
            result=result,
            kwargs_dump=kwargs.model_dump(mode="json")
        )

    @entry_model(GetReportStatsEntry)
    @timer
    async def get_report_stats_core_tool(
        self,
        asset_id: str | None = None
    ):
        """
        Statistiques agrégées des rapports (total, répartition par sévérité
        et par source, dates extrêmes, nombre avec fix) — globales si
        asset_id est None, ciblées sur un asset sinon.

        Args:
            asset_id: Si fourni, restreint les stats à cet asset. Sinon,
                stats globales sur tout le système.

        Returns:
            Dict avec:
                - success: True
                - entry_kwargs: les paramètres effectivement utilisés
                - stats: dict avec total, by_severity, by_source, latest,
                    oldest (ISO 8601), has_fix

        Example:
            >>> get_report_stats(asset_id="sh_as-...")
            {"success": True, "stats": {"total": 12, "by_severity": {...}, ...}}
        """
        kwargs = GetReportStatsEntry(asset_id=asset_id)
        stats = await self.report_manager.summary_stats(asset_id=kwargs.asset_id)
        stats = dict(stats)
        if stats.get("latest"):
            stats["latest"] = stats["latest"].isoformat()
        if stats.get("oldest"):
            stats["oldest"] = stats["oldest"].isoformat()
        return {
            "success": True,
            "entry_kwargs": kwargs.model_dump(mode="json"),
            "stats": stats,
        }
    
    @confirm_self(risk="medium", timeout=120)
    @entry_model(UpdateReportSeverityEntry)
    @timer
    async def update_report_severity_core_tool(
        self,
        report_id: int,
        severity: str,
        has_fix: bool | None = None
    ):
        """
        Reclasse la sévérité d'un rapport existant (ex: requalifier un faux
        positif en 'low', ou escalader une découverte en 'critical'). Seuls
        severity et has_fix sont modifiables via ce tool -- jamais content
        ou report_json, pour préserver l'intégrité du rapport d'Alex.

        Args:
            report_id: ID du rapport à modifier.
            severity: Nouvelle sévérité.
            has_fix: Si fourni, met aussi à jour le flag has_fix.

        Returns:
            {"success": bool, "entry_kwargs": {...}}

        Example:
            >>> update_report_severity(report_id=42, severity="low")
            {"success": True, "entry_kwargs": {"report_id": 42, "severity": "low"}}
        """
        entry = UpdateReportSeverityEntry(report_id=report_id, severity=severity, has_fix=has_fix)
        changes = {"severity": entry.severity.value}
        if entry.has_fix is not None:
            changes["has_fix"] = entry.has_fix
        async with resource_lock.acquire(f"report:{entry.report_id}"):
            success = await self.report_manager.update_by_id(entry.report_id, **changes)
        return {"success": success, "entry_kwargs": entry.model_dump(mode="json")}

    # Je marque
    @confirm_self(risk="high", timeout=120)
    @entry_model(DeleteReportEntry)
    @timer
    async def delete_report_core_tool(self, report_id: int):
        """
        ⚠️ Destructif et irréversible : supprime définitivement un rapport.

        Args:
            report_id: ID du rapport à supprimer.

        Returns:
            {"success": bool, "entry_kwargs": {...}}
        """
        entry = DeleteReportEntry(report_id=report_id)
        async with resource_lock.acquire(f"report:{entry.report_id}"):
            success = await self.report_manager.delete_by_id(entry.report_id)
        return {"success": success, "entry_kwargs": entry.model_dump(mode="json")}

    @confirm_self(risk="critical", timeout=180)
    @entry_model(DeleteOldReportsEntry)
    @timer
    async def delete_old_reports_core_tool(self, days: int):
        """
        ⚠️ Destructif, irréversible, LARGE IMPACT : supprime définitivement
        TOUS les rapports plus vieux que `days`
        jours. Utilisé aussi par le job planifié 'report_cleanup' du
        catalogue (voir job_catalog.py).

        Args:
            days: Âge en jours au-delà duquel les rapports sont supprimés.

        Returns:
            {"success": True, "deleted_count": int, "entry_kwargs": {...}}
        """
        entry = DeleteOldReportsEntry(days=days)
        count = await self.report_manager.delete_older_than(entry.days)
        return {"success": True, "deleted_count": count, "entry_kwargs": entry.model_dump(mode="json")}
    
    # Marqué
    
    # =============================================================================
    #  JobManager tools
    # =============================================================================
    
    @entry_model(ListJobsEntry)
    @timer
    def list_jobs_core_tool(self, in_memory: bool | None = None):
        """
        Liste tous les jobs planifiés (scan récurrents, rapports périodiques,
        etc.), avec leur trigger, prochaine exécution, fonction associée.

        Args:
            in_memory: True: jobstore mémoire uniquement. False: jobstore
                persistant (SQL) uniquement. None (défaut): les deux combinés.

        Returns:
            {"success": True, "find": bool, "entry_kwargs": {...},
             "result": [job_dict, ...]}

        Example:
            >>> list_jobs()
            {"success": True, "find": True, "result": [{"id": "scan_daily", ...}]}
        """
        kwargs = ListJobsEntry(in_memory=in_memory)
        result = self.job_manager.list_jobs_wrapped(in_memory=kwargs.in_memory)
        return self._return_job_generic(kwargs_dump=kwargs.model_dump(mode="json"), result=result)

    @entry_model(GetJobEntry)
    @timer
    def get_job_core_tool(self, job_id: str, in_memory: bool | None = None):
        """
        Récupère un job planifié précis par son ID (trigger complet,
        prochaine exécution, fonction associée, args/kwargs, etc.).

        Args:
            job_id: ID du job recherché.
            in_memory: Voir list_jobs.

        Returns:
            {"success": True, "find": bool, "entry_kwargs": {...},
             "result": [job_dict] ou []}
        """
        kwargs = GetJobEntry(job_id=job_id, in_memory=in_memory)
        result = self.job_manager.get_job_wrapped(job_id=kwargs.job_id, in_memory=kwargs.in_memory)
        return self._return_job_generic(kwargs_dump=kwargs.model_dump(mode="json"), result=result)

    @entry_model(GetJobStateEntry)
    @timer
    def get_job_state_core_tool(self, job_id: str, in_memory: bool | None = None):
        """
        Raccourci léger : retourne juste l'état d'un job ("running",
        "paused", "pending") sans le détail complet — pratique quand seule
        cette info compte (ex: "est-ce que ce job tourne encore ?").

        Args:
            job_id: ID du job.
            in_memory: Voir list_jobs.

        Returns:
            {"success": True, "find": bool, "entry_kwargs": {...},
             "state": str | None}
        """
        kwargs = GetJobStateEntry(job_id=job_id, in_memory=in_memory)
        state = self.job_manager.get_job_state(job_id=kwargs.job_id, in_memory=kwargs.in_memory)
        return {
            "success": True,
            "find": state is not None,
            "entry_kwargs": kwargs.model_dump(mode="json"),
            "state": state,
        }

    @entry_model(PauseJobEntry)
    @timer
    async def pause_job_core_tool(self, job_id: str, in_memory: bool | None = None):
        """
        Met un job en pause : arrête ses déclenchements futurs sans le
        supprimer. Réversible via resume_job — trigger et config du job
        restent intacts.

        Args:
            job_id: ID du job à mettre en pause.
            in_memory: Voir list_jobs.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "error": str | None,
             "traceback": str | None}
        """
        kwargs = PauseJobEntry(job_id=job_id, in_memory=in_memory)
        async with resource_lock.acquire(f"job:{kwargs.job_id}"):
            result = self.job_manager.pause_job(job_id=kwargs.job_id, in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}

    @entry_model(ResumeJobEntry)
    @timer
    async def resume_job_core_tool(self, job_id: str, in_memory: bool | None = None):
        """
        Reprend un job en pause. La prochaine exécution est recalculée à
        partir du trigger actuel du job et de l'instant présent.

        Args:
            job_id: ID du job à reprendre.
            in_memory: Voir list_jobs.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "error": str | None,
             "traceback": str | None}
        """
        kwargs = ResumeJobEntry(job_id=job_id, in_memory=in_memory)
        async with resource_lock.acquire(f"job:{kwargs.job_id}"):
            result = self.job_manager.resume_job(job_id=kwargs.job_id, in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}

    @confirm_self(risk="medium", timeout=120)
    @entry_model(ModifyJobEntry)
    @timer
    async def modify_job_core_tool(
        self,
        job_id: str,
        in_memory: bool | None = None,
        trigger: dict | None = None,
        args: list | None = None,
        kwargs: dict | None = None,
        name: str | None = None,
        max_instances: int | None = None,
        coalesce: bool | None = None,
        misfire_grace_time: int | None = None,
        executor: str | None = None,
    ):
        """
        Modifie un ou plusieurs attributs d'un job existant. Seuls les
        champs fournis (non None) sont appliqués. Si 'trigger' est fourni,
        la prochaine exécution est recalculée automatiquement — sauf si le
        job est actuellement en pause, auquel cas il reste en pause avec
        le nouveau trigger prêt pour la reprise.

        Args:
            job_id: ID du job à modifier.
            in_memory: Voir list_jobs.
            trigger: Nouveau trigger, ex: {"type": "cron", "hour": 9, "minute": 0}
                ou {"type": "interval", "hours": 6} ou {"type": "date",
                "run_date": "2026-08-01T12:00:00"} ou {"type": "calendarinterval",
                "months": 3}.
            args: Nouveaux arguments positionnels de la fonction du job.
            kwargs: Nouveaux arguments nommés de la fonction du job.
            name: Nouveau nom lisible.
            max_instances: Nombre max d'exécutions concurrentes.
            coalesce: Fusionner les exécutions manquées en une seule.
            misfire_grace_time: Tolérance (secondes) avant de considérer un run manqué.
            executor: Nom de l'executor APScheduler à utiliser.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "error": str | None,
             "traceback": str | None}

        Example:
            >>> modify_job("scan_daily", trigger={"type": "cron", "hour": 3})
        """
        entry = ModifyJobEntry(
            job_id=job_id, in_memory=in_memory, trigger=trigger, args=args,
            kwargs=kwargs, name=name, max_instances=max_instances,
            coalesce=coalesce, misfire_grace_time=misfire_grace_time, executor=executor,
        )
        changes = entry.model_dump(mode="json", exclude_none=True, exclude={"job_id", "in_memory"})
        async with resource_lock.acquire(f"job:{entry.job_id}"):
            result = self.job_manager.modify_job(job_id=entry.job_id, in_memory=entry.in_memory, **changes)
        return {"entry_kwargs": entry.model_dump(mode="json"), **result}
    
    # Je marque
    @confirm_self(risk="high", timeout=120)
    @entry_model(RemoveJobEntry)
    @timer
    async def remove_job_core_tool(self, job_id: str, in_memory: bool | None = None):
        """
        ⚠️ Destructif et irréversible : supprime définitivement un job.

        Args:
            job_id: ID du job à supprimer.
            in_memory: Voir list_jobs.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "error": str | None,
             "traceback": str | None}
        """
        kwargs = RemoveJobEntry(job_id=job_id, in_memory=in_memory)
        async with resource_lock.acquire(f"job:{kwargs.job_id}"):
            result = self.job_manager.remove_job(job_id=kwargs.job_id, in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}

    @confirm_self(risk="critical", timeout=180)
    @entry_model(RemoveAllJobsEntry)
    @timer
    async def remove_all_jobs_core_tool(self, in_memory: bool | None = None):
        """
        ⚠️ Destructif et irréversible, large impact : supprime définitivement
        TOUS les jobs (d'un jobstore ou des deux si in_memory=None).

        Args:
            in_memory: True: mémoire uniquement. False: persistant uniquement.
                None: les deux jobstores — à utiliser avec une extrême prudence.

        Returns:
            {"success": bool, "entry_kwargs": {...}, "error": str | None,
             "traceback": str | None}
        """
        kwargs = RemoveAllJobsEntry(in_memory=in_memory)
        result = self.job_manager.remove_all_jobs(in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}
    
    # Marqué
    @confirm_self(risk="medium", timeout=60)
    @entry_model(PauseAllJobsEntry)
    @timer
    async def pause_all_jobs_core_tool(self, in_memory: bool | None = None):
        """
        ⚠️ Large impact : met TOUS les jobs en pause. Réversible via
        resume_all_jobs, mais marqué comme action sensible en attendant la
        confirmation humaine (human-in-the-loop, à venir).

        Args:
            in_memory: True: mémoire uniquement. False: persistant uniquement.
                None: les deux jobstores.

        Returns:
            {"success": bool, "affected": int, "entry_kwargs": {...},
             "error": str | None, "traceback": str | None}
        """
        kwargs = PauseAllJobsEntry(in_memory=in_memory)
        result = self.job_manager.pause_all_jobs(in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}

    @entry_model(ResumeAllJobsEntry)
    @timer
    def resume_all_jobs_core_tool(self, in_memory: bool | None = None):
        """
        ⚠️ Large impact : reprend TOUS les jobs en pause. Marqué comme
        action sensible en attendant la confirmation humaine (à venir).

        Args:
            in_memory: True: mémoire uniquement. False: persistant uniquement.
                None: les deux jobstores.

        Returns:
            {"success": bool, "affected": int, "entry_kwargs": {...},
             "error": str | None, "traceback": str | None}
        """
        kwargs = ResumeAllJobsEntry(in_memory=in_memory)
        result = self.job_manager.resume_all_jobs(in_memory=kwargs.in_memory)
        return {"entry_kwargs": kwargs.model_dump(mode="json"), **result}
    
    @entry_model(ListJobCatalogEntry)
    @timer
    def list_job_catalog_core_tool(self):
        """
        Liste les jobs planifiables via add_job, avec leur description,
        trigger et kwargs par défaut. À utiliser avant add_job si les noms
        disponibles ne sont pas déjà connus.

        Returns:
            {"success": True, "catalog": [{"job_name", "description",
             "default_trigger", "default_kwargs"}, ...]}
        """
        return {"success": True, "catalog": describe_catalog()}

    @confirm_self(risk="medium", timeout=120)
    @entry_model(AddJobEntry)
    @timer
    async def add_job_core_tool(
        self,
        job_name: str,
        job_id: str,
        trigger: dict | None = None,
        kwargs: dict | None = None,
        in_memory: bool = False,
    ):
        """
        Planifie un nouveau job à partir du catalogue prédéfini (voir
        list_job_catalog). Coralie ne fournit qu'un nom -- jamais de
        fonction arbitraire (contrainte APScheduler, voir job_catalog.py).

        Args:
            job_name: Nom du job dans le catalogue.
            job_id: ID unique pour cette instance planifiée.
            trigger: Trigger custom, sinon celui par défaut du catalogue.
            kwargs: Kwargs custom, fusionnés avec ceux par défaut du catalogue.
            in_memory: Voir list_jobs.

        Returns:
            {"success": True, "entry_kwargs": {...}, "job": {...}}
        """
        entry = AddJobEntry(job_name=job_name, job_id=job_id, trigger=trigger, kwargs=kwargs, in_memory=in_memory)
        spec = JOB_CATALOG[entry.job_name]
        merged_kwargs = {**spec.default_kwargs, **(entry.kwargs or {})}
        job = self.job_manager.add_job_wrapped(
            func=spec.func,
            job_id=entry.job_id,
            name=spec.description,
            trigger=entry.trigger or spec.default_trigger,
            kwargs=merged_kwargs,
            in_memory=entry.in_memory,
        )
        return {"success": True, "entry_kwargs": entry.model_dump(mode="json"), "job": job}
    
    # =============================================================================
    #     Autres tools
    # =============================================================================
    
    @entry_model(GetInfoAboutToolEntry)
    @timer
    def get_info_about_tool_core_tool(
        self,
        tool_name: str
    ):
        """
        Retourne la documentation complète d'un tool précis : description,
        schéma des arguments (auto-généré, toujours à jour), use_case,
        impact et avertissements (curés à la main dans tool_docs.py). À
        utiliser avant d'appeler un tool peu familier ou dont l'impact
        (destructif ou non) n'est pas clair.

        Args:
            tool_name: Nom exact du tool à documenter (ex: "pause_asset")

        Returns:
            Dict avec:
                - success: True si le tool existe
                - info: {name, description, parameters, use_case, impact,
                    warnings, examples} si trouvé
                - error / available_tools: si tool_name est inconnu

        Example:
            >>> get_info_about_tool(tool_name="update_asset")
            {"success": True, "info": {"name": "update_asset", "impact": "non-destructif...", ...}}
        """
        kwargs = GetInfoAboutToolEntry(tool_name=tool_name)
        if kwargs.tool_name in self._analyst_tools:
            return analyst_get_info_about_tool(tool_name=kwargs.tool_name)
        
        if kwargs.tool_name not in self.tools:
            return {
                "success": False,
                "error": f"Tool inconnu : {kwargs.tool_name!r}",
                "available_tools": list_available_tools(self.tools),
            }

        func = self.tools[kwargs.tool_name]
        info = describe_tool(func, TOOL_DOCS, name=kwargs.tool_name)
        return {
            "success": True,
            "info": info,
        }

    @staticmethod
    def _make_llm_tool(exposed_name: str, bound_func):
        """
        Enveloppe une bound method (ex: self.pause_asset_core_tool) dans une
        fonction dont __name__ est le nom exposé (sans le suffixe
        '_core_tool'). Nécessaire car :
            1. function_to_generic_schema utilise func.__name__ comme nom du
               tool dans le schéma envoyé au modèle ;
            2. LLMManager.execute_tool retrouve ensuite la fonction à
               exécuter dans tool_map en cherchant CE MÊME nom.
        Sans ce renommage, le modèle verrait le tool sous le nom
        'pause_asset_core_tool' (avec suffixe), execute_tool chercherait ce
        nom dans un tool_map dont les clés sont 'pause_asset' (sans
        suffixe) et échouerait systématiquement ("Outil inconnu").
        Un bound method Python n'autorise pas la réassignation directe de
        __name__ (AttributeError), d'où ce wrapper plutôt qu'un simple
        renommage in-place.
        """
        entry_model_cls = getattr(bound_func, "__entry_model__", None)
        doc = bound_func.__doc__

        if inspect.iscoroutinefunction(bound_func):
            async def wrapper(*args, **kwargs):
                return await bound_func(*args, **kwargs)
        else:
            def wrapper(*args, **kwargs):
                return bound_func(*args, **kwargs)

        wrapper.__name__ = exposed_name
        wrapper.__doc__ = doc
        wrapper.__entry_model__ = entry_model_cls
        return wrapper

    def get_llm_tools(self) -> list:
        """
        Retourne la liste des tools au format attendu par
        LLMManager.run_agent (tools=... / tool_mapping=...), avec des noms
        exposés cohérents (sans suffixe '_core_tool') entre le schéma vu
        par le modèle et la clé utilisée pour l'exécution réelle.
        """
        return [
            self._make_llm_tool(exposed_name, bound_func)
            for exposed_name, bound_func in self.tools.items()
        ]

    def get_tools(self, name: bool = True, value: bool = False):
        if name and value:
            return list(self.tools.items())
        if name and not value:
            return list(self.tools.keys())
        if value and not name:
            return list(self.tools.values())
        
        return None
    