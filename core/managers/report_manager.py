#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 10 16:59:15 2026

@author: hounsousamuel
"""

import os
import time
import json
import typing
import inspect
import functools
import asyncio
from enum import Enum
import zstandard as zstd
from typing import Optional, List, Any
from sqlmodel import SQLModel, Field, select, func, or_, and_, String
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field as Pydantic_Field
from obsidian_hive.core.assets.asset_types import utcnow, Severity, SEVERITY_ORDER, Source
from modules_utils.loop_utils import _run_async


class AnalysisReportDB(SQLModel, table=True):
    """Modèle de base de données pour les rapports d'analyse.
    
    Stocke les rapports générés par Alex avec compression des données
    (content et report_json sont compressés avec Zstandard).
    
    Attributes:
        id (Optional[int]): ID du rapport en base.
        asset_id (str): item_id de l'asset concerné.
        source (Source): Module d'origine (scanner_web, ids_ips, etc.).
        severity (Severity): Niveau de gravité.
        content (bytes): Prompt d'entrée compressé.
        report_json (bytes): Rapport complet d'Alex compressé.
        created_at (datetime): Date de création.
        timestamp (float): Timestamp de création.
        has_fix (bool): True si le rapport contient un fix.
    """
    __tablename__ = "analysis_report_db"
    __table_args__ = {"extend_existing": True}

    id: Optional[int] = Field(primary_key=True, default=None, description="ID de report en DB")
    asset_id: str = Field(description="item_id de l'asset concerné")
    source: Source = Field(description="Module d'origine, ex: 'scanner_web', 'ids_ips'")
    severity: Severity = Field(description="Niveau de gravité: critical, high, medium, low, info")
    content: bytes = Field(description="Prompt d'entrée compressé.")
    report_json: bytes = Field(description="Rapport complet d'Alex, sérialisé JSON, puis compressé")
    created_at: datetime = Field(default_factory=utcnow, description="Date de création")
    timestamp: float = Field(default_factory=time.monotonic, description="Timestamp de création")
    has_fix: bool = Field(
        default=False,
        description="True si le rapport contient un fix proposé/appliqué"
    )

    
class AnalysisReport(BaseModel):
    """Modèle de lecture pour les rapports d'analyse (décompressé).
    
    Version désérialisée d'AnalysisReportDB avec content et report_json
    sous forme de chaînes décompressées.
    """
    id: Optional[int] = Pydantic_Field(description="ID de report en DB", default=None)
    asset_id: str = Pydantic_Field(description="item_id de l'asset concerné")
    source: Source = Pydantic_Field(description="Module d'origine, ex: 'scanner_web', 'ids_ips'")
    severity: Severity = Pydantic_Field(description="Niveau de gravité: critical, high, medium, low, info")
    content: str = Pydantic_Field(description="Prompt d'entrée.")
    report_json: str = Pydantic_Field(description="Rapport complet d'Alex, sérialisé JSON")
    created_at: datetime = Pydantic_Field(default_factory=utcnow, description="Date de création")
    timestamp: float = Pydantic_Field(default_factory=time.monotonic, description="Timestamp de création")
    has_fix: bool = Pydantic_Field(
        default=False,
        description="True si le rapport contient un fix proposé/appliqué"
    )


def compress(data: str | bytes):
    """Compresse des données avec Zstandard.

    Args:
        data (str | bytes): Données à compresser.

    Returns:
        bytes: Données compressées.
    """
    data = data if isinstance(data, bytes) else data.encode()
    return zstd.compress(data, level=6)


def decompress(data: str | bytes):
    """Décompresse des données Zstandard.

    Args:
        data (str | bytes): Données compressées.

    Returns:
        str: Données décompressées en chaîne.
    """
    data = data if isinstance(data, bytes) else data.encode()
    return zstd.decompress(data).decode()


def decompress_wrapper(func):
    """
    Décorateur qui décompresse les champs content et report_json
    des résultats retournés par les méthodes de lecture.
    
    Args:
        func (Callable): La fonction à décorer.

    Returns:
        Callable: La fonction wrapper.
    """
    
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> None | List[AnalysisReport] | AnalysisReport:
        result: List[AnalysisReportDB] | None | AnalysisReportDB = func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result: List[AnalysisReportDB] | None | AnalysisReportDB = await result
            
        if not result:
            return result
        
        if isinstance(result, AnalysisReportDB):
            result = result.model_dump()
            result["content"] = decompress(result["content"])
            result["report_json"] = decompress(result["report_json"])
            return AnalysisReport.model_validate(result)
        
        elif isinstance(result, list):
            results = []
            for r in result:
                r = r.model_dump()
                r["content"] = decompress(r["content"])
                r["report_json"] = decompress(r["report_json"])
                results.append(AnalysisReport.model_validate(r))
            
            return results
        
        return result
    
    return wrapper


class ReportManager:
    """Gestionnaire des rapports d'analyse avec compression et persistance.
    
    Fournit des opérations CRUD complètes pour les rapports d'analyse,
    avec compression automatique des données, filtrage avancé,
    statistiques et gestion des versions.
    
    Attributes:
        db_url (str): URL de connexion à la base de données.
        engine (AsyncEngine): Moteur SQLAlchemy asynchrone.
    """
    
    def __init__(self, db_url: str):
        """Initialise le gestionnaire de rapports.

        Args:
            db_url (str): URL de connexion à la base de données.
                Ex: "sqlite+aiosqlite:///reports.db"
        """
        self.db_url = db_url
        db_path = db_url.removeprefix("sqlite+aiosqlite:///")
        if db_path and db_path != ":memory:":
            dirname = os.path.dirname(db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
        self._initialized = False
        _run_async(self.init_db)

    async def init_db(self):
        """Initialise la base de données et crée la table si elle n'existe pas."""
        if self._initialized:
            return
        self.engine = create_async_engine(self.db_url)
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        self._initialized = True

    @asynccontextmanager
    async def get_session(self):
        """Retourne un contexte de session de base de données.

        Yields:
            AsyncSession: Une session SQLAlchemy asynchrone.
        """
        async with AsyncSession(self.engine, expire_on_commit=False) as session:
            yield session
    
    @staticmethod
    def has_fix(content: str):
        """Vérifie si un contenu JSON contient des indicateurs de fix.

        Args:
            content (str): Le contenu JSON à analyser.

        Returns:
            bool: True si le contenu contient des indicateurs de fix.
        """
        return any(c in content for c in ('"all_fix_applied": true', '"have_proposed_fix": true'))
    
    # =========================================================================
    # CRUD de base
    # =========================================================================

    async def add_report(self, asset_id: str, source: str, content: str, report: dict) -> AnalysisReportDB:
        """Ajoute un rapport d'analyse.

        Args:
            asset_id (str): L'ID de l'asset concerné.
            source (str): La source du rapport.
            content (str): Le prompt d'entrée.
            report (dict): Le rapport JSON à stocker.

        Returns:
            AnalysisReportDB: Le rapport ajouté.
        """
        async with self.get_session() as session:
            dumps = json.dumps(report, default=str)
            entry = AnalysisReportDB(
                asset_id=asset_id,
                source=Source(source),
                severity=Severity(report["severity"]),
                content=compress(content),
                report_json=compress(dumps),
                has_fix=self.has_fix(dumps),
            )
            session.add(entry)
            await session.commit()
            await session.refresh(entry)
            return entry

    async def add_many(
        self, 
        asset_ids: list[str], 
        sources: list[str],
        contents: list[str],
        reports: list[dict]
    ) -> list[AnalysisReportDB]:
        """Ajoute plusieurs rapports par lots.

        Args:
            asset_ids (list[str]): IDs des assets concernés.
            sources (list[str]): Sources des rapports.
            contents (list[str]): Prompts d'entrée.
            reports (list[dict]): Rapports JSON à stocker.

        Returns:
            list[AnalysisReportDB]: Les rapports ajoutés.
        """
        if not reports:
            return []

        async with self.get_session() as session:
            entries = []
            for asset_id, source, content, report in zip(asset_ids, sources, contents, reports):
                dumps = json.dumps(report, default=str)
                entry = AnalysisReportDB(
                    asset_id=asset_id,
                    source=Source(source),
                    severity=Severity(report["severity"]),
                    report_json=compress(dumps),
                    content=compress(content),
                    has_fix=self.has_fix(dumps),
                )
                entries.append(entry)

            batch = 500
            for i in range(0, len(entries), batch):
                session.add_all(entries[i:i + batch])
            await session.commit()

            for entry in entries:
                await session.refresh(entry)

            return entries

    async def upsert_report(self, asset_id: str, source: str, content: str, report: dict) -> AnalysisReportDB:
        """Met à jour ou insère un rapport (merge).

        Args:
            asset_id (str): L'ID de l'asset concerné.
            source (str): La source du rapport.
            content (str): Le prompt d'entrée.
            report (dict): Le rapport JSON à stocker.

        Returns:
            AnalysisReportDB: Le rapport après upsert.
        """
        async with self.get_session() as session:
            dumps = json.dumps(report, default=str)
            entry = AnalysisReportDB(
                asset_id=asset_id,
                source=Source(source),
                severity=Severity(report["severity"]),
                report_json=compress(json.dumps(report, default=str)),
                content=compress(content),
                has_fix=self.has_fix(dumps),
            )
            merged = await session.merge(entry)
            await session.commit()
            await session.refresh(merged)
            return merged

    async def upsert_many(
        self, 
        asset_ids: list[str], 
        sources: list[str],
        contents: list[str],
        reports: list[dict]
    ) -> list[AnalysisReportDB]:
        """Met à jour ou insère plusieurs rapports (merge).

        Args:
            asset_ids (list[str]): IDs des assets concernés.
            sources (list[str]): Sources des rapports.
            contents (list[str]): Prompts d'entrée.
            reports (list[dict]): Rapports JSON à stocker.

        Returns:
            list[AnalysisReportDB]: Les rapports après upsert.
        """
        if not reports:
            return []

        results = []
        async with self.get_session() as session:
            for asset_id, source, content, report in zip(asset_ids, sources, contents, reports):
                dumps = json.dumps(report, default=str)
                entry = AnalysisReportDB(
                    asset_id=asset_id,
                    source=Source(source),
                    severity=Severity(report["severity"]),
                    report_json=compress(json.dumps(report, default=str)),
                    content=compress(content),
                    has_fix=self.has_fix(dumps),
                )
                merged = await session.merge(entry)
                results.append(merged)

            await session.commit()
            for result in results:
                await session.refresh(result)

            return results

    # =========================================================================
    # Lecture
    # =========================================================================
    
    @decompress_wrapper
    async def get_by_id(self, report_id: int) -> AnalysisReportDB | None:
        """Récupère un rapport par son ID.

        Args:
            report_id (int): L'ID du rapport.

        Returns:
            AnalysisReportDB | None: Le rapport trouvé ou None.
        """
        async with self.get_session() as session:
            return await session.get(AnalysisReportDB, report_id)
    
    @decompress_wrapper
    async def get_by_asset(self, asset_id: str, limit: int = 50) -> list[AnalysisReportDB]:
        """Récupère tous les rapports d'un asset.

        Args:
            asset_id (str): L'ID de l'asset.
            limit (int, optional): Nombre maximum de rapports. Par défaut 50.

        Returns:
            list[AnalysisReportDB]: La liste des rapports.
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(AnalysisReportDB.asset_id == asset_id)
                .order_by(AnalysisReportDB.created_at.desc())
                .limit(limit)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    @decompress_wrapper
    async def get_latest_by_asset(self, asset_id: str) -> AnalysisReportDB | None:
        """Récupère le dernier rapport d'un asset.

        Args:
            asset_id (str): L'ID de l'asset.

        Returns:
            AnalysisReportDB | None: Le dernier rapport ou None.
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(AnalysisReportDB.asset_id == asset_id)
                .order_by(AnalysisReportDB.created_at.desc())
                .limit(1)
            )
            result = await session.execute(statement)
            result = list(result.scalars().all())
            return result[0] if result else None
    
    @decompress_wrapper
    async def get_firstest_by_asset(self, asset_id: str) -> AnalysisReportDB | None:
        """Récupère le premier rapport d'un asset.

        Args:
            asset_id (str): L'ID de l'asset.

        Returns:
            AnalysisReportDB | None: Le premier rapport ou None.
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(AnalysisReportDB.asset_id == asset_id)
                .order_by(AnalysisReportDB.created_at.asc())
                .limit(1)
            )
            result = await session.execute(statement)
            result = list(result.scalars().all())
            return result[0] if result else None
    
    @decompress_wrapper
    async def get_by_identifier(
        self,
        identifier: str,
        first: bool = False,
        limit: int = 50
    ) -> AnalysisReportDB | None | list[AnalysisReportDB]:
        """
        Récupère un ou plusieurs rapports par identifiant.
        
        Args:
            identifier (str): ID ou asset_id.
            first (bool, optional): Si True, retourne le premier résultat uniquement.
                Par défaut False.
            limit (int, optional): Nombre max de résultats. Par défaut 50.

        Returns:
            AnalysisReportDB | None | list[AnalysisReportDB]: Le(s) rapport(s) trouvé(s).
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(
                    or_(
                        func.cast(AnalysisReportDB.id, String) == identifier,
                        AnalysisReportDB.asset_id == identifier
                    )
                )
                .order_by(AnalysisReportDB.created_at.desc())
                .limit(1 if first else limit)
            )
            result = await session.execute(statement)
            results = list(result.scalars().all())

            if first and results:
                return results[0]
            return results

    # =========================================================================
    # Filtrage avancé
    # =========================================================================
    
    @decompress_wrapper
    async def list_by_severity(self, severity: str, limit: int = 100) -> list[AnalysisReportDB]:
        """Liste les rapports par sévérité.

        Args:
            severity (str): La sévérité à filtrer.
            limit (int, optional): Nombre maximum de résultats. Par défaut 100.

        Returns:
            list[AnalysisReportDB]: La liste des rapports.
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(AnalysisReportDB.severity == Severity(severity))
                .order_by(AnalysisReportDB.created_at.desc())
                .limit(limit)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    @decompress_wrapper
    async def list_by_source(self, source: str, limit: int = 100) -> list[AnalysisReportDB]:
        """Liste les rapports par source.

        Args:
            source (str): La source à filtrer.
            limit (int, optional): Nombre maximum de résultats. Par défaut 100.

        Returns:
            list[AnalysisReportDB]: La liste des rapports.
        """
        async with self.get_session() as session:
            statement = (
                select(AnalysisReportDB)
                .where(AnalysisReportDB.source == Source(source))
                .order_by(AnalysisReportDB.created_at.desc())
                .limit(limit)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    async def list_critical(self, limit: int = 100) -> list[AnalysisReportDB]:
        """Liste les rapports critiques.

        Args:
            limit (int, optional): Nombre maximum de résultats. Par défaut 100.

        Returns:
            list[AnalysisReportDB]: La liste des rapports critiques.
        """
        return await self.list_by_severity("critical", limit)
    
    @decompress_wrapper
    async def list_by_date_range(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100
    ) -> list[AnalysisReportDB]:
        """Liste les rapports dans un intervalle de dates.

        Args:
            start (datetime | None, optional): Date de début.
            end (datetime | None, optional): Date de fin.
            limit (int, optional): Nombre maximum de résultats. Par défaut 100.

        Returns:
            list[AnalysisReportDB]: La liste des rapports.
        """
        async with self.get_session() as session:
            conditions = []
            if start:
                conditions.append(AnalysisReportDB.created_at >= start)
            if end:
                conditions.append(AnalysisReportDB.created_at <= end)

            statement = select(AnalysisReportDB)
            if conditions:
                statement = statement.where(and_(*conditions))
            statement = statement.order_by(AnalysisReportDB.created_at.desc()).limit(limit)

            result = await session.execute(statement)
            return list(result.scalars().all())
    
    @decompress_wrapper
    async def list_by_filter(
        self,
        asset_id: str | None = None,
        source: Source | None = None,
        severity: str | None = None,
        min_severity: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        order_by: str = "created_at.desc",
    ) -> list[AnalysisReportDB]:
        """Filtrage complet avec tous les critères.

        Args:
            asset_id (str | None, optional): Filtrer par asset.
            source (Source | None, optional): Filtrer par source.
            severity (str | None, optional): Filtrer par sévérité exacte.
            min_severity (str | None, optional): Sévérité minimale.
            start_date (datetime | None, optional): Date de début.
            end_date (datetime | None, optional): Date de fin.
            limit (int, optional): Nombre maximum de résultats. Par défaut 100.
            order_by (str, optional): Ordre de tri. Par défaut "created_at.desc".

        Returns:
            list[AnalysisReportDB]: La liste des rapports.
        """
        
        async with self.get_session() as session:
            conditions = []

            if asset_id:
                conditions.append(AnalysisReportDB.asset_id == asset_id)
            if source:
                conditions.append(AnalysisReportDB.source == Source(source))
            if severity:
                conditions.append(AnalysisReportDB.severity == Severity(severity))
            if min_severity:
                min_level = SEVERITY_ORDER.get(min_severity.lower(), 1)
                conditions.append(
                    or_(*[
                        AnalysisReportDB.severity == Severity(s)
                        for s, level in SEVERITY_ORDER.items()
                        if level >= min_level
                    ])
                )
            if start_date:
                conditions.append(AnalysisReportDB.created_at >= start_date)
            if end_date:
                conditions.append(AnalysisReportDB.created_at <= end_date)

            statement = select(AnalysisReportDB)
            if conditions:
                statement = statement.where(and_(*conditions))

            if order_by == "created_at.desc":
                statement = statement.order_by(AnalysisReportDB.created_at.desc())
            elif order_by == "created_at.asc":
                statement = statement.order_by(AnalysisReportDB.created_at.asc())
            else:
                statement = statement.order_by(AnalysisReportDB.created_at.desc())

            statement = statement.limit(limit)
            result = await session.execute(statement)
            return list(result.scalars().all())

    # =========================================================================
    # Statistiques
    # =========================================================================

    async def count_by_severity(self, asset_id: str | None = None) -> dict[str, int]:
        """Compte les rapports par sévérité.

        Args:
            asset_id (str | None, optional): Filtrer par asset.

        Returns:
            dict[str, int]: Dictionnaire sévérité -> nombre.
        """
        async with self.get_session() as session:
            conditions = []
            if asset_id:
                conditions.append(AnalysisReportDB.asset_id == asset_id)

            statement = select(
                AnalysisReportDB.severity,
                func.count(AnalysisReportDB.id)
            )
            if conditions:
                statement = statement.where(and_(*conditions))
            statement = statement.group_by(AnalysisReportDB.severity)

            result = await session.execute(statement)
            counts = {
                (row[0].value if hasattr(row[0], "value") else row[0]): row[1]
                for row in result.all()
            }
            return counts

    async def count_by_source(self, asset_id: str | None = None) -> dict[str, int]:
        """Compte les rapports par source.

        Args:
            asset_id (str | None, optional): Filtrer par asset.

        Returns:
            dict[str, int]: Dictionnaire source -> nombre.
        """
        async with self.get_session() as session:
            conditions = []
            if asset_id:
                conditions.append(AnalysisReportDB.asset_id == asset_id)

            statement = select(
                AnalysisReportDB.source,
                func.count(AnalysisReportDB.id)
            )
            if conditions:
                statement = statement.where(and_(*conditions))
            statement = statement.group_by(AnalysisReportDB.source)

            result = await session.execute(statement)
            counts = {
                (row[0].value if hasattr(row[0], "value") else row[0]): row[1]
                for row in result.all()
            }
            return counts

    async def summary_stats(self, asset_id: str | None = None) -> dict:
        """Retourne un résumé statistique des rapports.

        Args:
            asset_id (str | None, optional): Filtrer par asset.

        Returns:
            dict: Statistiques complètes (total, par sévérité, par source, dates, has_fix).
        """
        async with self.get_session() as session:
            conditions = []
            if asset_id:
                conditions.append(AnalysisReportDB.asset_id == asset_id)

            # Total
            statement = select(func.count(AnalysisReportDB.id))
            if conditions:
                statement = statement.where(and_(*conditions))
            total = (await session.execute(statement)).scalar() or 0

            # Par sévérité
            severity_counts = await self.count_by_severity(asset_id)

            # Par source
            source_counts = await self.count_by_source(asset_id)

            # Dates extrêmes
            statement = select(
                func.min(AnalysisReportDB.created_at),
                func.max(AnalysisReportDB.created_at)
            )
            result = await session.execute(statement)
            oldest, latest = result.first() or (None, None)

            # Avec fix (via recherche dans le JSON)
            fix_conditions = list(conditions) + [
                AnalysisReportDB.has_fix == True
            ]
            statement = select(func.count(AnalysisReportDB.id)).where(and_(*fix_conditions))
            has_fix = (await session.execute(statement)).scalar() or 0
    
            return {
                "total": total,
                "by_severity": severity_counts,
                "by_source": source_counts,
                "latest": latest,
                "oldest": oldest,
                "has_fix": has_fix,
            }

    # =========================================================================
    # Mise à jour
    # =========================================================================

    async def update_by_id(self, report_id: int, **kwargs) -> bool:
        """Met à jour un rapport par son ID.

        Args:
            report_id (int): L'ID du rapport.
            **kwargs: Attributs à modifier.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        async with self.get_session() as session:
            report = await session.get(AnalysisReportDB, report_id)
            if not report:
                return False
            
            annotations = typing.get_type_hints(report)
            for key, value in kwargs.items():
                if hasattr(report, key) and key in annotations:
                    if key in ("content", "report_json"):
                        value = compress(value)
                    
                    type_ = typing.get_origin(annotations[key]) or annotations[key]
                    if inspect.isclass(type_) and issubclass(type_, Enum):
                        try:
                            value = type_(value)
                        except (ValueError, TypeError):
                            continue
                        
                    if isinstance(
                        value,
                        annotations[key] or typing.get_origin(annotations[key])
                    ):
                        setattr(report, key, value)

            session.add(report)
            await session.commit()
            return True

    async def update_by_identifier(
        self,
        identifier: str,
        first: bool = False,
        attrs: dict = None
    ) -> bool:
        """
        Met à jour un ou plusieurs rapports par identifiant.
        
        Args:
            identifier (str): ID ou asset_id.
            first (bool, optional): Si True, met à jour uniquement le premier.
                Par défaut False.
            attrs (dict, optional): Dictionnaire des attributs à modifier.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        if not attrs:
            return False

        async with self.get_session() as session:
            statement = select(AnalysisReportDB).where(
                or_(
                    AnalysisReportDB.asset_id == identifier,
                    func.cast(AnalysisReportDB.id, String) == identifier
                )
            )
            result = await session.execute(statement)
            to_update = list(result.scalars().all())
            if first and to_update:
                to_update = to_update[0:1]

            if not to_update:
                return False

            for report in to_update:
                annotations = typing.get_type_hints(report)
                for key, value in attrs.items():
                    if hasattr(report, key):
                        if key in ("content", "report_json"):
                            value = compress(value)
                        
                        type_ = typing.get_origin(annotations[key]) or annotations[key]
                        if inspect.isclass(type_) and issubclass(type_, Enum):
                            try:
                                value = type_(value)
                            except (ValueError, TypeError):
                                continue
                            
                        if isinstance(
                            value,
                            annotations[key] or typing.get_origin(annotations[key])
                        ):
                            setattr(report, key, value)

            session.add_all(to_update)
            await session.commit()
            return True

    # =========================================================================
    # Suppression
    # =========================================================================

    async def delete_by_id(self, report_id: int) -> bool:
        """Supprime un rapport par son ID.

        Args:
            report_id (int): L'ID du rapport.

        Returns:
            bool: True si la suppression a réussi, False sinon.
        """
        async with self.get_session() as session:
            report = await session.get(AnalysisReportDB, report_id)
            if not report:
                return False
            await session.delete(report)
            await session.commit()
            return True

    async def delete_by_identifier(
        self,
        identifier: str,
        first: bool = False
    ) -> int:
        """
        Supprime un ou plusieurs rapports par identifiant.
        
        Args:
            identifier (str): ID ou asset_id.
            first (bool, optional): Si True, supprime uniquement le premier.
                Par défaut False.
            
        Returns:
            int: Nombre de rapports supprimés.
        """
        async with self.get_session() as session:
            statement = select(AnalysisReportDB).where(
                or_(
                    AnalysisReportDB.asset_id == identifier,
                    func.cast(AnalysisReportDB.id, String) == identifier
                )
            )
            result = await session.execute(statement)
            to_delete = list(result.scalars().all())
            if first and to_delete:
                to_delete = to_delete[0:1]
            
            if not to_delete:
                return 0

            for report in to_delete:
                await session.delete(report)

            await session.commit()
            return len(to_delete)


    async def delete_older_than(self, days: int) -> int:
        """Supprime les rapports plus vieux que N jours.

        Args:
            days (int): Nombre de jours.

        Returns:
            int: Nombre de rapports supprimés.
        """
        cutoff = utcnow() - timedelta(days=days)
        async with self.get_session() as session:
            statement = select(AnalysisReportDB).where(
                AnalysisReportDB.created_at < cutoff
            )
            result = await session.execute(statement)
            to_delete = list(result.scalars().all())

            for report in to_delete:
                await session.delete(report)

            await session.commit()
            return len(to_delete)

    # =========================================================================
    # Désérialisation
    # =========================================================================

    def report_to_dict(self, report: AnalysisReportDB | AnalysisReport) -> dict:
        """Convertit un report en dictionnaire.

        Args:
            report (AnalysisReportDB | AnalysisReport): Le rapport à convertir.

        Returns:
            dict: Le dictionnaire du rapport.
        """
        data = report.model_dump(mode="json")
        data["report"] = json.loads(data["report_json"]) if data["report_json"] else {}
        data["severity"] = report.severity.value if hasattr(report.severity, "value") else report.severity
        del data["report_json"]
        return data

    def reports_to_list(self, reports: list[AnalysisReportDB | AnalysisReport]) -> list[dict]:
        """Convertit une liste de reports en dictionnaires.

        Args:
            reports (list[AnalysisReportDB | AnalysisReport]): Liste des rapports.

        Returns:
            list[dict]: Liste des dictionnaires.
        """
        return [self.report_to_dict(r) for r in reports]


# =============================================================================
# TESTS
# =============================================================================

async def test_report_manager():
    """Test complet du ReportManager avec compression"""
    import tempfile

    print("=" * 60)
    print("🧪 TEST REPORT MANAGER")
    print("=" * 60)

    # Créer une base temporaire
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    # db_path = "/home/hounsousamuel/PROJET/obsidian_hive/api/shieldai.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    print(f"\n📁 Base de données: {db_path}")

    # Initialiser
    manager = ReportManager(db_url)
    await manager.init_db()
    print("✅ Base initialisée")

    # Créer des rapports de test avec content
    print("\n📥 Ajout de rapports...")
    test_reports = [
        {
            "asset_id": "asset-001",
            "source": "scanner_web",
            "content": "Scan du site web principal - SQL Injection détectée",
            "report": {
                "severity": "critical",
                "summary": "SQL Injection dans auth.py",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": True,
                "prompt_injection_detected": False,
            },
        },
        {
            "asset_id": "asset-001",
            "source": "scanner_web",
            "content": "Scan du site web principal - Hardcoded credentials",
            "report": {
                "severity": "high",
                "summary": "Hardcoded credentials dans config.py",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": True,
                "prompt_injection_detected": False,
            },
        },
        {
            "asset_id": "asset-001",
            "source": "ids_ips",
            "content": "IDS/IPS - Tentative de connexion suspecte",
            "report": {
                "severity": "medium",
                "summary": "Tentative de connexion suspecte",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": False,
                "prompt_injection_detected": False,
            },
        },
        {
            "asset_id": "asset-002",
            "source": "scanner_web",
            "content": "Scan du site web secondaire - XSS détecté",
            "report": {
                "severity": "critical",
                "summary": "XSS sur /login",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": True,
                "prompt_injection_detected": True,
            },
        },
        {
            "asset_id": "asset-002",
            "source": "sandbox",
            "content": "Sandbox - Analyse du comportement suspicieux",
            "report": {
                "severity": "low",
                "summary": "Comportement suspicieux analysé",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": False,
                "prompt_injection_detected": False,
            },
        },
        {
            "asset_id": "asset-003",
            "source": "scanner_web",
            "content": "Scan du site web staging - Aucune vulnérabilité",
            "report": {
                "severity": "low",
                "summary": "Scan terminé, aucune vulnérabilité",
                "technical_explanation": "Détails techniques...",
                "natural_explanation": "Explication simple...",
                "have_proposed_fix": False,
                "prompt_injection_detected": False,
            },
        },
    ]

    # Ajouter les rapports
    added = []
    for r in test_reports:
        result = await manager.add_report(
            asset_id=r["asset_id"],
            source=r["source"],
            content=r["content"],
            report=r["report"]
        )
        added.append(result)
        print(f"   ✅ {result.id} - {result.severity.value}")

    assert len(added) == len(test_reports)
    print(f"\n✅ {len(added)} rapports ajoutés")

    # Test get_by_id (décompression automatique via wrapper)
    print("\n🔍 Test get_by_id...")
    first_id = added[0].id
    report = await manager.get_by_id(first_id)
    print(report.model_dump(mode="json"))
    print()
    print(report.model_dump(mode="python"))
    print()
    print(report.severity)
    print()
    assert report is not None
    print(f"   ✅ Récupéré: {report.id} - {report.severity.value}")
    print(f"   📝 Content: {report.content[:50]}...")

    # Test get_by_identifier (par ID)
    print("\n🔍 Test get_by_identifier (par ID)...")
    report_by_id = await manager.get_by_identifier(str(first_id), first=False)
    if isinstance(report_by_id, list):
        report_by_id = report_by_id[0]
    assert report_by_id is not None
    print(f"   ✅ Récupéré par ID: {report_by_id.id}")

    # Test get_by_identifier (par asset_id)
    print("\n🔍 Test get_by_identifier (par asset_id)...")
    reports_by_asset = await manager.get_by_identifier("asset-001", first=False)
    assert len(reports_by_asset) == 3
    print(f"   ✅ Récupérés {len(reports_by_asset)} rapports pour asset-001")

    # Test get_by_identifier (par asset_id, first=True)
    print("\n🔍 Test get_by_identifier (par asset_id, first=True)...")
    first_by_asset = await manager.get_by_identifier("asset-001", first=True)
    assert first_by_asset is not None
    print(f"   ✅ Premier rapport pour asset-001: {first_by_asset.id}")

    # Test get_by_asset
    print("\n🔍 Test get_by_asset...")
    asset_reports = await manager.get_by_asset("asset-001", limit=10)
    print(f"   ✅ {len(asset_reports)} rapports pour asset-001")

    # Test get_latest_by_asset
    print("\n🔍 Test get_latest_by_asset...")
    latest = await manager.get_latest_by_asset("asset-001")
    assert latest is not None
    print(f"   ✅ Dernier rapport: {latest.id} ({latest.created_at})")

    # Test get_firstest_by_asset
    print("\n🔍 Test get_firstest_by_asset...")
    firstest = await manager.get_firstest_by_asset("asset-001")
    assert firstest is not None
    print(f"   ✅ Premier rapport: {firstest.id} ({firstest.created_at})")

    # Test list_by_severity
    print("\n🔍 Test list_by_severity...")
    critical = await manager.list_by_severity("critical")
    print(f"   ✅ {len(critical)} rapports critiques")
    for r in critical:
        print(f"      - {r.id} ({r.asset_id})")

    # Test list_by_source
    print("\n🔍 Test list_by_source...")
    scanner_reports = await manager.list_by_source("scanner_web")
    print(f"   ✅ {len(scanner_reports)} rapports du scanner")

    # Test list_by_filter
    print("\n🔍 Test list_by_filter...")
    filtered = await manager.list_by_filter(
        asset_id="asset-001",
        min_severity="high",
        limit=10
    )
    print(f"   ✅ {len(filtered)} rapports pour asset-001 avec severity >= high")
    for r in filtered:
        print(f"      - {r.id}: {r.severity.value}")

    # Test count_by_severity
    print("\n🔍 Test count_by_severity...")
    counts = await manager.count_by_severity("asset-001")
    print(f"   ✅ Asset-001: {counts}")

    # Test count_by_source
    print("\n🔍 Test count_by_source...")
    source_counts = await manager.count_by_source()
    print(f"   ✅ Sources: {source_counts}")

    # Test summary_stats
    print("\n🔍 Test summary_stats...")
    stats = await manager.summary_stats("asset-001")
    print(f"   ✅ Stats asset-001:")
    print(f"      - Total: {stats['total']}")
    print(f"      - Par sévérité: {stats['by_severity']}")
    print(f"      - Par source: {stats['by_source']}")
    print(f"      - Dernier rapport: {stats['latest']}")
    
    # Test summary_stats global
    print("\n🔍 Test summary_stats (global)...")
    global_stats = await manager.summary_stats()
    print(f"   ✅ Stats globales:")
    print(f"      - Total: {global_stats['total']}")
    print(f"      - Par sévérité: {global_stats['by_severity']}")
    print(f"      - Has fix (global): {global_stats['has_fix']}")
    assert global_stats['has_fix'] > 0

    # Test update_by_id
    print("\n🔍 Test update_by_id...")
    if added:
        updated = await manager.update_by_id(
            added[0].id,
            severity="critical"
        )
        assert updated is True
        print(f"   ✅ Rapport {added[0].id} mis à jour")

    # Test update_by_identifier (par ID)
    print("\n🔍 Test update_by_identifier (par ID)...")
    if added:
        updated = await manager.update_by_identifier(
            str(added[1].id),
            first=False,
            attrs={"severity": "critical"}
        )
        assert updated is True
        print(f"   ✅ Rapport {added[1].id} mis à jour via update_by_identifier")

    # Test update_by_identifier (par asset_id)
    print("\n🔍 Test update_by_identifier (par asset_id)...")
    updated = await manager.update_by_identifier(
        "asset-002",
        first=False,
        attrs={"severity": "high"}
    )
    assert updated is True
    print("   ✅ Tous les rapports de asset-002 mis à jour en high")

    # Test delete_by_id
    print("\n🔍 Test delete_by_id...")
    if added:
        deleted = await manager.delete_by_id(added[-1].id)
        assert deleted is True
        print(f"   ✅ Rapport {added[-1].id} supprimé")

    # Test delete_by_identifier (par asset_id)
    print("\n🔍 Test delete_by_identifier (par asset_id)...")
    deleted_count = await manager.delete_by_identifier(
        "asset-003",
        first=False
    )
    print(f"   ✅ {deleted_count} rapport(s) supprimé(s) pour asset-003")

    remaining = await manager.get_by_asset("asset-003")
    assert len(remaining) == 0
    print("   ✅ Vérification: plus de rapports pour asset-003")

    # Test delete_by_identifier (par ID, first=True)
    print("\n🔍 Test delete_by_identifier (par ID, first=True)...")
    to_delete = await manager.get_by_asset("asset-001")
    if to_delete:
        deleted = await manager.delete_by_identifier(
            str(to_delete[0].id),
            first=True
        )
        assert deleted == 1
        print(f"   ✅ Rapport {to_delete[0].id} supprimé")

    # Test delete_older_than
    print("\n🔍 Test delete_older_than...")
    old_report = await manager.add_report(
        asset_id="asset-001",
        source="test",
        content="Vieux rapport",
        report={"severity": "low", "summary": "Vieux rapport"}
    )
    async with manager.get_session() as session:
        old_report.created_at = utcnow() - timedelta(days=10)
        session.add(old_report)
        await session.commit()

    deleted_count = await manager.delete_older_than(days=7)
    print(f"   ✅ {deleted_count} rapport(s) ancien(s) supprimé(s)")
    print(await manager.get_latest_by_asset(2))
    # Nettoyer
    print("\n🧹 Nettoyage...")
    os.unlink(db_path)
    print(f"   ✅ Base supprimée: {db_path}")

    print("\n" + "=" * 60)
    print("✅ TOUS LES TESTS SONT PASSÉS !")
    print("=" * 60)

    return True


if __name__ == "__main__":
    import asyncio
    import warnings
    warnings.filterwarnings("ignore")
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.run(test_report_manager())