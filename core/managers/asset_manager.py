#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jun 24 04:42:37 2026

@author: hounsousamuel
"""
import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

import time
import asyncio
import inspect
from enum import Enum
import json5
from typing import Optional, get_type_hints, get_origin
from sqlmodel import SQLModel, select, func, Field, or_, and_, String
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from obsidian_hive.core.assets.asset_types import (
    AssetStatus, 
    Priority, 
    AssetType, 
    utcnow, 
    AssetItem,
    ASSET_CLASS_MAPPING,
    NetworkAsset
)
from modules_utils.loop_utils import _run_async


class AssetItemDB(SQLModel, table=True):
    """Modèle de base de données pour les assets.
    
    Correspond à la table `asset_item_db` et stocke tous les champs d'un asset
    de manière sérialisée, avec des champs spécifiques pour la persistance.
    """
    __tablename__ = "asset_item_db"
    __table_args__ = {"extend_existing": True}
    
    id: Optional[int] = Field(primary_key=True, default=None)
    item_id: str | None = Field(default=None)
    name: str | None = Field(default=None, description="Label ou nom de l'asset comme 'Site vitrine'")
    type: AssetType = Field(description="Type de l'asset")
    status: AssetStatus = Field(description="Status de l'asset", default=AssetStatus.ACTIVE)
    priority: Priority = Field(default=Priority.LOW, description="Priorité de l'assets")
    tags: str = Field(default="", description=" Tags. Ex: '['prod', 'critique']'")
    auto_fix: bool = Field(default=False, description="appliquer les fixes sans validation")
    created_at: datetime = Field(default_factory=utcnow, description="Date de création")
    updated_at: datetime = Field(default_factory=utcnow, description="Dernière date de mise à jour")
    timestamp: float = Field(default_factory=time.monotonic, description="Timestamp de création")
    metadata_: str = Field(default="", description="Données supplémentaires sur l'assets")
    every: float = Field(default=3600 * 10, description="Durée de répétition du workflow")
    already_exec_for_first_time: bool = Field(default=False)
    last_rest_exec_time: float | None = Field(default=None)
    every_task_id: str | None = Field(default=None)
    workflow_task_id: str | None = Field(default=None)
    special_fields: str = Field(default="")
    extra_fields: str = Field(default="")
    extra: str = Field(default="")
    run_fields: str = Field(default="")
    asset_item_cls: str = Field(description="Classe de l'item")
    install_token: str | None = Field(default=None, index=True, description="Token d'install ServerAsset, NULL pour les autres types et une fois consommé")
    install_token_expires_at: datetime | None = Field(default=None)
    

def _json_default(o):
    """Fonction de sérialisation JSON par défaut pour les types non pris en charge.
    
    Args:
        o: L'objet à sérialiser.

    Returns:
        str: La représentation sérialisée.

    Raises:
        TypeError: Si le type de l'objet n'est pas pris en charge.
    """
    if isinstance(o, datetime):
        return o.isoformat()
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


class AssetManager:
    """Gestionnaire des assets avec persistance en base de données.
    
    Fournit des opérations CRUD complètes pour les assets, avec conversion
    entre les modèles métier (AssetItem) et les modèles de base de données
    (AssetItemDB). Supporte la recherche avancée, le filtrage et les
    opérations par lots.
    
    Attributes:
        db_url (str): URL de connexion à la base de données.
        engine (AsyncEngine): Moteur SQLAlchemy asynchrone.
    """
    
    def __init__(self, db_url: str):
        """Initialise le gestionnaire d'assets.

        Args:
            db_url (str): URL de connexion à la base de données.
                Ex: "sqlite+aiosqlite:///assets.db"
        """
        self.db_url = db_url
        db_path = db_url.removeprefix("sqlite+aiosqlite:///")
        if db_path and db_path != ":memory:":
            dirname = os.path.dirname(db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
        _run_async(self.init_db)
    
    async def init_db(self):
        """Initialise la base de données et crée les tables si elles n'existent pas."""
        self.engine = create_async_engine(self.db_url)
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
    
    @staticmethod
    def normalize_asset_item(asset_item: AssetItem | dict | str):
        """Normalise un AssetItem pour la persistance.
        
        Convertit les champs spéciaux (tags, metadata_, etc.) en JSON
        et extrait les champs supplémentaires dans un dictionnaire séparé.

        Args:
            asset_item (AssetItem | dict | str): L'asset à normaliser.

        Returns:
            tuple: (AssetItem normalisé, extra_fields JSON)
        """
        if isinstance(asset_item, dict):
            asset_item_copy = AssetItem.model_validate(asset_item)
        elif isinstance(asset_item, str):
            asset_item_copy = AssetItem.model_validate_json(asset_item)
        elif isinstance(asset_item, AssetItem):
            asset_item_copy = asset_item.model_copy()
            
        special_fields = asset_item_copy.special_fields
        extra_fields = asset_item_copy.extra_fields
        extra = {}
        if extra_fields: # En premier pour eviter que si des champs sont dans les deux ils deviennent str
            for field in extra_fields:
                if hasattr(asset_item_copy, field):
                    extra[field] = getattr(asset_item_copy, field)
        
        extra = json5.dumps(extra, default=_json_default)
        if special_fields:
            for field in special_fields:
                if hasattr(asset_item_copy, field):
                    attr = getattr(asset_item_copy, field)
                    setattr(
                        asset_item_copy,
                        field,
                        json5.dumps(
                            attr,
                            default=_json_default
                        )
                    )
        return asset_item_copy, extra
    
    @staticmethod
    def normalize_asset_item_db(asset_item_db: AssetItemDB | dict | str):
        """Normalise un AssetItemDB depuis la base de données.
        
        Dé-sérialise les champs JSON (special_fields, extra) pour reconstituer
        un objet Python utilisable.

        Args:
            asset_item_db (AssetItemDB | dict | str): L'asset DB à normaliser.

        Returns:
            tuple: (AssetItemDB normalisé, extra_fields dict)
        """
        if isinstance(asset_item_db, dict):
            asset_item_db_copy = AssetItemDB.model_validate(asset_item_db)
        elif isinstance(asset_item_db, str):
            asset_item_db_copy = AssetItemDB.model_validate_json(asset_item_db)
        elif isinstance(asset_item_db, AssetItemDB):
            asset_item_db_copy = asset_item_db.model_copy()
            
        special_fields = asset_item_db_copy.special_fields
        if special_fields:
            special_fields = json5.loads(special_fields)
            if isinstance(special_fields, list):
                for field in special_fields:
                    if hasattr(asset_item_db_copy, field):
                        attr = getattr(asset_item_db_copy, field)
                        setattr(
                            asset_item_db_copy,
                            field,
                            json5.loads(
                                attr
                            ) 
                        )
        extra = asset_item_db_copy.extra
        if extra:
            extra = json5.loads(extra)
        return asset_item_db_copy, extra or {}
    
    
    @staticmethod
    def asset_item_to_asset_item_db(asset_item: AssetItem | dict | str):
        """Convertit un AssetItem en AssetItemDB pour la persistance.

        Args:
            asset_item (AssetItem | dict | str): L'asset métier à convertir.

        Returns:
            AssetItemDB: L'asset prêt pour la base de données.
        """
        asset_item, extra = AssetManager.normalize_asset_item(asset_item)
        cls_name = asset_item.__class__.__name__
        asset_item_dict = asset_item.model_dump()
        asset_item_dict["extra"] = extra
        # item_id -> id
        # id -> item_db_id
        asset_item_dict["item_id"] = asset_item_dict["id"]
        asset_item_dict["id"] = asset_item_dict["item_db_id"]
        asset_item_dict["asset_item_cls"] = cls_name
        asset_item_dict.pop("item_db_id")
        return AssetItemDB.model_validate(asset_item_dict)
    
    @staticmethod
    def asset_item_db_to_asset_item(asset_item_db: AssetItemDB | dict | str):
        """Convertit un AssetItemDB en AssetItem métier.

        Args:
            asset_item_db (AssetItemDB | dict | str): L'asset DB à convertir.

        Returns:
            AssetItem: L'asset métier reconstitué.

        Raises:
            ValueError: Si la classe de l'asset n'est pas enregistrée.
        """
        asset_item_db, extra = AssetManager.normalize_asset_item_db(asset_item_db)
        asset_item_db_dict = asset_item_db.model_dump()
        if extra and isinstance(extra, dict):
            for k, v in extra.items():
                asset_item_db_dict[k] = v
        if "extra" in asset_item_db_dict:
            asset_item_db_dict.pop("extra")
        # item_db_id -> id
        # id -> item_id
        asset_item_db_dict["item_db_id"] = asset_item_db_dict["id"]
        asset_item_db_dict["id"] = asset_item_db_dict["item_id"]
        asset_item_db_dict.pop("item_id")
        asset_item_db_dict.pop("asset_item_cls")
        asset_class = asset_item_db.asset_item_cls
        if not asset_class in ASSET_CLASS_MAPPING:
            raise ValueError(f"Asset class is not registed ({asset_class})")
        asset_class = ASSET_CLASS_MAPPING[asset_class]
        return asset_class.model_validate(asset_item_db_dict)
    
    @asynccontextmanager
    async def get_session(self):
        """Retourne un contexte de session de base de données.

        Yields:
            AsyncSession: Une session SQLAlchemy asynchrone.
        """
        async with AsyncSession(self.engine, expire_on_commit=False) as session:
            yield session
    
    async def add(self, asset: AssetItem | AssetItemDB) -> AssetItemDB:
        """Ajoute un asset en base de données.

        Args:
            asset (AssetItem | AssetItemDB): L'asset à ajouter.

        Returns:
            AssetItemDB: L'asset ajouté avec son ID généré.
        """
        async with self.get_session() as session:
            if isinstance(asset, AssetItem):
                asset_db = self.asset_item_to_asset_item_db(asset)
            session.add(asset_db)
            await session.commit()
            await session.refresh(asset_db)
            return asset_db
    
    async def add_many(self, asset_list: list[AssetItem | AssetItemDB]) -> list[AssetItemDB]:
        """Ajoute plusieurs assets en base de données par lots.

        Args:
            asset_list (list[AssetItem | AssetItemDB]): Liste des assets à ajouter.

        Returns:
            list[AssetItemDB]: Les assets ajoutés avec leurs IDs.
        """
        async with self.get_session() as session:
            assets = []
            for asset in asset_list:
                if isinstance(asset, AssetItem):
                    assets.append(self.asset_item_to_asset_item_db(asset))
                else:
                    assets.append(asset)
                    
            batch = 500
            taille = len(assets)
            for i in range(0, taille, batch):    
                session.add_all(assets[i : i + batch])
            await session.commit()
                
            for asset in assets:
                await session.refresh(asset)
                
            return assets
    
    async def upsert(self, asset: AssetItem) -> AssetItemDB:
        """Met à jour ou insère un asset (merge).

        Args:
            asset (AssetItem): L'asset à upsert.

        Returns:
            AssetItemDB: L'asset après upsert.
        """
        async with self.get_session() as session:
            asset_db = self.asset_item_to_asset_item_db(asset)
            merged = await session.merge(asset_db)
            await session.commit()
            await session.refresh(merged)
            return merged
    
    async def upsert_many(self, assets: list[AssetItem]) -> list[AssetItemDB]:
        """Met à jour ou insère plusieurs assets (merge).

        Args:
            assets (list[AssetItem]): Liste des assets à upsert.

        Returns:
            list[AssetItemDB]: Les assets après upsert.
        """
        async with self.get_session() as session:
            results = []
            for asset in assets:
                asset_db = self.asset_item_to_asset_item_db(asset)
                merged = await session.merge(asset_db)
                results.append(merged)
            await session.commit()
            return results
            
    async def get_by_id(self, asset_id: int) -> AssetItemDB | None:
        """Récupère un asset par son ID primaire (int).

        Args:
            asset_id (int): L'ID primaire de l'asset.

        Returns:
            AssetItemDB | None: L'asset trouvé ou None.
        """
        async with self.get_session() as session:
            return await session.get(AssetItemDB, asset_id)
    
    async def get_by_item_id(self, asset_item_id: str) -> AssetItemDB | None:
        """Récupère un asset par son item_id (UUID).

        Args:
            asset_item_id (str): L'item_id de l'asset.

        Returns:
            AssetItemDB | None: L'asset trouvé ou None.
        """
        async with self.get_session() as session:
            result = await session.execute(
                select(AssetItemDB)
                .where(AssetItemDB.item_id == asset_item_id)
            )
            return result.scalar_one_or_none()
    
    async def get_by_name(self, asset_name: str, first: bool = False) -> AssetItemDB | None | list[AssetItemDB]:
        """Récupère un ou plusieurs assets par leur nom exact.

        Args:
            asset_name (str): Le nom de l'asset.
            first (bool, optional): Si True, retourne uniquement le premier. Par défaut False.

        Returns:
            AssetItemDB | None | list[AssetItemDB]: L'asset ou la liste trouvée.
        """
        async with self.get_session() as session:
            result = await session.execute(
                select(AssetItemDB)
                .where(AssetItemDB.name == asset_name)
            )
            results = list(result.scalars().all())
            if first and results:
                results = results[0]
                
            return results

    async def get_asset_by_name(
        self,
        name: str,
        case_sensitive: bool = False,
        partial: bool = True,
        first: bool = True,
        limit: int = 500
    ) -> AssetItemDB | None | list[AssetItemDB]:
        """
        Recherche un ou plusieurs assets par leur nom avec options avancées.
    
        Args:
            name (str): Nom de l'asset à rechercher.
            case_sensitive (bool, optional): Si True, recherche exacte (respecte la casse).
                Si False, recherche insensible à la casse. Par défaut False.
            partial (bool, optional): Si True, recherche partielle (contient la chaîne).
                Si False, recherche exacte. Par défaut True.
            first (bool, optional): Si True, retourne uniquement le premier résultat.
                Par défaut True.
            limit (int, optional): Nombre maximum de résultats. Par défaut 500.
    
        Returns:
            AssetItemDB | None | list[AssetItemDB]: L'asset ou la liste trouvée.
    
        Example:
            >>> # Recherche exacte, insensible à la casse
            >>> asset = await manager.get_asset_by_name("site vitrine", case_sensitive=False)
            
            >>> # Recherche partielle, insensible à la casse
            >>> assets = await manager.get_asset_by_name("vitrine", case_sensitive=False, partial=True, first=False)
        """
        async with self.get_session() as session:
            if case_sensitive:
                if partial:
                    # LIKE exact avec casse
                    statement = select(AssetItemDB).where(
                        AssetItemDB.name.contains(name)
                    )
                else:
                    # Égalité exacte avec casse
                    statement = select(AssetItemDB).where(
                        AssetItemDB.name == name
                    )
            else:
                # Recherche insensible à la casse (lowercase)
                name_lower = name.lower()
                if partial:
                    statement = select(AssetItemDB).where(
                        func.lower(AssetItemDB.name).contains(name_lower)
                    )
                else:
                    statement = select(AssetItemDB).where(
                        func.lower(AssetItemDB.name) == name_lower
                    )
    
            result = await session.execute(statement)
            results = list(result.scalars().all())
    
            if first:
                return results[0] if results else None
    
            return results[:limit]
    
    async def get_by_identifier(
        self, 
        identifier: str,
        include_name: bool = False,
        first: bool = False
    ) -> AssetItemDB | None | list[AssetItemDB]:
        """Récupère un asset par son identifiant (ID, item_id ou nom).

        Args:
            identifier (str): L'identifiant à rechercher.
            include_name (bool, optional): Si True, inclut la recherche par nom.
                Par défaut False.
            first (bool, optional): Si True, retourne uniquement le premier.
                Par défaut False.

        Returns:
            AssetItemDB | None | list[AssetItemDB]: L'asset ou la liste trouvée.
        """
        async with self.get_session() as session:
            if include_name:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                            AssetItemDB.name == identifier,
                        )
                    )
                )
            else:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                        )
                    )
                )
            
            result = await session.execute(statement)
            results = list(result.scalars().all())
            if first and results:
                results = results[0]
            return results
    
    async def search_asset(
        self,
        query: str,
        include_name: bool = False,
        case_sensitive: bool = False,
        partial: bool = True,
        first: bool = False,
        limit: int = 500
    ) -> AssetItemDB | None | list[AssetItemDB]:
        """
        Recherche un ou plusieurs assets par identifiant et/ou nom.
        
        Args:
            query (str): Chaîne de recherche (identifiant ou nom).
            include_name (bool, optional): Si True, recherche aussi dans le nom.
                Si False, recherche uniquement par identifiant. Par défaut False.
            case_sensitive (bool, optional): Si True, recherche exacte (respecte la casse).
                Si False, recherche insensible à la casse. Par défaut False.
            partial (bool, optional): Si True, recherche partielle (contient la chaîne).
                Si False, recherche exacte. Par défaut True.
            first (bool, optional): Si True, retourne uniquement le premier résultat.
                Par défaut False.
            limit (int, optional): Nombre maximum de résultats. Par défaut 500.
        
        Returns:
            AssetItemDB | None | list[AssetItemDB]: L'asset ou la liste trouvée.
        
        Examples:
            >>> # Recherche par ID exact
            >>> asset = await manager.search_asset("sh_as-123", include_name=False, first=True)
            
            >>> # Recherche par nom partiel, insensible à la casse
            >>> assets = await manager.search_asset("vitrine", include_name=True, partial=True, first=False)
            
            >>> # Recherche par nom exact, insensible à la casse
            >>> asset = await manager.search_asset("site vitrine", include_name=True, partial=False, first=True)
        """
        async with self.get_session() as session:
            conditions = []
            query_lower = query.lower() if not case_sensitive else query
            
            if partial:
                if case_sensitive:
                    conditions.append(
                        func.cast(AssetItemDB.id, String).contains(query)
                    )
                    conditions.append(
                        func.cast(AssetItemDB.item_id, String).contains(query)
                    )
                else:
                    # Recherche partielle insensible à la casse
                    conditions.append(
                        func.lower(func.cast(AssetItemDB.id, String)).contains(query_lower)
                    )
                    conditions.append(
                        func.lower(func.cast(AssetItemDB.item_id, String)).contains(query_lower)
                    )
            else:
                if case_sensitive:
                    # Recherche exacte avec casse
                    conditions.append(
                        func.cast(AssetItemDB.id, String) == query
                    )
                    conditions.append(
                        func.cast(AssetItemDB.item_id, String) == query
                    )
                else:
                    # Recherche exacte insensible à la casse
                    conditions.append(
                        func.lower(func.cast(AssetItemDB.id, String)) == query_lower
                    )
                    conditions.append(
                        func.lower(func.cast(AssetItemDB.item_id, String)) == query_lower
                    )
            
            if include_name:
                if partial:
                    if case_sensitive:
                        conditions.append(
                            AssetItemDB.name.contains(query)
                        )
                    else:
                        conditions.append(
                            func.lower(AssetItemDB.name).contains(query_lower)
                        )
                else:
                    if case_sensitive:
                        conditions.append(
                            AssetItemDB.name == query
                        )
                    else:
                        conditions.append(
                            func.lower(AssetItemDB.name) == query_lower
                        )
            
            if not conditions:
                return [] if not first else None
            
            statement = select(AssetItemDB).where(or_(*conditions))
            
            if limit and not first:
                statement = statement.limit(limit)
            
            result = await session.execute(statement)
            results = list(result.scalars().all())
            if first:
                return results[0] if results else None
            
            return results
    
    async def list_by_status(self, status: AssetStatus) -> list[AssetItemDB]:
        """Liste les assets par statut.

        Args:
            status (AssetStatus): Le statut à filtrer.

        Returns:
            list[AssetItemDB]: La liste des assets correspondants.
        """
        async with self.get_session() as session:
            statement = select(AssetItemDB).where(
                AssetItemDB.status == AssetStatus(status)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def list_active(self) -> list[AssetItemDB]:
        """Liste tous les assets actifs.

        Returns:
            list[AssetItemDB]: La liste des assets actifs.
        """
        return await self.list_by_status(AssetStatus.ACTIVE)
    
    async def list_by_type(self, type_: AssetType) -> list[AssetItemDB]:
        """Liste les assets par type.

        Args:
            type_ (AssetType): Le type d'asset à filtrer.

        Returns:
            list[AssetItemDB]: La liste des assets correspondants.
        """
        async with self.get_session() as session:
            statement = select(AssetItemDB).where(
                AssetItemDB.type == AssetType(type_)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    async def list_by_priority(self, priority: Priority) -> list[AssetItemDB]:
        """Liste les assets par priorité.

        Args:
            priority (Priority): La priorité à filtrer.

        Returns:
            list[AssetItemDB]: La liste des assets correspondants.
        """
        async with self.get_session() as session:
            statement = select(AssetItemDB).where(
                AssetItemDB.priority == Priority(priority)
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    async def list_by_tags(self, tags: list) -> list[AssetItemDB]:
        """Liste les assets contenant un ou plusieurs tags.

        Args:
            tags (list): Liste des tags à rechercher.

        Returns:
            list[AssetItemDB]: La liste des assets correspondants.
        """
        if not tags:
            return []
        
        async with self.get_session() as session:
            statement = select(AssetItemDB).where(
                and_(
                    func.length(func.trim(AssetItemDB.tags)) > 0,
                    or_(
                        *[
                            AssetItemDB.tags.contains(tag)
                            for tag in tags
                        ]
                    )
                )
            )
            result = await session.execute(statement)
            return list(result.scalars().all())
    
    async def list_by_filter(
        self,
        status: AssetStatus | None = None,
        type_: AssetType | None = None,
        priority: Priority | None = None,
        tags: list | None = None
    ) -> list[AssetItemDB]:
        """Liste les assets avec filtrage combiné.

        Args:
            status (AssetStatus | None, optional): Filtrer par statut.
            type_ (AssetType | None, optional): Filtrer par type.
            priority (Priority | None, optional): Filtrer par priorité.
            tags (list | None, optional): Filtrer par tags.

        Returns:
            list[AssetItemDB]: La liste des assets correspondants.
        """
        alls = [
            status, type_, priority, tags
        ]
        async with self.get_session() as session:
            if not any(alls):
                statement = select(AssetItemDB)
            
            else:
                conditions = []
                if status:
                    conditions.append(AssetItemDB.status == AssetStatus(status))
                if type_:
                    conditions.append(AssetItemDB.type == AssetType(type_))
                if priority:
                    conditions.append(AssetItemDB.priority == Priority(priority))
                if tags:
                    conditions.append(
                        and_(
                            func.length(func.trim(AssetItemDB.tags)) > 0,
                            or_(*[AssetItemDB.tags.contains(tag) for tag in tags])
                        )
                    )
                
                if not conditions:
                    statement = select(AssetItemDB)
                    
                else:
                    statement = select(AssetItemDB).where(and_(*conditions))
                        
            return list((await session.execute(statement)).scalars().all())
                
    async def delete_by_identifier(
        self, 
        identifier: str,
        include_name: bool = False,
        first: bool = False
    ):
        """Supprime un ou plusieurs assets par identifiant.

        Args:
            identifier (str): L'identifiant à rechercher.
            include_name (bool, optional): Si True, inclut la recherche par nom.
                Par défaut False.
            first (bool, optional): Si True, supprime uniquement le premier.
                Par défaut False.
        """
        async with self.get_session() as session:
            if include_name:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                            AssetItemDB.name == identifier,
                        )
                    )
                )
            else:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                        )
                    )
                )
            
            result = await session.execute(statement)
            to_delete = list(result.scalars().all())
            if to_delete and first:
                to_delete = to_delete[0:1]
            
            for asset in to_delete:
                if asset:
                    await session.delete(asset)
            await session.commit()
        
        return
    
    async def update_by_identifier(
        self, 
        identifier: str,
        include_name: bool = False,
        first: bool = False,
        attrs: dict = None
    ):
        """Met à jour un ou plusieurs assets par identifiant.

        Args:
            identifier (str): L'identifiant à rechercher.
            include_name (bool, optional): Si True, inclut la recherche par nom.
                Par défaut False.
            first (bool, optional): Si True, met à jour uniquement le premier.
                Par défaut False.
            attrs (dict, optional): Dictionnaire des attributs à modifier.

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        if not attrs:
            return False
        
        async with self.get_session() as session:
            if include_name:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                            AssetItemDB.name == identifier,
                        )
                    )
                )
            else:
                statement = (
                    select(AssetItemDB)
                    .where(
                        or_(
                            func.cast(AssetItemDB.id, String) == identifier,
                            AssetItemDB.item_id == identifier,
                        )
                    )
                )
            
            result = await session.execute(statement)
            to_update = list(result.scalars().all())
            if to_update and first:
                to_update = to_update[0:1]
                
            updated = []
            for asset in to_update:
                if asset:
                    asset_: AssetItem = self.asset_item_db_to_asset_item(asset)
                    annotations = get_type_hints(ASSET_CLASS_MAPPING[asset.asset_item_cls])
                    for name, value in attrs.items():
                        type_ = get_origin(annotations[name]) or annotations[name]
                        if inspect.isclass(type_) and issubclass(type_, Enum):
                            try:
                                value = type_(value)
                            except (ValueError, TypeError):
                                continue
                        if hasattr(asset_, name) and name in annotations:
                            if isinstance(
                                value,
                                get_origin(annotations[name]) or annotations[name]
                            ):
                                setattr(asset_, name, value)
                    asset_.updated_at = utcnow()
                    asset_: AssetItemDB = self.asset_item_to_asset_item_db(asset_)
                    for k in AssetItemDB.__annotations__.keys():
                        setattr(
                            asset,
                            k,
                            getattr(asset_, k)
                        )
                    updated.append(asset)
            
            if updated:    
                session.add_all(updated)
                await session.commit()
                return len(updated) == len(to_update)
            
            else:
                return False
        
        return False
    
    async def check_interface_conflict(self, interfaces: list[str]) -> dict:
        """Vérifie si des interfaces réseau sont déjà surveillées par un asset actif.

        Args:
            interfaces (list[str]): Liste des interfaces à vérifier.

        Returns:
            dict: Dictionnaire avec 'overlap' (bool) et 'message' (str | None).
        """
        result = {"overlap": False, "message": None}
        try:
            active = await self.list_by_filter(status=AssetStatus.ACTIVE, type_=AssetType.NETWORK)
            for a_db in active:
                asset = self.asset_item_db_to_asset_item(a_db)
                existing = asset.interfaces() if hasattr(asset, "interfaces") else []
                if not existing or not interfaces:
                    result["message"] = f"Conflit : {asset.id} couvre déjà toutes les interfaces"
                    result["overlap"] = True
                    return result
                overlap = set(existing) & set(interfaces)
                if overlap:
                    result["message"] = f"Interface(s) déjà surveillée(s) par {asset.id} : {', '.join(overlap)}"
                    result["overlap"] = True
                    return result
        except Exception as e:
            print(f"Erreur dans check_interface_conflict: {e!r}")
            return {"overlap": True, "message": f"Vérification d'unicité impossible ({e}), création refusée par sécurité"}
     
        return result
    
    async def check_port_is_available_for_network_asset(self, asset: NetworkAsset) -> bool:
        """Vérifie qu'aucun autre NetworkAsset actif n'utilise déjà le même host:port.
    
        Compare le host/port de l'API IDS de `asset` (lu dans son config_path)
        à ceux de tous les NetworkAsset actifs déjà enregistrés, puis tente une
        connexion socket sur ce host:port pour vérifier qu'il est réellement libre.
    
        Args:
            asset (NetworkAsset): L'asset réseau dont on veut valider le port.
    
        Returns:
            bool: True si le port est disponible (aucun conflit, port libre),
                False en cas de conflit avec un asset existant, si le port est
                déjà occupé, ou si une erreur survient pendant la vérification.
        """
        try:
            import socket
            from ids_ips_ia.config.config_manager import Config as IdsConfig, GLOBAL_CONFIG_KEY
            
            active = await self.list_by_filter(status=AssetStatus.ACTIVE, type_=AssetType.NETWORK)
            base_conf = IdsConfig(asset.config_path)
            api_config = base_conf.CONFIG.get(GLOBAL_CONFIG_KEY, {})["API_CONFIG"]
            base_host = api_config["host"]
            base_port = api_config["port"]
            for a_db in active:
                existing_asset: NetworkAsset = self.asset_item_db_to_asset_item(a_db)
                conf = IdsConfig(existing_asset.config_path)
                api_config = conf.CONFIG.get(GLOBAL_CONFIG_KEY, {})["API_CONFIG"]
                host = api_config["host"]
                port = api_config["port"]
                if host == base_host and port == base_port:
                    return False
            s = socket.socket()
            r = s.connect_ex((base_host, base_port))
            s.close()
            return r != 0
        except Exception:
            return False
    
    async def get_all_url_of_network_asset(self) -> dict[str, dict[str, str | bool]]:
        """Liste les URLs d'API de tous les NetworkAsset actifs.
    
        Pour chaque NetworkAsset actif, lit le host/port de son API IDS depuis
        son fichier de config, et teste si le port est actuellement ouvert
        (IDS démarré ou non). Sert de source de vérité au frontend pour se
        connecter directement à l'API de chaque IDS (modèle gateway par asset).
    
        Returns:
            dict[str, dict[str, str | bool]]: Dictionnaire indexé par asset.id,
                chaque valeur contenant "host", "port" et "is_open" (bool
                indiquant si une connexion a pu être établie sur ce port).
                Dictionnaire vide en cas d'erreur.
        """
        try:
            import socket
            from ids_ips_ia.config.config_manager import Config as IdsConfig, GLOBAL_CONFIG_KEY
            
            urls = {}
            active = await self.list_by_filter(status=AssetStatus.ACTIVE, type_=AssetType.NETWORK)
            s = socket.socket()
            
            for a_db in active:
                asset: NetworkAsset = self.asset_item_db_to_asset_item(a_db)
                conf = IdsConfig(asset.config_path)
                api_config = conf.get(GLOBAL_CONFIG_KEY, {})["API_CONFIG"]
                host = api_config["host"]
                port = api_config["port"]
                s = socket.socket()
                is_open = s.connect_ex((host, port)) == 0
                s.close()
                urls[asset.id] = {
                    "host": host,
                    "port": port,
                    "is_open": is_open,
                }
            return urls
            
        except Exception as e:
            print(f"Erreur, {e!r}")
            return {}
        
        
    async def get_server_asset_by_install_token(self, token: str | None) -> AssetItemDB | None | list[AssetItemDB]:
        """Récupère un ou plusieurs assets serveur par token d'installation.

        Args:
            token (str | None): Le token d'installation. Si None, retourne tous les serveurs.

        Returns:
            AssetItemDB | None | list[AssetItemDB]: L'asset ou la liste trouvée.
        """
        async with self.get_session() as session:
            statement = (
                select(AssetItemDB)
                .where(
                    AssetItemDB.type == AssetType.SERVER
                )
            )
            if token:
                statement = statement.where(AssetItemDB.install_token == token)
            result = await session.execute(statement)
            results = list(result.scalars().all())
            if not results:
                return None
            
            if token is None:
                return results
            
            return results[0]
        

async def test_asset_manager():
    """Test complet du AssetManager"""
    
    print("=" * 60)
    print("🧪 TEST ASSET MANAGER")
    print("=" * 60)
    
    # 1. Créer une base de données temporaire
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    
    # db_path = "/home/hounsousamuel/PROJET/obsidian_hive/api/shieldai.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    print(f"\n📁 Base de données: {db_path}")
    
    # 2. Initialiser le manager
    manager = AssetManager(db_url)
    await manager.init_db()
    print("✅ Base initialisée")
    
    # 3. Créer des assets de test
    # ATTENTION : Utilise les valeurs EXISTANTES dans tes enums !
    assets = [
        AssetItem(
            name="Site Vitrine",
            type=AssetType.WEB_SITE,      
            status=AssetStatus.ACTIVE,     
            priority=Priority.HIGH,
            tags=["prod", "critique"],     # ✅ tags est une list[str], pas un str
            auto_fix=True,
            every=3600 * 24,
            metadata_={"owner": "benny", "team": "security"},
        ),
        AssetItem(
            name="API Backend",
            type=AssetType.WEB_APP,        
            status=AssetStatus.ACTIVE,
            priority=Priority.CRITICAL,
            tags=["prod", "api"],
            auto_fix=False,
            every=3600 * 12,
            metadata_={"owner": "devops", "team": "backend"}
        ),
        AssetItem(
            name="Site Staging",
            type=AssetType.WEB_SITE,       
            status=AssetStatus.INACTIVE,   
            priority=Priority.LOW,
            tags=["staging", "test"],
            auto_fix=False,
            every=3600 * 48,
            metadata_={"owner": "qa", "team": "quality"}
        ),
        AssetItem(
            name="Serveur Principal",
            type=AssetType.SERVER,         
            status=AssetStatus.ACTIVE,
            priority=Priority.MEDIUM,
            tags=["prod", "server", "critique"],
            auto_fix=True,
            every=3600 * 6,
            metadata_={"owner": "dba", "team": "data"}
        ),
        AssetItem(
            name="Site Blog",
            type=AssetType.WEB_SITE,       
            status=AssetStatus.SUPPRESSED,
            priority=Priority.LOW,
            tags=["blog", "old"],
            auto_fix=False,
            every=3600 * 72,
            metadata_={"owner": "content", "team": "marketing"}
        ),
        # ✅ Ajout d'un asset de type EMAIL et CODE pour tester
        AssetItem(
            name="Email Corporate",
            type=AssetType.ANTI_PHISHING_EMAIL,
            status=AssetStatus.ACTIVE,
            priority=Priority.MEDIUM,
            tags=["prod", "email"],
            auto_fix=False,
            every=3600 * 24,
            metadata_={"owner": "it", "team": "infra"}
        ),
        AssetItem(
            name="Code Source",
            type=AssetType.CODE,
            status=AssetStatus.ACTIVE,
            priority=Priority.HIGH,
            tags=["prod", "code", "critique"],
            auto_fix=True,
            every=3600 * 12,
            metadata_={"owner": "dev", "team": "backend"}
        ),
    ]
    
    # 4. Ajouter les assets
    print("\n📥 Ajout des assets...")
    added = []
    added = await manager.add_many(assets)
    # for asset in assets:
    #     try:
    #         result = await manager.add(asset)
    #         added.append(result)
    #         print(f"   ✅ {result.name} (id: {result.id}, item_id: {result.item_id})")
    #     except Exception as e:
    #         print(f"   ❌ Erreur pour {asset.name}: {e}")
    
    assert len(added) == len(assets), "Tous les assets n'ont pas été ajoutés"
    print(f"\n✅ {len(added)} assets ajoutés avec succès")
    
    # 5. Tester get_by_id
    print("\n🔍 Test get_by_id...")
    first_id = added[0].id
    asset = await manager.get_by_id(first_id)
    assert asset is not None, f"Asset avec id {first_id} non trouvé"
    print(f"   ✅ Récupéré: {asset.name} (id: {asset.id})")
    # Convertir en AssetItem
    asset_item = AssetManager.asset_item_db_to_asset_item(asset)
    
    # Utiliser l'AssetItem
    print("Test conversion")
    print(f"📦 {asset_item.name}")
    print(f"   Type: {asset_item.type.value}")
    print(f"   Status: {asset_item.status.value}")
    print(f"   Priority: {asset_item.priority.name}")
    print(f"   Tags: {', '.join(asset_item.tags)}")
    print(f"   Auto-fix: {asset_item.auto_fix}")
    print(f"   Metadata: {asset_item.metadata_}")
    print("Egalité après conversion:", AssetManager.asset_item_to_asset_item_db(asset_item) == asset)
        
    # 6. Tester get_by_item_id
    print("\n🔍 Test get_by_item_id...")
    first_item_id = added[0].item_id
    asset = await manager.get_by_item_id(first_item_id)
    assert asset is not None, f"Asset avec item_id {first_item_id} non trouvé"
    print(f"   ✅ Récupéré: {asset.name} (item_id: {asset.item_id})")
    
    # 7. Tester get_by_name
    print("\n🔍 Test get_by_name...")
    assets_by_name = await manager.get_by_name("Site Vitrine", first=False)
    assert len(assets_by_name) >= 1, "Asset non trouvé par nom"
    print(f"   ✅ {len(assets_by_name)} asset(s) trouvé(s) pour 'Site Vitrine'")
    
    # 8. Tester get_by_identifier
    print("\n🔍 Test get_by_identifier...")
    # Par ID
    asset_by_id = await manager.get_by_identifier((first_id), first=True)
    assert asset_by_id is not None, "Asset non trouvé par ID"
    print(f"   ✅ Par ID: {asset_by_id.name}")
    
    # Par item_id
    asset_by_item = await manager.get_by_identifier(first_item_id, first=True)
    assert asset_by_item is not None, "Asset non trouvé par item_id"
    print(f"   ✅ Par item_id: {asset_by_item.name}")
    
    # Par nom
    asset_by_name = await manager.get_by_identifier("Site Vitrine", include_name=True, first=True)
    assert asset_by_name is not None, "Asset non trouvé par nom"
    print(f"   ✅ Par nom: {asset_by_name.name}")
    
    # 9. Tester list_by_status
    print("\n🔍 Test list_by_status...")
    active_assets = await manager.list_by_status(AssetStatus.ACTIVE)
    print(f"   ✅ {len(active_assets)} asset(s) actif(s)")
    for a in active_assets:
        print(f"      - {a.name} ({a.status.value})")
    
    # 10. Tester list_active
    print("\n🔍 Test list_active...")
    active = await manager.list_active()
    assert len(active) == len(active_assets), "list_active ne correspond pas à list_by_status(ACTIVE)"
    print(f"   ✅ {len(active)} asset(s) actif(s)")
    
    # 11. Tester list_by_type
    print("\n🔍 Test list_by_type...")
    websites = await manager.list_by_type(AssetType.WEB_SITE)
    print(f"   ✅ {len(websites)} site(s) web trouvé(s)")
    for w in websites:
        print(f"      - {w.name} ({w.type.value})")
    
    # 12. Tester list_by_priority
    print("\n🔍 Test list_by_priority...")
    critical = await manager.list_by_priority(Priority.CRITICAL)
    print(f"   ✅ {len(critical)} asset(s) critique(s)")
    for c in critical:
        print(f"      - {c.name} ({c.priority.value})")
    
    # 13. Tester list_by_tags (tags est une liste dans AssetItem, mais stocké en str dans DB)
    print("\n🔍 Test list_by_tags...")
    tags = ["prod", "api"]
    by_tags = await manager.list_by_tags(tags)
    print(f"   ✅ {len(by_tags)} asset(s) avec les tags {tags}")
    for a in by_tags:
        print(f"      - {a.name} (tags: {a.tags})")
    
    # 14. Tester list_by_filter
    print("\n🔍 Test list_by_filter...")
    filtered = await manager.list_by_filter(
        status=AssetStatus.ACTIVE,
        type_=AssetType.WEB_SITE,
        priority=Priority.HIGH
    )
    print(f"   ✅ {len(filtered)} asset(s) filtré(s) (ACTIVE + WEB_SITE + HIGH)")
    for a in filtered:
        print(f"      - {a.name} ({a.status.value}, {a.type.value}, {a.priority.value})")
    
    # 15. Tester update_by_identifier
    print("\n🔍 Test update_by_identifier...")
    updated = await manager.update_by_identifier(
        "Site Vitrine",
        include_name=True,
        first=True,
        attrs={
            "status": AssetStatus.INACTIVE,
            "priority": Priority.CRITICAL,
            "auto_fix": False
        }
    )
    assert updated is True, "La mise à jour a échoué"
    print(f"   ✅ Mise à jour réussie")
    
    # Vérifier la mise à jour
    updated_asset = await manager.get_by_identifier(
        "Site Vitrine",
        include_name=True,
        first=True
    )
    if updated_asset:
        print(f"      - Nouveau statut: {updated_asset.status.value}")
        print(f"      - Nouvelle priorité: {updated_asset.priority.value}")
        print(f"      - auto_fix: {updated_asset.auto_fix}")
    
    # 16. Tester update_by_identifier avec plusieurs assets
    print("\n🔍 Test update_by_identifier (multiple)...")
    updated_multiple = await manager.update_by_identifier(
        "WEB_SITE",  # Recherche par valeur, pas par nom
        include_name=False,
        first=False,
        attrs={
            "every": 3600 * 2
        }
    )
    print(f"   ✅ Mise à jour de plusieurs assets: {updated_multiple}")
    
    # 17. Tester delete_by_identifier
    print("\n🔍 Test delete_by_identifier...")
    deleted = await manager.delete_by_identifier(
        "Site Staging",
        include_name=True,
        first=True
    )
    print(f"   ✅ Asset 'Site Staging' supprimé")
    
    # Vérifier la suppression
    deleted_asset = await manager.get_by_identifier(
        "Site Staging",
        include_name=True,
        first=True
    )
    assert not deleted_asset, "L'asset n'a pas été supprimé"
    print(f"   ✅ Vérification: 'Site Staging' n'existe plus")
    
    # 18. Tester delete_by_identifier (multiple)
    print("\n🔍 Test delete_by_identifier (multiple)...")
    # Récupérer les assets à supprimer (SUPPRESSED au lieu de ARCHIVED)
    to_delete = await manager.list_by_status(AssetStatus.SUPPRESSED)
    if to_delete:
        for a in to_delete:
            await manager.delete_by_identifier(
                a.item_id,
                include_name=False,
                first=True
            )
        print(f"   ✅ {len(to_delete)} asset(s) supprimé(s) (status SUPPRESSED)")
    
    # 19. Vérifier l'état final
    print("\n📊 État final de la base:")
    remaining = await manager.list_by_filter(
        status=AssetStatus.ACTIVE,
        type_=AssetType.WEB_SITE
    )
    print(f"   ✅ {len(remaining)} site(s) web actif(s) restant(s)")
    for a in remaining:
        print(f"      - {a.name} ({a.status.value}, {a.priority.value})")
    
    # 20. Nettoyer
    print("\n🧹 Nettoyage...")
    os.unlink(db_path)
    print(f"   ✅ Base supprimée: {db_path}")
    
    print("\n" + "=" * 60)
    print("✅ TOUS LES TESTS SONT PASSÉS !")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    ai = AssetItem(type="web_site", item_db_id="12345")
    ain, extra = AssetManager.normalize_asset_item(ai)
    aidb = AssetManager.asset_item_to_asset_item_db(ai)
    aidbn, extra_aidb = AssetManager.normalize_asset_item_db(aidb)
    aidbt = AssetManager.asset_item_db_to_asset_item(aidb)
    import nest_asyncio, asyncio
    nest_asyncio.apply()
    asyncio.run(test_asset_manager())