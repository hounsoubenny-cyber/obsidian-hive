#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module de quarantaine pour le Sandbox ShieldAI V2.

Permet de mettre en quarantaine les échantillons malveillants détectés,
de les stocker de manière sécurisée et de les analyser ultérieurement.
"""

import os
import sys
import json
import shutil
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

from sandbox_ia.sandbox_utils.logger import get_logger
logger = get_logger()


# =============================================================================
# DATACLASS - Élément en quarantaine
# =============================================================================

@dataclass
class QuarantineItem:
    """
    Représente un échantillon en quarantaine.
    """
    id: str
    original_filename: str
    language: str
    code: str
    source: str  # "email", "upload", "network", etc.
    report: dict | None  # Rapport sandbox associé
    quarantine_date: str
    expiry_date: str | None
    status: str  # "pending", "analysed", "released", "deleted"
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "original_filename": self.original_filename,
            "language": self.language,
            "code": self.code,
            "source": self.source,
            "report": self.report,
            "quarantine_date": self.quarantine_date,
            "expiry_date": self.expiry_date,
            "status": self.status,
            "tags": self.tags,
            "notes": self.notes,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "QuarantineItem":
        return cls(
            id=data["id"],
            original_filename=data["original_filename"],
            language=data["language"],
            code=data["code"],
            source=data.get("source", "unknown"),
            report=data.get("report"),
            quarantine_date=data["quarantine_date"],
            expiry_date=data.get("expiry_date"),
            status=data.get("status", "pending"),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
        )


# =============================================================================
# QUARANTINE MANAGER
# =============================================================================

class QuarantineManager:
    """
    Gestionnaire de quarantaine pour les échantillons malveillants.
    
    Fonctionnalités :
    - Mettre en quarantaine un échantillon suspect
    - Stocker le code + rapport sandbox
    - Lister, rechercher, supprimer
    - Expiration automatique (TTL)
    - Exporter/Importer
    """
    
    def __init__(self, quarantine_dir: str = "quarantine", ttl_days: int = 30):
        self.quarantine_dir = Path(quarantine_dir)
        self.samples_dir = self.quarantine_dir / "samples"
        self.reports_dir = self.quarantine_dir / "reports"
        self.index_file = self.quarantine_dir / "index.json"
        self.ttl_days = ttl_days
        
        # Création des dossiers
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self._index: dict[str, QuarantineItem] = {}
        self._load_index()
    
    def _load_index(self) -> None:
        """Charge l'index depuis le disque."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    data = json.load(f)
                    self._index = {
                        k: QuarantineItem.from_dict(v)
                        for k, v in data.items()
                    }
                logger.print(f"📋 Index chargé: {len(self._index)} échantillons en quarantaine")
            except Exception as e:
                logger.warning(f"Erreur chargement index: {e}")
                self._index = {}
        else:
            self._index = {}
    
    def _save_index(self) -> None:
        """Sauvegarde l'index sur le disque."""
        try:
            data = {
                k: v.to_dict()
                for k, v in self._index.items()
            }
            with open(self.index_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.print(f"💾 Index sauvegardé: {len(self._index)} échantillons")
        except Exception as e:
            logger.warning(f"Erreur sauvegarde index: {e}")
    
    def _generate_id(self, code: str) -> str:
        """Génère un ID unique pour un échantillon."""
        hash_obj = hashlib.sha256(code.encode())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"q_{timestamp}_{hash_obj.hexdigest()[:8]}"
    
    def add(
        self,
        code: str,
        filename: str,
        language: str,
        source: str = "unknown",
        report: dict | None = None,
        tags: list[str] | None = None,
        notes: str = "",
        ttl_days: int | None = None,
    ) -> QuarantineItem:
        """
        Ajoute un échantillon en quarantaine.
        
        Args:
            code: Code source à mettre en quarantaine.
            filename: Nom original du fichier.
            language: Langage du code.
            source: Source ("email", "upload", "network"...).
            report: Rapport sandbox associé.
            tags: Tags pour catégorisation.
            notes: Notes supplémentaires.
            ttl_days: Durée de vie en jours (None = TTL par défaut).
        
        Returns:
            QuarantineItem: L'élément créé.
        """
        item_id = self._generate_id(code)
        ttl = ttl_days or self.ttl_days
        expiry_date = (datetime.now() + timedelta(days=ttl)).isoformat()
        
        # Convertir rapport en dict si c'est un SandboxReport
        report_dict = None
        if report:
            if hasattr(report, 'to_dict'):
                report_dict = report.to_dict()
            elif isinstance(report, dict):
                report_dict = report
        
        item = QuarantineItem(
            id=item_id,
            original_filename=filename,
            language=language,
            code=code,
            source=source,
            report=report_dict,
            quarantine_date=datetime.now().isoformat(),
            expiry_date=expiry_date,
            status="pending",
            tags=tags or [],
            notes=notes,
        )
        
        # Sauvegarder le code
        sample_path = self.samples_dir / f"{item_id}.{language}"
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write(code)
        
        # Sauvegarder le rapport
        if report_dict:
            report_path = self.reports_dir / f"{item_id}_report.json"
            with open(report_path, "w") as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        # Ajouter à l'index
        self._index[item_id] = item
        self._save_index()
        
        logger.success(f"🔒 Échantillon mis en quarantaine: {item_id} ({filename})")
        return item
    
    def get(self, item_id: str) -> QuarantineItem | None:
        """Récupère un échantillon par son ID."""
        return self._index.get(item_id)
    
    def qlist(self, status: str | None = None, tag: str | None = None) -> list[QuarantineItem]:
        """
        Liste les échantillons en quarantaine.
        
        Args:
            status: Filtrer par status ("pending", "analysed"...).
            tag: Filtrer par tag.
        
        Returns:
            list[QuarantineItem]: Liste filtrée.
        """
        result = list(self._index.values())
        
        if status:
            result = [item for item in result if item.status == status]
        
        if tag:
            result = [item for item in result if tag in item.tags]
        
        return sorted(result, key=lambda x: x.quarantine_date, reverse=True)
    
    def update_status(self, item_id: str, status: str, notes: str = "") -> bool:
        """
        Met à jour le statut d'un échantillon.
        
        Args:
            item_id: ID de l'échantillon.
            status: Nouveau statut.
            notes: Notes supplémentaires.
        
        Returns:
            bool: True si mis à jour.
        """
        item = self._index.get(item_id)
        if not item:
            logger.warning(f"⚠️ Échantillon {item_id} non trouvé")
            return False
        
        item.status = status
        if notes:
            item.notes = f"{item.notes}\n{datetime.now().isoformat()}: {notes}"
        
        self._save_index()
        logger.print(f"📝 Statut mis à jour: {item_id} → {status}")
        return True
    
    def add_tag(self, item_id: str, tag: str) -> bool:
        """Ajoute un tag à un échantillon."""
        item = self._index.get(item_id)
        if not item:
            return False
        if tag not in item.tags:
            item.tags.append(tag)
            self._save_index()
        return True
    
    def remove_tag(self, item_id: str, tag: str) -> bool:
        """Supprime un tag d'un échantillon."""
        item = self._index.get(item_id)
        if not item:
            return False
        if tag in item.tags:
            item.tags.remove(tag)
            self._save_index()
        return True
    
    def delete(self, item_id: str, remove_files: bool = True) -> bool:
        """
        Supprime un échantillon de la quarantaine.
        
        Args:
            item_id: ID de l'échantillon.
            remove_files: Si True, supprime aussi les fichiers.
        
        Returns:
            bool: True si supprimé.
        """
        item = self._index.get(item_id)
        if not item:
            return False
        
        if remove_files:
            # Supprimer le code
            sample_path = self.samples_dir / f"{item_id}.{item.language}"
            if sample_path.exists():
                sample_path.unlink()
            
            # Supprimer le rapport
            report_path = self.reports_dir / f"{item_id}_report.json"
            if report_path.exists():
                report_path.unlink()
        
        del self._index[item_id]
        self._save_index()
        logger.print(f"🗑️ Échantillon supprimé: {item_id}")
        return True
    
    def clean_expired(self) -> int:
        """
        Supprime les échantillons expirés.
        
        Returns:
            int: Nombre d'échantillons supprimés.
        """
        now = datetime.now().isoformat()
        expired = [
            item_id for item_id, item in self._index.items()
            if item.expiry_date and item.expiry_date < now
        ]
        
        for item_id in expired:
            self.delete(item_id, remove_files=True)
        
        if expired:
            logger.print(f"🧹 {len(expired)} échantillons expirés nettoyés")
        return len(expired)
    
    def export(self, path: str, item_ids: list[str] | None = None) -> int:
        """
        Exporte des échantillons vers un fichier archive.
        
        Args:
            path: Chemin du fichier d'export.
            item_ids: Liste des IDs à exporter (None = tous).
        
        Returns:
            int: Nombre d'échantillons exportés.
        """
        items = []
        ids = item_ids or list(self._index.keys())
        
        for item_id in ids:
            item = self._index.get(item_id)
            if item:
                items.append(item.to_dict())
        
        if not items:
            logger.warning("Aucun échantillon à exporter")
            return 0
        
        export_data = {
            "export_date": datetime.now().isoformat(),
            "count": len(items),
            "items": items,
        }
        
        with open(path, "w") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.print(f"📦 Exporté {len(items)} échantillons vers {path}")
        return len(items)
    
    def import_from(self, path: str) -> int:
        """
        Importe des échantillons depuis un fichier archive.
        
        Args:
            path: Chemin du fichier d'import.
        
        Returns:
            int: Nombre d'échantillons importés.
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
            
            items_data = data.get("items", [])
            imported = 0
            
            for item_data in items_data:
                # Vérifier si l'ID existe déjà
                item_id = item_data.get("id")
                if item_id in self._index:
                    logger.warning(f"⚠️ ID {item_id} déjà existant, ignoré")
                    continue
                
                item = QuarantineItem.from_dict(item_data)
                
                # Sauvegarder le code
                sample_path = self.samples_dir / f"{item.id}.{item.language}"
                with open(sample_path, "w", encoding="utf-8") as f:
                    f.write(item.code)
                
                self._index[item.id] = item
                imported += 1
            
            self._save_index()
            logger.print(f"📥 Importé {imported} échantillons depuis {path}")
            return imported
            
        except Exception as e:
            logger.warning(f"Erreur import: {e}")
            return 0
    
    def stats(self) -> dict:
        """Retourne les statistiques de la quarantaine."""
        total = len(self._index)
        by_status = {}
        by_language = {}
        by_tag = {}
        now = datetime.now().isoformat()
        expired = 0
        
        for item in self._index.values():
            by_status[item.status] = by_status.get(item.status, 0) + 1
            by_language[item.language] = by_language.get(item.language, 0) + 1
            for tag in item.tags:
                by_tag[tag] = by_tag.get(tag, 0) + 1
            if item.expiry_date and item.expiry_date < now:
                expired += 1
        
        return {
            "total": total,
            "by_status": by_status,
            "by_language": by_language,
            "by_tag": by_tag,
            "expired": expired,
            "ttl_days": self.ttl_days,
            "quarantine_dir": str(self.quarantine_dir),
        }

