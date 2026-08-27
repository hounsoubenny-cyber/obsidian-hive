#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul  4 15:49:33 2026

@author: hounsousamuel
"""

import os, sys
# sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..")))

from datetime import datetime
from typing import List, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from obsidian_hive.core.assets.asset_types import (
    WebAsset, AssetStatus, AssetType, Priority, NetworkAsset,
    Source, FixId, PromptMapping, Severity, ServerAsset, AgentStatus,
    AgentCapabilities
)
from scanner_ia.api.api import (
    ScanArgs, ScanInstanceArgs, DEFAULT_SCAN_PATH
)
from ids_ips_ia.config.config_manager import _config_path as DEFAULT_IDS_CONFIG_PATH

class LoginData(BaseModel):
    username: str = Field(description="Username de login")
    password: str = Field(description="Mot de passe de login")

class RefreshTokenData(BaseModel):
    token: str
    username: str
    
class WebAssetModel(WebAsset):
    # write_config_path: str = Field(description="Chemin d'écriture de la config", exclude=True)
    scan_args: ScanArgs = Field(description="Params de scan (run_args)", exclude=True)
    scan_instance_args: ScanInstanceArgs = Field(description="Params d'instanciation (init_config)", exclude=True)
    run_config: None | str | Dict = Field(default=None, exclude=True)
    init_config: None | str | Dict = Field(default=None, exclude=True)
    url: None | str = Field(default=None, exclude=True)
    manage_immediatly: bool = Field(default=False, exclude=True)
    conf_content: str | None = Field(default=None, exclude=True)
    
    # @field_validator("write_config_path")
    # @classmethod
    # def validate_write_config_path(cls, v: str):
    #     if v == DEFAULT_SCAN_PATH:
    #         raise ValueError("This file can't be used for write config")
    #     return v
    
    @model_validator(mode="after")
    def validate_model(self) -> "WebAssetModel":
        print("Hi, model validator annulé")
        return self

class NetworkAssetModel(NetworkAsset):
    # write_config_path: str = Field(description="Chemin d'écriture de la config", exclude=True)
    conf_content: str = Field(description="Configuration JSON de l'ids/ips", exclude=True)
    manage_immediatly: bool = Field(default=False, exclude=True)
    
    # @field_validator("write_config_path")
    # @classmethod
    # def validate_write_config_path(cls, v: str):
    #     if v == DEFAULT_IDS_CONFIG_PATH:
    #         raise ValueError("This file can't be used for write config")
    #     return v
    
    @model_validator(mode="after")
    def validate_model(self) -> "NetworkAssetModel":
        return self
    
class ListAssetData(BaseModel):
    status: AssetStatus | None = Field(default=None, description="Status de l'asset")
    type_: AssetType | None = Field(default=None, description="Type de l'asset")
    priority: Priority | None = Field(default=None, description="Priorité de l'asset")
    tags: List | None = Field(default=None, description="Tags de l'asset")

class GetAssetData(BaseModel):
    identifier: str = Field(description="Identifiant de l'asset (id, item_id, name)")
    include_name: bool = Field(
        default=False, 
        description="Definit si il faut considérer le identifier comme potentiel nom"
        )
    first: bool = Field(
        default=False,
        description="Definit s'il faut retourner le premier match ou tout"
    )

class SearchAssetData(BaseModel):
    query: str = Field(
        description="Chaîne de recherche (identifiant ou nom)",
        min_length=1,
        max_length=255
    )
    include_name: bool = Field(
        default=False,
        description="Si True, recherche aussi par nom. Sinon, uniquement par identifiant"
    )
    case_sensitive: bool = Field(
        default=False,
        description="Si True, recherche exacte (respecte la casse). Si False, insensible à la casse"
    )
    partial: bool = Field(
        default=True,
        description="Si True, recherche partielle (contient la chaîne). Si False, recherche exacte"
    )
    first: bool = Field(
        default=False,
        description="Si True, retourne uniquement le premier résultat"
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Nombre maximum de résultats (ignoré si first=True)"
    )
    
class ManageAssetData(BaseModel):
    asset_id: str = Field(description="Identifiant de l'asset (id, item_id, name)")
    
class RemoveAssetData(ManageAssetData):
    pass

class ResumeAssetData(ManageAssetData):
    pass

class PauseAssetData(ManageAssetData):
    pass

class PauseAssetsData(BaseModel):
    asset_type: AssetType | None = None
    asset_ids: list[str] | None = None
    priority: Priority | None = None
    tags: list[str] | None = None

class ResumeAssetsData(BaseModel):
    asset_type: AssetType | None = None
    asset_ids: list[str] | None = None
    priority: Priority | None = None
    tags: list[str] | None = None
    
class UpdateAssetData(ManageAssetData):
    attrs: Dict = Field(default_factory=dict, description="Le dictionnaire clé valeur des attributs à mettre à jour")
    restart_workflow: bool = Field(default=False, description="Définit s'il faut redémarer le workflow")

class SyncSourceCodeData(ManageAssetData):
    admin_source_code_dir: str = Field(
        description="Dossier source fourni par l'admin, à copier dans le sandbox"
    )
    
    @field_validator("admin_source_code_dir")
    @classmethod
    def validate_cource_code_dir(cls, path: str):
        if not os.path.exists(path):
            raise ValueError(f"Dossier introuvable : {path}")
        
        if not os.path.isdir(path):
            raise ValueError(f"{path} pas un dossier")
        
        return path
    

class AlexAnalyzeData(BaseModel):
    content: str = Field(description="Contenu brut à analyser (résultat de scan, log...)")
    source: Source = Field(description="Origine: 'scanner', 'anti_phishing', 'sandbox', 'ids_ips', 'manual'")
    asset_id: str | None = Field(default=None, description="Asset concerné, si applicable (pour persistance)")
    base_prompt: str | None = Field(default=None)
    
    @model_validator(mode="after")
    def validate_model(self) -> "AlexAnalyzeData":
        self.asset_id = self.asset_id or FixId[self.source.name].value
        self.base_prompt = PromptMapping[self.source.name].value
        return self


# =============================================================================
# JobManager — modèles
# =============================================================================

class InMemoryFilterData(BaseModel):
    """Base commune : le filtre in_memory revient sur quasi toutes les
    routes jobs (None = les deux jobstores, True = mémoire, False = persistant)."""
    in_memory: bool | None = Field(
        default=None,
        description="True: jobstore mémoire uniquement. False: persistant uniquement. None: les deux."
    )

class GetJobData(InMemoryFilterData):
    job_id: str = Field(description="ID du job")

class ModifyJobData(InMemoryFilterData):
    job_id: str = Field(description="ID du job à modifier")
    name: str | None = Field(default=None, description="Nouveau nom lisible du job")
    args: List | None = Field(default=None, description="Nouveaux arguments positionnels")
    kwargs: Dict | None = Field(default=None, description="Nouveaux arguments nommés")
    max_instances: int | None = Field(default=None, description="Nombre max d'instances concurrentes")
    coalesce: bool | None = Field(default=None, description="Fusionner les exécutions manquées en une seule")
    misfire_grace_time: int | None = Field(default=None, description="Délai de grâce en secondes en cas de retard")
    executor: str | None = Field(default=None, description="'default' (async) ou 'threadpool'")
    trigger: Dict | None = Field(
        default=None,
        description='Nouveau trigger, ex: {"type": "cron", "hour": 9, "minute": 0}'
    )

    def changes(self) -> Dict:
        """Ne renvoie que les champs explicitement fournis (jamais None par
        omission), pour ne pas écraser des attributs non voulus côté manager."""
        return self.model_dump(exclude_none=True, exclude={"job_id", "in_memory"})

class AddJobData(InMemoryFilterData):
    """Planifie un job à partir du catalogue prédéfini (voir job_catalog.py) —
    jamais de fonction arbitraire, contrainte imposée par APScheduler."""
    job_name: str = Field(description="Nom du job dans le catalogue (voir GET jobs/catalog)")
    job_id: str = Field(description="ID unique pour cette instance planifiée")
    trigger: Dict | None = Field(
        default=None,
        description="Trigger custom, sinon celui par défaut du catalogue est utilisé"
    )
    kwargs: Dict | None = Field(default=None, description="Kwargs custom, fusionnés avec ceux par défaut")

    @field_validator("job_name")
    @classmethod
    def job_name_must_exist(cls, v: str) -> str:
        from obsidian_hive.core.managers.job_catalog import JOB_CATALOG
        if v not in JOB_CATALOG:
            raise ValueError(f"job_name inconnu: '{v}'. Disponibles: {', '.join(JOB_CATALOG)}")
        return v


# =============================================================================
# ReportManager — modèles
# =============================================================================

class GetReportData(BaseModel):
    identifier: str = Field(description="ID de rapport (entier en string) OU asset_id")
    first: bool = Field(default=False, description="Ne retourner que le premier résultat")
    limit: int = Field(default=50, ge=1, le=500, description="Nombre max de résultats")

class GetByAssetData(BaseModel):
    asset_id: str = Field(description="Asset concerné")
    limit: int = Field(default=50, ge=1, le=500)

class ListReportsByFilterData(BaseModel):
    asset_id: str | None = Field(default=None)
    source: Source | None = Field(default=None)
    severity: str | None = Field(default=None, description="Sévérité exacte")
    min_severity: str | None = Field(
        default=None,
        description="Inclut tout ce qui est au-dessus ou égal — mutuellement exclusif avec severity"
    )
    start_date: datetime | None = Field(default=None)
    end_date: datetime | None = Field(default=None)
    limit: int = Field(default=100, ge=1, le=1000)
    order_by: str = Field(default="created_at.desc", description="'created_at.desc' ou 'created_at.asc'")

    @model_validator(mode="after")
    def validate_severity_exclusivity(self) -> "ListReportsByFilterData":
        if self.severity and self.min_severity:
            raise ValueError("severity et min_severity sont mutuellement exclusifs")
        return self

class ReportStatsData(BaseModel):
    asset_id: str | None = Field(default=None, description="Stats globales si omis")

class ReportIdData(BaseModel):
    report_id: int = Field(description="ID du rapport")

class UpdateReportSeverityData(ReportIdData):
    severity: Severity = Field(description="Nouvelle sévérité")
    has_fix: bool | None = Field(default=None, description="Si fourni, met aussi à jour ce flag")

class DeleteOldReportsData(BaseModel):
    days: int = Field(gt=0, description="Âge en jours au-delà duquel les rapports sont supprimés")

class ListCriticalReportsData(BaseModel):
    limit: int = Field(default=100, ge=1, le=500, description="Nombre max de résultats")

# =============================================================================
# ConversationManager — modèles
# (owner dérivé du token côté route, jamais fourni par le client)
# =============================================================================

class CreateConversationData(BaseModel):
    title: str | None = Field(default=None, description="Titre initial, sinon auto-généré au 1er message")

class ConversationRefData(BaseModel):
    """Référence à UNE conversation : conversation_id (public) ou id (interne)."""
    conversation_id: str | None = Field(default=None)
    id: int | None = Field(default=None)

    @model_validator(mode="after")
    def validate_one_ref(self) -> "ConversationRefData":
        if not self.conversation_id and self.id is None:
            raise ValueError("Il faut fournir conversation_id ou id")
        return self

class ListConversationsData(BaseModel):
    include_archived: bool = Field(default=False)
    favorites_only: bool = Field(default=False)
    limit: int | None = Field(default=None)
    offset: int = Field(default=0, ge=0)

class SearchConversationsData(BaseModel):
    query: str = Field(min_length=1)
    limit: int = Field(default=20, ge=1, le=100)

class UpdateConversationTitleData(ConversationRefData):
    title: str = Field(min_length=1, max_length=200)

class SetFavoriteData(ConversationRefData):
    favorite: bool = Field(default=True)

class SetArchivedData(ConversationRefData):
    archived: bool = Field(default=True)

class GetMessagesData(ConversationRefData):
    limit: int | None = Field(default=None)
    offset: int = Field(default=0, ge=0)

class GetLastMessageData(ConversationRefData):
    role: str | None = Field(default=None, description="Filtre 'user' ou 'assistant'")

class MessageIdData(BaseModel):
    message_id: int

class UpdateMessageContentData(MessageIdData):
    content: str = Field(min_length=1)

# =============================================================================
# Server Agent
# =============================================================================

class ServerAgentRegisterData(BaseModel):
    install_token: str
    system_info: Dict = Field(default_factory=dict, description="os, os_version, arch, hostname, python_version...")

class ServerAgentRevokeData(BaseModel):
    asset_id: str

class ServerAssetModel(ServerAsset):
    install_token: str | None = Field(default=None, exclude=True)
    install_token_expires_at: datetime | None = Field(default=None, exclude=True)
    agent_status: AgentStatus = Field(default=AgentStatus.PENDING_INSTALL, exclude=True)
    agent_credential_hash: str | None = Field(default=None, exclude=True)
    last_heartbeat: datetime | None = Field(default=None, exclude=True)
    system_info: Dict[str, Any] = Field(default_factory=dict, exclude=True)
    installed_modules: List[AgentCapabilities] = Field(default_factory=list, exclude=True)
    manage_immediatly: bool = Field(default=False, exclude=True) # Ignoré en vrai

    @model_validator(mode="after")
    def validate_model(self) -> "ServerAssetModel":
        return self

class ServerCapabilitiesData(BaseModel):
    asset_id: str = Field(description="Identifiant du ServerAsset")
    capabilities: List[AgentCapabilities] = Field(min_length=1, description="Capabilities à ajouter/retirer")

class ServerToolsData(BaseModel):
    asset_id: str = Field(description="Identifiant du ServerAsset")
    tools: List[str] = Field(min_length=1, description="Noms de tools à autoriser/révoquer")

class RotateSecretData(BaseModel):
    asset_id: str = Field(description="Identifiant du ServerAsset")

class ReactivateServerAssetData(BaseModel):
    asset_id: str = Field(description="Identifiant du ServerAsset")

