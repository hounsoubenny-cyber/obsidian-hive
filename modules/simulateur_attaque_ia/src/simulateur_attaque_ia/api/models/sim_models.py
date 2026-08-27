#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug  3 00:30:38 2026

@author: hounsousamuel
"""

"""
Modèles Pydantic pour l'API du simulateur d'attaque.
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))

from datetime import datetime
from enum import StrEnum
from typing import Any, Dict, List, Optional, Union, Literal
from pydantic import BaseModel, Field, model_validator
from simulateur_attaque_ia.core.fake_services_scripts import DEFAULT_SERVICE_REGISTRY

# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class SimMode(StrEnum):
    AUTO        = "auto"
    INTERACTIVE = "interactive"


class SimStatus(StrEnum):
    STARTING  = "starting"
    RUNNING   = "running"
    WAITING   = "waiting"       # interactif : attend une action user
    COMPLETED = "completed"
    STOPPED   = "stopped"
    FAILED    = "failed"


class ListMergeMode(StrEnum):
    """Comment fusionner une liste cliente avec les defaults existants."""
    REPLACE = "replace"   # remplace entièrement
    ADD     = "add"       # ajoute à l'existant (dédupliqué)
    KEEP    = "keep"      # ignore les nouvelles valeurs, garde l'existant


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    token:   str
    message: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# SimConfig – mirrors SimulatorConfig de auto_orchestrator (tout optionnel)
# ─────────────────────────────────────────────────────────────────────────────

class ReconConfig(BaseModel):
    port_range:      Optional[List[int]] = None
    timeout_socket:  Optional[float]     = None


class SSHConfig(BaseModel):
    timeout:       Optional[float]     = None
    total_timeout: Optional[float]     = None
    delay:         Optional[float]     = None
    max_attempts:  Optional[int]       = None
    add_common:    Optional[bool]      = None
    usernames:     Optional[List[str]] = None
    passwords:     Optional[List[str]] = None


class FTPConfig(BaseModel):
    timeout:       Optional[float]     = None
    total_timeout: Optional[float]     = None
    max_attempts:  Optional[int]       = None
    add_common:    Optional[bool]      = None
    usernames:     Optional[List[str]] = None
    passwords:     Optional[List[str]] = None


class HTTPConfig(BaseModel):
    timeout:    Optional[float]     = None
    preference: Optional[str]       = None
    add_common: Optional[bool]      = None
    paths:      Optional[List[str]] = None


class ExecConfig(BaseModel):
    timeout:      Optional[float]     = None
    exec_timeout: Optional[float]     = None
    commands:     Optional[List[str]] = None
    add_common:   Optional[bool]      = None
    quick:        Optional[bool]      = None


class ReverseShellConfig(BaseModel):
    attaquant_ip:     Optional[str]       = None
    attaquant_port:   Optional[int]       = None
    timeout:          Optional[float]     = None
    exec_timeout:     Optional[float]     = None
    listener_timeout: Optional[float]     = None
    total_timeout:    Optional[float]     = None
    commands:         Optional[List[str]] = None


class PersistenceConfig(BaseModel):
    ssh_key_timeout:      Optional[float] = None
    ssh_key_exec_timeout: Optional[float] = None
    ssh_key_algo:         Optional[str]   = None
    cron_script_path:     Optional[str]   = None
    cron_expression:      Optional[str]   = None
    cron_level:           Optional[str]   = None


class PrivescConfig(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None


class CredAccessConfig(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None


class LateralMovConfig(BaseModel):
    max_depth:    Optional[int]   = None
    max_workers:  Optional[int]   = None
    join_timeout: Optional[float] = None


class ExfilConfig(BaseModel):
    c2_url:  Optional[str] = None
    timeout: Optional[int] = None


class DefEvasionConfig(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None


class SimConfig(BaseModel):
    """Toutes les options de configuration de la simulation, toutes optionnelles."""
    recon:            Optional[ReconConfig]       = None
    ssh:              Optional[SSHConfig]         = None
    ftp:              Optional[FTPConfig]         = None
    http:             Optional[HTTPConfig]        = None
    execution:        Optional[ExecConfig]        = None
    python_execution: Optional[ExecConfig]        = None
    reverse_shell:    Optional[ReverseShellConfig]= None
    persistence:      Optional[PersistenceConfig] = None
    privesc:          Optional[PrivescConfig]     = None
    credential_access:Optional[CredAccessConfig]  = None
    lateral_movement: Optional[LateralMovConfig]  = None
    exfiltration:     Optional[ExfilConfig]       = None
    defense_evasion:  Optional[DefEvasionConfig]  = None


# ─────────────────────────────────────────────────────────────────────────────
# LLM Config
# ─────────────────────────────────────────────────────────────────────────────

class LLMConfig(BaseModel):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Sim Start Request
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SERVICES = Literal[*tuple(DEFAULT_SERVICE_REGISTRY)]

# class StartSimRequest(BaseModel):
#     image:          str
#     mode:           SimMode              = SimMode.AUTO
#     services:       Optional[Dict[int, Dict]] = None   # services.json, None = auto-capture
#     use_llm:        bool                 = False
#     llm_config:     Optional[LLMConfig]  = None
#     sim_config:     Optional[SimConfig]  = None
#     container_name: Optional[str]        = None
#     authorize_network:  bool                 = False  
#     network_caps:       bool                 = False  

class StartSimRequest(BaseModel):
    image:          str
    mode:           SimMode              = SimMode.AUTO
    services:       Optional[Dict[int, Dict]] = None   # services.json, None = auto-capture
    use_llm:        bool                 = False
    llm_config:     Optional[LLMConfig]  = None
    sim_config:     Optional[SimConfig]  = None
    container_name: Optional[str]        = None
    authorize_network:  bool             = False
    network_caps:       bool             = False
    default_services:       Optional[Dict[DEFAULT_SERVICES, List[int]]] = None
    only_listening:          bool                = False
    use_default_excludes:    bool                = True
    capture_excluded_names:  Optional[List[str]] = None
    capture_excluded_ports:  Optional[List[int]] = None
    capture_excluded_pids:   Optional[List[int]] = None
    auto_capture:             bool                = True
    # False = ne jamais scanner le host, même si `services` est absent/invalide.
    # Utile pour n'utiliser QUE default_services sans le coût du scan psutil.

class StartSimResponse(BaseModel):
    session_id: str
    status:     SimStatus
    message:    str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Clone Request
# ─────────────────────────────────────────────────────────────────────────────

class CloneRequest(BaseModel):
    src:              Optional[str]  = None     # défaut : / (linux) ou C:\ (windows)
    dest:             Optional[str]  = None     # où stocker l'archive
    archive_path:     Optional[str]  = None     # tar.gz déjà existant → skip copie
    remove_back_up:   bool           = True
    container_name:   Optional[str]  = None
    network_caps:     bool           = False    # NET_RAW + NET_ADMIN
    authorize_network:bool           = False    # False → --network=isolated


class CloneStatusResponse(BaseModel):
    clone_id:   str
    status:     Literal["running", "completed", "failed", "stopped", "not_found"]
    image:      Optional[str]        = None
    services:   Optional[Dict]       = None
    error:      Optional[str]        = None
    started_at: Optional[datetime]   = None
    ended_at:   Optional[datetime]   = None
    message:    Optional[str]        = None


# ─────────────────────────────────────────────────────────────────────────────
# Services
# ─────────────────────────────────────────────────────────────────────────────

class ValidateServicesRequest(BaseModel):
    services: Dict[str, Any]


class ValidateServicesResponse(BaseModel):
    valid:   bool
    errors:  List[str] = []
    warnings:List[str] = []


# ─────────────────────────────────────────────────────────────────────────────
# Params pour chaque step interactif
# ─────────────────────────────────────────────────────────────────────────────

class ReconParams(BaseModel):
    timeout_socket:  Optional[float]     = None
    port_range:      Optional[List[int]] = None
    port_range_mode: ListMergeMode       = ListMergeMode.REPLACE
    
    @model_validator(mode="after")
    def validate_model(self) -> "ReconParams":
        if self.port_range:
            self.port_range = [p for p in self.port_range if 0 <= p <= 65535]
        
        return self

class SSHAttackParams(BaseModel):
    enabled:         bool               = True
    timeout:         Optional[float]    = None
    total_timeout:   Optional[float]    = None
    delay:           Optional[float]    = None
    max_attempts:    Optional[int]      = None
    add_common:      Optional[bool]     = None
    usernames:       Optional[List[str]]= None
    usernames_mode:  ListMergeMode      = ListMergeMode.KEEP
    passwords:       Optional[List[str]]= None
    passwords_mode:  ListMergeMode      = ListMergeMode.KEEP
    ports:           Optional[List[int]]= None   # sous-ensemble des ports découverts
    
    @model_validator(mode="after")
    def validate_model(self) -> "SSHAttackParams":
        if self.ports:
            self.ports = [p for p in self.ports if 0 <= p <= 65535]
        
        return self


class FTPAttackParams(BaseModel):
    enabled:         bool               = True
    timeout:         Optional[float]    = None
    total_timeout:   Optional[float]    = None
    max_attempts:    Optional[int]      = None
    add_common:      Optional[bool]     = None
    usernames:       Optional[List[str]]= None
    usernames_mode:  ListMergeMode      = ListMergeMode.KEEP
    passwords:       Optional[List[str]]= None
    passwords_mode:  ListMergeMode      = ListMergeMode.KEEP
    ports:           Optional[List[int]]= None
    
    @model_validator(mode="after")
    def validate_model(self) -> "FTPAttackParams":
        if self.ports:
            self.ports = [p for p in self.ports if 0 <= p <= 65535]
        
        return self


class HTTPAttackParams(BaseModel):
    enabled:     bool               = True
    timeout:     Optional[float]    = None
    preference:  Optional[str]      = None
    add_common:  Optional[bool]     = None
    paths:       Optional[List[str]]= None
    paths_mode:  ListMergeMode      = ListMergeMode.KEEP
    ports:       Optional[List[int]]= None
    
    @model_validator(mode="after")
    def validate_model(self) -> "HTTPAttackParams":
        if self.ports:
            self.ports = [p for p in self.ports if 0 <= p <= 65535]
        
        return self


class InitialAccessParams(BaseModel):
    ssh:  Optional[SSHAttackParams]  = None
    ftp:  Optional[FTPAttackParams]  = None
    http: Optional[HTTPAttackParams] = None


class ExecutionParams(BaseModel):
    timeout:           Optional[float]     = None
    exec_timeout:      Optional[float]     = None
    commands:          Optional[List[str]] = None
    commands_mode:     ListMergeMode       = ListMergeMode.KEEP
    add_common:        Optional[bool]      = None
    quick:             Optional[bool]      = None
    credential_index:  int                 = 0      # index dans ssh_brute_force_found_credentials
    run_reverse_shell: bool                = False
    reverse_shell:     Optional[ReverseShellConfig] = None


class PersistenceParams(BaseModel):
    run_ssh_key:          bool           = True
    ssh_key_algo:         Optional[str]  = None
    ssh_key_timeout:      Optional[float]= None
    ssh_key_exec_timeout: Optional[float]= None
    run_cron:             bool           = True
    cron_script_path:     Optional[str]  = None
    cron_expression:      Optional[str]  = None
    cron_level:           Optional[str]  = None     # "user" | "root"


class PrivescParams(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None
    run_sudo:     bool            = True
    run_suid:     bool            = True


class CredAccessParams(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None
    run_dump:     bool            = True
    run_history:  bool            = True
    run_keys:     bool            = True


class LateralParams(BaseModel):
    max_depth:    Optional[int]   = None
    max_workers:  Optional[int]   = None
    join_timeout: Optional[float] = None


class ExfilParams(BaseModel):
    c2_url:  Optional[str] = None
    timeout: Optional[int] = None


class DefEvasionParams(BaseModel):
    timeout:      Optional[float] = None
    exec_timeout: Optional[float] = None
    run_clean:    bool            = True
    run_stomp:    bool            = True


# Union pour le dispatcher
StepParams = Union[
    ReconParams,
    InitialAccessParams,
    ExecutionParams,
    PersistenceParams,
    PrivescParams,
    CredAccessParams,
    LateralParams,
    ExfilParams,
    DefEvasionParams,
    Dict[str, Any],
]


# ─────────────────────────────────────────────────────────────────────────────
# Messages WS Client → Serveur (mode interactif)
# ─────────────────────────────────────────────────────────────────────────────

class ExecuteActionMessage(BaseModel):
    type:   str = "execute_action"
    action: str                      # "reconnaissance" | "initial_access" | ...
    params: Dict[str, Any] = {}


class RequestLLMSuggestMessage(BaseModel):
    type: str = "request_llm_suggest"


class RequestLLMReviewMessage(BaseModel):
    type:   str = "request_llm_review"
    action: str


class GetStateMessage(BaseModel):
    type: str = "get_state"


# ─────────────────────────────────────────────────────────────────────────────
# Status / History
# ─────────────────────────────────────────────────────────────────────────────

class SimStatusResponse(BaseModel):
    session_id:   str
    mode:         SimMode
    image:        str
    status:       SimStatus
    started_at:   datetime
    ended_at:     Optional[datetime] = None
    current_step: Optional[str]      = None
    progress:     float              = 0.0
    error:        Optional[str]      = None
    actions_done: List[str]          = []


class SimHistoryEntry(BaseModel):
    session_id:  str
    mode:        SimMode
    image:       str
    status:      SimStatus
    started_at:  datetime
    ended_at:    Optional[datetime] = None
    steps_done:  List[str]          = []
    report:      Optional[Dict]     = None
    error:       Optional[str]      = None


# =============================================================================
# Containers
# =============================================================================

ContainerStatus = Literal[
    "created",      # Container créé mais pas démarré
    "running",      # En cours d'exécution
    "exited",       # Arrêté normalement
    "paused",       # Mis en pause
    "restarting",   # En cours de redémarrage
    "removing",     # En cours de suppression
    "dead",         # Mort (ne peut pas être démarré)
    "stopped",      # Arrêté
    "unknown",      # Statut inconnu
]

class ContainerInfo(BaseModel):
    """Informations sur un container Docker."""
    id: str
    short_id: str
    name: str
    image: str
    status: ContainerStatus  # "running", "created", "exited", "paused", etc.
    ip: Optional[str] = None
    created: str
    size: int
    size_human: str
    labels: Dict[str, str]
    is_simatk: bool


class ContainerListResponse(BaseModel):
    """Réponse pour GET /containers/list."""
    total: int
    containers: List[ContainerInfo]
    filters: Dict[str, Any]

# ─── POST /containers/create ─────────────────────────────────────────────

Capability = Literal[
    # ─── Réseau (limité, sans échappement) ─────────────────────────────
    "NET_ADMIN",          # Configuration réseau (limité au container)
    "NET_RAW",            # Sockets bruts (ping, ARP, scans)
    "NET_BIND_SERVICE",   # Ports privilégiés (< 1024)
    
    # ─── Processus (limité au container) ────────────────────────────────
    "KILL",               # Tuer des processus (uniquement dans le container)
    
    # ─── Système (limité au container) ──────────────────────────────────
    "SYS_TIME",           # Changer l'horloge (uniquement dans le container)
    "SYS_RESOURCE",       # Modifier les limites de ressources (container)
    "IPC_LOCK",           # Verrouiller la mémoire (container)
    "WAKE_ALARM",         # Réveiller le système (container)

]
class ContainerCreateRequest(BaseModel):
    """Requête pour créer un container."""
    image: str = Field(..., description="Image Docker à utiliser")
    name: Optional[str] = Field(None, description="Nom du container (auto-généré si non fourni)")
    network: str = Field("bridge", description="Réseau Docker")
    cap_add: Optional[List[Capability] ] = Field(None, description="Capacités Linux à ajouter (ex: NET_RAW)")
    labels: Optional[Dict[str, str]] = Field(None, description="Labels à appliquer")
    environment: Optional[Dict[str, str]] = Field(None, description="Variables d'environnement")
    ports: Optional[Dict[int, int]] = Field(None, description="Mapping ports {host: container}")
    command: Optional[str] = Field("sleep infinity", description="Commande à exécuter")


class ContainerCreateResponse(BaseModel):
    """Réponse pour POST /containers/create."""
    success: bool = Field(..., description="Succès de l'opération")
    container: Dict[str, Any] = Field(..., description="Informations du container créé")
    message: str = Field(..., description="Message de confirmation")


# ─── POST /containers/{name}/stop ────────────────────────────────────────

class ContainerStopResponse(BaseModel):
    """Réponse pour POST /containers/{name}/stop."""
    success: bool = Field(..., description="Succès de l'opération")
    container: str = Field(..., description="Nom du container arrêté")
    message: str = Field(..., description="Message de confirmation")


# ─── POST /containers/{name}/exec ────────────────────────────────────────

class ContainerExecRequest(BaseModel):
    """Requête pour exécuter une commande dans un container."""
    command: str | list = Field(..., description="Commande à exécuter (ex: 'whoami && ls -la')")


class ContainerExecResponse(BaseModel):
    """Réponse pour POST /containers/{name}/exec."""
    success: bool = Field(..., description="Succès de l'opération")
    container: str = Field(..., description="Nom du container")
    command: str = Field(..., description="Commande exécutée")
    exit_code: int = Field(..., description="Code de retour")
    stdout: str | None = Field(None, description="Sortie de la commande (stdout)")
    stderr: str | None = Field(None, description="Sortie de la commande (stderr)")
    message: str | None = Field(None, description="Message en cas d'erreur")


# ─── GET /containers/cache ───────────────────────────────────────────────

class CachedContainerInfo(BaseModel):
    """Informations sur un container en cache."""
    name: str = Field(..., description="Nom du container")
    status: str = Field(..., description="Statut du container")
    image: str = Field(..., description="Image utilisée")
    last_used: Optional[float] = Field(None, description="Timestamp de dernière utilisation")


class CacheListResponse(BaseModel):
    """Réponse pour GET /containers/cache."""
    total: int = Field(..., description="Nombre total de containers en cache")
    containers: List[CachedContainerInfo] = Field(..., description="Liste des containers en cache")
    
    
# ─── Network ───────────────────────────────────────────────────────────────

class NetworkCreateRequest(BaseModel):
    """Requête pour créer un réseau Docker."""
    name: str = Field(..., description="Nom du réseau")
    driver: Literal["bridge", "overlay"] = Field("bridge", description="Driver réseau")
    subnet: Optional[str] = Field(None, description="Subnet (ex: 172.30.0.0/24)")
    internal: bool = Field(False, description="Réseau interne (pas d'accès internet)")
    labels: Optional[Dict[str, str]] = Field(None, description="Labels")
    
    def is_subnet_valid(self) -> bool:
        """
        Vérifie que le subnet fourni (si présent) est un préfixe CIDR valide.
        """
        import ipaddress
        if not self.subnet:
            return True  
        try:
            ipaddress.ip_network(self.subnet, strict=False)
            return True
        except ValueError:
            return False


class NetworkInfo(BaseModel):
    """Informations sur un réseau Docker."""
    name: str
    id: str
    short_id: str
    driver: str
    subnet: Optional[str]
    internal: bool
    containers_count: int
    labels: Dict[str, str]
    created: str


class NetworkListResponse(BaseModel):
    """Réponse pour GET /network/list."""
    total: int
    networks: List[NetworkInfo]


class NetworkCreateResponse(BaseModel):
    """Réponse pour POST /network/create."""
    success: bool
    network: Dict[str, Any]
    message: str
    error: Optional[str] = None


class NetworkContainerInfo(BaseModel):
    """Informations sur un container dans un réseau."""
    id: str
    name: str
    status: str
    image: str
    ip: Optional[str]
    labels: Dict[str, str]
    created: str
    is_simatk: bool
    message: Optional[str] = None          # message par container (ex: erreur récupération IP)


class NetworkContainersResponse(BaseModel):
    """Réponse pour GET /network/{name}/containers."""
    network: str
    network_id: str
    total: int
    containers: List[NetworkContainerInfo]
    message: Optional[str] = None
    error: Optional[str] = None


class NetworkRemoveResponse(BaseModel):
    """Réponse pour POST /network/{name}/remove."""
    success: bool
    network: str
    message: str
    containers: Optional[List[str]] = None
    removed_containers: Optional[List[str]] = None
    failed_containers: Optional[List[Dict[str, str]]] = None
    error: Optional[str] = None


class NetworkRemoveAllResponse(BaseModel):
    """Réponse pour POST /network/remove_all."""
    success: bool
    total: int
    removed: List[str]
    failed: List[Dict[str, str]]
    message: Optional[str] = None
    error: Optional[str] = None


class NetworkConnectRequest(BaseModel):
    """Requête pour connecter un container à un réseau."""
    container_name: str = Field(..., description="Nom du container")
    ip: Optional[str] = Field(None, description="IP statique à attribuer")
    aliases: Optional[List[str]] = Field(None, description="Alias DNS")


class NetworkConnectResponse(BaseModel):
    """Réponse pour POST /network/{name}/connect."""
    success: bool
    container: str
    network: str
    ip: Optional[str]
    aliases: Optional[List[str]] = None
    message: str
    error: Optional[str] = None


class NetworkDisconnectRequest(BaseModel):
    """Requête pour déconnecter un container d'un réseau."""
    container_name: str = Field(..., description="Nom du container")
    force: bool = Field(False, description="Forcer la déconnexion")


class NetworkDisconnectResponse(BaseModel):
    """Réponse pour POST /network/{name}/disconnect."""
    success: bool
    container: str
    network: str
    force: bool
    remaining_networks: List[str]
    message: str
    error: Optional[str] = None


class NetworkMoveRequest(BaseModel):
    """Requête pour déplacer un container d'un réseau à un autre."""
    container_name: str = Field(..., description="Nom du container")
    source_network: str = Field(..., description="Réseau source")
    destination_network: str = Field(..., description="Réseau destination")
    force: bool = Field(False, description="Forcer le déplacement")
    ip: Optional[str] = Field(None, description="IP statique sur le réseau destination")
    aliases: Optional[List[str]] = Field(None, description="Alias DNS")


class NetworkMoveResponse(BaseModel):
    """Réponse pour POST /network/move."""
    success: bool
    container: str
    source_network: str
    destination_network: str
    ip: Optional[str]
    aliases: Optional[List[str]] = None
    networks: List[str]
    message: str
    error: Optional[str] = None