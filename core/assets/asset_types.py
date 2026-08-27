#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 22 19:57:55 2026

@author: hounsousamuel
"""

import os
import time
import json5
import shutil
from typing import Dict, List, Any
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from enum import IntEnum, StrEnum
from pydantic import Field, BaseModel, field_validator, model_validator
from ids_ips_ia.config.config_manager import _config_path as DEFAULT_IDS_CONFIG_PATH
from scanner_ia.api.api_config import DEFAULT_SCAN_PATH
from modules_utils.validate_config import (
    validate_and_merge_config,
)
from scanner_ia.api.api_config import (
    CONFIG_TEMP_DIR, MAX_CONFIG_SIZE
)

def utcnow():
    """Retourne la date/heure UTC actuelle avec fuseau horaire.

    Returns:
        datetime: Date/heure actuelle en UTC.
    """
    return datetime.now(tz=timezone.utc)


def asset_id(tag: str = "sh_as-"):
    """Génère un identifiant unique d'asset avec un préfixe optionnel.

    Args:
        tag (str, optional): Préfixe pour l'ID de l'asset. Par défaut "sh_as-".

    Returns:
        str: Un ID unique combinant le préfixe et un UUID4.
    """
    return (tag or "sh_as-") + str(uuid4())


class ObsidianValidationError(Exception):
    """Exception personnalisée pour les erreurs de validation des assets Obsidian."""
    pass


# ============================================================================
# Enums génériques (priorité, sévérité, sources, mapping d'IDs/prompts)
# ============================================================================

class Priority(IntEnum):
    """Niveaux de priorité pour le traitement des assets, ordonnés par importance croissante."""
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

PRIORITY_MAPPING = {
    v: k
    for k, v in [(p.name, p.value) for p in Priority]
}


class Severity(StrEnum):
    """Niveaux de sévérité pour la classification des menaces/vulnérabilités."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

SEVERITY_ORDER = {
    'low': 1, 'medium': 2, 'high': 3, 'critical': 4
}


class Source(StrEnum):
    """Types de sources de données pour les analyses d'assets."""
    SCANNER_WEB         = "scanner_web"
    IDS_IPS             = "ids_ips"
    SANDBOX             = "sandbox"
    TEST                = "test"
    MANUAL              = "manual"
    SERVER              = "server"
    ANTI_PHISHING_EMAIL = "email"
    CODE                = "code"
    ANTI_PHISHING_URL   = "url"


class AssetType(StrEnum):
    """Types d'assets pouvant être gérés par le système."""
    WEB_SITE               = "web_site"  # DO
    WEB_APP                = "web_app"   # DO
    NETWORK                = "network"   # DO
    SERVER                 = "server"
    ANTI_PHISHING_EMAIL    = "email"
    ANTI_PHISHING_URL      = "url"
    CODE                   = "code"


class FixId(StrEnum):
    """IDs d'assets de repli utilisés par Alex quand aucun asset_id explicite n'est fourni.
    
    Un par valeur possible de `Source`, les noms sont alignés exactement sur ceux de `Source`
    (utilisé via FixId[source.name]).
    """
    MANUAL              = "sh_as-4ae622a6-6c3d-430d-8a6e-15af46939de4"
    SERVER              = "sh_as-fb96119e-28b8-43dd-824c-57865721a606"
    ANTI_PHISHING_EMAIL = "sh_as-31807387-dd31-4502-a7f9-da07fb0e917c"
    CODE                = "sh_as-ae64a9b0-afd1-4a43-b470-1d358ef0c156"
    SCANNER_WEB         = "sh_as-8c3e0a2b-1f4e-4a9d-9b6c-2d7f5a8e1c40"
    IDS_IPS             = "sh_as-b1d4f7a3-6e2c-4f18-9a5d-3c8b7e4f2a91"
    SANDBOX             = "sh_as-e5a2c9d1-7b3f-4e6a-8c4d-1f9b6a3e7d52"
    TEST                = "sh_as-2f8b4d6a-9c1e-4a7f-b3d5-6e2a8c4f1b93"
    ANTI_PHISHING_URL   = "sh_as-6d3a9f1c-4b7e-4c2a-8d5f-9a1b3e6c2f74"


class PromptMapping(StrEnum):
    """Prompts de base injectés avant le contenu brut envoyé à Alex, un par `Source`.
    
    Les noms correspondent à ceux de `Source` (cf. FixId).
    """
    SCANNER_WEB = """
        Tu reçois le résultat brut d'un scan de vulnérabilités web (SQLi, XSS, failles OWASP...). 
        Élimine les faux positifs, classe les vulnérabilités réelles par sévérité, et
        propose des correctifs concrets et applicables.
    """

    IDS_IPS = """
        Tu reçois une ou plusieurs alertes issues du système IDS/IPS réseau. 
        Identifie le vecteur d'attaque probable, évalue la criticité réelle du contexte, 
        et recommande une action (bloquer / surveiller / ignorer).
    """

    SANDBOX = """
        Tu reçois un rapport d'exécution de code en sandbox isolé (comportement système, appels réseau, fichiers touchés).
        Détermine si le code est malveillant, bénin ou suspect, explique ton raisonnement, et évalue le niveau de risque.
    """

    TEST = """
        Contexte de test — analyse librement le contenu fourni pour valider le pipeline.
    """

    MANUAL = """
        L'administrateur a soumis manuellement un contenu à analyser (log, extrait de code, résultat externe).
        Analyse-le selon son contexte et produis un rapport clair avec des conclusions actionnables.
    """

    SERVER = """
        Tu reçois des données de supervision d'un serveur (services exposés, configuration, versions). 
        Identifie les risques de configuration et les vulnérabilités connues, priorise par criticité.
    """

    ANTI_PHISHING_EMAIL = """
        Tu reçois le résultat d'une analyse anti-phishing d'un email (score IA + analyse passive). 
        Confirme ou infirme la classification, explique les indicateurs déterminants, recommande l'action à prendre.
    """

    CODE = """
        Tu reçois un extrait de code source à auditer (injections, secrets en dur, mauvaises pratiques cryptographiques...). 
        Identifie les problèmes réels, évalue leur sévérité, propose des correctifs précis.
    """

    ANTI_PHISHING_URL = """
        Tu reçois le résultat d'une analyse anti-phishing d'une URL (score IA + analyse passive). 
        Confirme ou infirme la classification, explique les indicateurs déterminants, recommande l'action à prendre.
    """


class AssetStatus(StrEnum):
    """Statut opérationnel courant d'un asset."""
    ACTIVE     = "active"
    SUPPRESSED = "suppressed"
    INACTIVE   = "inactive"


# ============================================================================
# AssetItem — base commune à tous les assets
# ============================================================================

class AssetItem(BaseModel):
    """Modèle de base pour tous les types d'assets dans le système Obsidian.
    
    Attributes:
        id (str | None): UUID de l'asset.
        item_db_id (int | None): Clé primaire entière côté DB, distincte de `id`.
        name (str | None): Label ou nom de l'asset (ex: 'Site vitrine').
        type (AssetType): Type de l'asset.
        status (AssetStatus): Statut courant de l'asset. Par défaut ACTIVE.
        priority (Priority): Priorité de traitement dans la file d'attente. Par défaut LOW.
        tags (List[str]): Tags libres, ex: ['prod', 'critique'].
        auto_fix (bool): Applique les fixes générés par Alex sans validation admin.
        created_at (datetime): Date de création.
        updated_at (datetime): Dernière date de mise à jour.
        timestamp (float): Timestamp monotonic pour le tri dans la file de priorité.
        metadata_ (Dict[str, Any]): Données supplémentaires libres sur l'asset.
        every (float): Durée de répétition du workflow en secondes. Par défaut 36000.
        run_every (bool): Définit s'il faut programmer une tâche périodique. Par défaut True.
        already_exec_for_first_time (bool): True dès la première exécution effectuée.
        last_rest_exec_time (float | None): Timestamp de la dernière exécution.
        every_task_id (str | None): ID de la tâche périodique dans la queue.
        workflow_task_id (str | None): ID de la tâche de workflow en cours dans la queue.
        special_fields (List[str]): Champs nécessitant un traitement spécial à la sérialisation.
        extra_fields (List[str]): Champs spécifiques à chaque sous-classe.
        run_fields (List[str]): Champs dont la modification redémarre le workflow associé.
        install_token (str | None): Token d'installation à usage unique, None une fois consommé.
        install_token_expires_at (datetime | None): Date d'expiration du token.
    """
    # --- Identité ---
    id: str | None = Field(default_factory=asset_id, description="UUID de l'asset")
    item_db_id: int | None = Field(default=None, description="Clé primaire entière côté DB, distincte de `id`")
    name: str | None = Field(default=None, description="Label ou nom de l'asset comme 'Site vitrine'")
    type: AssetType = Field(description="Type de l'asset")
    status: AssetStatus = Field(default=AssetStatus.ACTIVE, description="Statut courant de l'asset")

    # --- Classification / organisation ---
    priority: Priority = Field(default=Priority.LOW, description="Priorité de traitement de l'asset dans la queue")
    tags: List[str] = Field(default_factory=list, description="Tags libres. Ex: ['prod', 'critique']")
    auto_fix: bool = Field(default=False, description="Applique les fixes générés par Alex sans validation admin")

    # --- Horodatage ---
    created_at: datetime = Field(default_factory=utcnow, description="Date de création")
    updated_at: datetime = Field(default_factory=utcnow, description="Dernière date de mise à jour")
    timestamp: float = Field(default_factory=time.monotonic, description="Timestamp monotonic, utilisé pour le tri de la priority queue")

    # --- Divers / extension ---
    metadata_: Dict[str, Any] = Field(default_factory=dict, description="Données supplémentaires libres sur l'asset")

    # --- Planification (WorkflowManager) ---
    every: float = Field(default=3600 * 10, description="Durée de répétition du workflow, en secondes")
    run_every: bool = Field(default=True, description="Définit s'il faut programmer une tâche périodique")
    already_exec_for_first_time: bool = Field(default=False, description="True dès la première exécution effectuée")
    last_rest_exec_time: float | None = Field(default=None, description="Timestamp de la dernière exécution, pour reprendre le timer après une annulation")
    every_task_id: str | None = Field(default=None, description="ID de la tâche périodique dans la queue")
    workflow_task_id: str | None = Field(default=None, description="ID de la tâche de workflow en cours dans la queue")

    # --- Sérialisation ---
    special_fields: List[str] = Field(
        default_factory=lambda: ["tags", "metadata_", "special_fields", "extra_fields", "run_fields"],
        description="Champs nécessitant un traitement spécial à la sérialisation"
    )
    extra_fields: List[str] = Field(default_factory=list, description="Champs spécifiques à chaque sous-classe")
    run_fields: List[str] = Field(
        default_factory=lambda: ["every"],
        description="Champs dont la modification doit redémarrer le workflow associé"
    )
    
    # --- Installation (pour server asset)---
    install_token: str | None = Field(default=None, description="Token d'installation à usage unique, None une fois consommé")
    install_token_expires_at: datetime | None = Field(
        default=None,
        description="Expiration du token — None tant qu'aucun token n'est généré. Posé explicitement via `generate_install_token()`."
    )
    

    def __lt__(self, other: "AssetItem"):
        """Compare deux assets pour l'ordonnancement dans la file de priorité.
        
        Les assets de priorité plus élevée passent en premier ; à priorité égale,
        les plus anciens (timestamp le plus petit) sont traités en premier.

        Args:
            other (AssetItem): Autre asset à comparer.

        Returns:
            bool: True si cet asset a une priorité plus élevée ou un timestamp plus ancien.
        """
        if self.priority != other.priority:
            return self.priority > other.priority
        return self.timestamp < other.timestamp


def _get_config_path(config_path: str, config_content: str):
    """Garantit qu'un fichier de configuration existe et retourne son chemin.
    
    Si config_path est fourni et existe, le retourne. Sinon, régénère
    le fichier de configuration à partir de config_content.

    Args:
        config_path (str): Chemin où le fichier de config doit se trouver.
        config_content (str): Contenu JSON à écrire si le fichier est manquant.

    Returns:
        str: Le chemin du fichier de configuration.

    Raises:
        ObsidianValidationError: Si config_content est vide et config_path est manquant.
    """
    if config_path and os.path.exists(config_path):
        return config_path

    if not config_content:
        raise ObsidianValidationError("config_path manquant et aucun config_content pour le régénérer")

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        f.write(config_content)

    return config_path


# ============================================================================
# WebAsset / WebAppAsset — sites web et applications web
# ============================================================================

class WebAsset(AssetItem):
    """Asset représentant un site web à scanner pour les vulnérabilités.
    
    Attributes:
        url (str): URL du site à scanner.
        init_config (Dict[str, Any]): Dictionnaire d'instanciation du scanner.
        run_config (Dict[str, Any]): Dictionnaire de configuration du scan.
        conf_content (str): Configuration du scanner en chaîne JSON.
        config_path (str): Chemin du fichier de config sur disque. Par défaut DEFAULT_SCAN_PATH.
        fix_allowed (bool): Autorise Alex à générer des fixes ou non. Par défaut False.
        source_code_dir (str | None): Dossier du code source fourni par l'admin.
    """
    type: AssetType = AssetType.WEB_SITE

    # --- Cible ---
    url: str = Field(description="URL du site à scanner")

    # --- Configuration du Scanner ---
    init_config: Dict[str, Any] = Field(default_factory=dict, description="Dictionnaire d'instanciation du scanner")
    run_config: Dict[str, Any] = Field(default_factory=dict, description="Dictionnaire de configuration du scan")
    conf_content: str = Field(description="Configuration du scanner, en string JSON")
    config_path: str = Field(default=DEFAULT_SCAN_PATH, description="Chemin du fichier de config sur disque")

    # --- Fix / code source ---
    fix_allowed: bool = Field(default=False, description="Autorise Alex à générer des fixes ou non")
    source_code_dir: str | None = Field(default="", description="Dossier du code source fourni par l'admin, pour la génération de fix")

    special_fields: List[str] = Field(default_factory=lambda: [
        "tags", "metadata_", "special_fields", "extra_fields", "init_config", "run_config", "run_fields",
    ])
    extra_fields: List[str] = Field(default_factory=lambda: [
        "init_config", "run_config", "url", "fix_allowed", "source_code_dir", "conf_content",
        "config_path"
    ])
    run_fields: List[str] = Field(default_factory=lambda: [
        "every", "url", "init_config", "run_config", "source_code_dir", "fix_allowed",
        "conf_content", "config_path"
    ])
    
    def __setattr__(self, name, value):
        if name in ("conf_content",):
            copy_path = None
            try:
                uuid = str(uuid4())
                base, ext = os.path.splitext(self.config_path)
                copy_path = f"{base}_{uuid}{ext}"
                shutil.copy(self.config_path, copy_path)
                config_path = validate_and_merge_config(
                    max_size=MAX_CONFIG_SIZE,
                    config_temp_dir=CONFIG_TEMP_DIR,
                    default_config_path=copy_path,
                    user_config_str=json5.dumps(value) if not isinstance(value, str) else value,
                    id=self.id,
                    write_path=self.config_path,
                )
                self.config_path = config_path
                with open(config_path) as f:
                    value = json5.dumps(json5.loads(f.read()))
                
            except Exception as e:
                print(f"Erreur setattr pour WebAsset. Name: {name}, value: {value}. Erreur: {e!r}")
                return # Config invalide, on ignore
            
            finally:
                if copy_path:
                    try:
                        os.unlink(copy_path)
                    except Exception as e:
                        print(f"Erreur de suppression: {e!r}")
        
        elif name in ("run_config", "init_config",):
            write_path = None
            temp_path = None
            config_path = None
            try:
                last_value = getattr(self, name)
                uuid = str(uuid4())
                temp_path = f"conf_{uuid}.json"
                uuid = str(uuid4())
                write_path = f"conf_{uuid}.json"
                with open(temp_path, "w") as f:
                    json5.dump(last_value, f)
                    
                config_path = validate_and_merge_config(
                    max_size=MAX_CONFIG_SIZE,
                    config_temp_dir=CONFIG_TEMP_DIR,
                    default_config_path=temp_path,
                    user_config_str=json5.dumps(value) if not isinstance(value, str) else value,
                    id=self.id,
                    write_path=write_path
                )
                with open(config_path) as f:
                    value = dict(json5.load(f))
                
            except Exception as e:
                print(f"Erreur setattr pour WebAsset. Name: {name}, value: {value}. Erreur: {e!r}")
            
            finally:
                for path in (temp_path, write_path, config_path):
                    try:
                        if path:
                            os.unlink(path)
                    except Exception as e:
                        print(f"Erreur de suppression: {e!r}")
        super().__setattr__(name, value)
        
        
    def get_config_path(self) -> str:
        """Retourne le chemin du fichier de configuration, en le régénérant si le fichier est manquant.
        
        Returns:
            str: Le chemin du fichier de configuration.
        """
        self.config_path = _get_config_path(self.config_path, self.conf_content)
        if self.init_config is not None:
            self.init_config["config_path"] = self.config_path
        return self.config_path

    @field_validator("source_code_dir")
    @classmethod
    def validate_code_dir(cls, source_code_dir: str):
        """Valide que le répertoire du code source existe et est un répertoire.
        
        Args:
            source_code_dir (str): Chemin à valider.

        Returns:
            str | None: Le chemin validé ou None si vide.

        Raises:
            ObsidianValidationError: Si le chemin n'existe pas ou n'est pas un répertoire.
        """
        if source_code_dir:
            if not os.path.exists(source_code_dir):
                raise ObsidianValidationError("Le répertoire du code source n'existe pas")

            if not os.path.isdir(source_code_dir):
                raise ObsidianValidationError("Le chemin doit être un répertoire")

            return source_code_dir

        return None

    def _validate_fix_allowed(self):
        """Valide que fix_allowed n'est True que si source_code_dir est défini.
        
        Returns:
            bool: La valeur validée de fix_allowed.
        """
        self.fix_allowed = bool(self.fix_allowed and self.source_code_dir)
        return self.fix_allowed

    @model_validator(mode="after")
    def validate_model(self) -> "WebAsset":
        """Validation post-initialisation pour WebAsset.
        
        Garantit la cohérence de fix_allowed et que le chemin de config est valide.

        Returns:
            WebAsset: L'instance validée.
        """
        self._validate_fix_allowed()
        self.get_config_path()
        return self


WebSiteAsset = WebAsset


class WebAppAsset(WebAsset):
    """Asset représentant une application web (étend WebAsset).
    
    Utilise la même structure que WebAsset mais avec un type d'asset différent.
    """
    type: AssetType = AssetType.WEB_APP


# ============================================================================
# NetworkAsset — surveillance réseau (IDS/IPS)
# ============================================================================

class NetworkDeploymentMode(StrEnum):
    """Modes de déploiement réseau pour la surveillance IDS/IPS."""
    GATEWAY = "gateway"
    """
    🌐 Gateway
    Obsidian Hive est lui-même le routeur par lequel tout le trafic passe.
    Aucune config réseau spéciale à faire — la machine voit le trafic nativement, de par sa position.
    """

    SPAN_MIRROR = "span_mirror"
    """
    🔀 Port SPAN/Mirroring
    Un switch physique duplique tout son trafic vers un port dédié, 
    et l'interface d'écoute passe en mode promiscuous (ip link set <iface> promisc on). 
    Utile quand Obsidian Hive n'est pas dans le chemin réseau mais surveille en parallèle.
    """

    BRIDGE = "bridge"
    """
    🌉 Bridge transparent
    Obsidian Hive est inséré physiquement entre deux segments réseau 
    via un pont Linux, et le trafic le traverse sans routage
    visible pour les machines connectées. 
    Il capture depuis l'interface pont tout en laissant le trafic circuler normalement.
    """


class NetworkAsset(AssetItem):
    """Asset pour la surveillance réseau IDS/IPS.
    
    Attributes:
        deployment_mode (NetworkDeploymentMode): Mode de déploiement de la surveillance réseau.
        config_path (str): Chemin du fichier de config IDS. Par défaut DEFAULT_IDS_CONFIG_PATH.
        conf_content (str): Configuration de l'IDS en chaîne JSON.
        every (float): Défini à 0 car cet asset est piloté par événements.
        run_every (bool): Défini à False car piloté par événements.
    """
    type: AssetType = AssetType.NETWORK

    # --- Déploiement / config IDS ---
    deployment_mode: NetworkDeploymentMode = Field(description="Mode de déploiement réseau")
    config_path: str = Field(default=DEFAULT_IDS_CONFIG_PATH, description="Chemin du fichier de config IDS sur disque")
    conf_content: str = Field(description="Configuration de l'IDS/IPS, en string JSON")

    every: float = 0
    run_every: bool = False  # event-driven (subprocess dédié), pas de tâche périodique
    extra_fields: List[str] = Field(default_factory=lambda: ["config_path", "deployment_mode", "conf_content"])
    run_fields: List[str] = Field(default_factory=lambda: ["config_path", "deployment_mode", "conf_content"])
    
    def __setattr__(self, name, value):
        if name in ("conf_content",):
            copy_path = None
            try:
                uuid = str(uuid4())
                base, ext = os.path.splitext(self.config_path)
                copy_path = f"{base}_{uuid}{ext}"
                shutil.copy(self.config_path, copy_path)
                config_path = validate_and_merge_config(
                    max_size=MAX_CONFIG_SIZE,
                    config_temp_dir=CONFIG_TEMP_DIR,
                    default_config_path=copy_path,
                    user_config_str=json5.dumps(value) if not isinstance(value, str) else value,
                    id=self.id,
                    write_path=self.config_path,
                )
                self.config_path = config_path
                with open(config_path) as f:
                    value = json5.dumps(json5.loads(f.read()))
                
            except Exception as e:
                print(f"Erreur setattr pour NetworkAsset. Name: {name}, value: {value}. Erreur: {e!r}")
                return # Config invalide, on ignore
            
            finally:
                if copy_path:
                    try:
                        os.unlink(copy_path)
                    except Exception as e:
                        print(f"Erreur de suppression: {e!r}")
            
        super().__setattr__(name, value)
        
    def get_config_path(self) -> str:
        """Retourne le chemin du fichier de configuration, en le régénérant si le fichier est manquant.
        
        Returns:
            str: Le chemin du fichier de configuration.
        """
        self.config_path = _get_config_path(self.config_path, self.conf_content)
        return self.config_path

    def validate_config_path(self, path: str):
        """Valide que le fichier de configuration existe et contient du JSON valide.
        
        Args:
            path (str): Chemin du fichier de configuration.

        Returns:
            str: Le chemin validé.

        Raises:
            ObsidianValidationError: Si le fichier n'existe pas ou contient du JSON invalide.
        """
        if not path or not os.path.exists(path):
            raise ObsidianValidationError("Le chemin de configuration doit exister")
        try:
            json5.loads(open(path, "r").read())
        except json5.JSONDecodeError:
            raise ObsidianValidationError("Les données de configuration ne sont pas du JSON valide")

        return path

    @model_validator(mode="after")
    def validate_model(self) -> "NetworkAsset":
        """Validation post-initialisation pour NetworkAsset.
        
        Garantit que le chemin de config est valide et que le fichier existe.

        Returns:
            NetworkAsset: L'instance validée.
        """
        self.get_config_path()
        return self

    def interfaces(self):
        """Lit les interfaces réseau depuis le fichier de configuration sur disque.
        
        Le fichier de configuration est la source de vérité (défini par `_setup_deployment`/`conf.update`),
        on ne lit jamais depuis `conf_content` en mémoire pour éviter toute désynchronisation.

        Returns:
            list: Liste des interfaces réseau depuis la configuration, ou liste vide en cas d'erreur.
        """
        path = self.get_config_path()
        with open(path) as f:
            try:
                return dict(json5.load(f)).get("GLOBAL_CONFIG", {}).get("interface", [])
            except Exception:
                return []


# ============================================================================
# ServerAsset — administration/surveillance d'un serveur distant via agent
# ============================================================================

class AgentStatus(StrEnum):
    """Statut de connexion d'un agent serveur."""
    PENDING_INSTALL = "pending_install"  # ServerAsset créé, agent pas encore installé/connecté
    CONNECTED       = "connected"        # canal WS actif, heartbeat reçu récemment
    OFFLINE         = "offline"          # déjà connecté un jour, plus de heartbeat récent
    REVOKED         = "revoked"          # admin a invalidé manuellement (rotation credential, décommission)


class AgentCapabilities(StrEnum):
    """Modules/fonctionnalités majeurs qu'un ServerAsset peut exécuter (niveau activation).
    
    Distinct des `tools` (actions unitaires comme port_scan/read_log) qui vivent
    dans le catalogue d'outils. ANTI_PHISHING couvre à la fois email et URL —
    pas de séparation à ce niveau, contrairement à `Source`/`FixId` qui distinguent
    les deux pour le routage des rapports.
    """
    SCANNER_WEB   = "scanner_web"
    ANTI_PHISHING = "anti_phishing"
    SANDBOX       = "sandbox"
    IDS_IPS       = "ids_ips"
    SIMULATOR     = "simulator"


def list_agent_capabilities():
    """Retourne un dictionnaire des noms de capacités d'agent avec leurs descriptions.
    
    Returns:
        dict: Mapping nom de capacité -> description.
    """
    return {
        "scanner_web": "Permettre de lancer des scans de vulnérabilités web depuis le server",
        "anti_phishing": "Permettre de lancer des analyse de phishing (email, url) depuis le server",
        "sandbox": "Permettre de lancer des analyses de code suspect depuis le server",
        "ids_ips": "Permettre de lancer l'IDS/IPS sur le server",
        "simulator": "Permettre de lancer une simulation d'attaque sur le server",
    }


class ServerAsset(AssetItem):
    """Asset représentant un serveur distant géré via un agent.
    
    Attributes:
        install_token (str | None): Token d'installation à usage unique, None une fois consommé.
        install_token_expires_at (datetime | None): Date d'expiration du token.
        agent_status (AgentStatus): Statut courant de connexion de l'agent.
        last_heartbeat (datetime | None): Timestamp du dernier heartbeat reçu.
        agent_credential_hash (str | None): Hash du credential longue durée (jamais stocké en clair).
        capabilities (List[AgentCapabilities]): Modules majeurs que l'agent peut exécuter.
        installed_modules (List[AgentCapabilities]): Modules réellement installés sur la machine locale.
        system_info (Dict[str, Any]): Informations système rapportées par l'agent.
        allowed_tools (List[str]): Outils explicitement autorisés sur cet asset (fail-closed).
        pending_deletion (bool): Flag indiquant que l'asset est programmé pour suppression.
    """
    type: AssetType = AssetType.SERVER

    # --- Installation ---
    install_token: str | None = Field(
        default=None, 
        description="Token d'installation à usage unique, None une fois consommé",
    )
    install_token_expires_at: datetime | None = Field(
        default=None,
        description="Expiration du token — None tant qu'aucun token n'est généré. Posé explicitement via `generate_install_token()`."
    )

    # --- État de connexion ---
    agent_status: AgentStatus = Field(default=AgentStatus.PENDING_INSTALL, description="État courant de l'agent")
    last_heartbeat: datetime | None = Field(default=None, description="Timestamp du dernier heartbeat reçu")

    # --- Auth agent ↔ central ---
    agent_credential_hash: str | None = Field(
        default=None, description="Hash du credential longue durée — jamais le secret en clair en DB",
        exclude=True
    )

    # --- Capabilities déclarées par l'agent à l'enregistrement/heartbeat ---
    capabilities: List[AgentCapabilities] = Field(
        default_factory=list,
        description="Gros modules que cet agent peut exécuter (relayés ou installables)"
    )
    installed_modules: List[AgentCapabilities] = Field(
        default_factory=list,
        description="Sous-ensemble de capabilities réellement téléchargées/installées localement sur cette machine (ids_ips, simulator — les modules lourds, pas les capabilities relayées)"
    )

    # --- Infos machine, remontées par l'agent (jamais saisies par l'admin) ---
    system_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="Remonté par l'agent au register/heartbeat : os, os_version, arch, hostname, python_version..."
    )

    # --- Contrôle des tools (fail-closed) ---
    allowed_tools: List[str] = Field(
        default_factory=list,
        description="Tools explicitement autorisés sur cet asset — vide par défaut, l'admin active chaque tool un par un (machine appartenant au client, pas à Obsidian Hive)"
    )

    every: float = 0
    run_every: bool = False  # event-driven (canal WS agent), pas de tâche périodique
    pending_deletion: bool = Field(default=False)
    extra_fields: List[str] = Field(default_factory=lambda: [
        "install_token", "install_token_expires_at", "agent_status",
        "last_heartbeat", "agent_credential_hash", "capabilities", "installed_modules",
        "system_info", "allowed_tools", "pending_deletion"
    ])
    special_fields: List[str] = Field(
        default_factory=lambda: [
            "tags", "metadata_", "special_fields", "extra_fields", "run_fields",
            "system_info", "installed_modules", "allowed_tools", "capabilities",
        ],
        description="Champs spéciaux à sérialiser"
    )
    run_fields: List[str] = []

    @model_validator(mode="after")
    def validate_model(self) -> "ServerAsset":
        """Validation post-initialisation pour ServerAsset.
        
        Garantit que le token et l'expiration sont cohérents, et que les tokens
        ne sont présents que lorsque agent_status est PENDING_INSTALL.

        Returns:
            ServerAsset: L'instance validée.

        Raises:
            ObsidianValidationError: Si la cohérence token/expiration est violée.
        """
        if self.install_token and self.agent_status != AgentStatus.PENDING_INSTALL:
            raise ObsidianValidationError("install_token ne devrait exister que tant que agent_status == pending_install")
        if bool(self.install_token) != bool(self.install_token_expires_at):
            raise ObsidianValidationError("install_token et install_token_expires_at doivent être posés/effacés ensemble")
        return self
    
    @staticmethod
    def default_token_expiry(hours: float = 1) -> datetime:
        """Génère une date d'expiration par défaut pour un token d'installation.
        
        La durée par défaut est de 1 heure — assez longue pour exécuter le script
        d'installation sans laisser une fenêtre d'attaque indéfiniment ouverte.

        Args:
            hours (float, optional): Durée de validité du token en heures. Par défaut 1.

        Returns:
            datetime: Timestamp d'expiration.
        """
        return utcnow() + timedelta(hours=hours)
    
    @staticmethod
    def generate_token():
        """Génère un nouveau token d'installation.

        Returns:
            str: Un token unique avec le préfixe 'obds_tok-'.
        """
        return f"obds_tok-{str(uuid4())}"
    
    @staticmethod
    def hash_secret_input(secret: str) -> bytes:
        """Pré-hache un secret avec SHA-256 avant bcrypt.

        Bcrypt tronque/rejette les entrées au-delà de 72 octets, donc on condense
        le secret (potentiellement long) en une empreinte fixe de 32 octets avant
        de le passer à bcrypt. Retourne le digest binaire brut (pas hexadécimal) —
        bcrypt n'a pas besoin qu'il soit imprimable.

        Args:
            secret (str): Le secret à hacher.

        Returns:
            bytes: Digest SHA-256 du secret.
        """
        import hashlib
        return hashlib.sha256(secret.encode()).digest()

    def generate_install_token(self, hours: float = 1) -> str:
        """Génère un nouveau token d'installation et définit son expiration.
        
        Les deux champs sont toujours définis ensemble (cf. validate_model).

        Args:
            hours (float, optional): Durée de validité du token en heures. Par défaut 1.

        Returns:
            str: Le token d'installation généré.
        """
        # prefix: obsidian_server_asset: obds_tok
        self.install_token = self.generate_token()
        self.install_token_expires_at = self.default_token_expiry(hours)
        self.agent_status = AgentStatus.PENDING_INSTALL
        return self.install_token

    def consume_install_token(self) -> None:
        """Invalide le token d'installation après un enregistrement agent réussi.
        
        Le token ne peut pas être réutilisé après le premier enregistrement réussi.
        """
        self.install_token = None
        self.install_token_expires_at = None
    
    def is_install_token_valid(self, token: str) -> bool:
        """Vérifie si un token fourni est valide pour cet asset serveur.

        Args:
            token (str): Le token à valider.

        Returns:
            bool: True si le token correspond et n'a pas expiré.
        """
        if not self.install_token or not self.install_token_expires_at:
            return False
        if self.install_token != token:
            return False
        return utcnow() < self.install_token_expires_at
    
    @staticmethod
    def is_server_asset_token(token: str):
        """Vérifie si une chaîne de token a le format d'un token d'asset serveur.

        Args:
            token (str): Le token à vérifier.

        Returns:
            bool: True si le token commence par 'obds_tok' et a la bonne longueur.
        """
        if not token:
            return False
        
        token = str(token)
        return token.startswith("obds_tok") and len(token) == len(ServerAsset.generate_token())
    
    @staticmethod
    def status_is_invalide_for_register(status: AgentStatus):
        """Vérifie si un statut d'agent empêche l'enregistrement.

        Args:
            status (AgentStatus): Le statut à vérifier.

        Returns:
            bool: True si l'agent est REVOKED ou CONNECTED.
        """
        return str(status) in (
            AgentStatus.REVOKED.value,
            AgentStatus.CONNECTED.value
        )
    
    @staticmethod
    def generate_secret():
        """Génère un secret aléatoire cryptographiquement sécurisé.

        Returns:
            str: Token aléatoire encodé en base64 URL-safe de 64 octets.
        """
        import secrets
        return secrets.token_urlsafe(64)
    
    def is_revoked(self):
        """Vérifie si le statut de l'agent est REVOKED.

        Returns:
            bool: True si agent_status est REVOKED.
        """
        return self.agent_status.value == AgentStatus.REVOKED.value
    
    def revoke(self):
        """Révoque les credentials de l'agent et passe le statut à REVOKED.

        Returns:
            bool: True indiquant une révocation réussie.
        """
        self.agent_status = AgentStatus.REVOKED
        self.agent_credential_hash = None
        return True


# ============================================================================
# Mapping des classes d'assets, utilisé pour le dispatch par `type`
# ============================================================================

ASSET_CLASS_MAPPING = {
    cls.__name__: cls
    for cls in (
        asset_cls for asset_cls in (
            AssetItem, WebAppAsset, WebAsset,
            NetworkAsset, ServerAsset
        )
    )
}