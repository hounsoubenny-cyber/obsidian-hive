#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 10:53:59 2026

@author: hounsousamuel
"""

"""
core_shared.py

Extrait de core_router.py (split HTTP / WS / shared, août 2026).

Contient tout ce qui est utilisé À LA FOIS par core_router.py (routes HTTP)
et core_ws_router.py (routes WebSocket) : les singletons (engine, ws
managers, confirmer, coralie), les helpers de validation/création d'assets,
et les fonctions register/revoke server agent.
"""

import os
import json5
import shutil
import functools
import socket
from fastapi import HTTPException, status
from pydantic import ValidationError

from obsidian_hive.agents.config import OBSIDIAN_SANDBOX_ROOTS
from obsidian_hive.core.assets.asset_types import ObsidianValidationError, asset_id
from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.managers.main_manager import ObsidianManager  # noqa: F401
from obsidian_hive.core.managers.conversation_manager import ConversationManager
from modules_utils.api_dependencies import AuthManager
from obsidian_hive.core.assets.asset_types import (
    WebAppAsset, WebAsset, NetworkAsset, AssetType,
    ServerAsset, utcnow, AgentStatus as ServerAgentStatus,
)
from obsidian_hive.api.models.models import (
    WebAssetModel, NetworkAssetModel, ServerAssetModel,
    ServerAgentRegisterData, ServerAgentRevokeData,
)
from obsidian_hive.config.config import (
    ENGINE_CONFIG,
    SCANNER_CONF_REQUIRED_KEYS,
    IDS_CONF_REQUIRED_KEYS,
)
from scanner_ia.api.api_config import (
    CONFIG_TEMP_DIR, DEFAULT_SCAN_PATH,
    MAX_CONFIG_SIZE,
)
from scanner_ia.api.api import _resolve_helpers  # noqa: F401 (ré-exporté, utilisé aussi par core_router.py)
from ids_ips_ia.config.config_manager import _config_path as DEFAULT_IDS_CONFIG_PATH
from ids_ips_ia.main.orchestrator import build_ifaces
from modules_utils.validate_config import (
    validate_and_merge_config,
    ConfigError,
)
from obsidian_hive.agents.core.agent import Coralie, create_coralie
from obsidian_hive.agents.shared.human_in_loop import WSConfirmer
from obsidian_hive.api.api_utils.ws_manager import WSManager
from obsidian_hive.api.ap_config import ASSETS_CONFIG_DIR
from modules_utils.keyed_lock import resource_lock
from modules_utils.cryto_utils import hashpw
from obsidian_hive.api.api_utils.server_asset_agent_ws_manager import ServerAgentWSManager

# =============================================================================
# Singletons
# =============================================================================

_engine: ObsidianEngine | None = None

_ws_manager: WSManager | None = None

_confirmer: WSConfirmer | None = None

_coralie: Coralie | None = None

_server_asset_agent_ws_manager: ServerAgentWSManager | None = None


def get_engine() -> ObsidianEngine:
    """
    Retourne l'instance singleton du moteur Obsidian.

    Returns:
        ObsidianEngine: L'instance du moteur.
    """
    global _engine
    if _engine is None:
        _engine = ObsidianEngine(**ENGINE_CONFIG)
    return _engine


def get_ws_manager() -> WSManager:
    """
    Retourne l'instance singleton du gestionnaire WebSocket.

    Returns:
        WSManager: L'instance du WSManager.
    """
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WSManager()

    return _ws_manager


def get_server_agent_ws_manager() -> ServerAgentWSManager:
    """
    Retourne l'instance singleton du gestionnaire WebSocket pour les assets serveurs.

    Returns:
        ServerAgentWSManager: L'instance du ServerAgentWSManager.
    """
    global _server_asset_agent_ws_manager
    if _server_asset_agent_ws_manager is None:
        _server_asset_agent_ws_manager = ServerAgentWSManager()

    return _server_asset_agent_ws_manager


def get_confirmer() -> WSConfirmer:
    """
    Retourne l'instance singleton du confirmer (validation humaine).

    Confirmer singleton — pas de canal attaché tant qu'aucun admin n'est
    connecté (voir ws_route() dans core_ws_router.py : attach()/detach() au
    connect/disconnect).

    Returns:
        WSConfirmer: L'instance du confirmer.
    """
    global _confirmer
    if _confirmer is None:
        _confirmer = WSConfirmer()
    return _confirmer


def get_coralie(state) -> Coralie:
    """
    Retourne l'instance singleton de Coralie (agent principal).

    Coralie singleton, construite avec le confirmer singleton — c'est
    important que ce soit LE MÊME objet confirmer que celui sur lequel on
    fait attach()/detach() dans la route WS, sinon rebrancher le canal
    n'aurait aucun effet sur les tools déjà liés à l'ancienne instance.

    Args:
        state: L'état de l'application FastAPI.

    Returns:
        Coralie: L'instance de Coralie.
    """
    global _coralie
    if _coralie is None:
        _coralie = create_coralie(
            llm_manager=state.llm_manager,
            job_manager=state.job_manager,
            engine=state.core_engine,
            report_manager=state.report_manager,
            confirmer=get_confirmer(),
        )
    return _coralie


def get_auth_manager(state) -> AuthManager:
    """
    Retourne le gestionnaire d'authentification depuis l'état de l'application.

    Args:
        state: L'état de l'application FastAPI.

    Returns:
        AuthManager: Le gestionnaire d'authentification.
    """
    return getattr(state, "auth_manager")


def get_conversation_manager(state) -> ConversationManager:
    """
    Retourne le gestionnaire de conversations depuis l'état de l'application.

    Args:
        state: L'état de l'application FastAPI.

    Returns:
        ConversationManager: Le gestionnaire de conversations.
    """
    return getattr(state, "conversation_manager")


# =============================================================================
# Fonctions utilitaires
# =============================================================================

def check_port_is_open(host, port):
    s = socket.socket()
    r = s.connect_ex((host, port))
    s.close()
    return r != 0

def verify_keys(keys: list, obj: dict, detail: bool = False):
    """
    Vérifie la présence de clés dans un dictionnaire.

    Args:
        keys (list): Liste des clés à vérifier.
        obj (dict): Dictionnaire à inspecter.
        detail (bool, optional): Si True, retourne les clés manquantes.

    Returns:
        tuple: (bool, list | None) - bool indique si toutes les clés sont présentes,
            et la liste des clés manquantes si detail=True.
    """
    if not keys:
        return False, None

    if not detail:
        return all(key in obj for key in keys), None

    missing = []
    for key in keys:
        if key not in obj:
            missing.append(key)

    return len(missing) == 0, missing


def handler_wrapper(func):
    """
    Décorateur pour capturer les exceptions de validation et les transformer
    en HTTPException 406.

    Args:
        func (Callable): La fonction à décorer.

    Returns:
        Callable: La fonction wrapper.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)

        except (ObsidianValidationError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail={"error": str(e), "message": "Erreur de validation du modèle"}
            )

    return wrapper


@handler_wrapper
def handle_web_asset_creating(model: WebAssetModel | dict | str) -> WebAsset | WebAppAsset:
    """
    Traite la création d'un asset web à partir des données du modèle.

    Gère la validation, la configuration du scanner et la copie du code source.

    Args:
        model (WebAssetModel | dict | str): Données de l'asset web.

    Returns:
        WebAsset | WebAppAsset: L'asset web créé.

    Raises:
        HTTPException: 406 si la validation échoue.
        HTTPException: 400 si la configuration est invalide.
    """
    try:
        if isinstance(model, dict):
            model = WebAssetModel.model_validate(model)

        elif isinstance(model, str):
            model = WebAssetModel.model_validate_json(model)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail={"message": "Invalide data", "error": str(e)}
        )

    # Gerer la config
    config_str = model.scan_instance_args.conf_content
    conf_path = model.scan_instance_args.config_path
    _asset_id = asset_id()
    write_config_path = os.path.join(ASSETS_CONFIG_DIR, "web", _asset_id, "config.json5")
    os.makedirs(
        os.path.dirname(write_config_path),
        exist_ok=True
    )
    if config_str:
        try:
            json5.loads(config_str)
        except (ValueError, OSError) as e:
            raise ConfigError(f"JSON5 invalide: {e}")

        defalut_conf_path = DEFAULT_SCAN_PATH
        if conf_path != DEFAULT_SCAN_PATH and os.path.exists(conf_path):
            try:
                json5.loads(open(conf_path).read())
                defalut_conf_path = conf_path
            except ValueError:
                pass

        try:
            config_path = validate_and_merge_config(
                max_size=MAX_CONFIG_SIZE,
                config_temp_dir=CONFIG_TEMP_DIR,
                default_config_path=defalut_conf_path,
                user_config_str=config_str,
                id=model.id,
                write_path=write_config_path
            )
            model.scan_instance_args.config_path = config_path
            model.config_path = os.path.abspath(config_path)
            with open(config_path) as f:
                r = f.read()
                model.conf_content = json5.dumps(json5.loads(r))
        except ConfigError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": "configuration_invalide", "message": str(e)}
            )
    else:
        with open(write_config_path, "w") as f:
            with open(DEFAULT_SCAN_PATH) as f2:
                f2_load = json5.loads(f2.read())
                json5.dump(
                    f2_load,
                    f,
                    indent=2
                )
            model.conf_content = json5.dumps(f2_load)

        model.config_path = os.path.abspath(write_config_path)
    
    has_all, missing = verify_keys(
        obj=json5.loads(open(model.scan_instance_args.config_path).read()),
        detail=True,
        keys=SCANNER_CONF_REQUIRED_KEYS
    )
    if not has_all:
        raise ValueError(f"Some key are missing ({' '.join(missing or [])})")

    init_config = model.scan_instance_args.model_dump(exclude=["conf_content"])
    run_config = model.scan_args
    _resolve_helpers(run_config.helpers)
    run_config.filename = f"{model.id}_{run_config.filename}" if run_config.filename else model.id
    run_config = run_config.model_dump()
    model_dump = model.model_dump(
        exclude=[
            "scan_instance_args", "scan_args", "write_config_path",
            "run_config", "init_config", "manage_immediatly"
        ]
    )
    model_dump["run_config"] = run_config
    model_dump["init_config"] = init_config
    model_dump["url"] = model.scan_args.url
    model_dump["conf_content"] = model.conf_content
    asset_cls = WebAppAsset if model.scan_args.is_spa else WebAsset
    asset: WebAsset | WebAppAsset = asset_cls.model_validate(model_dump)
    if asset.source_code_dir:
        dest_dir = os.path.join(OBSIDIAN_SANDBOX_ROOTS[0], model.id)
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(asset.source_code_dir, dest_dir)
        asset.source_code_dir = dest_dir
        asset._validate_fix_allowed()
    return asset


@handler_wrapper
def handle_network_asset_creating(model: NetworkAssetModel | dict | str) -> NetworkAsset:
    """
    Traite la création d'un asset réseau à partir des données du modèle.

    Gère la validation et la configuration de l'IDS/IPS.

    Args:
        model (NetworkAssetModel | dict | str): Données de l'asset réseau.

    Returns:
        NetworkAsset: L'asset réseau créé.

    Raises:
        HTTPException: 406 si la validation échoue.
        HTTPException: 400 si la configuration est invalide.
    """
    try:
        if isinstance(model, dict):
            model = NetworkAssetModel.model_validate(model)

        elif isinstance(model, str):
            model = NetworkAssetModel.model_validate_json(model)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail={"message": "Invalide data", "error": str(e)}
        )

    # Gerer la config
    config_str = model.conf_content
    conf_path = model.config_path
    _asset_id = asset_id()
    write_config_path = os.path.join(ASSETS_CONFIG_DIR, "net", _asset_id, "config.json5")
    os.makedirs(
        os.path.dirname(write_config_path),
        exist_ok=True
    )
    if config_str:
        try:
            conf = dict(json5.loads(config_str))
            conf.setdefault("GLOBAL_CONFIG", {}).setdefault("interface", None)
            conf["GLOBAL_CONFIG"]["interface"] = build_ifaces(conf["GLOBAL_CONFIG"]["interface"])
            config_str = json5.dumps(conf)
        except (ValueError, OSError) as e:
            raise ConfigError(f"JSON5 invalide: {e}")

        defalut_conf_path = DEFAULT_IDS_CONFIG_PATH
        if conf_path != DEFAULT_IDS_CONFIG_PATH and os.path.exists(conf_path):
            try:
                json5.loads(open(conf_path).read())
                defalut_conf_path = conf_path
            except ValueError:
                pass

        try:
            config_path = validate_and_merge_config(
                max_size=MAX_CONFIG_SIZE,
                config_temp_dir=CONFIG_TEMP_DIR,
                default_config_path=defalut_conf_path,
                user_config_str=config_str,
                id=model.id,
                write_path=write_config_path
            )
            model.config_path = os.path.abspath(config_path)
            with open(config_path) as f:
                model.conf_content = json5.dumps(json5.loads(f.read()))
        except ConfigError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": "configuration_invalide", "message": str(e)}
            )
    else:
        with open(write_config_path, "w") as f:
            with open(DEFAULT_IDS_CONFIG_PATH) as f2:
                f2_load = dict(json5.loads(f2.read()))
                f2_load.setdefault("GLOBAL_CONFIG", {}).setdefault("interface", None)
                f2_load["GLOBAL_CONFIG"]["interface"] = build_ifaces(f2_load["GLOBAL_CONFIG"]["interface"])

                json5.dump(
                    f2_load,
                    f,
                    indent=2
                )
            model.conf_content = json5.dumps(f2_load)

        model.config_path = os.path.abspath(write_config_path)

    has_all, missing = verify_keys(
        obj=json5.loads(open(model.config_path).read()),
        detail=True,
        keys=IDS_CONF_REQUIRED_KEYS
    )
    if not has_all:
        raise ValueError(f"Some key are missing ({' '.join(missing or [])})")
    
    model_dump = model.model_dump(
        exclude=[
            "write_config_path",
            "manage_immediatly",
        ]
    )
    model_dump["conf_content"] = model.conf_content
    return NetworkAsset.model_validate(model_dump)


@handler_wrapper
def handle_server_asset_creating(model: ServerAssetModel | dict | str) -> ServerAsset:
    """
    Traite la création d'un asset serveur à partir des données du modèle.

    Gère la génération du token d'installation.

    Args:
        model (ServerAssetModel | dict | str): Données de l'asset serveur.

    Returns:
        ServerAsset: L'asset serveur créé.

    Raises:
        HTTPException: 406 si la validation échoue.
    """
    try:
        if isinstance(model, dict):
            model = ServerAssetModel.model_validate(model)
        elif isinstance(model, str):
            model = ServerAssetModel.model_validate_json(model)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail={"message": "Invalide data", "error": str(e)}
        )

    model_dump = model.model_dump(exclude=[
        "install_token", "install_token_expires_at", "agent_status",
        "agent_credential_hash", "last_heartbeat", "system_info", "installed_modules",
    ])
    asset: ServerAsset = ServerAsset.model_validate(model_dump)
    asset.generate_install_token()
    return asset


async def register_server_agent(data: ServerAgentRegisterData):
    """
    Enregistre un agent serveur auprès du système.

    Vérifie le token, génère un secret et met à jour l'asset.

    Args:
        data (ServerAgentRegisterData): Données d'enregistrement.

    Returns:
        dict: Résultat de l'enregistrement avec le secret généré.
    """
    engine = get_engine()
    token = data.install_token
    if not token:
        return {
            "status": "error",
            "message": "Veuillez fournir un token"
        }

    # Checker si c'est un token de server asset
    if not ServerAsset.is_server_asset_token(token):
        return {
            "status": "error",
            "message": "Token invalide"
        }

    async with resource_lock.acquire(f"server_register:{token}"):
        # =============================================================================
        # ETAPE 1: Checker si on a un tel asset
        # =============================================================================

        asset = await engine.asset_manager.get_server_asset_by_install_token(token)
        if not asset:
            return {
                "status": "error",
                "message": "Aucun asset server avec un tel token !"
            }

        # =============================================================================
        # ETAPE 2: Checker si l'asset est en mesure d'être enrégistré
        # =============================================================================

        asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset)
        if asset.status_is_invalide_for_register(asset.agent_status):
            return {
                "status": "error",
                "message": "Asset invalide pour régistration !"
            }

        # =============================================================================
        # ETAPE 3: Checker si le token est valide
        # =============================================================================
        if not asset.is_install_token_valid(token):
            return {
                "status": "error",
                "message": "Token invalide !"
            }

        # =============================================================================
        # ETAPE 4: Générer le secret et le hasher et consommer le token
        # =============================================================================
        # Secret
        secret = ServerAsset.generate_secret()
        secret_hash = hashpw(ServerAsset.hash_secret_input(secret))

        # Mettre a jour asset
        asset.consume_install_token()
        asset.agent_credential_hash = secret_hash.decode()
        asset.last_heartbeat = utcnow()
        asset.agent_status = ServerAgentStatus.CONNECTED
        asset.system_info = {**(asset.system_info or {}), **dict(data.system_info)}

        # =============================================================================
        # ETAPE 5: Persister (upsert ou update, ici upset)
        # =============================================================================
        asset = await engine.asset_manager.upsert(asset)
        asset = engine.asset_manager.asset_item_db_to_asset_item(asset)

        # =============================================================================
        # Retourner
        # =============================================================================
        return {
            "status": "success",
            "asset_id": asset.id,
            "item_db_id": asset.item_db_id,
            "secret": secret,
            "allowed_tools": asset.allowed_tools,
            "capabilities": [c.value for c in asset.capabilities],
        }


async def revoke_server_asset(data: ServerAgentRevokeData):
    """
    Révoque un asset serveur.

    Args:
        data (ServerAgentRevokeData): Données de révocation.

    Returns:
        dict: Résultat de la révocation.
    """
    engine = get_engine()
    asset = await engine.asset_manager.get_by_identifier(data.asset_id, first=True)
    if not asset:
        return {
            "status": "error",
            "message": "Asset introuvable !"
        }

    asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset)
    asset.revoke()
    asset = await engine.asset_manager.upsert(asset)
    asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset)
    return {
        "status": "success",
        "asset_id": asset.id,
        "item_db_id": asset.item_db_id
    }


def unlink(path):
    """Supprime un fichier si existant, ignore les erreurs.

    Args:
        path (str): Chemin du fichier à supprimer.
    """
    if path and isinstance(path, str) and os.path.exists(path):
        try:
            os.unlink(path)
        except Exception:
            pass


async def add_asset(asset, asset_data):
    """
    Ajoute un asset au système après validation.

    Args:
        asset: L'asset à ajouter.
        asset_data: Les données associées.

    Returns:
        dict: Résultat de l'ajout.
    """
    engine = get_engine()
    async with resource_lock.acquire("asset:creation"):
        # Checker si overlap interface si network
        if asset.type in (AssetType.NETWORK, ):
            overlap_result = await engine.asset_manager.check_interface_conflict(asset.interfaces())
            if overlap_result["overlap"]:
                unlink(getattr(asset, "config_path", None))
                return {
                    "status": "error",
                    "error": overlap_result["message"]
                }
            
            if not (await engine.asset_manager.check_port_is_available_for_network_asset(asset)):
                unlink(getattr(asset, "config_path", None))
                return {
                    "status": "error",
                    "error": "Port non disponible, veuillez en mettre un autre"
                }
            
        result = await engine.add_asset(
            asset=asset,
            priority=asset.priority,
            manage_immediatly=asset_data.manage_immediatly
        )

    if result["status"] == "error":
        unlink(getattr(asset, "config_path", None))
        return result

    return {
        **result,
        "asset_id": asset.id,
        "asset_data": asset.model_dump(mode="json"),
        "error": None
    }


def _server_error(e: Exception) -> HTTPException:
    """
    Formate une exception en HTTPException 500.

    Args:
        e (Exception): L'exception à formater.

    Returns:
        HTTPException: Une exception HTTP 500 avec les détails.
    """
    print(e)
    import traceback
    traceback.print_exc()
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": str(e), "type": type(e).__name__},
    )


async def _notify_agent_config_updated(
    server_agent_ws_manager: ServerAgentWSManager,
    asset: ServerAsset,
    data: dict | None = None,
):
    """
    Notifie l'agent d'une mise à jour de configuration.

    Push immédiat si l'agent est connecté — pas grave si ça échoue/agent
    offline, le prochain heartbeat_ack rattrapera l'état à jour de toute
    façon (cf. décision : push + filet de sécurité au heartbeat).

    Args:
        server_agent_ws_manager (ServerAgentWSManager): Gestionnaire WS.
        asset (ServerAsset): L'asset serveur.
        data (dict | None, optional): Données supplémentaires.
    """
    if server_agent_ws_manager.is_connected(asset.id):
        await server_agent_ws_manager.send_to(asset.id, {
            "type": "config_update",
            "capabilities": [c.value for c in asset.capabilities],
            "allowed_tools": asset.allowed_tools,
            **(data or {})
        })


async def _update_server_asset_field(asset_id: str, field: str, values: list, add: bool):
    """
    Met à jour un champ de liste d'un asset serveur (capabilities ou allowed_tools).

    Factorise add/remove capabilities et allow/revoke tools — même forme
    exacte des deux côtés (charger, modifier une liste, dédupliquer,
    persister, notifier), seule la sémantique add/retrait change.

    Args:
        asset_id (str): L'ID de l'asset.
        field (str): Le nom du champ à modifier.
        values (list): Les valeurs à ajouter ou retirer.
        add (bool): True pour ajouter, False pour retirer.

    Returns:
        dict: Résultat de l'opération avec l'état mis à jour.
    """
    engine = get_engine()
    server_agent_ws_manager = get_server_agent_ws_manager()

    async with resource_lock.acquire(f"asset:{asset_id}"):
        asset_db = await engine.asset_manager.get_by_identifier(asset_id, first=True)
        if not asset_db:
            return {"status": "error", "message": "Asset introuvable !"}

        asset: ServerAsset = engine.asset_manager.asset_item_db_to_asset_item(asset_db)
        if asset.type != AssetType.SERVER:
            return {"status": "error", "message": "Cet asset n'est pas un ServerAsset"}

        current = getattr(asset, field)
        if add:
            updated = list(current) + [v for v in values if v not in current]
        else:
            updated = [v for v in current if v not in values]
            
        setattr(asset, field, updated)

        asset = await engine.asset_manager.upsert(asset)
        asset = engine.asset_manager.asset_item_db_to_asset_item(asset)

    await _notify_agent_config_updated(server_agent_ws_manager, asset)

    return {
        "status": "success",
        "asset_id": asset.id,
        field: getattr(asset, field),
    }