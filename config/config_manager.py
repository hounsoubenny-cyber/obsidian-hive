#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 11 00:16:28 2026

@author: hounsousamuel
"""

import os
import socket
import tomllib
from pydantic import BaseModel, Field, field_validator, model_validator
from dotenv import load_dotenv, find_dotenv

scanner_conf_required_keys_func = lambda: ['fetcher', 'crawler', 'parser', 'analyzer_helper', 'scanner']
ids_conf_required_keys_func = lambda: [
    'SEUIL', 
    'CRITICAL_PORT', 
    'DANGEROUS_LOCALISATION', 
    'SCORING_CONFIG', 
    'ANOMALY_RATE_THRESHOLDS', 
    'DECAY_CONFIG', 
    'ANOMALY_CONFIG', 
    'CAPTURE_CONFIG', 
    'GLOBAL_CONFIG'
]

def _get_llm_env(name: str, default, cast_to: callable = None, prefix:str = "OBSIDIAN_LLM_MANAGER_"):
    if not name:
        raise ValueError("Name is required")
        
    key = prefix + name
    value = os.environ.get(key, default)
    if value is ...:
        raise RuntimeError(f"The key {key} is required but any value has find for it")
        
    if cast_to:
        value = cast_to(value)
    return value

def _get_api_keys(name: str, default, prefix:str = "OBSIDIAN_LLM_MANAGER_"):
    if not name:
        raise ValueError("Name is required")
    
    i = 1
    api_keys: list[tuple[str, str]] = []
    key = prefix + name + "_" + str(i)
    val = os.environ.get(key, None)
    while val:
        val_split = val.split(",")
        if len(val_split) in (2, 3):
            if len(val_split) == 2:
                model_name, api_key = val_split
                provider = None
            else:
                model_name, provider, api_key = val_split
                provider = provider.strip()
            model_name = model_name.strip()
            api_key = api_key.strip()
            api_keys.append((model_name, provider, api_key))
        i += 1
        key = prefix + name + "_" + str(i)
        val = os.environ.get(key, None)
    
    return api_keys or default

def _validate_path(path: str):
    if not os.path.exists(path):
        raise ValueError("This path doesn't exists")
    return path
        
def _check_port_is_open(host: str, port: int):
    sock = socket.socket()
    try:
        r = sock.connect_ex((host, port))
        if r == 0:
            # raise RuntimeError("Port is not available")
            pass
        
        return host, port
    finally:
        sock.close()
    
class GlobalConfig(BaseModel):
    start_ids_on_start: bool = Field(
        default=True,
        description="Démarrer automatiquement l'IDS/IPS au lancement du système"
    )
    scanner_conf_required_keys: list[str] = Field(
        default_factory=scanner_conf_required_keys_func,
        description="Clés requises pour valider une configuration du scanner web"
    )
    ids_conf_required_keys: list[str] = Field(
        default_factory=ids_conf_required_keys_func,
        description="Clés requises pour valider une configuration de l'IDS/IPS"
    )
    

class EngineConfig(BaseModel):
    db_url: str = Field(
        description="URL de connexion à la base de données (ex: sqlite+aiosqlite:///./shieldai.db)"
    )
    debug: bool = Field(
        default=False,
        description="Mode debug du moteur (true → logs détaillés, false → mode production)"
    )
    
class ApiConfig(BaseModel):
    api_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="Port sur lequel l'API écoute (défaut: 8000)"
    )
    
    @field_validator("api_port")
    @classmethod
    def check_port_is_open(cls, port: int):
        return _check_port_is_open("127.0.0.1", port)[1]
    

class LLMManagerConfig(BaseModel):
    host: str = Field(
        default="127.0.0.1",
        description="Hôte du serveur llama.cpp (127.0.0.1 = serveur local)"
    )
    port: int = Field(
        default=9090,
        ge=1024,
        le=65535,
        description="Port du serveur llama.cpp (défaut: 9090)"
    )
    llama_server_path: str = Field(
        default_factory=lambda: _get_llm_env(name="LLAMA_SERVER_PATH", default=...),
        description="Chemin absolu vers l'exécutable llama-server"
    )
    models_preset: str = Field(
        description="Chemin vers le fichier models.ini listant les modèles GGUF disponibles"
    )
    log_file: str | None = Field(
        default=None,
        description="Fichier de log du serveur llama.cpp (null = fichier auto dans le dossier par défaut)"
    )
    models_max: int = Field(
        default=1,
        ge=1,
        description="Nombre maximum de modèles chargés simultanément (défaut: 1)"
    )
    api_keys: list[tuple[str, str]] = Field(
        default_factory=lambda: _get_api_keys(
            name="API_KEY", 
            default=[("ornith1.0-9b", "local", "local-fake-key")]
        ),
        description="Liste des clés API (modèle, clé) chargée depuis les variables d'environnement"
    )
    wait_timeout: int | float = Field(
        default=120,
        description="Temps d'attente maximum pour le démarrage du serveur (secondes, défaut: 120)"
    )
    
    @field_validator("models_preset")
    @classmethod
    def validate_model_preset(cls, path: str):
        return _validate_path(path)
    
    @field_validator("log_file")
    @classmethod
    def _validate_log_file(cls, path: str | None):
        if not path:
            return path
        return _validate_path(path)
    
    
    @model_validator(mode="after")
    def validate_model(self) -> "LLMManagerConfig":
        _check_port_is_open(self.host, self.port)
        return self
        
    
class AnalystConfig(BaseModel):
    """Configuration de l'agent Analyst (Alex)."""
    
    max_iter: int = Field(
        default=8,
        ge=6,
        description="Nombre maximum d'itérations pour une analyse (défaut: 8)"
    )
    max_retries: int = Field(
        default=3,
        ge=2,
        description="Nombre de tentatives en cas d'échec (défaut: 3)"
    )
    temperature: float = Field(
        default=0.8,
        ge=0.1,
        le=1.0,
        description="Température du modèle (0.0 → déterministe, 1.0 → créatif, défaut: 0.8)"
    )
    max_tokens: int = Field(
        default=32768,
        ge=16384,
        description="Nombre maximum de tokens par réponse (défaut: 32768)"
    )
    system_prompt_mode: str = Field(
        default="full",
        description="Mode du prompt système: 'short' (rapide) ou 'full' (complet, défaut)"
    )
    model_name: str | None = Field(
        default=None,
        description="Nom du modèle LLM à utiliser (null → modèle par défaut du LLMManager)"
    )
    
    @field_validator("system_prompt_mode")
    @classmethod
    def validate_system_prompt_mode(cls, system_prompt_mode: str):
        if not system_prompt_mode in ("full", "short"):
            raise ValueError("system_prompt_mode value is unknown")
        
        return system_prompt_mode

class CoreAgentConfig(BaseModel):
    """Configuration de l'agent Core (Coralie)."""
    
    max_iter: int = Field(
        default=8,
        ge=6,
        description="Nombre maximum d'itérations pour une analyse (défaut: 8)"
    )
    max_retries: int = Field(
        default=3,
        ge=2,
        description="Nombre de tentatives en cas d'échec (défaut: 3)"
    )
    temperature: float = Field(
        default=0.8,
        ge=0.1,
        le=1.0,
        description="Température du modèle (0.0 → déterministe, 1.0 → créatif, défaut: 0.8)"
    )
    max_tokens: int = Field(
        default=32768,
        ge=16384,
        description="Nombre maximum de tokens par réponse (défaut: 32768)"
    )
    system_prompt_mode: str = Field(
        default="full",
        description="Mode du prompt système: 'short' (rapide) ou 'full' (complet, défaut)"
    )
    model_name: str | None = Field(
        default=None,
        description="Nom du modèle LLM à utiliser (null → modèle par défaut du LLMManager)"
    )
    
    @field_validator("system_prompt_mode")
    @classmethod
    def validate_system_prompt_mode(cls, system_prompt_mode: str):
        if not system_prompt_mode in ("full", "short"):
            raise ValueError("system_prompt_mode value is unknown")
        
        return system_prompt_mode
    
class ConfigManager:
    REQUIRED_KEYS = {
        "api": ["api_port"],
        "global": ["start_ids_on_start"],
        "engine_config": ["db_url", "debug"],
        "llm_manager": ["host", "port", "models_preset", "models_max", "wait_timeout"],
        "analyst": ["max_iter", "max_retries", "temperature", "system_prompt_mode", "max_tokens"],
        "core_agent": ["max_iter", "max_retries", "temperature", "system_prompt_mode", "max_tokens"],
    }
    
    def __init__(self):
        self._raw_conf: dict = None
        self.global_config: GlobalConfig = None
        self.engine_config: EngineConfig = None
        self.llm_manager_config: LLMManagerConfig = None
        self.api_config: ApiConfig = None
        self.analyst_config: AnalystConfig = None
        self.core_agent_config: CoreAgentConfig = None
        load_dotenv()
    
    def load_config(self, config_path: str = "config.toml") -> dict:
        with open(config_path, "rb") as f:
            self._raw_conf = tomllib.load(f)
            return self._raw_conf
    
    def validate_config(self, conf: dict = None):
        conf = conf or self._raw_conf
        if conf is None:
            raise RuntimeError("Aucune configuration chargée. Appelez load_config() d'abord.")
        
        missings = []
        for section, keys in self.REQUIRED_KEYS.items():
            if section not in conf:
                missings.append(f"La section '{section}' est manquante dans le fichier de config")
                continue
            
            for key in keys:
                if key not in conf[section]:
                    missings.append(f"La clé '{key}' est manquante dans la section '{section}'")
        
        if missings:
            raise RuntimeError("Erreurs de configuration:\n" + "\n".join(missings))
    
    def build_config(self, config_path: str = "config.toml"):
        self.load_config(config_path)
        self.validate_config()
        load_dotenv()
        
        self.global_config = GlobalConfig(
            start_ids_on_start=self._raw_conf["global"]["start_ids_on_start"]
        )
        
        self.api_config = ApiConfig(
            api_port=self._raw_conf["api"]["api_port"]
        )
        
        self.engine_config = EngineConfig(
            db_url=self._raw_conf["engine_config"]["db_url"],
            debug=self._raw_conf["engine_config"]["debug"]
        )
        
        log_file = self._raw_conf["llm_manager"].get("log_file")
        self.llm_manager_config = LLMManagerConfig(
            host=self._raw_conf["llm_manager"]["host"],
            port=self._raw_conf["llm_manager"]["port"],
            models_preset=self._raw_conf["llm_manager"]["models_preset"],
            log_file=log_file if log_file != "null" and log_file is not None else None,
            models_max=self._raw_conf["llm_manager"]["models_max"],
            wait_timeout=self._raw_conf["llm_manager"]["wait_timeout"],
        )
        
        amodel_name = self._raw_conf["analyst"].get("model_name")
        self.analyst_config = AnalystConfig(
            max_iter=self._raw_conf["analyst"]["max_iter"],
            max_retries=self._raw_conf["analyst"]["max_retries"],
            temperature=self._raw_conf["analyst"]["temperature"],
            max_tokens=self._raw_conf["analyst"]["max_tokens"],
            system_prompt_mode=self._raw_conf["analyst"]["system_prompt_mode"],
            model_name=amodel_name if amodel_name is None else (None if amodel_name == "null" else amodel_name)
        )
        
        cmodel_name = self._raw_conf["core_agent"].get("model_name")
        self.core_agent_config = CoreAgentConfig(
            max_iter=self._raw_conf["core_agent"]["max_iter"],
            max_retries=self._raw_conf["core_agent"]["max_retries"],
            temperature=self._raw_conf["core_agent"]["temperature"],
            max_tokens=self._raw_conf["core_agent"]["max_tokens"],
            system_prompt_mode=self._raw_conf["core_agent"]["system_prompt_mode"],
            model_name=cmodel_name if cmodel_name is None else (None if cmodel_name == "null" else cmodel_name)
        )
        
        return self
    
    def to_dict(self) -> dict:
        return {
            "global": self.global_config.model_dump() if self.global_config else None,
            "api": self.api_config.model_dump() if self.api_config else None,
            "engine": self.engine_config.model_dump() if self.engine_config else None,
            "llm_manager": self.llm_manager_config.model_dump() if self.llm_manager_config else None,
            "analyst": self.analyst_config.model_dump() if self.analyst_config else None,
        }        