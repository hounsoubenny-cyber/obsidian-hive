#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 10 23:32:08 2026

@author: hounsousamuel
"""

"""
config.py — chargement et persistance de la config locale de l'agent ServerAsset
"""

import os
import tomllib
import tomli_w
import copy
from pydantic import BaseModel, PrivateAttr, Field
from dotenv import load_dotenv
load_dotenv()

DEFAULT_CONFIG_PATH = "/opt/obsidian-agent/config.toml"


def _resolve_config_path(path: str | None = None) -> str:
    load_dotenv()
    return path or os.environ.get("OBSIDIAN_AGENT_CONFIG_PATH", DEFAULT_CONFIG_PATH)


class AgentConfig(BaseModel):
    asset_id: str
    central_http_url: str
    central_ws_url: str
    register_path: str
    download_tool_engine_path: str
    secret: str | None = None
    pending_token: str | None = None
    heartbeat_interval: float = 30.0
    ack_timeout: float = 10.    
    capabilities: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)

    _path: str = PrivateAttr(default="")

    @classmethod
    def load(cls, path: str | None = None) -> "AgentConfig":
        resolved_path = _resolve_config_path(path)
        with open(resolved_path, "rb") as f:
            data = tomllib.load(f)
        config = cls(**data)
        config._path = resolved_path
        return config

    def _current_path(self) -> str:
        return self._path or _resolve_config_path()

    def persist(self):
        """
        Réécrit le fichier en entier avec l'état actuel (secret compris).
        Écriture atomique (tmp + os.replace) pour éviter un fichier à moitié
        écrit si le process meurt en plein milieu. Permissions 600 forcées
        avant le remplacement — pas de fenêtre où le fichier serait lisible
        par d'autres.
        """
        path = self._current_path()
        data = {k: v for k, v in self.model_dump().items() if v is not None}
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "wb") as f:
            tomli_w.dump(
                data,
                f,
            )
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)

    def reload(self):
        """Recharge depuis le disque — utile seulement en cas de modif externe du fichier."""
        path = self._current_path()
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def set_secret(self, secret: str):
        """Nouveau secret (première registration ou rotation) — persisté immédiatement."""
        self.secret = secret
        self.pending_token = None
        self.persist()
    
    def update(self, data: dict, persist: bool = True):
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        if persist:
            self.persist()