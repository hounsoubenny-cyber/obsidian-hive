#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mapping des clés API vers les clients LLM
Vérifié avec la documentation officielle de chaque provider
"""

from openai import OpenAI, AsyncOpenAI
from groq import Groq, AsyncGroq
from anthropic import Anthropic, AsyncAnthropic
from cohere import ClientV2 as CohereClient, AsyncClientV2 as AsyncCohereClient    
from typing import Union

API_KEY_MAPPING = {
    "gsk_": {
        "name": "Groq",
        "client_sync_class": Groq,
        "client_async_class": AsyncGroq,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "sk-": {
        "name": "OpenAI",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "sk-or-": {
        "name": "OpenRouter",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://openrouter.ai/api/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://openrouter.ai/api/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "hf_": {
        "name": "HuggingFace Inference",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://api-inference.huggingface.co/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://api-inference.huggingface.co/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "sk-ant": {
        "name": "Anthropic",
        "client_sync_class": Anthropic,
        "client_async_class": AsyncAnthropic,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": ["seed", "frequency_penalty", "presence_penalty"],
    },

    "xai-": {
        "name": "XAI (Grok)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://api.x.ai/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://api.x.ai/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "cohere_": {
        "name": "Cohere",
        "client_sync_class": CohereClient,
        "client_async_class": AsyncCohereClient,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "AIza": {
        "name": "Google AI Studio (Gemini)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "init_kwargs": {"api_key": None, "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/"},
        "skip_model_list": True,
        "unsupported_params": ["seed"],
    },

    "AQ.": {
        "name": "Google AI Studio (Gemini)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "init_kwargs": {"api_key": None, "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/"},
        "skip_model_list": True,
        "unsupported_params": ["seed"],
    },

    "local": {
        "name": "Local LLM (llama.cpp)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": None,
        "init_kwargs": {"api_key": "local-fake-key"},
        "skip_model_list": False,
        "unsupported_params": [],
    },
}

PROVIDER_BY_NAME = {
    "groq": {
        "name": "Groq",
        "client_sync_class": Groq,
        "client_async_class": AsyncGroq,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "openai": {
        "name": "OpenAI",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "openrouter": {
        "name": "OpenRouter",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://openrouter.ai/api/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://openrouter.ai/api/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "huggingface": {
        "name": "HuggingFace Inference",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://api-inference.huggingface.co/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://api-inference.huggingface.co/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "anthropic": {
        "name": "Anthropic",
        "client_sync_class": Anthropic,
        "client_async_class": AsyncAnthropic,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": ["seed", "frequency_penalty", "presence_penalty"],  # Anthropic n'accepte pas ces params OpenAI-style
    },

    "xai": {
        "name": "XAI (Grok)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://api.x.ai/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://api.x.ai/v1"},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "cohere": {
        "name": "Cohere",
        "client_sync_class": CohereClient,
        "client_async_class": AsyncCohereClient,
        "base_url": None,
        "init_kwargs": {"api_key": None},
        "skip_model_list": False,
        "unsupported_params": [],
    },

    "google": {
        "name": "Google AI Studio (Gemini)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "init_kwargs": {"api_key": None, "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/"},
        "skip_model_list": True,
        "unsupported_params": ["seed"],
    },

    "mistral": {
        "name": "Mistral",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": "https://api.mistral.ai/v1",
        "init_kwargs": {"api_key": None, "base_url": "https://api.mistral.ai/v1"},
        "skip_model_list": False,
        "unsupported_params": ["seed"],
    },

    "local": {
        "name": "Local LLM (llama.cpp)",
        "client_sync_class": OpenAI,
        "client_async_class": AsyncOpenAI,
        "base_url": None,
        "init_kwargs": {"api_key": "local-fake-key"},
        "skip_model_list": False,
        "unsupported_params": [],
    },
}

# Modèles par défaut 
DEFAULT_MODELS = {
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
    "openrouter": "openrouter/auto",
    "huggingface": "meta-llama/Llama-3.2-3B-Instruct",
    "anthropic": "claude-sonnet-4-5-20250929",
    "xai": "grok-4.3",
    "cohere": "command-r-plus-08-2024",
    "google": "gemini-3.5-flash-lite",
    "mistral": "mistral-small-latest",
    "local": None,
}

CLIENT_UNION = Union[
    OpenAI, AsyncOpenAI,
    Groq, AsyncGroq,
    Anthropic, AsyncAnthropic,
    CohereClient, AsyncCohereClient,
]
def get_default():
    return {
        "client": API_KEY_MAPPING["local"],
        "default_model": DEFAULT_MODELS["local"],
        "prefix": "local",
    }

def get_client(
    api_key: str,
    raise_: bool = True,
    provider: str | None = None,
) -> dict:
    
    if provider:
        p = provider.lower().strip()
        if p in PROVIDER_BY_NAME:
            return {
                "client": PROVIDER_BY_NAME[p],
                "prefix": p,
                "default_model": DEFAULT_MODELS.get(p),
            }
        if raise_:
            raise ValueError(f"unknown_provider:{provider}")
        return get_default()
    
    for key_start, client_dict in sorted(
        list(API_KEY_MAPPING.items()),
        key=lambda kv: -len(kv[0])
    ):

        if api_key.startswith(key_start):
            return {
                "client": client_dict,
                "prefix": key_start,
                "default_model": DEFAULT_MODELS[key_start]
            }
    if raise_:
        raise ValueError("unknow_key")
    return get_default()

if __name__ == "__main__":
    cases = {
        "gsk_abc123": "gsk_",
        "sk-proj-abc123": "sk-",          # clé OpenAI classique
        "sk-ant-api03-abc123": "sk-ant",  # clé Anthropic — piège sans le fix
        "sk-or-v1-abc123": "sk-or-",      # clé OpenRouter — piège sans le fix
        "hf_abc123": "hf_",
        "xai-abc123": "xai-",
    }
 
    for key, expected_prefix in cases.items():
        result = get_client(key, raise_=False)
        actual = result["prefix"]
        status = "OK" if actual == expected_prefix else "FAIL"
        print(f"[{status}] {key!r:30} -> {actual!r} (attendu: {expected_prefix!r})")
