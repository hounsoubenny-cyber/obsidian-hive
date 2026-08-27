#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 16 20:43:46 2026

@author: hounsousamuel
"""

import os, sys
from llama_cpp.server.app import create_app
from llama_cpp.server.settings import Settings
from simulateur_attaque_ia.simulateur_utils.utils import silence_output

def detect_chat_format(model_name: str) -> str:
    model_name = model_name.lower()
    if "llama-3" in model_name or "llama3" in model_name:
        return "llama-3"
    elif "llama-2" in model_name or "llama2" in model_name:
        return "llama-2"
    elif "phi-3" in model_name or "phi3" in model_name:
        return "chatml"  # Phi-3 utilise ChatML
    elif "gemma" in model_name:
        return "gemma"
    elif "mistral" in model_name and "instruct" in model_name:
        return "mistral-instruct"
    elif "mistral" in model_name or "zephyr" in model_name:
        return "zephyr"
    elif "qwen" in model_name:
        return "qwen"
    elif "chatglm3" in model_name or "chatglm" in model_name:
        return "chatglm3"
    elif "vicuna" in model_name:
        return "vicuna"
    elif "openchat" in model_name:
        return "openchat"
    elif "baichuan" in model_name:
        return "baichuan"
    elif "openbuddy" in model_name:
        return "openbuddy"
    elif "alpaca" in model_name:
        return "alpaca"
    elif "phind" in model_name:
        return "phind"
    elif "deepseek" in model_name:
        # DeepSeek fonctionne bien avec chatml ou llama-3
        return "chatml"
    else:
        # Fallback : le plus générique
        return "chatml"
    
from obsidian_hive.core.managers.llm_managers.llm_manager import LLMManager
    