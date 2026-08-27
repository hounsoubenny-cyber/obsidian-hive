#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 15:30:42 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import io
import hashlib
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import zstandard as zstd
from transformers import AutoModel, AutoTokenizer
from diskcache import Cache
from deepfake_detector.deepfake_utils.logger import get_logger
from deepfake_detector.deepfake_utils.signal_manager import signal_manager

logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CACHE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "./text_encoder_cache"))
_CACHE = Cache(CACHE_DIR)
CACHE_EXPIRE = None
def put_default():
    keys = [("output2d", {}), ("output3d", {})]
    for k, v in keys:
        if k not in _CACHE:
            _CACHE.set(k, v, expire=CACHE_EXPIRE)

def _sig_handler(*args, **kwargs):
    if hasattr(_CACHE, "close"):
        _CACHE.close()

signal_manager(_sig_handler)
put_default()

class TextEncoder(nn.Module):
    def __init__(
        self, 
        bert_path_or_bert:str, 
        d_model:int, 
        model_type:str,
        num_layer_to_freeze:int|float = 0.5, 
        dropout:float = 0.2, 
        cls_only:bool = False,
    ):
        super().__init__()
        self._params = dict(
            d_model=d_model,
            bert_path_or_bert=bert_path_or_bert,
            num_layer_to_freeze=num_layer_to_freeze,
            dropout=dropout,
            cls_only=cls_only,
            model_type=model_type
        )
        self.model_match = {
            "very_fast": "transformer",
            "DistilBertModel": "transformer",
            
            "fast": "encoder",
            "RobertaModel": "encoder",
            
            "full": "encoder",
            "XLMRobertaModel": "encoder",
        }
        self.bert_path_or_bert = bert_path_or_bert
        self.build(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
    
    def _get_encoder_layer_name(self, model_name:str, model_type:str):
        encoder_layer_name = self.model_match.get(model_name, self.model_match.get(model_type))
        if not encoder_layer_name:
            raise ValueError("Model inconnue !")
        return encoder_layer_name
    
    def build(
        self, 
        bert_path_or_bert:str, 
        d_model:int, 
        model_type:str,
        num_layer_to_freeze:int|float, 
        dropout:float,
        cls_only:bool = False,
    ):
        if isinstance(bert_path_or_bert, str):
            self.model = AutoModel.from_pretrained(bert_path_or_bert)
        else:
            self.model = bert_path_or_bert
        
        encoder_layer_name = self._get_encoder_layer_name(model_type, type(self.model).__name__)
        num_layers = len(getattr(self.model, encoder_layer_name).layer)
        half = num_layers // 2
        if isinstance(num_layer_to_freeze, float):
            num_layer_to_freeze = int(num_layer_to_freeze * num_layers)
        
        num_layer_to_freeze = min(max(num_layer_to_freeze, half),  -5) # Eviter 0 et eviter de depasser le max
        for layer in getattr(self.model, encoder_layer_name).layer[:num_layer_to_freeze]: # Geler certaine layer de encoder
            for params in layer.parameters():
                params.requires_grad = False
        
        self.model = self.model.to(DEVICE)
        self.pool_norm = nn.LayerNorm(5 * d_model)
        self.pool = nn.Sequential(
            nn.Linear(in_features=5 * d_model, out_features=d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        
        self.head = nn.Sequential(
            nn.LayerNorm(self.model.config.hidden_size),
            nn.Linear(in_features=self.model.config.hidden_size, out_features=d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.LayerNorm(d_model)
        )
    
    def forward(self, tokenizer_output:dict, output2d:bool = False):
        x = self.model(**tokenizer_output)
        if self._params["cls_only"]:    
            x = x.last_hidden_state[:, 0, :].unsqueeze(1) # Prendre le CLS, alternative x.pooler_output
        else:
            x = x.last_hidden_state
        
        x = x.float()
        x = self.head(x)
        if output2d:
            cls = x[:, 0, :]
            x = x[:, 1:, :]
            mean = x.mean(dim=1)
            max = x.max(dim=1).values
            min = x.min(dim=1).values
            std = x.std(dim=1)
            x = self.pool_norm(torch.cat([cls, mean, std, max, min], dim=-1))
            x = self.pool(x) # On passe a 2d
        x = nn.functional.normalize(x, p=2, dim=-1)
        return x
    
    def get_key(self, tokenizer_output:dict):
        dict_str = str(tokenizer_output) + self._params["model_type"]
        return hashlib.md5(dict_str.encode()).hexdigest()
    
    def get_cache_key(self, output2d:bool = False):
        return "output2d" if output2d else "output3d"
    
    def cache(self, tokenizer_output:dict, embedding:torch.Tensor, output2d:bool = False):
        key = self.get_key(tokenizer_output)    
        cache_key = self.get_cache_key(output2d=output2d)
        cache = _CACHE.get(cache_key, default={})
        cache[key] = embedding.tolist()
        _CACHE.set(cache_key, cache, expire=CACHE_EXPIRE)
        return True
    
    def get_value(self, tokenizer_output:dict, output2d:bool = False):
        key = self.get_key(tokenizer_output)
        cache_key = self.get_cache_key(output2d=output2d)
        cache = _CACHE.get(cache_key, default={})
        if key in cache:
            return torch.tensor(cache.get(key))
        else:
            return None
        
    def predict(self, tokenizer_output:dict, cache:bool = True, output2d:bool = False):
        self.eval()
        with torch.inference_mode():
            if cache:
                cached = self.get_value(tokenizer_output, output2d=output2d)
                if cached is not None:
                    return torch.tensor(cached, device=DEVICE, dtype=torch.float32)
                
            embedding = self(tokenizer_output, output2d=output2d)
            if cache:
                self.cache(tokenizer_output, embedding=embedding, output2d=output2d)
            return embedding.float()
        
    def save(self, path:str):
        try:
            to_save = {
                "model_state_dict": self.state_dict(),
                "params": self._params
                }
            torch.save(to_save, path)
            logger.print(f"Modèle sauvegardé avec succès dans {path} !")
        except Exception as e:
            logger.print("Erreur de sauvegarde du modèle :", str(e))
    
    def _clean_state_dict(self, state_dict: dict, prefix = "_orig_mod.") -> dict:
        return {
            str(k).removeprefix(prefix) : v
            for k, v in state_dict.items()
        }
    
    def load(self, path:str):
        if os.path.exists(path):
            try:
                loaded = torch.load(path, weights_only=False, map_location=DEVICE)
                self._params = loaded["params"]
                state_dict = self._clean_state_dict(loaded["model_state_dict"])
                cop = {**self._params}  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                if self.bert_path_or_bert:
                    cop.pop("bert_path_or_bert")
                    self.build(**cop, bert_path_or_bert=self.bert_path_or_bert)
                else:
                    self.build(**cop)
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                self.to(DEVICE)
                logger.print("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur lors du chargement du modèle :", str(e))
                return
            
        logger.print("Erreur : Chemin inexistant !")


class TextEncoderDataset(torch.utils.data.Dataset):
    def __init__(
        self, 
        tokenizer_or_model:str|AutoTokenizer,
        text_dataset_path_or_df:str|pd.DataFrame,
        max_length:int = 20_000_000,
    ):
        super().__init__()
        if isinstance(text_dataset_path_or_df, pd.DataFrame):
            self.text_dataset = text_dataset_path_or_df
    
        else:
            self.text_dataset = pd.DataFrame(self.get_good_func(text_dataset_path_or_df)(text_dataset_path_or_df))
        
        assert "text" in self.text_dataset and "label" in self.text_dataset, "Certaines columns manquent"
        self.taille = len(self.text_dataset)
        self.max_length = max_length
        if not isinstance(tokenizer_or_model, str):
            self.tokenizer = tokenizer_or_model
        else:
            self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_or_model)
        
    def get_good_func(self, file:str):
        func = pd.read_csv
        if file.endswith(".json"):
            func = pd.read_json
        elif file.endswith(".pkl"):
            func = pd.read_pickle
        else:
            raise ValueError("Format de fichier non accepté !")
        
        return func(file)
    
    def __len__(self):
        return self.taille
    
    def __getitem__(self, index):
        text = self.text_dataset.loc[:, "text"][index]
        label = torch.tensor(self.text_dataset.loc[:, 'label'][index])
        output = self.tokenizer(
            str(text), # On veut 1d et le dataloader va retourner 2d
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        ids:torch.Tensor = output["input_ids"].squeeze()
        attn_mask:torch.Tensor = output["attention_mask"].squeeze()
        tokenizer_output = {
            **output,
            "input_ids": ids,
            "attention_mask": attn_mask,
        }
        return {
            **tokenizer_output,
            "label" :label
        }



    
        