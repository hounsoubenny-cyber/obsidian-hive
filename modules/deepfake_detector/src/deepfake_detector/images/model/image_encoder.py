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
import torchvision as tvision
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import zstandard as zstd
from transformers import AutoModel
from diskcache import Cache
from random import shuffle
from deepfake_detector.deepfake_utils.logger import get_logger
from deepfake_detector.images.model.model import DeepFakeDetectorImageProcessor
from deepfake_detector.deepfake_utils.signal_manager import signal_manager

logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CACHE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "./image_encoder_cache"))
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

class ImageEncoder(nn.Module):
    def __init__(
        self, 
        image_model_path_or_image_model:str, 
        d_model:int, 
        model_type:str,
        num_layer_to_freeze:int|float = 0.5, 
        dropout:float = 0.2, 
        cls_only:bool = False,
    ):
        super().__init__()
        self._params = dict(
            d_model=d_model,
            image_model_path_or_image_model=image_model_path_or_image_model,
            num_layer_to_freeze=num_layer_to_freeze,
            dropout=dropout,
            cls_only=cls_only,
            model_type=model_type
        )
        self.model_match = {
            "very_fast": "encoder",
            "ViTModel": "encoder",
            
            "fast": "encoder",
            "CLIPModel": "encoder",
            
            "full": "encoder",
        }
        self.build(**self._params)
        self.image_model_path_or_image_model = image_model_path_or_image_model
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
    
    def _get_encoder_layer_name(self, model_name:str, model_type:str):
        encoder_layer_name = self.model_match.get(model_name, self.model_match.get(model_type))
        if not encoder_layer_name:
            raise ValueError("Model inconnue !")
        return encoder_layer_name
    
    def build(
        self, 
        image_model_path_or_image_model:str|AutoModel, 
        d_model:int, 
        model_type:str,
        num_layer_to_freeze:int|float, 
        dropout:float,
        cls_only:bool = False,
    ):
        if isinstance(image_model_path_or_image_model, str):
            self.model = AutoModel.from_pretrained(image_model_path_or_image_model)
        else:
            self.model = image_model_path_or_image_model
        
        if type(self.model).__name__ == "CLIPModel": # CLIP
            self.model = self.model.vision_model
        encoder_layer_name = self._get_encoder_layer_name(model_type, type(self.model).__name__)
        num_layers = len(getattr(self.model, encoder_layer_name).layers)
        half = num_layers // 2
        if isinstance(num_layer_to_freeze, float):
            num_layer_to_freeze = int(num_layer_to_freeze * num_layers)
        
        num_layer_to_freeze = min(max(num_layer_to_freeze, half),  -5) # Eviter 0 et eviter de depasser le max
        
        for layer in getattr(self.model, encoder_layer_name).layers[:num_layer_to_freeze]: # Geler certaine layer de encoder
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
    
    def forward(self, processor_output:dict, output2d:bool = False):
        x = self.model(**processor_output)
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
    
    def get_key(self, processor_output:dict):
        dict_str = str(processor_output) + self._params["model_type"]
        return hashlib.md5(dict_str.encode()).hexdigest()
    
    def get_cache_key(self, output2d:bool = False):
        return "output2d" if output2d else "output3d"
    
    def cache(self, processor_output:dict, embedding:torch.Tensor, output2d:bool = False):
        key = self.get_key(processor_output)    
        cache_key = self.get_cache_key(output2d=output2d)
        cache = _CACHE.get(cache_key, default={})
        cache[key] = embedding.tolist()
        _CACHE.set(cache_key, cache, expire=CACHE_EXPIRE)
        return True
    
    def get_value(self, processor_output:dict, output2d:bool = False):
        key = self.get_key(processor_output)
        cache_key = self.get_cache_key(output2d=output2d)
        cache = _CACHE.get(cache_key, default={})
        if key in cache:
            return torch.tensor(cache.get(key))
        else:
            return None
        
    def predict(self, processor_output:dict, cache:bool = True, output2d:bool = False):
        self.eval()
        with torch.inference_mode():
            if cache:
                cached = self.get_value(processor_output, output2d=output2d)
                if cached is not None:
                    return torch.tensor(cached, device=DEVICE, dtype=torch.float32)
                
            embedding = self(processor_output, output2d=output2d)
            if cache:
                self.cache(processor_output, embedding=embedding, output2d=output2d)
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
                cop = {**self._params}
                if self.image_model_path_or_image_model:
                    cop.pop("image_model_path_or_image_model")
                    self.build(**cop, image_model_path_or_image_model=self.image_model_path_or_image_model)
                else:
                    self.build(**cop)
                self.build(**self._params)  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                self.to(DEVICE)
                logger.print("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur lors du chargement du modèle :", str(e))
                return
            
        logger.print("Erreur : Chemin inexistant !")


class ImageEncoderDataset(torch.utils.data.Dataset):
    EXT = (".jpg", ".jpeg", ".png", ".ppm", ".bmp", ".pgm", ".tif", ".tiff", ".webp")
    def __init__(
        self, 
        root_path:str,
        features_extractor:callable,
        classes_match:dict,
        transform:DeepFakeDetectorImageProcessor = None
    ):
        super().__init__()
        self.training = False
        self._train_is_called = False
        if not transform:
            raise RuntimeError("Transform Manquant !")
        self.root_path = root_path
        self.features_extractor = features_extractor
        self._classes_match = classes_match
        self.transform = transform
        

    def get_data(self, root_path):
        data = []
        if self.training:
            for classe in self.classes:
                path = os.path.abspath(os.path.join(root_path, classe))
                if os.path.isdir(path):
                    for path_ in os.listdir(path):
                        if os.path.splitext(path_)[-1].strip().lower() in self.EXT:
                            data.append((os.path.join(path, path_), classe))
        else:
            if os.path.isdir(root_path):
                for path_ in os.listdir(root_path):
                    if os.path.splitext(path_)[-1] in self.EXT:
                        data.append((os.path.join(path, path_), None))
        
        shuffle(data)
        return data
        
    def build(self):
        self.classes = os.listdir(self.root_path)
        self.classes_idx =  self.get_idx(self.classes)
        self.idx_to_classe = dict(zip(self.classes_idx, self.classes))
        self.classe_to_idx = self._classes_match
        self.data = self.get_data(self.root_path)
        self.taille = len(self.data)
        
            
    def get_idx(self, classes:str|list[str]):
        if isinstance(classes, str):
            return self._classes_match[classes]
        return [self._classes_match[classe] for classe in classes]
        
    def eval(self):
        self.train(True)
    
    def train(self, mode:bool = True):
        if not self._train_is_called:
            self.training = mode
            self._train_is_called = True
        raise RuntimeError("self.train appelé plus d'une fois !")
    
    def __len__(self):
        return self.taille
    
    def __getitem__(self, index):
        path, label = self.data[index]
        img = tvision.datasets.folder.pil_loader(path)
        label = self.classe_to_idx[label]
            

        self.transform.train(self.training)
        processsor_output = self.transform(img)
        
        return {
             **processsor_output,
             "label" :label
        }
    