#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 14:21:58 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import io
import PIL.Image
import torchvision as tvision
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import zstandard as zstd
from transformers import AutoImageProcessor
from random import shuffle
from deepfake_detector.deepfake_utils.logger import get_logger

logger = get_logger()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class TransformerLayer(nn.Module):
    def __init__(
        self, 
        d_model:int,
        num_heads:int,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
    ):
        assert d_model % num_heads == 0, "d_model doit être divisible par num_heads !"
        super().__init__()
        self._dropout = dropout
        self.attention = nn.MultiheadAttention(
            batch_first=True,
            embed_dim=d_model,
            dropout=dropout,
            device=DEVICE,
            num_heads=num_heads
        )
        dim_feed_forward_hidden = d_model * feed_forward_factor
        self.feed_forward = nn.Sequential(
            nn.Linear(d_model, dim_feed_forward_hidden),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim_feed_forward_hidden, d_model)
        )
        self.layer_norm1 = nn.LayerNorm(d_model)
        self.layer_norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(self._dropout)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
        
    def forward(self, x):
        x_norm = self.layer_norm1(x)
        attention, _ = self.attention(x_norm, x_norm, x_norm, need_weights=False)
        x = x + self.dropout(attention)
        x = x + self.dropout(self.feed_forward(self.layer_norm2(x)))
        return x

class Transformer(nn.Module):
    def __init__(
        self, 
        d_model:int,
        num_heads:int,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer:int = 4,
    ):
        assert num_layer >= 1, "Le nombre de layers doit être supérieur ou égal à 1"
        super().__init__()
        self.layers = nn.ModuleList([
                TransformerLayer(d_model, num_heads, feed_forward_factor, dropout)
                for _ in range(num_layer)
            ])
        self.layer_norm = nn.LayerNorm(d_model)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
        
    def forward(self, x):
        for layer in self.layers:
            x = layer(x)
        
        return self.layer_norm(x)
    
        
class DeepFakeDetectorImage(nn.Module):
    def __init__(
        self,
        d_model:int,
        num_heads:int,
        num_features:int,
        ml_proba_features:int = 1,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer:int = 4,
        num_classe:int = 2,    # JE compte utiliser cross entropy loss, plus intuitif et moins de problème
        cls_only:bool = False,
        n_layers:int = 100
    ):
        assert num_classe >= 1, "Le nombre de classe doit être supérieur ou égal à 1"
        super().__init__()
        self._params = dict(
            d_model=d_model, 
            num_heads=num_heads, 
            feed_forward_factor=feed_forward_factor,
            dropout=dropout,
            num_layer=num_layer,
            num_classe=num_classe,
            num_features=num_features,
            ml_proba_features=ml_proba_features,
            cls_only=cls_only,
            n_layers=n_layers
        )
        self.build(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
    
    def build(
        self, 
        d_model:int,
        num_heads:int,
        num_features:int,
        ml_proba_features:int = 1,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer:int = 4,
        num_classe:int = 2,
        cls_only:bool = False,
        n_layers:int = 100
    ):
        self.transformer = Transformer(
            num_heads=num_heads,
            d_model=d_model,
            dropout=dropout,
            feed_forward_factor=feed_forward_factor,
            num_layer=num_layer
        )
        self.feature_head = nn.Linear(
            in_features=num_features,
            out_features=d_model,
            bias=True,
        )
        self.pool_norm = nn.LayerNorm(5 * d_model)
        self.pool = nn.Sequential(
            nn.Linear(in_features=5 * d_model, out_features=d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.head = nn.Sequential(
            nn.Linear(
                in_features=d_model, out_features=d_model * feed_forward_factor
            ),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(
                in_features=d_model * feed_forward_factor,
                out_features=num_classe,
            )
        )
        self.norm = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, embeddings:torch.Tensor, features:torch.Tensor|np.ndarray):
        if not isinstance(features, torch.Tensor):
            features = torch.tensor(features, device=DEVICE)
        
        features = features.float()
        embeddings = embeddings.float()
        features:torch.Tensor = self.feature_head(features)
        # Embedding, shape 2d, [batch, d_model] ou 3d shape [batch, seq_len, d_model]
        # Features shape 2d, [batch, d_model]
        if self._params["cls_only"]:    
            if embeddings.ndim == 3:
                embeddings = embeddings[:, 0, :] # Prendre le premier en supposant cls token
            x:torch.Tensor = torch.stack([embeddings, features], dim=1)  # Car transformer attention attend 3d
        else:
            if embeddings.ndim < 3:
                embeddings = embeddings.unsqueeze(1) # Passer a 3d
            if self._params["n_layers"]:
                embeddings = embeddings[:, :self._params["n_layers"], :]
            features = features.unsqueeze(1)
            x = torch.cat([embeddings, features], dim=1)
        x = self.norm(x)
        x = self.transformer(x)
        x = self.dropout(x)
        cls = x[:, 0, :]
        x = x[:, 1:, :]
        mean = x.mean(dim=1)
        max = x.max(dim=1).values
        min = x.min(dim=1).values
        std = x.std(dim=1)
        x = self.pool_norm(torch.cat([cls, mean, std, max, min], dim=-1))
        x = self.pool(x) # On passe a 2d
        x = self.head(x) 
        return x
    
    def _clean_state_dict(self, state_dict: dict, prefix = "_orig_mod.") -> dict:
        return {
            str(k).removeprefix(prefix) : v
            for k, v in state_dict.items()
        }
    
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
    
    def load(self, path:str):
        if os.path.exists(path):
            try:
                loaded = torch.load(path, weights_only=False, map_location=DEVICE)
                self._params = loaded["params"]
                state_dict = self._clean_state_dict(loaded["model_state_dict"])
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
    
    def predict(
        self, 
        embeddings:torch.Tensor, 
        features:torch.Tensor|np.ndarray,
        logits:torch.Tensor|None = None, 
        threashold:float = 0.5
    ):
        with torch.inference_mode():
            if logits is None:
                logits = self(embeddings=embeddings, features=features)
            
            if self._params["num_classe"] == 1:
                prob = nn.functional.sigmoid(logits)  
                pred = (prob > threashold).long()
                return prob, pred
            
            else :
                prob = nn.functional.softmax(logits, dim=-1)
                pred = torch.argmax(prob, dim=-1).long()
                return prob, pred
    

class DeepFakeDetectorImageProcessor(nn.Module):
    def __init__(self, resize:int = 256, is_vit:bool = True, processor:AutoImageProcessor|None = None):
        super().__init__()
        self._params = dict(
            resize=resize,
            processor=processor
            
        )
        if not processor:
            raise RuntimeError("Processor Manquant !")
            
        self.is_vit = is_vit
        self.build(**self._params)
    
    def build(
        self, 
        resize:int = 256,
        processor = None
    ):
        self.processor = processor
        self.resize_processor = tvision.transforms.v2.Resize(size=resize)
        self.train_processor = tvision.transforms.v2.Compose([
            tvision.transforms.v2.CenterCrop(size=resize),
            tvision.transforms.v2.RandomSolarize(0.2),
            tvision.transforms.v2.RandomResizedCrop(size=resize),
            tvision.transforms.v2.RandomHorizontalFlip(),
            tvision.transforms.v2.RandomRotation(degrees=15),
            tvision.transforms.v2.ColorJitter(
                brightness=0.2,
                contrast=0.2,
                saturation=0.2
                ),
            tvision.transforms.v2.ToImage(),
            tvision.transforms.v2.ToDtype(torch.float32, scale=True)
        ])
        self.eval_processor = tvision.transforms.v2.Compose([
            tvision.transforms.v2.CenterCrop(size=resize),
            tvision.transforms.v2.ToTensor(),
        ])
        if self.is_vit:
            if self.processor is None:
                self.train_processor = tvision.transforms.v2.Compose([
                    tvision.transforms.v2.CenterCrop(size=resize),
                    tvision.transforms.v2.RandomSolarize(0.2),
                    tvision.transforms.v2.RandomResizedCrop(size=resize),
                    tvision.transforms.v2.RandomHorizontalFlip(),
                    tvision.transforms.v2.RandomRotation(degrees=15),
                    tvision.transforms.v2.ColorJitter(
                        brightness=0.2,
                        contrast=0.2,
                        saturation=0.2
                        ),
                    tvision.transforms.v2.ToImage(),
                    tvision.transforms.v2.ToDtype(torch.float32, scale=True),
                    tvision.transforms.v2.Normalize(
                        mean=[0.485, 0.456, 0.406],
                        std=[0.229, 0.224, 0.225]
                    )
                ])
                
                self.eval_processor = tvision.transforms.v2.Compose([
                    tvision.transforms.v2.CenterCrop(size=resize),
                    tvision.transforms.v2.ToTensor(),
                    tvision.transforms.v2.Normalize(
                        mean=[0.485, 0.456, 0.406],
                        std=[0.229, 0.224, 0.225]
                    )
                ])
                
        else:
            if self.processor is None:
                self.train_processor = tvision.transforms.v2.Compose([
                    tvision.transforms.v2.CenterCrop(size=resize),
                    tvision.transforms.v2.RandomSolarize(0.2),
                    tvision.transforms.v2.RandomResizedCrop(size=resize),
                    tvision.transforms.v2.RandomHorizontalFlip(),
                    tvision.transforms.v2.RandomRotation(degrees=15),
                    tvision.transforms.v2.ColorJitter(
                        brightness=0.2,
                        contrast=0.2,
                        saturation=0.2
                        ),
                    tvision.transforms.v2.ToImage(),
                    tvision.transforms.v2.ToDtype(torch.float32, scale=True),
                    tvision.transforms.v2.Normalize(
                        mean=[0.48145466, 0.4578275, 0.40821073],
                        std=[0.26862954, 0.26130258, 0.27577711]
                    )
                ])
                
                self.eval_processor = tvision.transforms.v2.Compose([
                    tvision.transforms.v2.CenterCrop(size=resize),
                    tvision.transforms.v2.ToTensor(),
                    tvision.transforms.v2.Normalize(
                        mean=[0.48145466, 0.4578275, 0.40821073],
                        std=[0.26862954, 0.26130258, 0.27577711]
                    )
                ])
        
    def resize(self, input):
        return self.resize_processor(input)
    
    def forward(self, image:PIL.Image.Image, texte:list[str] = ["An AI generated image", "A Natural Image"]):
        if isinstance(image, torch.Tensor):
            image = tvision.transforms.v2.ToPILImage()(image)
            
        image = self.resize(image)
        if self.training:
            image = self.train_processor(image)
            
        else:# On est en eval / Inference
            image = self.eval_processor(image)
        
        if self.is_vit:
            return self.processor(images=image, return_tensors="pt")
        else:
            return self.processor(images=image, text=texte, return_tensors="pt") 
        
    def save(self, path:str):
        try:
            to_save = {
                "model_state_dict": self.state_dict(),
                "params": self._params
                }
            buffer = io.BytesIO()
            torch.save(to_save, buffer)
            buffer.seek(0)
            model = buffer.read()
            model_compressed = zstd.compress(model, level=20)
            with open(path, mode="wb") as f:
                f.write(model_compressed)
                
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
                compressed = None
                with open(path, mode="rb") as f:
                    compressed = f.read()
                decompressed = zstd.decompress(compressed)
                buffer = io.BytesIO(decompressed)
                buffer.seek(0)
                loaded = torch.load(buffer)
                self._params = loaded["params"]
                state_dict = self._clean_state_dict(loaded["model_state_dict"])
                self.build(**self._params)  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                logger.print("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur lors du chargement du modèle :", str(e))
                return
            
        logger.print("Erreur : Chemin inexistant !")
        
class DeepFakeDetectorImageDataset(torch.utils.data.Dataset):
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
        self.train(False)
    
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
        features = torch.tensor(self.features_extractor(img), dtype=torch.float32)
        label = self.classe_to_idx[label]
            
        self.transform.train(self.training)
        processsor_output = self.transform(img)
        processsor_output = {k: v.to(DEVICE) if hasattr(v, "to") else v for k, v in processsor_output.items()}
            
        return {
            **processsor_output,
            "features": features,
            "label" :label
        }
        
    