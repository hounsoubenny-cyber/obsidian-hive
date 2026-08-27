#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 14:21:58 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import io
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import zstandard as zstd
from transformers import AutoTokenizer
from anti_phishing_ia.phishing_utils.logger import get_logger

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
    
class MailPhishing(nn.Module):
    def __init__(
        self,
        d_model: int,
        num_heads: int,
        feed_forward_factor: int = 4,
        dropout: float = 0.2,
        num_layer: int = 4,
        num_classe: int = 2,    # JE compte utiliser cross entropy loss, plus intuitif et moins de problème
        cls_only: bool = False,
        n_layers: int = 100
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
            cls_only=cls_only,
            n_layers=n_layers
        )
        self.build(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
    
    def build(
        self, 
        d_model: int,
        num_heads: int,
        feed_forward_factor: int = 4,
        dropout: float = 0.2,
        num_layer: int = 4,
        num_classe: int = 2,
        cls_only: bool = False,
        n_layers: int = 100
    ):
        self.transformer = Transformer(
            num_heads=num_heads,
            d_model=d_model,
            dropout=dropout,
            feed_forward_factor=feed_forward_factor,
            num_layer=num_layer
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
    
    def forward(self, embeddings:torch.Tensor):
        embeddings = embeddings.float()
        # Embedding, shape 2d, [batch, d_model] ou 3d shape [batch, seq_len, d_model]
        if self._params["cls_only"]:    
            if embeddings.ndim == 3:
                embeddings = embeddings[:, 0, :] # Prendre le premier en supposant cls token
        if embeddings.ndim < 3:
            embeddings = embeddings.unsqueeze(1) # Passer a 3d
        if self._params["n_layers"]:
            embeddings = embeddings[:, :self._params["n_layers"], :]
            
        x = self.norm(embeddings)
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
                loaded = torch.load(path, map_location=DEVICE, weights_only=False)
                self._params = loaded["params"]
                state_dict = loaded["model_state_dict"]
                state_dict = self._clean_state_dict(state_dict)
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
        logits:torch.Tensor|None = None, 
        threashold:float = 0.5
    ):
        with torch.inference_mode():
            if logits is None:
                logits = self(embeddings=embeddings)
            
            if self._params["num_classe"] == 1:
                prob = nn.functional.sigmoid(logits)  
                pred = (prob > threashold).long()
                return prob, pred
            
            else :
                prob = nn.functional.softmax(logits, dim=-1)
                pred = torch.argmax(prob, dim=-1).long()
                return prob, pred
            
class MailPhishingDataset(torch.utils.data.Dataset):
    def __init__(
        self, 
        tokenizer_or_model:str|AutoTokenizer,
        text_dataset_path_or_df:str|pd.DataFrame,
        max_length:int = 20_000_000,
    ):
        super().__init__()
        if isinstance(text_dataset_path_or_df, pd.DataFrame):
            self.text_dataset = text_dataset_path_or_df
        
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
        
        return func
    
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
        output = {k: v.to(DEVICE) if hasattr(v, "to") else v for k, v in output.items()}
        ids:torch.Tensor = output["input_ids"].squeeze().to(DEVICE)
        attn_mask:torch.Tensor = output["attention_mask"].squeeze().to(DEVICE)
        tokenizer_output = {
            **output,
            "input_ids": ids,
            "attention_mask": attn_mask,
        }
        return {
            **tokenizer_output,
            "label" :label
       }
    

        
        