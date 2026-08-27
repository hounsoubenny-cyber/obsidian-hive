#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 30 11:26:05 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import io
import torch
import torch.nn as nn
import zstandard as zstd
import torch.utils.data as tdata
import numpy as np
import pandas as pd
from transformers import AutoModel, AutoTokenizer
from scanner_ia.scanner_utils.logger import get_logger

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logger = get_logger()

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
        
    def forward(self, x, padding_mask=None):
        x_norm = self.layer_norm1(x)
        attention, _ = self.attention(x_norm, x_norm, x_norm, need_weights=False, key_padding_mask=padding_mask)
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
        assert d_model % num_heads == 0, "d_model doit être divisible par num_heads !"
        super().__init__()
        self.layers = nn.ModuleList([
                TransformerLayer(d_model, num_heads, feed_forward_factor, dropout)
                for _ in range(num_layer)
            ])
        self.layer_norm = nn.LayerNorm(d_model)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(DEVICE)
        
    def forward(self, x):
        padding_mask = (x == 0)
        for layer in self.layers:
            x = layer(x, padding_mask=padding_mask)
        
        return self.layer_norm(x)

class AutoEncoder(nn.Module):
    def __init__(
        self,
        d_model:int,
        num_heads:int,
        num_features: int,
        bert_path_or_bert: str, 
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer_per_encoder_transformer:int = 2,
        num_layer_for_encoder_and_decoder: int = 4,
        max_length: int = 8192,
    ):
        super().__init__()
        self._params = dict(
            d_model=d_model,
            num_heads=num_heads,
            num_features=num_features,
            feed_forward_factor=feed_forward_factor,
            dropout=dropout,
            num_layer_per_encoder_transformer=num_layer_per_encoder_transformer,
            num_layer_for_encoder_and_decoder=num_layer_for_encoder_and_decoder,
            max_length=max_length,
            bert_path_or_bert=bert_path_or_bert
        )
        self.bert_path_or_bert = bert_path_or_bert
        self.build_model(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters(recurse=True))
        
    def build_model(
        self, 
        d_model:int,
        num_heads:int,
        num_features: int,
        bert_path_or_bert: str, 
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer_per_encoder_transformer:int = 2,
        num_layer_for_encoder_and_decoder: int = 4,
        max_length: int = None,
    ):
        
        m = AutoModel.from_pretrained(bert_path_or_bert)
        m.to(DEVICE)
        object.__setattr__(self, 'model',m)
        object.__setattr__(self, 'tokenizer', AutoTokenizer.from_pretrained(bert_path_or_bert))
        for param in self.model.parameters():
            param.requires_grad = False
            
        if num_features == 0 or num_features is None:
            self._params["num_features"] = self.model.config.hidden_size
            num_features = self.model.config.hidden_size
        self.head1 = nn.Linear(
            in_features=num_features,
            out_features=d_model
        )
        self.head2 = nn.Linear(
            in_features=d_model,
            out_features=d_model
        )
        self.head_norm = nn.LayerNorm(d_model)
        self.head_norm1 = nn.LayerNorm(num_features)
        self.head_norm2 = nn.LayerNorm(d_model)
        encoders = []
        d_model_ = d_model
        for _ in range(num_layer_for_encoder_and_decoder):
            # d_model_ = max(d_model_, 16)  # Ne pas allez sous 16
            t = Transformer(
                d_model=d_model_,
                num_heads=num_heads,
                dropout=dropout,
                num_layer=num_layer_per_encoder_transformer,
                feed_forward_factor=feed_forward_factor,
            )
            l = nn.Linear(
                in_features=d_model_,
                out_features=d_model_ // 2
            )
            ac = nn.GELU()
            encoders.extend([t, l, ac] if _ != num_layer_for_encoder_and_decoder - 1 else [t, l])
            d_model_ = d_model_ // 2    
            
        self.encoder = nn.Sequential(*encoders)
        self.memory_projection = nn.Linear(in_features=d_model_, out_features=d_model)
        self.decoder = nn.TransformerDecoder(
            num_layers=num_layer_for_encoder_and_decoder,
            decoder_layer=nn.TransformerDecoderLayer(
                d_model=d_model,
                nhead=num_heads,
                batch_first=True,
                dim_feedforward=feed_forward_factor * d_model,
                dropout=dropout,
                activation=nn.functional.gelu,
            )
        )
        self.final_head = nn.Linear(
            in_features=d_model,
            out_features=num_features
        )
        self.pool_norm = nn.LayerNorm(self.model.config.hidden_size)
        self.pool = nn.Sequential(
            nn.Linear(in_features=self.model.config.hidden_size, out_features=num_features),
            nn.LayerNorm(num_features),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.to(DEVICE)
    
    def tokenize(self, x: str | list) -> dict:
        output = self.tokenizer(
            x,
            add_special_tokens=True,
            max_length=self._params["max_length"],
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        output = {k: v.to(DEVICE) if hasattr(v, "to") else v for k, v in output.items()}
        return output
        
    def prepare_input(self, x: list) -> torch.Tensor:
        tokenizer_output = self.tokenize(x)
        with torch.no_grad():
            x = self.model(**tokenizer_output).last_hidden_state
        cls = x[:, 0, :]
        x = x[:, 1:, :]
        mean = x.mean(dim=1)
        max = x.max(dim=1).values
        min = x.min(dim=1).values
        std = x.std(dim=1)
        x = self.pool_norm(torch.stack([cls, mean, std, max, min], dim=1))
        x = self.pool(x)
        return x
        
    def forward(
        self,
        x: list | torch.Tensor,
    ):
        if isinstance(x, list):
            x = self.prepare_input(x)
        
        if not isinstance(x, torch.Tensor):
            raise ValueError(f"Expected tensor, got {type(x).__name__}")
            
        x = x.to(DEVICE, dtype=torch.float)
        if x.ndim == 1:
            x = x.unsqueeze(0).unsqueeze(0)
            
        elif x.ndim == 2:
            x = x.unsqueeze(1)
            
        elif x.ndim > 3:
            raise ValueError(f"Expected a tensor of dim 1, 2, or 3, got {x.ndim}")
        
        x = self.head1(self.head_norm1(x))  # 3d : batch, 5, d_model
        x = self.head_norm(self.head2(self.head_norm2(x)))
        memory = self.encoder(x)
        memory = self.memory_projection(memory)
        out = self.decoder(x, memory)
        return self.final_head(out)
    
    def compute_mse_and_mae(
        self, 
        x: torch.Tensor,
        logits: torch.Tensor
    ):
        with torch.no_grad():
            return nn.MSELoss()(logits, x), nn.L1Loss()(logits, x)
    
    def predict(
        self,
        x: torch.Tensor,
        logits: torch.Tensor | None = None
    ):
        if logits is None:
            if x is None:
                raise ValueError("Expected one of x or x_ebd when logits is None !")
                
            logits = self(x)
        
        return self.compute_mse_and_mae(x, logits)
        
    def save(self, path:str):
        try:
            to_save = {
                "model_state_dict": self.state_dict(),
                "params": self._params
                }
            torch.save(to_save, path)
            logger.success(f"Modèle sauvegardé avec succès dans {path} !")
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
                # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                cop = {**self._params}
                if self.bert_path_or_bert:
                    cop.pop("bert_path_or_bert") if "bert_path_or_bert" in cop else None
                    self.build_model(**cop, bert_path_or_bert=self.bert_path_or_bert)  
                else:
                    self.build_model(**cop)  
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                logger.success("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur de chargement du modèle :", str(e))
                return
            
        logger.print("Erreur : Chemin inexistant !")

class AELoss(nn.Module):
    def __init__(self):
        super().__init__()
        self.mse = nn.MSELoss()
        self.mae = nn.L1Loss()
    
    def forward(self, logits, target):
        mse = self.mse(logits, target)
        mae = self.mae(logits, target)
        return mae + mse + torch.sqrt(mse)


class AEDataset(tdata.Dataset):
    def __init__(
        self,
        dataset_path_or_df:str|pd.DataFrame,
        callback: callable = None,
    ):
        super().__init__()
        if isinstance(dataset_path_or_df, pd.DataFrame):
            self.dataset = dataset_path_or_df
        else:
            self.dataset = pd.DataFrame(self.get_good_func(dataset_path_or_df))
        
        assert "text" in self.dataset, "Certaines columns manquent"
        self.dataset = self.dataset.reset_index(drop=True)
        self.taille = len(self.dataset)
        self.callback = callback
        
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
        text = self.dataset.loc[index, "text"]
        if self.callback is not None:
            text = self.callback(text)
        return {
            "text": text
       }
        
        
if __name__ == "__main__" :
    pass