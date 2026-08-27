#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr  5 09:41:33 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import io
import random
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import zstandard as zstd
from model.static_analyzer import StaticAnalyser

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
try:
    torch.set_num_threads(os.cpu_count() - 2)
except Exception:
    pass

class Embedding(nn.Module):
    def __init__(self, vocab_size:int, d_model:int, max_seq_len:int = 5000):
        super().__init__()
        self.ebd = nn.Embedding(vocab_size, d_model, max_norm=1.0)
        PE = torch.zeros(max_seq_len, d_model)
        position = torch.arange(0, max_seq_len).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2) * (-np.log(10000.0) / d_model)
        )
        PE[:, 0::2] = torch.sin(position * div_term)
        PE[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("PE", PE)
        self.d_model = d_model
        self.to(device)
        
    def forward(self, x):
        seq_len = x.size(1)
        return self.ebd(x) * np.sqrt(self.d_model) + self.PE[:seq_len, ...]



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
            device=device,
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
        self.to(device)
        
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
        self.to(device)
        
    def forward(self, x):
        for layer in self.layers:
            x = layer(x)
        
        return self.layer_norm(x)
    

class ContextGuardModel(nn.Module):
    def __init__(
        self, 
        vocab_size:int,
        d_model:int,
        max_seq_len:int,
        num_heads:int,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer:int = 4,
        num_classe:int = 4
    ):
        assert num_classe >= 1, "Le nombre de classe doit être supérieur ou égal à 1"
        super().__init__()
        self._params = dict(
            vocab_size=vocab_size, 
            d_model=d_model, 
            max_seq_len=max_seq_len, 
            num_heads=num_heads, 
            feed_forward_factor=feed_forward_factor,
            dropout=dropout,
            num_layer=num_layer,
            num_classe=num_classe
            )
        self.build(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters())
        self.to(device)
        
    def build(self, vocab_size, d_model, max_seq_len, num_heads, feed_forward_factor, dropout, num_layer, num_classe):
        self.embedding = Embedding(vocab_size, d_model, max_seq_len)
        self.transformer = Transformer(d_model, num_heads, feed_forward_factor, dropout, num_layer)
        self.head = nn.Sequential(
            nn.Linear(d_model, 128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_classe)
            )
    
    def mean_pooling(self, transformer_output:torch.Tensor, attention_mask:torch.Tensor):
        # Mettre au mếme dim car transformer_output = (batch, seq_len, d_model) et attention_mask = (batch, seq_len)
        attention_mask = attention_mask.unsqueeze(-1).float()
        sum_ebd = (transformer_output * attention_mask).sum(dim=1)  # Là on vient à (batch, d_model)
        return sum_ebd / attention_mask.sum(dim=1).clamp(min=1e-8)  # Éviter division par 0
    
    def forward(self, input_ids:torch.Tensor, attention_mask:torch.Tensor, *args, **kwargs):
        transformer_output:torch.Tensor = self.transformer(self.embedding(input_ids))
        x:torch.Tensor = self.mean_pooling(transformer_output, attention_mask)
        x = self.head(x)
        return x
    
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
                
            print(f"Modèle sauvegardé avec succès dans {path} !")
        except Exception as e:
            print("Erreur de sauvegarde du modèle :", str(e))
    
    def load(self, path:str):
        if os.path.exists(path):
            try:
                model = None
                with open(path, mode="rb") as f:
                    model = f.read()
                model = zstd.decompress(model)
                buffer = io.BytesIO()
                buffer.write(model)
                buffer.seek(0)
                loaded = torch.load(buffer)
                self._params = loaded["params"]
                state_dict = loaded["model_state_dict"]
                self.build(**self._params)  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                print("Modele chargé avec succès")
                return
            except Exception as e:
                print("Erreur lors du chargement du modèle :", str(e))
                return
            
        print("Erreur : Chemin inexistant !")
    
    def predict(self, input_ids:torch.Tensor, attention_mask:torch.Tensor, logits = None, threashold:float = 0.5, *args, **kwargs):
        with torch.inference_mode():
            if logits is None:
                logits = self(input_ids, attention_mask)
            
            if self._params["num_classe"] == 1:
                prob = nn.functional.sigmoid(logits)  
                pred = (prob > threashold).long()
                return prob, pred
            
            else :
                prob = nn.functional.softmax(logits, dim=-1)
                pred = torch.argmax(prob, dim=-1).long()
                return prob, pred


class ContextGuardDataset(torch.utils.data.Dataset):
    def __init__(self, file_or_df:str|pd.DataFrame, tokenizer, max_length:int):
        if isinstance(file_or_df, pd.DataFrame):
            self.dataset = file_or_df
            
        else:
            func = pd.read_csv
            if file_or_df.endswith(".json"):
                func = pd.read_json
            elif file_or_df.endswith(".pkl"):
                func = pd.read_pickle
            else:
                raise ValueError("Format de fichier non accepté !")
                
            self.dataset = pd.DataFrame(func(file_or_df))
            self.tokenizer = tokenizer
        
        assert "text" in self.dataset and "label" in self.dataset, "Certaines columns manquent"
        self.taille = len(self.dataset)
        self.max_length = max_length
        
    def __len__(self):
        return self.taille
    
    def __getitem__(self, index):
        text = self.dataset.loc[:, "text"][index]
        output = self.tokenizer(
            [text], 
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
            )
        
        ids:torch.Tensor = output["input_ids"].squeeze()
        attn_mask:torch.Tensor = output["attention_mask"].squeeze()
        # if ids.ndim == 1:
        #     ids = ids.unsqueeze(0)
        #     attn_mask = attn_mask.unsqueeze(0)
        return (ids, attn_mask), self.dataset.loc[:, 'label'][index]
        
        
# ── Wrapper : adapte ContextGuardModel au Trainer ────────
# Le Trainer appelle self.model(X) avec X = (input_ids, attention_mask)
# Ce wrapper déballe le tuple avant de passer au modèle
   
class ModelWrapper(nn.Module):
    def __init__(self, model: ContextGuardModel):
        super().__init__()
        self.model = model
        self._params   = model._params
        self.num_params = model.num_params

    def forward(self, X):
        # X est un tuple (input_ids, attention_mask) venant du DataLoader
        input_ids, attention_mask = X
        input_ids      = input_ids.to(device) if input_ids.ndim == 2 else input_ids.squeeze(1).to(device)
        attention_mask = attention_mask.to(device) if attention_mask.ndim == 2 else attention_mask.squeeze(1).to(device)
        return self.model(input_ids, attention_mask)

    def predict(self, X, y, logits=None, threashold=0.5):
        input_ids, attention_mask = X
        input_ids      = input_ids.squeeze(1).to(device)
        attention_mask = attention_mask.squeeze(1).to(device)
        return self.model.predict(
            input_ids, attention_mask, y, logits, threashold
        )
        
    def state_dict(self, **kwargs):
        return self.model.state_dict(**kwargs)

    def load_state_dict(self, state_dict, **kwargs):
        return self.model.load_state_dict(state_dict, **kwargs)
    
    def parameters(self, **kwargs):
        return self.model.parameters(**kwargs)


class PredictWrapper(nn.Module):
    def __init__(self, tokenizer, model:ContextGuardModel, static_analyzer:StaticAnalyser|None = None):
        super().__init__()
        self.tokenizer = tokenizer
        self.model = torch.compile(model)
        self.model.eval()
        self.static_analyzer = static_analyzer if isinstance(static_analyzer, StaticAnalyser) else StaticAnalyser()
    
    def predict(self, text, threashold=0.5, use_onnx:bool = False, onnx_model=None, onnx_file:str=None):
        texts = [text] if isinstance(text, str) else text
        static_result = [self.static_analyzer.analyse(t) for t in texts]
        if all(c != -1 for c in static_result):
            return [random.uniform(0.95, 0.99909) for _ in static_result], static_result
        
        not_find_txt = [t for t, l in zip(texts, static_result) if l == -1]
        not_find_idx = [k for k, l in enumerate(static_result) if l == -1]
        
        find_label = [l for t, l in zip(texts, static_result) if l != -1]
        find_idx = [k for k, l in enumerate(static_result) if l != -1]
        
        output = self.tokenizer(
            not_find_txt,
            add_special_tokens=True,
            max_length=self.model._params["max_seq_len"],
            padding='max_length',
            truncation=True,
            return_tensors='pt'
            )
        ids:torch.Tensor = output["input_ids"]
        attn_mask:torch.Tensor = output["attention_mask"]
        
        if use_onnx:
            if onnx_model is not None and onnx_file is not None:
                logits = torch.tensor(onnx_model.inference(onnx_file, [ids.cpu().numpy(), attn_mask.cpu().numpy()], ["output"])[0])
                prob, preb = self.model.predict(ids, attn_mask, threashold=threashold, logits=logits)
        else:
            prob, pred = self.model.predict(ids, attn_mask, threashold=threashold)
            
        final_pred = torch.zeros(len(texts), dtype=torch.long)
        final_prob = torch.zeros(len(texts), self.model._params["num_classe"])
        
        if find_idx:
            for idx, label in zip(find_idx, find_label):
                final_pred[idx] = label
                final_prob[idx, label] = 1.0
        
        for idx, label, prob in zip(not_find_idx, pred, prob):
            final_pred[idx] = label
            final_prob[idx] = prob
            
        return final_prob, final_pred
        

if __name__ == "__main__":
    from transformers import BertTokenizer
    
    prompt = "Hello, how are you ?"
    BASEDIR = os.path.dirname(os.path.abspath(__file__))
    TOKENIZER_PATH = os.path.join(BASEDIR, "models", "tokenizer")
    MODEL_SAVE     = os.path.join(BASEDIR, "models", "contextguard2.pt") 
    tokenizer = BertTokenizer.from_pretrained(TOKENIZER_PATH)
    D_MODEL        = 256
    NUM_HEADS      = 8
    NUM_LAYERS     = 3
    FF_FACTOR      = 4
    DROPOUT        = 0.2
    MAX_SEQ_LEN    = 256
    NUM_CLASSES    = 4
    VOCAB_SIZE = tokenizer.vocab_size
    model = ContextGuardModel(
        vocab_size        = VOCAB_SIZE,
        d_model           = D_MODEL,
        max_seq_len       = MAX_SEQ_LEN,
        num_heads         = NUM_HEADS,
        feed_forward_factor = FF_FACTOR,
        dropout           = DROPOUT,
        num_layer         = NUM_LAYERS,
        num_classe        = NUM_CLASSES
    )
    model.load(MODEL_SAVE)
    predictmodel = PredictWrapper(tokenizer, model)
    prob, pred = predictmodel.predict(prompt, threashold=0.2)
    if isinstance(pred, list):
        print(prob)
        print(pred)
    else:
        print(prob)
        print(pred)
        for i, j in enumerate(pred):
            print("="*10)
            print(prob[i][pred[i].item()].item())
            print(pred[i].item())
