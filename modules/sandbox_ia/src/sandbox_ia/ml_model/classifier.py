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
import numpy as np
import zstandard as zstd
from sandbox_ia.sandbox_utils.logger import get_logger
from sandbox_ia.ml_model.autoencoders import Transformer, TransformerLayer
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logger = get_logger()

class Classifier(nn.Module):
    def __init__(
        self,
        d_model:int,
        num_heads:int,
        num_features: int,
        num_layer:int,
        num_classe: int = 2,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_embeddings: int = 100,
        max_seq_len:int = 100,
    ):
        super().__init__()
        self._params = dict(
            d_model=d_model,
            num_heads=num_heads,
            num_features=num_features,
            feed_forward_factor=feed_forward_factor,
            dropout=dropout,
            num_embeddings=num_embeddings,
            max_seq_len=max_seq_len,
            num_layer=num_layer,
            num_classe=num_classe
        )
        self.build_model(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters(recurse=True))
        
    def build_model(
        self, 
        d_model:int,
        num_heads:int,
        num_features: int,
        num_layer:int,
        num_classe: int = 2,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_embeddings: int = 100,
        max_seq_len:int = 100,
    ):
        PE = torch.zeros(max_seq_len, d_model)
        position = torch.arange(0, max_seq_len).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2) * (-np.log(10000.0) / d_model)
        )
        PE[:, 0::2] = torch.sin(position * div_term)
        PE[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("PE", PE)
        
        self.embedding = nn.Embedding(
            num_embeddings=num_embeddings,
            embedding_dim=d_model,
            max_norm=1.0
        )
        self.head1 = nn.Linear(
            in_features=num_features - 1,
            out_features=d_model
        )
        self.head2 = nn.Linear(
            in_features=d_model,
            out_features=d_model
        )
        self.head3 = nn.Linear(
            in_features=d_model,
            out_features=d_model
        )
        self.head_norm = nn.LayerNorm(d_model)
        self.head_norm1 = nn.LayerNorm(num_features - 1)
        self.head_norm2 = nn.LayerNorm(d_model)
        self.head_norm3 = nn.LayerNorm(d_model)
        self.transformer = Transformer(
            d_model=d_model,
            num_heads=num_heads,
            num_layer=num_layer,
            feed_forward_factor=feed_forward_factor,
            dropout=dropout
        )
        self.pool_norm = nn.LayerNorm(5 * d_model)
        self.pool = nn.Sequential(
            nn.Linear(in_features=5 * d_model, out_features=d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.classifier = nn.Linear(
            in_features=d_model,
            out_features=num_classe
        )
        self.to(DEVICE)
        
    def forward(
        self,
        x_ebd: torch.Tensor,
        x: torch.Tensor,
    ):
        # x_ebd, 2d; x: 3d
        for tensor in (x_ebd, x):
            if not isinstance(tensor, torch.Tensor):
                raise ValueError(f"Expected tensor, got {type(tensor).__name__}")
        
        x_ebd = x_ebd.long()
        x = x.float()
        
        if x_ebd.ndim == 1:
            x_ebd = x_ebd.unsqueeze(0)
            
        elif x_ebd.ndim > 2:
            raise ValueError(f"Expected a tensor of dim 1 or 2, got {x_ebd.ndim}")
            
        if x.ndim == 1:
            x = x.unsqueeze(0).unsqueeze(0)
            
        elif x.ndim == 2:
            x = x.unsqueeze(1)
            
        elif x.ndim > 3:
            raise ValueError(f"Expected a tensor of dim 1, 2, or 3, got {x.ndim}")
        
        x_ebd = self.embedding(x_ebd)  # 3d : batch, seq_len, d_model
        x = self.head1(self.head_norm1(x))  # 3d : batch, seq_len, d_model
        x = self.head_norm2(x + x_ebd)
        x = self.head2(x) 
        x = x + self.PE[:x.shape[1]]
        x = self.head_norm(self.head3(self.head_norm3(x)))
        x = self.transformer(x)
        mean = x.mean(dim=1)
        std = x.std(dim=1)
        max = x.max(dim=1).values
        min = x.min(dim=1).values
        last = x[:, -1, :]
        x = self.pool_norm(torch.cat([mean, std, min, max, last], dim=-1))
        x = self.pool(x) # On passe a 2d
        return self.classifier(x)
        
    
    def predict(
        self, 
        x_ebd:torch.Tensor, 
        x: torch.Tensor,
        logits = None,
        threashold:float = 0.5
    ):
        with torch.inference_mode():
            if logits is None:
                logits = self(x_ebd, x)
            
            if self._params["num_classe"] == 1:
                prob = nn.functional.sigmoid(logits)  
                pred = (prob > threashold).long()
                return prob, pred
            
            else :
                prob = nn.functional.softmax(logits, dim=-1)
                pred = torch.argmax(prob, dim=-1).long()
                return prob, pred
    
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
                
            logger.success(f"Modèle sauvegardé avec succès dans {path} !")
        except Exception as e:
            logger.print("Erreur de sauvegarde du modèle :", str(e))
    
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
                state_dict = loaded["model_state_dict"]
                self.build_model(**self._params)  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                logger.success("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur de sauvegarde du modèle :", str(e))
                return
            
        logger.print("Erreur : Chemin inexistant !")
        
        
if __name__ == "__main__":
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    
    print("=" * 60)
    print("🧪 TEST DU CLASSIFIER TRANSFORMER")
    print("=" * 60)
    
    # Paramètres
    BATCH_SIZE = 8
    SEQ_LEN = 100
    NUM_FEATURES = 25
    NUM_CLASSES = 2
    D_MODEL = 64  # Plus petit pour test rapide
    NUM_LAYER = 2
    EPOCHS = 10
    
    # Données synthétiques
    print("\n📊 Génération des données...")
    N_SAMPLES = 500
    
    # x: features continues
    x = torch.randn(N_SAMPLES, SEQ_LEN, NUM_FEATURES)
    # x_ebd: syscall IDs (0-99)
    x_ebd = torch.randint(0, 100, (N_SAMPLES, SEQ_LEN))
    
    # Labels aléatoires (0 ou 1)
    y = torch.randint(0, NUM_CLASSES, (N_SAMPLES,))
    
    dataset = TensorDataset(x_ebd, x, y)
    dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)
    
    # Modèle
    print("🏗️ Construction du modèle...")
    model = Classifier(
        d_model=D_MODEL,
        num_heads=4,
        num_features=NUM_FEATURES,
        num_layer=NUM_LAYER,
        num_classe=NUM_CLASSES,
        feed_forward_factor=2,
        dropout=0.1,
        num_embeddings=100,
        max_seq_len=SEQ_LEN
    )
    
    optimizer = optim.AdamW(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss()
    
    print(f"📊 Device: {DEVICE}")
    print(f"📊 Paramètres: {model.num_params:,}")
    print("\n🚀 Début de l'entraînement...\n")
    
    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch_ebd, batch_x, batch_y in dataloader:
            batch_ebd = batch_ebd.to(DEVICE)
            batch_x = batch_x.to(DEVICE)
            batch_y = batch_y.to(DEVICE)
            
            optimizer.zero_grad()
            logits = model(batch_ebd, batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            pred = logits.argmax(dim=1)
            correct += (pred == batch_y).sum().item()
            total += batch_y.size(0)
        
        avg_loss = total_loss / len(dataloader)
        acc = correct / total * 100
        
        if (epoch + 1) % 5 == 0:
            print(f"Epoch {epoch+1:3d}/{EPOCHS} | Loss: {avg_loss:.4f} | Acc: {acc:.2f}%")
    
    # Test final
    print("\n🧪 Test sur un échantillon...")
    model.eval()
    with torch.inference_mode():
        test_ebd = x_ebd[:1].to(DEVICE)
        test_x = x[:1].to(DEVICE)
        test_y = y[:1].to(DEVICE)
        
        logits = model(test_ebd, test_x)
        prob, pred = model.predict(test_ebd, test_x)
        
        print(f"\n📈 Résultats:")
        print(f"   Label réel:        {test_y.item()}")
        print(f"   Logits:            {logits.cpu().numpy()}")
        print(f"   Probabilités:      {prob.cpu().numpy()}")
        print(f"   Prédiction:        {pred.item()}")
        
        # Vérification du pooling
        print(f"\n🔍 Vérification des shapes:")
        with torch.inference_mode():
            x_ebd_emb = model.embedding(test_ebd)
            print(f"   Embedding:         {x_ebd_emb.shape}")
            
            # Forward partiel pour debug
            x_proj = model.head1(model.head_norm1(test_x))
            print(f"   Après head1:       {x_proj.shape}")
            
            x = model.transformer(x_proj)
            print(f"   Après transformer: {x.shape}")
            
            mean = x.mean(dim=1)
            std = x.std(dim=1)
            maxv = x.max(dim=1).values
            minv = x.min(dim=1).values
            last = x[:, -1, :]
            print(f"   Mean: {mean.shape}, Std: {std.shape}")
            print(f"   Max: {maxv.shape}, Min: {minv.shape}, Last: {last.shape}")
            
            concat = torch.cat([mean, std, minv, maxv, last], dim=-1)
            print(f"   Concatenation:     {concat.shape}")
            print(f"   Attendu: (batch, {5 * D_MODEL})")
    
    print("\n✅ Test terminé !")