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
        # padding_mask = (x == 0)
        for layer in self.layers:
            # x = layer(x, padding_mask=padding_mask)
            x = layer(x)
        
        return self.layer_norm(x)

class AutoEncoder(nn.Module):
    def __init__(
        self,
        d_model:int,
        num_heads:int,
        num_features: int,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer_per_encoder_transformer:int = 2,
        num_layer_for_encoder_and_decoder: int = 4,
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
            num_layer_per_encoder_transformer=num_layer_per_encoder_transformer,
            num_layer_for_encoder_and_decoder=num_layer_for_encoder_and_decoder,
            num_embeddings=num_embeddings,
            max_seq_len=max_seq_len,
        )
        self.build_model(**self._params)
        self.num_params = sum(p.numel() for p in self.parameters(recurse=True))
        
    def build_model(
        self, 
        d_model:int,
        num_heads:int,
        num_features: int,
        feed_forward_factor:int = 4,
        dropout:float = 0.2,
        num_layer_per_encoder_transformer:int = 2,
        num_layer_for_encoder_and_decoder: int = 4,
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
        initial_x: torch.Tensor, 
        x: torch.Tensor = None,
        x_ebd: torch.Tensor = None,
        logits: torch.Tensor | None = None
    ):
        if logits is None:
            if x is None or x_ebd is None:
                raise ValueError("Expected one of x or x_ebd when logits is None !")
                
            logits = self(x, x_ebd)
        
        return self.compute_mse_and_mae(initial_x, logits)
        
            
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
                loaded = torch.load(buffer, weights_only=False)
                self._params = loaded["params"]
                state_dict = self._clean_state_dict(loaded["model_state_dict"])
                self.build_model(**self._params)  # IMPORTANT, BUILD AVANT LOAD_STATE_DICT SINON ÇA CASSE
                self.load_state_dict(state_dict)
                self.num_params = sum(p.numel() for p in self.parameters())
                logger.success("Modele chargé avec succès")
                return
            except Exception as e:
                logger.print("Erreur de sauvegarde du modèle :", str(e))
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
        
        
if __name__ == "__main__" :
    ae = AutoEncoder(
        d_model=512,
        num_heads=8,
        num_features=50,
    )
    x = torch.randint(1, 100, (10, 100, 50))
    x_ebd = torch.randint(1, 100, (10, 100))
    ae(x_ebd, x)
    
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    
    # Hyperparamètres
    BATCH_SIZE = 8
    SEQ_LEN = 100
    NUM_FEATURES = 25
    EPOCHS = 50
    D_MODEL = 128  # plus petit pour test rapide
    
    # Données synthétiques
    # x: features continues (durée, score, etc.)
    # x_ebd: syscall IDs (0-99)
    print("🔧 Génération des données...")
    x = torch.randn(1000, SEQ_LEN, NUM_FEATURES)
    x_ebd = torch.randint(0, 100, (1000, SEQ_LEN))
    
    dataset = TensorDataset(x_ebd, x)
    dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)
    
    # Modèle
    print("🏗️ Construction du modèle...")
    ae = AutoEncoder(
        d_model=D_MODEL,
        num_heads=4,
        num_features=NUM_FEATURES,
        num_layer_per_encoder_transformer=1,      # plus petit pour test
        num_layer_for_encoder_and_decoder=3,       # 512→256→128
        num_embeddings=100,
        max_seq_len=SEQ_LEN
    )
    
    optimizer = optim.AdamW(ae.parameters(), lr=1e-3, weight_decay=1e-5)
    
    print(f"📊 Device: {DEVICE}")
    print(f"📊 Nombre de paramètres: {ae.num_params:,}")
    print("\n🚀 Début de l'entraînement...\n")
    
    for epoch in range(EPOCHS):
        ae.train()
        total_loss = 0.0
        total_mse = 0.0
        total_mae = 0.0
        
        for batch_ebd, batch_x in dataloader:
            batch_ebd = batch_ebd.to(DEVICE)
            batch_x = batch_x.to(DEVICE)
            
            optimizer.zero_grad()
            
            # Forward
            reconstructed = ae(batch_ebd, batch_x)
            
            # Loss = MSE + MAE
            mse = nn.MSELoss()(reconstructed, batch_x)
            mae = nn.L1Loss()(reconstructed, batch_x)
            loss = mse + mae
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            total_mse += mse.item()
            total_mae += mae.item()
        
        avg_loss = total_loss / len(dataloader)
        avg_mse = total_mse / len(dataloader)
        avg_mae = total_mae / len(dataloader)
        
        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1:3d}/{EPOCHS} | Loss: {avg_loss:.4f} | MSE: {avg_mse:.4f} | MAE: {avg_mae:.4f}")
    
    # Test sur un échantillon
    print("\n🧪 Test sur un échantillon...")
    ae.eval()
    with torch.no_grad():
        test_ebd = x_ebd[:1].to(DEVICE)
        test_x = x[:1].to(DEVICE)
        reconstructed = ae(test_ebd, test_x)
        
        # Calcul des métriques finales
        final_mse = nn.MSELoss()(reconstructed, test_x).item()
        final_mae = nn.L1Loss()(reconstructed, test_x).item()
        
        print(f"\n📈 Résultats finaux:")
        print(f"   MSE (erreur quadratique): {final_mse:.6f}")
        print(f"   MAE (erreur absolue):    {final_mae:.6f}")
        print(f"   RMSE:                    {np.sqrt(final_mse):.6f}")
        
        # Aperçu des reconstructions
        print(f"\n🔍 Aperçu (première séquence, premier token):")
        print(f"   Original:     {test_x[0, 0, :5].cpu().numpy()}")
        print(f"   Reconstruit:  {reconstructed[0, 0, :5].cpu().numpy()}")
    
        
        
    