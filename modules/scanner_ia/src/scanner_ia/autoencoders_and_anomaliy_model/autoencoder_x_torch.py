#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 20 06:18:11 2026

@author: hounsousamuel
"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import zstandard as zstd

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class AutoencoderX(nn.Module):
    def __init__(
            self,
            num_features:int = 96,
            num_layers:int = 5,
            dr:float = 0.5,
            include_extender:bool = False,
        ):
        super().__init__()  # Initialiser nn.Module pour pourvoir profiter de ses méthodes
        self.num_features = num_features
        self.dr = dr
        self.include_extender = include_extender
        initial_out_fea = (512 if self.num_features <= 512 else self.num_features)
        m = 0
        initial_out_fea_ = initial_out_fea
        while initial_out_fea_ != 0:
            initial_out_fea_ = initial_out_fea_ // 2
            m += 1
            
        self.num_layers = m // 2 + 1  #Pour eviter 0, genre des couches a 0, 0
        self.build(self.num_features, self.num_layers, initial_out_fea)
        
    def build(self, num_features, num_layers, initial_out_fea = None):
        if initial_out_fea is None:
            initial_out_fea = (512 if self.num_features <= 512 else self.num_features)
        self.input_norm = nn.LayerNorm(num_features)
        self.encoder = nn.Sequential()
        self.decoder = nn.Sequential()
        in_fea, out_fea = num_features, initial_out_fea
        nl = num_layers  if not self.include_extender else num_layers - 1 # Pou respecter 5 layers ou j'enlève les -1 et là on a  
        # 5 encoder, 5 decoder et un compresseur et un decompresseur
        for _ in range(nl):  
            self.encoder.append(nn.Linear(in_fea, out_fea))
            self.encoder.append(nn.BatchNorm1d(out_fea))
            self.encoder.append(nn.ReLU(inplace=False))
            self.encoder.append(nn.Dropout(self.dr))
            in_fea = out_fea
            out_fea = out_fea // 2
        
        k = min(min(num_features // 4, in_fea), min(out_fea, in_fea))
        self.encoder.append(nn.Linear(in_fea, k))
        self.encoder.append(nn.LayerNorm(k))
        self.encoder.append(nn.ReLU(inplace=False))
        
        in_fea, out_fea = k, out_fea * 2
        for _ in range(nl - 1):  # Pour gerer les 256 manuellement
            self.decoder.append(nn.Linear(in_fea, out_fea))
            self.decoder.append(nn.BatchNorm1d(out_fea))
            self.decoder.append(nn.ReLU(inplace=False))
            self.decoder.append(nn.Dropout(self.dr))
            in_fea = out_fea
            out_fea = out_fea * 2
        
        self.decoder.append(nn.Linear(out_fea // 2, initial_out_fea))
        self.decoder.append(nn.BatchNorm1d(initial_out_fea))
        self.decoder.append(nn.ReLU(inplace=False))
        self.decoder.append(nn.Dropout(self.dr))
        self.decoder.append(nn.Linear(initial_out_fea, num_features))
        self.n_params = sum(p.numel() for p in self.parameters())
        self.to(device)
        
    # @torch.compile
    def forward(self, X):
        x = self.input_norm(X)
        x = self.encoder(x)
        # print pour debug si j'en ai besoin, comme on veut compiler, je laisse d'abord
        x = self.decoder(x)
        return x
    
    # @torch.compile
    def _reconstruction_error(self, x):
        with torch.inference_mode():
            reconstructed = self(x)
            errors = torch.mean((x - reconstructed) ** 2, dim=1)  # Car on veut par sample
        return errors
    
    def reconstruction_error(self, x):
        self.eval()
        return self._reconstruction_error(x)
    
    def predict(self, x, logits = None):
        with torch.inference_mode():
            if logits is not None:
                return torch.mean((x - logits) ** 2, dim=1) 
        return self.reconstruction_error(x)
    
    def load_model(self, path: str):
        """Charge un modèle (.pt ou .pt.zst)"""
        try:
            if path.endswith('.zst'):
                with open(path, "rb") as f:
                    compressed = f.read()
                decompressed = zstd.decompress(compressed)
                
                temp_path = path.replace('.zst', '.tmp')
                with open(temp_path, "wb") as f:
                    f.write(decompressed)
                loaded = torch.load(temp_path)
                os.remove(temp_path)
            else:
                
                if os.path.exists(path):
                    loaded = torch.load(path)
                elif os.path.exists(path + ".zst"):
                    return self.load_model(path + ".zst")
                else:
                    print(f"❌ Fichier inexistant: {path}")
                    return False
            
            self.num_features = loaded["num_features"]
            self.num_layers = loaded["num_layers"]
            self.dr = loaded["dr"]
            self.include_extender = loaded.get("include_extender", False)
            self.n_params = loaded["n_params"]
            
            self.build(self.num_features, self.num_layers)
            self.load_state_dict(loaded["model_state_dict"])
            
            print(f"✅ Modèle chargé: {path}")
            print(f"   └─ Features: {self.num_features}")
            print(f"   └─ Paramètres: {self.n_params:,}")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur: {e}")
            return False
    
    def save_model(self, path: str):
        """Sauvegarde avec compression zstd et affichage des stats"""
        try:
            torch.save({
                "model_state_dict": self.state_dict(),
                "num_features": self.num_features,
                "num_layers": self.num_layers,
                "n_params": self.n_params,
                "include_extender": self.include_extender,
                "dr": self.dr,
            }, path)
            
            with open(path, "rb") as f:
                data = f.read()
            
            original_size = len(data)
            
            compressed = zstd.compress(data, level=22)
            comp_size = len(compressed)
            ratio = original_size / comp_size
            
            with open(path + ".zst", "wb") as f:
                f.write(compressed)
            
            print("✅ Modèle sauvegardé:")
            print(f"   └─ Original: {original_size / 1024 / 1024:.2f} MB")
            print(f"   └─ Compressé: {comp_size / 1024 / 1024:.2f} MB")
            print(f"   └─ Ratio: {ratio:.2f}x")
            print(f"   └─ Paramètres: {self.n_params:,}")
            
            if os.path.exists(path + ".zst"):
                os.remove(path)
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur: {e}")
            return False
        

if __name__ == "__main__":    
    ae = AutoencoderX()
    print(ae)
    x = torch.rand(2, 1000, 1000)
    reconstructed = torch.rand(2, 1000, 1000)
    errors = torch.mean((x - reconstructed) ** 2, dim=1).mean()
    print(errors)
    errors = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
    print(errors)
    print(errors.numel())
    ae.load_model("/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/autoencoders/model_autoencoder_bodies/model.pt")
    print(ae)
    ae.save_model("/home/hounsousamuel/PROJET/ShieldIA_v2/scanner_ia/autoencoders/model_autoencoder_bodies/model.pt")
    # ae = AutoencoderX(5000)
    # print(ae)
    # print(torch.__config__.show())
    
        
        
            
        