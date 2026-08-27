#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May  8 14:37:36 2026

@author: hounsousamuel

Script de téléchargement des modèles TrustSignal
Utilise huggingface_hub pour un téléchargement fiable et complet
"""

from huggingface_hub import snapshot_download, login, logout
import os

# ========== CONFIG ==========
BASE_DIR = "models"
TOKEN = "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"
MODELS = {
    # Texte
    "text/very_fast": "distilbert/distilbert-base-multilingual-cased",
    "text/fast": "distilbert/distilroberta-base",
    "text/full": "FacebookAI/xlm-roberta-base",
    
    # Image
    "image/very_fast": "google/vit-base-patch16-224",
    "image/fast": "openai/clip-vit-base-patch32",
    "image/full": "openai/clip-vit-large-patch14",
    
    # Perplexité
    "perplexity/base": "distilbert/distilgpt2",
}

login(token=TOKEN)
# ========== TÉLÉCHARGEMENT ==========
for folder, model_name in MODELS.items():
    local_dir = os.path.join(BASE_DIR, folder)
    os.makedirs(local_dir, exist_ok=True)
    
    print(f"\n📥 Téléchargement : {model_name}")
    print(f"   Dossier : {local_dir}")
    
    try:
        snapshot_download(
            repo_id=model_name,
            local_dir=local_dir,
            ignore_patterns=["*.msgpack", "*.h5", "flax_model.msgpack", "rust_model.ot", "pytorch*.bin"],  # Évite les formats inutiles
            resume_download=True,  # Reprend si interrompu
        )
        print(f"   ✅ Succès !")
    except Exception as e:
        print(f"   ❌ Erreur : {e}")

print("\n✅ Téléchargement terminé !")
logout(token_name=TOKEN)


"""
from PIL import Image
import requests

from transformers import CLIPProcessor, CLIPModel

model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")

url = "http://images.cocodataset.org/val2017/000000039769.jpg"
image = Image.open(requests.get(url, stream=True).raw)

inputs = processor(text=["a photo of a cat", "a photo of a dog"], images=image, return_tensors="pt", padding=True)

outputs = model(**inputs)
logits_per_image = outputs.logits_per_image # this is the image-text similarity score
probs = logits_per_image.softmax(dim=1) # we can take the softmax to get the label probabilities

"""