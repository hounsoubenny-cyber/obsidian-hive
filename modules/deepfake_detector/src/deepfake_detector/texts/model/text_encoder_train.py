#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 19:53:08 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
import torch
import pandas as pd
from torch.utils.data import DataLoader
from transformers import AutoTokenizer
from deepfake_detector.texts.model.constrative_loss import SupervisedConstrativeLoss
from deepfake_detector.texts.model.callbacks import EarlyStopping
from deepfake_detector.texts.model.text_encoder import TextEncoderDataset, TextEncoder
from deepfake_detector.texts.model.text_encoder_trainer import Trainer

# ========== CONFIG ==========
MODEL_PATH = "/home/hounsousamuel/PROJET/OBSIDIAN_ShieldIA_v2/modules/MODEL_SHARED/text/full"
BATCH_SIZE = 4
EPOCHS = 20
LEARNING_RATE = 1e-4
MAX_LENGTH = 128
D_MODEL = 256
NUM_LAYER_TO_FREEZE = 3  # Geler les 3 premières couches sur 6
BASEDIR = os.path.dirname(os.path.abspath(__file__))
SAVEDIR = os.path.abspath(os.path.join(BASEDIR, "model_trained"))
os.makedirs(SAVEDIR, exist_ok=True)
# ========== CORPUS ==========
corpus = [
    # Humains (0)
    {"text": "Je suis allé au marché ce matin.", "label": 0},
    {"text": "Hier j'ai vu un film émouvant.", "label": 0},
    {"text": "Ma grand-mère m'a fait un gâteau.", "label": 0},
    {"text": "Promenade au parc avec mon chien.", "label": 0},
    {"text": "J'ai oublié mes clés chez moi.", "label": 0},
    {"text": "Barbecue entre amis ce weekend.", "label": 0},
    {"text": "Je n'arrive pas à dormir.", "label": 0},
    {"text": "Mon fils a perdu sa première dent.", "label": 0},
    # IA (1)
    {"text": "L'intelligence artificielle révolutionne le paysage technologique.", "label": 1},
    {"text": "Les algorithmes d'apprentissage profond analysent les données.", "label": 1},
    {"text": "L'optimisation des hyperparamètres améliore les performances.", "label": 1},
    {"text": "Le traitement automatique du langage extrait l'information.", "label": 1},
    {"text": "Les réseaux de neurones convolutifs excellent en vision.", "label": 1},
    {"text": "La descente de gradient optimise la fonction de coût.", "label": 1},
    {"text": "Les transformeurs capturent les dépendances à longue portée.", "label": 1},
    {"text": "L'apprentissage par transfert exploite des modèles pré-entraînés.", "label": 1},
]

df = pd.DataFrame(corpus)
print(f"Corpus : {len(df)} textes")
print(f"Classes : {df['label'].value_counts().to_dict()}")


def train(
    model_path:str = MODEL_PATH,
    batch_size:int = BATCH_SIZE,
    epochs:int = EPOCHS,
    learning_rate:int = LEARNING_RATE,
    max_length:int = MAX_LENGTH,
    d_model:int = D_MODEL,
    num_layer_to_freeze:int = NUM_LAYER_TO_FREEZE,
    cls_only:bool = False,
    save_path:str = os.path.join(SAVEDIR, "text_encoder_trained.pth")
):

    # ========== TOKENIZER ==========
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    
    # ========== DATASETS ==========
    dataset = TextEncoderDataset(
        tokenizer_or_model=tokenizer,
        text_dataset_path_or_df=df,
        max_length=max_length
    )
    
    # Split train/val (80/20)
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
    
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # ========== MODÈLE ==========
    model = TextEncoder(
        bert_path_or_bert=model_path,
        d_model=d_model,
        num_layer_to_freeze=num_layer_to_freeze,
        dropout=0.1,
        cls_only=False
    )
    print(f"Modèle créé : {model.num_params:,} paramètres")
    
    # ========== LOSS & OPTIMIZER ==========
    loss_fn = SupervisedConstrativeLoss(temperature=0.07)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    
    # ========== TRAINER ==========
    trainer = Trainer(
        model=model,
        loss=loss_fn,
        optimizer=optimizer,
        scheduler=scheduler,
        each_epochs=True,
        compile_model=True,  #
        compile_loss=False,
    )
    
    # ========== GO ! ==========
    history = trainer.fit(
        dataloader=train_loader,
        valloader=val_loader,
        epochs=EPOCHS,
        plot_history=True
    )
    
    # ========== SAUVEGARDE ==========
    model.save("text_encoder_trained.pth")
    print("✅ Modèle sauvegardé !")

if __name__ == "__main__":
    # pass
    train()
    