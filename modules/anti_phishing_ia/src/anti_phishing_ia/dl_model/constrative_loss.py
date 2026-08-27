#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 13:41:11 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
import torch
import torch.nn as nn

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class SupervisedConstrativeLoss(nn.Module):
    def __init__(self, temperature:float = 0.07):
        super().__init__()
        self.to(DEVICE)
        self.temperature = temperature
        
    def forward(self, embedding:torch.Tensor, labels:torch.Tensor|list, is_in_device:bool = True, is_normalized:bool = True):
        # embedding, 2d, shape [batch_size, seq_len]
        # Label, 1d
        if embedding.ndim == 3:
            embedding = embedding[:, 0, :]
            
        if not isinstance(labels, torch.Tensor):
            labels = torch.tensor(labels)
            labels = labels.to(DEVICE)
        
        if not is_in_device:
            embedding = embedding.to(DEVICE)
            labels = labels.to(DEVICE)
        
        if not is_normalized:
            embedding = nn.functional.normalize(embedding, dim=-1, p=2)
            
        labels = labels.squeeze()
        sim_matrix:torch.Tensor = (embedding @ embedding.T) / self.temperature  # Matrice de similarité entre les élément, comme c'est déja normalisé, le matmul donne en meme temps la matrice de similarité, / temp pour forcer le modèle a se corriger et eviter les petit nombres
        labels_matrix:torch.Tensor = (labels.unsqueeze(0) == labels.unsqueeze(1)).float()  # Matrice qui indique quels éléments ont les même labels
        eye_matrix:torch.Tensor = 1 - torch.eye(embedding.shape[0], device=embedding.device) # Matrice identité pour annulé la diagonale, 1 - ..., pour annuler la diagonale
        labels_matrix = labels_matrix * eye_matrix
        # La formule, p = log(exp(sim) / somme(exp(sim)))
        # Donc p = sim - log(somme(exp(sim)))
        exp_matrix = torch.exp(sim_matrix) * eye_matrix # Annuler la diagonale, un élément avec lui meme
        log_prob = sim_matrix - torch.log(exp_matrix.sum(dim=-1, keepdim=True)) # Keepdim pour que l'opération marche
        
        # Loss = moyenne sur les paires positives, et - car p est entre 0 et 1, donc log < 0, sans le -, la loss serait petite et l'optimiseur va croire que tout va bien
        loss = -(labels_matrix * log_prob).sum(dim=-1) / labels_matrix.sum(dim=-1).clamp(min=1)
        return loss.mean()  # Car backwar attend un scalaire


        
        
        
        