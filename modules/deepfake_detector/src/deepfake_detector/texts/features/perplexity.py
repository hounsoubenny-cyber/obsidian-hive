#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 10 09:24:12 2026

@author: hounsousamuel
"""

import os, sys
import torch
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from transformers import AutoModelForCausalLM, AutoTokenizer
from deepfake_detector.deepfake_utils.logger import get_logger
from deepfake_detector.models_config import GPT_PATH

logger = get_logger()
BASEDIR = os.path.dirname(os.path.abspath(__file__))

    
class Perplexity:
    def __init__(self, path:str = None):
        self.path = path or GPT_PATH
        self.max_length = 512
        self.tokenizer  = AutoTokenizer.from_pretrained(self.path)
        self.model = AutoModelForCausalLM.from_pretrained(self.path)
        self.tokenizer.pad_token = self.tokenizer.eos_token  # GPT n'a pas de PAD token par défaut
        self.model.eval()
        
    def compute_perplexity(self, textes:list[str]|str = "") -> tuple[float, float]:
        try:
            if not textes:
                return -1.0, -1.0
            if isinstance(textes, str):
                textes = [textes]
                
            tokenizer_output = self.tokenizer(
                textes, 
                padding=True, 
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt"
            )
            with torch.inference_mode():
                labels = tokenizer_output['input_ids'].clone()
                labels[tokenizer_output['attention_mask'] == 0] = -100  # Ignorer les pad token, crossEntropyLoss ignore les -100
                model_output = self.model(
                    input_ids=tokenizer_output['input_ids'],
                    attention_mask=tokenizer_output['attention_mask'],
                    labels=labels  # Important pour la loss
                )
                return model_output.loss.item(), torch.exp(model_output.loss).item()
        except Exception as e:
            logger.print("Erreur dans compute_perplexity :", str(e))
            return -1.0, -1.0
        
    def __call__(self, textes:list[str]|str = ""):
        return self.compute_perplexity(textes)
            
if __name__ == "__main__":
    perplexity = Perplexity()
    texte = "The future of AI is"
    loss, pexplexity_score = perplexity(texte)
    print(f"Loss : {loss:.4f}")  # ex: 5.234
    print(f"Perplexité : {pexplexity_score:.2f}")  # ex: 187.5
