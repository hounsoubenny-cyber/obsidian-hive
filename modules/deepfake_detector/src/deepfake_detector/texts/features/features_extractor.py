#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
import re
import zlib
import torch
from collections import Counter
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from deepfake_detector.texts.features.perplexity import Perplexity
from deepfake_detector.deepfake_utils.logger import get_logger

logger = get_logger()

class FeaturesExtractor:
    def __init__(self, gpt_path:str = None):
        self.Perplexity = Perplexity(path=gpt_path)
        self._compute_methodes = [
            method for method in dir(self) 
            if method.startswith("compute_") and method != "compute_all"
        ]
        self._names = [method.replace("compute_", "") for method in self._compute_methodes]
    
    def compute_perplexity(self, textes:str|list[str], *args, **kwargs):
        return self.Perplexity(textes)[1]
    
    def compute_burstiness(self, textes:str|list[str], *args, **kwargs):
        """Variation de longueur des phrases — bas → IA, haut → humain"""
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        sentences = re.split(r'[.!?]+', textes)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if len(sentences) < 2:
            return 0.0
        
        lengths = torch.tensor(
            [len(s.split()) for s in sentences], 
            dtype=torch.float32
        )
        return (lengths.std() / lengths.mean().clamp(min=1e-8)).item()
    
    def compute_ttr(self, textes:str|list[str], *args, **kwargs):
        """Mots uniques / total — haut → humain, bas → IA"""
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        words = textes.split()
        if not words:
            return 0.0
        unique = set(words)
        return len(unique) / len(words)
    
    def compute_hapax_legomena(self, textes:str|list[str], *args, **kwargs):
        """Mots apparus exactement 1 fois — haut → humain, bas → IA"""
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        words = textes.split()
        if not words:
            return 0.0
        counts = Counter(words)
        hapax = [w for w, c in counts.items() if c == 1]
        return len(hapax) / len(words)
    
    def compute_entropy_n_gram(self, textes:str|list[str], n_gram:int = 2, *args, **kwargs):
        """
        Diversité des séquences de mots
        haut → humain, bas → IA
        E = - Σ P(gᵢ) * log₂(P(gᵢ))
        """
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        words = textes.split()
        if len(words) < n_gram:
            return 0.0
        
        n_grams = [" ".join(words[i:i + n_gram]) for i in range(len(words) - n_gram + 1)]
        total = len(n_grams)
        counts = Counter(n_grams)
        probs = torch.tensor(
            [c / total for c in counts.values()], 
            dtype=torch.float32
        )
        entropy = -torch.sum(probs * torch.log2(probs.clamp(min=1e-10))).item()
        return entropy
    
    def compute_compression_ratio(self, textes:str|list[str], *args, **kwargs):
        """
        Entropie informationnelle — indépendant de la langue
        bas → répétitif → IA, haut → varié → humain
        """
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        encoded = textes.encode()
        if not encoded:
            return 0.0
        return len(zlib.compress(encoded)) / len(encoded)
    
    def compute_discourse_markers(self, textes:str|list[str], *args, **kwargs):
        """
        Marqueurs de discours — LLMs en abusent
        haut → IA, bas → humain
        """
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        markers = {
            "moreover", "furthermore", "additionally", "in conclusion",
            "it is important", "it is worth noting", "in addition",
            "therefore", "thus", "hence", "consequently", "nevertheless",
            "however", "on the other hand", "in summary", "to summarize",
            "notably", "specifically", "particularly", "significantly"
        }
        words = textes.lower().split()
        count = sum(1 for w in words if w in markers)
        return count / max(len(words), 1)
    
    def compute_hedge_words(self, textes:str|list[str], *args, **kwargs):
        """
        Mots de nuance — LLMs en sur-utilisent
        haut → IA, bas → humain
        """
        if isinstance(textes, list):
            textes = "\n".join(textes)
        
        hedges = {
            "perhaps", "might", "could", "possibly", "generally",
            "typically", "usually", "often", "sometimes", "apparently",
            "seemingly", "likely", "probably", "may", "tend", "tends",
            "suggest", "suggests", "indicate", "indicates", "appear",
            "appears", "somewhat", "rather", "fairly", "quite"
        }
        words = textes.lower().split()
        count = sum(1 for w in words if w in hedges)
        return count / max(len(words), 1)
    
    def compute_all(self, textes:str|list[str], n_gram:int = 2, *args, **kwargs):
        """
        Calcule toutes les features et les retourne sous forme de dict + tensor.
        """
        features = {
            method.replace("compute_", ""): getattr(self, method)(textes, n_gram)
            for method in self._compute_methodes
        }
        return features, torch.tensor(list(features.values()), dtype=torch.float32)
    
    def __call__(self, textes:str|list[str], n_gram:int = 2, *args, **kwargs):
        return self.compute_all(textes, n_gram)


if __name__ == "__main__":
    FE = FeaturesExtractor()
    
    texte_ia = """Moreover, it is important to note that artificial intelligence 
    has significantly transformed modern society. Furthermore, these developments 
    suggest that future progress will likely continue at a rapid pace."""
    
    texte_humain = """j'sais pas trop, ça dépend vraiment. 
    Des fois c'est cool, des fois bof. 
    Hier j'ai essayé et franchement c'était pas terrible."""
    
    print("=== Texte IA ===")
    features, values = FE(texte_ia)
    for k, v in features.items():
        print(f"  {k:25s} : {v:.4f}")
    
    print("\n=== Texte Humain ===")
    features, values = FE(texte_humain)
    for k, v in features.items():
        print(f"  {k:25s} : {v:.4f}")