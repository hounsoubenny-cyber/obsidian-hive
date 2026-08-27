#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May  8 07:39:56 2026

@author: hounsousamuel
"""

# corpus_test.py
corpus = [
    # ===== TEXTES HUMAINS (label 0) =====
    {"text": "Je suis allé au marché ce matin pour acheter des légumes frais.", "label": 0},
    {"text": "Hier, j'ai vu un film vraiment émouvant au cinéma du quartier.", "label": 0},
    {"text": "Ma grand-mère m'a préparé un délicieux gâteau au chocolat.", "label": 0},
    {"text": "Je me suis promené dans le parc avec mon chien tout l'après-midi.", "label": 0},
    {"text": "J'ai oublié mes clés à l'intérieur et j'ai dû appeler un serrurier.", "label": 0},
    {"text": "Le weekend dernier, on a fait un barbecue avec des amis.", "label": 0},
    {"text": "Je n'arrive pas à dormir à cause de la chaleur cette nuit.", "label": 0},
    {"text": "Mon fils a perdu sa première dent aujourd'hui, il était tout fier.", "label": 0},
    {"text": "J'ai renversé mon café sur mon clavier, quelle catastrophe.", "label": 0},
    {"text": "La voiture ne démarre plus, je vais devoir l'emmener au garage.", "label": 0},
    
    # ===== TEXTES IA (label 1) =====
    {"text": "L'intelligence artificielle révolutionne le paysage technologique contemporain.", "label": 1},
    {"text": "Les algorithmes d'apprentissage profond permettent une analyse prédictive avancée.", "label": 1},
    {"text": "L'optimisation des hyperparamètres améliore significativement les performances du modèle.", "label": 1},
    {"text": "Le traitement automatique du langage naturel facilite l'extraction d'informations.", "label": 1},
    {"text": "Les réseaux de neurones convolutifs excellent dans la reconnaissance d'images.", "label": 1},
    {"text": "La descente de gradient stochastique optimise la fonction de coût de manière itérative.", "label": 1},
    {"text": "Les transformeurs utilisent des mécanismes d'attention pour capturer les dépendances à longue portée.", "label": 1},
    {"text": "L'apprentissage par transfert permet d'exploiter des modèles pré-entraînés pour de nouvelles tâches.", "label": 1},
    {"text": "La régularisation L2 réduit le surapprentissage en pénalisant les poids élevés.", "label": 1},
    {"text": "Les modèles génératifs adversariales produisent des données synthétiques réalistes.", "label": 1},
]

# Sauvegarde
import json
with open('./dataset/corpus_test.json', 'w') as f:
    json.dump(corpus, f, ensure_ascii=False, indent=2)