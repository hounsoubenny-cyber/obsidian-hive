#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 25 18:01:08 2026

@author: hounsousamuel
"""

from sentence_transformers import SentenceTransformer, SentenceTransformerTrainer
from autoencoder_x_torch import AutoencoderX
from trainer import Trainer
import joblib
from sklearn.metrics.pairwise import cosine_similarity

ENCODER = SentenceTransformer("/home/hounsousamuel/PROJETS/Nexus_projet_hackaton/conversation_app/chat_nexus/EMBEDDING/")

def train():
    # data = joblib.load(path)
    # data = ENCODER.encode(data, show_progress_bar=True, batch_size=32, convert_to_tensor=True)
    normal_responses = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page normale</body></html>",
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page d'accueil</body></html>",
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Contact</body></html>",
    ]
    
    suspicious_responses = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><script>alert('XSS')</script></body></html>",
        "HTTP/1.1 500 Internal Error\n\nErreur SQL: syntax error near 'SELECT'",
    ]
    print(cosine_similarity(ENCODER.encode(normal_responses[0:1], normalize_embeddings=True), ENCODER.encode(suspicious_responses[0:1], normalize_embeddings=True)).max())
    print(cosine_similarity(ENCODER.encode(normal_responses[0:1], normalize_embeddings=True), ENCODER.encode(suspicious_responses[0:1], normalize_embeddings=True)).min())
    print(cosine_similarity(ENCODER.encode(normal_responses[0:1], normalize_embeddings=True), ENCODER.encode(suspicious_responses[0:1], normalize_embeddings=True)).mean())
    print(cosine_similarity(ENCODER.encode(normal_responses[1:2], normalize_embeddings=True), ENCODER.encode(suspicious_responses[1:2], normalize_embeddings=True)).max())
    print(cosine_similarity(ENCODER.encode(normal_responses[1:2], normalize_embeddings=True), ENCODER.encode(suspicious_responses[1:2], normalize_embeddings=True)).min())
    print(cosine_similarity(ENCODER.encode(normal_responses[1:2], normalize_embeddings=True), ENCODER.encode(suspicious_responses[1:2], normalize_embeddings=True)).mean())
    # print(cosine_similarity(ENCODER.encode(normal_responses[0], normalize_embeddings=True), ENCODER.encode(suspicious_responses[0], normalize_embeddings=True)).max())
    
train()