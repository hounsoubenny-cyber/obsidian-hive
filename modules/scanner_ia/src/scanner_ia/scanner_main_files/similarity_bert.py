#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 06:50:54 2026

@author: hounsousamuel
"""

import os
import time
import hashlib
import traceback
from sentence_transformers import SentenceTransformer
from sentence_transformers.util import pytorch_cos_sim
from scanner_ia.scanner_utils.warnings_manager import suppres_warnings
from scanner_ia.fuzzer.config import BERT_SIMILARITY_MODEL
from cachetools import TTLCache
from threading import Lock
from scanner_ia.scanner_utils.logger import get_logger

suppres_warnings()
similarity_logger = get_logger()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TTLCACHE = TTLCache(maxsize=1000, ttl=60 * 10)

class CosineSimilarityBERT:
    def __init__(self, *args, **kwargs):
        self.model = None
        self.model_dir = os.path.join(BASE_DIR, BERT_SIMILARITY_MODEL)
        os.makedirs(self.model_dir, exist_ok=True)
        self.metadata = {}
        similarity_logger.info(f"✅ CosineSimilarityBERT initialisé - model_dir: {self.model_dir}")
        self._lock = Lock()
        self._is_verify = False
    
    def transform(self, X, **kwargs):
        return self.model.encode(X, **kwargs)
    
    def encode(self, X):
        return self.transform(X)
    
    def fit(self, *args, **kwargs):
       return self
    
    @staticmethod
    def _cache_key(X: list) -> str:
        """Clé stable pour cacher l'embedding d'une liste de textes (typiquement la baseline)."""
        return hashlib.sha256("\x00".join(X).encode("utf-8", errors="ignore")).hexdigest()
    
    def verify_model(self):
        """Vérifie que le modèle est chargé"""
        with self._lock:
            try:
                if not self.model:
                    similarity_logger.debug("Modèle non trouvé en mémoire, tentative de chargement...")
                    self.model = SentenceTransformer(self.model_dir)
                if not self.model:
                    raise ValueError("Model indisponible")
                # similarity_logger.debug("✓ Modèle vérifié avec succès")
                self._is_verify = True
            except Exception as e:
                similarity_logger.error(f"❌ Erreur de vérification du modèle: {str(e)}")
                similarity_logger.error(traceback.format_exc())
                raise
            
    def cosine_similarity(self, X1, X2, aggregation='mean'):
        """
        Calcule la similarité cosinus entre deux ensembles de textes
        
        Args:
            X1: Premier texte ou liste de textes
            X2: Second texte ou liste de textes
            aggregation: 'mean', 'max', ou 'min' pour agréger la matrice
        
        Returns:
            float: Similarité agrégée
        """
        if not self._is_verify:
            self.verify_model()
        
        if isinstance(X1, str):
            X1 = [X1]
        if isinstance(X2, str):
            X2 = [X2]
        
        # similarity_logger.debug(f"Calcul cosine similarity: {len(X1)} vs {len(X2)} textes")
        start_time = time.time()

        # X1 (la baseline) est quasi toujours IDENTIQUE d'un payload à l'autre pour une
        # même URL — on cache son embedding pour éviter de le recalculer à chaque test.
        # X2 (la réponse au payload) change à chaque appel : pas de gain à le cacher.
        x1_key = self._cache_key(X1)
        with self._lock:
            X1_vec = TTLCACHE.get(x1_key)

        cache_hit = X1_vec is not None
        if not cache_hit:
            X1_vec = self.model.encode(X1, normalize_embeddings=True, convert_to_tensor=True)
            with self._lock:
                TTLCACHE[x1_key] = X1_vec

        X2_vec = self.model.encode(X2, normalize_embeddings=True, convert_to_tensor=True)
        
        # similarity_logger.debug(f"   └─ X1 shape: {X1_vec.shape}")
        # similarity_logger.debug(f"   └─ X2 shape: {X2_vec.shape}")
        
        sim_matrix = pytorch_cos_sim(X1_vec, X2_vec)
        if sim_matrix.shape[0] == 1:
            result = sim_matrix.item()
            aggregation = "first element (1D)"
        elif aggregation == 'mean':
            result = sim_matrix.mean()
        elif aggregation == 'max':
            result = sim_matrix.max()
        elif aggregation == 'min':
            result = sim_matrix.min()
        else:
            result = sim_matrix.mean()
        
        elapsed = time.time() - start_time
        similarity_logger.debug(f"   └─ Similarité ({aggregation}): {result:.4f} ({elapsed:.3f}s, baseline_cache={'hit' if cache_hit else 'miss'})")
        
        return result
    
    def save_model(self, model, path):
        # if self.model:
        #     self.model.save(path)
        return True

    def load_model(self, path):
        # self.model = SentenceTransformer(path)
        return True
        
    def __call__(self, X1, X2, aggregation='mean', **kwargs):
        """Rend l'instance appelable directement"""
        return self.cosine_similarity(X1, X2, aggregation=aggregation)
    
    def test(self, test_data=None):
        """
        Méthode de test pour valider le fonctionnement
        
        Args:
            test_data: Données de test (optionnel)
        """
        similarity_logger.info("\n" + "="*70)
        similarity_logger.info("🧪 TEST DE CosineSimilarityTFIDF")
        similarity_logger.info("="*70)
        
        # Données de test par défaut
        if test_data is None:
            test_data = [
                # Réponses normales
                "<html><body>Page d'accueil normale</body></html>",
                "<html><body>Page de connexion</body></html>",
                "<html><body>Tableau de bord</body></html>",
                "<html><body>Profil utilisateur</body></html>",
                
                # Réponses vulnérables
                "<html><body><script>alert('XSS')</script></body></html>",
                "<html><body>Erreur SQL: syntax error near 'SELECT'</body></html>",
                "<html><body><img src=x onerror=alert(1)></body></html>",
                "<html><body>../../../etc/passwd</body></html>",
            ]
        
        similarity_logger.info(f"\n📊 Données de test: {len(test_data)} échantillons")
        
        # Test similarités
        similarity_logger.info("\n📌 Test 2: Similarités")
        
        # Comparaisons normales vs normales
        sim_norm_norm = self.cosine_similarity(test_data[0], test_data[1])
        similarity_logger.info(f"   Normale vs Normale: {sim_norm_norm:.4f}")
        
        # Comparaisons normales vs vulnérables
        sim_norm_xss = self.cosine_similarity(test_data[0], test_data[4])
        similarity_logger.info(f"   Normale vs XSS:     {sim_norm_xss:.4f}")
        
        sim_norm_sql = self.cosine_similarity(test_data[0], test_data[5])
        similarity_logger.info(f"   Normale vs SQLi:    {sim_norm_sql:.4f}")
        
        # Test différents modes d'agrégation
        similarity_logger.info("\n📌 Test 3: Modes d'agrégation")
        X1 = test_data[:2]
        X2 = test_data[4:6]
        
        for agg in ['mean', 'max', 'min']:
            sim = self.cosine_similarity(X1, X2, aggregation=agg)
            similarity_logger.info(f"   {agg}: {sim:.4f}")
        
        # Test comparaison à baseline
        similarity_logger.info("\n📌 Test 4: Comparaison à baseline")
        debug
        similarity_logger.info("\n📌 Test 5: Sauvegarde et chargement")
        test_model_dir = os.path.join(BASE_DIR, "test_similarity_model")
        self.save_model(self.model, test_model_dir)
        
        new_instance = CosineSimilarityBERT(model_dir="test_similarity_model")
        new_instance.load_model(test_model_dir)
        
        # Vérifier que les prédictions sont identiques
        sim_original = self.cosine_similarity(test_data[0], test_data[4])
        sim_loaded = new_instance.cosine_similarity(test_data[0], test_data[4])
        
        if abs(sim_original - sim_loaded) < 0.0001:
            similarity_logger.success("✅ Sauvegarde/chargement OK - prédictions identiques")
        else:
            similarity_logger.error("❌ Sauvegarde/chargement KO - prédictions différentes")
        
        similarity_logger.info("\n" + "="*70)
        similarity_logger.info("✅ TEST TERMINÉ")
        similarity_logger.info("="*70)
        
        return True


# ============================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================
if __name__ == "__main__":
    # Créer une instance
    cosine_sim = CosineSimilarityBERT(
        model_dir="test_similarity",
        n_features=1000,
        verbose=1
    )
    
    # Lancer les tests
    # cosine_sim.test()
    
    # Exemple d'utilisation
    print("\n" + "="*70)
    print("🚀 EXEMPLE D'UTILISATION")
    print("="*70)
    
    # Réponses HTTP simulées
    normal_responses = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page normale</body></html>",
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page d'accueil</body></html>",
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Contact</body></html>",
    ]
    
    suspicious_responses = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><script>alert('XSS')</script></body></html>",
        "HTTP/1.1 500 Internal Error\n\nErreur SQL: syntax error near 'SELECT'",
    ]
    
    # Entraînement
    cosine_sim.fit(normal_responses)
    print(cosine_sim(normal_responses[0], suspicious_responses[0]))
    
    cosine_sim = CosineSimilarityBERT(
        # model_dir="test_similarity",
        # n_features=1000,
        verbose=1
    )
    print(cosine_sim(normal_responses[0], suspicious_responses[0]))