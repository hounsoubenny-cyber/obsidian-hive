#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 06:50:54 2026

@author: hounsousamuel
"""

import os
import io
import time
import json
import joblib
import hashlib
import traceback
import numpy as np
import pandas as pd
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity as sklearn_cosine_similarity
import zstandard as zstd
from datetime import datetime
from threading import Lock
from cachetools import TTLCache
from scanner_ia.scanner_utils.logger import get_logger

pd.set_option("display.max_row", 200)
pd.set_option("display.max_columns", 200)

_RANDOM_STATE = 42
_JOBS = int(0.75 * joblib.cpu_count())
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(BASE_DIR, exist_ok=True)

TTLCACHE = TTLCache(maxsize=1000, ttl=60 * 10)

similarity_logger = get_logger()

class CosineSimilarityTFIDF:
    def __init__(self, model_dir:str = "model_similarity", verbose:int = 1, cv:int = 3, n_features:int = 1000):
        self.model = None
        self.cv = cv
        self.verbose = verbose
        self.n_features = n_features
        self.model_dir = os.path.join(BASE_DIR, model_dir)
        os.makedirs(self.model_dir, exist_ok=True)
        self.metadata = {}
        self._lock = Lock()
        self._is_verify = False
        similarity_logger.info(f"✅ CosineSimilarityTFIDF initialisé - model_dir: {model_dir}, n_features: {n_features}")
    
    def build_model(self):
        """Construit le modèle FeatureUnion avec TF-IDF multi-échelles"""
        similarity_logger.debug("Construction du modèle FeatureUnion...")
        
        n_first = self.n_features // 2
        n_second = self.n_features - n_first
        
        similarity_logger.debug(f"  └─ Features courtes (3-5): {n_first}")
        similarity_logger.debug(f"  └─ Features longues (6-8): {n_second}")
        
        transformers = [
            ("short_ngrams", TfidfVectorizer(
                analyzer="char",
                max_features=n_first,
                min_df=2,
                max_df=0.8,
                ngram_range=(3, 5),
                norm='l2',
                use_idf=True,
                smooth_idf=True,
                sublinear_tf=True,
                dtype=np.float32
            )),
            
            ("long_ngrams", TfidfVectorizer(
                analyzer="char",
                max_features=n_second,
                min_df=2,
                max_df=0.8,
                ngram_range=(6, 8),
                norm='l2',
                use_idf=True,
                smooth_idf=True,
                sublinear_tf=True,
                dtype=np.float32  # Reduire precision pour gain memoire
            )),
        ]
        
        model = FeatureUnion(
            verbose=bool(self.verbose),
            transformer_list=transformers,
            n_jobs=_JOBS,
        )
        
        similarity_logger.success("✅ Modèle FeatureUnion construit")
        return model
    
    def transform(self, X):
        return self.model.transform(X).toarray()

    @staticmethod
    def _cache_key(X: list) -> str:
        """Clé stable pour cacher l'embedding d'une liste de textes (typiquement la baseline)."""
        return hashlib.sha256("\x00".join(X).encode("utf-8", errors="ignore")).hexdigest()
    
    def save_model(self, model, dir:str):
        similarity_logger.info(f"💾 Sauvegarde du modèle dans {dir}")
        
        try:
            similarity_logger.debug("Sérialisation avec skops.io.dumps...")
            buffer = io.BytesIO()
            joblib.dump(model, buffer, compress=9)
            buffer.seek(0)
            dumps = buffer.read()
            joblib_size = len(dumps) / (1024 * 1024)
            similarity_logger.debug((f"✓ Taille après JobLib: {joblib_size:.2f} MB"))
            
            os.makedirs(dir, exist_ok=True)
            
            similarity_logger.debug("Compression avec Zstandard (niveau 21)...")
            compressed = zstd.compress(dumps, level=21)
            
            model_path = os.path.join(dir, "model_similarity.joblib.zst")
            joblib.dump(compressed, model_path, compress=9)
            
            final_size = os.path.getsize(model_path) / (1024 * 1024)
            ratio = len(dumps) / len(compressed)
            
            similarity_logger.success(f"✓ Modèle sauvegardé: {model_path}")
            similarity_logger.info(f"   └─ Taille finale: {final_size:.2f} MB (ratio: {ratio:.2f}x)")
            
            metadata = {
                "date_saved": datetime.now().isoformat(),
                "num_model": len(model.named_transformers),
                "models_name": list(model.named_transformers.keys()),
                "n_features": self.n_features,
                "compression": {
                    "skops_level": 8,
                    "zstd_level": 20,
                    "original_size_mb": joblib_size,
                    "final_size_mb": final_size,
                    "ratio": ratio
                }
            }
            
            meta_path = os.path.join(dir, "metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            meta_size = os.path.getsize(meta_path) / 1024
            similarity_logger.success(f"✓ Métadonnées sauvegardées: {meta_path} ({meta_size:.2f} KB)")
            
        except Exception as e:
            similarity_logger.error(f"❌ Erreur de sauvegarde du modèle: {str(e)}")
            similarity_logger.error(traceback.format_exc())
            raise
    
    def load_model(self, dir:str):
        similarity_logger.info(f"📂 Chargement du modèle depuis {dir}")
        
        try:
            model_path = os.path.join(dir, "model_similarity.joblib.zst")
            meta_path = os.path.join(dir, "metadata.json")
            
            missing = []
            if not os.path.exists(model_path):
                missing.append("model_similarity.joblib.zst")
            if not os.path.exists(meta_path):
                missing.append("metadata.json")
                
            if missing:
                raise FileNotFoundError(f"Fichiers manquants: {', '.join(missing)}")
            
            similarity_logger.debug("Lecture du fichier compressé...")
            compressed = joblib.load(model_path)
            
            similarity_logger.debug("Décompression Zstandard...")
            decompressed = zstd.decompress(compressed)
            buffer = io.BytesIO(decompressed)
            
            similarity_logger.debug("Désérialisation JobLib...")
            self.model = joblib.load(buffer)
            
            
            similarity_logger.debug("Chargement des métadonnées...")
            metadata = {}
            with open(meta_path, "r") as f:
                metadata = json.load(f)
            
            if "compression" in metadata:
                comp = metadata["compression"]
                similarity_logger.info(f"   └─ Compression: ratio {comp['ratio']:.2f}x ({comp['original_size_mb']:.1f} MB → {comp['final_size_mb']:.1f} MB)")
            
            if "n_features" in metadata:
                self.n_features = metadata["n_features"]
                similarity_logger.info(f"   └─ Features: {self.n_features}")
            
            similarity_logger.success("✅ Modèle chargé avec succès")
            self.metadata = metadata
            
        except Exception as e:
            similarity_logger.error(f"❌ Erreur de chargement du modèle: {str(e)}")
            similarity_logger.error(traceback.format_exc())
            raise
    
    def fit(self, X:list, y:list = None):
        """
        Entraîne le modèle TF-IDF sur les données
        
        Args:
            X: Liste de textes (réponses HTTP)
            y: Ignoré (pour compatibilité)
        """
        similarity_logger.info("� Début de l'entraînement...")
        similarity_logger.info(f"   └─ {len(X)} échantillons")
        
        start_time = time.time()
        
        self.model = self.build_model()
        self.model.fit(X, y)
        
        elapsed = time.time() - start_time
        similarity_logger.success(f"✅ Entraînement terminé en {elapsed:.2f}s")
        
        if hasattr(self, 'model') and self.model:
            n_features_total = 0
            for name, transformer in self.model.named_transformers.items():
                if hasattr(transformer, 'vocabulary_'):
                    n_features = len(transformer.vocabulary_)
                    n_features_total += n_features
                    similarity_logger.debug(f"   └─ {name}: {n_features} features")
            
            similarity_logger.info(f"📊 Total features: {n_features_total}")
        
        self.save_model(self.model, self.model_dir)
    
    def verify_model(self):
        """Vérifie que le modèle est chargé"""
        with self._lock:
            try:
                if not self.model:
                    similarity_logger.debug("Modèle non trouvé en mémoire, tentative de chargement...")
                    self.load_model(self.model_dir)
                if not self.model:
                    raise ValueError("Model indisponible")
                similarity_logger.debug("✓ Modèle vérifié avec succès")
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
            X1_vec = self.model.transform(X1)
            with self._lock:
                TTLCACHE[x1_key] = X1_vec

        X2_vec = self.model.transform(X2)
        
        # similarity_logger.debug(f"   └─ X1 shape: {X1_vec.shape}")
        # similarity_logger.debug(f"   └─ X2 shape: {X2_vec.shape}")
        
        sim_matrix = sklearn_cosine_similarity(X1_vec, X2_vec, dense_output=True)
        if sim_matrix.shape[0] == 1:
            result = sim_matrix.item(0)
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
        
        # Entraînement
        similarity_logger.info("\n📌 Test 1: Entraînement")
        self.fit(test_data[:4])  # Entraîne sur les normales
        
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
        
        similarity_logger.info("\n📌 Test 5: Sauvegarde et chargement")
        test_model_dir = os.path.join(BASE_DIR, "test_similarity_model")
        self.save_model(self.model, test_model_dir)
        
        new_instance = CosineSimilarityTFIDF(model_dir="test_similarity_model")
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
    cosine_sim = CosineSimilarityTFIDF(
        model_dir="test_similarity",
        n_features=1000,
        verbose=1
    )
    # cosine_sim.load_model(cosine_sim.model_dir)
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
    
    # # Entraînement
    cosine_sim.fit(normal_responses)
    print(cosine_sim(normal_responses[0], suspicious_responses[0]))
    
    cosine_sim = CosineSimilarityTFIDF(
        # model_dir="test_similarity",
        # n_features=1000,
        verbose=1
    )
    print(cosine_sim(normal_responses[0], suspicious_responses[0]))