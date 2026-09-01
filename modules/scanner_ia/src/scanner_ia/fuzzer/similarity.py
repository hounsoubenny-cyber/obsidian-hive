#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 06:50:54 2026

@author: hounsousamuel
"""

import os
import io
import gc
import sys
import time
import json
import joblib
import hashlib
import resource
import numpy as np
import pandas as pd
from sklearn.pipeline import FeatureUnion
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import normalize
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer, TfidfTransformer
from sklearn.metrics.pairwise import cosine_similarity as sklearn_cosine_similarity
import zstandard as zstd
from datetime import datetime
from threading import Lock, Semaphore
from cachetools import TTLCache
from scanner_ia.scanner_utils.logger import get_logger

pd.set_option("display.max_row", 200)
pd.set_option("display.max_columns", 200)

_RANDOM_STATE = 42
_JOBS = 1 # int(0.75 * joblib.cpu_count())
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(BASE_DIR, exist_ok=True)

TTLCACHE = TTLCache(maxsize=1000, ttl=5 * 10 * 60)

similarity_logger = get_logger()
MAX_CONCURRENT = 25 # Plus rapide


def _peak_rss_mb():
    """RAM maximale utilisée par le process jusqu'ici, en Mo (best-effort).
    Sous Linux, ru_maxrss est en Ko ; sous macOS, en octets."""
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024
    except Exception:
        return None


class StreamingTfidfTransformer:
    """
    Remplace sklearn.TfidfTransformer, mais permet un calcul de l'IDF
    en 2 passes "streaming" : on ne garde JAMAIS tout le corpus en RAM,
    seulement un accumulateur de taille n_features (doc_freq).

    Compatible avec un usage classique (fit/transform en une fois) ET
    avec un usage streaming (partial_fit_batch appelé plusieurs fois
    puis finalize_idf une seule fois à la fin).

    Formules identiques à sklearn (smooth_idf=True, sublinear_tf=True,
    norm='l2') :
        idf(t)  = ln((n_docs+1)/(df(t)+1)) + 1
        tf'(t)  = 1 + ln(tf(t))   (sur les valeurs non nulles seulement)
        tfidf   = tf' * idf, puis normalisation L2 par ligne
    """

    def __init__(self, sublinear_tf: bool = True, norm: str = "l2"):
        self.sublinear_tf = sublinear_tf
        self.norm = norm
        self.idf_ = None
        self._doc_freq = None
        self._n_docs = 0

    def _init_accumulator(self, n_features: int):
        if self._doc_freq is None:
            self._doc_freq = np.zeros(n_features, dtype=np.int64)

    def partial_fit_batch(self, counts):
        """Passe 1 (streaming) : accumule le doc_freq à partir d'UN batch
        de comptages (sortie de HashingVectorizer.transform(batch)).
        Peut être appelé N fois de suite sur des batches successifs."""
        self._init_accumulator(counts.shape[1])
        self._doc_freq += (counts != 0).sum(axis=0).A1
        self._n_docs += counts.shape[0]

    def finalize_idf(self):
        """Fin de la passe 1 : calcule l'IDF global à partir de tout ce
        qui a été accumulé via partial_fit_batch(). À appeler une seule
        fois, quand tout le corpus a été vu."""
        if self._doc_freq is None:
            raise ValueError("Aucun batch n'a été vu — appelle partial_fit_batch() avant finalize_idf().")
        idf = np.log((self._n_docs + 1) / (self._doc_freq + 1)) + 1
        self.idf_ = idf.astype(np.float32)
        return self.idf_

    def fit(self, counts, y=None):
        """Fit "classique" (non-streaming) : tout le batch est déjà en
        mémoire d'un coup (utilisé quand on n'est pas en mode streaming,
        via Pipeline.fit() normal)."""
        self._doc_freq = None
        self._n_docs = 0
        self.partial_fit_batch(counts)
        self.finalize_idf()
        return self

    def transform(self, counts):
        if self.idf_ is None:
            raise ValueError("StreamingTfidfTransformer non fitté : idf_ est None. Appelle fit() ou finalize_idf() d'abord.")
        X = counts.astype(np.float32)
        if self.sublinear_tf:
            X.data = 1 + np.log(X.data)
        X = X.multiply(self.idf_)
        if self.norm:
            X = normalize(X, norm=self.norm)
        return X.tocsr()

    def fit_transform(self, counts, y=None):
        self.fit(counts, y)
        return self.transform(counts)

    def get_params(self, deep=True):
        return {"sublinear_tf": self.sublinear_tf, "norm": self.norm}

    def set_params(self, **params):
        for k, v in params.items():
            setattr(self, k, v)
        return self


class CosineSimilarityTFIDF:
    def __init__(
        self,
        model_dir:str = "model_similarity", 
        verbose:int = 1, 
        cv:int = 3, 
        n_features:int = 1000,
        use_hashing: bool = False,
        use_streaming: bool = False,
        batch_size: int = 5000,
    ):
        self.model = None
        self.cv = cv
        self.verbose = verbose
        self.n_features = n_features 
        self.model_dir = os.path.join(BASE_DIR, model_dir)
        os.makedirs(self.model_dir, exist_ok=True)
        self.metadata = {}
        self._lock = Lock()
        self.use_hashing = use_hashing
        self.use_streaming = use_streaming
        self.batch_size = batch_size
        self._is_verify = False
        self._encode_semaphore = Semaphore(MAX_CONCURRENT)

        if self.use_streaming and not self.use_hashing:
            similarity_logger.warning(
                "⚠️ use_streaming=True nécessite use_hashing=True (le vocabulaire de "
                "TfidfVectorizer ne peut pas être construit en streaming). "
                "Activation automatique de use_hashing=True."
            )
            self.use_hashing = True

        similarity_logger.info(
            f"✅ CosineSimilarityTFIDF initialisé - model_dir: {model_dir}, "
            f"n_features: {n_features}, use_hashing: {self.use_hashing}, "
            f"use_streaming: {self.use_streaming}"
        )
    
    def _make_vectorizer(self, analyzer: str, ngram_range: tuple, n_feat: int,
                          token_pattern: str = None):
        """Retourne un TfidfVectorizer classique OU un Pipeline Hashing+Tfidf,
        selon self.use_hashing / self.use_streaming. Même interface de sortie
        (fit/transform) dans les 3 cas."""
        if self.use_hashing:
            hv_kwargs = dict(
                analyzer=analyzer,
                ngram_range=ngram_range,
                n_features=n_feat,
                alternate_sign=False,
                dtype=np.float32,
            )
            if token_pattern:
                hv_kwargs["token_pattern"] = token_pattern

            # /!\ Seule différence streaming vs non-streaming : le transformer
            # utilisé pour l'IDF. HashingVectorizer, lui, est déjà "streaming
            # friendly" par nature (pas de vocabulaire à construire).
            if self.use_streaming:
                tfidf_step = StreamingTfidfTransformer(sublinear_tf=True)
            else:
                tfidf_step = TfidfTransformer(sublinear_tf=True)

            return Pipeline([
                ("hash", HashingVectorizer(**hv_kwargs)),
                ("tfidf", tfidf_step),
            ], verbose=bool(self.verbose))
        else:
            tv_kwargs = dict(
                analyzer=analyzer,
                ngram_range=ngram_range,
                max_features=n_feat,
                min_df=1,
                max_df=0.9,
                sublinear_tf=True,
                dtype=np.float32,
            )
            if token_pattern:
                tv_kwargs["token_pattern"] = token_pattern
            return TfidfVectorizer(**tv_kwargs)
        
    def build_model(self):
        """Construit le modèle FeatureUnion avec TF-IDF multi-échelles et mots structurels"""
        similarity_logger.debug("Construction du modèle FeatureUnion...")
        
        # Répartition des features : 30% Mots (HTML/JSON), 40% Char(3-5), 30% Char(6-8)
        n_words = int(self.n_features * 0.3)
        n_short = int(self.n_features * 0.4)
        n_long = self.n_features - n_words - n_short
        
        similarity_logger.debug(f"  ├─ Mots structurels (HTML/JSON): {n_words}")
        similarity_logger.debug(f"  ├─ Features courtes (3-5): {n_short}")
        similarity_logger.debug(f"  └─ Features longues (6-8): {n_long}")
        
        transformers = [
            # 1. Analyseur de structure (Mots entiers, tags HTML, clés JSON)
            ("word_tokens", self._make_vectorizer(
                analyzer="word",
                ngram_range=(1, 1),
                n_feat=n_words,
                # Capture mots classiques + symboles individuels (évite un mot unique
                # par identifiant aléatoire, ex: <div id="1"> et <div id="2">)
                token_pattern=r'(?u)\b\w+\b|[^\w\s]',
            )),

            # 2. Analyseur de petits fragments (obfuscation, petites erreurs)
            ("short_ngrams", self._make_vectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                n_feat=n_short,
            )),

            # 3. Analyseur de longs fragments (phrases d'erreurs, chemins de fichiers)
            ("long_ngrams", self._make_vectorizer(
                analyzer="char",
                ngram_range=(6, 8),
                n_feat=n_long,
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
        # /!\ CHANGEMENT MAJEUR : On ne fait plus .toarray() !
        # Retourne une matrice creuse (scipy.sparse.csr_matrix).
        # C'est ~10x plus rapide pour le calcul cosinus et prend ~90% de RAM en moins.
        return self.model.transform(X)

    @staticmethod
    def _cache_key(X: list) -> str:
        return hashlib.sha256("\x00".join(X).encode("utf-8", errors="ignore")).hexdigest()
    
    def save_model(self, model, dir:str):
        similarity_logger.info(f"💾 Sauvegarde du modèle dans {dir}")
        try:
            buffer = io.BytesIO()
            joblib.dump(model, buffer, compress=9)
            buffer.seek(0)
            dumps = buffer.read()
            joblib_size = len(dumps) / (1024 * 1024)
            
            os.makedirs(dir, exist_ok=True)
            compressed = zstd.compress(dumps, level=21)
            model_path = os.path.join(dir, "model_similarity.joblib.zst")
            joblib.dump(compressed, model_path, compress=9)
            
            final_size = os.path.getsize(model_path) / (1024 * 1024)
            ratio = len(dumps) / len(compressed)
            
            similarity_logger.success(f"✓ Modèle sauvegardé: {model_path}")
            
            metadata = {
                "date_saved": datetime.now().isoformat(),
                "num_model": len(model.named_transformers),
                "models_name": list(model.named_transformers.keys()),
                "n_features": self.n_features,
                "use_hashing": self.use_hashing,
                "use_streaming": self.use_streaming,
                "compression": {
                    "original_size_mb": joblib_size,
                    "final_size_mb": final_size,
                    "ratio": ratio
                }
            }
            
            meta_path = os.path.join(dir, "metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
        except Exception as e:
            similarity_logger.error(f"❌ Erreur de sauvegarde du modèle: {str(e)}")
            raise
    
    def load_model(self, dir:str):
        similarity_logger.info(f"📂 Chargement du modèle depuis {dir}")
        try:
            model_path = os.path.join(dir, "model_similarity.joblib.zst")
            meta_path = os.path.join(dir, "metadata.json")
            
            compressed = joblib.load(model_path)
            decompressed = zstd.decompress(compressed)
            buffer = io.BytesIO(decompressed)
            self.model = joblib.load(buffer)
            try:
                self.model.n_jobs = 1
            except Exception:
                pass
            
            with open(meta_path, "r") as f:
                self.metadata = json.load(f)
            
            if "n_features" in self.metadata:
                self.n_features = self.metadata["n_features"]
            
            if "use_hashing" in self.metadata:
                self.use_hashing = self.metadata["use_hashing"]

            if "use_streaming" in self.metadata:
                self.use_streaming = self.metadata["use_streaming"]
                
            self._is_verify = True
            similarity_logger.success("✅ Modèle chargé avec succès")
            
        except Exception as e:
            similarity_logger.error(f"❌ Erreur de chargement du modèle: {str(e)}")
            raise
    
    def fit(self, X:list, y:list = None):
        similarity_logger.info("⚙️ Début de l'entraînement...")
        start_time = time.time()
        
        self.model = self.build_model()
        self.model.fit(X, y)
        self._is_verify = True
        
        elapsed = time.time() - start_time
        similarity_logger.success(f"✅ Entraînement terminé en {elapsed:.2f}s")
        self.save_model(self.model, self.model_dir)
    
    def fit_sequential(self, X:list, y:list = None):
        similarity_logger.info("⚙️ Début de l'entraînement...")
        start_time = time.time()
        
        self.model = self.build_model()
        models_path:list[tuple[str, str]] = []
        base_path = "./temp/models"
        os.makedirs(base_path, exist_ok=True)
        t = list(self.model.named_transformers.items())
        n = len(t)
        for i, (name, transformer) in enumerate(t, 1):
            p = os.path.abspath(
                os.path.join(
                    base_path,
                    f'{name}_.pkl'
                )
            )
            print(f"Step {i} / {n}, {name} -> {p}")
            transformer.fit(X, y)
            joblib.dump(transformer, p)
            models_path.append((name, p))
            print(f"Fin step {i} / {n}")
            del transformer
            gc.collect()
        
        transformers = [
            (name, joblib.load(p))
            for name, p in models_path
        ]
        self.model.transformer_list = transformers
        self._is_verify = True
        
        elapsed = time.time() - start_time
        similarity_logger.success(f"✅ Entraînement terminé en {elapsed:.2f}s")
        self.save_model(self.model, self.model_dir)
        for _, p in models_path:
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def fit_streaming(self, X: list, y: list = None, batch_size: int = None,
                       log_every: int = None, n_jobs: int = 1):
        """
        Entraînement en 2 passes SANS jamais charger tout le corpus
        vectorisé en RAM :
          - Passe 1 : on lit X batch par batch, on hash chaque batch
            (HashingVectorizer, taille fixe, pas de vocabulaire), et on
            accumule le doc_freq dans chaque StreamingTfidfTransformer.
          - Fin de passe 1 : on calcule l'IDF final pour chaque sous-modèle
            (word_tokens / short_ngrams / long_ngrams) du FeatureUnion.

        Le FeatureUnion reste inchangé dans sa structure : seule la
        manière de "fitter" chaque Pipeline interne change (batch par
        batch au lieu d'un .fit() sur tout X d'un coup).

        Nécessite use_hashing=True (activé automatiquement si besoin).

        log_every : nombre de batches entre deux logs de progression.
        Si None, calculé automatiquement pour ~20 lignes de log au total.

        n_jobs : nombre de branches (word_tokens/short_ngrams/long_ngrams)
        hashées EN PARALLÈLE pour chaque batch. Les 3 branches sont
        totalement indépendantes (accumulateurs séparés), donc c'est
        embarrassingly parallel — sûr même avec n_jobs=3 (le max utile,
        vu qu'il n'y a que 3 branches). La mise à jour des accumulateurs
        (partial_fit_batch) reste toujours faite séquentiellement APRÈS
        la parallélisation, pour éviter tout risque de race condition.
        n_jobs=1 (défaut) = comportement séquentiel classique, identique
        à avant. Ceci est indépendant du n_jobs de self.model (toujours
        figé à 1 pour l'inférence via _JOBS).
        """
        if not self.use_hashing:
            raise ValueError(
                "fit_streaming() nécessite use_hashing=True : TfidfVectorizer "
                "a besoin de construire un vocabulaire sur tout le corpus, "
                "ce qui n'est pas compatible avec le streaming."
            )
        self.use_streaming = True
        bs = batch_size or self.batch_size
        n_jobs = max(1, n_jobs)

        n = len(X)
        n_batches = (n + bs - 1) // bs
        if log_every is None:
            log_every = max(1, n_batches // 20)

        similarity_logger.info(
            f"⚙️ Début de l'entraînement streaming — {n} documents, "
            f"batch_size={bs}, {n_batches} batches, n_jobs={n_jobs}"
        )
        start_time = time.time()

        self.model = self.build_model()
        transformers = dict(self.model.named_transformers)
        names = list(transformers.keys())
        pipelines = list(transformers.values())

        # ── Passe 1 : accumulation du doc_freq, batch par batch ──────────
        for b, i in enumerate(range(0, n, bs), 1):
            batch = X[i:i + bs]

            if n_jobs > 1:
                # Hashing des 3 branches en parallèle (threads : le hashing
                # murmurhash + la construction de la matrice sparse libèrent
                # le GIL, donc un vrai gain est possible). La mise à jour des
                # accumulateurs se fait ensuite, séquentiellement, dans le
                # thread principal — donc zéro risque de race condition.
                hashed_batches = joblib.Parallel(n_jobs=n_jobs, backend="threading")(
                    joblib.delayed(pipeline.named_steps["hash"].transform)(batch)
                    for pipeline in pipelines
                )
                for name, pipeline, counts in zip(names, pipelines, hashed_batches):
                    pipeline.named_steps["tfidf"].partial_fit_batch(counts)
                    del counts
                del hashed_batches
            else:
                for name, pipeline in transformers.items():
                    hasher = pipeline.named_steps["hash"]
                    tfidf = pipeline.named_steps["tfidf"]
                    counts = hasher.transform(batch)   # petit : juste ce batch
                    tfidf.partial_fit_batch(counts)     # accumulateur MINUSCULE (taille n_features)
                    del counts
            gc.collect()

            docs_done = min(i + bs, n)
            if b == 1 or b % log_every == 0 or b == n_batches:
                elapsed_so_far = time.time() - start_time
                pct = 100 * docs_done / n
                throughput = docs_done / elapsed_so_far if elapsed_so_far > 0 else 0
                eta_min = ((n - docs_done) / throughput / 60) if throughput > 0 else 0
                peak_mb = _peak_rss_mb()
                mem_str = f", RAM pic≈{peak_mb:.0f} Mo" if peak_mb else ""
                similarity_logger.info(
                    f"  📦 Batch {b}/{n_batches} — {docs_done}/{n} docs ({pct:.1f}%) "
                    f"— {throughput:.0f} docs/s — ETA {eta_min:.1f} min{mem_str}"
                )

        # ── Fin de passe 1 : calcul de l'IDF final pour chaque sous-modèle ─
        for name, pipeline in transformers.items():
            idf = pipeline.named_steps["tfidf"].finalize_idf()
            similarity_logger.debug(f"  ├─ IDF calculé pour '{name}' (n_features={idf.shape[0]})")

        self._is_verify = True
        elapsed = time.time() - start_time
        similarity_logger.success(f"✅ Entraînement streaming terminé en {elapsed:.2f}s ({n} documents, {n_batches} batches)")
        self.save_model(self.model, self.model_dir)

    def transform_streaming(self, X: list, batch_size: int = None):
        """
        Transforme une grande liste de documents batch par batch et
        renvoie une seule matrice sparse empilée. Utile pour appliquer
        le modèle déjà fitté (fit_streaming) à un gros corpus sans tout
        charger d'un coup.
        """
        from scipy.sparse import vstack
        bs = batch_size or self.batch_size
        results = []
        for i in range(0, len(X), bs):
            batch = X[i:i + bs]
            results.append(self.model.transform(batch))
            gc.collect()
        return vstack(results).tocsr()
    
    def verify_model(self):
        with self._lock:
            try:
                if not self.model:
                    self.load_model(self.model_dir)
                if not self.model:
                    raise ValueError("Model indisponible")
                self._is_verify = True
            except Exception as e:
                similarity_logger.error(f"❌ Erreur de vérification: {str(e)}")
                raise
            
    def cosine_similarity(self, X1, X2, aggregation='mean'):
        if not self._is_verify:
            self.verify_model()
        
        if isinstance(X1, str): X1 = [X1]
        if isinstance(X2, str): X2 = [X2]
        
        with self._encode_semaphore:
            start_time = time.time()
            
            x1_key = self._cache_key(X1)
            with self._lock:
                X1_vec = TTLCACHE.get(x1_key)
    
            cache_hit = X1_vec is not None
            if not cache_hit:
                X1_vec = self.transform(X1)
                with self._lock:
                    TTLCACHE[x1_key] = X1_vec
    
            X2_vec = self.transform(X2)
            
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
        return self.cosine_similarity(X1, X2, aggregation=aggregation)

if __name__ == "__main__":
    StreamingTfidfTransformer.__module__ = "scanner_ia.fuzzer.similarity"
    
    def benchmark_inference(cosine_sim, sample_docs, n_runs=50):
        """
        A appeler juste après fit()/fit_streaming()/load_model().
        sample_docs : liste de documents REPRÉSENTATIFS (mélange de mes vraies tailles.
        """
        import time, random
        # Warm-up : la 1ère passe est souvent plus lente (imports internes, cache CPU)
        cosine_sim.transform([sample_docs[0]])
    
        times_transform, times_cosine = [], []
        for _ in range(n_runs):
            d1, d2 = random.sample(sample_docs, 2)
    
            t0 = time.perf_counter()
            cosine_sim.transform([d1])
            times_transform.append((time.perf_counter() - t0) * 1000)
    
            t0 = time.perf_counter()
            cosine_sim(d1, d2)
            times_cosine.append((time.perf_counter() - t0) * 1000)
    
        def stats(arr, label):
            arr = np.array(arr)
            print(f"{label:20s} — moyenne={arr.mean():.2f}ms  médiane={np.median(arr):.2f}ms  "
                  f"p95={np.percentile(arr,95):.2f}ms  max={arr.max():.2f}ms")
    
        stats(times_transform, "transform() seul")
        stats(times_cosine, "cosine_similarity()")
        return {"transform_ms": times_transform, "cosine_ms": times_cosine}

    def test():
        # Test d'exemple
        cosine_sim = CosineSimilarityTFIDF(n_features=1500, verbose=1, model_dir="test_similarity",)
        
        normal_responses = [
            "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page normale</body></html>",
            "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Page d'accueil</body></html>",
        ]
        
        suspicious_responses = [
            "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><script>alert('XSS')</script></body></html>",
            "HTTP/1.1 500 Internal Error\n\nErreur SQL: syntax error near 'SELECT'",
        ]
        
        cosine_sim.fit(normal_responses)
        
        print("\n--- Test Similarité ---")
        print(f"Normale vs XSS : {cosine_sim(normal_responses[0], suspicious_responses[0]):.4f}")
        print(f"Normale vs SQLi : {cosine_sim(normal_responses[0], suspicious_responses[1]):.4f}")
    
    def fit():
        import zstandard as zstd, time, random
        dpath = "/home/hounsousamuel/PROJET/obsidian_hive/modules/scanner_ia/src/scanner_ia/fuzzer/datasets/corpus_tfidf_web.json.zst"
        dataset = json.loads(zstd.decompress(open(dpath, "rb").read()))
        n = None # 200_000
        if n:
            dataset = random.sample(dataset, n)
        print(f"📊 Total pour l'entraînement : {len(dataset)} documents.")
        
        # ─── 3. ENTRAÎNEMENT DU MODÈLE TF-IDF ─────────────────────────────────────
        n_features = 2 ** 18
        print(f"\n⚙️ Lancement du .fit() avec {n_features} features...")
        start_fit = time.time()
        
        # Instanciation de votre modèle
        cosine_sim = CosineSimilarityTFIDF(
            n_features=n_features,
            verbose=1,
            use_hashing=True,
            use_streaming=True,   # active le mode 2-passes économe en RAM
            batch_size=50_000,
        )
        cosine_sim.fit_streaming(dataset, batch_size=5000, n_jobs=3)
        
        print(f"\n🎉 Entraînement terminé en {time.time() - start_fit:.2f}s !")
        print(f"💾 Modèle prêt et sauvegardé dans le dossier '{cosine_sim.model_dir}'.")
        
        sample_size = min(20_000, len(dataset))
        sample = random.sample(dataset, sample_size)
        benchmark_inference(cosine_sim, sample, n_runs=100)
    
    is_fit = bool(list(sys.argv)[1].strip()  in ("fit", "train")) if len(list(sys.argv)) >= 2 else False
    
    if is_fit:
        fit()
        
    else:
        test()