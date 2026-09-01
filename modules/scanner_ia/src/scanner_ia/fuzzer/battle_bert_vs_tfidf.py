#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 31 12:52:23 2026

@author: hounsousamuel
"""

"""
ShieldAI — Battle BERT vs TF-IDF pour la similarité baseline/payload du fuzzer.
"""

import os
import json
import time
import argparse
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
from sklearn.metrics import roc_auc_score

# =============================================================================
# 1. IMPORT DE VOTRE VRAI BACKEND TF-IDF
# =============================================================================
from scanner_ia.fuzzer.similarity import CosineSimilarityTFIDF


# =============================================================================
# 2. JEU DE TEST — synthétique
# =============================================================================

@dataclass
class TestCase:
    baseline: str
    response: str
    label: str  # "SAFE" ou "VULN"
    note: str = ""


SYNTHETIC_CASES: List[TestCase] = [
    # ── SAFE ──
    TestCase(
        "<html><body>Page d'accueil normale</body></html>",
        "<html><body>Page d'accueil normale</body></html>",
        "SAFE", "payload sans effet, écho identique",
    ),
    TestCase(
        "<html><body>Résultat de recherche : aucun produit trouvé</body></html>",
        "<html><body>Résultat de recherche : aucun produit trouvé</body></html>",
        "SAFE", "input neutre, comportement inchangé",
    ),
    TestCase(
        "{\"status\": \"ok\", \"user\": \"alice\", \"role\": \"user\"}",
        "{\"status\": \"ok\", \"user\": \"alice\", \"role\": \"user\"}",
        "SAFE", "API JSON, payload ignoré",
    ),
    TestCase(
        "<html><body>Formulaire de connexion</body></html>",
        "<html><body>Formulaire de connexion</body></html><!-- rien de changé -->",
        "SAFE", "quasi identique, commentaire HTML ajouté seulement",
    ),

    # ── VULN ──
    TestCase(
        "<html><body>Page d'accueil normale</body></html>",
        "<html><body><script>alert('XSS')</script></body></html>",
        "VULN", "XSS reflété — payload exécutable injecté verbatim",
    ),
    TestCase(
        "<html><body>Résultat de recherche : aucun produit trouvé</body></html>",
        "<html><body>Erreur SQL: syntax error near 'SELECT * FROM users WHERE'</body></html>",
        "VULN", "SQLi — message d'erreur SQL exposé",
    ),
    TestCase(
        "{\"status\": \"ok\"}",
        "uid=0(root) gid=0(root) groups=0(root)\nLinux srv01 5.15.0-generic",
        "VULN", "CMDi — sortie de commande système exposée",
    ),
    TestCase(
        "<html><body>Fichier introuvable</body></html>",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "VULN", "DirTrav — contenu de /etc/passwd exposé",
    ),
    TestCase(
        "<html><body>Traitement XML effectué</body></html>",
        "<html><body>root:x:0:0:root:/root:/bin/bash</body></html>",
        "VULN", "XXE — lecture de fichier via entité externe",
    ),
    TestCase(
        "<html><body>Profil utilisateur : alice</body></html>",
        "<html><body>Profil utilisateur : admin (role=superuser, email=admin@internal.local)</body></html>",
        "VULN", "IDOR — accès à un profil non autorisé",
    ),
    TestCase(
        "{\"status\": \"ok\", \"balance\": 100}",
        "Traceback (most recent call last):\n  File \"app.py\", line 42, in transfer\npickle.UnpicklingError: invalid load key",
        "VULN", "InsecDeser — stack trace Python exposée",
    ),
]


# =============================================================================
# 3. CHARGEMENT DU CORPUS ET DES CAS RÉELS
# =============================================================================

def load_corpus(corpus_path: str) -> List[str]:
    import zstandard as zstd
    if os.path.isdir(corpus_path):
        all_texts = []
        for fname in sorted(os.listdir(corpus_path)):
            if fname.endswith(".json.zst"):
                with open(os.path.join(corpus_path, fname), "rb") as f:
                    all_texts.extend(json.loads(zstd.decompress(f.read()).decode("utf-8")))
        return all_texts
    else:
        with open(corpus_path, "rb") as f:
            return json.loads(zstd.decompress(f.read()).decode("utf-8"))


def load_real_cases(path: str) -> List[TestCase]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [TestCase(**item) for item in raw]


# =============================================================================
# 4. HARNAIS DE BATTLE & AFFICHAGE
# =============================================================================

def run_backend(backend, cases: List[TestCase], name: str) -> dict:
    scores = []
    labels = []
    times = []

    for case in cases:
        t0 = time.perf_counter()
        score = backend.cosine_similarity(case.baseline, case.response, aggregation="mean")
        elapsed = time.perf_counter() - t0

        scores.append(score)
        labels.append(1 if case.label == "VULN" else 0)
        times.append(elapsed)

    scores = np.array(scores)
    labels = np.array(labels)

    safe_scores = scores[labels == 0]
    vuln_scores = scores[labels == 1]
    anomaly_scores = 1 - scores

    try:
        auc = roc_auc_score(labels, anomaly_scores) if len(set(labels)) > 1 else float("nan")
    except ValueError:
        auc = float("nan")

    return {
        "name": name,
        "mean_safe_score": float(safe_scores.mean()) if len(safe_scores) else float("nan"),
        "mean_vuln_score": float(vuln_scores.mean()) if len(vuln_scores) else float("nan"),
        "separation": float(safe_scores.mean() - vuln_scores.mean()) if len(safe_scores) and len(vuln_scores) else float("nan"),
        "roc_auc": float(auc),
        "total_time_s": float(sum(times)),
        "avg_time_ms": float(sum(times) / len(times) * 1000) if times else 0.0,
        "per_case": [
            {"note": c.note, "label": c.label, "score": float(s)}
            for c, s in zip(cases, scores)
        ],
    }


def print_scoreboard(bert_result: dict, tfidf_result: dict):
    print("\n" + "=" * 70)
    print("🥊 BATTLE : BERT vs TF-IDF")
    print("=" * 70)

    print(f"\n{'Métrique':<30} {'BERT':>18} {'TF-IDF':>18}")
    print("-" * 68)
    rows = [
        ("Score moyen SAFE (↑ mieux)", "mean_safe_score", ".4f"),
        ("Score moyen VULN (↓ mieux)", "mean_vuln_score", ".4f"),
        ("Séparation SAFE-VULN (↑ mieux)", "separation", ".4f"),
        ("ROC-AUC (↑ mieux, 1.0=parfait)", "roc_auc", ".4f"),
        ("Temps total (s)", "total_time_s", ".4f"),
        ("Temps moyen/appel (ms)", "avg_time_ms", ".3f"),
    ]
    for label, key, fmt in rows:
        b = format(bert_result[key], fmt)
        t = format(tfidf_result[key], fmt)
        print(f"{label:<30} {b:>18} {t:>18}")

    print("\n📌 Verdict :")
    speedup = bert_result['total_time_s'] / max(tfidf_result['total_time_s'], 1e-9)
    if tfidf_result["roc_auc"] >= bert_result["roc_auc"]:
        print(f"  → TF-IDF est GAGNANT (AUC {tfidf_result['roc_auc']:.4f} vs {bert_result['roc_auc']:.4f}) "
              f"ET {speedup:.1f}x plus rapide.")
    else:
        print(f"  → BERT discrimine mieux (AUC {bert_result['roc_auc']:.4f} vs {tfidf_result['roc_auc']:.4f}), "
              f"mais TF-IDF est {speedup:.1f}x plus rapide.")


# =============================================================================
# 5. FONCTIONS PRINCIPALES (DIRECTE & CLI)
# =============================================================================

def run_battle(
    model_path: str = "model_similarity",
    corpus_path: Optional[str] = None,
    real_cases_path: Optional[str] = None,
    max_features: int = 10_000,
    force_fit: bool = False,
    output_json: Optional[str] = "./battle_results.json"
):
    """
    Fonction appelable directement depuis Python avec vos variables.
    """
    cases = list(SYNTHETIC_CASES)
    if real_cases_path and os.path.exists(real_cases_path):
        real = load_real_cases(real_cases_path)
        cases.extend(real)
        print(f"➕ {len(real)} vraies paires ajoutées depuis {real_cases_path}")

    print(f"🧪 {len(cases)} cas de test au total "
          f"({sum(1 for c in cases if c.label=='SAFE')} SAFE / "
          f"{sum(1 for c in cases if c.label=='VULN')} VULN)")

    # ── 1. Initialisation de votre vraie classe TF-IDF ──
    tfidf = CosineSimilarityTFIDF(model_dir=model_path, n_features=max_features, verbose=0)
    
    # Vérification de l'existence du modèle (fichier direct ou dossier)
    model_exists = False
    if os.path.isdir(model_path) and os.path.exists(os.path.join(model_path, "model_similarity.joblib.zst")):
        model_exists = True
    elif os.path.isfile(model_path):
        model_exists = True

    if model_exists and not force_fit:
        print(f"📂 Modèle TF-IDF existant trouvé et chargé depuis : {model_path}")
        tfidf.load_model(model_path)
    else:
        if not corpus_path or not os.path.exists(corpus_path):
            raise FileNotFoundError(
                f"Aucun modèle trouvé à '{model_path}' et aucun corpus valide fourni ('{corpus_path}')."
            )
        print(f"📥 Chargement du corpus : {corpus_path}")
        corpus_texts = load_corpus(corpus_path)
        print(f"   └─ {len(corpus_texts)} documents chargés")
        print(f"⚙️ Entraînement TF-IDF ({max_features} features)...")
        tfidf.fit(corpus_texts)
        print(f"💾 Nouveau modèle entraîné et sauvegardé dans : {tfidf.model_dir}")

    # ── 2. Chargement BERT ──
    try:
        from scanner_ia.fuzzer.similarity_bert import CosineSimilarityBERT
        bert = CosineSimilarityBERT()
        bert.verify_model()
    except Exception as e:
        print(f"⚠️ Impossible de charger BERT ({e}), test avec TF-IDF seul.")
        bert = None

    # ── 3. Lancement des Benchmarks ──
    tfidf_result = run_backend(tfidf, cases, "TF-IDF")
    
    if bert:
        print("\n🏃 Exécution BERT...")
        bert_result = run_backend(bert, cases, "BERT")
        print("🏃 Exécution TF-IDF...")
        print_scoreboard(bert_result, tfidf_result)
        res_data = {"bert": bert_result, "tfidf": tfidf_result}
    else:
        res_data = {"tfidf": tfidf_result}

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(res_data, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Résultats sauvegardés dans : {output_json}")

    return res_data


def main():
    """Point d'entrée CLI (Argparse)."""
    parser = argparse.ArgumentParser(description="Battle BERT vs TF-IDF (similarité fuzzer)")
    parser.add_argument("--model-path", default="model_similarity", help="Dossier ou fichier du modèle")
    parser.add_argument("--corpus", default=None, help="Chemin vers le corpus .json.zst")
    parser.add_argument("--real-cases", default=None, help="JSON de vraies paires (optionnel)")
    parser.add_argument("--max-features", type=int, default=10_000)
    parser.add_argument("--force-fit", action="store_true", help="Force le réentraînement")
    parser.add_argument("--output", default="./battle_results.json", help="Fichier de sortie des résultats")
    args = parser.parse_args()

    run_battle(
        model_path=args.model_path,
        corpus_path=args.corpus,
        real_cases_path=args.real_cases,
        max_features=args.max_features,
        force_fit=args.force_fit,
        output_json=args.output
    )


if __name__ == "__main__":
    # import __main__
    # from scanner_ia.fuzzer.similarity import StreamingTfidfTransformer
    # __main__.StreamingTfidfTransformer = StreamingTfidfTransformer
    # Option 1: Via CLI
    # main()

    # Option 2: Appel direct Python
    run_battle(
        model_path="model_similarity",                # Dossier où se trouve model_similarity.joblib.zst
        corpus_path="./safe_web_dataset_160k.json.zst", # Votre corpus si réentraînement
        force_fit=False,                              # False = utilise le modèle sauvegardé
        output_json="./battle_results.json",
        max_features=2 ** 18
    )