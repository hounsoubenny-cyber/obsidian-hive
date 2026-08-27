#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 17 13:07:22 2026

@author: hounsousamuel
"""

"""
Benchmark ThreadPoolExecutor vs ProcessPoolExecutor
=====================================================
Objectif : trancher, sur TA vraie machine multi-coeurs, si passer analyse()
en ProcessPoolExecutor vaut le coup — ou si ThreadPoolExecutor suffit déjà.

Le workload simulé reproduit les 2 natures de calcul qu'on a identifiées
dans analyse() :
  1. REGEX_ONLY   -> proxy du string/regex matching (html_signatures.json,
                      ~154 règles) — 100% Python pur, bloqué par le GIL.
  2. REGEX_PLUS_NUMPY -> ajoute un calcul matriciel lourd (proxy de
                      model.encode()/transform() pour BERT/TFIDF), qui
                      libère en partie le GIL (confirmé par le micro-test
                      qu'on a fait avant : x1.29 de ralentissement contre
                      x1.92 pour du Python pur en concurrence).

Comment lire les résultats :
  - Si REGEX_ONLY : ProcessPool nettement plus rapide que ThreadPool
    (proche du nb de coeurs)  -> le GIL est bien le goulot, vaut le coup
    de migrer au moins la partie regex/string-matching en process.
  - Si REGEX_PLUS_NUMPY : l'écart ThreadPool/ProcessPool se réduit
    -> le calcul modèle (déjà hors-GIL) compense une partie du manque à
    gagner du ThreadPool sur la partie Python pure.

Usage :
    python3 bench_thread_vs_process.py
    python3 bench_thread_vs_process.py --workers 10 --payloads 2000
    python3 bench_thread_vs_process.py --mode regex_only
    python3 bench_thread_vs_process.py --mode both   # les deux modes, à la suite
"""

import argparse
import re
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


# ─────────────────────────────────────────────────────────────────────────
# Simulation du corps de réponse HTTP (baseline / test), taille réaliste
# ─────────────────────────────────────────────────────────────────────────
def _random_body(size_kb: float = 8.0) -> str:
    n = int(size_kb * 1024)
    chunk = "".join(random.choices(string.ascii_letters + string.digits + " <>/=\"'\n", k=n))
    return f"<html><body>{chunk}</body></html>"


# Un sous-ensemble représentatif des patterns qu'on a vus dans
# html_signatures.json (XSS, SQLi, XXE, SSRF, LDAP, path traversal, etc.)
# — pas besoin des 154 exactes, la charge CPU par regex est ce qui compte.
_PATTERNS = [
    re.compile(p) for p in [
        r"<!DOCTYPE\s+[^>]+>",
        r"(uid=.*)(cn=.*)",
        r"root:x:0:0:root",
        r"SHLD[A-Z0-9]{4,16}",
        r"169\.254\.169\.254",
        r"health.*\"status\":",
        r"instance-id",
        r"computeMetadata",
        r"iam/security-credentials",
        r"google/compute/v1",
        r"local-ipv4",
        r"ami-id",
        r"<script[^>]*>[^<]+</script>",
        r"(?i)select\s+.+\s+from\s+.+",
        r"(?i)union\s+select",
        r"\.\./\.\./",
        r"php://filter",
        r"\$\{.*\}",
        r"#set\(\$\w+=",
        r"(?i)<iframe[^>]*srcdoc",
    ]
] * 8  # x8 pour retomber sur ~150 checks, comme dans le vrai code


def _regex_scan(body: str) -> int:
    """Proxy du string/indicator matching — 100% Python pur, GIL-bound."""
    hits = 0
    for pattern in _PATTERNS:
        if pattern.search(body):
            hits += 1
    return hits


def _model_encode_proxy(body_a: str, body_b: str) -> float:
    """
    Proxy de model.encode()/transform() + cosine_similarity — calcul
    matriciel lourd type BERT/TFIDF, qui libère une bonne partie du GIL
    (confirmé par microbenchmark).
    """
    if not HAS_NUMPY:
        return 0.0
    rng = np.random.default_rng(abs(hash(body_a[:50])) % (2**32))
    a = rng.random((600, 600))
    b = rng.random((600, 600))
    m = a @ b
    return float(m.mean())


def analyse_one(args) -> dict:
    """
    Une 'analyse()' simulée pour un seul payload — mode paramétrable.
    args = (baseline_body, test_body, mode)
    """
    baseline_body, test_body, mode = args
    result = {"hits": 0, "sim": 0.0}
    result["hits"] = _regex_scan(test_body)
    if mode == "regex_plus_numpy":
        result["sim"] = _model_encode_proxy(baseline_body, test_body)
    return result


# ─────────────────────────────────────────────────────────────────────────
# Harnais de benchmark
# ─────────────────────────────────────────────────────────────────────────
def run_bench(executor_cls, n_workers: int, tasks: list, label: str) -> float:
    start = time.time()
    with executor_cls(max_workers=n_workers) as executor:
        results = list(executor.map(analyse_one, tasks))
    elapsed = time.time() - start
    total_hits = sum(r["hits"] for r in results)
    print(f"  {label:<22} : {elapsed:6.2f}s  ({len(tasks)/elapsed:7.1f} payloads/s)  [sanity hits={total_hits}]")
    return elapsed


def main():
    parser = argparse.ArgumentParser(description="Benchmark ThreadPool vs ProcessPool pour analyse()")
    parser.add_argument("--workers", type=int, default=min(10, multiprocessing.cpu_count()),
                         help="Nombre de workers (défaut: min(10, nb de coeurs))")
    parser.add_argument("--payloads", type=int, default=1500,
                         help="Nombre de payloads simulés (défaut: 1500)")
    parser.add_argument("--body-size-kb", type=float, default=8.0,
                         help="Taille simulée du corps de réponse HTTP en Ko (défaut: 8)")
    parser.add_argument("--mode", choices=["regex_only", "regex_plus_numpy", "both"], default="both",
                         help="Quelle charge simuler (défaut: both = les deux, à la suite)")
    args = parser.parse_args()

    print(f"CPU disponibles : {multiprocessing.cpu_count()}")
    print(f"Workers utilisés : {args.workers}")
    print(f"Payloads simulés : {args.payloads}")
    print(f"NumPy dispo : {HAS_NUMPY} {'' if HAS_NUMPY else '(mode regex_plus_numpy sera équivalent à regex_only)'}")
    print()

    baseline_body = _random_body(args.body_size_kb)
    modes = ["regex_only", "regex_plus_numpy"] if args.mode == "both" else [args.mode]

    for mode in modes:
        print(f"═══ MODE: {mode} ═══")
        tasks = [(baseline_body, _random_body(args.body_size_kb), mode) for _ in range(args.payloads)]

        t_seq = run_bench(ThreadPoolExecutor, 1, tasks, "Séquentiel (1 worker)")
        t_thread = run_bench(ThreadPoolExecutor, args.workers, tasks, f"ThreadPool ({args.workers}w)")
        t_process = run_bench(ProcessPoolExecutor, args.workers, tasks, f"ProcessPool ({args.workers}w)")

        print(f"  -> Speedup ThreadPool  vs séquentiel : x{t_seq/t_thread:.2f}")
        print(f"  -> Speedup ProcessPool vs séquentiel : x{t_seq/t_process:.2f}")
        print(f"  -> ProcessPool vs ThreadPool          : x{t_thread/t_process:.2f} "
              f"({'ProcessPool gagne' if t_process < t_thread else 'ThreadPool gagne'})")
        print()


if __name__ == "__main__":
    main()