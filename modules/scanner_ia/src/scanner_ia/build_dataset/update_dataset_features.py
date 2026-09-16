#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 15 11:04:15 2026

@author: hounsousamuel
"""

"""
update_dataset_features.py — Régénère les features dérivées de la réponse
(is_json/json_*, balises HTML, tech_*, headers de sécu, code_scripts_*,
passive_*) sur des datasets déjà collectés, en repassant chaque URL dans
le VRAI pipeline :

    AnalyzerHelper (crawl+fetch+parse) -> CodeAnalyzer -> PassiveAnalyzer
    -> FeatureExtractor.extract()

... et pas un simple fetch brut. C'est ce qui garantit que num_balise_*,
tech_*, code_scripts_* etc. sont correctement recalculés maintenant que
vulnserver/safeserver renvoient parfois du HTML.

LE FUZZER N'EST PAS RELANCÉ : les colonnes fuzzer_* / num_active_test /
fuzer_ratio_vuln / fuzzer_ratio_* / fuzzer_max_score sont RÉUTILISÉES
telles quelles depuis le dataset d'origine (labels indépendants du
fuzzer — vérifié dans build_dataset.py — et comportement des moteurs
inchangé). On passe un FuzzerResult() vide à extract() puis on écrase
ses colonnes fuzzer_* (mises à 0 par défaut) avec les anciennes valeurs.

MATCHING : dataframes et urls partagent un seul pool d'urls, consommé
séquentiellement (même logique que la version précédente) :
    df A = 100 échantillons -> urls[0:100]
    df B = 50  échantillons (suit A) -> urls[100:150]

Pas de réordonnancement de colonnes ici : FeatureExtractor.extract()
filtre déjà sur FEATURES_LIST en interne.

⚠️ Suppose que vulnserver/safeserver tournent déjà.
"""

import asyncio
import time
from typing import List

import aiohttp
import pandas as pd

from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.ml_model.features_extractor import FeatureExtractor
from scanner_ia.scanner_utils.utils_scanner import is_url_reachable
# Colonnes réutilisées telles quelles depuis le dataset d'origine
# (le fuzzer n'est pas relancé par ce script).
FUZZER_COLS = [
    'fuzzer_SQLi', 'fuzzer_CMDi', 'fuzzer_InsecDeser', 'fuzzer_InsecUpload',
    'fuzzer_BufOvr', 'fuzzer_CredsExpose', 'fuzzer_BrokenAuth', 'fuzzer_XSS',
    'fuzzer_DirTrav', 'fuzzer_XXE', 'fuzzer_NoSQLi', 'fuzzer_LDAPi',
    'fuzzer_InsecPerm', 'fuzzer_IDOR', 'fuzzer_SessFix', 'fuzzer_SSRF',
    'fuzzer_SSTI', 'fuzzer_Prototype_Pollution', 'fuzzer_HTTP_Request_Smuggling',
    'fuzzer_XPATH_Injection', 'fuzzer_GraphQLi', 'fuzzer_CORS', 'fuzzer_CSRF',
    'fuzzer_RateLimit', 'fuzzer_InfoDisc', 'fuzzer_InsecCrypto',
    'fuzzer_OpenRedirect', 'fuzzer_JWT', 'fuzzer_CRLF_Injection',
    'fuzzer_RaceCondition',
    'num_active_test', 'fuzer_ratio_vuln', 'fuzzer_ratio_indicators_matched',
    'fuzzer_ration_status_changed', 'fuzzer_ratio_headers_changed',
    'fuzzer_ratio_body_changed', 'fuzzer_max_score',
]


def _assign_url_slices(dataframes: List[pd.DataFrame], urls: List[str]) -> List[List[str]]:
    """Distribue le pool d'urls séquentiellement selon la taille de chaque df."""
    total_needed = sum(len(df) for df in dataframes)
    if total_needed > len(urls):
        raise ValueError(
            f"Pas assez d'urls : {total_needed} échantillons au total, "
            f"seulement {len(urls)} urls fournies."
        )
    slices, cursor = [], 0
    for df in dataframes:
        n = len(df)
        slices.append(urls[cursor: cursor + n])
        cursor += n
    return slices


async def _extract_one(
    url: str,
    analyzer: AnalyzerHelper,
    code_analyzer: CodeAnalyzer,
    passive_analyzer: PassiveCodeAnalyzer,
    feature_extractor: FeatureExtractor,
) -> pd.DataFrame:
    """
    Repasse une URL dans le vrai pipeline. Retourne TOUJOURS exactement
    1 ligne (même en cas d'échec, avec des colonnes vides/NaN) pour que
    l'alignement positionnel avec le dataframe d'origine reste garanti.
    """
    try:
        # can = await is_url_reachable(url, timeout=160)
        # if not can:
        #     print(f"[warning] {url} inaccessible, analyse annulée")
        #     return pd.DataFrame([{}])
        
        analyzer_response = await analyzer.analyse_and_parse_all(
            url, verify_reachability=False, restore=False, silent=True
        )
        ca_result = code_analyzer.analyse(analyzer_response)
        pa_result = passive_analyzer.analyse(analyzer_response)
        features = await feature_extractor.extract(
            analyzer_response, pa_result, ca_result, FuzzerResult()
        )
        if len(features) != 1:
            print(f"⚠️  {url} : {len(features)} ligne(s) extraite(s) au lieu de 1 "
                  f"(url injoignable/vide ?) — ligne vide insérée pour garder l'alignement")
            return pd.DataFrame([{}])
        return features.reset_index(drop=True)
    except Exception as e:
        print(f"⚠️  Échec extraction {url} : {e}")
        return pd.DataFrame([{}])


async def _worker(
    queue: "asyncio.Queue",
    results: list,
    analyzer: AnalyzerHelper,
    code_analyzer: CodeAnalyzer,
    passive_analyzer: PassiveCodeAnalyzer,
    feature_extractor: FeatureExtractor,
    progress: dict,
    total: int,
) -> None:
    """Consomme la queue en continu — pool de taille fixe, pas 1 task par url."""
    while True:
        item = await queue.get()
        if item is None:  # signal d'arrêt
            queue.task_done()
            break
        idx, url = item
        results[idx] = await _extract_one(url, analyzer, code_analyzer, passive_analyzer, feature_extractor)
        progress["done"] += 1
        if progress["done"] % 200 == 0 or progress["done"] == total:
            print(f"   … {progress['done']}/{total} urls traitées")
        queue.task_done()


async def _extract_many(urls: List[str], concurrency: int, get_timeout: float) -> pd.DataFrame:
    """
    Pool de `concurrency` workers fixes qui dépilent une queue — le
    nombre de tasks créées est borné à `concurrency`, jamais à
    len(urls). Scalable à 100k+ urls sans exploser la mémoire ni
    l'ordonnanceur asyncio.
    """
    n = len(urls)
    results: list = [None] * n
    queue: asyncio.Queue = asyncio.Queue()
    for idx, url in enumerate(urls):
        queue.put_nowait((idx, url))
    for _ in range(concurrency):
        queue.put_nowait(None)  # 1 signal d'arrêt par worker

    progress = {"done": 0}

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        force_close=True,        # pas de réutilisation de socket = plus de race
        enable_cleanup_closed=True,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        analyzer = AnalyzerHelper(session=session, use_cache=False, GET_TIMEOUT=get_timeout)
        analyzer.crawler.config.MAX_WORKERS = 1
        analyzer.crawler.config.MAX_DEEPTH = 1
        analyzer.crawler.config.MAX_PAGES = 1
        analyzer.crawler.config.GET_TIMEOUT = 2
        analyzer.crawler.config.JOIN_TIMEOUT = 1 * 10 * 60
        analyzer.crawler.config.USE_CACHE_FOR_GET_LINKS = False
        analyzer.crawler.config.SAVE_ON_CRAWL = False
        analyzer.crawler.parser.fetcher.config.TIMEOUT = 120
        code_analyzer = CodeAnalyzer(True)
        passive_analyzer = PassiveCodeAnalyzer()
        feature_extractor = FeatureExtractor()

        workers = [
            asyncio.create_task(
                _worker(queue, results, analyzer, code_analyzer, passive_analyzer, feature_extractor, progress, n)
            )
            for _ in range(concurrency)
        ]
        await asyncio.gather(*workers)

    return pd.concat(results, ignore_index=True)


async def update_datasets(
    dataframes: List[pd.DataFrame],
    urls: List[str],
    paths: List[str],
    concurrency: int = 20,
    get_timeout: float = 15.0,
) -> List[pd.DataFrame]:
    if len(dataframes) != len(paths):
        raise ValueError("dataframes et paths doivent avoir la même longueur (1 chemin de sauvegarde par dataframe).")

    url_slices = _assign_url_slices(dataframes, urls)
    updated = []
    cursor = 0

    for i, (df, url_slice, path) in enumerate(zip(dataframes, url_slices, paths)):
        print(f"\n📦 Dataset {i + 1}/{len(dataframes)} — {len(df)} échantillons "
              f"(urls[{cursor}:{cursor + len(url_slice)}])")
        cursor += len(url_slice)
        start = time.time()

        fresh = await _extract_many(url_slice, concurrency, get_timeout)
        fresh = fresh.reset_index(drop=True)

        df = df.reset_index(drop=True).copy()

        # Toutes les colonnes fraîches SAUF les colonnes fuzzer (réutilisées
        # telles quelles depuis df, pas de refuzz).
        fresh_cols = [c for c in fresh.columns if c not in FUZZER_COLS and c != "url"]
        for col in fresh_cols:
            df[col] = fresh[col].values

        elapsed = time.time() - start
        n_json = int(df["is_json"].sum()) if "is_json" in df.columns else -1
        print(f"✅ {len(df)} lignes régénérées en {elapsed:.1f}s "
              f"({n_json} réponses JSON, {len(df) - n_json} HTML/autres)"
              if n_json >= 0 else f"✅ {len(df)} lignes régénérées en {elapsed:.1f}s")

        df.to_csv(path, index=False)
        print(f"💾 Sauvegardé : {path}")
        updated.append(df)

    return updated


# ============================================================
# CONFIG — modifie directement ces variables
# ============================================================
DATASET_PATHS = [
    "./dataset/shieldai_dataset_augmented_v4_001.csv",
    "./dataset/shieldai_dataset_augmented_v4_01.csv",
    "./dataset/shieldai_dataset_augmented_v4_02.csv",
    "./dataset/shieldai_dataset_augmented_v4_03.csv",
]
URLS = []  # <- à remplir : list[str], même ordre que la concaténation des DATASET_PATHS
OUTPUT_PATHS = [
    "./dataset/shieldai_dataset_augmented_v4_001_v2.csv",
    "./dataset/shieldai_dataset_augmented_v4_01_v2.csv",
    "./dataset/shieldai_dataset_augmented_v4_02_v2.csv",
    "./dataset/shieldai_dataset_augmented_v4_03_v2.csv",
]
CONCURRENCY = 20  # plus bas que le fetch brut : pipeline plus lourd (crawl+parse+code+passive)
GET_TIMEOUT = 15.0
# ============================================================


def main():
    dataframes = [pd.read_csv(p) for p in DATASET_PATHS]
    asyncio.run(update_datasets(
        dataframes, URLS, OUTPUT_PATHS,
        concurrency=CONCURRENCY, get_timeout=GET_TIMEOUT,
    ))


if __name__ == "__main__":
    from scanner_ia.build_dataset.utils_update_json_features import (
        URLS, CHUNK_FILES as DATASET_PATHS
    )
    OUTPUT_PATHS = DATASET_PATHS.copy()
    main()