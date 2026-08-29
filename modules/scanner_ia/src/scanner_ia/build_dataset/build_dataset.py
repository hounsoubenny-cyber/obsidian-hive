#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 21:22:58 2026

@author: hounsousamuel
"""

import os
import sys
import json
import time
import asyncio
import aiohttp
import traceback
import pandas as pd
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter
from nest_asyncio import apply

from scanner_ia.core.parser import Parser
from scanner_ia.analyzers.code_analyzer import CodeAnalyzer
from scanner_ia.analyzers.passive_analyzer import PassiveCodeAnalyzer
from scanner_ia.fuzzer.response_analyzer import ResponseAnalyzer
from scanner_ia.base_class.analyser_helper_base_class import AnalyzerHelperResult
from scanner_ia.base_class.code_analyse_base_class import CodeAnalyzerResult
from scanner_ia.base_class.fuzzer_base_class import FuzzerResult
from scanner_ia.base_class.passive_analyzer_base_class import PassiveAnalyzerResult
from scanner_ia.core.analyzer_helper import AnalyzerHelper
from scanner_ia.fuzzer.active_fuzzer import Fuzzer
from scanner_ia.ml_model.features_extractor import FeatureExtractor
from scanner_ia.scanner_utils.helpers.resolve_helpers import (
    HelperCall,
    resolve_helpers,
)
from scanner_ia.scanner_utils.logger import get_logger
from scanner_ia.scanner_utils.utils_scanner import is_url_reachable
from scanner_ia.build_dataset.build_dataset_data import V1_TARGETS

logger = get_logger()

# Nombre FIXE de workers pour la construction du dataset.
# Indépendant du nombre de cibles : ne monte plus jamais en flèche avec
# la taille de V1_TARGETS. À tuner selon la RAM/CPU dispo (chaque worker
# porte un Fuzzer + un AnalyzerHelper/Crawler ; le ResponseAnalyzer/BERT
# est partagé une seule fois pour tout le run, voir build_dataset()).
NUM_WORKERS = 100


# =============================================================================
# 1. CLASSE DE CONFIGURATION AVEC TO_DICT ET FROM_DICT
# =============================================================================

@dataclass
class SingleUrlExtractorConfig:
    """Configuration fine pour l'extraction de features sur une URL unique."""

    # ── Réseau & Scope ──
    timeout: int = 10
    semaphore: int = 20
    verify_reachability: bool = True
    allowed_domains: List[str] = field(
        default_factory=lambda: ["http://127.0.0.1", "http://localhost"]
    )
    is_spa: bool = False

    # ── Authentification / Helpers ──
    helpers: List[Dict[str, Any] | HelperCall] = field(default_factory=list)
    raise_on_helper_error: bool = False

    # ── Contrôle du Fuzzing ──
    active_fuzz: bool = True
    limit_vulns: Optional[List[str] | int] = None
    max_test_fuzzer: Optional[int] = None
    fuzzer_delay: float = 0.001
    dynamic_timeout: bool = False
    use_semantic: bool = True
    use_arjun: bool = False
    arjun_timeout: int = 30
    known_params_dir: Optional[str] = None

    # ── Cache & Debug ──
    # Tout le cache est désactivé par défaut pour le build de dataset :
    # on veut toujours des résultats frais, jamais une valeur périmée
    # d'un run précédent (cf. bug classify_link/get_all_links du 29/08).
    use_cache: bool = False
    restore: bool = False
    debug: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Sérialise la configuration en dictionnaire JSON-compatible."""
        data = asdict(self)
        data["helpers"] = [
            h.model_dump() if hasattr(h, "model_dump") else h
            for h in self.helpers
        ]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SingleUrlExtractorConfig":
        """Instancie la configuration depuis un dictionnaire."""
        if not data:
            return cls()

        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}

        return cls(**filtered_data)


# =============================================================================
# 2. FONCTION PRINCIPALE ASYNC SANS GESTION DE SESSION
# =============================================================================

async def extract_features_single_url(
    url: str,
    analyzer_helper: AnalyzerHelper,
    passive_analyzer: PassiveCodeAnalyzer,
    code_analyzer: CodeAnalyzer,
    feature_extractor: FeatureExtractor,
    fuzzer: Optional[Fuzzer] = None,
    config: Optional[SingleUrlExtractorConfig] = None,
    vulns: Optional[list] = None,
) -> Tuple[pd.DataFrame, dict]:
    """Extrait le vecteur de features complet (100+ colonnes) pour une seule URL

    en orchestrant les instances de modules déjà injectées.
    """
    cfg = config or SingleUrlExtractorConfig()

    # ── 1. Normalisation & Vérification ──
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    url = url.strip()

    if cfg.verify_reachability:
        if not await is_url_reachable(url, timeout=cfg.timeout):
            raise ValueError(f"URL cible inaccessible : {url}")

    try:
        logger.info(f"🚀 [FeatureExtractor] Début d'analyse pour : {url}")

        # ── 2. Phase 1 : Crawl, Parse & Baseline ──
        resolved_helpers = resolve_helpers(cfg.helpers) if cfg.helpers else []

        crawled_data: AnalyzerHelperResult = await analyzer_helper.analyse_and_parse_all(
            url=url,
            verify_reachability=False,
            restore=cfg.restore,
            fetch=True,
            semaphore=cfg.semaphore,
            silent=not cfg.debug,
            helpers=resolved_helpers,
            raise_on_helper_error=cfg.raise_on_helper_error,
            is_spa=cfg.is_spa,
        )

        if not crawled_data or not crawled_data.elements:
            raise RuntimeError(f"Échec de récupération de la page pour l'URL : {url}")

        # Restreindre strictement aux données de l'URL cible (éviter les débordements).
        # Le crawler stocke ses clés après normalize_link() + rstrip("/"), qui peut
        # différer légèrement de `url` ici (ex: slash final). On tente donc le match
        # exact, puis un match "sans slash final", et seulement en dernier recours on
        # retombe sur la première entrée — avec un warning si l'ambiguïté est réelle
        # (plusieurs pages crawlées), pour ne plus jamais sélectionner silencieusement
        # la mauvaise page.
        if url in crawled_data.elements:
            crawled_data.elements = {url: crawled_data.elements[url]}
        elif url.rstrip("/") in crawled_data.elements:
            matched_url = url.rstrip("/")
            crawled_data.elements = {matched_url: crawled_data.elements[matched_url]}
        else:
            first_key = next(iter(crawled_data.elements))
            if len(crawled_data.elements) > 1:
                logger.warning(
                    f"⚠️ Clé exacte pour '{url}' introuvable parmi "
                    f"{len(crawled_data.elements)} entrées crawlées — fallback sur "
                    f"'{first_key}'. Vérifier la normalisation d'URL si ce n'est pas "
                    f"la cible attendue."
                )
            crawled_data.elements = {first_key: crawled_data.elements[first_key]}

        # ── 3. Phase 2 & 3 : Analyses Passive et Statique ──
        passive_result: PassiveAnalyzerResult = await asyncio.to_thread(
            passive_analyzer.analyse,
            crawled_data,
        )

        code_result: CodeAnalyzerResult = await asyncio.to_thread(
            code_analyzer.analyse,
            crawled_data,
        )

        # ── 4. Phase 4 : Fuzzing Actif Différentiel ──
        fuzzer_result: FuzzerResult
        if cfg.active_fuzz and fuzzer is not None:
            domain = Parser.get_domain(url) or "localhost"
            allowed = list(set(cfg.allowed_domains + [url, domain]))

            fuzzer_result = await fuzzer.fuzz(
                base_url=url,
                analyzer_helper_result=crawled_data,
                limit_vuln=cfg.limit_vulns,
                time_between=cfg.fuzzer_delay,
                allowed_domains=allowed,
                dynamic_timeout=cfg.dynamic_timeout,
                max_test=cfg.max_test_fuzzer,
            )
        else:
            # Mode Passif pur
            fuzzer_result = FuzzerResult()
            fuzzer_result.url = url

        # ── 5. Phase 5 : Extraction & Tabularisation ──
        features_df: pd.DataFrame = await feature_extractor.extract(
            analyzer_helper_result=crawled_data,
            passive_analyzer_result=passive_result,
            code_analyzer_result=code_result,
            fuzzer_result=fuzzer_result,
        )

        if features_df.empty:
            raise RuntimeError(f"FeatureExtractor a retourné un DataFrame vide pour {url}")

        logger.success(f"✅ Features extraites ({features_df.shape[1]} colonnes) pour {url}")

        if "url" in features_df.columns:
            matching = features_df[features_df["url"] == url]
            row_df = matching if not matching.empty else features_df.iloc[[0]]
        else:
            row_df = features_df.iloc[[0]]

        row = row_df.iloc[0].to_dict()
        row["url"] = url
        row["labels"] = vulns if vulns is not None else []

        return features_df, row

    except Exception as e:
        logger.error(f"❌ Erreur lors de l'extraction sur {url} : {e}")
        if cfg.debug:
            logger.error(traceback.format_exc())
        raise


# =============================================================================
# 3. POOL DE WORKERS (fonction libre, hors de build_dataset())
# =============================================================================

@dataclass
class _DatasetWorkerContext:
    """Regroupe les ressources partagées entre tous les workers du pool.

    Permet de garder `_dataset_worker` comme fonction libre (pas une closure
    imbriquée dans `build_dataset`) sans lui passer une dizaine de paramètres
    positionnels séparés.
    """
    session: aiohttp.ClientSession
    queue: "asyncio.Queue[tuple]"
    results: list
    results_lock: asyncio.Lock
    base_config: SingleUrlExtractorConfig
    total: int
    passive_analyzer: PassiveCodeAnalyzer
    code_analyzer: CodeAnalyzer
    feature_extractor: FeatureExtractor
    shared_response_analyzer: ResponseAnalyzer


async def _dataset_worker(worker_id: int, ctx: _DatasetWorkerContext) -> None:
    """Un worker du pool fixe : consomme `ctx.queue` jusqu'à épuisement.

    Un seul `Fuzzer` est créé ici pour tout le worker (pas par cible), et
    réutilisé séquentiellement pour toutes les URLs qu'il traite. Le reset
    de l'état mutable entre deux cibles (`_cancel_flag`) est désormais géré
    directement dans `Fuzzer.fuzz()` (finally), donc rien à faire ici.

    NE JAMAIS partager un `Fuzzer` ENTRE plusieurs workers concurrents : il
    porte de l'état d'instance (self.config, self._cancel_flag) qui n'est
    pas isolé par tâche.
    """
    base_config = ctx.base_config

    fuzzer: Optional[Fuzzer] = None
    if base_config.active_fuzz:
        fuzzer = Fuzzer(
            session=ctx.session,
            semaphore=base_config.semaphore,
            debug=base_config.debug,
            use_semantic=base_config.use_semantic,
            use_arjun=base_config.use_arjun,
            arjun_timeout=base_config.arjun_timeout,
            known_params_dir=base_config.known_params_dir,
        )
        fuzzer.config.MAX_WORKERS = 20
        fuzzer.config.GET_TIMEOUT = 2
        fuzzer.config.FUZZ_TIMEOUT = 15 * 10 * 60
        # Remplace le ResponseAnalyzer (avec son propre BERT) créé par le
        # constructeur de Fuzzer par l'instance partagée pour tout le run.
        fuzzer.response_analyzer = ctx.shared_response_analyzer

    while True:
        try:
            i, url, vulns, is_spa, helpers = await asyncio.wait_for(ctx.queue.get(), 2)
        except asyncio.TimeoutError:
            break

        names = [
            h.get("name") if isinstance(h, dict) else getattr(h, "name", "")
            for h in helpers
        ] if helpers else []
        logger.info(
            f"[{i}/{ctx.total}] (worker {worker_id}) Analyse de {url} "
            f"-> {vulns or 'SAFE'} (SPA={is_spa}, Helpers={names})"
        )

        cfg = SingleUrlExtractorConfig.from_dict(base_config.to_dict())
        cfg.is_spa = is_spa
        cfg.helpers = helpers or []

        # AnalyzerHelper (et son Crawler) restent créés par cible : objets
        # légers (pas de modèle), garantit un état de crawl frais pour
        # chaque URL sans avoir à auditer la remise à zéro interne du
        # Crawler entre deux appels sur une même instance.
        analyzer_helper = AnalyzerHelper(
            session=ctx.session,
            use_cache=cfg.use_cache,
            DEBUG=cfg.debug,
            Semaphore=cfg.semaphore,
        )
        analyzer_helper.crawler.config.MAX_WORKERS = 1
        analyzer_helper.crawler.config.MAX_DEEPTH = 1
        analyzer_helper.crawler.config.MAX_PAGES = 1
        analyzer_helper.crawler.config.GET_TIMEOUT = 2
        analyzer_helper.crawler.config.JOIN_TIMEOUT = 1 * 2 * 60
        # Cache disque du classify_link/get_all_links (TTL 24h) : désactivé,
        # sinon un ancien résultat périmé peut être resservi silencieusement
        # (cf. bug du 29/08).
        analyzer_helper.crawler.config.USE_CACHE_FOR_GET_LINKS = False
        # Aucun bénéfice à écrire dans var/crawler_cache pour un build de
        # dataset one-shot (restore toujours False) — évite la contention
        # d'écriture SQLite à haute concurrence (num_workers élevé).
        analyzer_helper.crawler.config.SAVE_ON_CRAWL = False

        t0 = time.time()
        err: Optional[Exception] = None
        row = None
        try:
            _, row = await extract_features_single_url(
                url=url,
                analyzer_helper=analyzer_helper,
                passive_analyzer=ctx.passive_analyzer,
                code_analyzer=ctx.code_analyzer,
                feature_extractor=ctx.feature_extractor,
                fuzzer=fuzzer,
                config=cfg,
                vulns=vulns,
            )
        except Exception as ex:
            err = ex
            logger.error(f"[WORKER {worker_id}] ❌ Échec sur {url} : {ex}")

        elapsed_url = time.time() - t0

        async with ctx.results_lock:
            ctx.results.append({
                "url": url,
                "row": row,
                "error": err,
                "error_type": type(err).__name__ if err is not None else None,
                "elapsed": elapsed_url,
            })

        ctx.queue.task_done()


# =============================================================================
# 4. ORCHESTRATEUR DE CONSTRUCTION DU DATASET (pool de workers fixe + queue)
# =============================================================================

async def build_dataset(
    targets: list,
    config: Optional[SingleUrlExtractorConfig] = None,
    out_path: str = "./dataset_mvp",
    num_workers: int = NUM_WORKERS,
) -> pd.DataFrame:
    """Construit un dataset complet à partir d'une liste de cibles.

    Architecture : un pool FIXE de `num_workers` coroutines (`_dataset_worker`,
    définie hors de cette fonction) consomment une `asyncio.Queue` pré-remplie
    avec toutes les cibles. La concurrence réelle ne dépend plus du nombre de
    cibles : au maximum `num_workers` Fuzzer/AnalyzerHelper existent en
    mémoire simultanément, quel que soit `len(targets)`.

    Sauvegarde aussi un fichier `{out_path}_stats.json` avec le détail complet
    du run (succès/échecs, erreurs par type, timing).

    Format attendu pour chaque cible : (url, vulns_list, is_spa, helpers_list)
    """
    base_config = config or SingleUrlExtractorConfig()
    total = len(targets)

    logger.info(
        f"🏁 Démarrage du build de dataset sur {total} cibles "
        f"avec {num_workers} workers fixes (queue asyncio)..."
    )

    queue: "asyncio.Queue[tuple]" = asyncio.Queue()
    for i, target in enumerate(targets, 1):
        queue.put_nowait((i, *target))

    results: list = []
    results_lock = asyncio.Lock()

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=num_workers * 10),
    ) as session:

        passive_analyzer = PassiveCodeAnalyzer()
        code_analyzer = CodeAnalyzer(debug=base_config.debug)
        feature_extractor = FeatureExtractor()

        # Instance UNIQUE partagée par tous les workers. Charge le modèle
        # BERT (similarity_model) une seule fois pour tout le run, au lieu
        # d'une fois par cible/worker. Safe à partager : toute mutation
        # interne (self._cache) est déjà protégée par un threading.Lock,
        # aucun autre attribut d'instance n'est modifié après __init__.
        shared_response_analyzer = ResponseAnalyzer(
            debug=base_config.debug,
            use_semantic=base_config.use_semantic,
        )

        ctx = _DatasetWorkerContext(
            session=session,
            queue=queue,
            results=results,
            results_lock=results_lock,
            base_config=base_config,
            total=total,
            passive_analyzer=passive_analyzer,
            code_analyzer=code_analyzer,
            feature_extractor=feature_extractor,
            shared_response_analyzer=shared_response_analyzer,
        )

        t0_run = time.time()
        workers = [
            asyncio.create_task(_dataset_worker(w, ctx), name=f"dataset-worker-{w}")
            for w in range(num_workers)
        ]
        await asyncio.gather(*workers)
        run_elapsed = time.time() - t0_run

        # ── Agrégation des résultats + stats complètes ──
        rows = []
        n_success = 0
        n_failed = 0
        errors_by_type: Counter = Counter()
        errors_detail = []
        per_url_timings = []

        for entry in results:
            per_url_timings.append(entry["elapsed"])
            if entry["error"] is None and entry["row"]:
                rows.append(entry["row"])
                n_success += 1
            else:
                n_failed += 1
                err_type = entry["error_type"] or "EmptyResult"
                errors_by_type[err_type] += 1
                errors_detail.append({
                    "url": entry["url"],
                    "error_type": err_type,
                    "error_message": (
                        str(entry["error"]) if entry["error"] is not None
                        else "Résultat vide (row/features manquants)"
                    ),
                    "elapsed": round(entry["elapsed"], 2),
                })

        dataset = pd.DataFrame(rows)
        logger.info(f"\n✨ Extraction terminée : {dataset.shape[0]}/{total} cibles extraites avec succès.")

        stats: Dict[str, Any] = {
            "run_timestamp": datetime.now().isoformat(),
            "total_targets": total,
            "num_workers": num_workers,
            "success": n_success,
            "failed": n_failed,
            "success_rate": round(n_success / total, 4) if total else 0.0,
            "elapsed_seconds": round(run_elapsed, 2),
            "avg_time_per_target": (
                round(sum(per_url_timings) / len(per_url_timings), 2)
                if per_url_timings else 0.0
            ),
            "errors_by_type": dict(errors_by_type),
            "errors_detail": errors_detail,
        }

        if not dataset.empty:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            FeatureExtractor.save_dataset(dataset, out_path)

            if "labels" in dataset.columns:
                labels_series = dataset["labels"]
                counts = Counter(v for v_list in labels_series for v in v_list)
                counts["SAFE (labels=[])"] = sum(1 for v_list in labels_series if not v_list)
                stats["labels_distribution"] = dict(counts)

                logger.info("\n📊 Répartition des classes dans le dataset :")
                for vuln_name, count in sorted(counts.items(), key=lambda x: -x[1]):
                    logger.info(f"  • {vuln_name:<25} : {count}")

        # Sauvegarde des stats, même si le dataset est vide (utile pour debug).
        stats_path = f"{out_path}_stats.json"
        stats_dir = os.path.dirname(os.path.abspath(stats_path))
        os.makedirs(stats_dir, exist_ok=True)
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False, default=str)

        logger.info(
            f"\n📈 Stats sauvegardées : {stats_path}\n"
            f"   ├─ Succès      : {n_success}/{total} ({stats['success_rate'] * 100:.1f}%)\n"
            f"   ├─ Échecs      : {n_failed}\n"
            f"   ├─ Temps total : {stats['elapsed_seconds']}s "
            f"(moy/cible: {stats['avg_time_per_target']}s)\n"
            f"   └─ Erreurs par type : {dict(errors_by_type) or 'aucune'}"
        )

        return dataset


# =============================================================================
# 5. POINT D'ENTRÉE DU SCRIPT
# =============================================================================

if __name__ == "__main__":
    apply()

    async def main():
        print("=" * 70)
        print("🚀 GÉNÉRATION DU DATASET D'ENTRAÎNEMENT SCANNER IA")
        print("=" * 70)

        # Config globale pour la génération
        build_config = SingleUrlExtractorConfig(
            active_fuzz=True,
            max_test_fuzzer=None,
            dynamic_timeout=False,
            debug=False,
            use_semantic=True,
            semaphore=200,
            use_cache=False,   # explicite : jamais de résultats périmés
            restore=False,     # explicite : jamais de restauration de crawl précédent
        )

        output_file = "./dataset/shieldai_dataset_augmented_v4_001"

        t0 = time.time()
        dataset_result = await build_dataset(
            targets=V1_TARGETS[:],
            config=build_config,
            out_path=output_file,
            num_workers=NUM_WORKERS,
        )
        elapsed = time.time() - t0

        print("\n" + "=" * 70)
        print(f"🎉 Dataset prêt en {elapsed:.2f}s | Lignes : {len(dataset_result)}")
        print("=" * 70)

    asyncio.run(main())