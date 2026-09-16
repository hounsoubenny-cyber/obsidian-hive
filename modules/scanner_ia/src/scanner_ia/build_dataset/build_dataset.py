#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug 28 21:22:58 2026

@author: hounsousamuel
"""

import os
import ast
import gc
import math
import json
import time
import asyncio
import aiohttp
import resource
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
NUM_WORKERS = 20


# =============================================================================
# 0. DIMENSIONNEMENT RÉSEAU DYNAMIQUE
# =============================================================================

def compute_connector_limit(
    num_workers: int,
    fuzzer_max_workers: int,
    safety_margin: float = 1.3,
    min_limit: int = 100,
) -> int:
    """Dimensionne le TCPConnector à partir de la concurrence réelle du run.

    Le pic de connexions simultanées est atteint en phase fuzz (~98% du temps
    par cible) : chaque tâche `_worker` de active_fuzzer.py ne parallélise pas
    en interne (1 requête en vol par tâche), donc le pic théorique est
    num_workers x fuzzer_max_workers. safety_margin absorbe le chevauchement
    avec la phase crawl et les connexions keep-alive pas encore libérées.
    """
    peak_concurrent = num_workers * fuzzer_max_workers
    return max(min_limit, math.ceil(peak_concurrent * safety_margin))


def check_ulimit(required: int) -> None:
    """Avertit (et tente de relever) ulimit -n si trop bas pour `required`
    connexions simultanées. Chaque connexion aiohttp consomme un file
    descriptor, +marge pour les fichiers ouverts par DirTrav/InsecUpload."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = required + 2000  # marge : fds de fichiers, logs, stdout, etc.
    if soft < needed:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(needed, hard), hard))
            logger.info(f"🔧 ulimit -n relevé de {soft} à {min(needed, hard)}")
        except (ValueError, OSError):
            logger.warning(
                f"⚠️ ulimit -n actuel ({soft}) trop bas pour {required} connexions "
                f"simultanées (besoin ~{needed}). Lance le script avec "
                f"`ulimit -n 65536` avant, sinon risque de 'Too many open files'."
            )


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
    fuzzer_limit: Optional[int] = None
    # Nombre de tâches async concurrentes DANS un Fuzzer (consommation de la
    # queue de payloads pour UNE cible). À ne pas confondre avec num_workers
    # (le pool build_dataset, qui lui traite plusieurs cibles en parallèle).
    # Piloté ici plutôt qu'en dur dans _dataset_worker pour que le connector
    # (compute_connector_limit) et le ThreadPoolExecutor du Fuzzer restent
    # cohérents avec la même valeur.
    fuzzer_max_workers: int = 10

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

def _normalize_vulns(vulns: Any, url: str = "") -> List[str]:
    """Force `vulns` en vraie liste de strings, quel que soit le format
    reçu depuis `V1_TARGETS`.

    Bug constaté le 04/09 : certaines entrées de `V1_TARGETS` ont `vulns`
    stocké comme une string simple ("SSTI" au lieu de ["SSTI"]) ou comme le
    repr d'une liste ("['XSS']" au lieu de la vraie liste). Sans cette
    normalisation, `row["labels"] = vulns` copie la string telle quelle, et
    un `for v in labels` en aval (stats de `build_dataset`, dédup dans
    `merge_chunks.py`) l'itère caractère par caractère → labels absurdes
    ('S', 'T', 'i', "'", '[', ']'...) au lieu des vraies classes.

    Cette fonction rattrape le coup ici, mais le vrai fix reste de nettoyer
    `V1_TARGETS` à la source — un warning est loggé à chaque fois qu'une
    entrée sale est rencontrée pour pouvoir les repérer.
    """
    if vulns is None:
        return []
    if isinstance(vulns, (list, tuple, set)):
        return [str(v) for v in vulns]
    if isinstance(vulns, str):
        s = vulns.strip()
        if not s:
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, (list, tuple, set)):
                    logger.warning(
                        f"⚠️ vulns mal formé pour {url!r} : stocké comme repr "
                        f"de liste ({s!r}) au lieu d'une vraie liste dans "
                        f"V1_TARGETS. Parsé correctement ici, mais V1_TARGETS "
                        f"mérite d'être corrigé à la source."
                    )
                    return [str(v) for v in parsed]
            except (ValueError, SyntaxError):
                pass
        logger.warning(
            f"⚠️ vulns mal formé pour {url!r} : string simple ({s!r}) au "
            f"lieu d'une liste dans V1_TARGETS. Enveloppé en [{s!r}] ici, "
            f"mais V1_TARGETS mérite d'être corrigé à la source."
        )
        return [s]
    logger.warning(
        f"⚠️ vulns de type inattendu ({type(vulns).__name__}) pour {url!r} : "
        f"{vulns!r}. Converti en [str(vulns)]."
    )
    return [str(vulns)]


async def extract_features_single_url(
    url: str,
    analyzer_helper: AnalyzerHelper,
    passive_analyzer: PassiveCodeAnalyzer,
    code_analyzer: CodeAnalyzer,
    feature_extractor: FeatureExtractor,
    fuzzer: Optional[Fuzzer] = None,
    config: Optional[SingleUrlExtractorConfig] = None,
    vulns: Optional[list] = None,
) -> Tuple[pd.DataFrame, dict, Dict[str, float]]:
    """Extrait le vecteur de features complet (100+ colonnes) pour une seule URL

    en orchestrant les instances de modules déjà injectées.

    Returns:
        (features_df, row, phase_timings) — phase_timings donne la durée en
        secondes de chaque phase (reachability, crawl, passive_code, fuzz,
        feature_extraction), pour identifier le vrai goulot d'étranglement
        plutôt que de deviner.
    """
    cfg = config or SingleUrlExtractorConfig()
    timings: Dict[str, float] = {}

    # ── 1. Normalisation & Vérification ──
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    url = url.strip()

    if cfg.verify_reachability:
        t0 = time.time()
        reachable = await is_url_reachable(url, timeout=cfg.timeout)
        timings["reachability"] = time.time() - t0
        if not reachable:
            raise ValueError(f"URL cible inaccessible : {url}")

    try:
        logger.info(f"🚀 [FeatureExtractor] Début d'analyse pour : {url}")

        # ── 2. Phase 1 : Crawl, Parse & Baseline ──
        resolved_helpers = resolve_helpers(cfg.helpers) if cfg.helpers else []

        t0 = time.time()
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
        timings["crawl"] = time.time() - t0

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
        t0 = time.time()
        passive_result: PassiveAnalyzerResult = await asyncio.to_thread(
            passive_analyzer.analyse,
            crawled_data,
        )

        code_result: CodeAnalyzerResult = await asyncio.to_thread(
            code_analyzer.analyse,
            crawled_data,
        )
        timings["passive_code"] = time.time() - t0

        # ── 4. Phase 4 : Fuzzing Actif Différentiel ──
        t0 = time.time()
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
                close_threadpool=False
            )
        else:
            # Mode Passif pur
            fuzzer_result = FuzzerResult()
            fuzzer_result.url = url
        timings["fuzz"] = time.time() - t0

        # ── 5. Phase 5 : Extraction & Tabularisation ──
        t0 = time.time()
        features_df: pd.DataFrame = await feature_extractor.extract(
            analyzer_helper_result=crawled_data,
            passive_analyzer_result=passive_result,
            code_analyzer_result=code_result,
            fuzzer_result=fuzzer_result,
        )
        timings["feature_extraction"] = time.time() - t0

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
        row["labels"] = _normalize_vulns(vulns, url=url)

        return features_df, row, timings

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

    Robustesse : TOUT le corps de la boucle (y compris la construction
    d'AnalyzerHelper) est dans le try/except, et t0/row/err/phase_timings
    sont initialisés AVANT le try — comme ça, une exception à n'importe
    quel endroit (même avant que t0 existe) est catchée, enregistrée dans
    ctx.results avec son error_type, et le worker continue sur l'item
    suivant au lieu de crasher et d'abandonner le reste de sa part de queue.
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
            limit=base_config.fuzzer_limit
        )
        fuzzer.config.MAX_WORKERS = base_config.fuzzer_max_workers
        fuzzer.config.GET_TIMEOUT = 2
        fuzzer.config.FUZZ_TIMEOUT = 10 * 10 * 60
        fuzzer.config.TIMEOUT = base_config.timeout
        # Remplace le ResponseAnalyzer (avec son propre BERT) créé par le
        # constructeur de Fuzzer par l'instance partagée pour tout le run.
        fuzzer.response_analyzer = ctx.shared_response_analyzer
        # Recrée le ThreadPoolExecutor interne à la bonne taille : sinon il
        # reste figé sur la valeur par défaut de Config() prise au moment du
        # __init__ du Fuzzer, indépendamment de MAX_WORKERS réglé juste au-dessus.
        fuzzer._init_pool()

    while True:
        try:
            i, url, vulns, is_spa, helpers = ctx.queue.get_nowait()
        except asyncio.QueueEmpty:
            break

        # Initialisés AVANT le try : garantit qu'on peut toujours calculer
        # elapsed_url et enregistrer un résultat (même en échec), peu importe
        # où l'exception a lieu à l'intérieur du bloc.
        t0 = time.time()
        row: Optional[dict] = None
        err: Optional[Exception] = None
        phase_timings: Dict[str, float] = {}

        try:
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
            analyzer_helper.crawler.config.JOIN_TIMEOUT = 1 * 10 * 60
            analyzer_helper.crawler.parser.fetcher.config.TIMEOUT = 120
            # Cache disque du classify_link/get_all_links (TTL 24h) : désactivé,
            # sinon un ancien résultat périmé peut être resservi silencieusement
            # (cf. bug du 29/08).
            analyzer_helper.crawler.config.USE_CACHE_FOR_GET_LINKS = False
            # Aucun bénéfice à écrire dans var/crawler_cache pour un build de
            # dataset one-shot (restore toujours False) — évite la contention
            # d'écriture SQLite à haute concurrence (num_workers élevé).
            analyzer_helper.crawler.config.SAVE_ON_CRAWL = False

            _, row, phase_timings = await extract_features_single_url(
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
                "phase_timings": phase_timings,
            })

        ctx.queue.task_done()

    if fuzzer is not None:
        # Le worker a fini sa part de la queue : plus aucune réutilisation
        # du Fuzzer à venir, on arrête son ThreadPoolExecutor pour de bon.
        fuzzer.close()


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

    # Connector dimensionné dynamiquement : pic théorique = num_workers x
    # fuzzer_max_workers (voir compute_connector_limit), pas un chiffre en dur.
    connector_limit = compute_connector_limit(num_workers, base_config.fuzzer_max_workers)
    check_ulimit(connector_limit)
    logger.info(
        f"🔌 Connector dimensionné à {connector_limit} "
        f"(num_workers={num_workers} × fuzzer_max_workers={base_config.fuzzer_max_workers})"
    )

    queue: "asyncio.Queue[tuple]" = asyncio.Queue()
    for i, target in enumerate(targets, 1):
        queue.put_nowait((i, *target))

    results: list = []
    results_lock = asyncio.Lock()

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            limit=connector_limit,
            limit_per_host=connector_limit,  # tout tape sur 127.0.0.1, même chose
            ttl_dns_cache=300,
        ),
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
        # return_exceptions=True : un crash imprévu dans UN worker (bug pas
        # encore anticipé, en dehors du try/except de _dataset_worker) ne tue
        # plus les autres. Sans ça, un seul worker en échec faisait planter
        # gather(), annulait tous les workers restants (résultats déjà en
        # mémoire perdus car jamais écrits sur disque) et arrêtait tout le
        # script — c'était la cause probable des chunks entiers "perdus".
        worker_errors = await asyncio.gather(*workers, return_exceptions=True)
        for w, exc in enumerate(worker_errors):
            if isinstance(exc, Exception):
                logger.error(f"💥 Worker {w} a crashé hors try/except interne : {exc}")
                if base_config.debug:
                    logger.error("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        run_elapsed = time.time() - t0_run

        # ── Agrégation des résultats + stats complètes ──
        rows = []
        n_success = 0
        n_failed = 0
        errors_by_type: Counter = Counter()
        errors_detail = []
        per_url_timings = []
        # Accumule les timings par phase sur les cibles RÉUSSIES uniquement
        # (les échecs n'ont souvent qu'une partie des phases exécutées, les
        # inclure fausserait la moyenne par phase).
        phase_timings_acc: Dict[str, list] = {}

        for entry in results:
            per_url_timings.append(entry["elapsed"])
            if entry["error"] is None and entry["row"]:
                rows.append(entry["row"])
                n_success += 1
                for phase, dur in entry.get("phase_timings", {}).items():
                    phase_timings_acc.setdefault(phase, []).append(dur)
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

        avg_target_time = (
            sum(per_url_timings) / len(per_url_timings) if per_url_timings else 0.0
        )

        phase_breakdown = {}
        for phase, durations in phase_timings_acc.items():
            avg = sum(durations) / len(durations)
            sorted_d = sorted(durations)
            median = sorted_d[len(sorted_d) // 2]
            phase_breakdown[phase] = {
                "avg_seconds": round(avg, 2),
                "median_seconds": round(median, 2),
                "pct_of_target_time": (
                    round(avg / avg_target_time * 100, 1) if avg_target_time else 0.0
                ),
            }

        stats: Dict[str, Any] = {
            "run_timestamp": datetime.now().isoformat(),
            "total_targets": total,
            "num_workers": num_workers,
            "fuzzer_max_workers": base_config.fuzzer_max_workers,
            "connector_limit": connector_limit,
            "success": n_success,
            "failed": n_failed,
            "success_rate": round(n_success / total, 4) if total else 0.0,
            "elapsed_seconds": round(run_elapsed, 2),
            "avg_time_per_target": round(avg_target_time, 2),
            "phase_breakdown": phase_breakdown,
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

        if phase_breakdown:
            logger.info("\n⏱️  Répartition du temps par phase (moyenne sur cibles réussies) :")
            for phase, v in sorted(phase_breakdown.items(), key=lambda x: -x[1]["avg_seconds"]):
                logger.info(
                    f"  • {phase:<20} : {v['avg_seconds']}s en moyenne "
                    f"({v['pct_of_target_time']}% du temps/cible)"
                )

        return dataset


# =============================================================================
# 5. DÉCOUPAGE EN LOTS (chunks)
# =============================================================================

def round_chunk_size(chunk_size: int, num_workers: int) -> int:
    """Arrondit `chunk_size` au multiple de `num_workers` le plus proche
    (jamais 0 : au moins `num_workers` lui-même). Pur confort d'équilibrage
    entre workers — n'affecte jamais la correction du resume (voir `start`)."""
    if num_workers <= 0:
        return chunk_size
    n = max(1, round(chunk_size / num_workers))
    return n * num_workers


def _progress_path(out_dir: str) -> str:
    return os.path.join(out_dir, "_progress.json")


def load_progress(out_dir: str, total_targets: int, fallback: int = 0) -> int:
    """Lit `_progress.json` s'il existe et renvoie l'offset absolu à partir
    duquel reprendre. Refuse (raise) si `total_targets` a changé depuis le
    dernier run enregistré : ça veut dire que `V1_TARGETS` a été modifié
    (ajout/suppression de cibles) et que l'offset stocké ne pointerait plus
    sur les bonnes cibles — mieux vaut planter clairement que corrompre le
    dataset silencieusement.
    """
    p = _progress_path(out_dir)
    if not os.path.exists(p):
        return fallback

    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    
    stored_total = data.get("total_targets")
    if stored_total != total_targets:
        raise RuntimeError(
            f"❌ _progress.json incohérent : enregistré avec total_targets="
            f"{stored_total}, mais len(targets) actuel={total_targets}. "
            f"`V1_TARGETS` a changé depuis le dernier run — l'offset "
            f"last_completed_offset={data.get('last_completed_offset')} ne "
            f"pointe plus forcément sur les bonnes cibles. Supprime/corrige "
            f"{p} manuellement (ou repars avec un out_dir neuf) avant de "
            f"relancer."
        )

    return data["last_completed_offset"]


def save_progress(out_dir: str, last_completed_offset: int, total_targets: int) -> None:
    """Écrit l'état de progression après chaque lot réussi. `total_targets`
    est stocké pour détecter une incohérence si `targets` change de taille
    entre deux runs (voir `load_progress`)."""
    with open(_progress_path(out_dir), "w", encoding="utf-8") as f:
        json.dump(
            {
                "last_completed_offset": last_completed_offset,
                "total_targets": total_targets,
                "updated_at": datetime.now().isoformat(),
            },
            f,
            indent=2,
        )


async def build_dataset_chunked(
    targets: list,
    config: Optional[SingleUrlExtractorConfig] = None,
    out_dir: str = "./dataset_chunks",
    num_workers: int = NUM_WORKERS,
    chunk_size: int = 100,
    start: Optional[int] = None,
) -> List[str]:
    """Découpe `targets` en lots de `chunk_size` et appelle `build_dataset()`
    séquentiellement sur chacun, avec nettoyage explicite entre les lots :
      - `build_dataset()` ouvre/ferme déjà sa propre session aiohttp par lot
        (via `async with`), donc pas de fuite de connexions entre lots.
      - Chaque Fuzzer créé dans un lot est maintenant fermé proprement en
        fin de worker (`fuzzer.close()`), donc pas de fuite de threads.
      - `gc.collect()` explicite entre les lots pour forcer la libération
        mémoire immédiatement plutôt que d'attendre le GC automatique.

    `start` est un OFFSET ABSOLU (0-based) dans `targets`, pas un numéro de
    lot — il reste valide même si `chunk_size` change d'un run à l'autre
    (ex: via `round_chunk_size` pour équilibrer sur `num_workers`).
    Si `start=None` (défaut), l'offset est lu depuis `{out_dir}/_progress.json`
    s'il existe, sinon `0`. Le fichier de progression est mis à jour
    automatiquement après chaque lot réussi — tu n'as normalement jamais à
    le toucher à la main (voir `load_progress`/`save_progress`).

    Chaque lot produit son propre fichier nommé par la plage de cibles qu'il
    couvre (`chunk_00000-00099.pkl` + `.csv` + `_stats.json`) plutôt que par
    un numéro de lot arbitraire — lisible directement sans avoir à recalculer
    avec quel `chunk_size` il a été produit. Utilise `merge_chunks.py`
    ensuite pour les recombiner en un seul dataset.

    Si un lot échoue avec une exception non gérée, les lots précédents
    restent sur disque (rien n'est perdu) et `_progress.json` pointe déjà sur
    le dernier lot réussi — relance simplement le script sans argument.

    Returns:
        Liste des chemins `.pkl` de chaque lot produit (dans cette exécution).
    """
    os.makedirs(out_dir, exist_ok=True)
    base_config = config or SingleUrlExtractorConfig()
    total = len(targets)
    if start is None:
        start = load_progress(out_dir, total_targets=total, fallback=0)

    if start >= total:
        logger.info(f"✅ Rien à faire : start={start} >= total={total} (déjà terminé).")
        return []

    chunk_paths: List[str] = []
    n_chunks_remaining = math.ceil((total - start) / chunk_size)
    
    logger.info(
        f"📦 Reprise à l'offset {start}/{total} — {n_chunks_remaining} lots de "
        f"~{chunk_size} cibles restants ({num_workers} workers/lot)"
    )

    for offset in range(start, total, chunk_size):
        end = min(offset + chunk_size, total)
        chunk = targets[offset:end]
        chunk_out_path = os.path.join(out_dir, f"chunk_{offset:05d}-{end - 1:05d}")

        logger.info(f"\n{'=' * 60}\n📦 Cibles [{offset}:{end}] ({len(chunk)})\n{'=' * 60}")

        try:
            await build_dataset(
                targets=chunk,
                config=base_config,
                out_path=chunk_out_path,
                num_workers=num_workers,
            )
            chunk_paths.append(f"{chunk_out_path}.pkl")
        except Exception as ex:
            logger.error(f"❌ Lot [{offset}:{end}] interrompu : {ex}")
            logger.error(traceback.format_exc())
            logger.info(
                f"Les {len(chunk_paths)} lots de cette exécution sont intacts sur "
                f"disque. `_progress.json` est resté sur le dernier offset validé "
                f"({offset}) — relance simplement le script sans argument pour "
                f"reprendre exactement là où ça a cassé."
            )
            raise

        # Le lot est écrit sur disque avec succès AVANT qu'on avance le curseur
        # de progression : si le process meurt entre les deux (kill -9, OOM),
        # on retraite au pire ce même lot au prochain run — jamais un trou.
        save_progress(out_dir, last_completed_offset=end, total_targets=total)

        gc.collect()
        logger.info(f"🧹 Lot [{offset}:{end}] terminé, mémoire nettoyée.")

    logger.info(f"\n✨ Tous les lots terminés : {len(chunk_paths)} fichiers dans {out_dir}")
    return chunk_paths


# =============================================================================
# 6. POINT D'ENTRÉE DU SCRIPT
# =============================================================================

# Passage progressif 12 -> 20 workers (au lieu d'un saut direct à 100) :
# chunk_size arrondi au multiple de num_workers le plus proche pour un
# partage équitable entre workers en fin de lot (voir round_chunk_size).
# fuzzer_max_workers reste à 10 (déjà pris en compte dans le connector
# dynamique ci-dessus). Reste sur ce palier le temps de valider
# `errors_by_type` sur 2-3 chunks avant de remonter plus haut.
NUM_WORKERS_DEFAULT_RUN = 10
CHUNK_SIZE_DEFAULT = round_chunk_size(30, NUM_WORKERS_DEFAULT_RUN)  # → 100 (déjà multiple)

if __name__ == "__main__":
    apply()

    async def main(start: Optional[int] = None):
        print("=" * 70)
        print("🚀 GÉNÉRATION DU DATASET D'ENTRAÎNEMENT SCANNER IA (par lots)")
        print("=" * 70)

        # Config globale pour la génération
        build_config = SingleUrlExtractorConfig(
            active_fuzz=True,
            max_test_fuzzer=None,
            dynamic_timeout=False,
            debug=False,
            timeout=120,
            fuzzer_limit=100,
            fuzzer_max_workers=10,
            use_semantic=True,
            semaphore=200,
            use_cache=False,   # explicite : jamais de résultats périmés
            restore=False,     # explicite : jamais de restauration de crawl précédent
        )

        out_dir = "./dataset_chunks"

        t0 = time.time()
        chunk_paths = await build_dataset_chunked(
            targets=V1_TARGETS,
            config=build_config,
            out_dir=out_dir,
            num_workers=NUM_WORKERS_DEFAULT_RUN,
            chunk_size=CHUNK_SIZE_DEFAULT,
            start=start,  # None => lu automatiquement depuis _progress.json
        )
        elapsed = time.time() - t0

        print("\n" + "=" * 70)
        print(f"🎉 {len(chunk_paths)} lots prêts en {elapsed:.2f}s dans {out_dir}")
        print("👉 Lance merge_chunks.py pour les recombiner en un seul dataset")
        print("=" * 70)

    import sys
    # Aucun argv => start=None => offset lu automatiquement depuis
    # dataset_chunks/_progress.json (ou 0 si le fichier n'existe pas encore).
    # Passer un argv force un offset ABSOLU précis (ex: pour reprendre
    # manuellement après avoir corrigé _progress.json à la main).
    start = int(sys.argv[1]) if len(sys.argv) >= 2 else None
    asyncio.run(main(start=start))