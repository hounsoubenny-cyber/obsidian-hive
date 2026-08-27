#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug  6 12:13:14 2026

@author: hounsousamuel
"""

"""
Collecte de traces comportementales pour entraîner les modèles ML du sandbox.

Pipeline :
  manifest.json → orchestrateur (sandbox) → events → FeatureExtractor
  → build_dataset_from_events → X_seq, X_ebd, y → sauvegarde numpy

Tournera en parallèle avec asyncio.Semaphore pour maximiser le débit
sans saturer la machine (N containers simultanés max).

Usage :
    python3 collect_traces.py --manifest output/manifest.json \
                              --out_dir ml_model/datasets     \
                              --max_concurrent 3              \
                              --seq_len 50                    \
                              --limit 200                     # optionnel, pour tester
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))
import json
import asyncio
import argparse
import logging
import traceback
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.preprocessing import RobustScaler
import joblib
from typing import Optional, List, Dict, Any

orchestrators = []

# ── Chemin vers sandbox_ia ──────────────────────────────────────────────────
SANDBOX_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(SANDBOX_ROOT))

from sandbox_ia.core.orchestrator import SandboxOrchestrator, SandboxConfig
from sandbox_ia.ml_model.features_extractor_v2 import FeatureExtractor
from sandbox_ia.ml_model.dataset_builder import build_dataset_from_events
from sandbox_ia.ml_model.vocab import encode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("collect")


# =============================================================================
# CONFIG SANDBOX LÉGÈRE (optimisée pour la collecte de dataset)
# =============================================================================

def make_config(language: str) -> SandboxConfig:
    """Config sandbox optimisée pour la collecte : timeout court, strace actif."""
    from sandbox_ia.configs.executor_config import LANGUAGE_TIMEOUTS
    timeout = LANGUAGE_TIMEOUTS.get(language, 20)
    return SandboxConfig(
        image_name="shieldai-sandbox:v2-light",
        mem_limit="256m",
        exec_timeout=float(timeout),
        alert_threshold=30,
        decay_interval=10.0,
        decay_amount=3,
        enable_strace=True,
        enable_fs_monitor=True,
        network_disabled=True,
    )


# =============================================================================
# COLLECTE D'UN SEUL FICHIER
# =============================================================================

async def collect_one(
    entry: dict,
    semaphore: asyncio.Semaphore,
    extractor: FeatureExtractor,
    seq_len: int,
) -> Optional[Dict[str, Any]]:
    """
    Analyse un fichier dans le sandbox et retourne X_seq, X_ebd, y.
    Retourne None si l'analyse a échoué ou produit 0 events.
    """
    path = entry["path"]
    label = entry["label"]
    family = entry["family"]
    language = entry["language"]

    async with semaphore:
        log.info(f"▶  {Path(path).name} [{family}/{language}] label={label}")
        try:
            code = Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            log.warning(f"   Lecture échouée: {e}")
            return None

        try:
            config = make_config(language)
            orchestrator = SandboxOrchestrator(store_event=True)
            # orchestrators.append(orchestrator)
            report = await orchestrator.analyze(
                code=code,
                language=language,
                config=config,
                use_cache=False,
            )
        except Exception as e:
            log.warning(f"   Analyse échouée: {e}")
            log.debug(traceback.format_exc())
            return None

        events = orchestrator.events
        
        if not events:
            log.warning(f"   0 events collectés — skip")
            return None

        log.info(f"   ✅ {len(events)} events | score={report.final_score} [{report.final_level}]")

        try:
            extractor.reset()
            X_seq, X_ebd, y = build_dataset_from_events(
                events=events,
                label=label,
                extractor=extractor,
                seq_len=seq_len,
                reset=False,
            )
        except Exception as e:
            log.warning(f"   build_dataset_from_events échoué: {e}")
            log.debug(traceback.format_exc())
            return None

        return {
            "X_seq": X_seq,
            "X_ebd": X_ebd,
            "y": y,
            "n_events": len(events),
            "family": family,
            "language": language,
            "label": label,
            "final_score": report.final_score,
            "final_level": report.final_level,
            "n_alerts": len(report.alerts),
        }


# =============================================================================
# SAUVEGARDE PAR BATCH
# =============================================================================

def save_batch(results: List[Dict], out_dir: Path, batch_idx: int) -> tuple:
    """Concatène et sauvegarde un batch de résultats en numpy."""
    X_list, Xebd_list, y_list = [], [], []
    for r in results:
        if r is not None:
            X_list.append(r["X_seq"])
            Xebd_list.append(r["X_ebd"])
            y_list.append(r["y"])

    if not X_list:
        return None, None, None

    X = np.concatenate(X_list, axis=0)
    Xebd = np.concatenate(Xebd_list, axis=0)
    y = np.concatenate(y_list, axis=0)

    np.save(out_dir / f"X_seq_batch{batch_idx:03d}.npy", X)
    np.save(out_dir / f"X_ebd_batch{batch_idx:03d}.npy", Xebd)
    np.save(out_dir / f"y_batch{batch_idx:03d}.npy", y)

    log.info(f"   💾 Batch {batch_idx}: X={X.shape} Xebd={Xebd.shape} y={y.shape}")
    return X, Xebd, y


# =============================================================================
# FUSION DES BATCHES + SCALER GLOBAL
# =============================================================================

def merge_and_finalize(out_dir: Path, seq_len: int):
    """Fusionne tous les batches en fichiers finaux + entraîne le scaler global."""
    X_files = sorted(out_dir.glob("X_seq_batch*.npy"))
    Xebd_files = sorted(out_dir.glob("X_ebd_batch*.npy"))
    y_files = sorted(out_dir.glob("y_batch*.npy"))

    if not X_files:
        log.error("Aucun batch trouvé !")
        return

    log.info(f"Fusion de {len(X_files)} batches...")
    X = np.concatenate([np.load(f) for f in X_files], axis=0)
    Xebd = np.concatenate([np.load(f) for f in Xebd_files], axis=0)
    y = np.concatenate([np.load(f) for f in y_files], axis=0)

    # Sauvegarde finale
    np.save(out_dir / "X_seq.npy", X)
    np.save(out_dir / "X_ebd.npy", Xebd)
    np.save(out_dir / "y.npy", y)

    # Stats
    n_mal = int((y == 1).sum())
    n_ben = int((y == 0).sum())
    n_seq = len(y)
    log.info("=" * 60)
    log.info(f"✅ Dataset final sauvegardé dans {out_dir}")
    log.info(f"   X_seq  : {X.shape}")
    log.info(f"   X_ebd  : {Xebd.shape}")
    log.info(f"   y      : {y.shape}  (malveillant={n_mal}, bénin={n_ben})")
    log.info(f"   ratio  : {n_mal/n_seq*100:.1f}% malveillant")
    # log.info(f"   scaler : {out_dir/'scaler.joblib'}")
    log.info("=" * 60)

    # Nettoyage des batches intermédiaires
    for f in X_files + Xebd_files + y_files:
        f.unlink()
    log.info("Batches intermédiaires supprimés.")


# =============================================================================
# FONCTION PRINCIPALE DE COLLECTE (utilisable directement)
# =============================================================================

async def collect_traces(
    manifest_path: str | Path,
    out_dir: str | Path,
    max_concurrent: int = 3,
    seq_len: int = 50,
    batch_size: int = 50,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Fonction principale de collecte de traces.
    
    Args:
        manifest_path: Chemin vers le fichier manifest.json
        out_dir: Dossier de sortie
        max_concurrent: Nombre de containers simultanés
        seq_len: Longueur de séquence
        batch_size: Sauvegarde intermédiaire tous les N fichiers
        limit: Limite le nombre de fichiers (pour tester)
    
    Returns:
        Dict avec les statistiques de la collecte
    """
    manifest_path = Path(manifest_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(manifest_path.read_text())
    if limit:
        # Pour tester : prend N entrées en conservant la balance malveillant/bénin
        mal = [e for e in manifest if e["label"] == 1][:limit//2]
        ben = [e for e in manifest if e["label"] == 0][:limit//2]
        manifest = mal + ben
        log.info(f"Mode test : {len(manifest)} fichiers (limit={limit})")
    else:
        log.info(f"{len(manifest)} fichiers à analyser")

    semaphore = asyncio.Semaphore(max_concurrent)
    extractor = FeatureExtractor(window_size=20)

    # Log de progression
    stats = {"ok": 0, "fail": 0, "total_events": 0}
    run_log = []

    batch_idx = 0
    batch_buffer = []

    start = datetime.now()
    
    # Création des tâches
    tasks = [
        collect_one(entry, semaphore, FeatureExtractor(window_size=20), seq_len)
        for entry in manifest
    ]
    
    # Traitement au fil de l'eau avec as_completed
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        result = await coro
        entry = manifest[i] if i < len(manifest) else {}

        if result is not None:
            stats["ok"] += 1
            stats["total_events"] += result["n_events"]
            batch_buffer.append(result)
            run_log.append({
                "path": entry.get("path", ""),
                "label": result["label"],
                "family": result["family"],
                "language": result["language"],
                "n_events": result["n_events"],
                "final_score": result["final_score"],
                "status": "ok",
            })
        else:
            stats["fail"] += 1
            run_log.append({"path": entry.get("path", ""), "status": "fail"})

        # Sauvegarde par batch
        if len(batch_buffer) >= batch_size:
            save_batch(batch_buffer, out_dir, batch_idx)
            batch_idx += 1
            batch_buffer = []

        # Progression
        done = stats["ok"] + stats["fail"]
        if done % 20 == 0 or done == len(manifest):
            elapsed = (datetime.now() - start).total_seconds()
            rate = done / elapsed if elapsed > 0 else 0
            log.info(f"[{done}/{len(manifest)}] ok={stats['ok']} fail={stats['fail']} "
                     f"events={stats['total_events']} {rate:.1f} fichiers/s")

    # Dernier batch partiel
    if batch_buffer:
        save_batch(batch_buffer, out_dir, batch_idx)

    # Sauvegarde du log de run
    run_log_path = out_dir / "run_log.json"
    run_log_path.write_text(json.dumps(run_log, indent=2))

    # Fusion finale + scaler global
    merge_and_finalize(out_dir, seq_len)

    elapsed = (datetime.now() - start).total_seconds()
    log.info(f"Terminé en {elapsed/60:.1f} min | ok={stats['ok']} fail={stats['fail']}")
    
    return {
        "ok": stats["ok"],
        "fail": stats["fail"],
        "total_events": stats["total_events"],
        "elapsed_seconds": elapsed,
        "output_dir": str(out_dir),
    }


# =============================================================================
# INTERFACE ARGPARSE
# =============================================================================

def parse_args():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(description="Collecte de traces sandbox pour ML")
    parser.add_argument("--manifest", default="output/manifest.json",
                        help="Chemin vers le fichier manifest.json")
    parser.add_argument("--out_dir", default="../ml_model/datasets",
                        help="Dossier de sortie pour X_seq.npy, X_ebd.npy, y.npy, scaler.joblib")
    parser.add_argument("--max_concurrent", type=int, default=3,
                        help="Containers simultanés (calibre selon ta RAM : N × 256m)")
    parser.add_argument("--seq_len", type=int, default=50,
                        help="Longueur de séquence (baisse si peu d'events/session)")
    parser.add_argument("--batch_size", type=int, default=50,
                        help="Sauvegarde intermédiaire tous les N fichiers")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limite le nombre de fichiers (pour tester)")
    return parser.parse_args()


# =============================================================================
# MAIN
# =============================================================================

async def main(**kwargs):
    """Point d'entrée principal avec argparse."""
    args_name = ["manifest_path", "out_dir", "max_concurrent", "seq_len", "batch_size", "limit"]
    # Appel de la fonction de collecte avec les arguments parsés
    stats = await collect_traces(
        **{k:v for k, v in kwargs.items() if k in args_name}
    )
    
    return stats


if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    # args = parse_args()
    # asyncio.run(main(**vars(args)))
    args = {
        "manifest_path": "output/manifest.json",
        "out_dir": "../ml_model/datasets",
        "max_concurrent": 10,
        "seq_len": 50,
        "batch_size": 500,
        # "limit": 2,
    }
    asyncio.run(main(**args))