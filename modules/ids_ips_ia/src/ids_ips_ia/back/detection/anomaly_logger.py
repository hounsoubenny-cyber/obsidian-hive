#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct  1 07:40:31 2026

@author: hounsousamuel
"""


"""
anomaly_logger.py — Remplace la persistance de log_anomaly() (joblib.dump de TOUTE la liste à chaque anomalie).

Avant : append en mémoire + joblib.dump(self.anomalies) à CHAQUE anomalie, dans le thread de détection
        -> coût O(n) par anomalie (quadratique au total), pickler Python pur, features en list de floats.
Après : log() = copie float32 + put_nowait dans une queue (quelques µs). Un thread d'écriture dédié
        regroupe les entrées par lots (taille OU délai) et les AJOUTE à la fin du fichier courant
        avec le pickler C. Le fichier tourne (rotation) tous les `max_per_file` entrées.

Garanties :
  - la détection ne bloque JAMAIS sur le disque : queue bornée, si elle est pleine l'anomalie est
    comptée dans `dropped` (et un avertissement limité à 1 / 10 s est émis) ;
  - aucun gros fichier rechargé au démarrage : chaque run démarre un NOUVEAU fichier ;
  - crash-safe : un lot = un pickle complet ; une fin tronquée est ignorée par iter_anomalies() ;
  - fermeture propre via atexit (drain de la queue). Un SIGKILL perd au plus `flush_interval` secondes ;
  - sûr avec fork/spawn : le thread est (re)démarré paresseusement si le PID change.
,
Intégration dans detection/detection_module.py :

    from ids_ips_ia.detection.anomaly_logger import AnomalyLogger

    # __init__ : remplace  self.anomalies, self.current_file = self.load_anomalies()
    self.anomaly_logger = AnomalyLogger(ANOM_DIR, ANOMALY_FILE_PREFIX, int(MAX_ANOMALIES),
                                        on_warning=logger.print)

    # log_anomaly devient :
    def log_anomaly(self, array, pred, source="IA"):
        self.anomaly_logger.log(array, pred, source)

    # (optionnel) dans tes stats : self.anomaly_logger.stats()

Lecture (refit, scripts...) : for entry in iter_anomalies(path): ...   # gère nouveau ET ancien format
Format d'une entrée (inchangé, sauf `features`) :
  {"timestamp", "prediction", "source", "seq_length", "features"}  avec features = ndarray float32
  (avant : list de floats). np.asarray(entry["features"]) marche pour les deux.
"""

import os
import time
import queue
import atexit
import pickle
import threading
import numpy as np
from typing import Callable
from datetime import datetime

_STOP = object()


class AnomalyLogger:
    def __init__(
        self,
        directory: str,
        prefix: str = "anomalies", 
        max_per_file: int = 10_000, 
        *,
        batch_size: int = 128, 
        flush_interval: float = 2.0, 
        queue_max: int = 5_000,
        on_warning: Callable | None = None, 
        on_write: Callable | None = None, 
        after_write: Callable | None = None, 
        dtype=np.float32
    ):
        self.dir = str(directory)
        self.prefix = prefix
        self.max_per_file = max(1, int(max_per_file))
        self.batch_size = max(1, int(batch_size))
        self.flush_interval = float(flush_interval)
        self.dtype = dtype
        self._warn_cb = on_warning or print
        self._on_write = on_write
        self._after_write = after_write
        self._on_write_is_callable = callable(on_write)
        self._after_write_is_callable = callable(after_write)
        os.makedirs(self.dir, exist_ok=True)

        self._q = queue.Queue(maxsize=int(queue_max))
        self._lock = threading.Lock()          # protège seulement le (re)démarrage du thread
        self._thread = None
        self._pid = None
        self._closed = False
        self._last_warn = 0.0

        # état touché UNIQUEMENT par le thread d'écriture
        self._file = self._next_file()
        self._count = 0

        # compteurs (lecture seule côté appelant)
        self.logged = 0
        self.written = 0
        self.dropped = 0
        self.write_errors = 0

        atexit.register(self.close)

    # ------------------------------------------------------------------ API
    def log(self, array, pred, source="IA") -> bool:
        """Enregistre une anomalie. Non bloquant. Retourne False si elle a été abandonnée."""
        if self._closed:
            return False
        try:
            feats = np.array(array, dtype=self.dtype)           # COPIE : l'appelant peut réutiliser `array`
            entry = {
                "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "prediction": pred,
                "source": source,
                "seq_length": len(feats),
                "features": feats,
            }
            self._ensure_thread()
            self._q.put_nowait(entry)
            self.logged += 1
            return True
        except queue.Full:
            self.dropped += 1
            self._warn(f"AnomalyLogger : queue pleine, anomalie abandonnée ({self.dropped} au total)")
            return False
        except Exception as e:                                    # ne jamais casser la détection
            self.write_errors += 1
            self._warn(f"AnomalyLogger.log : {e!r}")
            return False

    def close(self, timeout: float = 15.0):
        """Vide la queue et écrit le dernier lot. Idempotent."""
        if self._closed:
            return
        
        self._closed = True
        t = self._thread
        if t is not None and t.is_alive() and self._pid == os.getpid():
            try:
                self._q.put(_STOP, timeout=timeout)
            except queue.Full:
                return
            t.join(timeout)

    def stats(self) -> dict:
        return {
            "logged": self.logged, 
            "written": self.written, 
            "dropped": self.dropped,
            "write_errors": self.write_errors,
            "queued": self._q.qsize(), 
            "file": self._file
        }

    # ------------------------------------------------------------- interne
    def _warn(self, msg: str):
        now = time.monotonic()
        if now - self._last_warn > 10.0:                          # anti-flood
            self._last_warn = now
            try:
                self._warn_cb(msg)
            except Exception:
                pass

    def _ensure_thread(self):
        pid = os.getpid()
        t = self._thread
        if t is not None and t.is_alive() and self._pid == pid:
            return
        with self._lock:
            t = self._thread
            if t is not None and t.is_alive() and self._pid == pid:
                return
            if self._pid is not None and self._pid != pid:        # après fork : nouvelle queue + lock propres
                self._q = queue.Queue(maxsize=self._q.maxsize)
                self._lock = threading.Lock()
            self._pid = pid
            self._thread = threading.Thread(target=self._run, name="AnomalyWriter", daemon=True)
            self._thread.start()

    def _next_file(self) -> str:
        i = 0
        while os.path.exists(os.path.join(self.dir, f"{self.prefix}_{i}.pkl")):
            i += 1
        return os.path.join(self.dir, f"{self.prefix}_{i}.pkl")

    def _run(self):
        batch, deadline = [], 0.0
        while True:
            timeout = max(0.0, deadline - time.monotonic()) if batch else self.flush_interval
            try:
                item = self._q.get(timeout=timeout)
            except queue.Empty:
                item = None
            stop = item is _STOP
            if item is not None and not stop:
                if not batch:
                    deadline = time.monotonic() + self.flush_interval
                batch.append(item)
                
            if batch and (stop or len(batch) >= self.batch_size or time.monotonic() >= deadline):
                self._write(batch)
                batch = []
                
            if stop:
                return

    def _write(self, batch):
        try:
            i = 0
            if self._on_write_is_callable:
                try:
                    self._on_write(self, batch)
                except Exception:
                    pass
                
            while i < len(batch):
                room = self.max_per_file - self._count # place restant dans le fichier courant
                if room <= 0:                                     # rotation
                    self._file = self._next_file()
                    self._count = 0
                    room = self.max_per_file
                chunk = batch[i:i + room]
                with open(self._file, "ab") as f:                 # append : on ne réécrit JAMAIS l'historique
                    pickle.dump(chunk, f, protocol=pickle.HIGHEST_PROTOCOL)
                self._count += len(chunk)
                i += len(chunk)
            self.written += len(batch)
        except Exception as e:
            self.write_errors += 1
            self._warn(f"AnomalyLogger écriture : {e!r} (lot de {len(batch)} perdu)")
        
        finally:
            if self._after_write_is_callable:
                try:
                    self._after_write(self)
                except Exception:
                    pass

def iter_anomalies(path):
    """
    Itère sur les entrées d'un fichier d'anomalies.
    Gère : nouveau format (lots pickle successifs, fin tronquée tolérée) et ancien format joblib.
    """
    got_any = False
    try:
        with open(path, "rb") as f:
            while True:
                try:
                    chunk = pickle.load(f)
                except EOFError:
                    return
                got_any = True
                yield from chunk
    except (pickle.UnpicklingError, AttributeError, ImportError, IndexError, ValueError, MemoryError, OSError):
        if got_any:
            return                                                # fin tronquée après un crash : on garde le reste
        import joblib                                             # ancien format (peut être compressé)
        yield from joblib.load(path)


if __name__ == "__main__":
    # Auto-test : python3 anomaly_logger.py
    import glob
    import shutil
    import tempfile

    def after_write(logger, *args, **kwargs):
        print("Stats: ", logger.stats())
        
    tmp = tempfile.mkdtemp()
    try:
        N, F = 1000, 40
        lg = AnomalyLogger(tmp, "anomalies", max_per_file=100, batch_size=10, flush_interval=0.2, after_write=after_write)
        arr = np.random.rand(60, F)
        t0 = time.perf_counter()
        for k in range(N):
            arr[0, 0] = k                                         # l'appelant réutilise/modifie son buffer
            assert lg.log(arr, 0.9, "IA")
        per_call = (time.perf_counter() - t0) / N * 1e6
        lg.close()
        files = sorted(glob.glob(os.path.join(tmp, "anomalies_*.pkl")))
        entries = [e for p in files for e in iter_anomalies(p)]
        assert len(entries) == N and lg.written == N and lg.dropped == 0, lg.stats()
        assert len(files) == 10, files                            # rotation tous les 100
        assert entries[5]["features"][0, 0] == 5.0 and entries[5]["features"].dtype == np.float32  # copie OK
        assert entries[0]["seq_length"] == 60

        # fin tronquée (crash) : on récupère tout sauf le dernier lot incomplet
        with open(files[-1], "ab") as f:
            f.write(b"\x80\x05garbage-tronque")
        assert len([e for e in iter_anomalies(files[-1])]) == 100

        # queue pleine : jamais bloquant, compté dans dropped
        lg2 = AnomalyLogger(tmp, "q", 10, queue_max=5, flush_interval=5, batch_size=1000, on_warning=lambda m: None)
        lg2._ensure_thread()
        lg2._thread = threading.Thread(target=lambda: time.sleep(5), daemon=True); lg2._thread.start()  # writer figé
        res = [lg2.log(arr, 1, "IA") for _ in range(20)]
        assert res.count(False) == 10 and lg2.dropped == 10
        print(f"✅ tests OK — log() = {per_call:.1f} µs/appel · {N} entrées · {len(files)} fichiers · "
              f"queue pleine gérée (10/20 abandonnées sans bloquer)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
