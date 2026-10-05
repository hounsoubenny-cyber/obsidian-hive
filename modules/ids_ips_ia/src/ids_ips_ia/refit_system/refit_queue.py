#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 21:16:21 2026

@author: hounsousamuel

RefitQueue : met de côté les paquets capturés (deque en RAM) et les écrit sur disque
périodiquement, dans REFIT_DIR, pour le ré-apprentissage (ModelRefitMonitor).

À créer DANS le processus de capture : la deque n'est jamais partagée entre processus,
seuls les fichiers sur disque sortent du processus (c'est le canal vers le refit).
Si plusieurs processus de capture utilisent la même session, chacun a son `tag`
(par défaut son PID) : leurs fichiers ne se marchent pas dessus.

Corrections par rapport à l'ancienne version :
  - stop() fait une DERNIÈRE sauvegarde (avant : jusqu'à 50 000 paquets perdus).
  - le thread se réveille toutes les 60 s au maximum (avant : sleep fixe de 5 min,
    donc stop() n'attendait pas vraiment).
  - la rotation par taille (getsize * 1024 * 1024, toujours vraie) est supprimée :
    UN fichier par sauvegarde, écrit de façon ATOMIQUE (.tmp puis os.replace). Le refit
    ne lit donc jamais un fichier à moitié écrit. Les anciens fichiers .pkl (plusieurs
    chunks par fichier) restent lisibles : load_pkt_file lit tous les chunks.
  - si l'écriture échoue, les paquets sont REMIS dans la deque (avant : perdus).
  - verrou threading.Lock (avant : mp.Lock alors que seuls des threads l'utilisent).
  - put_many() : un seul verrou pour tout un lot (ta capture travaille par lots).
  - put() renvoie True/False et compte les pertes ; stats() les expose.
  - remove_files() / __main__ : les chemins sont maintenant joints à REFIT_DIR.
"""

import os
import time
import random
import threading
from collections import deque
from ids_ips_ia.core.capture import _save
from ids_ips_ia.ids_ips_utils.logger import get_logger
from ids_ips_ia.refit_system.config import FILE_PREFIX, REFIT_DIR
from concurrent.futures import ThreadPoolExecutor

logger = get_logger()


class RefitQueue:
    """Tampon de paquets (ts, raw) sauvegardé périodiquement sur disque.

    Args:
        session_id:    identifiant de la session (dans le nom des fichiers).
        save_interval: secondes entre deux sauvegardes automatiques.
        max_items:     taille max de la deque. Pleine : les NOUVEAUX paquets sont jetés
                       (on garde les plus anciens de la période) et comptés dans `over`.
        sample_rate:   probabilité de garder chaque paquet (1.0 = tous). Avec max_items
                       fixe, une valeur < 1 étale la deque sur toute la période au lieu
                       de ne garder que les premières secondes après chaque sauvegarde.
        tag:           étiquette unique de ce processus dans les noms de fichiers
                       (défaut : le PID).
    """

    def __init__(
        self,
        session_id: str,
        max_file_size: int = 100 * 1024 * 1024,
        save_interval: int | float = 5.0,
        max_items: int = 150_000,
        sample_rate: float = 1.0,
        tag: str | None = None,
        *args, **kwargs
    ):
        if not 0.0 < sample_rate <= 1.0:
            raise ValueError("sample_rate doit être dans ]0, 1]")
        self.session_id = session_id
        self.tag = tag if tag is not None else str(os.getpid())
        self.current_num = 0
        self.last_save_time = time.time()
        self.stop_event = threading.Event()
        self.current_filename = ""
        self.max_items = max_items
        self.q_size = max_items                  # ancien nom
        self.queue = deque()
        self._backup = deque()
        self._lock = threading.Lock()
        self.thread = None
        self.save_interval = save_interval
        self.sample_rate = sample_rate
        self._threadpool = ThreadPoolExecutor(max_workers=4)
        # compteurs (pour stats())
        self.over = 0             # nombre de paquet qui dépassent
        self.sampled_out = 0      # non gardés volontairement (sample_rate < 1)
        self.saved_files = 0
        self.saved_items = 0
        self.failed_saves = 0

    # ------------------------------------------------------------ cycle de vie
    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self.save_periodic,
            args=(self.save_interval,),
            daemon=True,
            name="RefitQueue-save",
        )
        self.thread.start()

    def stop(self, timeout: float = 10.0):
        """Arrête le thread puis fait une DERNIÈRE sauvegarde."""
        self.stop_event.set()
        if self.thread:
            try:
                self.thread.join(timeout)
            except Exception:
                pass
        self._threadpool.shutdown(wait=True, cancel_futures=False)
        self.save()

    # ----------------------------------------------------------------- écrire
    def put(self, item) -> bool:
        """Ajoute un paquet. True = gardé (ou écarté volontairement par sample_rate),
        False = deque pleine, paquet perdu (compté dans `over`)."""
        if self.sample_rate < 1.0 and random.random() >= self.sample_rate:
            self.sampled_out += 1
            return True
        
        over = False
        with self._lock:
            if len(self.queue) >= self.max_items:
                self.queue.append(item)
                over = True
                self.over += 1
            if not over:
                self.queue.append(item)
                return True
            
        if over:
            self._threadpool.submit(self.save, )
        return True

    def put_nowait(self, item) -> bool:
        return self.put(item)

    def put_many(self, items) -> int:
        """Ajoute un lot de paquets avec UN SEUL verrou.
        Renvoie le nombre de paquets gardés. Ceux qui ne rentrent pas sont jetés et
        comptés dans `over`."""
        if self.sample_rate < 1.0:
            rate = self.sample_rate
            kept = [it for it in items if random.random() < rate]
            self.sampled_out += len(items) - len(kept)
            items = kept
        with self._lock:
            room = self.max_items - len(self.queue)
            self.queue.extend(items)
            over = (len(items) - room) if room < len(items) else 0
        if over:
            self._threadpool.submit(self.save, )
        self.over += over
        return len(items)

    # ------------------------------------------------------------------ lire
    def get(self):
        """Retire le plus ancien paquet, ou None si vide."""
        with self._lock:
            return self.queue.popleft() if self.queue else None

    def get_nowait(self):
        return self.get()

    # --------------------------------------------------------------- fichiers
    def build_filename(self):
        # FORMAT "FILE_PREFIX__session_id__tag__num.pkl"
        filename = f"{FILE_PREFIX}__{self.session_id}__{self.tag}__{self.current_num}.pkl"
        self.current_filename = filename
        self.current_num += 1
        return filename

    def is_current_refit_queue_file(self, path: str) -> bool:
        return self.session_id in path and self.tag in path

    def remove_files(self):
        """Supprime les fichiers de refit des AUTRES sessions."""
        for name in os.listdir(REFIT_DIR):
            full = os.path.join(REFIT_DIR, name)
            if (
                os.path.isfile(full) and name.startswith(FILE_PREFIX)
                and name.endswith(".pkl")
                and not self.is_current_refit_queue_file(name)
            ):
                os.remove(full)

    def save_periodic(self, save_interval):
        # wait() se réveille tout de suite si stop() est appelé
        while not self.stop_event.wait(timeout=min(float(save_interval), 5.0)):
            if time.time() - self.last_save_time >= save_interval:
                self.save()
        
        self.save()

    def save(self) -> bool:
        """Écrit la deque dans UN nouveau fichier (atomique). True = ok (ou rien à écrire)."""
        with self._lock:
            data = list(self.queue)
            self.queue.clear()
        
        if not data:
            self.last_save_time = time.time()
            return True

        try:
            os.makedirs(REFIT_DIR, exist_ok=True)
            filename = os.path.join(REFIT_DIR, self.build_filename())
            _save(data, filename)                # .tmp puis os.replace
        except Exception as e:
            logger.error("Erreur survenue lors de la sauvegarde :", str(e))
            self.failed_saves += 1
            with self._lock:                     # on REMET les paquets (les plus anciens devant)
                self.queue.extendleft(reversed(data))
            return False
        
            
        self.saved_files += 1
        self.saved_items += len(data)
        self.last_save_time = time.time()
        return True

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict:
        with self._lock:
            queued = len(self.queue)
        return {
            "queued": queued,
            "over": self.over,
            "sampled_out": self.sampled_out,
            "saved_files": self.saved_files,
            "saved_items": self.saved_items,
            "failed_chunks": self.failed_saves,
        }


if __name__ == "__main__":
    filesname = [
        name for name in os.listdir(REFIT_DIR)
        if os.path.isfile(os.path.join(REFIT_DIR, name)) and name.startswith(FILE_PREFIX)
        and name.endswith(".pkl")
    ]
    logger.info(filesname)
    
    rf = RefitQueue(session_id="sam",)
    rf.start()
    for i in range(10000000):
        rf.put(i)
    
    for batch in [list(range(1000)) for _ in range(10000)]:
        rf.put_many(batch)
    rf.stop()
    print("stats")
    print(rf.stats())