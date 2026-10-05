#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 05:42:05 2026

@author: hounsousamuel
"""

"""
ring.py : buffer circulaire en mémoire partagée (SharedMemory + struct).

Disposition de la mémoire partagée :

    [ n_write (8) ][ n_read (8) ][ zone de données : cap octets ............ ]
      compteurs qui ne font qu'augmenter             position réelle = compteur % cap

Un paquet dans la zone de données = [ts (8 octets)][taille (4 octets)][données]

Principe : UN SEUL writer et UN SEUL reader par ring, donc aucun lock.
    - seul le WRITER modifie n_write (EN DERNIER, après avoir écrit les données)
    - seul le READER modifie n_read  (EN DERNIER, après avoir lu les données)
Chacun lit le compteur de l'autre sans jamais l'écrire. Si ce compteur est un peu en
retard, on est pessimiste (moins de place / moins de données), jamais optimiste.

ATTENTION, compteurs : on les lit/écrit avec un memoryview de type 'Q' (UN accès de
8 octets alignés, atomique sur x86-64 et ARM64), PAS avec struct.pack_into. struct écrit
l'entier en deux temps (zéro puis octets) : un lecteur peut alors voir 0 au milieu d'une
écriture (mesuré : des dizaines de milliers de lectures "en arrière" sur 3 millions
d'écritures). Lire le compteur deux fois ne règle pas ça.
 

Plusieurs sources (ex : n processus de capture) ? UN RING PAR SOURCE, puis un
MultiReader qui les lit à tour de rôle.
RingQueue = un MultiReader déguisé en queue.Queue (get_nowait / put_nowait / qsize...),
avec en plus une petite file locale pour les éléments qui ne sont pas des bytes.

Les 3 rôles (paramètre `role`) :
    "P"  Parent / Propriétaire : CRÉE le bloc (create=True) et appelle unlink()
         à la fin, une seule fois. Rôle par défaut quand create=True.
    "W"  Writer : rejoint le bloc (create=False), appelle SEULEMENT put().
    "R"  Reader : rejoint le bloc (create=False), appelle SEULEMENT get().
Le rôle sert aux messages de debug et à deux garde-fous : un "R" ne peut pas appeler
put(), un "W" ne peut pas appeler get(). Tout le monde appelle close() à la fin.
"""

# La nouvelle idée, on garde des positions qui grandissent, pour avoir la position, on fait % cap
# Là c'est plus simple, utilisé = w - r (écrit - lu = restant, bloc utilisé qui contient encore des données)
# w - r == 0 => vide, pas de bloc utilisé, w - r == cap => buffer plein
# libre (là où on peut écrire) = cap - utilisé = cap - (w - r)

import os
import sys
import time
import queue
import struct
import multiprocessing as mp
from typing import List
from multiprocessing import shared_memory


IDX_W, IDX_R = 0, 1                 # les 2 compteurs = tableau de 2 entiers de 8 octets :
                                    # n_write à l'octet 0, n_read à l'octet 8
HEADER_SIZE = 16                    # 8 + 8 : la zone de données commence à l'octet 16
PKT_HEADER = struct.Struct("<dI")   # ts (double) + taille du paquet (entier)
PKT_HEADER_SIZE = PKT_HEADER.size   # 12
 


class Ring:
    """Un buffer circulaire en mémoire partagée, pour UN writer et UN reader.

    Args:
        name:    nom du bloc de mémoire partagée (le même pour tous les processus).
        cap:     taille de la zone de données en octets. DOIT être identique partout.
        create:  True = je crée le bloc (rôle P). False = je rejoins un bloc existant.
        verbose: True = affiche chaque put/get avec n_write, n_read, used, free.
        role:    "P", "W" ou "R" (voir la docstring du module). Vide = pas de garde-fou.

    Attributs utiles :
        counts:  compteurs locaux à CE processus : wraps (paquets qui traversent le
                 bord), full (put refusés), empty (get sans rien à lire).
    """

    def __init__(
        self, name: str, cap: int, create: bool = False,
        verbose: bool = False, role: str = ""
    ):
        if role not in ("", "P", "W", "R"):
            raise ValueError(f"role doit être 'P', 'W', 'R' ou vide, obtenu {role!r}")
        self.name = name
        self.cap = cap
        self.verbose = verbose
        self.role = role or ("P" if create else "")
        self.created = create
        self.counts = {"wraps": 0, "full": 0, "empty": 0}
        self._wait_state = None                  # pour ne pas spammer "plein" / "vide"

        if create:                               # le PARENT fabrique le bloc
            self.shm = shared_memory.SharedMemory(
                name=name, create=True, size=HEADER_SIZE + cap
            )
        else:                                    # les autres le REJOIGNENT par son nom
            # Python >= 3.13 : track=False pour que le "surveillant" ne supprime pas
            # le bloc quand CE processus se termine.
            kwargs = {"track": False} if sys.version_info >= (3, 13) else {}
            self.shm = shared_memory.SharedMemory(name=name, **kwargs)
            if self.shm.size < HEADER_SIZE + cap:
                raise ValueError(
                    f"Bloc trop petit : même cap partout ! "
                    f"({self.shm.size} < {HEADER_SIZE + cap})"
                )
        # Les 2 compteurs vus comme un tableau d'entiers 'Q' (8 octets natifs, alignés) :
        # chaque lecture / écriture est UN seul accès mémoire (atomique).
        self._hdr_view = self.shm.buf[:HEADER_SIZE]
        self._ctr = self._hdr_view.cast("Q")
        if create:
            self._ctr[IDX_W] = 0
            self._ctr[IDX_R] = 0
        self._dbg(f"INIT name={name} cap={cap} créé={create}")

    def _dbg(self, msg: str):
        if self.verbose:
            print(f"[{self.role}{os.getpid()}] {msg}", flush=True)

    # ----------------------------------------------------------------- compteurs
    def _counters(self):
        """Lit (n_write, n_read). Chaque lecture est atomique (un accès de 8 octets).
        Les deux ne sont pas lus au même instant, mais ce n'est pas grave : le compteur
        de l'AUTRE processus peut seulement être en retard, donc on est pessimiste."""
        return self._ctr[IDX_W], self._ctr[IDX_R]
    
    def _all(self):
        """Toutes les infos en une fois :
        (n_write, n_read, w_pos, r_pos, used, free)
    
        w_pos / r_pos = position réelle dans la mémoire partagée (header compris).
        used = n_write - n_read   (octets occupés, pas encore lus)
        free = cap - used         (octets où on peut écrire)
        """
        n_write, n_read = self._counters()
        w_pos = (n_write % self.cap) + HEADER_SIZE
        r_pos = (n_read % self.cap) + HEADER_SIZE
        used = n_write - n_read
        return n_write, n_read, w_pos, r_pos, used, self.cap - used


    # --- écrire / lire des octets "dans le cercle", en coupant en deux au bord ---
    def _write_at(self, counter: int, data: bytes):
        """Écrit `data` à partir du compteur `counter`. Si ça dépasse la fin de la
        zone de données, le reste repart au début."""
        pos = counter % self.cap                 # position réelle dans la zone de données
        first = min(len(data), self.cap - pos)   # ce qui tient jusqu'au bord
        self.shm.buf[HEADER_SIZE + pos : HEADER_SIZE + pos + first] = data[:first]
        self.shm.buf[HEADER_SIZE : HEADER_SIZE + len(data) - first] = data[first:]

    def _read_at(self, counter: int, length: int) -> bytes:
        """Lit `length` octets à partir du compteur `counter` (coupé en deux au bord)."""
        pos = counter % self.cap
        first = min(length, self.cap - pos)
        return (bytes(self.shm.buf[HEADER_SIZE + pos : HEADER_SIZE + pos + first])
                + bytes(self.shm.buf[HEADER_SIZE : HEADER_SIZE + length - first]))

    # ----------------------------------------------------------------------- API
    def put(self, pkt: bytes, ts: float | None = None) -> bool:
        """Écrit un paquet. Rôle W (ou P/vide pour un test mono-processus).

        Ne bloque jamais.
        Args:
            pkt: les octets du paquet.
            ts:  date du paquet (ex : celle de la capture). None = date d'écriture.
                 (`is None` et pas `or` : un ts valant 0.0 reste un vrai ts.)
        Returns:
            True  : paquet écrit.
            False : pas assez de place pour CE paquet. À toi de décider : réessayer
                    plus tard, ou le jeter et compter un "dropped" (cas d'un IDS).
        Raises:
            PermissionError : si le rôle est "R".
            ValueError      : si le paquet ne rentrera JAMAIS (plus grand que cap).
        """
        if self.role == "R":
            raise PermissionError("rôle R : seul un writer (W) peut appeler put()")
        n_write, n_read, w_pos, r_pos, used, free = self._all()
        item = PKT_HEADER.pack(time.time() if ts is None else ts, len(pkt)) + pkt
        if len(item) > self.cap:
            raise ValueError(f"Paquet trop grand ({len(item)} > {self.cap})")

        if free < len(item):
            self.counts["full"] += 1
            if self._wait_state != "full":
                self._dbg(
                    f"PUT item={len(item)} | n_write={n_write} n_read={n_read} "
                    f"used={used} free={free} -> PLEIN"
                )
                self._wait_state = "full"
            return False

        self._wait_state = None
        if n_write % self.cap + len(item) > self.cap:
            self.counts["wraps"] += 1
        self._write_at(n_write, item)
        # EN DERNIER : on avance n_write seulement quand les données sont écrites
        self._ctr[IDX_W] = n_write + len(item)
        self._dbg(
            f"PUT item={len(item)} | n_write {n_write} -> {n_write + len(item)} "
            f"w_pos={w_pos} r_pos={r_pos} used={used} free={free}"
        )
        return True
    
    def put_many(self, items) -> int:
        """Écrit PLUSIEURS paquets en une fois (un lot de capture). Rôle W (ou P/vide).

        Beaucoup plus économe que n appels à put() : les lectures des compteurs, la
        copie dans la mémoire et la mise à jour de n_write ne sont faites qu'UNE fois.

        Args:
            items: liste de (ts, pkt), exactement le format de ta capture.
                   ts = None : date d'écriture.
        Returns:
            Le NOMBRE de paquets écrits. On écrit les premiers, DANS L'ORDRE, tant qu'il
            y a de la place, et on s'arrête au premier qui ne rentre pas (jamais de trou
            dans l'ordre). Les autres ne sont PAS écrits : à toi de les compter comme
            perdus (dropped += len(items) - n) ou de les réessayer.
        Raises:
            PermissionError : si le rôle est "R".
            ValueError      : si un paquet ne rentrera JAMAIS (plus grand que cap).
        """
        if self.role == "R":
            raise PermissionError("rôle R : seul un writer (W) peut appeler put_many()")
        n_write, n_read, w_pos, r_pos, used, free = self._all()
        parts, total, count = [], 0, 0
        for ts, pkt in items:
            need = PKT_HEADER_SIZE + len(pkt)
            if need > self.cap:
                raise ValueError(f"Paquet trop grand ({need} > {self.cap})")
            if total + need > free:                  # ne rentre pas : on s'arrête ici
                break
            parts.append(PKT_HEADER.pack(time.time() if ts is None else ts, len(pkt)))
            parts.append(pkt)
            total += need
            count += 1

        if count < len(items):
            self.counts["full"] += 1
        if count == 0:
            return 0
        if n_write % self.cap + total > self.cap:
            self.counts["wraps"] += 1
        self._write_at(n_write, b"".join(parts))     # UNE seule copie (coupée en 2 si besoin)
        self._ctr[IDX_W] = n_write + total           # UNE seule mise à jour, EN DERNIER
        self._dbg(
            f"PUT_MANY {count}/{len(items)} paquets, {total} octets | "
            f"n_write {n_write} -> {n_write + total} used={used} free={free}"
        )
        return count
    

    def get(self):
        """Lit le plus ancien paquet. Rôle R (ou P/vide pour un test mono-processus).

        Ne bloque jamais.
        Returns:
            (ts, pkt) : le paquet (ts = date d'écriture en secondes, pkt = bytes).
            (None, None) : rien à lire pour l'instant.
        Raises:
            PermissionError : si le rôle est "W".
            RuntimeError    : si le buffer est corrompu (ne devrait jamais arriver).
        """
        if self.role == "W":
            raise PermissionError("rôle W : seul un reader (R) peut appeler get()")
        n_write, n_read, w_pos, r_pos, used, free = self._all()
        if used == 0:
            self.counts["empty"] += 1
            if self._wait_state != "empty":
                self._dbg(f"GET | n_write={n_write} n_read={n_read} used=0 -> VIDE")
                self._wait_state = "empty"
            return None, None

        self._wait_state = None
        ts, size = PKT_HEADER.unpack(self._read_at(n_read, PKT_HEADER_SIZE))
        if size > used - PKT_HEADER_SIZE:        # impossible si tout va bien
            raise RuntimeError(f"Buffer corrompu : size={size} used={used} "
                               f"n_write={n_write} n_read={n_read}")
        pkt = self._read_at(n_read + PKT_HEADER_SIZE, size)   # JUSTE APRÈS l'en-tête
        new_read = n_read + PKT_HEADER_SIZE + size
        self._ctr[IDX_R] = new_read                           # EN DERNIER
        self._dbg(f"GET size={size} | n_read {n_read} -> {new_read} "
                  f"w_pos={w_pos} r_pos={r_pos} used={used} free={free}")
        return ts, pkt

    def close(self):
        """Tout le monde appelle close() quand il a fini."""
        self._ctr.release()           # il faut libérer les vues AVANT de fermer la mémoire
        self._hdr_view.release()
        self.shm.close()

    def unlink(self):
        """SEUL le parent (P) appelle unlink(), une seule fois, à la fin."""
        self.shm.unlink()


class MultiReader:
    """Lit plusieurs rings (un par source) à tour de rôle, dans UN seul processus.

    Chaque ring est ouvert avec create=False et role="R". Les rings doivent donc
    déjà exister (créés par le parent).

    Args:
        configs: liste des arguments d'init de chaque ring, par exemple
                 [{"name": "cap0", "cap": 1 << 20}, {"name": "cap1", "cap": 1 << 20}]
                 (create et role sont ignorés : ils sont forcés à False et "R").
        verbose: True = debug sur chaque ring.

    Équité : on ne commence pas toujours par le ring 0, sinon un ring très actif
    affamerait les autres. Après chaque lecture réussie, on commence au ring SUIVANT.
    """

    def __init__(self, configs: list[dict], verbose: bool = False):
        self.rings: list[Ring] = []
        for cfg in configs:
            kwargs = {k: v for k, v in cfg.items() if k not in ("create", "role")}
            kwargs.setdefault("verbose", verbose)
            self.rings.append(Ring(**kwargs, create=False, role="R"))
        self._next = 0                           # par quel ring commencer la prochaine fois

    def get(self):
        """Renvoie le premier paquet disponible, en parcourant les rings à tour de rôle.

        Returns:
            (index, ts, pkt) : index = position du ring dans `configs`.
            (None, None, None) : tous les rings sont vides.
        """
        n = len(self.rings)
        for k in range(n):
            i = (self._next + k) % n
            ts, pkt = self.rings[i].get()
            if ts is not None:
                self._next = (i + 1) % n         # la prochaine fois, on commence après
                return i, ts, pkt
        return None, None, None

    def close(self):
        """Ferme tous les rings (sans unlink : ce n'est pas notre bloc)."""
        for ring in self.rings:
            ring.close()


class RingWriter:
    def __init__(self, ring: Ring):
        if not isinstance(ring, Ring):
            raise TypeError("Un objet ring est nécessaire !")
            
        self.ring = ring
    
    def put(self, item: tuple[float | None, bytes]):
        try:
            ts, raw = item
            r = self.ring.put(pkt=raw, ts=ts)
            if r is False:
                raise queue.Full
            return r
        except (PermissionError, ValueError) as e:
            raise e
    
    def put_many(self, items: List[tuple[float | None, bytes]]):
        try:
            return self.ring.put_many(items)
        except (PermissionError, ValueError) as e:
            raise e
            
    def put_nowait(self, item: tuple[float | None, bytes]):
        return self.put(item)
        
            
class RingQueue:
    """Un MultiReader déguisé en `queue.Queue`, pour le détecteur.

    Il remplace la queue.Queue de l'orchestrator, avec deux sources :
      - les RINGS (un par interface), écrits par les processus de capture ;
      - une petite queue.Queue LOCALE, pour les éléments produits dans CE processus
        et qui ne sont pas des bytes (ex : les alertes Suricata `(eth, alert)`).

    get_nowait() regarde d'abord la file locale (rare, important), puis les rings.
    Il lève `queue.Empty` quand tout est vide, comme le détecteur l'attend, et renvoie
    `(ts, bytes)` pour un paquet capturé.

    Args:
        configs:       arguments d'init de chaque ring (voir MultiReader).
        local_maxsize: taille max de la file locale (0 = illimitée).
        est_pkt_bytes: taille moyenne estimée d'un paquet. Sert UNIQUEMENT à convertir
                       les octets des rings en nombre de paquets APPROXIMATIF pour
                       qsize() et maxsize (donc pour le fill_pct du détecteur).
        verbose:       debug sur chaque ring.
    """

    def __init__(
        self, configs: list[dict], local_maxsize: int = 10_000,
        est_pkt_bytes: int = 800, verbose: bool = False
    ):
        self._reader = MultiReader(configs, verbose=verbose)
        self._local = queue.Queue(maxsize=local_maxsize)
        self._est = max(1, est_pkt_bytes)

    # ------------------------------------------------- écrire (éléments locaux)
    def put_nowait(self, item):
        """Dépose un élément LOCAL (alerte...). Lève queue.Full si la file locale est pleine.
        Les paquets capturés n'arrivent PAS par ici : ils viennent des rings."""
        self._local.put_nowait(item)

    def put(self, item, block: bool = True, timeout: float | None = None):
        self._local.put(item, block, timeout)

    # ----------------------------------------------------------------- lire
    def get_nowait(self):
        """Renvoie un élément sans attendre : d'abord la file locale, puis les rings.
        Lève queue.Empty si tout est vide."""
        try:
            return self._local.get_nowait()
        except queue.Empty:
            pass
        idx, ts, pkt = self._reader.get()
        if idx is None:
            raise queue.Empty
        return ts, pkt

    def get(self, block: bool = True, timeout: float | None = None):
        """Comme queue.Queue.get : attend (en interrogeant toutes les ms) jusqu'à timeout."""
        if not block:
            return self.get_nowait()
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                return self.get_nowait()
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise
                time.sleep(0.001)

    # ------------------------------------------------------- taille / stats
    def _used_bytes(self) -> int:
        return sum(r._all()[4] for r in self._reader.rings)   # [4] = used

    def empty(self) -> bool:
        return self._local.empty() and self._used_bytes() == 0

    def qsize(self) -> int:
        """Nombre d'éléments APPROXIMATIF : locaux + octets des rings // est_pkt_bytes."""
        return self._local.qsize() + self._used_bytes() // self._est

    @property
    def maxsize(self) -> int:
        """Capacité APPROXIMATIVE en éléments (même estimation que qsize)."""
        return self._local.maxsize + sum(r.cap for r in self._reader.rings) // self._est

    def stats(self) -> dict:
        """Remplissage exact, en OCTETS, de chaque ring + taille de la file locale."""
        rings = []
        for r in self._reader.rings:
            used = r._all()[4]
            rings.append({
                "name": r.name,
                "used_bytes": used,
                "cap_bytes": r.cap,
                "fill_pct": round(100 * used / r.cap, 1),
            })
        return {"rings": rings, "local_size": self._local.qsize(),
                "local_max": self._local.maxsize}

    def close(self):
        """Ferme les rings (sans unlink : le parent s'en occupe)."""
        self._reader.close()



# =============================================================================
# TEST : n_rings processus writer (un ring chacun) + le processus principal
# qui les lit tous avec un MultiReader. Les fonctions des processus sont au niveau
# du module (obligatoire sur certains systèmes).
# =============================================================================
TS0 = 1_700_000_000.0      # le writer de test donne au paquet i la date TS0 + i
 
 
def make_packet(ring_id: int, i: int) -> bytes:
    """[ring_id (1 octet)][numéro du paquet (4 octets)][octet répété] : tailles variables."""
    size = 20 + (i * 7919 + ring_id * 131) % 380
    return bytes([ring_id]) + i.to_bytes(4, "little") + bytes([i % 251]) * (size - 5)
 
 
def writer_proc(results, cfg, ring_id, n, verbose):
    try:
        ring = Ring(**cfg, create=False, role="W", verbose=verbose)
        start = time.time()
        deadline = start + 30
        for i in range(n):
            pkt = make_packet(ring_id, i)
            while not ring.put(pkt, TS0 + i):    # plein : ici on attend (pour le test).
                # Dans un vrai IDS : on jette le paquet et on compte "dropped += 1".
                if time.time() > deadline:
                    raise TimeoutError(f"writer {ring_id} bloqué au paquet {i}")
                time.sleep(0.001)
        results.put((ring_id, time.time() - start, ring.counts))
        ring.close()
    except Exception as e:
        results.put((ring_id, "ERREUR", repr(e)))
 
 
def cleanup_old(name):
    # Si un test précédent a planté, le bloc existe encore : on le supprime.
    try:
        old = shared_memory.SharedMemory(name=name)
        old.close()
        old.unlink()
        print(f"(ancien bloc {name} supprimé)")
    except FileNotFoundError:
        pass
 
 
def main(n_rings: int = 3, n: int = 200, cap: int = 2000, verbose: bool = False):
    configs = [{"name": f"ring_cap{k}", "cap": cap} for k in range(n_rings)]
    for cfg in configs:
        cleanup_old(cfg["name"])
    parents = [Ring(**cfg, create=True, verbose=verbose) for cfg in configs]   # rôle P
 
    results = mp.Queue()
    procs = [mp.Process(daemon=True, target=writer_proc,
                        args=(results, cfg, k, n, verbose))
             for k, cfg in enumerate(configs)]
    for p in procs:
        p.start()
 
    reader = MultiReader(configs, verbose=verbose)       # lit TOUT, rôle R
    expected = [0] * n_rings                              # prochain numéro attendu par ring
    got = [0] * n_rings
    errors = []
    start = time.time()
    total = n_rings * n
    while sum(got) < total and time.time() < start + 30:
        idx, ts, pkt = reader.get()
        if idx is None:                                   # tout est vide : on attend un peu
            time.sleep(0.001)
            continue
        ring_id, i = pkt[0], int.from_bytes(pkt[1:5], "little")
        if ring_id != idx:
            errors.append(f"paquet du ring {ring_id} lu dans le ring {idx}")
        if i != expected[idx]:
            errors.append(f"ring {idx} : attendu {expected[idx]}, reçu {i}")
        if ts != TS0 + i:
            errors.append(f"ring {idx} paquet {i} : ts perdu ({ts})")
        if pkt != make_packet(ring_id, i):
            errors.append(f"contenu faux : ring {idx} paquet {i}")
        expected[idx] = i + 1
        got[idx] += 1
    elapsed = time.time() - start
 
    for p in procs:
        p.join(timeout=10)
    for _ in range(n_rings):
        r = results.get(timeout=5)
        if r[1] == "ERREUR":
            print(f"   ❌ writer {r[0]} : {r[2]}")
        else:
            print(f"   ✏️ writer {r[0]} : {n} paquets en {r[1]:.3f}s | counts={r[2]}")
    print(f"   📖 reader : {sum(got)}/{total} paquets en {elapsed:.3f}s | par ring : {got}")
    print("   ✅ ordre et contenu OK (dans chaque ring)" if not errors and sum(got) == total
          else f"   ❌ problèmes : {errors[:5]}")
 
    reader.close()
    for ring in parents:
        ring.close()
        ring.unlink()                                     # le parent supprime les blocs
 
 
def test_ringqueue(n: int = 100, cap: int = 2000):
    """RingQueue = interface de queue.Queue : alertes locales d'abord, puis les rings."""
    print("\n=== Test RingQueue ===")
    configs = [{"name": f"rq_cap{k}", "cap": cap} for k in range(2)]
    for cfg in configs:
        cleanup_old(cfg["name"])
    parents = [Ring(**cfg, create=True) for cfg in configs]
    results = mp.Queue()
    procs = [mp.Process(daemon=True, target=writer_proc, args=(results, cfg, k, n, False))
             for k, cfg in enumerate(configs)]
    for p in procs:
        p.start()
 
    rq = RingQueue(configs, local_maxsize=3)
    errors = []
 
    # 1) alertes locales (comme le moniteur Suricata) : elles passent AVANT les paquets
    rq.put_nowait(("fake_eth_1", {"msg": "alerte 1"}))
    rq.put_nowait(("fake_eth_2", {"msg": "alerte 2"}))
    time.sleep(0.05)                                   # les rings contiennent déjà des paquets
    for k in (1, 2):
        item = rq.get_nowait()
        if not (isinstance(item[1], dict) and item[1]["msg"] == f"alerte {k}"):
            errors.append(f"alerte {k} pas en premier : {item[0]!r}")
 
    # 2) file locale bornée : la 4e alerte doit lever queue.Full
    for k in range(3):
        rq.put_nowait(("x", {"k": k}))
    try:
        rq.put_nowait(("x", {"k": 3}))
        errors.append("queue.Full attendu")
    except queue.Full:
        pass
    for _ in range(3):
        rq.get_nowait()
 
    # 3) tous les paquets : (ts, bytes), ts conservé, ordre conservé par ring
    expected = [0, 0]
    got, start = 0, time.time()
    while got < 2 * n and time.time() < start + 30:
        try:
            ts, raw = rq.get_nowait()
        except queue.Empty:
            time.sleep(0.001)
            continue
        ring_id, i = raw[0], int.from_bytes(raw[1:5], "little")
        if not isinstance(raw, bytes) or ts != TS0 + i or i != expected[ring_id]:
            errors.append(f"ring {ring_id} : attendu {expected[ring_id]}, reçu {i}, ts={ts}")
        expected[ring_id] = i + 1
        got += 1
 
    # 4) tout est vide : queue.Empty, empty() vrai, stats() utilisable
    try:
        rq.get_nowait()
        errors.append("queue.Empty attendu")
    except queue.Empty:
        pass
    if not rq.empty() or rq.qsize() != 0:
        errors.append(f"pas vide : qsize={rq.qsize()}")
    st = rq.stats()
    print(f"   stats() = {st}")
    print(f"   qsize={rq.qsize()} maxsize={rq.maxsize}")
    print(f"   {got}/{2 * n} paquets lus, alertes locales d'abord, queue.Full / queue.Empty OK"
          if not errors and got == 2 * n else f"   ❌ problèmes : {errors[:5]}")
 
    for p in procs:
        p.join(timeout=10)
    rq.close()
    for ring in parents:
        ring.close()
        ring.unlink()
 
 
if __name__ == "__main__":
    VERBOSE = False        # mets True (avec un petit n) pour voir chaque put / get
    main(n_rings=3, n=200, cap=2000, verbose=VERBOSE)
    test_ringqueue()
 
