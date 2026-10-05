#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 08:31:23 2026

@author: hounsousamuel
"""

"""
resolve_hostname NON BLOQUANTE — remplaçant de la fonction de detection/anomaly_scorer.py (lignes ~68-95).

Ce que fait ce code (en 4 phrases)
----------------------------------
1. 1er appel pour une IP : renvoie TOUT DE SUITE "non-résolu" et envoie la vraie résolution (socket.gethostbyaddr,
   bloquant) à un petit pool de threads.
2. Le thread range le résultat dans le cache. Les appels suivants pour cette IP lisent le cache (instantané).
3. Un échec est mémorisé aussi (5 min) : sinon une IP sans PTR relancerait un appel DNS à CHAQUE anomalie.
4. Garde-fous : au plus _HOSTNAME_MAX_PENDING résolutions en cours (panne DNS, scan avec IP spoofées) ; cache borné.

Pourquoi ça corrige le bug d'origine
------------------------------------
L'ancienne version ne faisait jamais `await` sur `asyncio.to_thread(...)` / `asyncio.wait_for(...)` : `result[0]`
plantait toujours, donc toujours "non-résolu". Et un simple `await` attendrait jusqu'à 0,5 s PAR anomalie dans la
boucle de détection (detect_pkt appelle resolve_hostname à chaque anomalie, ligne ~924). Ici on n'attend jamais.

Utilisation : remplace dans anomaly_scorer.py le bloc `_hostname_cache = {} ... async def resolve_hostname`
par le contenu de ce fichier (hors self-test). L'appel `await resolve_hostname(target)` ne change pas.
Auto-test : python resolve_hostname_fixed.py
"""
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor

_UNRESOLVED = "non-résolu"

# ip -> (valeur, instant d'expiration en time.monotonic())
_hostname_cache: dict[str, tuple[str, float]] = {}
_HOSTNAME_CACHE_MAXSIZE = 500
_HOSTNAME_TTL_OK = 3600.0       # un nom trouvé reste valable 1 h
_HOSTNAME_TTL_FAIL = 300.0      # un échec est mémorisé 5 min

_hostname_pending: set[str] = set()     # IP dont la résolution est en cours
_HOSTNAME_MAX_PENDING = 32              # au-delà : on ne lance plus rien (retour "non-résolu" immédiat)

_hostname_cache_lock = threading.Lock()  # protège seulement l'ÉCRITURE/éviction ; lire un dict n'en a pas besoin
_hostname_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")


def _lookup_hostname(ip: str) -> None:
    """Tourne dans un thread du pool : résout (bloquant), puis range le résultat. Ne lève jamais."""
    try:
        value, ttl = socket.gethostbyaddr(ip)[0], _HOSTNAME_TTL_OK
    except Exception:
        value, ttl = _UNRESOLVED, _HOSTNAME_TTL_FAIL
    try:
        with _hostname_cache_lock:
            if ip not in _hostname_cache and len(_hostname_cache) >= _HOSTNAME_CACHE_MAXSIZE:
                del _hostname_cache[next(iter(_hostname_cache))]    # FIFO : la plus ancienne insertion
            _hostname_cache[ip] = (value, time.monotonic() + ttl)
    finally:
        _hostname_pending.discard(ip)   # APRÈS l'écriture du cache : jamais "ni en cache, ni en cours"


async def resolve_hostname(ip: str) -> str:
    """
    Nom d'hôte d'une IP, SANS JAMAIS ATTENDRE le DNS.
    Cache chaud -> la valeur ; sinon "non-résolu" et la résolution part en arrière-plan pour le prochain appel.
    (`async` conservé pour ne pas changer l'appel `await resolve_hostname(target)` ; rien n'est attendu à l'intérieur.)
    """
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        return "local"
    
    # return "non-resolu"
    entry = _hostname_cache.get(ip)
    if entry is not None:
        value, expires = entry
        if time.monotonic() < expires:
            return value                # cache valide (nom trouvé OU échec récent)
        # périmé : on renvoie quand même l'ancienne valeur (mieux que rien) et on la rafraîchit ci-dessous
    else:
        value = _UNRESOLVED

    if ip not in _hostname_pending and len(_hostname_pending) < _HOSTNAME_MAX_PENDING:
        _hostname_pending.add(ip)
        try:
            _hostname_pool.submit(_lookup_hostname, ip)
        except RuntimeError:            # pool déjà arrêté (fermeture)
            _hostname_pending.discard(ip)
    return value


def shutdown_hostname_resolver() -> None:
    """À appeler à l'arrêt du module. Un thread bloqué dans un DNS lent finira son appel avant la sortie du process."""
    _hostname_pool.shutdown(wait=False, cancel_futures=True)


# ======================================= AUTO-TEST (python resolve_hostname_fixed.py) =======================================
if __name__ == "__main__":
    import asyncio

    calls: list[str] = []

    def make_fake(delay=0.0, fail=False):
        def fake(ip):
            calls.append(ip)
            time.sleep(delay)
            if fail:
                raise socket.herror("pas de PTR")
            return (f"host-{ip}.example", [], [ip])
        return fake

    async def settle(timeout=3.0):
        """Attend que plus aucune résolution ne soit en cours."""
        t0 = time.monotonic()
        while _hostname_pending and time.monotonic() - t0 < timeout:
            await asyncio.sleep(0.01)

    def reset():
        _hostname_cache.clear(); _hostname_pending.clear(); calls.clear()

    async def tests():
        global _HOSTNAME_TTL_FAIL, _HOSTNAME_MAX_PENDING, _HOSTNAME_CACHE_MAXSIZE
        real = socket.gethostbyaddr
        try:
            # A) 1er appel immédiat malgré un DNS lent, 2e appel = résolu, 3e = cache instantané
            reset(); socket.gethostbyaddr = make_fake(delay=0.3)
            t = time.perf_counter(); v1 = await resolve_hostname("198.51.100.1"); dt = (time.perf_counter() - t) * 1000
            assert v1 == _UNRESOLVED and dt < 20, (v1, dt)
            await settle()
            assert await resolve_hostname("198.51.100.1") == "host-198.51.100.1.example"
            t = time.perf_counter(); await resolve_hostname("198.51.100.1"); assert (time.perf_counter() - t) * 1000 < 5
            print(f"A OK  1er appel : {dt:.2f} ms alors que le DNS met 300 ms ; 2e appel : résolu")

            # B) 50 appels pendant que ça résout -> UNE seule requête DNS
            reset(); socket.gethostbyaddr = make_fake(delay=0.2)
            for _ in range(50):
                await resolve_hostname("198.51.100.2")
            await settle()
            assert calls == ["198.51.100.2"], calls
            print("B OK  50 appels simultanés -> 1 seule requête DNS")

            # C) un échec est mémorisé (pas de DNS à chaque anomalie), puis réessayé après le TTL
            reset(); socket.gethostbyaddr = make_fake(fail=True); _HOSTNAME_TTL_FAIL = 0.3
            await resolve_hostname("198.51.100.3"); await settle()
            for _ in range(100):
                assert await resolve_hostname("198.51.100.3") == _UNRESOLVED
            assert len(calls) == 1, calls
            await asyncio.sleep(0.35)
            assert await resolve_hostname("198.51.100.3") == _UNRESOLVED       # périmé : valeur renvoyée sans attendre
            await settle(); assert len(calls) == 2, calls
            print("C OK  échec mémorisé (1 requête pour 100 appels), réessayé après le TTL")

            # D) borne des résolutions en cours (panne DNS / scan d'IP spoofées)
            reset(); socket.gethostbyaddr = make_fake(delay=0.4); _HOSTNAME_MAX_PENDING = 3
            res = [await resolve_hostname(f"203.0.113.{i}") for i in range(10)]
            assert all(r == _UNRESOLVED for r in res)
            await asyncio.sleep(0.05)
            assert len(set(calls)) == 3, calls
            await settle()
            await resolve_hostname("203.0.113.99"); await settle()
            assert "203.0.113.99" in calls
            print("D OK  10 IP d'un coup avec un DNS lent -> seulement 3 requêtes lancées ; la suite repart ensuite")

            # E) cache borné + 4 threads qui écrivent en même temps, sans erreur
            reset(); socket.gethostbyaddr = make_fake(); _HOSTNAME_MAX_PENDING = 10_000; _HOSTNAME_CACHE_MAXSIZE = 50
            for i in range(500):
                await resolve_hostname(f"10.1.{i // 250}.{i % 250}")
                if i % 20 == 0:
                    await asyncio.sleep(0.001)
            await settle()
            assert len(_hostname_cache) <= 50 and not _hostname_pending, (len(_hostname_cache), len(_hostname_pending))
            print(f"E OK  500 IP, cache borné à {len(_hostname_cache)}/50, aucune résolution restée en suspens")

            # F) IP locales
            assert await resolve_hostname("127.0.0.1") == "local" and await resolve_hostname("") == "local"
            print("F OK  IP locales -> 'local'")
        finally:
            socket.gethostbyaddr = real

    asyncio.run(tests())
    shutdown_hostname_resolver()
    print("TOUS LES TESTS OK")