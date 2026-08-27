#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Aug  2 08:23:38 2026

@author: hounsousamuel
"""

# ============================================================================
# keyed_lock.py — verrou asyncio par clé
# ============================================================================
# Empêche deux tâches de manipuler la MÊME ressource en même temps, sans
# bloquer les autres ressources entre elles. Utile pour ton exec parallèle :
# si le modèle demande 2 update_asset sur le même asset_id dans le même
# lot, elles s'exécuteront l'une après l'autre (comme avant, en séquentiel)
# — mais deux update_asset sur des assets DIFFÉRENTS continuent de tourner
# en parallèle sans se gêner. Best of both worlds.
#
# Usage typique : wrapper les tools sensibles (ceux qui font des
# lectures-modifications-écritures sur un objet identifiable par un id)
# dans ton tool_mapping, PAS dans LLMManager lui-même (LLMManager ne sait
# rien du domaine métier / de ce qu'est un "asset_id").
# ============================================================================

import asyncio
import weakref
from collections import defaultdict
from contextlib import asynccontextmanager


class KeyedLock:
    """Verrou asyncio par clé arbitraire (ex: asset_id). Crée le verrou à la
    demande, jamais de config préalable nécessaire."""

    def __init__(self):
        self._locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()
        self._meta_lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self, key: str):
        async with self._meta_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
                
        async with lock:
            yield
    
    def debug_count(self) -> int:
        """Nombre de verrous actuellement vivants dans le dico (pour la démo)."""
        return len(self._locks)


# Instance partagée — un seul verrou pour toute l'app, peu importe combien
# de runs/conversations tournent en parallèle. Les clés sont namespacées
# ("asset:xxx", "report:42", "job:scan_daily") pour qu'un asset_id et un
# report_id qui se ressembleraient par hasard ne se marchent jamais dessus.
        
resource_lock = KeyedLock()

if __name__ == "__main__":
    from modules_utils.loop_utils import _run_async
    async def fake_update_asset(asset_id: str, worker_id: int, duration: float = 0.3):
        """Simule un update_asset qui prend du temps (I/O, DB, etc.)."""
        async with resource_lock.acquire(f"asset:{asset_id}"):
            print(f"  🔒 [worker {worker_id}] entre dans asset:{asset_id} "
                  f"(locks vivants: {resource_lock.debug_count()})")
            await asyncio.sleep(duration)
            print(f"  🔓 [worker {worker_id}] sort de asset:{asset_id}")
 
    async def demo_meme_ressource():
        """2 tâches sur LE MÊME asset_id -> doivent s'exécuter en séquentiel."""
        print("\n=== 🧪 Test 1 : deux tâches sur la MÊME ressource (asset:42) ===")
        print("Attendu : worker 1 doit finir avant que worker 2 n'entre.\n")
        await asyncio.gather(
            fake_update_asset("42", worker_id=1),
            fake_update_asset("42", worker_id=2),
        )
 
    async def demo_ressources_differentes():
        """2 tâches sur des asset_id DIFFÉRENTS -> doivent tourner en parallèle."""
        print("\n=== 🧪 Test 2 : deux tâches sur des ressources DIFFÉRENTES (asset:1, asset:2) ===")
        print("Attendu : les deux workers doivent se chevaucher dans le temps.\n")
        await asyncio.gather(
            fake_update_asset("1", worker_id=1),
            fake_update_asset("2", worker_id=2),
        )
 
    async def demo_nettoyage_memoire():
        """Vérifie que les verrous disparaissent bien du dico une fois relâchés."""
        print("\n=== 🧪 Test 3 : nettoyage mémoire automatique (WeakValueDictionary) ===")
        print(f"Avant tout appel        -> locks vivants: {resource_lock.debug_count()}")
 
        async with resource_lock.acquire("asset:99"):
            print(f"Pendant le 'async with' -> locks vivants: {resource_lock.debug_count()} "
                  f"(le verrou de asset:99 est utilisé, donc gardé)")
 
        # Le verrou n'est plus tenu par personne juste après le 'async with'.
        # On force un petit passage de contrôle pour laisser le garbage
        # collector faire son travail (utile surtout sous PyPy ; sous
        # CPython le refcounting est en général immédiat).
        await asyncio.sleep(0)
        import gc
        gc.collect()
 
        print(f"Après le 'async with'   -> locks vivants: {resource_lock.debug_count()} "
              f"(devrait être 0 : le verrou a été garbage-collecté et sa clé effacée)")
 
    async def demo_stress_test(nb_assets: int = 5, nb_workers_par_asset: int = 4):
        """Beaucoup de workers, sur peu d'assets -> vérifie qu'il n'y a jamais
        2 workers en même temps sur le MÊME asset, et que ça reste rapide
        grâce au parallélisme entre assets différents."""
        print(f"\n=== 🧪 Test 4 : stress test ({nb_assets} assets x {nb_workers_par_asset} workers) ===")
 
        # On garde une trace de qui est "dedans" pour détecter une éventuelle
        # violation (2 workers en même temps sur le même asset_id).
        currently_inside = set()
        violations = []
 
        async def worker(asset_id: str, worker_id: int):
            async with resource_lock.acquire(f"asset:{asset_id}"):
                if asset_id in currently_inside:
                    violations.append(asset_id)
                currently_inside.add(asset_id)
                await asyncio.sleep(0.05)
                currently_inside.discard(asset_id)
 
        tasks = [
            worker(asset_id=str(a), worker_id=w)
            for a in range(nb_assets)
            for w in range(nb_workers_par_asset)
        ]
 
        start = asyncio.get_event_loop().time()
        await asyncio.gather(*tasks)
        elapsed = asyncio.get_event_loop().time() - start
        print(f"Terminé en {elapsed:.2f}s pour {len(tasks)} tâches.")
        if violations:
            print(f"❌ VIOLATIONS détectées sur : {violations}")
        else:
            print("✅ Aucune violation : jamais 2 workers en même temps sur le même asset_id.")
 
        await asyncio.sleep(0)
        import gc
        gc.collect()
        print(f"Locks vivants après le stress test -> {resource_lock.debug_count()} (devrait être 0)")
 
    async def main():
        await demo_meme_ressource()
        await demo_ressources_differentes()
        await demo_nettoyage_memoire()
        await demo_stress_test()
 
    _run_async(main)
 

